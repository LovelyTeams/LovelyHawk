use std::{collections::BTreeMap, ops::Range, sync::Arc};

use gpui::{
    AnyElement, Context, Entity, Render, ScrollHandle, SharedString, Subscription,
    UniformListScrollHandle, Window, div, prelude::*, px, uniform_list,
};
use gpui_component::{
    Disableable, Selectable, Sizable, StyledExt,
    button::ButtonVariants,
    input::{Input, InputEvent, InputState},
    scroll::ScrollableElement,
};
use lovelyres_core::{
    BackendServices, CoreError, CoreResult,
    middleware::{
        MiddlewareChangePlan, MiddlewareChangeRecord, MiddlewareChangeState,
        MiddlewareConfigSnapshot, MiddlewareConfigurationBundle, MiddlewareDraft,
        MiddlewareInstance, MiddlewareProduct,
    },
    middleware_document::{MiddlewareDocumentNode, MiddlewareDocumentNodeKind},
    operations::DangerousConfirmation,
    ssh::BoundSshSession,
    target::TargetGuard,
};
use tokio::task::AbortHandle;

use crate::{app::SharedAppState, runtime::TokioBridge, theme::ThemeTokens};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum RequestLane {
    Discover,
    Load,
    Plan,
}

const APACHE_EVIDENCE_SEAL_DISABLED_REASON: &str = "Apache 配置变更已禁用：exact runtime invocation provider 与 stable configuration graph evidence seal 尚未接线；当前仅提供预览与只读发现，不能编辑草稿、生成或执行变更计划，也不能生成恢复计划。";
const MAX_NODE_SEARCH_CHARS: usize = 128;
const SENSITIVE_NODE_PREVIEW_PREFIX: &str = "<敏感内容由 core 保留 · ";
const SYNTAX_ONLY_UNKNOWN: &str = "SyntaxOnlyUnknown · 仅识别结构语法，未做目标指令语义验证";

#[derive(Clone, Debug, Eq, PartialEq)]
struct MiddlewareNodeExplanation {
    label: String,
    kind: &'static str,
    meaning: &'static str,
    span_start: usize,
    span_end: usize,
    depth: usize,
    child_count: usize,
    sensitive: bool,
    preview_truncated: bool,
    actionability: &'static str,
}

fn middleware_mutation_disabled_reason(product: MiddlewareProduct) -> Option<&'static str> {
    (product == MiddlewareProduct::ApacheHttpd).then_some(APACHE_EVIDENCE_SEAL_DISABLED_REASON)
}

fn middleware_mutations_disabled(product: MiddlewareProduct) -> bool {
    middleware_mutation_disabled_reason(product).is_some()
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MiddlewareBinding {
    connection_id: String,
    session_id: String,
    target: TargetGuard,
}

impl MiddlewareBinding {
    fn from_session(session: &BoundSshSession) -> Self {
        Self {
            connection_id: session.connection_id().to_owned(),
            session_id: session.session_id().to_owned(),
            target: session.target().clone(),
        }
    }

    fn capture(shared: &SharedAppState) -> Option<Self> {
        shared
            .active_ssh
            .as_ref()
            .map(|active| Self::from_session(&active.session))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RequestLease {
    activation_generation: u64,
    request_id: u64,
    lane: RequestLane,
    product: MiddlewareProduct,
    binding: MiddlewareBinding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DetailTab {
    Overview,
    Visual,
    Raw,
    Diff,
    History,
}

impl DetailTab {
    const ALL: [Self; 5] = [
        Self::Overview,
        Self::Visual,
        Self::Raw,
        Self::Diff,
        Self::History,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Overview => "概览",
            Self::Visual => "可视化",
            Self::Raw => "原文",
            Self::Diff => "差异",
            Self::History => "历史",
        }
    }
}

struct MiddlewareModel {
    active: bool,
    activation_generation: u64,
    next_request_id: u64,
    latest: BTreeMap<RequestLane, u64>,
    binding: Option<MiddlewareBinding>,
    product: MiddlewareProduct,
    instances: Vec<MiddlewareInstance>,
    selected_instance_id: Option<String>,
    bundle: Option<Arc<MiddlewareConfigurationBundle>>,
    drafts: Vec<MiddlewareDraft>,
    selected_file: Option<usize>,
    selected_node: Option<usize>,
    tab: DetailTab,
    history: Vec<MiddlewareChangeRecord>,
}

impl Default for MiddlewareModel {
    fn default() -> Self {
        Self {
            active: false,
            activation_generation: 0,
            next_request_id: 0,
            latest: BTreeMap::new(),
            binding: None,
            product: MiddlewareProduct::Nginx,
            instances: Vec::new(),
            selected_instance_id: None,
            bundle: None,
            drafts: Vec::new(),
            selected_file: None,
            selected_node: None,
            tab: DetailTab::Overview,
            history: Vec::new(),
        }
    }
}

impl MiddlewareModel {
    fn activate(&mut self, binding: Option<MiddlewareBinding>) {
        self.active = true;
        self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
        self.rebind(binding);
    }

    fn deactivate(&mut self) {
        self.active = false;
        self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
        self.latest.clear();
        self.clear_target_state();
    }

    fn rebind(&mut self, binding: Option<MiddlewareBinding>) {
        if self.binding == binding {
            return;
        }
        self.binding = binding;
        self.latest.clear();
        self.clear_target_state();
    }

    fn clear_target_state(&mut self) {
        self.instances.clear();
        self.selected_instance_id = None;
        self.bundle = None;
        self.drafts.clear();
        self.selected_file = None;
        self.selected_node = None;
        self.history.clear();
    }

    fn switch_product(&mut self, product: MiddlewareProduct) {
        if self.product == product {
            return;
        }
        self.product = product;
        self.latest.clear();
    }

    fn begin(&mut self, lane: RequestLane, binding: MiddlewareBinding) -> CoreResult<RequestLease> {
        if !self.active {
            return Err(CoreError::Validation {
                subject: "middleware page",
                message: "page is not active".to_owned(),
            });
        }
        self.rebind(Some(binding.clone()));
        self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
        self.latest.insert(lane, self.next_request_id);
        Ok(RequestLease {
            activation_generation: self.activation_generation,
            request_id: self.next_request_id,
            lane,
            product: self.product,
            binding,
        })
    }

    fn accepts(&self, lease: &RequestLease, binding: Option<&MiddlewareBinding>) -> bool {
        self.active
            && self.activation_generation == lease.activation_generation
            && self.latest.get(&lease.lane) == Some(&lease.request_id)
            && self.product == lease.product
            && binding == Some(&lease.binding)
    }

    fn accepts_completion(
        &self,
        activation_generation: u64,
        product: MiddlewareProduct,
        binding: &MiddlewareBinding,
        current_binding: Option<&MiddlewareBinding>,
    ) -> bool {
        self.active
            && self.activation_generation == activation_generation
            && self.product == product
            && current_binding == Some(binding)
    }

    fn selected_instance(&self) -> Option<&MiddlewareInstance> {
        let id = self.selected_instance_id.as_deref()?;
        self.instances.iter().find(|instance| instance.id() == id)
    }

    fn selected_snapshot(&self) -> Option<&MiddlewareConfigSnapshot> {
        let index = self.selected_file?;
        self.bundle.as_ref()?.files().get(index)
    }

    fn selected_draft(&self) -> Option<&MiddlewareDraft> {
        self.drafts.get(self.selected_file?)
    }

    fn has_changes(&self) -> bool {
        self.selected_draft()
            .is_some_and(MiddlewareDraft::has_changes)
    }
}

pub struct MiddlewarePage {
    services: Arc<BackendServices>,
    tokio: Arc<TokioBridge>,
    shared: Entity<SharedAppState>,
    model: MiddlewareModel,
    raw_input: Option<Entity<InputState>>,
    value_input: Option<Entity<InputState>>,
    node_search_input: Entity<InputState>,
    node_search_query: String,
    node_revision: u64,
    raw_dirty: bool,
    node_scroll: UniformListScrollHandle,
    page_scroll: ScrollHandle,
    read_abort: Option<AbortHandle>,
    busy: bool,
    executing: bool,
    pending: Option<MiddlewareChangePlan>,
    error: Option<SharedString>,
    notice: Option<SharedString>,
    _shared_subscription: Subscription,
    _node_search_subscription: Subscription,
    raw_subscription: Option<Subscription>,
}

impl MiddlewarePage {
    pub fn new(
        services: Arc<BackendServices>,
        tokio: Arc<TokioBridge>,
        shared: Entity<SharedAppState>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let shared_subscription = cx.observe(&shared, |page, _, cx| page.handle_shared_change(cx));
        let node_search_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder("搜索节点类型或安全名称（最多 128 字符）")
        });
        let node_search_subscription = cx.subscribe_in(
            &node_search_input,
            window,
            |page, input, event: &InputEvent, window, cx| {
                if matches!(event, InputEvent::Change) {
                    page.sync_node_search(input, window, cx);
                }
            },
        );
        Self {
            services,
            tokio,
            shared,
            model: MiddlewareModel::default(),
            raw_input: None,
            value_input: None,
            node_search_input,
            node_search_query: String::new(),
            node_revision: 0,
            raw_dirty: false,
            node_scroll: UniformListScrollHandle::new(),
            page_scroll: ScrollHandle::new(),
            read_abort: None,
            busy: false,
            executing: false,
            pending: None,
            error: None,
            notice: None,
            _shared_subscription: shared_subscription,
            _node_search_subscription: node_search_subscription,
            raw_subscription: None,
        }
    }

    pub fn activate(&mut self, _window: &mut Window, cx: &mut Context<Self>) {
        self.model
            .activate(MiddlewareBinding::capture(self.shared.read(cx)));
        self.clear_editors();
        self.refresh(cx);
    }

    pub fn deactivate(&mut self, cx: &mut Context<Self>) {
        self.cancel_read();
        self.model.deactivate();
        self.pending = None;
        self.busy = false;
        self.executing = false;
        self.clear_editors();
        self.error = None;
        self.notice = None;
        // A confirmed mutation intentionally continues in its detached task so
        // core can finish journal, verification and automatic restoration.
        cx.notify();
    }

    pub const fn is_active(&self) -> bool {
        self.model.active
    }

    fn current_session(&self, cx: &Context<Self>) -> Option<BoundSshSession> {
        self.shared
            .read(cx)
            .active_ssh
            .as_ref()
            .map(|active| active.session.clone())
    }

    fn current_binding(&self, cx: &Context<Self>) -> Option<MiddlewareBinding> {
        MiddlewareBinding::capture(self.shared.read(cx))
    }

    fn cancel_read(&mut self) {
        if let Some(abort) = self.read_abort.take() {
            abort.abort();
        }
        self.model.latest.clear();
    }

    fn clear_editors(&mut self) {
        self.raw_subscription = None;
        self.raw_input = None;
        self.invalidate_node_selection();
        self.raw_dirty = false;
    }

    fn invalidate_node_selection(&mut self) {
        self.node_revision = self.node_revision.wrapping_add(1).max(1);
        self.model.selected_node = None;
        self.value_input = None;
    }

    fn sync_node_search(
        &mut self,
        input: &Entity<InputState>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let value = input.read(cx).value().to_string();
        let bounded = bounded_node_search_query(&value);
        if bounded != value {
            let replacement = bounded.clone();
            input.update(cx, |input, cx| input.set_value(replacement, window, cx));
        }
        self.node_search_query = bounded;
        self.node_revision = self.node_revision.wrapping_add(1).max(1);
        let visible = self
            .model
            .selected_draft()
            .map(|draft| visible_node_indices(draft, &self.node_search_query))
            .unwrap_or_default();
        let retained = retained_visible_selection(self.model.selected_node, &visible);
        if retained != self.model.selected_node {
            self.model.selected_node = None;
            self.value_input = None;
        }
        cx.notify();
    }

    fn reject_disabled_mutation(&mut self, cx: &mut Context<Self>) -> bool {
        let Some(reason) = middleware_mutation_disabled_reason(self.model.product) else {
            return false;
        };
        self.pending = None;
        self.notice = None;
        self.error = Some(reason.into());
        cx.notify();
        true
    }

    fn handle_shared_change(&mut self, cx: &mut Context<Self>) {
        if !self.model.active {
            return;
        }
        let binding = self.current_binding(cx);
        if binding == self.model.binding {
            return;
        }
        self.cancel_read();
        self.pending = None;
        self.busy = false;
        self.executing = false;
        self.model.rebind(binding);
        self.clear_editors();
        self.error = None;
        self.notice = None;
        self.refresh(cx);
        cx.notify();
    }

    fn begin(&mut self, lane: RequestLane, session: &BoundSshSession) -> CoreResult<RequestLease> {
        self.cancel_read();
        self.model
            .begin(lane, MiddlewareBinding::from_session(session))
    }

    fn refresh(&mut self, cx: &mut Context<Self>) {
        if self.busy || self.executing {
            return;
        }
        let Some(session) = self.current_session(cx) else {
            self.error = Some("未连接可信目标".into());
            cx.notify();
            return;
        };
        let lease = match self.begin(RequestLane::Discover, &session) {
            Ok(lease) => lease,
            Err(_) => return,
        };
        self.busy = true;
        self.error = None;
        self.notice = Some("正在探测受支持的 systemd 中间件实例…".into());
        let service = self.services.middleware().clone();
        let task = self
            .tokio
            .spawn(async move { service.discover(&session).await });
        self.read_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        let binding = page.current_binding(cx);
                        if !page.model.accepts(&lease, binding.as_ref()) {
                            return;
                        }
                        page.busy = false;
                        page.read_abort = None;
                        match result {
                            Ok(Ok(instances)) => {
                                page.clear_editors();
                                page.pending = None;
                                page.model.instances = instances;
                                page.model.selected_instance_id = None;
                                page.model.bundle = None;
                                page.model.drafts.clear();
                                page.model.selected_file = None;
                                page.model.selected_node = None;
                                match page.services.middleware().history(&lease.binding.target) {
                                    Ok(history) => {
                                        page.model.history = history;
                                        page.error = None;
                                    }
                                    Err(_) => {
                                        page.model.history.clear();
                                        page.error = Some("读取中间件变更历史失败".into());
                                    }
                                }
                                page.notice = None;
                            }
                            Ok(Err(_)) => page.error = Some("中间件探测失败".into()),
                            Err(error) if error.is_cancelled() => return,
                            Err(_) => page.error = Some("中间件探测任务异常终止".into()),
                        }
                        cx.notify();
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn select_product(&mut self, product: MiddlewareProduct, cx: &mut Context<Self>) {
        if self.busy || self.executing {
            return;
        }
        self.model.switch_product(product);
        self.model.selected_instance_id = None;
        self.model.bundle = None;
        self.model.drafts.clear();
        self.model.selected_file = None;
        self.model.selected_node = None;
        self.pending = None;
        self.clear_editors();
        cx.notify();
    }

    fn select_instance(&mut self, id: String, cx: &mut Context<Self>) {
        if self.busy || self.executing {
            return;
        }
        let Some(instance) = self
            .model
            .instances
            .iter()
            .find(|instance| instance.id() == id)
            .cloned()
        else {
            return;
        };
        if instance.product() != self.model.product {
            return;
        }
        let Some(session) = self.current_session(cx) else {
            return;
        };
        let lease = match self.begin(RequestLane::Load, &session) {
            Ok(lease) => lease,
            Err(_) => return,
        };
        self.model.selected_instance_id = Some(instance.id().to_owned());
        self.model.bundle = None;
        self.model.drafts.clear();
        self.model.selected_file = None;
        self.model.selected_node = None;
        self.pending = None;
        self.clear_editors();
        self.busy = true;
        self.notice = Some("正在读取完整配置与 include 图…".into());
        self.error = None;
        let service = self.services.middleware().clone();
        let task = self
            .tokio
            .spawn(async move { service.load_configuration(&session, &instance).await });
        self.read_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        let binding = page.current_binding(cx);
                        if !page.model.accepts(&lease, binding.as_ref()) {
                            return;
                        }
                        page.busy = false;
                        page.read_abort = None;
                        match result {
                            Ok(Ok(bundle)) => {
                                let drafts = bundle
                                    .files()
                                    .iter()
                                    .map(MiddlewareConfigSnapshot::create_draft)
                                    .collect::<CoreResult<Vec<_>>>();
                                match drafts {
                                    Ok(drafts) => {
                                        page.model.drafts = drafts;
                                        page.model.selected_file =
                                            (!bundle.files().is_empty()).then_some(0);
                                        page.invalidate_node_selection();
                                        page.model.bundle = Some(Arc::new(bundle));
                                        page.notice = None;
                                        page.error = None;
                                    }
                                    Err(_) => {
                                        page.model.bundle = None;
                                        page.model.drafts.clear();
                                        page.error = Some("生成脱敏配置视图失败".into());
                                    }
                                }
                            }
                            Ok(Err(_)) => page.error = Some("读取中间件配置失败".into()),
                            Err(error) if error.is_cancelled() => return,
                            Err(_) => page.error = Some("配置读取任务异常终止".into()),
                        }
                        cx.notify();
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn select_file(&mut self, index: usize, window: &mut Window, cx: &mut Context<Self>) {
        if self.busy || self.executing {
            return;
        }
        if self.model.drafts.get(index).is_none() {
            return;
        }
        self.model.selected_file = Some(index);
        self.invalidate_node_selection();
        self.pending = None;
        self.install_raw_editor(window, cx);
        cx.notify();
    }

    fn install_raw_editor(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.raw_subscription = None;
        self.raw_input = None;
        self.raw_dirty = false;
        let Some(draft) = self.model.selected_draft() else {
            return;
        };
        let Some(raw) = draft.safe_raw_text().map(str::to_owned) else {
            return;
        };
        let input = cx.new(|cx| {
            InputState::new(window, cx)
                .code_editor("plaintext")
                .soft_wrap(false)
                .default_value(raw)
        });
        self.raw_subscription =
            Some(
                cx.subscribe_in(&input, window, |page, _, event: &InputEvent, _, cx| {
                    if matches!(event, InputEvent::Change) {
                        page.raw_dirty = true;
                        cx.notify();
                    }
                }),
            );
        self.raw_input = Some(input);
    }

    fn select_node(
        &mut self,
        index: usize,
        revision: u64,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if revision != self.node_revision {
            return;
        }
        let editable_value = self
            .model
            .selected_draft()
            .and_then(|draft| draft.editable_value(index));
        if self
            .model
            .selected_draft()
            .and_then(|draft| draft.nodes().get(index))
            .is_none()
        {
            return;
        }
        self.model.selected_node = Some(index);
        let Some(editable) = editable_value else {
            self.value_input = None;
            cx.notify();
            return;
        };
        self.value_input = Some(cx.new(|cx| {
            InputState::new(window, cx)
                .multi_line(true)
                .masked(editable.sensitive)
                .default_value(editable.value.unwrap_or_default())
        }));
        cx.notify();
    }

    fn apply_span_patch(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(input) = self.value_input.as_ref() else {
            return;
        };
        let replacement = input.read(cx).value().to_string();
        self.apply_span_replacement(replacement, window, cx);
    }

    fn clear_sensitive_span(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.apply_span_replacement(String::new(), window, cx);
    }

    fn apply_span_replacement(
        &mut self,
        replacement: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.reject_disabled_mutation(cx) {
            return;
        }
        if self.raw_dirty {
            self.error = Some("请先应用或丢弃原文编辑，再进行结构化修改".into());
            cx.notify();
            return;
        }
        let (Some(file_index), Some(node_index)) =
            (self.model.selected_file, self.model.selected_node)
        else {
            return;
        };
        let Some(draft) = self.model.drafts.get(file_index) else {
            return;
        };
        match draft.apply_node_edit(node_index, replacement) {
            Ok(patched) => {
                self.model.drafts[file_index] = patched;
                self.invalidate_node_selection();
                self.pending = None;
                self.install_raw_editor(window, cx);
                self.notice = Some("已生成本地精确 span 修改；远端尚未写入".into());
                self.error = None;
            }
            Err(_) => self.error = Some("该节点无法进行精确 span 修改".into()),
        }
        cx.notify();
    }

    fn apply_raw_edit(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.reject_disabled_mutation(cx) {
            return;
        }
        let (Some(file_index), Some(input)) = (self.model.selected_file, self.raw_input.as_ref())
        else {
            return;
        };
        let replacement = input.read(cx).value().to_string();
        let Some(draft) = self.model.drafts.get(file_index) else {
            return;
        };
        match draft.replace_safe_raw(replacement) {
            Ok(replaced) => {
                self.model.drafts[file_index] = replaced;
                self.invalidate_node_selection();
                self.pending = None;
                self.install_raw_editor(window, cx);
                self.notice = Some("已保留全部原文并更新本地草稿；远端尚未写入".into());
                self.error = None;
            }
            Err(_) => self.error = Some("原文不满足大小或字节边界".into()),
        }
        cx.notify();
    }

    fn discard_draft(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(index) = self.model.selected_file else {
            return;
        };
        let Some(snapshot) = self
            .model
            .bundle
            .as_ref()
            .and_then(|bundle| bundle.files().get(index))
        else {
            return;
        };
        let Ok(draft) = snapshot.create_draft() else {
            self.error = Some("无法重建脱敏配置草稿".into());
            cx.notify();
            return;
        };
        self.model.drafts[index] = draft;
        self.invalidate_node_selection();
        self.pending = None;
        self.install_raw_editor(window, cx);
        self.notice = Some("已丢弃本地草稿".into());
        self.error = None;
        cx.notify();
    }

    fn prepare_plan(&mut self, cx: &mut Context<Self>) {
        if self.reject_disabled_mutation(cx) {
            return;
        }
        if self.busy || self.executing || self.pending.is_some() || !self.model.has_changes() {
            return;
        }
        let Some(session) = self.current_session(cx) else {
            return;
        };
        let (Some(bundle), Some(file_index), Some(draft)) = (
            self.model.bundle.clone(),
            self.model.selected_file,
            self.model.selected_draft().cloned(),
        ) else {
            return;
        };
        let lease = match self.begin(RequestLane::Plan, &session) {
            Ok(lease) => lease,
            Err(_) => return,
        };
        self.busy = true;
        self.notice = Some("正在重读安全边界并生成不可变 CAS 计划…".into());
        self.error = None;
        let service = self.services.middleware().clone();
        let task = self.tokio.spawn(async move {
            service
                .plan_change(&session, &bundle, file_index, draft)
                .await
        });
        self.read_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        let binding = page.current_binding(cx);
                        if !page.model.accepts(&lease, binding.as_ref()) {
                            return;
                        }
                        page.busy = false;
                        page.read_abort = None;
                        match result {
                            Ok(Ok(plan)) if !middleware_mutations_disabled(page.model.product) => {
                                page.pending = Some(plan);
                                page.notice = None;
                                page.error = None;
                            }
                            Ok(Ok(_)) => {
                                page.pending = None;
                                page.notice = None;
                                page.error =
                                    middleware_mutation_disabled_reason(page.model.product)
                                        .map(Into::into);
                            }
                            Ok(Err(_)) => page.error = Some("无法创建中间件变更计划".into()),
                            Err(error) if error.is_cancelled() => return,
                            Err(_) => page.error = Some("计划任务异常终止".into()),
                        }
                        cx.notify();
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn prepare_restore(&mut self, record_id: String, cx: &mut Context<Self>) {
        if self.reject_disabled_mutation(cx) {
            return;
        }
        if self.busy || self.executing || self.pending.is_some() {
            return;
        }
        let Some(session) = self.current_session(cx) else {
            self.error = Some("未连接可信目标".into());
            cx.notify();
            return;
        };
        let lease = match self.begin(RequestLane::Plan, &session) {
            Ok(lease) => lease,
            Err(_) => return,
        };
        self.busy = true;
        self.notice = Some("正在校验远端备份、当前配置图与运行实例身份…".into());
        self.error = None;
        let service = self.services.middleware().clone();
        let task = self
            .tokio
            .spawn(async move { service.plan_restore(&session, &record_id).await });
        self.read_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        let binding = page.current_binding(cx);
                        if !page.model.accepts(&lease, binding.as_ref()) {
                            return;
                        }
                        page.busy = false;
                        page.read_abort = None;
                        match result {
                            Ok(Ok(plan)) if !middleware_mutations_disabled(page.model.product) => {
                                page.pending = Some(plan);
                                page.notice = Some(
                                    "恢复计划已生成；请核对哈希、目标 epoch 与激活方式后确认"
                                        .into(),
                                );
                                page.error = None;
                            }
                            Ok(Ok(_)) => {
                                page.pending = None;
                                page.notice = None;
                                page.error =
                                    middleware_mutation_disabled_reason(page.model.product)
                                        .map(Into::into);
                            }
                            Ok(Err(_)) => {
                                page.error = Some(
                                    "无法创建恢复计划：当前配置、远端备份或实例身份已变化".into(),
                                )
                            }
                            Err(error) if error.is_cancelled() => return,
                            Err(_) => page.error = Some("恢复计划任务异常终止".into()),
                        }
                        cx.notify();
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn approve_pending(&mut self, cx: &mut Context<Self>) {
        if self.reject_disabled_mutation(cx) {
            return;
        }
        if self.executing {
            return;
        }
        let Some(execution_binding) = self.current_binding(cx) else {
            self.error = Some("目标连接已失效，请重新生成计划".into());
            cx.notify();
            return;
        };
        let execution_generation = self.model.activation_generation;
        let execution_product = self.model.product;
        let Some(mut plan) = self.pending.take() else {
            return;
        };
        let confirmation = DangerousConfirmation::approve(plan.definition());
        if plan.confirm(confirmation).is_err() {
            self.error = Some("计划确认已失效，请重新生成".into());
            cx.notify();
            return;
        }
        self.executing = true;
        self.error = None;
        self.notice = Some("正在执行、配置测试、激活、健康回读并按需自动恢复…".into());
        let task = self
            .tokio
            .spawn(async move { plan.execute_and_verify().await });
        // Do not retain the abort handle: confirmed remote mutation must finish
        // its journal/verify/restore path even when this entity is deactivated.
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        let current_binding = page.current_binding(cx);
                        if !page.model.accepts_completion(
                            execution_generation,
                            execution_product,
                            &execution_binding,
                            current_binding.as_ref(),
                        ) {
                            return;
                        }
                        page.executing = false;
                        match result {
                            Ok(Ok(outcome)) => {
                                page.notice = Some(if outcome.history_persisted {
                                    "变更已验证并写入恢复历史".into()
                                } else {
                                    "变更已验证，但便携历史写入失败；请立即检查日志".into()
                                });
                                page.error = None;
                                page.refresh(cx);
                            }
                            Ok(Err(error)) => {
                                page.model.bundle = None;
                                page.model.drafts.clear();
                                page.model.selected_file = None;
                                page.model.selected_node = None;
                                page.clear_editors();
                                let history = page
                                    .services
                                    .middleware()
                                    .history(&execution_binding.target);
                                page.notice = None;
                                page.error = Some(match history {
                                    Ok(records) => {
                                        page.model.history = records;
                                        format!(
                                            "变更未完成：{}。请按历史状态核对或重试恢复。",
                                            bounded_status_error(&error.to_string())
                                        )
                                        .into()
                                    }
                                    Err(history_error) => format!(
                                        "变更未完成：{}。恢复历史读取也失败：{}。请保留当前目标会话并检查便携数据目录。",
                                        bounded_status_error(&error.to_string()),
                                        bounded_status_error(&history_error.to_string())
                                    )
                                    .into(),
                                });
                            }
                            Err(_) => {
                                page.model.bundle = None;
                                page.model.drafts.clear();
                                page.model.selected_file = None;
                                page.model.selected_node = None;
                                page.clear_editors();
                                page.model.history = page
                                    .services
                                    .middleware()
                                    .history(&execution_binding.target)
                                    .unwrap_or_default();
                                page.notice = None;
                                page.error = Some("变更任务异常终止；请按历史记录复核".into());
                            }
                        }
                        cx.notify();
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn set_tab(&mut self, tab: DetailTab, cx: &mut Context<Self>) {
        self.model.tab = tab;
        cx.notify();
    }

    fn ensure_editor(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.raw_input.is_none()
            && self
                .model
                .selected_draft()
                .is_some_and(|draft| draft.safe_raw_text().is_some())
        {
            self.install_raw_editor(window, cx);
        }
    }

    fn render_left(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let selected_product = self.model.product;
        let instances = self
            .model
            .instances
            .iter()
            .filter(|instance| instance.product() == selected_product)
            .cloned()
            .collect::<Vec<_>>();
        div()
            .w(px(240.0))
            .min_h_0()
            .flex_none()
            .rounded_lg()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .flex()
            .flex_col()
            .child(
                div()
                    .p_3()
                    .border_b_1()
                    .border_color(tokens.border)
                    .child(div().font_semibold().child("产品与实例")),
            )
            .child(div().p_2().flex().flex_col().gap_1().children(
                MiddlewareProduct::ALL.into_iter().map(|product| {
                    let count = self
                        .model
                        .instances
                        .iter()
                        .filter(|instance| instance.product() == product)
                        .count();
                    crate::buttons::button(SharedString::from(format!(
                        "middleware-product-{product:?}"
                    )))
                    .label(format!("{} · {count}", product.label()))
                    .small()
                    .ghost()
                    .selected(selected_product == product)
                    .disabled(self.busy || self.executing)
                    .on_click(cx.listener(move |page, _, _, cx| page.select_product(product, cx)))
                }),
            ))
            .child(div().mx_3().border_t_1().border_color(tokens.border))
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scrollbar()
                    .p_2()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .when(instances.is_empty(), |list| {
                        list.child(
                            div()
                                .p_3()
                                .text_sm()
                                .text_color(tokens.muted)
                                .child("未探测到该产品的受管 systemd 实例"),
                        )
                    })
                    .children(instances.into_iter().enumerate().map(|(index, instance)| {
                        let id = instance.id().to_owned();
                        let selected = self.model.selected_instance_id.as_deref() == Some(&id);
                        div()
                            .id(SharedString::from(format!("middleware-instance-{index}")))
                            .rounded_md()
                            .border_1()
                            .border_color(if selected {
                                tokens.accent
                            } else {
                                tokens.border
                            })
                            .bg(if selected {
                                tokens.surface_alt
                            } else {
                                tokens.surface
                            })
                            .p_3()
                            .cursor_pointer()
                            .on_click(cx.listener(move |page, _, _, cx| {
                                page.select_instance(id.clone(), cx)
                            }))
                            .child(div().font_semibold().child(instance.unit().to_owned()))
                            .child(
                                div()
                                    .mt_1()
                                    .text_xs()
                                    .text_color(if instance.is_active() {
                                        tokens.success
                                    } else {
                                        tokens.warning
                                    })
                                    .child(format!(
                                        "{} / {} · PID {}",
                                        instance.active_state(),
                                        instance.sub_state(),
                                        instance.main_pid()
                                    )),
                            )
                            .child(
                                div()
                                    .mt_1()
                                    .text_xs()
                                    .text_color(tokens.muted)
                                    .child(instance.version().to_owned()),
                            )
                    })),
            )
            .into_any_element()
    }

    fn render_middle(&mut self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let files = self
            .model
            .bundle
            .as_ref()
            .map(|bundle| {
                bundle
                    .files()
                    .iter()
                    .enumerate()
                    .map(|(index, file)| {
                        (
                            index,
                            file.role(),
                            file.path().as_str().to_owned(),
                            file.byte_len(),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let node_count = self
            .model
            .selected_draft()
            .map_or(0, |document| document.nodes().len());
        let visible_nodes = Arc::new(
            self.model
                .selected_draft()
                .map(|document| visible_node_indices(document, &self.node_search_query))
                .unwrap_or_default(),
        );
        let visible_node_count = visible_nodes.len();
        let node_revision = self.node_revision;
        div()
            .w(px(390.0))
            .min_h_0()
            .flex_none()
            .rounded_lg()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .flex()
            .flex_col()
            .child(
                div().p_3().border_b_1().border_color(tokens.border).child(
                    div()
                        .font_semibold()
                        .child(format!("配置文件 · {}", files.len())),
                ),
            )
            .child(
                div()
                    .max_h(px(190.0))
                    .overflow_y_scrollbar()
                    .p_2()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .when(files.is_empty(), |list| {
                        list.child(
                            div()
                                .p_3()
                                .text_sm()
                                .text_color(tokens.muted)
                                .child("选择实例后读取主配置、递归 include 与 Tomcat 已知配置"),
                        )
                    })
                    .children(files.into_iter().map(|(index, role, path, bytes)| {
                        let selected = self.model.selected_file == Some(index);
                        crate::buttons::button(SharedString::from(format!(
                            "middleware-file-{index}"
                        )))
                        .label(format!("{} · {path} · {bytes} B", role.label()))
                        .small()
                        .ghost()
                        .selected(selected)
                        .disabled(self.busy || self.executing)
                        .on_click(cx.listener(
                            move |page, _, window, cx| page.select_file(index, window, cx),
                        ))
                    })),
            )
            .child(
                div()
                    .px_3()
                    .py_2()
                    .border_t_1()
                    .border_b_1()
                    .border_color(tokens.border)
                    .font_semibold()
                    .child(format!("完整节点树 · {visible_node_count} / {node_count}")),
            )
            .child(
                div()
                    .flex_none()
                    .p_2()
                    .border_b_1()
                    .border_color(tokens.border)
                    .child(Input::new(&self.node_search_input).small())
                    .child(
                        div().mt_1().text_xs().text_color(tokens.muted).child(
                            "仅匹配节点静态类型与安全名称；不搜索参数、值、预览、原文或注释",
                        ),
                    ),
            )
            .child(
                uniform_list(
                    "middleware-node-tree",
                    visible_node_count,
                    cx.processor(move |page, range, _, cx| {
                        page.render_node_rows(
                            range,
                            visible_nodes.as_slice(),
                            node_revision,
                            tokens,
                            cx,
                        )
                    }),
                )
                .flex_1()
                .min_h_0()
                .track_scroll(self.node_scroll.clone()),
            )
            .into_any_element()
    }

    fn render_node_rows(
        &mut self,
        range: Range<usize>,
        visible_nodes: &[usize],
        revision: u64,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> Vec<AnyElement> {
        let Some(document) = self.model.selected_draft() else {
            return Vec::new();
        };
        range
            .filter_map(|visible_index| {
                let index = *visible_nodes.get(visible_index)?;
                let node = document.nodes().get(index)?;
                let selected = self.model.selected_node == Some(index);
                let label = node_kind_label(node.kind, node.name.as_deref());
                let preview = document.node_preview(index);
                let depth = node.depth.min(12) as f32 * 12.0;
                Some(
                    div()
                        .id(SharedString::from(format!("middleware-node-{index}")))
                        .h(px(42.0))
                        .px_2()
                        .pl(px(8.0 + depth))
                        .border_b_1()
                        .border_color(tokens.border)
                        .bg(if selected {
                            tokens.surface_alt
                        } else {
                            tokens.surface
                        })
                        .cursor_pointer()
                        .on_click(cx.listener(move |page, _, window, cx| {
                            page.select_node(index, revision, window, cx)
                        }))
                        .child(
                            div()
                                .text_xs()
                                .font_semibold()
                                .text_color(if node.editable_value.is_some() {
                                    tokens.accent
                                } else {
                                    tokens.muted
                                })
                                .child(label),
                        )
                        .child(
                            div()
                                .text_xs()
                                .text_color(tokens.text)
                                .overflow_hidden()
                                .child(preview),
                        )
                        .into_any_element(),
                )
            })
            .collect()
    }

    fn render_detail(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let content = match self.model.tab {
            DetailTab::Overview => self.render_overview(tokens),
            DetailTab::Visual => self.render_visual(tokens, cx),
            DetailTab::Raw => self.render_raw(tokens, cx),
            DetailTab::Diff => self.render_diff(tokens),
            DetailTab::History => self.render_history(tokens, cx),
        };
        div()
            .flex_1()
            .min_w_0()
            .min_h_0()
            .rounded_lg()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .flex()
            .flex_col()
            .child(
                div()
                    .h(px(42.0))
                    .flex_none()
                    .overflow_x_scrollbar()
                    .px_2()
                    .border_b_1()
                    .border_color(tokens.border)
                    .flex()
                    .items_center()
                    .gap_1()
                    .children(DetailTab::ALL.into_iter().map(|tab| {
                        crate::buttons::button(SharedString::from(format!(
                            "middleware-detail-{tab:?}"
                        )))
                        .label(tab.label())
                        .small()
                        .ghost()
                        .selected(self.model.tab == tab)
                        .on_click(cx.listener(move |page, _, _, cx| page.set_tab(tab, cx)))
                    })),
            )
            .child(div().flex_1().min_h_0().child(content))
            .into_any_element()
    }

    fn render_overview(&self, tokens: ThemeTokens) -> AnyElement {
        let product = self.model.product;
        let boundary = product_boundary(product);
        let mut rows = vec![
            ("产品", product.label().to_owned()),
            ("配置校验", product.validator().label().to_owned()),
            ("应用方式", product.activation().label().to_owned()),
            ("安全边界", boundary.to_owned()),
        ];
        if let Some(instance) = self.model.selected_instance() {
            rows.extend([
                ("systemd unit", instance.unit().to_owned()),
                (
                    "ExecStart 可执行文件",
                    instance.binary_path().as_str().to_owned(),
                ),
                ("主配置", instance.primary_config().as_str().to_owned()),
                ("配置根", instance.config_root().as_str().to_owned()),
                ("版本", instance.version().to_owned()),
            ]);
        }
        div()
            .size_full()
            .min_h_0()
            .overflow_y_scrollbar()
            .p_4()
            .flex()
            .flex_col()
            .gap_2()
            .children(rows.into_iter().map(|(label, value)| {
                div()
                    .rounded_md()
                    .bg(tokens.surface_alt)
                    .p_3()
                    .child(div().text_xs().text_color(tokens.muted).child(label))
                    .child(div().mt_1().text_sm().child(value))
            }))
            .when_some(self.model.bundle.as_ref(), |view, bundle| {
                view.child(
                    div()
                        .rounded_md()
                        .border_1()
                        .border_color(if bundle.unresolved_includes().is_empty() {
                            tokens.border
                        } else {
                            tokens.warning
                        })
                        .p_3()
                        .text_sm()
                        .child(format!(
                            "已读取 {} 个文件 / {} B；未解析 include {} 项",
                            bundle.files().len(),
                            bundle.total_bytes(),
                            bundle.unresolved_includes().len()
                        )),
                )
            })
            .into_any_element()
    }

    fn render_visual(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let explanation = self.model.selected_node.and_then(|index| {
            explain_node(self.model.selected_draft()?, index, self.model.product)
        });
        let has_selected = explanation.is_some();
        let selected_sensitive = explanation
            .as_ref()
            .is_some_and(|explanation| explanation.sensitive);
        let sensitive_value_empty = selected_sensitive
            && self
                .value_input
                .as_ref()
                .is_none_or(|input| input.read(cx).value().is_empty());
        div()
            .size_full()
            .min_h_0()
            .overflow_y_scrollbar()
            .p_4()
            .when_some(explanation, |view, explanation| {
                view.child(
                    div()
                        .child(
                            div()
                                .font_semibold()
                                .child(explanation.label),
                        )
                        .child(
                            div()
                                .mt_1()
                                .text_xs()
                                .text_color(tokens.muted)
                                .child(format!(
                                    "byte {}..{}",
                                    explanation.span_start, explanation.span_end
                                )),
                        )
                        .child(
                            div()
                                .mt_3()
                                .rounded_md()
                                .border_1()
                                .border_color(tokens.border)
                                .bg(tokens.surface_alt)
                                .p_3()
                                .flex()
                                .flex_col()
                                .gap_1()
                                .child(explanation_row(
                                    "结构类型",
                                    explanation.kind.to_owned(),
                                    tokens,
                                ))
                                .child(explanation_row(
                                    "结构含义",
                                    explanation.meaning.to_owned(),
                                    tokens,
                                ))
                                .child(explanation_row(
                                    "层级",
                                    explanation.depth.to_string(),
                                    tokens,
                                ))
                                .child(explanation_row(
                                    "直接子项数",
                                    explanation.child_count.to_string(),
                                    tokens,
                                ))
                                .child(explanation_row(
                                    "敏感内容",
                                    if explanation.sensitive { "是" } else { "否" }.to_owned(),
                                    tokens,
                                ))
                                .child(explanation_row(
                                    "预览截断",
                                    if explanation.preview_truncated {
                                        "是"
                                    } else {
                                        "否"
                                    }
                                    .to_owned(),
                                    tokens,
                                ))
                                .child(explanation_row(
                                    "可操作",
                                    explanation.actionability.to_owned(),
                                    tokens,
                                ))
                                .child(explanation_row(
                                    "语义验证",
                                    SYNTAX_ONLY_UNKNOWN.to_owned(),
                                    tokens,
                                )),
                        )
                        .when_some(self.value_input.clone(), |panel, input| {
                            panel
                                .when(selected_sensitive, |panel| {
                                    panel.child(
                                        div()
                                            .mt_3()
                                            .text_xs()
                                            .text_color(tokens.warning)
                                            .child("敏感值由 core 保留且不会回显；输入新值后以掩码方式生成替换意图，清空必须使用单独的明确按钮。"),
                                    )
                                })
                                .child(div().mt_3().h(px(110.0)).child(Input::new(&input)))
                                .child(
                                    div().mt_3().child(
                                        crate::buttons::button("middleware-apply-span")
                                            .label("应用精确 span 修改")
                                            .primary()
                                            .disabled(
                                                self.raw_dirty
                                                    || sensitive_value_empty
                                                    || middleware_mutations_disabled(
                                                        self.model.product,
                                                    ),
                                            )
                                            .on_click(cx.listener(|page, _, window, cx| {
                                                page.apply_span_patch(window, cx)
                                            })),
                                    ),
                                )
                                .when(selected_sensitive, |panel| {
                                    panel.child(
                                        div().mt_2().child(
                                            crate::buttons::button(
                                                "middleware-clear-sensitive-span",
                                            )
                                            .label("明确清空敏感值")
                                            .danger()
                                            .disabled(
                                                self.raw_dirty
                                                    || middleware_mutations_disabled(
                                                        self.model.product,
                                                    ),
                                            )
                                            .on_click(cx.listener(|page, _, window, cx| {
                                                page.clear_sensitive_span(window, cx)
                                            })),
                                        ),
                                    )
                                })
                        }),
                )
            })
            .when(!has_selected, |view| {
                view.child(
                    div()
                        .text_color(tokens.muted)
                        .child("选择中栏任意节点。注释、空白、include、未知指令与未识别节点均完整显示且不会被序列化丢失。"),
                )
            })
            .into_any_element()
    }

    fn render_raw(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let sensitive = self
            .model
            .selected_draft()
            .is_some_and(MiddlewareDraft::contains_sensitive_values);
        let unavailable_raw = self
            .model
            .selected_draft()
            .is_some_and(|draft| draft.safe_raw_text().is_none());
        let invalid_utf8 = unavailable_raw && !sensitive;
        div()
            .size_full()
            .min_h_0()
            .p_3()
            .flex()
            .flex_col()
            .gap_2()
            .child(
                div()
                    .flex_none()
                    .text_xs()
                    .text_color(tokens.warning)
                    .child("凭据类正文只由 core 保留；不会进入普通 GPUI 文本状态、通知、调试、历史或操作 metadata。"),
            )
            .when_some(self.raw_input.clone(), |view, input| {
                view.child(div().flex_1().min_h_0().child(Input::new(&input).h_full()))
                    .child(
                        div()
                            .flex_none()
                            .flex()
                            .justify_end()
                            .gap_2()
                            .child(
                                crate::buttons::button("middleware-discard-raw")
                                    .label("丢弃草稿")
                                    .disabled(!self.model.has_changes() && !self.raw_dirty)
                                    .on_click(cx.listener(|page, _, window, cx| {
                                        page.discard_draft(window, cx)
                                    })),
                            )
                            .child(
                                crate::buttons::button("middleware-accept-raw")
                                    .label("更新本地原文草稿")
                                    .primary()
                                    .disabled(
                                        !self.raw_dirty
                                            || middleware_mutations_disabled(self.model.product),
                                    )
                                    .on_click(cx.listener(|page, _, window, cx| {
                                        page.apply_raw_edit(window, cx)
                                    })),
                            ),
                    )
            })
            .when(invalid_utf8, |view| {
                view.child(
                    div()
                        .flex_1()
                        .rounded_md()
                        .border_1()
                        .border_color(tokens.warning)
                        .p_4()
                        .text_color(tokens.warning)
                        .child("该文件不是 UTF-8：仅展示字节长度与未识别节点元数据，拒绝原文及结构化编辑，避免损坏原始字节。"),
                )
            })
            .when(sensitive, |view| {
                view.child(
                    div()
                        .flex_1()
                        .rounded_md()
                        .border_1()
                        .border_color(tokens.warning)
                        .p_4()
                        .text_color(tokens.warning)
                        .child("该文件含凭据类配置：core 保留完整原文，但拒绝复制到普通文本编辑器。请在“可视化”页选择敏感节点，以掩码输入替换其值；其他字节保持不变。"),
                )
            })
            .when(self.raw_input.is_none() && !unavailable_raw, |view| {
                view.child(
                    div()
                        .flex_1()
                        .flex()
                        .items_center()
                        .justify_center()
                        .text_color(tokens.muted)
                        .child("选择一个配置文件查看完整原文"),
                )
            })
            .into_any_element()
    }

    fn render_diff(&self, _tokens: ThemeTokens) -> AnyElement {
        let diff = self
            .model
            .selected_snapshot()
            .zip(self.model.selected_draft())
            .map_or_else(
                || "选择配置文件后显示差异".to_owned(),
                |(snapshot, draft)| draft.safe_diff(snapshot),
            );
        div()
            .size_full()
            .min_h_0()
            .overflow_scrollbar()
            .p_4()
            .font_family("Cascadia Mono")
            .text_sm()
            .whitespace_nowrap()
            .child(diff)
            .into_any_element()
    }

    fn render_history(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let records = self
            .model
            .history
            .iter()
            .filter(|record| record.product == self.model.product)
            .cloned()
            .collect::<Vec<_>>();
        div()
            .size_full()
            .min_h_0()
            .overflow_y_scrollbar()
            .p_3()
            .flex()
            .flex_col()
            .gap_2()
            .when(records.is_empty(), |list| {
                list.child(
                    div()
                        .p_4()
                        .text_color(tokens.muted)
                        .child("当前目标没有该产品的变更历史"),
                )
            })
            .children(records.into_iter().map(|record| {
                let can_restore = matches!(
                    record.state,
                    MiddlewareChangeState::RecoveryPending
                        | MiddlewareChangeState::Applied
                        | MiddlewareChangeState::RestoreFailed
                );
                let restore_label = match record.state {
                    MiddlewareChangeState::RecoveryPending => "核对并生成恢复计划",
                    MiddlewareChangeState::RestoreFailed => "重试恢复计划",
                    _ => "生成恢复计划",
                };
                let record_id = record.id.clone();
                div()
                    .rounded_md()
                    .border_1()
                    .border_color(tokens.border)
                    .p_3()
                    .child(div().font_semibold().child(format!(
                        "{} · {}",
                        record.unit,
                        change_state_label(record.state)
                    )))
                    .child(
                        div()
                            .mt_1()
                            .text_xs()
                            .text_color(tokens.muted)
                            .child(format!(
                                "{} · {} B → {} B · {} · {}",
                                record.path.as_str(),
                                record.old_bytes,
                                record.new_bytes,
                                record.validator.label(),
                                record.activation.label()
                            )),
                    )
                    .child(
                        div().mt_1().text_xs().text_color(tokens.muted).child(
                            record
                                .updated_at
                                .format("%Y-%m-%d %H:%M:%S UTC")
                                .to_string(),
                        ),
                    )
                    .when(can_restore, |row| {
                        row.child(
                            div().mt_2().flex().justify_end().child(
                                crate::buttons::button(SharedString::from(format!(
                                    "middleware-restore-{}",
                                    record_id
                                )))
                                .label(restore_label)
                                .small()
                                .disabled(
                                    self.busy
                                        || self.executing
                                        || self.pending.is_some()
                                        || middleware_mutations_disabled(self.model.product),
                                )
                                .on_click(cx.listener(
                                    move |page, _, _, cx| {
                                        page.prepare_restore(record_id.clone(), cx)
                                    },
                                )),
                            ),
                        )
                    })
            }))
            .into_any_element()
    }
}

impl Render for MiddlewarePage {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.ensure_editor(window, cx);
        let tokens = self.shared.read(cx).theme.tokens();
        let pending = self.pending.as_ref().map(|plan| {
            let definition = plan.definition();
            let preview = plan.preview();
            (
                definition.id.clone(),
                definition.target.identity.as_str().to_owned(),
                definition.target.generation,
                preview.path.as_str().to_owned(),
                preview.old_sha256.clone(),
                preview.new_sha256.clone(),
                preview.old_bytes,
                preview.new_bytes,
                preview.changed_lines,
                preview.validator.label(),
                preview.activation.label(),
            )
        });
        div()
            .relative()
            .size_full()
            .min_h_0()
            .child(
                div()
                    .id("middleware-page-scroll")
                    .size_full()
                    .min_w(px(980.0))
                    .min_h(px(460.0))
                    .overflow_scroll()
                    .track_scroll(&self.page_scroll)
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(
                        div()
                    .flex_none()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(
                        div()
                            .text_sm()
                            .text_color(tokens.muted)
                            .child(product_boundary(self.model.product)),
                    )
                    .child(div().flex_1())
                    .child(
                        crate::buttons::button("middleware-refresh")
                            .label(if self.busy { "处理中…" } else { "重新探测" })
                            .small()
                            .disabled(self.busy || self.executing)
                            .on_click(cx.listener(|page, _, _, cx| page.refresh(cx))),
                    ),
                    )
            .when_some(self.error.clone(), |view, error| {
                view.child(message_banner(error, tokens.danger, tokens))
            })
            .when_some(
                middleware_mutation_disabled_reason(self.model.product),
                |view, reason| {
                    view.child(message_banner(reason.into(), tokens.warning, tokens))
                },
            )
            .when_some(self.notice.clone(), |view, notice| {
                view.child(message_banner(notice, tokens.accent, tokens))
            })
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .flex()
                    .gap_3()
                    .child(self.render_left(tokens, cx))
                    .child(self.render_middle(tokens, cx))
                    .child(self.render_detail(tokens, cx)),
            )
            .when_some(pending, |view, pending| {
                let (
                    plan_id,
                    target,
                    generation,
                    path,
                    old_hash,
                    new_hash,
                    old_bytes,
                    new_bytes,
                    changed_lines,
                    validator,
                    activation,
                ) = pending;
                view.child(
                    div()
                        .flex_none()
                        .rounded_lg()
                        .border_1()
                        .border_color(tokens.danger)
                        .bg(tokens.surface)
                        .p_3()
                        .flex()
                        .items_center()
                        .gap_3()
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .child(
                                    div()
                                        .font_semibold()
                                        .text_color(tokens.danger)
                                        .child("危险操作精确确认"),
                                )
                                .child(div().text_sm().child(format!(
                                    "{path} · {old_bytes} B → {new_bytes} B · {changed_lines} 行变化 · {validator} · {activation}"
                                )))
                                .child(
                                    div()
                                        .text_xs()
                                        .text_color(tokens.muted)
                                        .child(format!(
                                            "计划 {plan_id} · 目标 {target} / epoch {generation} · SHA {}… → {}…",
                                            &old_hash[..12.min(old_hash.len())],
                                            &new_hash[..12.min(new_hash.len())]
                                        )),
                                ),
                        )
                        .child(
                            crate::buttons::button("middleware-cancel-plan")
                                .label("取消")
                                .small()
                                .disabled(self.executing)
                                .on_click(cx.listener(|page, _, _, cx| {
                                    page.pending = None;
                                    cx.notify();
                                })),
                        )
                        .child(
                            crate::buttons::button("middleware-confirm-plan")
                                .label("确认执行")
                                .danger()
                                .small()
                                .disabled(
                                    self.executing
                                        || middleware_mutations_disabled(self.model.product),
                                )
                                .on_click(cx.listener(|page, _, _, cx| page.approve_pending(cx))),
                        ),
                )
            })
                    .when(self.pending.is_none(), |view| {
                view.child(
                    div()
                        .flex_none()
                        .flex()
                        .justify_end()
                        .child(
                            crate::buttons::button("middleware-create-plan")
                                .label(if self.busy { "生成中…" } else { "生成不可变变更计划" })
                                .primary()
                                .disabled(
                                    self.busy
                                        || self.executing
                                        || self.raw_dirty
                                        || !self.model.has_changes()
                                        || middleware_mutations_disabled(self.model.product),
                                )
                                .on_click(cx.listener(|page, _, _, cx| page.prepare_plan(cx))),
                        ),
                )
                    }),
            )
            .vertical_scrollbar(&self.page_scroll)
    }
}

fn bounded_node_search_query(value: &str) -> String {
    value.chars().take(MAX_NODE_SEARCH_CHARS).collect()
}

fn contains_search_term(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

fn node_kind_name(kind: MiddlewareDocumentNodeKind) -> &'static str {
    match kind {
        MiddlewareDocumentNodeKind::Preamble => "前导字节",
        MiddlewareDocumentNodeKind::Whitespace => "空白 / 空行",
        MiddlewareDocumentNodeKind::Comment => "注释",
        MiddlewareDocumentNodeKind::Directive => "指令（未知项亦原样保留）",
        MiddlewareDocumentNodeKind::BlockStart => "块开始",
        MiddlewareDocumentNodeKind::BlockEnd => "块结束",
        MiddlewareDocumentNodeKind::ElementStart => "元素开始",
        MiddlewareDocumentNodeKind::ElementEnd => "元素结束",
        MiddlewareDocumentNodeKind::Attribute => "属性",
        MiddlewareDocumentNodeKind::Text => "文本",
        MiddlewareDocumentNodeKind::Cdata => "CDATA",
        MiddlewareDocumentNodeKind::ProcessingInstruction => "处理指令",
        MiddlewareDocumentNodeKind::Declaration => "声明",
        MiddlewareDocumentNodeKind::Opaque => "未识别 / 不透明",
    }
}

fn node_kind_label(kind: MiddlewareDocumentNodeKind, name: Option<&str>) -> String {
    let kind = if kind == MiddlewareDocumentNodeKind::Directive && name == Some("include") {
        "include"
    } else {
        node_kind_name(kind)
    };
    name.map_or_else(|| kind.to_owned(), |name| format!("{kind} · {name}"))
}

fn node_kind_meaning(kind: MiddlewareDocumentNodeKind) -> &'static str {
    match kind {
        MiddlewareDocumentNodeKind::Preamble => "文件前导标记；按原字节保留",
        MiddlewareDocumentNodeKind::Whitespace => "空白或换行；仅用于保持原始排版",
        MiddlewareDocumentNodeKind::Comment => "注释节点；正文不参与搜索",
        MiddlewareDocumentNodeKind::Directive => "词法指令；名称不代表已获语义授权",
        MiddlewareDocumentNodeKind::BlockStart => "配置块起点；其后更深层节点属于该块",
        MiddlewareDocumentNodeKind::BlockEnd => "配置块结束边界",
        MiddlewareDocumentNodeKind::ElementStart => "XML 元素起点；可包含属性与子节点",
        MiddlewareDocumentNodeKind::ElementEnd => "XML 元素结束边界",
        MiddlewareDocumentNodeKind::Attribute => "XML 属性；仅精确值 span 可能可编辑",
        MiddlewareDocumentNodeKind::Text => "XML 文本内容",
        MiddlewareDocumentNodeKind::Cdata => "XML CDATA 内容；按原文保留",
        MiddlewareDocumentNodeKind::ProcessingInstruction => "XML 处理指令；按原文保留",
        MiddlewareDocumentNodeKind::Declaration => "声明节点；按原文保留",
        MiddlewareDocumentNodeKind::Opaque => "解析器未识别内容；正文与名称均不参与搜索",
    }
}

fn node_is_sensitive(draft: &MiddlewareDraft, index: usize) -> bool {
    if draft
        .editable_value(index)
        .is_some_and(|value| value.sensitive)
    {
        return true;
    }
    // `node_preview` is a bounded, core-redacted UI API. Only its static
    // redaction marker is inspected here; preview text never becomes a search field.
    draft
        .node_preview(index)
        .starts_with(SENSITIVE_NODE_PREVIEW_PREFIX)
}

fn node_matches_search(node: &MiddlewareDocumentNode, sensitive: bool, query: &str) -> bool {
    let query = query.trim();
    if query.is_empty() || contains_search_term(node_kind_name(node.kind), query) {
        return true;
    }
    if sensitive
        || matches!(
            node.kind,
            MiddlewareDocumentNodeKind::Comment | MiddlewareDocumentNodeKind::Opaque
        )
    {
        return false;
    }
    node.name
        .as_deref()
        .is_some_and(|name| contains_search_term(name, query))
}

fn node_can_have_children(kind: MiddlewareDocumentNodeKind) -> bool {
    matches!(
        kind,
        MiddlewareDocumentNodeKind::BlockStart | MiddlewareDocumentNodeKind::ElementStart
    )
}

fn visible_node_indices(draft: &MiddlewareDraft, query: &str) -> Vec<usize> {
    visible_node_indices_with(draft.nodes(), query, |index| {
        node_is_sensitive(draft, index)
    })
}

fn visible_node_indices_with(
    nodes: &[MiddlewareDocumentNode],
    query: &str,
    mut is_sensitive: impl FnMut(usize) -> bool,
) -> Vec<usize> {
    if query.trim().is_empty() {
        return (0..nodes.len()).collect();
    }
    let mut visible = vec![false; nodes.len()];
    let mut parents = Vec::<(usize, usize)>::new();
    for (index, node) in nodes.iter().enumerate() {
        while parents
            .last()
            .is_some_and(|(depth, _)| *depth >= node.depth)
        {
            parents.pop();
        }
        if node_matches_search(node, is_sensitive(index), query) {
            visible[index] = true;
            for (_, parent_index) in &parents {
                visible[*parent_index] = true;
            }
        }
        if node_can_have_children(node.kind) {
            parents.push((node.depth, index));
        }
    }
    visible
        .into_iter()
        .enumerate()
        .filter_map(|(index, visible)| visible.then_some(index))
        .collect()
}

fn immediate_child_count(nodes: &[MiddlewareDocumentNode], index: usize) -> usize {
    let Some(node) = nodes
        .get(index)
        .filter(|node| node_can_have_children(node.kind))
    else {
        return 0;
    };
    nodes[index + 1..]
        .iter()
        .take_while(|candidate| candidate.depth > node.depth)
        .filter(|candidate| candidate.depth == node.depth + 1)
        .count()
}

fn retained_visible_selection(selected: Option<usize>, visible: &[usize]) -> Option<usize> {
    selected.filter(|selected| visible.contains(selected))
}

fn explain_node(
    draft: &MiddlewareDraft,
    index: usize,
    product: MiddlewareProduct,
) -> Option<MiddlewareNodeExplanation> {
    let node = draft.nodes().get(index)?;
    let sensitive = node_is_sensitive(draft, index);
    let preview_truncated = !sensitive && draft.node_preview(index).ends_with('…');
    let actionability = if node.editable_value.is_none() {
        "否 · 只读保留节点"
    } else if middleware_mutations_disabled(product) {
        "否 · Apache evidence seal 尚未接线"
    } else {
        "是 · 仅精确值 span 修改"
    };
    Some(MiddlewareNodeExplanation {
        label: node_kind_label(node.kind, node.name.as_deref()),
        kind: node_kind_name(node.kind),
        meaning: node_kind_meaning(node.kind),
        span_start: node.span.start(),
        span_end: node.span.end(),
        depth: node.depth,
        child_count: immediate_child_count(draft.nodes(), index),
        sensitive,
        preview_truncated,
        actionability,
    })
}

fn explanation_row(label: &'static str, value: String, tokens: ThemeTokens) -> impl IntoElement {
    div()
        .flex()
        .gap_2()
        .text_xs()
        .child(
            div()
                .w(px(76.0))
                .flex_none()
                .text_color(tokens.muted)
                .child(label),
        )
        .child(div().min_w_0().text_color(tokens.text).child(value))
}

#[cfg(test)]
fn node_preview(
    document: &lovelyres_core::middleware_document::MiddlewareDocument,
    start: usize,
    end: usize,
) -> String {
    let bytes = document.raw_bytes().get(start..end).unwrap_or_default();
    if std::str::from_utf8(bytes).is_err() {
        return format!("<非 UTF-8 · {} B>", bytes.len());
    }
    let mut preview = String::new();
    for character in String::from_utf8_lossy(bytes).chars().take(180) {
        match character {
            '\n' => preview.push_str("\\n"),
            '\r' => preview.push_str("\\r"),
            '\t' => preview.push_str("\\t"),
            value if value.is_control() => preview.push('�'),
            value => preview.push(value),
        }
    }
    if String::from_utf8_lossy(bytes).chars().count() > 180 {
        preview.push('…');
    }
    preview
}

fn product_boundary(product: MiddlewareProduct) -> &'static str {
    match product {
        MiddlewareProduct::Nginx => "Nginx：官方 nginx -t 校验后平滑 reload；失败自动恢复原文件。",
        MiddlewareProduct::ApacheHttpd => {
            "Apache HTTPD：当前仅开放配置预览与只读发现；远端变更等待 evidence seal 接线。"
        }
        MiddlewareProduct::Redis => {
            "Redis：整文件无通用 configtest/reload；本页使用结构校验、restart 与健康回读。在线 CONFIG SET 属独立层级。"
        }
        MiddlewareProduct::Tomcat => {
            "Tomcat：server.xml 不能容器级 reload；本页使用 XML 结构校验、restart 与健康回读。"
        }
    }
}

fn change_state_label(state: MiddlewareChangeState) -> &'static str {
    match state {
        MiddlewareChangeState::RecoveryPending => "待核对恢复状态",
        MiddlewareChangeState::Applied => "已应用",
        MiddlewareChangeState::AutomaticallyRestored => "验证失败后已自动恢复",
        MiddlewareChangeState::RestoreFailed => "自动恢复失败",
    }
}

fn bounded_status_error(value: &str) -> String {
    const MAX_CHARS: usize = 640;
    let mut bounded = String::new();
    let mut truncated = false;
    for (index, character) in value.chars().enumerate() {
        if index >= MAX_CHARS {
            truncated = true;
            break;
        }
        bounded.push(if character.is_control() {
            ' '
        } else {
            character
        });
    }
    if truncated {
        bounded.push('…');
    }
    bounded
}

#[cfg(test)]
fn bounded_line_diff(before: &[u8], after: &[u8]) -> String {
    if before == after {
        return "无差异".to_owned();
    }
    let (Ok(before), Ok(after)) = (std::str::from_utf8(before), std::str::from_utf8(after)) else {
        return format!(
            "非 UTF-8 文件不生成文本差异；原始字节保持只读。\n{} B → {} B",
            before.len(),
            after.len()
        );
    };
    const MAX_DIFF_LINES: usize = 2_000;
    const MAX_DIFF_BYTES: usize = 256 * 1024;
    let left = before.lines().collect::<Vec<_>>();
    let right = after.lines().collect::<Vec<_>>();
    let mut output = String::new();
    let mut emitted = 0usize;
    for index in 0..left.len().max(right.len()) {
        let old = left.get(index).copied();
        let new = right.get(index).copied();
        if old == new {
            continue;
        }
        if let Some(old) = old {
            output.push_str(&format!("- {:>5} | {old}\n", index + 1));
        }
        if let Some(new) = new {
            output.push_str(&format!("+ {:>5} | {new}\n", index + 1));
        }
        emitted += 1;
        if emitted >= MAX_DIFF_LINES || output.len() >= MAX_DIFF_BYTES {
            output.push_str("… 差异预览已达到界面边界；计划仍使用完整字节 …\n");
            break;
        }
    }
    output
}

fn message_banner(
    message: SharedString,
    color: gpui::Rgba,
    tokens: ThemeTokens,
) -> impl IntoElement {
    div()
        .flex_none()
        .rounded_md()
        .border_1()
        .border_color(color)
        .bg(tokens.surface)
        .px_3()
        .py_2()
        .text_sm()
        .text_color(color)
        .child(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lovelyres_core::{
        middleware::MiddlewareActivationPolicy,
        middleware_document::{
            ByteSpan, MiddlewareDocument, MiddlewareDocumentNode, MiddlewareDocumentNodeKind,
            MiddlewareDocumentPatch, MiddlewareDocumentSyntax,
        },
        target::TargetIdentity,
    };

    fn binding(identity: &str, generation: u64) -> MiddlewareBinding {
        MiddlewareBinding {
            connection_id: identity.to_owned(),
            session_id: format!("session-{identity}"),
            target: TargetGuard {
                identity: TargetIdentity::new(identity).unwrap(),
                generation,
            },
        }
    }

    fn search_node(
        kind: MiddlewareDocumentNodeKind,
        name: Option<&str>,
        depth: usize,
    ) -> MiddlewareDocumentNode {
        MiddlewareDocumentNode {
            kind,
            name: name.map(str::to_owned),
            span: ByteSpan::new(0, 1),
            editable_value: None,
            depth,
        }
    }

    #[test]
    fn lifecycle_and_target_epoch_reject_late_results_and_clear_documents() {
        let mut model = MiddlewareModel::default();
        let first = binding("host-a", 1);
        model.activate(Some(first.clone()));
        let execution_generation = model.activation_generation;
        let lease = model.begin(RequestLane::Load, first.clone()).unwrap();
        model.selected_file = Some(0);
        assert!(model.accepts(&lease, Some(&first)));
        assert!(model.accepts_completion(
            execution_generation,
            MiddlewareProduct::Nginx,
            &first,
            Some(&first)
        ));
        model.rebind(Some(binding("host-b", 2)));
        assert!(model.drafts.is_empty());
        assert_eq!(model.selected_file, None);
        assert!(!model.accepts(&lease, model.binding.as_ref()));
        assert!(!model.accepts_completion(
            execution_generation,
            MiddlewareProduct::Nginx,
            &first,
            model.binding.as_ref()
        ));
        model.deactivate();
        assert!(model.drafts.is_empty());
    }

    #[test]
    fn apache_evidence_seal_disables_all_mutation_controls_with_a_static_reason() {
        assert!(middleware_mutations_disabled(
            MiddlewareProduct::ApacheHttpd
        ));
        assert_eq!(
            middleware_mutation_disabled_reason(MiddlewareProduct::ApacheHttpd),
            Some(APACHE_EVIDENCE_SEAL_DISABLED_REASON)
        );
        assert!(APACHE_EVIDENCE_SEAL_DISABLED_REASON.contains("exact runtime invocation provider"));
        assert!(
            APACHE_EVIDENCE_SEAL_DISABLED_REASON
                .contains("stable configuration graph evidence seal")
        );
        assert!(APACHE_EVIDENCE_SEAL_DISABLED_REASON.contains("预览与只读发现"));
        assert!(product_boundary(MiddlewareProduct::ApacheHttpd).contains("只读发现"));
        assert_eq!(
            SYNTAX_ONLY_UNKNOWN,
            "SyntaxOnlyUnknown · 仅识别结构语法，未做目标指令语义验证"
        );
    }

    #[test]
    fn nginx_mutation_controls_and_boundary_remain_unchanged() {
        assert!(!middleware_mutations_disabled(MiddlewareProduct::Nginx));
        assert_eq!(
            middleware_mutation_disabled_reason(MiddlewareProduct::Nginx),
            None
        );
        assert_eq!(
            product_boundary(MiddlewareProduct::Nginx),
            "Nginx：官方 nginx -t 校验后平滑 reload；失败自动恢复原文件。"
        );
        assert!(SYNTAX_ONLY_UNKNOWN.starts_with("SyntaxOnlyUnknown"));
    }

    #[test]
    fn node_search_is_bounded_and_never_uses_sensitive_opaque_or_comment_names() {
        let nodes = vec![
            search_node(MiddlewareDocumentNodeKind::BlockStart, Some("http"), 0),
            search_node(
                MiddlewareDocumentNodeKind::Directive,
                Some("server_name"),
                1,
            ),
            search_node(MiddlewareDocumentNodeKind::Directive, Some("password"), 1),
            search_node(
                MiddlewareDocumentNodeKind::Comment,
                Some("comment-secret"),
                1,
            ),
            search_node(MiddlewareDocumentNodeKind::Opaque, Some("opaque-secret"), 1),
            search_node(MiddlewareDocumentNodeKind::BlockEnd, None, 0),
        ];
        let sensitive = |index| index == 2;

        assert_eq!(
            visible_node_indices_with(&nodes, "SERVER_NAME", sensitive),
            vec![0, 1]
        );
        assert!(visible_node_indices_with(&nodes, "password", sensitive).is_empty());
        assert!(visible_node_indices_with(&nodes, "secret", sensitive).is_empty());
        assert_eq!(
            visible_node_indices_with(&nodes, "指令", sensitive),
            vec![0, 1, 2]
        );

        let overlong = "界".repeat(MAX_NODE_SEARCH_CHARS + 12);
        let bounded = bounded_node_search_query(&overlong);
        assert_eq!(bounded.chars().count(), MAX_NODE_SEARCH_CHARS);
    }

    #[test]
    fn node_search_does_not_match_arguments_values_previews_raw_text_or_comments() {
        let document = MiddlewareDocument::parse(
            MiddlewareDocumentSyntax::Nginx,
            b"# comment-only-secret\nworker_processes value-only-secret;\n".to_vec(),
        )
        .unwrap();
        let visible = |query| visible_node_indices_with(document.nodes(), query, |_| false);

        assert!(visible("comment-only-secret").is_empty());
        assert!(visible("value-only-secret").is_empty());
        assert_eq!(visible("worker_processes"), vec![2]);
    }

    #[test]
    fn filtered_tree_keeps_container_parent_chain_order_and_clears_hidden_selection() {
        let nodes = vec![
            search_node(MiddlewareDocumentNodeKind::BlockStart, Some("http"), 0),
            search_node(MiddlewareDocumentNodeKind::Directive, Some("listen"), 1),
            search_node(MiddlewareDocumentNodeKind::BlockStart, Some("server"), 1),
            search_node(
                MiddlewareDocumentNodeKind::Directive,
                Some("server_name"),
                2,
            ),
            search_node(MiddlewareDocumentNodeKind::BlockEnd, None, 1),
            search_node(MiddlewareDocumentNodeKind::BlockEnd, None, 0),
        ];
        let visible = visible_node_indices_with(&nodes, "server_name", |_| false);
        assert_eq!(visible, vec![0, 2, 3]);
        assert_eq!(retained_visible_selection(Some(3), &visible), Some(3));
        assert_eq!(retained_visible_selection(Some(1), &visible), None);
        assert_eq!(immediate_child_count(&nodes, 0), 3);
        assert_eq!(immediate_child_count(&nodes, 2), 1);
        assert_eq!(immediate_child_count(&nodes, 1), 0);
    }

    #[test]
    fn product_switch_rejects_late_request_and_execution_state_even_after_switch_back() {
        let mut model = MiddlewareModel::default();
        let target = binding("host-a", 1);
        model.activate(Some(target.clone()));
        let execution_generation = model.activation_generation;
        let lease = model.begin(RequestLane::Plan, target.clone()).unwrap();

        model.switch_product(MiddlewareProduct::ApacheHttpd);
        assert!(!model.accepts(&lease, Some(&target)));
        assert!(!model.accepts_completion(
            execution_generation,
            MiddlewareProduct::Nginx,
            &target,
            Some(&target)
        ));

        model.switch_product(MiddlewareProduct::Nginx);
        assert!(!model.accepts(&lease, Some(&target)));
    }

    #[test]
    fn complete_tree_keeps_comments_blank_lines_includes_and_unknown_content_visible() {
        let raw = b"# keep\n\ninclude conf.d/*.conf;\nfuture_directive value;\nhttp {\n";
        let document =
            MiddlewareDocument::parse(MiddlewareDocumentSyntax::Nginx, raw.to_vec()).unwrap();
        assert!(document.nodes().iter().any(|node| {
            node.kind == MiddlewareDocumentNodeKind::Comment
                && node_kind_label(node.kind, node.name.as_deref()).contains("注释")
        }));
        assert!(document.nodes().iter().any(|node| {
            node.kind == MiddlewareDocumentNodeKind::Whitespace
                && node_kind_label(node.kind, node.name.as_deref()).contains("空白")
        }));
        assert!(document.nodes().iter().any(|node| {
            node.name.as_deref() == Some("include")
                && node_kind_label(node.kind, node.name.as_deref()).contains("include")
        }));
        assert!(document.nodes().iter().any(|node| {
            node.name.as_deref() == Some("future_directive")
                && node_preview(&document, node.span.start(), node.span.end())
                    .contains("future_directive")
        }));
        assert!(
            document
                .nodes()
                .iter()
                .any(|node| node.kind == MiddlewareDocumentNodeKind::Opaque)
        );
    }

    #[test]
    fn structured_patch_changes_only_exact_value_and_raw_edit_preserves_every_other_byte() {
        let source = b"# password-like value stays local\nworker_processes  2;\nunknown x;\n";
        let document =
            MiddlewareDocument::parse(MiddlewareDocumentSyntax::Nginx, source.to_vec()).unwrap();
        let span = document
            .nodes()
            .iter()
            .find(|node| node.name.as_deref() == Some("worker_processes"))
            .and_then(|node| node.editable_value)
            .unwrap();
        let patched = document
            .apply_patches(&[MiddlewareDocumentPatch::new(span, "auto")])
            .unwrap();
        assert_eq!(
            patched.raw_bytes(),
            b"# password-like value stays local\nworker_processes  auto;\nunknown x;\n"
        );
        let replaced = patched
            .replace_raw("# password-like value stays local\nworker_processes auto;\nunknown y;\n")
            .unwrap();
        assert_eq!(
            replaced.raw_bytes(),
            b"# password-like value stays local\nworker_processes auto;\nunknown y;\n"
        );
    }

    #[test]
    fn non_utf8_diff_and_editor_boundary_never_lossily_rewrite_bytes() {
        let bytes = vec![b'a', 0xff, b'b'];
        let document =
            MiddlewareDocument::parse(MiddlewareDocumentSyntax::Redis, bytes.clone()).unwrap();
        assert!(std::str::from_utf8(document.raw_bytes()).is_err());
        assert_eq!(document.raw_bytes(), bytes);
        assert!(bounded_line_diff(&bytes, b"text").contains("不生成文本差异"));
    }

    #[test]
    fn product_activation_copy_matches_official_boundaries() {
        assert_eq!(
            MiddlewareProduct::Nginx.activation(),
            MiddlewareActivationPolicy::Reload
        );
        assert_eq!(
            MiddlewareProduct::ApacheHttpd.activation(),
            MiddlewareActivationPolicy::Reload
        );
        assert_eq!(
            MiddlewareProduct::Redis.activation(),
            MiddlewareActivationPolicy::Restart
        );
        assert_eq!(
            MiddlewareProduct::Tomcat.activation(),
            MiddlewareActivationPolicy::Restart
        );
        assert!(product_boundary(MiddlewareProduct::Redis).contains("CONFIG SET"));
        assert!(product_boundary(MiddlewareProduct::Tomcat).contains("不能容器级 reload"));
    }
}
