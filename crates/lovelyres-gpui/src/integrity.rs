use std::{collections::BTreeSet, ops::Range, sync::Arc};

use gpui::{
    AnyElement, Context, Entity, EventEmitter, IntoElement, Render, SharedString, Subscription,
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
    integrity::{
        INTEGRITY_PRESETS, IntegrityBaseline, IntegrityDiff, IntegrityDiffEntry, IntegrityDiffKind,
        IntegrityQuarantinePlan, IntegritySeverity,
    },
    operations::DangerousConfirmation,
    sftp::RemotePath,
    ssh::BoundSshSession,
    target::TargetGuard,
};
use tokio::task::AbortHandle;

use crate::{app::SharedAppState, runtime::TokioBridge, theme::ThemeTokens};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenIntegrityInSftp {
    target: TargetGuard,
    directory: RemotePath,
}

impl OpenIntegrityInSftp {
    pub fn target(&self) -> &TargetGuard {
        &self.target
    }

    pub fn directory(&self) -> &RemotePath {
        &self.directory
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct IntegrityBinding {
    connection_id: String,
    session_id: String,
    target: TargetGuard,
}

impl IntegrityBinding {
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
enum IntegrityRequestKind {
    Create,
    Compare(String),
    PlanQuarantine { baseline_id: String, path: String },
    ExecuteQuarantine { operation_id: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct IntegrityRequestLease {
    activation_generation: u64,
    request_id: u64,
    binding: IntegrityBinding,
    kind: IntegrityRequestKind,
}

#[derive(Debug)]
struct PendingQuarantine {
    plan: IntegrityQuarantinePlan,
    lease: IntegrityRequestLease,
}

#[derive(Debug)]
pub struct IntegrityModel {
    active: bool,
    activation_generation: u64,
    next_request_id: u64,
    latest_request_id: Option<u64>,
    binding: Option<IntegrityBinding>,
    selected_paths: BTreeSet<String>,
    baselines: Vec<IntegrityBaseline>,
    diff: Option<IntegrityDiff>,
    selected_diff_path: Option<String>,
}

impl Default for IntegrityModel {
    fn default() -> Self {
        Self {
            active: false,
            activation_generation: 0,
            next_request_id: 0,
            latest_request_id: None,
            binding: None,
            selected_paths: INTEGRITY_PRESETS
                .iter()
                .filter(|(_, _, selected)| *selected)
                .map(|(_, path, _)| (*path).to_owned())
                .collect(),
            baselines: Vec::new(),
            diff: None,
            selected_diff_path: None,
        }
    }
}

impl IntegrityModel {
    fn activate(&mut self, binding: Option<IntegrityBinding>) {
        self.active = true;
        self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
        self.rebind(binding);
    }

    fn deactivate(&mut self) {
        self.active = false;
        self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
        self.latest_request_id = None;
    }

    fn rebind(&mut self, binding: Option<IntegrityBinding>) {
        if self.binding == binding {
            return;
        }
        self.binding = binding;
        self.baselines.clear();
        self.diff = None;
        self.selected_diff_path = None;
        self.latest_request_id = None;
    }

    fn begin_request(
        &mut self,
        binding: IntegrityBinding,
        kind: IntegrityRequestKind,
    ) -> CoreResult<IntegrityRequestLease> {
        if !self.active {
            return Err(CoreError::Validation {
                subject: "integrity page",
                message: "page is not active".to_owned(),
            });
        }
        self.rebind(Some(binding.clone()));
        self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
        self.latest_request_id = Some(self.next_request_id);
        Ok(IntegrityRequestLease {
            activation_generation: self.activation_generation,
            request_id: self.next_request_id,
            binding,
            kind,
        })
    }

    fn accepts(&self, lease: &IntegrityRequestLease, binding: Option<&IntegrityBinding>) -> bool {
        self.active
            && self.activation_generation == lease.activation_generation
            && self.latest_request_id == Some(lease.request_id)
            && binding == Some(&lease.binding)
    }

    fn toggle_path(&mut self, path: &str) {
        if !self.selected_paths.remove(path) {
            self.selected_paths.insert(path.to_owned());
        }
    }

    fn apply_baselines(&mut self, baselines: Vec<IntegrityBaseline>) {
        self.baselines = baselines;
        if self.diff.as_ref().is_some_and(|diff| {
            !self
                .baselines
                .iter()
                .any(|item| item.id == diff.baseline_id)
        }) {
            self.diff = None;
            self.selected_diff_path = None;
        }
    }

    fn apply_diff(&mut self, diff: IntegrityDiff) {
        self.selected_diff_path = diff.entries.first().map(|entry| entry.path.clone());
        self.diff = Some(diff);
    }
}

pub struct IntegrityPage {
    services: Arc<BackendServices>,
    tokio: Arc<TokioBridge>,
    shared: Entity<SharedAppState>,
    model: IntegrityModel,
    custom_paths: Entity<InputState>,
    diff_scroll: UniformListScrollHandle,
    read_abort: Option<AbortHandle>,
    busy: bool,
    mutation_running: bool,
    pending_quarantine: Option<PendingQuarantine>,
    error: Option<SharedString>,
    notice: Option<SharedString>,
    _subscriptions: Vec<Subscription>,
}

impl IntegrityPage {
    pub fn new(
        services: Arc<BackendServices>,
        tokio: Arc<TokioBridge>,
        shared: Entity<SharedAppState>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let custom_paths = cx.new(|cx| {
            InputState::new(window, cx)
                .multi_line(true)
                .placeholder("自定义绝对路径，每行或逗号分隔（最多 16 项）")
        });
        let subscriptions = vec![
            cx.subscribe_in(
                &custom_paths,
                window,
                |page, _, event: &InputEvent, _, cx| {
                    if matches!(event, InputEvent::Change) {
                        page.error = None;
                        cx.notify();
                    }
                },
            ),
            cx.observe(&shared, |page, _, cx| page.handle_shared_change(cx)),
        ];
        Self {
            services,
            tokio,
            shared,
            model: IntegrityModel::default(),
            custom_paths,
            diff_scroll: UniformListScrollHandle::new(),
            read_abort: None,
            busy: false,
            mutation_running: false,
            pending_quarantine: None,
            error: None,
            notice: None,
            _subscriptions: subscriptions,
        }
    }

    pub fn activate(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.model.activate(self.current_binding(cx));
        self.custom_paths
            .update(cx, |input, cx| input.focus(window, cx));
        self.refresh_baselines(cx);
    }

    pub fn deactivate(&mut self, cx: &mut Context<Self>) {
        abort_task(&mut self.read_abort);
        self.model.deactivate();
        self.busy = false;
        self.pending_quarantine = None;
        cx.notify();
    }

    pub const fn is_active(&self) -> bool {
        self.model.active
    }

    fn current_binding(&self, cx: &Context<Self>) -> Option<IntegrityBinding> {
        IntegrityBinding::capture(self.shared.read(cx))
    }

    fn current_session(&self, cx: &Context<Self>) -> Option<BoundSshSession> {
        self.shared
            .read(cx)
            .active_ssh
            .as_ref()
            .map(|active| active.session.clone())
    }

    fn handle_shared_change(&mut self, cx: &mut Context<Self>) {
        if !self.model.active {
            return;
        }
        let binding = self.current_binding(cx);
        if self.model.binding == binding {
            return;
        }
        abort_task(&mut self.read_abort);
        self.model.rebind(binding);
        self.pending_quarantine = None;
        self.busy = false;
        self.error = None;
        if self.model.binding.is_some() {
            self.refresh_baselines(cx);
        } else {
            self.error = Some("未连接可信目标，无法使用文件完整性基线".into());
            cx.notify();
        }
    }

    fn refresh_baselines(&mut self, cx: &mut Context<Self>) {
        let Some(binding) = self.current_binding(cx) else {
            self.error = Some("未连接可信目标".into());
            return;
        };
        match self.services.integrity().list(&binding.target) {
            Ok(baselines) => {
                self.model.rebind(Some(binding));
                self.model.apply_baselines(baselines);
                self.error = None;
            }
            Err(error) => self.error = Some(format!("无法读取基线：{error}").into()),
        }
        cx.notify();
    }

    fn selected_paths(&self, cx: &Context<Self>) -> CoreResult<Vec<String>> {
        let mut paths = self
            .model
            .selected_paths
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        let custom = self.custom_paths.read(cx).value().to_string();
        paths.extend(
            custom
                .split([',', '\n', '\r'])
                .map(str::trim)
                .filter(|path| !path.is_empty())
                .map(ToOwned::to_owned),
        );
        paths.sort();
        paths.dedup();
        if paths.is_empty() {
            return Err(CoreError::Validation {
                subject: "integrity paths",
                message: "请至少选择一个路径".to_owned(),
            });
        }
        Ok(paths)
    }

    fn create_baseline(&mut self, cx: &mut Context<Self>) {
        if self.busy || self.mutation_running {
            return;
        }
        let paths = match self.selected_paths(cx) {
            Ok(paths) => paths,
            Err(error) => {
                self.error = Some(error.to_string().into());
                cx.notify();
                return;
            }
        };
        let Some(session) = self.current_session(cx) else {
            self.error = Some("未连接可信目标".into());
            return;
        };
        let binding = IntegrityBinding::from_session(&session);
        let lease = match self
            .model
            .begin_request(binding, IntegrityRequestKind::Create)
        {
            Ok(lease) => lease,
            Err(error) => {
                self.error = Some(error.to_string().into());
                return;
            }
        };
        self.mutation_running = true;
        self.error = None;
        self.notice = Some("正在计算远端 SHA-256 基线，目录较大时可能需要数分钟…".into());
        let service = self.services.integrity().clone();
        let task = self
            .tokio
            .spawn(async move { service.create_baseline(&session, paths).await });
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_create(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_create(
        &mut self,
        lease: IntegrityRequestLease,
        result: Result<CoreResult<IntegrityBaseline>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        self.mutation_running = false;
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            return;
        }
        match result {
            Ok(Ok(baseline)) => {
                self.notice = Some(format!("基线已建立：{} 个文件", baseline.file_count).into());
                self.error = None;
                self.refresh_baselines(cx);
            }
            Ok(Err(error)) => self.error = Some(format!("建立基线失败：{error}").into()),
            Err(error) => self.error = Some(format!("基线任务异常终止：{error}").into()),
        }
        cx.notify();
    }

    fn compare(&mut self, baseline_id: String, cx: &mut Context<Self>) {
        if self.busy || self.mutation_running {
            return;
        }
        let Some(session) = self.current_session(cx) else {
            self.error = Some("未连接可信目标".into());
            return;
        };
        let binding = IntegrityBinding::from_session(&session);
        let lease = match self
            .model
            .begin_request(binding, IntegrityRequestKind::Compare(baseline_id.clone()))
        {
            Ok(lease) => lease,
            Err(error) => {
                self.error = Some(error.to_string().into());
                return;
            }
        };
        abort_task(&mut self.read_abort);
        self.busy = true;
        self.error = None;
        self.notice = Some("正在重新扫描并校验基线摘要…".into());
        let service = self.services.integrity().clone();
        let task = self
            .tokio
            .spawn(async move { service.compare(&session, &baseline_id).await });
        self.read_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_compare(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_compare(
        &mut self,
        lease: IntegrityRequestLease,
        result: Result<CoreResult<IntegrityDiff>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            return;
        }
        self.busy = false;
        self.read_abort = None;
        match result {
            Ok(Ok(diff)) => {
                let count = diff.entries.len();
                self.notice = Some(
                    if count == 0 {
                        "未发现变化，当前文件与基线一致".to_owned()
                    } else {
                        format!("发现 {count} 项变化")
                    }
                    .into(),
                );
                self.model.apply_diff(diff);
                self.error = None;
            }
            Ok(Err(error)) => self.error = Some(format!("基线对比失败：{error}").into()),
            Err(error) if error.is_cancelled() => return,
            Err(error) => self.error = Some(format!("对比任务异常终止：{error}").into()),
        }
        cx.notify();
    }

    fn open_in_sftp(&mut self, path: String, cx: &mut Context<Self>) {
        let Some(binding) = self.current_binding(cx) else {
            self.error = Some("目标已经变化，已阻止打开旧差异".into());
            return;
        };
        let directory = path
            .rsplit_once('/')
            .map(|(parent, _)| parent)
            .unwrap_or("/");
        let directory = if directory.is_empty() { "/" } else { directory };
        match RemotePath::new(directory) {
            Ok(directory) => cx.emit(OpenIntegrityInSftp {
                target: binding.target,
                directory,
            }),
            Err(error) => self.error = Some(format!("无法打开远端目录：{error}").into()),
        }
        cx.notify();
    }

    fn plan_quarantine(&mut self, baseline_id: String, path: String, cx: &mut Context<Self>) {
        if self.busy || self.mutation_running || self.pending_quarantine.is_some() {
            return;
        }
        let Some(session) = self.current_session(cx) else {
            self.error = Some("未连接可信目标".into());
            return;
        };
        let binding = IntegrityBinding::from_session(&session);
        let lease = match self.model.begin_request(
            binding,
            IntegrityRequestKind::PlanQuarantine {
                baseline_id: baseline_id.clone(),
                path: path.clone(),
            },
        ) {
            Ok(lease) => lease,
            Err(error) => {
                self.error = Some(error.to_string().into());
                return;
            }
        };
        self.busy = true;
        self.error = None;
        self.notice = Some("正在重新验证该文件仍属于当前差异…".into());
        let service = self.services.integrity().clone();
        let task = self
            .tokio
            .spawn(async move { service.plan_quarantine(&session, &baseline_id, &path).await });
        self.read_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.finish_plan_quarantine(lease, result, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_plan_quarantine(
        &mut self,
        lease: IntegrityRequestLease,
        result: Result<CoreResult<IntegrityQuarantinePlan>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            return;
        }
        self.busy = false;
        self.read_abort = None;
        match result {
            Ok(Ok(plan)) => {
                self.pending_quarantine = Some(PendingQuarantine { plan, lease });
                self.notice = None;
                self.error = None;
            }
            Ok(Err(error)) => self.error = Some(format!("无法创建隔离计划：{error}").into()),
            Err(error) if error.is_cancelled() => return,
            Err(error) => self.error = Some(format!("隔离计划任务异常终止：{error}").into()),
        }
        cx.notify();
    }

    fn approve_quarantine(&mut self, cx: &mut Context<Self>) {
        if self.mutation_running {
            return;
        }
        let Some(pending) = self.pending_quarantine.take() else {
            return;
        };
        let Some(session) = self.current_session(cx) else {
            self.error = Some("目标已经断开，隔离计划已取消".into());
            return;
        };
        if IntegrityBinding::from_session(&session) != pending.lease.binding {
            self.error = Some("目标已经变化，隔离计划已取消".into());
            return;
        }
        let definition = pending.plan.definition().clone();
        let confirmation = DangerousConfirmation::approve(&definition);
        let operation_id = definition.id.clone();
        let lease = match self.model.begin_request(
            pending.lease.binding,
            IntegrityRequestKind::ExecuteQuarantine { operation_id },
        ) {
            Ok(lease) => lease,
            Err(error) => {
                self.error = Some(error.to_string().into());
                return;
            }
        };
        self.mutation_running = true;
        self.notice = Some("正在隔离并执行回读验证…".into());
        let service = self.services.integrity().clone();
        let journal = self.services.operation_journal().clone();
        let task = self.tokio.spawn(async move {
            service
                .execute_quarantine(&session, pending.plan, confirmation, &journal)
                .await
        });
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_quarantine(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_quarantine(
        &mut self,
        lease: IntegrityRequestLease,
        result: Result<
            CoreResult<lovelyres_core::integrity::IntegrityQuarantineOutcome>,
            tokio::task::JoinError,
        >,
        cx: &mut Context<Self>,
    ) {
        self.mutation_running = false;
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            return;
        }
        match result {
            Ok(Ok(outcome)) if outcome.verified => {
                self.notice = Some("文件已移入受管隔离目录，操作已记录并验证".into());
                self.error = None;
                if let IntegrityRequestKind::ExecuteQuarantine { .. } = lease.kind
                    && let Some(diff) = self.model.diff.as_ref()
                {
                    self.compare(diff.baseline_id.clone(), cx);
                    return;
                }
            }
            Ok(Ok(outcome)) => {
                self.error = Some(
                    format!(
                        "隔离验证失败{}：{}",
                        if outcome.restored_after_failed_verification {
                            "，已自动恢复"
                        } else {
                            ""
                        },
                        outcome.verification_detail
                    )
                    .into(),
                );
            }
            Ok(Err(error)) => self.error = Some(format!("隔离失败：{error}").into()),
            Err(error) => self.error = Some(format!("隔离任务异常终止：{error}").into()),
        }
        cx.notify();
    }

    fn cancel_quarantine(&mut self, cx: &mut Context<Self>) {
        self.pending_quarantine = None;
        self.notice = Some("隔离计划已取消，未执行任何远端变更".into());
        cx.notify();
    }

    fn render_diff_rows(
        &mut self,
        range: Range<usize>,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> Vec<AnyElement> {
        let Some(diff) = self.model.diff.as_ref() else {
            return Vec::new();
        };
        range
            .filter_map(|index| diff.entries.get(index).cloned().map(|entry| (index, entry)))
            .map(|(index, entry)| {
                let path = entry.path.clone();
                let selected = self.model.selected_diff_path.as_ref() == Some(&path);
                div()
                    .id(("integrity-diff-row", index))
                    .h(px(38.0))
                    .flex()
                    .items_center()
                    .gap_3()
                    .px_3()
                    .border_b_1()
                    .border_color(tokens.border)
                    .bg(if selected {
                        tokens.surface_alt
                    } else {
                        tokens.surface
                    })
                    .hover(|row| row.bg(tokens.surface_alt))
                    .cursor_pointer()
                    .on_click(cx.listener(move |page, _, _, cx| {
                        page.model.selected_diff_path = Some(path.clone());
                        cx.notify();
                    }))
                    .child(
                        div()
                            .w(px(74.0))
                            .text_xs()
                            .text_color(kind_color(entry.kind, tokens))
                            .child(kind_label(entry.kind)),
                    )
                    .child(
                        div()
                            .w(px(64.0))
                            .text_xs()
                            .text_color(severity_color(entry.severity, tokens))
                            .child(severity_label(entry.severity)),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .overflow_hidden()
                            .whitespace_nowrap()
                            .text_ellipsis()
                            .font_family("Cascadia Mono")
                            .text_sm()
                            .child(entry.path),
                    )
                    .into_any_element()
            })
            .collect()
    }
}

impl Render for IntegrityPage {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens = self.shared.read(cx).theme.tokens();
        let row_count = self
            .model
            .diff
            .as_ref()
            .map_or(0, |diff| diff.entries.len());
        let selected_entry = self.model.diff.as_ref().and_then(|diff| {
            let selected = self.model.selected_diff_path.as_ref()?;
            diff.entries
                .iter()
                .find(|entry| &entry.path == selected)
                .cloned()
        });
        let pending_summary = self
            .pending_quarantine
            .as_ref()
            .map(|pending| pending.plan.definition().summary.clone());

        div()
            .size_full()
            .min_h_0()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .child(div().text_lg().font_semibold().child("文件完整性"))
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(tokens.muted)
                                    .child("可信目标基线 · SHA-256 摘要校验 · 可逆隔离"),
                            ),
                    )
                    .child(
                        crate::buttons::button("integrity-refresh")
                            .label("刷新基线")
                            .small()
                            .disabled(self.busy || self.mutation_running)
                            .on_click(cx.listener(|page, _, _, cx| page.refresh_baselines(cx))),
                    ),
            )
            .when_some(self.error.clone(), |view, error| {
                view.child(message_banner(error, tokens.danger, tokens))
            })
            .when_some(self.notice.clone(), |view, notice| {
                view.child(message_banner(notice, tokens.accent, tokens))
            })
            .child(
                div()
                    .rounded_lg()
                    .border_1()
                    .border_color(tokens.border)
                    .bg(tokens.surface)
                    .p_4()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(div().font_semibold().child("建立新基线"))
                    .child(
                        div().flex().flex_wrap().gap_2().children(
                            INTEGRITY_PRESETS.iter().enumerate().map(
                                |(index, (label, path, _))| {
                                    let path = (*path).to_owned();
                                    crate::buttons::button(SharedString::from(format!("integrity-path-{index}")))
                                        .label(*label)
                                        .small()
                                        .selected(self.model.selected_paths.contains(&path))
                                        .disabled(self.busy || self.mutation_running)
                                        .on_click(cx.listener(move |page, _, _, cx| {
                                            page.model.toggle_path(&path);
                                            cx.notify();
                                        }))
                                },
                            ),
                        ),
                    )
                    .child(Input::new(&self.custom_paths).h(px(64.0)))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(tokens.muted)
                                    .child("清单保存在远端受管目录；本地仅保存目标绑定元数据和摘要"),
                            )
                            .child(
                                crate::buttons::button("integrity-create")
                                    .label(if self.mutation_running {
                                        "正在建立…"
                                    } else {
                                        "建立基线"
                                    })
                                    .primary()
                                    .small()
                                    .disabled(self.busy || self.mutation_running)
                                    .on_click(cx.listener(|page, _, _, cx| page.create_baseline(cx))),
                            ),
                    ),
            )
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .flex()
                    .gap_3()
                    .child(self.render_baselines(tokens, cx))
                    .child(self.render_diff(tokens, row_count, selected_entry, cx)),
            )
            .when_some(pending_summary, |view, summary| {
                view.child(
                    div()
                        .rounded_lg()
                        .border_1()
                        .border_color(tokens.danger)
                        .bg(tokens.surface)
                        .p_3()
                        .flex()
                        .items_center()
                        .justify_between()
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .child(div().font_semibold().text_color(tokens.danger).child("危险操作确认"))
                                .child(div().text_sm().child(summary))
                                .child(
                                    div()
                                        .text_xs()
                                        .text_color(tokens.muted)
                                        .child("文件将移出原位置；失败会自动尝试恢复，执行与验证结果写入操作日志。"),
                                ),
                        )
                        .child(
                            div()
                                .flex()
                                .gap_2()
                                .child(
                                    crate::buttons::button("integrity-quarantine-cancel")
                                        .label("取消")
                                        .small()
                                        .on_click(cx.listener(|page, _, _, cx| page.cancel_quarantine(cx))),
                                )
                                .child(
                                    crate::buttons::button("integrity-quarantine-approve")
                                        .label("确认隔离")
                                        .danger()
                                        .small()
                                        .on_click(cx.listener(|page, _, _, cx| page.approve_quarantine(cx))),
                                ),
                        ),
                )
            })
    }
}

impl IntegrityPage {
    fn render_baselines(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        div()
            .w(px(360.0))
            .min_h_0()
            .flex()
            .flex_col()
            .rounded_lg()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .child(
                div()
                    .h(px(40.0))
                    .px_3()
                    .flex()
                    .items_center()
                    .border_b_1()
                    .border_color(tokens.border)
                    .font_semibold()
                    .child(format!("基线记录 · {}", self.model.baselines.len())),
            )
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scrollbar()
                    .when(self.model.baselines.is_empty(), |list| {
                        list.child(div().p_5().text_sm().text_color(tokens.muted).child(
                            "当前可信目标尚无基线。建议进场后优先记录 Web 目录与系统二进制。",
                        ))
                    })
                    .children(self.model.baselines.iter().cloned().enumerate().map(
                        |(index, baseline)| {
                            let baseline_id = baseline.id.clone();
                            div()
                                .p_3()
                                .border_b_1()
                                .border_color(tokens.border)
                                .child(div().font_semibold().child(
                                    baseline.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
                                ))
                                .child(div().text_xs().text_color(tokens.muted).child(format!(
                                    "{} 个文件 · {}",
                                    baseline.file_count,
                                    baseline.paths.join(" · ")
                                )))
                                .child(
                                    div().mt_2().flex().justify_end().child(
                                        crate::buttons::button(SharedString::from(format!(
                                            "integrity-compare-{index}"
                                        )))
                                        .label("立即对比")
                                        .small()
                                        .primary()
                                        .disabled(self.busy || self.mutation_running)
                                        .on_click(
                                            cx.listener(move |page, _, _, cx| {
                                                page.compare(baseline_id.clone(), cx)
                                            }),
                                        ),
                                    ),
                                )
                        },
                    )),
            )
            .into_any_element()
    }

    fn render_diff(
        &self,
        tokens: ThemeTokens,
        row_count: usize,
        selected: Option<IntegrityDiffEntry>,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let summary = self.model.diff.as_ref().map(|diff| {
            format!(
                "新增 {} · 修改 {} · 删除 {}{}",
                diff.added,
                diff.modified,
                diff.removed,
                if diff.truncated {
                    " · 结果已截断"
                } else {
                    ""
                }
            )
        });
        let scroll = self.diff_scroll.clone();
        div()
            .flex_1()
            .min_w_0()
            .min_h_0()
            .flex()
            .flex_col()
            .rounded_lg()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .child(
                div()
                    .h(px(40.0))
                    .px_3()
                    .flex()
                    .items_center()
                    .justify_between()
                    .border_b_1()
                    .border_color(tokens.border)
                    .child(div().font_semibold().child("对比结果"))
                    .when_some(summary, |header, summary| {
                        header.child(div().text_xs().text_color(tokens.muted).child(summary))
                    }),
            )
            .child(diff_header(tokens))
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .when(row_count == 0, |body| {
                        body.child(
                            div()
                                .size_full()
                                .flex()
                                .items_center()
                                .justify_center()
                                .text_color(tokens.muted)
                                .child(if self.busy {
                                    "正在扫描…"
                                } else if self.model.diff.is_some() {
                                    "未发现变化"
                                } else {
                                    "选择一条基线开始对比"
                                }),
                        )
                    })
                    .when(row_count > 0, |body| {
                        body.child(
                            uniform_list(
                                "integrity-diff-rows",
                                row_count,
                                cx.processor(move |page, range: Range<usize>, _, cx| {
                                    page.render_diff_rows(range, tokens, cx)
                                }),
                            )
                            .size_full()
                            .track_scroll(scroll),
                        )
                    }),
            )
            .when_some(selected, |panel, entry| {
                let path_for_sftp = entry.path.clone();
                let path_for_quarantine = entry.path.clone();
                let baseline_id = self
                    .model
                    .diff
                    .as_ref()
                    .map(|diff| diff.baseline_id.clone())
                    .unwrap_or_default();
                panel.child(
                    div()
                        .border_t_1()
                        .border_color(tokens.border)
                        .p_3()
                        .flex()
                        .items_center()
                        .justify_between()
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .font_family("Cascadia Mono")
                                .text_sm()
                                .child(entry.path),
                        )
                        .child(
                            div()
                                .flex()
                                .gap_2()
                                .child(
                                    crate::buttons::button("integrity-open-sftp")
                                        .label("在 SFTP 中查看")
                                        .small()
                                        .disabled(entry.kind == IntegrityDiffKind::Removed)
                                        .on_click(cx.listener(move |page, _, _, cx| {
                                            page.open_in_sftp(path_for_sftp.clone(), cx)
                                        })),
                                )
                                .child(
                                    crate::buttons::button("integrity-plan-quarantine")
                                        .label("隔离文件")
                                        .danger()
                                        .small()
                                        .disabled(
                                            entry.kind == IntegrityDiffKind::Removed
                                                || self.busy
                                                || self.mutation_running
                                                || self.pending_quarantine.is_some(),
                                        )
                                        .on_click(cx.listener(move |page, _, _, cx| {
                                            page.plan_quarantine(
                                                baseline_id.clone(),
                                                path_for_quarantine.clone(),
                                                cx,
                                            )
                                        })),
                                ),
                        ),
                )
            })
            .into_any_element()
    }
}

impl EventEmitter<OpenIntegrityInSftp> for IntegrityPage {}

fn abort_task(task: &mut Option<AbortHandle>) {
    if let Some(task) = task.take() {
        task.abort();
    }
}

fn message_banner(
    message: SharedString,
    color: gpui::Rgba,
    tokens: ThemeTokens,
) -> impl IntoElement {
    div()
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

fn diff_header(tokens: ThemeTokens) -> impl IntoElement {
    div()
        .h(px(34.0))
        .flex()
        .items_center()
        .gap_3()
        .px_3()
        .bg(tokens.surface_alt)
        .border_b_1()
        .border_color(tokens.border)
        .text_xs()
        .text_color(tokens.muted)
        .child(div().w(px(74.0)).child("类型"))
        .child(div().w(px(64.0)).child("风险"))
        .child(div().flex_1().child("远端路径"))
}

const fn kind_label(kind: IntegrityDiffKind) -> &'static str {
    match kind {
        IntegrityDiffKind::Added => "新增",
        IntegrityDiffKind::Removed => "删除",
        IntegrityDiffKind::Modified => "修改",
    }
}

const fn severity_label(severity: IntegritySeverity) -> &'static str {
    match severity {
        IntegritySeverity::High => "高风险",
        IntegritySeverity::Medium => "中风险",
    }
}

const fn kind_color(kind: IntegrityDiffKind, tokens: ThemeTokens) -> gpui::Rgba {
    match kind {
        IntegrityDiffKind::Added => tokens.accent,
        IntegrityDiffKind::Modified => tokens.warning,
        IntegrityDiffKind::Removed => tokens.muted,
    }
}

const fn severity_color(severity: IntegritySeverity, tokens: ThemeTokens) -> gpui::Rgba {
    match severity {
        IntegritySeverity::High => tokens.danger,
        IntegritySeverity::Medium => tokens.warning,
    }
}

#[cfg(test)]
mod tests {
    use lovelyres_core::target::{TargetContext, TargetIdentity};

    use super::*;

    fn binding(context: &TargetContext, identity: &str, session: &str) -> IntegrityBinding {
        IntegrityBinding {
            connection_id: identity.to_owned(),
            session_id: session.to_owned(),
            target: context
                .activate(TargetIdentity::new(identity).unwrap())
                .unwrap(),
        }
    }

    #[test]
    fn stale_results_are_rejected_after_target_or_lifecycle_change() {
        let context = TargetContext::new();
        let first = binding(&context, "a", "session-a");
        let mut model = IntegrityModel::default();
        model.activate(Some(first.clone()));
        let lease = model
            .begin_request(first.clone(), IntegrityRequestKind::Compare("x".to_owned()))
            .unwrap();
        assert!(model.accepts(&lease, Some(&first)));

        let second = binding(&context, "b", "session-b");
        model.rebind(Some(second.clone()));
        assert!(!model.accepts(&lease, Some(&second)));
        model.deactivate();
        assert!(!model.accepts(&lease, Some(&first)));
    }

    #[test]
    fn default_paths_match_legacy_safety_profile_and_toggle_cleanly() {
        let mut model = IntegrityModel::default();
        assert_eq!(
            model.selected_paths,
            BTreeSet::from([
                "/bin".to_owned(),
                "/usr/bin".to_owned(),
                "/usr/sbin".to_owned(),
                "/var/www".to_owned(),
            ])
        );
        model.toggle_path("/etc");
        assert!(model.selected_paths.contains("/etc"));
        model.toggle_path("/etc");
        assert!(!model.selected_paths.contains("/etc"));
    }

    #[test]
    fn applying_diff_selects_stable_remote_path_without_interpreting_markup() {
        let mut model = IntegrityModel::default();
        let path = "/var/www/<script>alert(1)</script>.php".to_owned();
        model.apply_diff(IntegrityDiff {
            baseline_id: "baseline".to_owned(),
            entries: vec![IntegrityDiffEntry {
                path: path.clone(),
                kind: IntegrityDiffKind::Added,
                severity: IntegritySeverity::High,
            }],
            added: 1,
            removed: 0,
            modified: 0,
            truncated: false,
        });
        assert_eq!(model.selected_diff_path, Some(path));
    }
}
