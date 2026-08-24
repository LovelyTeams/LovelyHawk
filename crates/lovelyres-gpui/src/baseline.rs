use std::{collections::BTreeMap, sync::Arc};

use gpui::{
    AnyElement, Context, Entity, IntoElement, Render, SharedString, Subscription, Window, div,
    prelude::*, px,
};
use gpui_component::{
    Disableable, Selectable, Sizable, StyledExt,
    button::ButtonVariants,
    input::{Input, InputState},
    scroll::ScrollableElement,
};
use lovelyres_core::{
    BackendServices, CoreError, CoreResult,
    baseline::{
        BASELINE_CATALOG, BaselineCategory, BaselineChangePlan, BaselineChangeRecord,
        BaselineChangeRequest, BaselineChangeState, BaselineObservedValue,
        BaselineOperationOutcome, BaselineReloadPolicy, BaselineRestorePlan, BaselineRisk,
        BaselineScan, BaselineStatus, BaselineValueKind,
    },
    operations::{DangerousConfirmation, OperationPlan},
    ssh::BoundSshSession,
    target::TargetGuard,
};
use tokio::task::AbortHandle;

use crate::{app::SharedAppState, runtime::TokioBridge, theme::ThemeTokens};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BaselineTab {
    Catalog,
    Plan,
    History,
}

impl BaselineTab {
    const ALL: [Self; 3] = [Self::Catalog, Self::Plan, Self::History];

    const fn label(self) -> &'static str {
        match self {
            Self::Catalog => "基线目录",
            Self::Plan => "变更计划",
            Self::History => "恢复历史",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BaselineBinding {
    session_id: String,
    connection_id: String,
    target: TargetGuard,
}

impl BaselineBinding {
    fn from_session(session: &BoundSshSession) -> Self {
        Self {
            session_id: session.session_id().to_owned(),
            connection_id: session.connection_id().to_owned(),
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct BaselineLease {
    activation_generation: u64,
    request_id: u64,
    binding: BaselineBinding,
}

#[derive(Debug, Clone)]
enum PendingBaselinePlan {
    Changes(BaselineChangePlan),
    Restore(BaselineRestorePlan),
}

impl PendingBaselinePlan {
    fn definition(&self) -> &OperationPlan {
        match self {
            Self::Changes(plan) => plan.definition(),
            Self::Restore(plan) => plan.definition(),
        }
    }
}

#[derive(Debug)]
struct BaselineModel {
    active: bool,
    activation_generation: u64,
    next_request_id: u64,
    latest_request_id: Option<u64>,
    binding: Option<BaselineBinding>,
    tab: BaselineTab,
    category: BaselineCategory,
    selected_item: Option<String>,
    statuses: Vec<BaselineStatus>,
    queued: BTreeMap<String, String>,
    history: Vec<BaselineChangeRecord>,
    reload_policy: BaselineReloadPolicy,
}

impl Default for BaselineModel {
    fn default() -> Self {
        Self {
            active: false,
            activation_generation: 0,
            next_request_id: 0,
            latest_request_id: None,
            binding: None,
            tab: BaselineTab::Catalog,
            category: BaselineCategory::Ssh,
            selected_item: None,
            statuses: Vec::new(),
            queued: BTreeMap::new(),
            history: Vec::new(),
            reload_policy: BaselineReloadPolicy::Defer,
        }
    }
}

impl BaselineModel {
    fn activate(&mut self, binding: Option<BaselineBinding>) {
        self.active = true;
        self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
        self.rebind(binding);
    }

    fn deactivate(&mut self) {
        self.active = false;
        self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
        self.latest_request_id = None;
    }

    fn rebind(&mut self, binding: Option<BaselineBinding>) {
        if self.binding == binding {
            return;
        }
        self.binding = binding;
        self.latest_request_id = None;
        self.selected_item = None;
        self.statuses.clear();
        self.queued.clear();
        self.history.clear();
    }

    fn begin_request(&mut self, binding: BaselineBinding) -> CoreResult<BaselineLease> {
        if !self.active {
            return Err(CoreError::Validation {
                subject: "baseline page",
                message: "page is not active".to_owned(),
            });
        }
        self.rebind(Some(binding.clone()));
        self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
        self.latest_request_id = Some(self.next_request_id);
        Ok(BaselineLease {
            activation_generation: self.activation_generation,
            request_id: self.next_request_id,
            binding,
        })
    }

    fn accepts(&self, lease: &BaselineLease, binding: Option<&BaselineBinding>) -> bool {
        self.active
            && self.activation_generation == lease.activation_generation
            && self.latest_request_id == Some(lease.request_id)
            && binding == Some(&lease.binding)
    }

    fn status(&self, item_id: &str) -> Option<&BaselineStatus> {
        self.statuses
            .iter()
            .find(|status| status.item_id == item_id)
    }
}

pub struct BaselinePage {
    services: Arc<BackendServices>,
    tokio: Arc<TokioBridge>,
    shared: Entity<SharedAppState>,
    model: BaselineModel,
    value_input: Entity<InputState>,
    read_task_abort: Option<AbortHandle>,
    busy: bool,
    pending: Option<PendingBaselinePlan>,
    error: Option<SharedString>,
    notice: Option<SharedString>,
    _subscriptions: Vec<Subscription>,
}

impl BaselinePage {
    pub fn new(
        services: Arc<BackendServices>,
        tokio: Arc<TokioBridge>,
        shared: Entity<SharedAppState>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let value_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("选择一项后输入允许的配置值"));
        let subscriptions = vec![cx.observe(&shared, |page, _, cx| page.handle_shared_change(cx))];
        Self {
            services,
            tokio,
            shared,
            model: BaselineModel::default(),
            value_input,
            read_task_abort: None,
            busy: false,
            pending: None,
            error: None,
            notice: None,
            _subscriptions: subscriptions,
        }
    }

    pub fn activate(&mut self, _window: &mut Window, cx: &mut Context<Self>) {
        self.busy = false;
        self.model.activate(self.current_binding(cx));
        self.refresh(cx);
        cx.notify();
    }

    pub fn deactivate(&mut self, cx: &mut Context<Self>) {
        self.cancel_read_task();
        self.pending = None;
        self.model.deactivate();
        cx.notify();
    }

    pub const fn is_active(&self) -> bool {
        self.model.active
    }

    fn current_binding(&self, cx: &Context<Self>) -> Option<BaselineBinding> {
        BaselineBinding::capture(self.shared.read(cx))
    }

    fn current_session(&self, cx: &Context<Self>) -> Option<BoundSshSession> {
        self.shared
            .read(cx)
            .active_ssh
            .as_ref()
            .map(|active| active.session.clone())
    }

    fn cancel_read_task(&mut self) {
        if let Some(task) = self.read_task_abort.take() {
            task.abort();
        }
        self.model.latest_request_id = None;
    }

    fn handle_shared_change(&mut self, cx: &mut Context<Self>) {
        if !self.model.active {
            return;
        }
        let binding = self.current_binding(cx);
        if binding == self.model.binding {
            return;
        }
        self.cancel_read_task();
        self.pending = None;
        self.busy = false;
        self.model.rebind(binding);
        self.error = None;
        self.notice = None;
        if self.model.binding.is_some() {
            self.refresh(cx);
        } else {
            self.error = Some("未连接可信目标，无法读取或修改基线".into());
            cx.notify();
        }
    }

    fn begin(&mut self, session: &BoundSshSession) -> CoreResult<BaselineLease> {
        self.cancel_read_task();
        self.model
            .begin_request(BaselineBinding::from_session(session))
    }

    fn refresh(&mut self, cx: &mut Context<Self>) {
        if self.busy {
            return;
        }
        let Some(session) = self.current_session(cx) else {
            self.error = Some("未连接可信目标".into());
            return;
        };
        let lease = match self.begin(&session) {
            Ok(lease) => lease,
            Err(error) => {
                self.error = Some(error.to_string().into());
                return;
            }
        };
        self.busy = true;
        self.error = None;
        self.notice = Some("正在读取封闭基线目录的当前值…".into());
        let service = self.services.baseline().clone();
        let task = self.tokio.spawn(async move {
            let scan = service.scan(&session).await?;
            let history = service.list_history(session.target())?;
            Ok::<_, CoreError>((scan, history))
        });
        self.read_task_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_refresh(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_refresh(
        &mut self,
        lease: BaselineLease,
        result: Result<
            CoreResult<(BaselineScan, Vec<BaselineChangeRecord>)>,
            tokio::task::JoinError,
        >,
        cx: &mut Context<Self>,
    ) {
        if !self
            .model
            .accepts(&lease, self.current_binding(cx).as_ref())
        {
            return;
        }
        self.busy = false;
        self.read_task_abort = None;
        match result {
            Ok(Ok((scan, history))) => {
                self.model.statuses = scan.statuses;
                self.model.history = history;
                self.error = None;
                self.notice = None;
            }
            Ok(Err(error)) => self.error = Some(format!("读取基线失败：{error}").into()),
            Err(error) if error.is_cancelled() => return,
            Err(error) => self.error = Some(format!("基线任务异常终止：{error}").into()),
        }
        cx.notify();
    }

    fn select_category(&mut self, category: BaselineCategory, cx: &mut Context<Self>) {
        self.model.category = category;
        self.model.selected_item = None;
        cx.notify();
    }

    fn select_item(&mut self, item_id: String, window: &mut Window, cx: &mut Context<Self>) {
        let Ok(definition) = lovelyres_core::baseline::definition(&item_id) else {
            return;
        };
        let value = self
            .model
            .queued
            .get(&item_id)
            .cloned()
            .or_else(|| {
                self.model.status(&item_id).and_then(|status| {
                    if let BaselineObservedValue::Value(value) = &status.observed {
                        Some(value.clone())
                    } else {
                        None
                    }
                })
            })
            .unwrap_or_else(|| definition.recommendation.to_owned());
        self.model.selected_item = Some(item_id);
        self.value_input
            .update(cx, |input, cx| input.set_value(value, window, cx));
        cx.notify();
    }

    fn set_recommended(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(item_id) = self.model.selected_item.as_deref() else {
            return;
        };
        let Ok(definition) = lovelyres_core::baseline::definition(item_id) else {
            return;
        };
        self.value_input.update(cx, |input, cx| {
            input.set_value(definition.recommendation, window, cx)
        });
    }

    fn set_choice(&mut self, value: &'static str, window: &mut Window, cx: &mut Context<Self>) {
        self.value_input
            .update(cx, |input, cx| input.set_value(value, window, cx));
    }

    fn queue_selected(&mut self, cx: &mut Context<Self>) {
        let Some(item_id) = self.model.selected_item.clone() else {
            self.error = Some("请先选择一项基线".into());
            return;
        };
        let value = self.value_input.read(cx).value().to_string();
        match BaselineChangeRequest::new(item_id.clone(), value) {
            Ok(request) => {
                let already_current = self.model.status(&item_id).is_some_and(|status| {
                    status.observed == BaselineObservedValue::Value(request.value.clone())
                });
                if already_current {
                    self.model.queued.remove(&item_id);
                    self.notice = Some("该值与当前远端值一致，无需加入计划".into());
                } else {
                    self.model.queued.insert(item_id, request.value);
                    self.notice = Some("已加入待确认变更".into());
                    self.model.tab = BaselineTab::Plan;
                }
                self.error = None;
            }
            Err(error) => self.error = Some(format!("配置值无效：{error}").into()),
        }
        cx.notify();
    }

    fn remove_queued(&mut self, item_id: String, cx: &mut Context<Self>) {
        self.model.queued.remove(&item_id);
        cx.notify();
    }

    fn prepare_changes(&mut self, cx: &mut Context<Self>) {
        if self.busy || self.pending.is_some() {
            return;
        }
        let Some(session) = self.current_session(cx) else {
            self.error = Some("未连接可信目标".into());
            return;
        };
        let requests = self
            .model
            .queued
            .iter()
            .map(|(item_id, value)| BaselineChangeRequest::new(item_id.clone(), value.clone()))
            .collect::<CoreResult<Vec<_>>>();
        let requests = match requests {
            Ok(requests) if !requests.is_empty() => requests,
            Ok(_) => {
                self.error = Some("当前没有待应用的变更".into());
                return;
            }
            Err(error) => {
                self.error = Some(error.to_string().into());
                return;
            }
        };
        let lease = match self.begin(&session) {
            Ok(lease) => lease,
            Err(error) => {
                self.error = Some(error.to_string().into());
                return;
            }
        };
        self.busy = true;
        self.error = None;
        self.notice = Some("正在重读当前值并生成不可变变更计划…".into());
        let service = self.services.baseline().clone();
        let reload_policy = self.model.reload_policy;
        let task = self.tokio.spawn(async move {
            service
                .plan_changes(&session, requests, reload_policy)
                .await
        });
        self.read_task_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_change_plan(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_change_plan(
        &mut self,
        lease: BaselineLease,
        result: Result<CoreResult<BaselineChangePlan>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if !self
            .model
            .accepts(&lease, self.current_binding(cx).as_ref())
        {
            return;
        }
        self.busy = false;
        self.read_task_abort = None;
        match result {
            Ok(Ok(plan)) => {
                self.pending = Some(PendingBaselinePlan::Changes(plan));
                self.notice = None;
                self.error = None;
            }
            Ok(Err(error)) => self.error = Some(format!("无法创建基线计划：{error}").into()),
            Err(error) if error.is_cancelled() => return,
            Err(error) => self.error = Some(format!("计划任务异常终止：{error}").into()),
        }
        cx.notify();
    }

    fn prepare_restore(&mut self, record_id: String, cx: &mut Context<Self>) {
        if self.busy || self.pending.is_some() {
            return;
        }
        let Some(session) = self.current_session(cx) else {
            self.error = Some("未连接可信目标".into());
            return;
        };
        match self.services.baseline().plan_restore(&session, &record_id) {
            Ok(plan) => {
                self.pending = Some(PendingBaselinePlan::Restore(plan));
                self.error = None;
                self.notice = None;
            }
            Err(error) => self.error = Some(format!("无法创建恢复计划：{error}").into()),
        }
        cx.notify();
    }

    fn approve_pending(&mut self, cx: &mut Context<Self>) {
        if self.busy {
            return;
        }
        let Some(pending) = self.pending.take() else {
            return;
        };
        let Some(session) = self.current_session(cx) else {
            self.error = Some("目标已断开，计划未执行".into());
            return;
        };
        let lease = match self.begin(&session) {
            Ok(lease) => lease,
            Err(error) => {
                self.error = Some(error.to_string().into());
                return;
            }
        };
        self.busy = true;
        self.error = None;
        self.notice = Some("正在备份、写入、审计并逐项读回验证…".into());
        let service = self.services.baseline().clone();
        let task = self.tokio.spawn(async move {
            match pending {
                PendingBaselinePlan::Changes(plan) => {
                    let confirmation = DangerousConfirmation::approve(plan.definition());
                    service.execute_changes(&session, plan, confirmation).await
                }
                PendingBaselinePlan::Restore(plan) => {
                    let confirmation = DangerousConfirmation::approve(plan.definition());
                    service.execute_restore(&session, plan, confirmation).await
                }
            }
        });
        // A destructive workflow is detached once started so core can always
        // finish journal/verify or perform its compensation path.
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_operation(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_operation(
        &mut self,
        lease: BaselineLease,
        result: Result<CoreResult<BaselineOperationOutcome>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if !self
            .model
            .accepts(&lease, self.current_binding(cx).as_ref())
        {
            return;
        }
        self.busy = false;
        match result {
            Ok(Ok(outcome)) => {
                self.notice = Some(
                    format!(
                        "基线变更已{}，{} 项远端读回验证通过",
                        outcome.record.state.label(),
                        outcome.record.changes.len()
                    )
                    .into(),
                );
                self.error = None;
                self.model.queued.clear();
                self.model.tab = BaselineTab::History;
                self.refresh(cx);
            }
            Ok(Err(error)) => {
                self.error = Some(format!("基线操作失败：{error}").into());
                self.refresh(cx);
            }
            Err(error) => self.error = Some(format!("基线任务异常终止：{error}").into()),
        }
        cx.notify();
    }

    fn render_catalog(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let category = self.model.category;
        let selected = self.model.selected_item.clone();
        let detail = selected
            .as_deref()
            .and_then(|item_id| lovelyres_core::baseline::definition(item_id).ok());
        div()
            .size_full()
            .min_h_0()
            .flex()
            .gap_3()
            .child(
                div()
                    .w(px(150.))
                    .flex_none()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .children(BaselineCategory::ALL.into_iter().map(|item| {
                        crate::buttons::button(SharedString::from(format!(
                            "baseline-category-{:?}",
                            item
                        )))
                        .label(item.label())
                        .selected(category == item)
                        .on_click(cx.listener(move |page, _, _, cx| page.select_category(item, cx)))
                    })),
            )
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .min_h_0()
                    .overflow_y_scrollbar()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .children(
                        BASELINE_CATALOG
                            .iter()
                            .filter(|definition| definition.category == category)
                            .map(|definition| {
                                let item_id = definition.id.to_owned();
                                let status = self.model.status(definition.id);
                                let observed =
                                    status.map_or("尚未读取", |status| status.observed.label());
                                let compliant = status.is_some_and(|status| status.compliant);
                                let queued = self.model.queued.get(definition.id);
                                div()
                                    .id(SharedString::from(format!(
                                        "baseline-item-{}",
                                        definition.id
                                    )))
                                    .rounded_lg()
                                    .border_1()
                                    .border_color(if selected.as_deref() == Some(definition.id) {
                                        tokens.accent
                                    } else {
                                        tokens.border
                                    })
                                    .bg(tokens.surface)
                                    .p_3()
                                    .cursor_pointer()
                                    .on_click(cx.listener(move |page, _, window, cx| {
                                        page.select_item(item_id.clone(), window, cx)
                                    }))
                                    .child(
                                        div()
                                            .flex()
                                            .items_center()
                                            .gap_2()
                                            .child(div().font_semibold().child(definition.title))
                                            .child(
                                                div()
                                                    .text_xs()
                                                    .text_color(risk_color(definition.risk, tokens))
                                                    .child(definition.risk.label()),
                                            )
                                            .child(div().flex_1())
                                            .child(
                                                div()
                                                    .text_sm()
                                                    .text_color(if compliant {
                                                        tokens.success
                                                    } else {
                                                        tokens.muted
                                                    })
                                                    .child(if compliant {
                                                        "符合推荐"
                                                    } else {
                                                        "待检查 / 待加固"
                                                    }),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .mt_2()
                                            .text_sm()
                                            .text_color(tokens.muted)
                                            .child(definition.description),
                                    )
                                    .child(
                                        div()
                                            .mt_2()
                                            .flex()
                                            .gap_4()
                                            .text_sm()
                                            .child(format!("当前：{observed}"))
                                            .child(format!("推荐：{}", definition.recommendation))
                                            .when_some(queued.cloned(), |row, value| {
                                                row.child(
                                                    div()
                                                        .text_color(tokens.accent)
                                                        .child(format!("待变更：{value}")),
                                                )
                                            }),
                                    )
                            }),
                    ),
            )
            .child(
                div()
                    .w(px(300.))
                    .flex_none()
                    .rounded_lg()
                    .border_1()
                    .border_color(tokens.border)
                    .bg(tokens.surface)
                    .p_4()
                    .when_some(detail, |panel, definition| {
                        let choices = match definition.value_kind {
                            BaselineValueKind::Choice(choices) => Some(choices),
                            BaselineValueKind::Integer { .. } => None,
                        };
                        panel
                            .child(div().text_lg().font_semibold().child(definition.title))
                            .child(
                                div()
                                    .mt_2()
                                    .text_sm()
                                    .text_color(tokens.muted)
                                    .child(format!(
                                        "允许值：{}",
                                        value_hint(definition.value_kind)
                                    )),
                            )
                            .child(div().mt_3().child(Input::new(&self.value_input)))
                            .when_some(choices, |panel, choices| {
                                panel.child(div().mt_2().flex().flex_wrap().gap_2().children(
                                    choices.iter().copied().map(|choice| {
                                        crate::buttons::button(SharedString::from(format!(
                                            "baseline-choice-{choice}"
                                        )))
                                        .label(choice)
                                        .small()
                                        .on_click(
                                            cx.listener(move |page, _, window, cx| {
                                                page.set_choice(choice, window, cx)
                                            }),
                                        )
                                    }),
                                ))
                            })
                            .child(
                                div()
                                    .mt_3()
                                    .flex()
                                    .gap_2()
                                    .child(
                                        crate::buttons::button("baseline-recommended")
                                            .label("填入推荐值")
                                            .on_click(cx.listener(|page, _, window, cx| {
                                                page.set_recommended(window, cx)
                                            })),
                                    )
                                    .child(
                                        crate::buttons::button("baseline-queue")
                                            .label("加入变更")
                                            .primary()
                                            .on_click(cx.listener(|page, _, _, cx| {
                                                page.queue_selected(cx)
                                            })),
                                    ),
                            )
                    })
                    .when(detail.is_none(), |panel| {
                        panel.child(
                            div()
                                .text_color(tokens.muted)
                                .child("选择左侧配置项查看允许值并加入变更。"),
                        )
                    }),
            )
            .into_any_element()
    }

    fn render_plan(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        div()
            .size_full()
            .min_h_0()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .rounded_lg()
                    .border_1()
                    .border_color(tokens.border)
                    .bg(tokens.surface)
                    .p_4()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(
                                div()
                                    .font_semibold()
                                    .child(format!("待应用变更 · {} 项", self.model.queued.len())),
                            )
                            .child(div().flex_1())
                            .child(
                                crate::buttons::button("baseline-reload-defer")
                                    .label("稍后重载")
                                    .selected(
                                        self.model.reload_policy == BaselineReloadPolicy::Defer,
                                    )
                                    .on_click(cx.listener(|page, _, _, cx| {
                                        page.model.reload_policy = BaselineReloadPolicy::Defer;
                                        cx.notify();
                                    })),
                            )
                            .child(
                                crate::buttons::button("baseline-reload-now")
                                    .label("立即校验并重载")
                                    .selected(
                                        self.model.reload_policy
                                            == BaselineReloadPolicy::ApplyNow,
                                    )
                                    .on_click(cx.listener(|page, _, _, cx| {
                                        page.model.reload_policy = BaselineReloadPolicy::ApplyNow;
                                        cx.notify();
                                    })),
                            ),
                    )
                    .child(
                        div()
                            .mt_2()
                            .text_sm()
                            .text_color(tokens.muted)
                            .child("SSH 配置始终先执行 sshd -t；选择立即重载时，会在写入后应用 sysctl 并重载 sshd。"),
                    ),
            )
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scrollbar()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .when(self.model.queued.is_empty(), |list| {
                        list.child(empty_state("尚未加入任何变更", tokens))
                    })
                    .children(self.model.queued.iter().map(|(item_id, value)| {
                        let definition = lovelyres_core::baseline::definition(item_id).ok();
                        let title = definition
                            .map_or_else(|| item_id.clone(), |item| item.title.to_owned());
                        let current = self
                            .model
                            .status(item_id)
                            .map_or("未读取", |status| status.observed.label());
                        let remove_id = item_id.clone();
                        div()
                            .rounded_lg()
                            .border_1()
                            .border_color(tokens.border)
                            .bg(tokens.surface)
                            .p_3()
                            .flex()
                            .items_center()
                            .gap_3()
                            .child(
                                div()
                                    .flex_1()
                                    .child(
                                        div().font_semibold().child(title),
                                    )
                                    .child(
                                        div()
                                            .mt_1()
                                            .text_sm()
                                            .text_color(tokens.muted)
                                            .child(format!("{current} → {value}")),
                                    ),
                            )
                            .child(
                                crate::buttons::button(SharedString::from(format!(
                                    "baseline-remove-{item_id}"
                                )))
                                .label("移除")
                                .small()
                                .on_click(cx.listener(move |page, _, _, cx| {
                                    page.remove_queued(remove_id.clone(), cx)
                                })),
                            )
                    })),
            )
            .child(
                div()
                    .flex()
                    .justify_end()
                    .child(
                        crate::buttons::button("baseline-create-plan")
                            .label(if self.busy { "生成中…" } else { "生成不可变计划" })
                            .primary()
                            .disabled(self.busy || self.model.queued.is_empty())
                            .on_click(cx.listener(|page, _, _, cx| page.prepare_changes(cx))),
                    ),
            )
            .into_any_element()
    }

    fn render_history(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        div()
            .size_full()
            .min_h_0()
            .overflow_y_scrollbar()
            .flex()
            .flex_col()
            .gap_2()
            .when(self.model.history.is_empty(), |list| {
                list.child(empty_state("当前目标没有基线变更历史", tokens))
            })
            .children(self.model.history.iter().map(|record| {
                let record_id = record.id.clone();
                let summary = record
                    .changes
                    .iter()
                    .map(|change| {
                        let title = lovelyres_core::baseline::definition(&change.item_id)
                            .map_or(change.item_id.as_str(), |definition| definition.title);
                        format!("{title}: {} → {}", change.before.label(), change.after)
                    })
                    .collect::<Vec<_>>()
                    .join("；");
                div()
                    .rounded_lg()
                    .border_1()
                    .border_color(tokens.border)
                    .bg(tokens.surface)
                    .p_3()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_3()
                            .child(div().font_semibold().child(format!(
                                "{} · {} 项",
                                record.state.label(),
                                record.changes.len()
                            )))
                            .child(
                                div().text_sm().text_color(tokens.muted).child(
                                    record
                                        .created_at
                                        .format("%Y-%m-%d %H:%M:%S UTC")
                                        .to_string(),
                                ),
                            )
                            .child(div().flex_1())
                            .when(record.state == BaselineChangeState::Applied, |row| {
                                row.child(
                                    crate::buttons::button(SharedString::from(format!(
                                        "baseline-restore-{}",
                                        record.id
                                    )))
                                    .label("创建恢复计划")
                                    .danger()
                                    .small()
                                    .disabled(self.busy || self.pending.is_some())
                                    .on_click(cx.listener(move |page, _, _, cx| {
                                        page.prepare_restore(record_id.clone(), cx)
                                    })),
                                )
                            }),
                    )
                    .child(
                        div()
                            .mt_2()
                            .text_sm()
                            .text_color(tokens.muted)
                            .child(summary),
                    )
                    .child(
                        div()
                            .mt_1()
                            .text_xs()
                            .text_color(tokens.muted)
                            .child(format!(
                                "{} · 受管备份 {}",
                                record.reload_policy.label(),
                                record.remote_root
                            )),
                    )
            }))
            .into_any_element()
    }
}

impl Render for BaselinePage {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens = self.shared.read(cx).theme.tokens();
        let tab = self.model.tab;
        let pending_summary = self
            .pending
            .as_ref()
            .map(|pending| pending.definition().summary.clone());
        let content = match tab {
            BaselineTab::Catalog => self.render_catalog(tokens, cx),
            BaselineTab::Plan => self.render_plan(tokens, cx),
            BaselineTab::History => self.render_history(tokens, cx),
        };
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
                    .gap_2()
                    .children(BaselineTab::ALL.into_iter().map(|item| {
                        crate::buttons::button(SharedString::from(format!(
                            "baseline-tab-{}",
                            item.label()
                        )))
                        .label(item.label())
                        .selected(tab == item)
                        .on_click(cx.listener(move |page, _, _, cx| {
                            page.model.tab = item;
                            cx.notify();
                        }))
                    }))
                    .child(div().flex_1())
                    .child(div().text_sm().text_color(tokens.muted).child(format!(
                        "{} 项封闭目录 · {} 项待变更",
                        BASELINE_CATALOG.len(),
                        self.model.queued.len()
                    )))
                    .child(
                        crate::buttons::button("baseline-refresh")
                            .label(if self.busy { "处理中…" } else { "刷新" })
                            .small()
                            .disabled(self.busy)
                            .on_click(cx.listener(|page, _, _, cx| page.refresh(cx))),
                    ),
            )
            .when_some(self.error.clone(), |view, error| {
                view.child(message_banner(error, tokens.danger, tokens))
            })
            .when_some(self.notice.clone(), |view, notice| {
                view.child(message_banner(notice, tokens.success, tokens))
            })
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
                        .gap_3()
                        .child(
                            div()
                                .flex_1()
                                .child(div().font_semibold().child("危险操作精确确认"))
                                .child(
                                    div()
                                        .mt_1()
                                        .text_sm()
                                        .text_color(tokens.muted)
                                        .child(summary),
                                ),
                        )
                        .child(
                            crate::buttons::button("baseline-cancel-plan")
                                .label("取消")
                                .disabled(self.busy)
                                .on_click(cx.listener(|page, _, _, cx| {
                                    page.pending = None;
                                    cx.notify();
                                })),
                        )
                        .child(
                            crate::buttons::button("baseline-confirm-plan")
                                .label("确认并执行")
                                .danger()
                                .disabled(self.busy)
                                .on_click(cx.listener(|page, _, _, cx| page.approve_pending(cx))),
                        ),
                )
            })
            .child(div().flex_1().min_h_0().child(content))
    }
}

fn value_hint(kind: BaselineValueKind) -> String {
    match kind {
        BaselineValueKind::Choice(choices) => choices.join(" / "),
        BaselineValueKind::Integer { minimum, maximum } => format!("{minimum}..={maximum}"),
    }
}

fn risk_color(risk: BaselineRisk, tokens: ThemeTokens) -> gpui::Rgba {
    match risk {
        BaselineRisk::Critical | BaselineRisk::High => tokens.danger,
        BaselineRisk::Medium => tokens.warning,
        BaselineRisk::Low => tokens.muted,
    }
}

fn empty_state(message: &'static str, tokens: ThemeTokens) -> impl IntoElement {
    div()
        .rounded_lg()
        .border_1()
        .border_color(tokens.border)
        .bg(tokens.surface)
        .p_4()
        .text_color(tokens.muted)
        .child(message)
}

fn message_banner(
    message: SharedString,
    color: gpui::Rgba,
    tokens: ThemeTokens,
) -> impl IntoElement {
    div()
        .rounded_lg()
        .border_1()
        .border_color(color)
        .bg(tokens.surface)
        .px_3()
        .py_2()
        .text_sm()
        .child(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lovelyres_core::target::TargetIdentity;

    fn binding(name: &str, generation: u64) -> BaselineBinding {
        BaselineBinding {
            session_id: format!("session-{name}"),
            connection_id: name.to_owned(),
            target: TargetGuard {
                identity: TargetIdentity::new(name).unwrap(),
                generation,
            },
        }
    }

    #[test]
    fn target_rebind_clears_status_queue_and_history() {
        let mut model = BaselineModel::default();
        model.activate(Some(binding("a", 1)));
        model.statuses.push(BaselineStatus {
            item_id: "ssh-max-auth-tries".to_owned(),
            observed: BaselineObservedValue::Value("6".to_owned()),
            compliant: false,
        });
        model
            .queued
            .insert("ssh-max-auth-tries".to_owned(), "4".to_owned());
        model.rebind(Some(binding("b", 2)));
        assert!(model.statuses.is_empty());
        assert!(model.queued.is_empty());
        assert!(model.history.is_empty());
    }

    #[test]
    fn lease_rejects_deactivate_and_replacement_target() {
        let mut model = BaselineModel::default();
        let first = binding("a", 1);
        model.activate(Some(first.clone()));
        let lease = model.begin_request(first.clone()).unwrap();
        assert!(model.accepts(&lease, Some(&first)));
        model.deactivate();
        assert!(!model.accepts(&lease, Some(&first)));
        model.activate(Some(binding("b", 2)));
        assert!(!model.accepts(&lease, model.binding.as_ref()));
    }

    #[test]
    fn page_value_boundary_reuses_closed_core_catalog() {
        assert!(BaselineChangeRequest::new("ssh-max-auth-tries", "4").is_ok());
        assert!(BaselineChangeRequest::new("ssh-max-auth-tries", "4;id").is_err());
        assert!(BaselineChangeRequest::new("/etc/passwd", "root").is_err());
    }
}
