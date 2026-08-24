use std::sync::Arc;

use chrono::Utc;
use gpui::{
    AnyElement, ClipboardItem, Context, Entity, IntoElement, Render, SharedString, Subscription,
    Window, div, prelude::*, px,
};
use gpui_component::{
    Disableable, Selectable, Sizable, StyledExt,
    button::ButtonVariants,
    input::{Input, InputState},
    scroll::ScrollableElement,
};
use lovelyres_core::{
    BackendServices, CoreError, CoreResult,
    firewall::{
        FirewallChangeRecord, FirewallChangeState, FirewallInspection, FirewallMutationPlan,
        FirewallMutationRequest, FirewallOperationOutcome, FirewallResolution,
        FirewallResolutionPlan,
    },
    operations::{DangerousConfirmation, OperationPlan},
    ssh::BoundSshSession,
    target::TargetGuard,
};
use tokio::task::AbortHandle;

use crate::{app::SharedAppState, runtime::TokioBridge, theme::ThemeTokens};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirewallTab {
    Rules,
    Response,
    History,
}

impl FirewallTab {
    const ALL: [Self; 3] = [Self::Rules, Self::Response, Self::History];

    const fn label(self) -> &'static str {
        match self {
            Self::Rules => "当前规则",
            Self::Response => "隔离计划",
            Self::History => "恢复记录",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FirewallBinding {
    session_id: String,
    connection_id: String,
    target: TargetGuard,
}

impl FirewallBinding {
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
struct FirewallLease {
    activation_generation: u64,
    request_id: u64,
    binding: FirewallBinding,
}

#[derive(Debug, Clone)]
enum PendingFirewallPlan {
    Mutation(FirewallMutationPlan),
    Resolution(FirewallResolutionPlan),
}

impl PendingFirewallPlan {
    fn definition(&self) -> &OperationPlan {
        match self {
            Self::Mutation(plan) => plan.definition(),
            Self::Resolution(plan) => plan.definition(),
        }
    }
}

#[derive(Debug)]
struct FirewallModel {
    active: bool,
    activation_generation: u64,
    next_request_id: u64,
    latest_request_id: Option<u64>,
    binding: Option<FirewallBinding>,
    tab: FirewallTab,
    inspection: Option<FirewallInspection>,
    changes: Vec<FirewallChangeRecord>,
}

impl Default for FirewallModel {
    fn default() -> Self {
        Self {
            active: false,
            activation_generation: 0,
            next_request_id: 0,
            latest_request_id: None,
            binding: None,
            tab: FirewallTab::Rules,
            inspection: None,
            changes: Vec::new(),
        }
    }
}

impl FirewallModel {
    fn activate(&mut self, binding: Option<FirewallBinding>) {
        self.active = true;
        self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
        self.rebind(binding);
    }

    fn deactivate(&mut self) {
        self.active = false;
        self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
        self.latest_request_id = None;
    }

    fn rebind(&mut self, binding: Option<FirewallBinding>) {
        if self.binding == binding {
            return;
        }
        self.binding = binding;
        self.latest_request_id = None;
        self.inspection = None;
        self.changes.clear();
    }

    fn begin_request(&mut self, binding: FirewallBinding) -> CoreResult<FirewallLease> {
        if !self.active {
            return Err(CoreError::Validation {
                subject: "firewall page",
                message: "page is not active".to_owned(),
            });
        }
        self.rebind(Some(binding.clone()));
        self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
        self.latest_request_id = Some(self.next_request_id);
        Ok(FirewallLease {
            activation_generation: self.activation_generation,
            request_id: self.next_request_id,
            binding,
        })
    }

    fn accepts(&self, lease: &FirewallLease, binding: Option<&FirewallBinding>) -> bool {
        self.active
            && self.activation_generation == lease.activation_generation
            && self.latest_request_id == Some(lease.request_id)
            && binding == Some(&lease.binding)
    }
}

pub struct FirewallPage {
    services: Arc<BackendServices>,
    tokio: Arc<TokioBridge>,
    shared: Entity<SharedAppState>,
    model: FirewallModel,
    source_input: Entity<InputState>,
    port_input: Entity<InputState>,
    read_task_abort: Option<AbortHandle>,
    busy: bool,
    pending: Option<PendingFirewallPlan>,
    error: Option<SharedString>,
    notice: Option<SharedString>,
    _subscriptions: Vec<Subscription>,
}

impl FirewallPage {
    pub fn new(
        services: Arc<BackendServices>,
        tokio: Arc<TokioBridge>,
        shared: Entity<SharedAppState>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let source_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder("IPv4 / CIDR，例如 203.0.113.7 或 10.0.0.0/24")
        });
        let port_input = cx.new(|cx| InputState::new(window, cx).placeholder("TCP 端口，例如 443"));
        let subscriptions = vec![cx.observe(&shared, |page, _, cx| page.handle_shared_change(cx))];
        Self {
            services,
            tokio,
            shared,
            model: FirewallModel::default(),
            source_input,
            port_input,
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

    fn current_binding(&self, cx: &Context<Self>) -> Option<FirewallBinding> {
        FirewallBinding::capture(self.shared.read(cx))
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
            self.error = Some("未连接可信目标，无法管理边界隔离".into());
            cx.notify();
        }
    }

    fn begin(&mut self, session: &BoundSshSession) -> CoreResult<FirewallLease> {
        self.cancel_read_task();
        self.model
            .begin_request(FirewallBinding::from_session(session))
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
        self.notice = Some("正在探测防火墙后端并读取规则…".into());
        let service = self.services.firewall().clone();
        let task = self.tokio.spawn(async move {
            let _ = service.reconcile(&session).await;
            let inspection = service.inspect(&session).await?;
            let changes = service.list_changes(session.target())?;
            Ok::<_, CoreError>((inspection, changes))
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
        lease: FirewallLease,
        result: Result<
            CoreResult<(FirewallInspection, Vec<FirewallChangeRecord>)>,
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
            Ok(Ok((inspection, changes))) => {
                self.model.inspection = Some(inspection);
                self.model.changes = changes;
                self.error = None;
                self.notice = None;
            }
            Ok(Err(error)) => self.error = Some(format!("防火墙探测失败：{error}").into()),
            Err(error) if error.is_cancelled() => return,
            Err(error) => self.error = Some(format!("防火墙任务异常终止：{error}").into()),
        }
        cx.notify();
    }

    fn plan_block(&mut self, cx: &mut Context<Self>) {
        let source = self.source_input.read(cx).value().to_string();
        match FirewallMutationRequest::block_ipv4(source) {
            Ok(request) => self.prepare_mutation(request, cx),
            Err(error) => {
                self.error = Some(format!("封禁来源无效：{error}").into());
                cx.notify();
            }
        }
    }

    fn plan_allow_port(&mut self, cx: &mut Context<Self>) {
        let value = self.port_input.read(cx).value().to_string();
        match value
            .trim()
            .parse::<u16>()
            .map_err(|_| CoreError::Validation {
                subject: "firewall port",
                message: "请输入 1..=65535 的 TCP 端口".to_owned(),
            })
            .and_then(FirewallMutationRequest::allow_tcp_port)
        {
            Ok(request) => self.prepare_mutation(request, cx),
            Err(error) => {
                self.error = Some(error.to_string().into());
                cx.notify();
            }
        }
    }

    fn prepare_mutation(&mut self, request: FirewallMutationRequest, cx: &mut Context<Self>) {
        if self.busy || self.pending.is_some() {
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
        self.notice = Some("正在读取变更前规则并创建不可变计划…".into());
        let service = self.services.firewall().clone();
        let task = self
            .tokio
            .spawn(async move { service.plan_mutation(&session, request).await });
        self.read_task_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_plan(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_plan(
        &mut self,
        lease: FirewallLease,
        result: Result<CoreResult<FirewallMutationPlan>, tokio::task::JoinError>,
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
                self.pending = Some(PendingFirewallPlan::Mutation(plan));
                self.notice = None;
                self.error = None;
            }
            Ok(Err(error)) => self.error = Some(format!("无法创建隔离计划：{error}").into()),
            Err(error) if error.is_cancelled() => return,
            Err(error) => self.error = Some(format!("计划任务异常终止：{error}").into()),
        }
        cx.notify();
    }

    fn prepare_resolution(
        &mut self,
        change_id: String,
        resolution: FirewallResolution,
        cx: &mut Context<Self>,
    ) {
        if self.busy || self.pending.is_some() {
            return;
        }
        let Some(session) = self.current_session(cx) else {
            self.error = Some("未连接可信目标".into());
            return;
        };
        match self
            .services
            .firewall()
            .plan_resolution(&session, &change_id, resolution)
        {
            Ok(plan) => {
                self.pending = Some(PendingFirewallPlan::Resolution(plan));
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
        self.notice = Some("正在执行、审计并回读验证；请勿关闭 SSH 会话…".into());
        let service = self.services.firewall().clone();
        let task = self.tokio.spawn(async move {
            match pending {
                PendingFirewallPlan::Mutation(plan) => {
                    let confirmation = DangerousConfirmation::approve(plan.definition());
                    service.execute_mutation(&session, plan, confirmation).await
                }
                PendingFirewallPlan::Resolution(plan) => {
                    let confirmation = DangerousConfirmation::approve(plan.definition());
                    service
                        .execute_resolution(&session, plan, confirmation)
                        .await
                }
            }
        });
        // Once a destructive workflow starts, it is intentionally not aborted by
        // page navigation. Core must finish journal/verify or leave the dead-man armed.
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
        lease: FirewallLease,
        result: Result<CoreResult<FirewallOperationOutcome>, tokio::task::JoinError>,
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
                let state = outcome.change.state;
                self.notice = Some(match state {
                    FirewallChangeState::AwaitingKeep => format!(
                        "规则已验证；请在 {} 前明确保留，否则远端自动恢复",
                        outcome.change.deadman_deadline.format("%H:%M:%S UTC")
                    )
                    .into(),
                    _ => format!("防火墙变更已{}并完成回读验证", state.label()).into(),
                });
                self.error = None;
                self.model.tab = FirewallTab::History;
                self.refresh(cx);
            }
            Ok(Err(error)) => {
                self.error = Some(format!("防火墙操作失败：{error}").into());
                self.refresh(cx);
            }
            Err(error) => self.error = Some(format!("防火墙任务异常终止：{error}").into()),
        }
        cx.notify();
    }

    fn copy_rules(&mut self, cx: &mut Context<Self>) {
        let Some(inspection) = self.model.inspection.as_ref() else {
            return;
        };
        cx.write_to_clipboard(ClipboardItem::new_string(inspection.rules.clone()));
        self.notice = Some("当前规则已复制为纯文本".into());
        cx.notify();
    }

    fn render_rules(&self, tokens: ThemeTokens) -> AnyElement {
        let Some(inspection) = self.model.inspection.as_ref() else {
            return empty_state("尚未读取防火墙规则", tokens).into_any_element();
        };
        div()
            .size_full()
            .min_h_0()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .grid()
                    .grid_cols(4)
                    .gap_3()
                    .child(status_card("管理后端", inspection.backend.label(), tokens))
                    .child(status_card(
                        "安全变更引擎",
                        inspection.engine.label(),
                        tokens,
                    ))
                    .child(status_card(
                        "运行状态",
                        if inspection.active {
                            "已启用"
                        } else {
                            "未启用 / 空规则"
                        },
                        tokens,
                    ))
                    .child(status_card(
                        "规则摘要",
                        &format!("SHA-256 {}…", &inspection.rules_sha256[..12]),
                        tokens,
                    )),
            )
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .overflow_scrollbar()
                    .rounded_lg()
                    .border_1()
                    .border_color(tokens.border)
                    .bg(tokens.terminal_background)
                    .p_4()
                    .font_family("Cascadia Mono")
                    .text_sm()
                    .text_color(tokens.text)
                    .whitespace_normal()
                    .child(if inspection.rules.is_empty() {
                        "(无规则或无读取权限)".to_owned()
                    } else {
                        bounded_display(&inspection.rules, 256 * 1024)
                    }),
            )
            .when(
                inspection.rules_truncated || inspection.rules.len() > 256 * 1024,
                |view| {
                    view.child(message_banner(
                        "规则输出较大，界面仅展示前 256 KiB；复制仍使用 core 已接收的完整有界文本"
                            .into(),
                        tokens.warning,
                        tokens,
                    ))
                },
            )
            .into_any_element()
    }

    fn render_response(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let mutation_available = self.model.inspection.as_ref().is_some_and(|inspection| {
            !matches!(
                inspection.engine,
                lovelyres_core::firewall::FirewallEngine::Unavailable
            )
        });
        div()
            .size_full()
            .min_h_0()
            .overflow_y_scrollbar()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .rounded_lg()
                    .border_1()
                    .border_color(tokens.warning)
                    .bg(tokens.surface)
                    .p_4()
                    .child(
                        div()
                            .font_semibold()
                            .text_color(tokens.warning)
                            .child("防自锁策略"),
                    )
                    .child(
                        div()
                            .mt_1()
                            .text_sm()
                            .text_color(tokens.muted)
                            .child("所有动作先创建独立链/表，保留当前 SSH 端口、回环和已建立连接，并启动 60 秒远端自动恢复。关闭页面或客户端不会取消兜底。"),
                    ),
            )
            .child(action_card(
                "封禁 IPv4 来源",
                "阻断一个 IPv4 地址或 CIDR；当前已建立 SSH 会话优先放行。",
                Input::new(&self.source_input).into_any_element(),
                crate::buttons::button("firewall-plan-block")
                    .label("创建封禁计划")
                    .danger()
                    .disabled(self.busy || !mutation_available)
                    .on_click(cx.listener(|page, _, _, cx| page.plan_block(cx)))
                    .into_any_element(),
                tokens,
            ))
            .child(action_card(
                "放行 TCP 端口",
                "通过独立高优先级规则临时放行指定 TCP 端口。",
                Input::new(&self.port_input).into_any_element(),
                crate::buttons::button("firewall-plan-port")
                    .label("创建放行计划")
                    .disabled(self.busy || !mutation_available)
                    .on_click(cx.listener(|page, _, _, cx| page.plan_allow_port(cx)))
                    .into_any_element(),
                tokens,
            ))
            .child(
                div()
                    .rounded_lg()
                    .border_1()
                    .border_color(tokens.danger)
                    .bg(tokens.surface)
                    .p_4()
                    .flex()
                    .items_center()
                    .gap_4()
                    .child(
                        div()
                            .flex_1()
                            .child(div().font_semibold().child("隔离全部入站流量"))
                            .child(
                                div()
                                    .mt_1()
                                    .text_sm()
                                    .text_color(tokens.muted)
                                    .child("仅保留回环、已建立连接及当前 SSH 监听端口；不修改系统持久化防火墙配置。"),
                            ),
                    )
                    .child(
                        crate::buttons::button("firewall-plan-isolate")
                            .label("创建隔离计划")
                            .danger()
                            .disabled(self.busy || !mutation_available)
                            .on_click(cx.listener(|page, _, _, cx| {
                                page.prepare_mutation(
                                    FirewallMutationRequest::isolate_inbound(),
                                    cx,
                                )
                            })),
                    ),
            )
            .when(!mutation_available, |view| {
                view.child(message_banner(
                    "目标缺少完整 iptables-save/restore 或 nftables；当前仅开放规则查看。".into(),
                    tokens.warning,
                    tokens,
                ))
            })
            .into_any_element()
    }

    fn render_history(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let changes = self.model.changes.clone();
        div()
            .size_full()
            .min_h_0()
            .overflow_y_scrollbar()
            .rounded_lg()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .when(changes.is_empty(), |view| {
                view.child(empty_state("当前目标尚无边界隔离记录", tokens))
            })
            .children(changes.into_iter().map(|change| {
                let keep_id = change.id.clone();
                let restore_id = change.id.clone();
                let remaining = (change.deadman_deadline - Utc::now()).num_seconds().max(0);
                div()
                    .px_4()
                    .py_3()
                    .border_b_1()
                    .border_color(tokens.border)
                    .flex()
                    .items_center()
                    .gap_4()
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child(div().font_semibold().child(change.request.label()))
                                    .child(
                                        div()
                                            .text_xs()
                                            .text_color(change_state_color(change.state, tokens))
                                            .child(change.state.label()),
                                    ),
                            )
                            .child(
                                div()
                                    .mt_1()
                                    .text_xs()
                                    .text_color(tokens.muted)
                                    .child(format!(
                                        "{} · {} · SSH {} · {}",
                                        change.backend.label(),
                                        change.engine.label(),
                                        change.ssh_port,
                                        change.created_at.format("%Y-%m-%d %H:%M:%S UTC")
                                    )),
                            )
                            .child(
                                div()
                                    .mt_1()
                                    .font_family("Cascadia Mono")
                                    .text_xs()
                                    .text_color(tokens.muted)
                                    .child(format!(
                                        "{} · SHA {}…",
                                        change.id,
                                        &change.preflight_sha256[..12]
                                    )),
                            )
                            .when(change.state == FirewallChangeState::AwaitingKeep, |view| {
                                view.child(
                                    div()
                                        .mt_1()
                                        .text_xs()
                                        .text_color(tokens.warning)
                                        .child(format!("自动恢复倒计时约 {remaining} 秒")),
                                )
                            }),
                    )
                    .when(change.state == FirewallChangeState::AwaitingKeep, |view| {
                        view.child(
                            crate::buttons::button(SharedString::from(format!(
                                "firewall-keep-{keep_id}"
                            )))
                            .label("保留规则")
                            .small()
                            .disabled(self.busy)
                            .on_click(cx.listener(
                                move |page, _, _, cx| {
                                    page.prepare_resolution(
                                        keep_id.clone(),
                                        FirewallResolution::Keep,
                                        cx,
                                    )
                                },
                            )),
                        )
                    })
                    .when(
                        matches!(
                            change.state,
                            FirewallChangeState::AwaitingKeep | FirewallChangeState::Kept
                        ),
                        |view| {
                            view.child(
                                crate::buttons::button(SharedString::from(format!(
                                    "firewall-restore-{restore_id}"
                                )))
                                .label("立即恢复")
                                .danger()
                                .small()
                                .disabled(self.busy)
                                .on_click(cx.listener(
                                    move |page, _, _, cx| {
                                        page.prepare_resolution(
                                            restore_id.clone(),
                                            FirewallResolution::Restore,
                                            cx,
                                        )
                                    },
                                )),
                            )
                        },
                    )
            }))
            .into_any_element()
    }
}

impl Render for FirewallPage {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens = self.shared.read(cx).theme.tokens();
        let tab = self.model.tab;
        let pending_summary = self
            .pending
            .as_ref()
            .map(|pending| pending.definition().summary.clone());
        let content = match tab {
            FirewallTab::Rules => self.render_rules(tokens),
            FirewallTab::Response => self.render_response(tokens, cx),
            FirewallTab::History => self.render_history(tokens, cx),
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
                    .children(FirewallTab::ALL.into_iter().map(|item| {
                        crate::buttons::button(SharedString::from(format!(
                            "firewall-tab-{}",
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
                    .when(tab == FirewallTab::Rules, |view| {
                        view.child(
                            crate::buttons::button("firewall-copy-rules")
                                .label("复制规则")
                                .small()
                                .disabled(self.model.inspection.is_none())
                                .on_click(cx.listener(|page, _, _, cx| page.copy_rules(cx))),
                        )
                    })
                    .child(
                        crate::buttons::button("firewall-refresh")
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
                                .child(
                                    div()
                                        .font_semibold()
                                        .text_color(tokens.danger)
                                        .child("危险操作确认"),
                                )
                                .child(div().mt_1().text_sm().child(summary))
                                .child(
                                    div()
                                        .mt_1()
                                        .text_xs()
                                        .text_color(tokens.muted)
                                        .child("确认只绑定这一个不可变计划。变更后仍需第二次明确选择“保留”，否则死人开关自动恢复。"),
                                ),
                        )
                        .child(
                            crate::buttons::button("firewall-cancel-plan")
                                .label("取消")
                                .on_click(cx.listener(|page, _, _, cx| {
                                    page.pending = None;
                                    page.notice = Some("计划已取消，未产生远端变更".into());
                                    cx.notify();
                                })),
                        )
                        .child(
                            crate::buttons::button("firewall-approve-plan")
                                .label("确认执行")
                                .danger()
                                .on_click(cx.listener(|page, _, _, cx| page.approve_pending(cx))),
                        ),
                )
            })
            .child(div().flex_1().min_h_0().child(content))
    }
}

fn status_card(label: &'static str, value: &str, tokens: ThemeTokens) -> impl IntoElement {
    div()
        .rounded_lg()
        .border_1()
        .border_color(tokens.border)
        .bg(tokens.surface)
        .p_3()
        .child(div().text_xs().text_color(tokens.muted).child(label))
        .child(
            div()
                .mt_1()
                .text_sm()
                .font_semibold()
                .child(value.to_owned()),
        )
}

fn action_card(
    title: &'static str,
    description: &'static str,
    input: AnyElement,
    button: AnyElement,
    tokens: ThemeTokens,
) -> impl IntoElement {
    div()
        .rounded_lg()
        .border_1()
        .border_color(tokens.border)
        .bg(tokens.surface)
        .p_4()
        .child(div().font_semibold().child(title))
        .child(
            div()
                .mt_1()
                .text_sm()
                .text_color(tokens.muted)
                .child(description),
        )
        .child(
            div()
                .mt_3()
                .flex()
                .items_center()
                .gap_3()
                .child(div().flex_1().child(input))
                .child(button),
        )
}

fn empty_state(message: &'static str, tokens: ThemeTokens) -> impl IntoElement {
    div()
        .h_full()
        .min_h(px(140.0))
        .flex()
        .items_center()
        .justify_center()
        .text_sm()
        .text_color(tokens.muted)
        .child(message)
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

fn change_state_color(state: FirewallChangeState, tokens: ThemeTokens) -> gpui::Rgba {
    match state {
        FirewallChangeState::AwaitingKeep => tokens.warning,
        FirewallChangeState::Kept => tokens.danger,
        FirewallChangeState::Restored | FirewallChangeState::AutoRestored => tokens.success,
    }
}

fn bounded_display(value: &str, maximum_bytes: usize) -> String {
    if value.len() <= maximum_bytes {
        return value.to_owned();
    }
    let mut end = maximum_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n\n…（界面展示已截断）", &value[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use lovelyres_core::target::TargetIdentity;

    fn binding(id: &str, generation: u64) -> FirewallBinding {
        FirewallBinding {
            session_id: format!("session-{generation}"),
            connection_id: id.to_owned(),
            target: TargetGuard {
                identity: TargetIdentity::new(id).unwrap(),
                generation,
            },
        }
    }

    #[test]
    fn target_rebind_clears_remote_state_and_invalidates_old_request() {
        let mut model = FirewallModel::default();
        model.activate(Some(binding("a", 1)));
        let lease = model.begin_request(binding("a", 1)).unwrap();
        model.changes.push(FirewallChangeRecord {
            id: "placeholder".to_owned(),
            operation_id: "operation".to_owned(),
            last_operation_id: "operation".to_owned(),
            target: TargetIdentity::new("a").unwrap(),
            backend: lovelyres_core::firewall::FirewallBackend::Unknown,
            engine: lovelyres_core::firewall::FirewallEngine::Iptables,
            request: FirewallMutationRequest::IsolateInbound,
            ssh_port: 22,
            remote_root: "/tmp/test".to_owned(),
            object_name: "LR_TEST".to_owned(),
            preflight_sha256: "00".repeat(32),
            state: FirewallChangeState::Restored,
            created_at: Utc::now(),
            deadman_deadline: Utc::now(),
            updated_at: Utc::now(),
        });
        model.rebind(Some(binding("b", 2)));
        assert!(model.changes.is_empty());
        assert!(!model.accepts(&lease, Some(&binding("b", 2))));
    }

    #[test]
    fn deactivation_rejects_late_results() {
        let mut model = FirewallModel::default();
        let current = binding("a", 1);
        model.activate(Some(current.clone()));
        let lease = model.begin_request(current.clone()).unwrap();
        model.deactivate();
        assert!(!model.accepts(&lease, Some(&current)));
    }

    #[test]
    fn all_firewall_tabs_are_stable_and_unique() {
        assert_eq!(FirewallTab::ALL.len(), 3);
        assert_ne!(FirewallTab::Rules.label(), FirewallTab::Response.label());
        assert_ne!(FirewallTab::Response.label(), FirewallTab::History.label());
    }
}
