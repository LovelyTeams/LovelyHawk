use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
    sync::Arc,
    time::Duration,
};

use gpui::{
    AnyElement, ClipboardItem, Context, Entity, Render, SharedString, Subscription,
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
    audit::{
        AuditAnalysis, AuditCommandState, AuditCommandStatus, AuditCycle, AuditCycleCategory,
        AuditLogEntry, AuditLogReport, AuditMutationOutcome, AuditMutationPlan, AuditStatusReport,
        AuditSuggestion, AuditSuggestionSeverity, DEFAULT_AUDIT_COMMANDS,
    },
    operations::DangerousConfirmation,
    ssh::BoundSshSession,
    target::TargetGuard,
};
use tokio::task::AbortHandle;

use crate::{app::SharedAppState, runtime::TokioBridge, theme::ThemeTokens};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuditTab {
    Commands,
    Logs,
    Analysis,
    Suggestions,
}

impl AuditTab {
    const ALL: [Self; 4] = [
        Self::Commands,
        Self::Logs,
        Self::Analysis,
        Self::Suggestions,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Commands => "命令状态",
            Self::Logs => "审计日志",
            Self::Analysis => "周期分析",
            Self::Suggestions => "处置建议",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuditBinding {
    connection_id: String,
    session_id: String,
    target: TargetGuard,
}

impl AuditBinding {
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum RequestLane {
    Status,
    Log,
    Plan,
    Mutation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuditRequestLease {
    activation_generation: u64,
    request_id: u64,
    lane: RequestLane,
    binding: AuditBinding,
}

#[derive(Debug)]
struct PendingMutation {
    plan: AuditMutationPlan,
    lease: AuditRequestLease,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum MutationIntent {
    Deploy(Vec<String>),
    Restore(Vec<String>),
    ClearLog,
}

#[derive(Debug)]
struct AuditModel {
    active: bool,
    activation_generation: u64,
    next_request_id: u64,
    latest_requests: BTreeMap<RequestLane, u64>,
    binding: Option<AuditBinding>,
    tab: AuditTab,
    custom_commands: BTreeSet<String>,
    status: Option<AuditStatusReport>,
    log: AuditLogReport,
    analysis: AuditAnalysis,
    query: String,
    filtered_log_indices: Vec<usize>,
}

impl Default for AuditModel {
    fn default() -> Self {
        Self {
            active: false,
            activation_generation: 0,
            next_request_id: 0,
            latest_requests: BTreeMap::new(),
            binding: None,
            tab: AuditTab::Commands,
            custom_commands: BTreeSet::new(),
            status: None,
            log: AuditLogReport {
                entries: Vec::new(),
                suspicious_count: 0,
                command_counts: Vec::new(),
            },
            analysis: AuditAnalysis {
                cycles: Vec::new(),
                suggestions: Vec::new(),
            },
            query: String::new(),
            filtered_log_indices: Vec::new(),
        }
    }
}

impl AuditModel {
    fn activate(&mut self, binding: Option<AuditBinding>) {
        self.active = true;
        self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
        self.rebind(binding);
    }

    fn deactivate(&mut self) {
        self.active = false;
        self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
        self.latest_requests.clear();
    }

    fn rebind(&mut self, binding: Option<AuditBinding>) {
        if self.binding == binding {
            return;
        }
        self.binding = binding;
        self.latest_requests.clear();
        self.status = None;
        self.log.entries.clear();
        self.log.command_counts.clear();
        self.log.suspicious_count = 0;
        self.analysis.cycles.clear();
        self.analysis.suggestions.clear();
        self.filtered_log_indices.clear();
    }

    fn begin_request(
        &mut self,
        binding: AuditBinding,
        lane: RequestLane,
    ) -> CoreResult<AuditRequestLease> {
        if !self.active {
            return Err(CoreError::Validation {
                subject: "check audit page",
                message: "page is not active".to_owned(),
            });
        }
        self.rebind(Some(binding.clone()));
        self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
        self.latest_requests.insert(lane, self.next_request_id);
        Ok(AuditRequestLease {
            activation_generation: self.activation_generation,
            request_id: self.next_request_id,
            lane,
            binding,
        })
    }

    fn accepts(&self, lease: &AuditRequestLease, binding: Option<&AuditBinding>) -> bool {
        self.active
            && self.activation_generation == lease.activation_generation
            && self.latest_requests.get(&lease.lane) == Some(&lease.request_id)
            && binding == Some(&lease.binding)
    }

    fn command_names(&self) -> Vec<String> {
        let mut names = DEFAULT_AUDIT_COMMANDS
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>();
        names.extend(self.custom_commands.iter().cloned());
        names.sort();
        names.dedup();
        names
    }

    fn set_query(&mut self, query: String) {
        self.query = query.trim().to_lowercase();
        self.rebuild_log_filter();
    }

    fn apply_log(&mut self, report: AuditLogReport, analysis: AuditAnalysis) {
        self.log = report;
        self.analysis = analysis;
        self.rebuild_log_filter();
    }

    fn rebuild_log_filter(&mut self) {
        self.filtered_log_indices.clear();
        for (index, entry) in self.log.entries.iter().enumerate() {
            if self.query.is_empty()
                || [
                    entry.timestamp.as_str(),
                    entry.command.as_str(),
                    entry.args.as_str(),
                    entry.user.as_str(),
                    entry.caller.as_str(),
                ]
                .iter()
                .any(|value| value.to_lowercase().contains(&self.query))
            {
                self.filtered_log_indices.push(index);
            }
        }
    }
}

pub struct CheckAuditPage {
    services: Arc<BackendServices>,
    tokio: Arc<TokioBridge>,
    shared: Entity<SharedAppState>,
    model: AuditModel,
    custom_input: Entity<InputState>,
    search_input: Entity<InputState>,
    log_scroll: UniformListScrollHandle,
    status_abort: Option<AbortHandle>,
    log_abort: Option<AbortHandle>,
    plan_abort: Option<AbortHandle>,
    status_loading: bool,
    log_loading: bool,
    plan_loading: bool,
    mutation_running: bool,
    pending_mutation: Option<PendingMutation>,
    auto_refresh_seconds: Option<u64>,
    auto_refresh_generation: u64,
    error: Option<SharedString>,
    notice: Option<SharedString>,
    _subscriptions: Vec<Subscription>,
}

impl CheckAuditPage {
    pub fn new(
        services: Arc<BackendServices>,
        tokio: Arc<TokioBridge>,
        shared: Entity<SharedAppState>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let custom_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder("添加命令名，如 openssl（最多 32 项）")
        });
        let search_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("搜索命令、参数、用户或调用者…"));
        let subscriptions = vec![
            cx.subscribe_in(
                &search_input,
                window,
                |page, input, event: &InputEvent, _, cx| {
                    if matches!(event, InputEvent::Change) {
                        page.model.set_query(input.read(cx).value().to_string());
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
            model: AuditModel::default(),
            custom_input,
            search_input,
            log_scroll: UniformListScrollHandle::new(),
            status_abort: None,
            log_abort: None,
            plan_abort: None,
            status_loading: false,
            log_loading: false,
            plan_loading: false,
            mutation_running: false,
            pending_mutation: None,
            auto_refresh_seconds: None,
            auto_refresh_generation: 0,
            error: None,
            notice: None,
            _subscriptions: subscriptions,
        }
    }

    pub fn activate(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.model.activate(self.current_binding(cx));
        self.custom_input
            .update(cx, |input, cx| input.focus(window, cx));
        self.refresh_status(cx);
        if matches!(
            self.model.tab,
            AuditTab::Logs | AuditTab::Analysis | AuditTab::Suggestions
        ) {
            self.refresh_log(cx);
        }
        self.restart_auto_refresh(cx);
    }

    pub fn deactivate(&mut self, cx: &mut Context<Self>) {
        abort_task(&mut self.status_abort);
        abort_task(&mut self.log_abort);
        abort_task(&mut self.plan_abort);
        self.model.deactivate();
        self.status_loading = false;
        self.log_loading = false;
        self.plan_loading = false;
        self.pending_mutation = None;
        self.auto_refresh_generation = self.auto_refresh_generation.wrapping_add(1).max(1);
        cx.notify();
    }

    pub const fn is_active(&self) -> bool {
        self.model.active
    }

    fn current_binding(&self, cx: &Context<Self>) -> Option<AuditBinding> {
        AuditBinding::capture(self.shared.read(cx))
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
        abort_task(&mut self.status_abort);
        abort_task(&mut self.log_abort);
        abort_task(&mut self.plan_abort);
        self.model.rebind(binding);
        self.pending_mutation = None;
        self.status_loading = false;
        self.log_loading = false;
        self.plan_loading = false;
        self.auto_refresh_generation = self.auto_refresh_generation.wrapping_add(1).max(1);
        self.error = None;
        if self.model.binding.is_some() {
            self.refresh_status(cx);
            if matches!(
                self.model.tab,
                AuditTab::Logs | AuditTab::Analysis | AuditTab::Suggestions
            ) {
                self.refresh_log(cx);
            }
            self.restart_auto_refresh(cx);
        } else {
            self.error = Some("未连接可信目标，无法使用核查审计".into());
            cx.notify();
        }
    }

    fn set_tab(&mut self, tab: AuditTab, cx: &mut Context<Self>) {
        if self.model.tab == tab {
            return;
        }
        self.model.tab = tab;
        if matches!(
            tab,
            AuditTab::Logs | AuditTab::Analysis | AuditTab::Suggestions
        ) && self.model.log.entries.is_empty()
        {
            self.refresh_log(cx);
        }
        self.restart_auto_refresh(cx);
        cx.notify();
    }

    fn add_custom_commands(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let value = self.custom_input.read(cx).value().to_string();
        let names = value
            .split([',', ';', ' ', '\n', '\r', '\t'])
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        if names.is_empty() {
            self.error = Some("请输入至少一个命令名".into());
            cx.notify();
            return;
        }
        if let Some(invalid) = names.iter().find(|name| !valid_command_name(name)) {
            self.error = Some(format!("命令名不合法：{invalid}").into());
            cx.notify();
            return;
        }
        let additional = names
            .iter()
            .filter(|name| {
                !DEFAULT_AUDIT_COMMANDS.contains(&name.as_str())
                    && !self.model.custom_commands.contains(*name)
            })
            .count();
        if DEFAULT_AUDIT_COMMANDS.len() + self.model.custom_commands.len() + additional > 32 {
            self.error = Some("命令总数不能超过 32 项".into());
            cx.notify();
            return;
        }
        for name in names {
            if !DEFAULT_AUDIT_COMMANDS.contains(&name.as_str()) {
                self.model.custom_commands.insert(name);
            }
        }
        self.custom_input
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.refresh_status(cx);
    }

    fn remove_custom_command(&mut self, name: String, cx: &mut Context<Self>) {
        self.model.custom_commands.remove(&name);
        self.refresh_status(cx);
    }

    fn refresh_status(&mut self, cx: &mut Context<Self>) {
        if self.status_loading {
            return;
        }
        let Some(session) = self.current_session(cx) else {
            self.error = Some("未连接可信目标".into());
            cx.notify();
            return;
        };
        let binding = AuditBinding::from_session(&session);
        let lease = match self.model.begin_request(binding, RequestLane::Status) {
            Ok(lease) => lease,
            Err(error) => {
                self.error = Some(error.to_string().into());
                cx.notify();
                return;
            }
        };
        abort_task(&mut self.status_abort);
        self.status_loading = true;
        self.error = None;
        let names = self.model.command_names();
        let service = self.services.audit().clone();
        let task = self
            .tokio
            .spawn(async move { service.statuses(&session, &names).await });
        self.status_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_status(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_status(
        &mut self,
        lease: AuditRequestLease,
        result: Result<CoreResult<AuditStatusReport>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            return;
        }
        self.status_loading = false;
        self.status_abort = None;
        match result {
            Ok(Ok(report)) => {
                self.model.status = Some(report);
                self.error = None;
            }
            Ok(Err(error)) => self.error = Some(format!("读取命令状态失败：{error}").into()),
            Err(error) if error.is_cancelled() => return,
            Err(error) => self.error = Some(format!("状态任务异常终止：{error}").into()),
        }
        cx.notify();
    }

    fn refresh_log(&mut self, cx: &mut Context<Self>) {
        if self.log_loading {
            return;
        }
        let Some(session) = self.current_session(cx) else {
            self.error = Some("未连接可信目标".into());
            cx.notify();
            return;
        };
        let binding = AuditBinding::from_session(&session);
        let lease = match self.model.begin_request(binding, RequestLane::Log) {
            Ok(lease) => lease,
            Err(error) => {
                self.error = Some(error.to_string().into());
                cx.notify();
                return;
            }
        };
        abort_task(&mut self.log_abort);
        self.log_loading = true;
        self.error = None;
        let service = self.services.audit().clone();
        let task = self.tokio.spawn(async move {
            let report = service.read_log(&session, 500).await?;
            let analysis = service.analyze(&report.entries);
            Ok::<_, CoreError>((report, analysis))
        });
        self.log_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_log(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_log(
        &mut self,
        lease: AuditRequestLease,
        result: Result<CoreResult<(AuditLogReport, AuditAnalysis)>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            return;
        }
        self.log_loading = false;
        self.log_abort = None;
        match result {
            Ok(Ok((report, analysis))) => {
                let count = report.entries.len();
                self.model.apply_log(report, analysis);
                self.notice = Some(format!("已读取 {count} 条审计记录").into());
                self.error = None;
            }
            Ok(Err(error)) => self.error = Some(format!("读取审计日志失败：{error}").into()),
            Err(error) if error.is_cancelled() => return,
            Err(error) => self.error = Some(format!("日志任务异常终止：{error}").into()),
        }
        cx.notify();
    }

    fn plan_mutation(&mut self, intent: MutationIntent, cx: &mut Context<Self>) {
        if self.plan_loading || self.mutation_running || self.pending_mutation.is_some() {
            return;
        }
        let Some(session) = self.current_session(cx) else {
            self.error = Some("未连接可信目标".into());
            cx.notify();
            return;
        };
        let binding = AuditBinding::from_session(&session);
        let lease = match self.model.begin_request(binding, RequestLane::Plan) {
            Ok(lease) => lease,
            Err(error) => {
                self.error = Some(error.to_string().into());
                cx.notify();
                return;
            }
        };
        abort_task(&mut self.plan_abort);
        self.plan_loading = true;
        self.error = None;
        self.notice = Some("正在重新探测远端路径与摘要，生成不可变操作计划…".into());
        let service = self.services.audit().clone();
        let task = self.tokio.spawn(async move {
            match intent {
                MutationIntent::Deploy(names) => service.plan_deploy_many(&session, &names).await,
                MutationIntent::Restore(names) => service.plan_restore_many(&session, &names).await,
                MutationIntent::ClearLog => service.plan_clear_log(&session).await,
            }
        });
        self.plan_abort = Some(task.abort_handle());
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
        lease: AuditRequestLease,
        result: Result<CoreResult<AuditMutationPlan>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            return;
        }
        self.plan_loading = false;
        self.plan_abort = None;
        match result {
            Ok(Ok(plan)) => {
                self.notice = Some("计划已生成；请核对目标与摘要后再确认。".into());
                self.pending_mutation = Some(PendingMutation { plan, lease });
                self.error = None;
            }
            Ok(Err(error)) => self.error = Some(format!("无法生成操作计划：{error}").into()),
            Err(error) if error.is_cancelled() => return,
            Err(error) => self.error = Some(format!("计划任务异常终止：{error}").into()),
        }
        cx.notify();
    }

    fn approve_pending(&mut self, cx: &mut Context<Self>) {
        if self.mutation_running {
            return;
        }
        let Some(pending) = self.pending_mutation.take() else {
            return;
        };
        let binding = self.current_binding(cx);
        if !self.model.accepts(&pending.lease, binding.as_ref()) {
            self.error = Some("目标或页面生命周期已变化，原计划已失效".into());
            cx.notify();
            return;
        }
        let Some(session) = self.current_session(cx) else {
            self.error = Some("未连接可信目标".into());
            cx.notify();
            return;
        };
        let lease = match self
            .model
            .begin_request(AuditBinding::from_session(&session), RequestLane::Mutation)
        {
            Ok(lease) => lease,
            Err(error) => {
                self.error = Some(error.to_string().into());
                cx.notify();
                return;
            }
        };
        let confirmation = DangerousConfirmation::approve(pending.plan.definition());
        let service = self.services.audit().clone();
        let journal = self.services.operation_journal().clone();
        self.mutation_running = true;
        self.error = None;
        self.notice = Some("危险操作正在执行；无论页面是否切换，仍会完成审计与验证。".into());
        let task = self.tokio.spawn(async move {
            service
                .execute_mutation(&session, pending.plan, confirmation, &journal)
                .await
        });
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_mutation(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_mutation(
        &mut self,
        lease: AuditRequestLease,
        result: Result<CoreResult<AuditMutationOutcome>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        self.mutation_running = false;
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            return;
        }
        match result {
            Ok(Ok(outcome)) if outcome.verified => {
                self.notice = Some(
                    format!(
                        "操作已执行并验证：{}",
                        if outcome.affected_commands.is_empty() {
                            outcome.detail
                        } else {
                            format!(
                                "{} · {}",
                                outcome.affected_commands.join(", "),
                                outcome.detail
                            )
                        }
                    )
                    .into(),
                );
                self.error = None;
                self.refresh_status(cx);
                self.refresh_log(cx);
            }
            Ok(Ok(outcome)) => {
                self.error = Some(
                    format!(
                        "验证未通过{}：{}",
                        if outcome.restored_after_failed_verification {
                            "，已自动恢复"
                        } else {
                            ""
                        },
                        outcome.detail
                    )
                    .into(),
                );
                self.refresh_status(cx);
            }
            Ok(Err(error)) => self.error = Some(format!("危险操作失败：{error}").into()),
            Err(error) => self.error = Some(format!("危险操作任务异常终止：{error}").into()),
        }
        cx.notify();
    }

    fn cancel_pending(&mut self, cx: &mut Context<Self>) {
        self.pending_mutation = None;
        self.notice = Some("操作计划已取消，远端未发生变化。".into());
        cx.notify();
    }

    fn plan_one(&mut self, name: String, state: AuditCommandState, cx: &mut Context<Self>) {
        match state {
            AuditCommandState::Original => {
                self.plan_mutation(MutationIntent::Deploy(vec![name]), cx)
            }
            AuditCommandState::Instrumented => {
                self.plan_mutation(MutationIntent::Restore(vec![name]), cx)
            }
            AuditCommandState::Missing | AuditCommandState::ForeignScript => {
                self.error = Some("该命令当前状态不允许自动替换或恢复".into());
                cx.notify();
            }
        }
    }

    fn plan_all(&mut self, state: AuditCommandState, cx: &mut Context<Self>) {
        let names = self
            .model
            .status
            .as_ref()
            .map(|report| {
                report
                    .commands
                    .iter()
                    .filter(|command| command.state == state)
                    .map(|command| command.name.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if names.is_empty() {
            self.error = Some("当前没有符合条件的命令".into());
            cx.notify();
            return;
        }
        match state {
            AuditCommandState::Original => self.plan_mutation(MutationIntent::Deploy(names), cx),
            AuditCommandState::Instrumented => {
                self.plan_mutation(MutationIntent::Restore(names), cx)
            }
            AuditCommandState::Missing | AuditCommandState::ForeignScript => {}
        }
    }

    fn set_auto_refresh(&mut self, seconds: Option<u64>, cx: &mut Context<Self>) {
        self.auto_refresh_seconds = seconds;
        self.restart_auto_refresh(cx);
        cx.notify();
    }

    fn restart_auto_refresh(&mut self, cx: &mut Context<Self>) {
        self.auto_refresh_generation = self.auto_refresh_generation.wrapping_add(1).max(1);
        let generation = self.auto_refresh_generation;
        let Some(seconds) = self.auto_refresh_seconds else {
            return;
        };
        if !self.model.active || self.model.tab != AuditTab::Logs {
            return;
        }
        cx.spawn(async move |page, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_secs(seconds))
                    .await;
                let mut keep_running = false;
                let _ = cx.update(|cx| {
                    if let Some(page) = page.upgrade() {
                        page.update(cx, |page, cx| {
                            if page.model.active
                                && page.model.tab == AuditTab::Logs
                                && page.auto_refresh_seconds == Some(seconds)
                                && page.auto_refresh_generation == generation
                            {
                                keep_running = true;
                                page.refresh_log(cx);
                            }
                        });
                    }
                });
                if !keep_running {
                    break;
                }
            }
        })
        .detach();
    }

    fn export_logs(&mut self, cx: &mut Context<Self>) {
        if self.model.log.entries.is_empty() {
            self.error = Some("当前没有可导出的日志".into());
            cx.notify();
            return;
        }
        let mut output =
            String::from("timestamp\tcommand\targs\tuser\tpid\tppid\tcaller\tsuspicious\n");
        for entry in &self.model.log.entries {
            output.push_str(&format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                tsv(&entry.timestamp),
                tsv(&entry.command),
                tsv(&entry.args),
                tsv(&entry.user),
                entry.pid,
                entry.ppid,
                tsv(&entry.caller),
                entry.suspicious,
            ));
        }
        cx.write_to_clipboard(ClipboardItem::new_string(output));
        self.notice = Some("审计日志已复制为 TSV。".into());
        cx.notify();
    }

    fn copy_command(&mut self, command: String, cx: &mut Context<Self>) {
        cx.write_to_clipboard(ClipboardItem::new_string(command));
        self.notice = Some("命令已复制；请先人工核对目标与影响，再决定是否执行。".into());
        cx.notify();
    }

    fn render_log_rows(
        &mut self,
        range: Range<usize>,
        tokens: ThemeTokens,
        _: &mut Context<Self>,
    ) -> Vec<AnyElement> {
        range
            .filter_map(|position| {
                let index = *self.model.filtered_log_indices.get(position)?;
                let entry = self.model.log.entries.get(index)?.clone();
                Some(log_row(entry, tokens).into_any_element())
            })
            .collect()
    }
}

impl Render for CheckAuditPage {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens = self.shared.read(cx).theme.tokens();
        let pending_summary = self.pending_mutation.as_ref().map(|pending| {
            let definition = pending.plan.definition();
            format!(
                "{} · 目标 {} · epoch {}",
                definition.summary,
                definition.target.identity.as_str(),
                definition.target.generation
            )
        });
        let content = match self.model.tab {
            AuditTab::Commands => self.render_commands(tokens, cx),
            AuditTab::Logs => self.render_logs(tokens, cx),
            AuditTab::Analysis => self.render_analysis(tokens, cx),
            AuditTab::Suggestions => self.render_suggestions(tokens, cx),
        };

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
                    .px_4()
                    .py_3()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .child(div().text_lg().font_semibold().child("核查审计"))
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(tokens.muted)
                                    .child("观察 Check 脚本调用；系统命令替换仅经不可变计划、精确确认、日志与读回验证执行。"),
                            ),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(tokens.warning)
                            .child("部署 wrapper 会短暂修改系统二进制，请确保 sudo -n 可用并预留恢复通道。"),
                    ),
            )
            .child(
                div()
                    .h(px(38.0))
                    .flex_none()
                    .flex()
                    .items_center()
                    .gap_2()
                    .children(AuditTab::ALL.into_iter().map(|tab| {
                        let selected = self.model.tab == tab;
                        crate::buttons::button(SharedString::from(format!("audit-tab-{tab:?}")))
                            .label(tab.label())
                            .small()
                            .ghost()
                            .selected(selected)
                            .on_click(cx.listener(move |page, _, _, cx| page.set_tab(tab, cx)))
                    })),
            )
            .when_some(self.error.clone(), |view, error| {
                view.child(message_banner(error, tokens.danger, tokens))
            })
            .when_some(self.notice.clone(), |view, notice| {
                view.child(message_banner(notice, tokens.accent, tokens))
            })
            .child(div().flex_1().min_h_0().child(content))
            .when_some(pending_summary, |view, summary| {
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
                        .justify_between()
                        .gap_4()
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .child(
                                    div()
                                        .font_semibold()
                                        .text_color(tokens.danger)
                                        .child("危险操作确认"),
                                )
                                .child(div().text_sm().child(summary))
                                .child(
                                    div()
                                        .text_xs()
                                        .text_color(tokens.muted)
                                        .child("确认值只对当前目标 epoch 与本次计划有效；任何状态变化都会使计划失效。"),
                                ),
                        )
                        .child(
                            div()
                                .flex()
                                .gap_2()
                                .child(
                                    crate::buttons::button("audit-plan-cancel")
                                        .label("取消")
                                        .small()
                                        .on_click(cx.listener(|page, _, _, cx| {
                                            page.cancel_pending(cx)
                                        })),
                                )
                                .child(
                                    crate::buttons::button("audit-plan-approve")
                                        .label("确认执行")
                                        .danger()
                                        .small()
                                        .disabled(self.mutation_running)
                                        .on_click(cx.listener(|page, _, _, cx| {
                                            page.approve_pending(cx)
                                        })),
                                ),
                        ),
                )
            })
    }
}

impl CheckAuditPage {
    fn render_commands(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let commands = self
            .model
            .status
            .as_ref()
            .map(|report| report.commands.clone())
            .unwrap_or_default();
        let is_root = self
            .model
            .status
            .as_ref()
            .is_some_and(|report| report.is_root);
        let original_count = commands
            .iter()
            .filter(|command| command.state == AuditCommandState::Original)
            .count();
        let instrumented_count = commands
            .iter()
            .filter(|command| command.state == AuditCommandState::Instrumented)
            .count();
        div()
            .size_full()
            .min_h_0()
            .flex()
            .flex_col()
            .rounded_lg()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .child(
                div()
                    .flex_none()
                    .p_3()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap_3()
                    .border_b_1()
                    .border_color(tokens.border)
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(div().w(px(300.0)).child(Input::new(&self.custom_input)))
                            .child(
                                crate::buttons::button("audit-add-command")
                                    .label("添加")
                                    .small()
                                    .disabled(self.status_loading || self.mutation_running)
                                    .on_click(cx.listener(|page, _, window, cx| {
                                        page.add_custom_commands(window, cx)
                                    })),
                            )
                            .child(div().text_xs().text_color(tokens.muted).child(
                                if self.model.status.is_some() {
                                    if is_root {
                                        "远端身份：root"
                                    } else {
                                        "远端身份：非 root（修改使用 sudo -n）"
                                    }
                                } else {
                                    "尚未探测"
                                },
                            )),
                    )
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .child(
                                crate::buttons::button("audit-refresh-status")
                                    .label(if self.status_loading {
                                        "探测中…"
                                    } else {
                                        "刷新状态"
                                    })
                                    .small()
                                    .disabled(self.status_loading || self.mutation_running)
                                    .on_click(
                                        cx.listener(|page, _, _, cx| page.refresh_status(cx)),
                                    ),
                            )
                            .child(
                                crate::buttons::button("audit-deploy-all")
                                    .label(format!("部署全部 · {original_count}"))
                                    .danger()
                                    .small()
                                    .disabled(
                                        original_count == 0
                                            || self.plan_loading
                                            || self.mutation_running,
                                    )
                                    .on_click(cx.listener(|page, _, _, cx| {
                                        page.plan_all(AuditCommandState::Original, cx)
                                    })),
                            )
                            .child(
                                crate::buttons::button("audit-restore-all")
                                    .label(format!("恢复全部 · {instrumented_count}"))
                                    .small()
                                    .disabled(
                                        instrumented_count == 0
                                            || self.plan_loading
                                            || self.mutation_running,
                                    )
                                    .on_click(cx.listener(|page, _, _, cx| {
                                        page.plan_all(AuditCommandState::Instrumented, cx)
                                    })),
                            ),
                    ),
            )
            .child(command_header(tokens))
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scrollbar()
                    .when(commands.is_empty(), |body| {
                        body.child(
                            div()
                                .size_full()
                                .flex()
                                .items_center()
                                .justify_center()
                                .text_color(tokens.muted)
                                .child(if self.status_loading {
                                    "正在探测远端命令…"
                                } else {
                                    "暂无命令状态"
                                }),
                        )
                    })
                    .children(
                        commands
                            .into_iter()
                            .enumerate()
                            .map(|(index, command)| self.command_row(index, command, tokens, cx)),
                    ),
            )
            .into_any_element()
    }

    fn command_row(
        &self,
        index: usize,
        command: AuditCommandStatus,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let name = command.name.clone();
        let state = command.state;
        let removable = !DEFAULT_AUDIT_COMMANDS.contains(&command.name.as_str());
        let remove_name = command.name.clone();
        div()
            .min_h(px(44.0))
            .px_3()
            .py_2()
            .flex()
            .items_center()
            .gap_3()
            .border_b_1()
            .border_color(tokens.border)
            .child(
                div()
                    .w(px(130.0))
                    .font_family("Cascadia Mono")
                    .font_semibold()
                    .child(command.name),
            )
            .child(div().w(px(116.0)).child(status_badge(state, tokens)))
            .child(
                div()
                    .w(px(80.0))
                    .text_xs()
                    .text_color(if command.critical {
                        tokens.danger
                    } else {
                        tokens.muted
                    })
                    .child(if command.critical {
                        "高影响"
                    } else {
                        "常规"
                    }),
            )
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .font_family("Cascadia Mono")
                    .text_sm()
                    .text_color(tokens.muted)
                    .overflow_hidden()
                    .child(command.path.unwrap_or_else(|| "—".to_owned())),
            )
            .child(
                div()
                    .w(px(188.0))
                    .flex_none()
                    .flex()
                    .justify_end()
                    .gap_2()
                    .when(removable, |actions| {
                        actions.child(
                            crate::buttons::button(SharedString::from(format!(
                                "audit-remove-{index}"
                            )))
                            .label("移除")
                            .xsmall()
                            .ghost()
                            .disabled(self.status_loading || self.mutation_running)
                            .on_click(cx.listener(
                                move |page, _, _, cx| {
                                    page.remove_custom_command(remove_name.clone(), cx)
                                },
                            )),
                        )
                    })
                    .when(
                        matches!(
                            state,
                            AuditCommandState::Original | AuditCommandState::Instrumented
                        ),
                        |actions| {
                            actions.child(
                                crate::buttons::button(SharedString::from(format!(
                                    "audit-action-{index}"
                                )))
                                .label(if state == AuditCommandState::Original {
                                    "部署审计"
                                } else {
                                    "恢复原始"
                                })
                                .small()
                                .when(state == AuditCommandState::Original, |button| {
                                    button.danger()
                                })
                                .disabled(self.plan_loading || self.mutation_running)
                                .on_click(cx.listener(
                                    move |page, _, _, cx| page.plan_one(name.clone(), state, cx),
                                )),
                            )
                        },
                    ),
            )
            .into_any_element()
    }

    fn render_logs(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let row_count = self.model.filtered_log_indices.len();
        let scroll = self.log_scroll.clone();
        div()
            .size_full()
            .min_h_0()
            .flex()
            .flex_col()
            .rounded_lg()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .child(
                div()
                    .flex_none()
                    .p_3()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap_3()
                    .border_b_1()
                    .border_color(tokens.border)
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .flex()
                            .items_center()
                            .gap_3()
                            .child(div().w(px(340.0)).child(Input::new(&self.search_input)))
                            .child(div().text_sm().child(format!(
                                "显示 {row_count} / {} · 可疑 {}",
                                self.model.log.entries.len(),
                                self.model.log.suspicious_count
                            ))),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(div().text_xs().text_color(tokens.muted).child("自动"))
                            .children([None, Some(3), Some(5), Some(10)].into_iter().map(
                                |seconds| {
                                    let selected = self.auto_refresh_seconds == seconds;
                                    crate::buttons::button(SharedString::from(format!(
                                        "audit-auto-{}",
                                        seconds.unwrap_or_default()
                                    )))
                                    .label(seconds.map_or_else(
                                        || "关".to_owned(),
                                        |value| format!("{value}s"),
                                    ))
                                    .xsmall()
                                    .ghost()
                                    .selected(selected)
                                    .on_click(cx.listener(move |page, _, _, cx| {
                                        page.set_auto_refresh(seconds, cx)
                                    }))
                                },
                            ))
                            .child(
                                crate::buttons::button("audit-log-refresh")
                                    .label(if self.log_loading {
                                        "刷新中…"
                                    } else {
                                        "刷新"
                                    })
                                    .small()
                                    .disabled(self.log_loading)
                                    .on_click(cx.listener(|page, _, _, cx| page.refresh_log(cx))),
                            )
                            .child(
                                crate::buttons::button("audit-log-export")
                                    .label("复制 TSV")
                                    .small()
                                    .disabled(self.model.log.entries.is_empty())
                                    .on_click(cx.listener(|page, _, _, cx| page.export_logs(cx))),
                            )
                            .child(
                                crate::buttons::button("audit-log-clear")
                                    .label("清空")
                                    .danger()
                                    .small()
                                    .disabled(
                                        self.plan_loading
                                            || self.mutation_running
                                            || self.pending_mutation.is_some(),
                                    )
                                    .on_click(cx.listener(|page, _, _, cx| {
                                        page.plan_mutation(MutationIntent::ClearLog, cx)
                                    })),
                            ),
                    ),
            )
            .when(!self.model.log.command_counts.is_empty(), |view| {
                view.child(
                    div()
                        .flex_none()
                        .px_3()
                        .py_2()
                        .flex()
                        .gap_2()
                        .overflow_x_scrollbar()
                        .children(self.model.log.command_counts.iter().take(12).map(|count| {
                            div()
                                .flex_none()
                                .rounded_md()
                                .bg(tokens.surface_alt)
                                .px_2()
                                .py_1()
                                .text_xs()
                                .child(format!("{} · {}", count.command, count.count))
                        })),
                )
            })
            .child(log_header(tokens))
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
                                .child(if self.log_loading {
                                    "正在读取审计日志…"
                                } else if self.model.log.entries.is_empty() {
                                    "暂无审计记录；部署 wrapper 后执行 Check 流程即可采集。"
                                } else {
                                    "没有符合搜索条件的记录"
                                }),
                        )
                    })
                    .when(row_count > 0, |body| {
                        body.child(
                            uniform_list(
                                "audit-log-rows",
                                row_count,
                                cx.processor(move |page, range: Range<usize>, _, cx| {
                                    page.render_log_rows(range, tokens, cx)
                                }),
                            )
                            .size_full()
                            .track_scroll(scroll),
                        )
                    }),
            )
            .into_any_element()
    }

    fn render_analysis(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let cycles = self.model.analysis.cycles.clone();
        div()
            .size_full()
            .min_h_0()
            .flex()
            .flex_col()
            .rounded_lg()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .child(
                div()
                    .h(px(44.0))
                    .flex_none()
                    .px_3()
                    .flex()
                    .items_center()
                    .justify_between()
                    .border_b_1()
                    .border_color(tokens.border)
                    .child(
                        div()
                            .font_semibold()
                            .child(format!("周期行为 · {}", cycles.len())),
                    )
                    .child(
                        crate::buttons::button("audit-analysis-refresh")
                            .label("重新读取并分析")
                            .small()
                            .disabled(self.log_loading)
                            .on_click(cx.listener(|page, _, _, cx| page.refresh_log(cx))),
                    ),
            )
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scrollbar()
                    .when(cycles.is_empty(), |body| {
                        body.child(
                            div()
                                .size_full()
                                .flex()
                                .items_center()
                                .justify_center()
                                .text_color(tokens.muted)
                                .child("至少需要同一命令与参数的多次记录，才能识别周期行为。"),
                        )
                    })
                    .children(
                        cycles
                            .into_iter()
                            .enumerate()
                            .map(|(index, cycle)| cycle_row(index, cycle, tokens)),
                    ),
            )
            .into_any_element()
    }

    fn render_suggestions(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let suggestions = self.model.analysis.suggestions.clone();
        div()
            .size_full()
            .min_h_0()
            .flex()
            .flex_col()
            .rounded_lg()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .child(
                div()
                    .h(px(44.0))
                    .flex_none()
                    .px_3()
                    .flex()
                    .items_center()
                    .justify_between()
                    .border_b_1()
                    .border_color(tokens.border)
                    .child(
                        div()
                            .font_semibold()
                            .child(format!("处置建议 · {}", suggestions.len())),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(tokens.muted)
                            .child("这里只复制命令，不自动执行。"),
                    ),
            )
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scrollbar()
                    .p_3()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .when(suggestions.is_empty(), |body| {
                        body.child(
                            div()
                                .size_full()
                                .flex()
                                .items_center()
                                .justify_center()
                                .text_color(tokens.muted)
                                .child("当前分析尚未生成处置建议。"),
                        )
                    })
                    .children(
                        suggestions
                            .into_iter()
                            .enumerate()
                            .map(|(index, suggestion)| {
                                self.suggestion_card(index, suggestion, tokens, cx)
                            }),
                    ),
            )
            .into_any_element()
    }

    fn suggestion_card(
        &self,
        index: usize,
        suggestion: AuditSuggestion,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let check = suggestion.check_command.clone();
        let fix = suggestion.fix_command.clone();
        let severity_color = suggestion_color(suggestion.severity, tokens);
        div()
            .rounded_lg()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.background)
            .p_3()
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .font_semibold()
                            .text_color(severity_color)
                            .child(suggestion.title),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(severity_color)
                            .child(suggestion_severity_label(suggestion.severity)),
                    ),
            )
            .child(
                div()
                    .mt_1()
                    .text_sm()
                    .text_color(tokens.muted)
                    .child(suggestion.description),
            )
            .child(
                div()
                    .mt_3()
                    .rounded_md()
                    .bg(tokens.surface_alt)
                    .p_2()
                    .font_family("Cascadia Mono")
                    .text_sm()
                    .child(check.clone()),
            )
            .child(
                div()
                    .mt_2()
                    .flex()
                    .justify_end()
                    .gap_2()
                    .child(
                        crate::buttons::button(SharedString::from(format!(
                            "audit-copy-check-{index}"
                        )))
                        .label("复制核查命令")
                        .small()
                        .on_click(
                            cx.listener(move |page, _, _, cx| page.copy_command(check.clone(), cx)),
                        ),
                    )
                    .child(
                        crate::buttons::button(SharedString::from(format!(
                            "audit-copy-fix-{index}"
                        )))
                        .label("复制建议命令")
                        .small()
                        .on_click(
                            cx.listener(move |page, _, _, cx| page.copy_command(fix.clone(), cx)),
                        ),
                    ),
            )
            .into_any_element()
    }
}

fn command_header(tokens: ThemeTokens) -> impl IntoElement {
    div()
        .h(px(34.0))
        .flex_none()
        .px_3()
        .flex()
        .items_center()
        .gap_3()
        .bg(tokens.surface_alt)
        .border_b_1()
        .border_color(tokens.border)
        .text_xs()
        .text_color(tokens.muted)
        .child(div().w(px(130.0)).child("命令"))
        .child(div().w(px(116.0)).child("状态"))
        .child(div().w(px(80.0)).child("影响"))
        .child(div().flex_1().child("远端真实路径"))
        .child(div().w(px(188.0)).text_right().child("操作"))
}

fn log_header(tokens: ThemeTokens) -> impl IntoElement {
    div()
        .h(px(34.0))
        .flex_none()
        .px_3()
        .flex()
        .items_center()
        .gap_3()
        .bg(tokens.surface_alt)
        .border_b_1()
        .border_color(tokens.border)
        .text_xs()
        .text_color(tokens.muted)
        .child(div().w(px(154.0)).child("时间"))
        .child(div().w(px(100.0)).child("命令"))
        .child(div().flex_1().child("参数"))
        .child(div().w(px(100.0)).child("用户"))
        .child(div().w(px(86.0)).child("PID / PPID"))
        .child(div().w(px(120.0)).child("调用者"))
}

fn log_row(entry: AuditLogEntry, tokens: ThemeTokens) -> impl IntoElement {
    let color = if entry.suspicious {
        tokens.danger
    } else {
        tokens.text
    };
    div()
        .h(px(38.0))
        .px_3()
        .flex()
        .items_center()
        .gap_3()
        .border_b_1()
        .border_color(tokens.border)
        .text_sm()
        .text_color(color)
        .child(div().w(px(154.0)).text_xs().child(entry.timestamp))
        .child(
            div()
                .w(px(100.0))
                .font_family("Cascadia Mono")
                .font_semibold()
                .child(entry.command),
        )
        .child(
            div()
                .flex_1()
                .min_w_0()
                .overflow_hidden()
                .font_family("Cascadia Mono")
                .child(entry.args),
        )
        .child(div().w(px(100.0)).child(entry.user))
        .child(
            div()
                .w(px(86.0))
                .text_xs()
                .child(format!("{} / {}", entry.pid, entry.ppid)),
        )
        .child(div().w(px(120.0)).overflow_hidden().child(entry.caller))
}

fn cycle_row(index: usize, cycle: AuditCycle, tokens: ThemeTokens) -> impl IntoElement {
    div()
        .id(SharedString::from(format!("audit-cycle-{index}")))
        .min_h(px(58.0))
        .px_3()
        .py_2()
        .flex()
        .items_center()
        .gap_3()
        .border_b_1()
        .border_color(tokens.border)
        .child(
            div()
                .w(px(110.0))
                .font_family("Cascadia Mono")
                .font_semibold()
                .child(cycle.command),
        )
        .child(
            div()
                .w(px(100.0))
                .text_sm()
                .text_color(tokens.accent)
                .child(cycle_category_label(cycle.category)),
        )
        .child(
            div()
                .flex_1()
                .min_w_0()
                .font_family("Cascadia Mono")
                .text_sm()
                .child(cycle.args),
        )
        .child(
            div()
                .w(px(120.0))
                .text_sm()
                .child(cycle.interval_seconds.map_or_else(
                    || "未识别周期".to_owned(),
                    |seconds| format!("约每 {seconds}s"),
                )),
        )
        .child(
            div()
                .w(px(90.0))
                .text_sm()
                .child(format!("{} 次", cycle.count)),
        )
        .child(
            div()
                .w(px(150.0))
                .text_xs()
                .text_color(tokens.muted)
                .child(cycle.last_seen),
        )
}

fn status_badge(state: AuditCommandState, tokens: ThemeTokens) -> impl IntoElement {
    let (label, color) = match state {
        AuditCommandState::Original => ("原始二进制", tokens.success),
        AuditCommandState::Instrumented => ("已部署审计", tokens.accent),
        AuditCommandState::Missing => ("未安装", tokens.muted),
        AuditCommandState::ForeignScript => ("未知脚本", tokens.warning),
    };
    div()
        .rounded_md()
        .bg(tokens.surface_alt)
        .px_2()
        .py_1()
        .text_xs()
        .text_color(color)
        .child(label)
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

const fn cycle_category_label(category: AuditCycleCategory) -> &'static str {
    match category {
        AuditCycleCategory::FileRead => "文件读取",
        AuditCycleCategory::ServiceCheck => "服务探测",
        AuditCycleCategory::Network => "网络访问",
        AuditCycleCategory::Database => "数据库",
        AuditCycleCategory::Process => "进程行为",
    }
}

const fn suggestion_severity_label(severity: AuditSuggestionSeverity) -> &'static str {
    match severity {
        AuditSuggestionSeverity::Critical => "高风险",
        AuditSuggestionSeverity::Warning => "需关注",
        AuditSuggestionSeverity::Info => "信息",
    }
}

const fn suggestion_color(severity: AuditSuggestionSeverity, tokens: ThemeTokens) -> gpui::Rgba {
    match severity {
        AuditSuggestionSeverity::Critical => tokens.danger,
        AuditSuggestionSeverity::Warning => tokens.warning,
        AuditSuggestionSeverity::Info => tokens.accent,
    }
}

fn tsv(value: &str) -> String {
    value.replace(['\t', '\n', '\r'], " ")
}

fn valid_command_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && name.len() <= 128
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
}

fn abort_task(task: &mut Option<AbortHandle>) {
    if let Some(task) = task.take() {
        task.abort();
    }
}

#[cfg(test)]
mod tests {
    use lovelyres_core::target::{TargetContext, TargetIdentity};

    use super::*;

    fn binding(context: &TargetContext, identity: &str, session: &str) -> AuditBinding {
        AuditBinding {
            connection_id: identity.to_owned(),
            session_id: session.to_owned(),
            target: context
                .activate(TargetIdentity::new(identity).unwrap())
                .unwrap(),
        }
    }

    #[test]
    fn stale_results_are_rejected_per_lane_after_target_or_lifecycle_change() {
        let context = TargetContext::new();
        let first = binding(&context, "a", "session-a");
        let mut model = AuditModel::default();
        model.activate(Some(first.clone()));
        let status = model
            .begin_request(first.clone(), RequestLane::Status)
            .unwrap();
        let log = model
            .begin_request(first.clone(), RequestLane::Log)
            .unwrap();
        assert!(model.accepts(&status, Some(&first)));
        assert!(model.accepts(&log, Some(&first)));

        let second = binding(&context, "b", "session-b");
        model.rebind(Some(second.clone()));
        assert!(!model.accepts(&status, Some(&second)));
        assert!(!model.accepts(&log, Some(&second)));
        model.deactivate();
        assert!(!model.accepts(&status, Some(&first)));
    }

    #[test]
    fn log_filter_treats_remote_markup_as_plain_searchable_text() {
        let mut model = AuditModel::default();
        model.apply_log(
            AuditLogReport {
                entries: vec![AuditLogEntry {
                    timestamp: "2026-08-11".to_owned(),
                    command: "cat".to_owned(),
                    args: "/tmp/<script>alert(1)</script>".to_owned(),
                    user: "root".to_owned(),
                    pid: 1,
                    ppid: 0,
                    caller: "check".to_owned(),
                    raw: "raw".to_owned(),
                    suspicious: true,
                }],
                suspicious_count: 1,
                command_counts: Vec::new(),
            },
            AuditAnalysis {
                cycles: Vec::new(),
                suggestions: Vec::new(),
            },
        );
        model.set_query("<script>".to_owned());
        assert_eq!(model.filtered_log_indices, vec![0]);
    }

    #[test]
    fn custom_commands_are_deduplicated_without_replacing_defaults() {
        let mut model = AuditModel::default();
        model.custom_commands.insert("openssl".to_owned());
        model.custom_commands.insert("cat".to_owned());
        let names = model.command_names();
        assert_eq!(names.iter().filter(|name| *name == "cat").count(), 1);
        assert!(names.contains(&"openssl".to_owned()));
    }

    #[test]
    fn exported_cells_cannot_inject_tsv_rows() {
        assert_eq!(tsv("a\tb\nc\r"), "a b c ");
    }

    #[test]
    fn custom_command_validation_matches_the_typed_core_boundary() {
        assert!(valid_command_name("redis-cli"));
        for invalid in ["", "-rf", "cat;id", "../cat", "a b", "a\nwhoami"] {
            assert!(!valid_command_name(invalid), "accepted {invalid:?}");
        }
    }
}
