use std::{sync::Arc, time::Duration};

use gpui::{
    AnyElement, ClipboardItem, Context, Entity, EventEmitter, IntoElement, Render, SharedString,
    Subscription, Window, div, prelude::*, px,
};
use gpui_component::{
    Disableable, Sizable,
    button::ButtonVariants,
    input::{Input, InputEvent, InputState},
    scroll::ScrollableElement,
};
use lovelyres_core::{
    BackendServices, CoreError, CoreResult,
    investigation::{
        AddCommandHistory, CommandHistoryClearPlan, CommandHistoryRecord, CommandHistoryRemovePlan,
        CommandHistoryRepository, CommandReplayIntent, CommandReplayPlan, CommandRisk,
        InvestigationOperationOutcome, MAX_COMMAND_HISTORY, ReplayBlockReason,
    },
    operations::{DangerousConfirmation, OperationPlan},
    ssh::{BoundSshSession, SshCommandOutput},
    target::TargetGuard,
};

use crate::{
    app::SharedAppState,
    interaction::{DialogAction, DialogError, DialogId, DialogOutcome},
    runtime::TokioBridge,
    theme::ThemeTokens,
};

const MAX_SEARCH_CHARS: usize = 256;
const MAX_PREVIEW_CHARS: usize = 100;
const REPLAY_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandHistoryEvent {
    CloseRequested,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandHistoryBinding {
    connection_id: String,
    session_id: String,
    target: TargetGuard,
}

impl CommandHistoryBinding {
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

    fn label(&self) -> String {
        format!(
            "目标 {} · SSH {} · generation {}",
            self.target.identity.as_str(),
            self.session_id,
            self.target.generation
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandHistoryRequestLease {
    activation_generation: u64,
    request_id: u64,
    binding: CommandHistoryBinding,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CommandHistoryMutationKind {
    Remove,
    Clear,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CommandHistoryMutationPlan {
    Remove(CommandHistoryRemovePlan),
    Clear(CommandHistoryClearPlan),
}

impl CommandHistoryMutationPlan {
    fn definition(&self) -> &OperationPlan {
        match self {
            Self::Remove(plan) => plan.definition(),
            Self::Clear(plan) => plan.definition(),
        }
    }

    const fn kind(&self) -> CommandHistoryMutationKind {
        match self {
            Self::Remove(_) => CommandHistoryMutationKind::Remove,
            Self::Clear(_) => CommandHistoryMutationKind::Clear,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CommandHistoryMutationProposal {
    presentation: CommandHistoryRequestLease,
    plan: CommandHistoryMutationPlan,
}

impl CommandHistoryMutationProposal {
    fn definition(&self) -> &OperationPlan {
        self.plan.definition()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingCommandHistoryMutation {
    proposal: CommandHistoryMutationProposal,
    dialog_id: DialogId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CommandHistoryMutationResolution {
    Ignored,
    Cancelled,
    Stale,
    Authorized {
        plan: Box<CommandHistoryMutationPlan>,
        confirmation: DangerousConfirmation,
        presentation: CommandHistoryRequestLease,
    },
}

#[derive(Debug, Default)]
pub struct CommandHistoryModel {
    active: bool,
    activation_generation: u64,
    next_request_id: u64,
    binding: Option<CommandHistoryBinding>,
    records: Vec<CommandHistoryRecord>,
    selected_id: Option<String>,
    query: String,
    latest_list_request: Option<u64>,
    latest_replay_request: Option<u64>,
    pending_mutation: Option<PendingCommandHistoryMutation>,
}

impl CommandHistoryModel {
    pub fn activate(&mut self, binding: Option<CommandHistoryBinding>) -> u64 {
        self.active = true;
        self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
        self.rebind(binding);
        self.activation_generation
    }

    pub fn deactivate(&mut self) {
        self.active = false;
        self.latest_list_request = None;
        self.latest_replay_request = None;
        self.pending_mutation = None;
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn binding(&self) -> Option<&CommandHistoryBinding> {
        self.binding.as_ref()
    }

    pub fn records(&self) -> &[CommandHistoryRecord] {
        &self.records
    }

    pub fn selected(&self) -> Option<&CommandHistoryRecord> {
        let selected_id = self.selected_id.as_deref()?;
        self.records.iter().find(|record| record.id == selected_id)
    }

    pub fn selected_id(&self) -> Option<&str> {
        self.selected_id.as_deref()
    }

    pub fn select(&mut self, id: &str) -> bool {
        if !self.records.iter().any(|record| record.id == id) {
            return false;
        }
        self.selected_id = Some(id.to_owned());
        true
    }

    pub fn query(&self) -> &str {
        &self.query
    }

    pub fn set_query(&mut self, query: impl Into<String>) {
        self.query = query.into().chars().take(MAX_SEARCH_CHARS).collect();
    }

    pub const fn is_loading(&self) -> bool {
        self.latest_list_request.is_some()
    }

    pub const fn is_replaying(&self) -> bool {
        self.latest_replay_request.is_some()
    }

    fn rebind(&mut self, binding: Option<CommandHistoryBinding>) {
        if self.binding == binding {
            return;
        }
        self.binding = binding;
        self.records.clear();
        self.selected_id = None;
        self.latest_list_request = None;
        self.latest_replay_request = None;
        // Keep a pending proposal long enough for a matching confirmation to be
        // classified as stale. It can never execute against the new binding.
    }

    fn new_lease(&mut self) -> CoreResult<CommandHistoryRequestLease> {
        if !self.active {
            return Err(CoreError::Validation {
                subject: "command history overlay",
                message: "overlay is not active".to_owned(),
            });
        }
        let binding = self.binding.clone().ok_or(CoreError::NoActiveTarget)?;
        self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
        Ok(CommandHistoryRequestLease {
            activation_generation: self.activation_generation,
            request_id: self.next_request_id,
            binding,
        })
    }

    fn begin_list(
        &mut self,
        binding: Option<CommandHistoryBinding>,
    ) -> CoreResult<CommandHistoryRequestLease> {
        self.rebind(binding);
        let lease = self.new_lease()?;
        self.latest_list_request = Some(lease.request_id);
        Ok(lease)
    }

    fn begin_replay(
        &mut self,
        id: &str,
        binding: Option<CommandHistoryBinding>,
    ) -> CoreResult<CommandHistoryRequestLease> {
        self.rebind(binding);
        if !self.records.iter().any(|record| record.id == id) {
            return Err(CoreError::Validation {
                subject: "command history replay",
                message: "selected record no longer exists in the active target view".to_owned(),
            });
        }
        let lease = self.new_lease()?;
        self.latest_replay_request = Some(lease.request_id);
        Ok(lease)
    }

    pub fn accepts(
        &self,
        lease: &CommandHistoryRequestLease,
        current_binding: Option<&CommandHistoryBinding>,
    ) -> bool {
        self.active
            && self.activation_generation == lease.activation_generation
            && self.binding.as_ref() == Some(&lease.binding)
            && current_binding == Some(&lease.binding)
    }

    fn apply_list(
        &mut self,
        lease: &CommandHistoryRequestLease,
        current_binding: Option<&CommandHistoryBinding>,
        mut records: Vec<CommandHistoryRecord>,
    ) -> bool {
        if self.latest_list_request != Some(lease.request_id)
            || !self.accepts(lease, current_binding)
        {
            return false;
        }
        self.latest_list_request = None;
        records.truncate(MAX_COMMAND_HISTORY);
        let previous = self.selected_id.clone();
        self.records = records;
        self.selected_id = previous
            .filter(|id| self.records.iter().any(|record| record.id == *id))
            .or_else(|| self.records.first().map(|record| record.id.clone()));
        true
    }

    fn reject_list(
        &mut self,
        lease: &CommandHistoryRequestLease,
        current_binding: Option<&CommandHistoryBinding>,
    ) -> bool {
        if self.latest_list_request != Some(lease.request_id)
            || !self.accepts(lease, current_binding)
        {
            return false;
        }
        self.latest_list_request = None;
        true
    }

    fn apply_replay(
        &mut self,
        lease: &CommandHistoryRequestLease,
        current_binding: Option<&CommandHistoryBinding>,
        record: CommandHistoryRecord,
    ) -> bool {
        if self.latest_replay_request != Some(lease.request_id)
            || !self.accepts(lease, current_binding)
        {
            return false;
        }
        self.latest_replay_request = None;
        self.records.retain(|item| item.id != record.id);
        self.selected_id = Some(record.id.clone());
        self.records.insert(0, record);
        self.records.truncate(MAX_COMMAND_HISTORY);
        true
    }

    fn reject_replay(
        &mut self,
        lease: &CommandHistoryRequestLease,
        current_binding: Option<&CommandHistoryBinding>,
    ) -> bool {
        if self.latest_replay_request != Some(lease.request_id)
            || !self.accepts(lease, current_binding)
        {
            return false;
        }
        self.latest_replay_request = None;
        true
    }

    fn propose_remove(
        &mut self,
        id: &str,
        current_binding: Option<&CommandHistoryBinding>,
        repository: &CommandHistoryRepository,
    ) -> CoreResult<CommandHistoryMutationProposal> {
        self.ensure_current_binding(current_binding)?;
        if !self.records.iter().any(|record| record.id == id) {
            return Err(CoreError::Validation {
                subject: "command history record",
                message: "selected record no longer exists".to_owned(),
            });
        }
        let presentation = self.new_lease()?;
        let plan = repository.plan_remove(&presentation.binding.target.identity, id)?;
        Ok(CommandHistoryMutationProposal {
            presentation,
            plan: CommandHistoryMutationPlan::Remove(plan),
        })
    }

    fn propose_clear(
        &mut self,
        current_binding: Option<&CommandHistoryBinding>,
        repository: &CommandHistoryRepository,
    ) -> CoreResult<CommandHistoryMutationProposal> {
        self.ensure_current_binding(current_binding)?;
        if self.records.is_empty() {
            return Err(CoreError::Validation {
                subject: "command history",
                message: "there are no records to clear for the active target".to_owned(),
            });
        }
        let presentation = self.new_lease()?;
        let plan = repository.plan_clear_for_target(&presentation.binding.target.identity)?;
        if plan.record_count() == 0 {
            return Err(CoreError::Validation {
                subject: "command history",
                message: "there are no records to clear for the active target".to_owned(),
            });
        }
        Ok(CommandHistoryMutationProposal {
            presentation,
            plan: CommandHistoryMutationPlan::Clear(plan),
        })
    }

    fn ensure_current_binding(
        &self,
        current_binding: Option<&CommandHistoryBinding>,
    ) -> CoreResult<()> {
        if !self.active {
            return Err(CoreError::Validation {
                subject: "command history overlay",
                message: "overlay is not active".to_owned(),
            });
        }
        if self.binding.as_ref() != current_binding {
            return Err(CoreError::Validation {
                subject: "command history target",
                message: "the active SSH target changed; refresh before continuing".to_owned(),
            });
        }
        if current_binding.is_none() {
            return Err(CoreError::NoActiveTarget);
        }
        Ok(())
    }

    fn arm_mutation(&mut self, proposal: CommandHistoryMutationProposal, dialog_id: DialogId) {
        self.pending_mutation = Some(PendingCommandHistoryMutation {
            proposal,
            dialog_id,
        });
    }

    fn pending_dialog_id(&self) -> Option<DialogId> {
        self.pending_mutation
            .as_ref()
            .map(|pending| pending.dialog_id)
    }

    fn resolve_mutation(
        &mut self,
        outcome: &DialogOutcome,
        current_binding: Option<&CommandHistoryBinding>,
    ) -> CommandHistoryMutationResolution {
        let Some(pending) = self.pending_mutation.as_ref() else {
            return CommandHistoryMutationResolution::Ignored;
        };
        let matches_dialog = match outcome {
            DialogOutcome::Cancelled { dialog_id }
            | DialogOutcome::DangerousApproved { dialog_id, .. } => *dialog_id == pending.dialog_id,
            DialogOutcome::AlertDismissed { .. } | DialogOutcome::PromptSubmitted { .. } => false,
        };
        if !matches_dialog {
            return CommandHistoryMutationResolution::Ignored;
        }
        let pending = self
            .pending_mutation
            .take()
            .expect("the matching pending command-history mutation exists");
        match outcome {
            DialogOutcome::Cancelled { .. } => CommandHistoryMutationResolution::Cancelled,
            DialogOutcome::DangerousApproved { operation_id, .. }
                if operation_id == &pending.proposal.definition().id =>
            {
                if !self.accepts(&pending.proposal.presentation, current_binding) {
                    return CommandHistoryMutationResolution::Stale;
                }
                CommandHistoryMutationResolution::Authorized {
                    confirmation: DangerousConfirmation::approve(pending.proposal.definition()),
                    presentation: pending.proposal.presentation,
                    plan: Box::new(pending.proposal.plan),
                }
            }
            DialogOutcome::DangerousApproved { .. } => CommandHistoryMutationResolution::Ignored,
            DialogOutcome::AlertDismissed { .. } | DialogOutcome::PromptSubmitted { .. } => {
                CommandHistoryMutationResolution::Ignored
            }
        }
    }
}

struct ReplayExecution {
    output: SshCommandOutput,
    history: CommandHistoryRecord,
}

pub struct CommandHistoryOverlay {
    services: Arc<BackendServices>,
    tokio: Arc<TokioBridge>,
    shared: Entity<SharedAppState>,
    model: CommandHistoryModel,
    search_input: Entity<InputState>,
    list_abort: Option<tokio::task::AbortHandle>,
    replay_abort: Option<tokio::task::AbortHandle>,
    mutations_in_flight: usize,
    notice: Option<(SharedString, bool)>,
    _subscriptions: Vec<Subscription>,
}

impl EventEmitter<CommandHistoryEvent> for CommandHistoryOverlay {}

impl CommandHistoryOverlay {
    pub fn new(
        services: Arc<BackendServices>,
        tokio: Arc<TokioBridge>,
        shared: Entity<SharedAppState>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let search_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("搜索命令、标题、输出或来源…"));
        let subscriptions = vec![
            cx.subscribe_in(
                &search_input,
                window,
                |overlay, input, event: &InputEvent, _, cx| {
                    if matches!(event, InputEvent::Change) {
                        overlay.model.set_query(input.read(cx).value().to_string());
                        overlay.refresh(cx);
                    }
                },
            ),
            cx.observe(&shared, |overlay, _, cx| {
                overlay.handle_shared_change(cx);
            }),
        ];
        Self {
            services,
            tokio,
            shared,
            model: CommandHistoryModel::default(),
            search_input,
            list_abort: None,
            replay_abort: None,
            mutations_in_flight: 0,
            notice: None,
            _subscriptions: subscriptions,
        }
    }

    pub fn activate(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let binding = self.current_binding(cx);
        self.model.activate(binding);
        self.search_input
            .update(cx, |input, cx| input.focus(window, cx));
        self.refresh(cx);
        cx.notify();
    }

    pub const fn is_active(&self) -> bool {
        self.model.is_active()
    }

    pub fn deactivate(&mut self, cx: &mut Context<Self>) {
        abort_task(&mut self.list_abort);
        abort_task(&mut self.replay_abort);
        if let Some(dialog_id) = self.model.pending_dialog_id() {
            self.shared.update(cx, |state, cx| {
                if state
                    .interactions
                    .dialogs
                    .active()
                    .map(|dialog| dialog.id())
                    == Some(dialog_id)
                {
                    let _ = state
                        .interactions
                        .dialogs
                        .dispatch(DialogAction::Cancel { dialog_id });
                    state.interactions.mark_overlay_closed();
                    cx.notify();
                }
            });
        }
        // Confirmed local mutations deliberately have no abort handle. Their
        // plan/journal/verify sequence must finish after this presentation closes.
        self.model.deactivate();
        cx.notify();
    }

    pub fn request_close(&mut self, cx: &mut Context<Self>) {
        cx.emit(CommandHistoryEvent::CloseRequested);
    }

    fn current_binding(&self, cx: &Context<Self>) -> Option<CommandHistoryBinding> {
        CommandHistoryBinding::capture(self.shared.read(cx))
    }

    fn current_session(&self, cx: &Context<Self>) -> Option<BoundSshSession> {
        self.shared
            .read(cx)
            .active_ssh
            .as_ref()
            .map(|active| active.session.clone())
    }

    fn handle_shared_change(&mut self, cx: &mut Context<Self>) {
        if !self.model.is_active() {
            return;
        }
        let binding = self.current_binding(cx);
        if self.model.binding() == binding.as_ref() {
            return;
        }
        abort_task(&mut self.list_abort);
        abort_task(&mut self.replay_abort);
        self.model.rebind(binding.clone());
        if binding.is_some() {
            self.notice = Some(("活动目标已变化，命令历史已重新绑定".into(), false));
            self.refresh(cx);
        } else {
            self.notice = Some(("未连接 SSH 目标，无法读取命令历史".into(), true));
            cx.notify();
        }
    }

    fn refresh(&mut self, cx: &mut Context<Self>) {
        let current_binding = self.current_binding(cx);
        let lease = match self.model.begin_list(current_binding) {
            Ok(lease) => lease,
            Err(error) => {
                self.notice = Some((format!("命令历史无法加载：{error}").into(), true));
                cx.notify();
                return;
            }
        };
        abort_task(&mut self.list_abort);
        let query = self.model.query().to_owned();
        let repository = self.services.investigation().command_history().clone();
        let target_context = Arc::clone(self.services.target());
        let guard = lease.binding.target.clone();
        let target = guard.identity.clone();
        let task = self.tokio.spawn(async move {
            target_context.validate(&guard)?;
            let result = if query.trim().is_empty() {
                repository.list_for_target(&target)
            } else {
                repository.search(&target, &query)
            }?;
            target_context.validate(&guard)?;
            Ok(result)
        });
        self.list_abort = Some(task.abort_handle());
        cx.spawn(async move |overlay, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(overlay) = overlay.upgrade() {
                    overlay.update(cx, |overlay, cx| {
                        overlay.finish_refresh(lease, result, cx);
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_refresh(
        &mut self,
        lease: CommandHistoryRequestLease,
        result: Result<CoreResult<Vec<CommandHistoryRecord>>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let current = self.current_binding(cx);
        if !self.model.accepts(&lease, current.as_ref()) {
            return;
        }
        match result {
            Err(error) if error.is_cancelled() => {}
            Err(error) => {
                if self.model.reject_list(&lease, current.as_ref()) {
                    self.list_abort = None;
                    self.notice = Some((format!("命令历史加载任务失败：{error}").into(), true));
                    cx.notify();
                }
            }
            Ok(Err(error)) => {
                if self.model.reject_list(&lease, current.as_ref()) {
                    self.list_abort = None;
                    self.notice = Some((format!("命令历史读取失败：{error}").into(), true));
                    cx.notify();
                }
            }
            Ok(Ok(records)) => {
                if self.model.apply_list(&lease, current.as_ref(), records) {
                    self.list_abort = None;
                    self.notice = None;
                    cx.notify();
                }
            }
        }
    }

    fn select(&mut self, id: &str, cx: &mut Context<Self>) {
        if self.model.select(id) {
            cx.notify();
        }
    }

    fn request_remove(&mut self, id: &str, cx: &mut Context<Self>) {
        let current = self.current_binding(cx);
        let Some(binding) = current.as_ref() else {
            self.notice = Some(("无法创建删除计划：当前没有活动 SSH 目标".into(), true));
            cx.notify();
            return;
        };
        if let Err(error) = self.services.target().validate(&binding.target) {
            self.notice = Some((format!("无法创建删除计划：{error}").into(), true));
            cx.notify();
            return;
        }
        match self.model.propose_remove(
            id,
            current.as_ref(),
            self.services.investigation().command_history(),
        ) {
            Ok(proposal) => self.request_mutation(proposal, cx),
            Err(error) => {
                self.notice = Some((format!("无法创建删除计划：{error}").into(), true));
                cx.notify();
            }
        }
    }

    fn request_clear(&mut self, cx: &mut Context<Self>) {
        let current = self.current_binding(cx);
        let Some(binding) = current.as_ref() else {
            self.notice = Some(("无法创建清空计划：当前没有活动 SSH 目标".into(), true));
            cx.notify();
            return;
        };
        if let Err(error) = self.services.target().validate(&binding.target) {
            self.notice = Some((format!("无法创建清空计划：{error}").into(), true));
            cx.notify();
            return;
        }
        match self.model.propose_clear(
            current.as_ref(),
            self.services.investigation().command_history(),
        ) {
            Ok(proposal) => self.request_mutation(proposal, cx),
            Err(error) => {
                self.notice = Some((format!("无法创建清空计划：{error}").into(), true));
                cx.notify();
            }
        }
    }

    fn request_mutation(
        &mut self,
        proposal: CommandHistoryMutationProposal,
        cx: &mut Context<Self>,
    ) {
        let plan = proposal.definition().clone();
        let dialog = self.shared.update(cx, |state, cx| {
            if state.interactions.dialogs.active().is_some() {
                return Err(DialogError::ActionTypeMismatch);
            }
            let dialog_id = state.interactions.dialogs.show_dangerous(&plan)?;
            state.interactions.focus_dialog();
            cx.notify();
            Ok(dialog_id)
        });
        match dialog {
            Ok(dialog_id) => self.model.arm_mutation(proposal, dialog_id),
            Err(error) => {
                self.notice = Some((format!("危险确认框无法打开：{error:?}").into(), true));
            }
        }
        cx.notify();
    }

    pub fn handle_dialog_outcome(
        &mut self,
        outcome: &DialogOutcome,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        let current = self.current_binding(cx);
        match self.model.resolve_mutation(outcome, current.as_ref()) {
            CommandHistoryMutationResolution::Ignored => false,
            CommandHistoryMutationResolution::Cancelled => {
                self.notice = Some(("命令历史变更已取消".into(), false));
                cx.notify();
                true
            }
            CommandHistoryMutationResolution::Stale => {
                self.notice = Some(("目标或弹层生命周期已变化，迟到的确认未执行".into(), true));
                cx.notify();
                true
            }
            CommandHistoryMutationResolution::Authorized {
                plan,
                confirmation,
                presentation,
            } => {
                let kind = plan.kind();
                let repository = self.services.investigation().command_history().clone();
                let journal = self.services.operation_journal().clone();
                let target_context = Arc::clone(self.services.target());
                let guard = presentation.binding.target.clone();
                self.mutations_in_flight = self.mutations_in_flight.saturating_add(1);
                let task = self.tokio.spawn(async move {
                    target_context.validate(&guard)?;
                    let outcome = match *plan {
                        CommandHistoryMutationPlan::Remove(plan) => {
                            repository
                                .execute_remove(plan, confirmation, &journal)
                                .await
                        }
                        CommandHistoryMutationPlan::Clear(plan) => {
                            repository
                                .execute_clear_for_target(plan, confirmation, &journal)
                                .await
                        }
                    }?;
                    target_context.validate(&guard)?;
                    Ok(outcome)
                });
                cx.spawn(async move |overlay, cx| {
                    let result = task.await;
                    let _ = cx.update(|cx| {
                        if let Some(overlay) = overlay.upgrade() {
                            overlay.update(cx, |overlay, cx| {
                                overlay.finish_mutation(presentation, kind, result, cx);
                            });
                        }
                    });
                })
                .detach();
                cx.notify();
                true
            }
        }
    }

    fn finish_mutation(
        &mut self,
        presentation: CommandHistoryRequestLease,
        kind: CommandHistoryMutationKind,
        result: Result<CoreResult<InvestigationOperationOutcome>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        self.mutations_in_flight = self.mutations_in_flight.saturating_sub(1);
        let current = self.current_binding(cx);
        if !self.model.accepts(&presentation, current.as_ref()) {
            return;
        }
        match result {
            Err(error) => {
                self.notice = Some((format!("命令历史变更任务失败：{error}").into(), true));
            }
            Ok(Err(error)) => {
                self.notice = Some((format!("命令历史变更失败：{error}").into(), true));
            }
            Ok(Ok(outcome)) => {
                let verb = match kind {
                    CommandHistoryMutationKind::Remove => "删除",
                    CommandHistoryMutationKind::Clear => "清空",
                };
                self.notice = Some((
                    format!(
                        "命令历史{verb}完成：{} 条记录已写入操作日志并验证",
                        outcome.affected_records
                    )
                    .into(),
                    false,
                ));
                self.refresh(cx);
                return;
            }
        }
        cx.notify();
    }

    fn request_replay(&mut self, id: &str, cx: &mut Context<Self>) {
        let Some(session) = self.current_session(cx) else {
            self.notice = Some(("无法重放：当前没有活动 SSH 目标".into(), true));
            cx.notify();
            return;
        };
        let binding = CommandHistoryBinding::from_session(&session);
        if let Err(error) = self.services.target().validate(session.target()) {
            self.notice = Some((format!("无法重放：{error}").into(), true));
            cx.notify();
            return;
        }
        let plan = match self
            .services
            .investigation()
            .command_history()
            .plan_replay(&binding.target.identity, id)
        {
            Ok(plan) => plan,
            Err(error) => {
                self.notice = Some((format!("重放计划校验失败：{error}").into(), true));
                cx.notify();
                return;
            }
        };
        let intent = match plan {
            CommandReplayPlan::Blocked { reason } => {
                self.notice = Some((replay_block_message(reason).into(), true));
                cx.notify();
                return;
            }
            CommandReplayPlan::Intent { intent } if intent.risk == CommandRisk::ReadOnly => intent,
            CommandReplayPlan::Intent { .. } => {
                self.notice = Some((
                    "重放已禁用：可写或未知命令没有 typed verify/restore，不能绕过 PlannedOperation 策略"
                        .into(),
                    true,
                ));
                cx.notify();
                return;
            }
        };
        let lease = match self.model.begin_replay(id, Some(binding)) {
            Ok(lease) => lease,
            Err(error) => {
                self.notice = Some((format!("无法开始重放：{error}").into(), true));
                cx.notify();
                return;
            }
        };
        abort_task(&mut self.replay_abort);
        let repository = self.services.investigation().command_history().clone();
        let ssh = self.services.ssh().clone();
        let target_context = Arc::clone(self.services.target());
        let task = self.tokio.spawn(execute_read_only_replay(
            repository,
            ssh,
            target_context,
            session,
            intent,
        ));
        self.replay_abort = Some(task.abort_handle());
        cx.spawn(async move |overlay, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(overlay) = overlay.upgrade() {
                    overlay.update(cx, |overlay, cx| {
                        overlay.finish_replay(lease, result, cx);
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_replay(
        &mut self,
        lease: CommandHistoryRequestLease,
        result: Result<CoreResult<ReplayExecution>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let current = self.current_binding(cx);
        if !self.model.accepts(&lease, current.as_ref()) {
            return;
        }
        if self
            .services
            .target()
            .validate(&lease.binding.target)
            .is_err()
        {
            let _ = self.model.reject_replay(&lease, current.as_ref());
            return;
        }
        self.replay_abort = None;
        match result {
            Err(error) if error.is_cancelled() => {
                let _ = self.model.reject_replay(&lease, current.as_ref());
            }
            Err(error) => {
                if self.model.reject_replay(&lease, current.as_ref()) {
                    self.notice = Some((format!("只读重放任务失败：{error}").into(), true));
                    cx.notify();
                }
            }
            Ok(Err(error)) => {
                if self.model.reject_replay(&lease, current.as_ref()) {
                    self.notice = Some((format!("只读重放失败：{error}").into(), true));
                    cx.notify();
                }
            }
            Ok(Ok(execution)) => {
                let exit_code = execution.output.exit_code;
                if self
                    .model
                    .apply_replay(&lease, current.as_ref(), execution.history)
                {
                    self.notice = Some((
                        format!("只读命令重放完成，退出码 {exit_code:?}；结果已追加到历史").into(),
                        false,
                    ));
                    cx.notify();
                }
            }
        }
    }

    fn copy_selected(&mut self, field: CommandHistoryTextField, cx: &mut Context<Self>) {
        let Some(record) = self.model.selected() else {
            return;
        };
        let value = match field {
            CommandHistoryTextField::Command => record.command.clone(),
            CommandHistoryTextField::Output => record.output.clone(),
        };
        cx.write_to_clipboard(ClipboardItem::new_string(value));
        self.notice = Some((format!("已复制{}纯文本", field.label()).into(), false));
        cx.notify();
    }
}

async fn execute_read_only_replay(
    repository: CommandHistoryRepository,
    ssh: lovelyres_core::ssh::SshService,
    target_context: Arc<lovelyres_core::target::TargetContext>,
    session: BoundSshSession,
    intent: CommandReplayIntent,
) -> CoreResult<ReplayExecution> {
    target_context.validate(session.target())?;
    let current_plan = repository.plan_replay(&intent.target, &intent.history_id)?;
    match current_plan {
        CommandReplayPlan::Intent {
            intent: current_intent,
        } if current_intent == intent && current_intent.risk == CommandRisk::ReadOnly => {}
        _ => {
            return Err(CoreError::Validation {
                subject: "command history replay",
                message: "the exact read-only replay plan changed before dispatch".to_owned(),
            });
        }
    }
    target_context.validate(session.target())?;
    let output = ssh
        .execute_bound(&session, intent.command.clone(), REPLAY_TIMEOUT)
        .await?;
    target_context.validate(session.target())?;
    let history = repository.add(AddCommandHistory {
        command: intent.command,
        title: intent.title,
        output: output.output.clone(),
        exit_code: output.exit_code,
        target: intent.target,
        source: "command-history-replay".to_owned(),
    })?;
    Ok(ReplayExecution { output, history })
}

#[derive(Clone, Copy)]
enum CommandHistoryTextField {
    Command,
    Output,
}

impl CommandHistoryTextField {
    const fn label(self) -> &'static str {
        match self {
            Self::Command => "命令",
            Self::Output => "输出",
        }
    }
}

impl Render for CommandHistoryOverlay {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens = self.shared.read(cx).theme.tokens();
        let binding_label = self
            .model
            .binding()
            .map(CommandHistoryBinding::label)
            .unwrap_or_else(|| "未连接 SSH 目标".to_owned());
        let records = self.model.records().to_vec();
        let selected_id = self.model.selected_id().map(ToOwned::to_owned);
        let selected = self.model.selected().cloned();
        let notice = self.notice.clone();
        let is_loading = self.model.is_loading();
        let is_replaying = self.model.is_replaying();
        let query_empty = self.model.query().trim().is_empty();
        let mutation_busy = self.mutations_in_flight > 0;

        div()
            .id("command-history-overlay")
            .size_full()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(
                        div()
                            .flex_1()
                            .child(div().text_2xl().child("命令历史"))
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(tokens.muted)
                                    .child(binding_label),
                            ),
                    )
                    .child(
                        crate::buttons::button("command-history-refresh")
                            .label("刷新")
                            .small()
                            .on_click(cx.listener(|this, _, _, cx| this.refresh(cx))),
                    )
                    .child(
                        crate::buttons::button("command-history-clear")
                            .label("永久清空")
                            .small()
                            .danger()
                            .disabled(records.is_empty() || mutation_busy)
                            .on_click(cx.listener(|this, _, _, cx| this.request_clear(cx))),
                    )
                    .child(
                        crate::buttons::close_button("command-history-close")
                            .small()
                            .on_click(cx.listener(|this, _, _, cx| this.request_close(cx))),
                    ),
            )
            .when_some(notice, |overlay, (message, is_error)| {
                overlay.child(
                    div()
                        .rounded_md()
                        .border_1()
                        .border_color(if is_error {
                            tokens.danger
                        } else {
                            tokens.success
                        })
                        .p_2()
                        .text_sm()
                        .text_color(if is_error {
                            tokens.danger
                        } else {
                            tokens.success
                        })
                        .child(message),
                )
            })
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .flex()
                    .gap_3()
                    .child(
                        div()
                            .w(px(390.0))
                            .flex_none()
                            .min_h_0()
                            .rounded_lg()
                            .border_1()
                            .border_color(tokens.border)
                            .bg(tokens.surface)
                            .p_3()
                            .flex()
                            .flex_col()
                            .gap_3()
                            .child(Input::new(&self.search_input).small())
                            .child(
                                div()
                                    .flex_1()
                                    .min_h_0()
                                    .overflow_y_scrollbar()
                                    .when(is_loading && records.is_empty(), |list| {
                                        list.child(empty_message(
                                            "正在读取当前目标的命令历史…",
                                            tokens,
                                        ))
                                    })
                                    .when(!is_loading && records.is_empty(), |list| {
                                        list.child(empty_message(
                                            if query_empty {
                                                "当前目标暂无命令历史"
                                            } else {
                                                "没有匹配的命令历史"
                                            },
                                            tokens,
                                        ))
                                    })
                                    .children(records.iter().cloned().map(|record| {
                                        history_list_item(
                                            record,
                                            selected_id.as_deref(),
                                            tokens,
                                            cx,
                                        )
                                    })),
                            )
                            .child(
                                div()
                                    .pt_2()
                                    .border_t_1()
                                    .border_color(tokens.border)
                                    .text_xs()
                                    .text_color(tokens.muted)
                                    .child(format!("当前筛选 {} 条", records.len())),
                            ),
                    )
                    .child(match selected {
                        Some(record) => {
                            self.render_record(record, is_replaying, mutation_busy, tokens, cx)
                        }
                        None => empty_detail(tokens),
                    }),
            )
    }
}

impl CommandHistoryOverlay {
    fn render_record(
        &mut self,
        record: CommandHistoryRecord,
        is_replaying: bool,
        mutation_busy: bool,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let remove_id = record.id.clone();
        let replay_id = record.id.clone();
        let replay_allowed = record.risk == CommandRisk::ReadOnly;
        let replay_label = if replay_allowed {
            "只读重放"
        } else {
            "可写/未知：禁止重放"
        };
        let metadata = format!(
            "{} · {} · 退出码 {:?} · 来源 {} · ID {}",
            risk_label(record.risk),
            record.timestamp,
            record.exit_code,
            record.source,
            record.id
        );
        div()
            .id("command-history-detail")
            .flex_1()
            .min_w_0()
            .min_h_0()
            .rounded_lg()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .p_4()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .child(div().text_xl().child(record.title.clone()))
                            .child(div().text_xs().text_color(tokens.muted).child(metadata)),
                    )
                    .child(
                        crate::buttons::button("command-history-copy-command")
                            .label("复制命令")
                            .small()
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.copy_selected(CommandHistoryTextField::Command, cx);
                            })),
                    )
                    .child(
                        crate::buttons::button("command-history-copy-output")
                            .label("复制输出")
                            .small()
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.copy_selected(CommandHistoryTextField::Output, cx);
                            })),
                    )
                    .child(
                        crate::buttons::button("command-history-replay")
                            .label(replay_label)
                            .small()
                            .disabled(!replay_allowed || is_replaying)
                            .on_click(
                                cx.listener(move |this, _, _, cx| {
                                    this.request_replay(&replay_id, cx);
                                }),
                            ),
                    )
                    .child(
                        crate::buttons::button("command-history-remove")
                            .label("永久删除")
                            .small()
                            .danger()
                            .disabled(mutation_busy)
                            .on_click(
                                cx.listener(move |this, _, _, cx| {
                                    this.request_remove(&remove_id, cx);
                                }),
                            ),
                    ),
            )
            .child(
                div()
                    .text_xs()
                    .text_color(if replay_allowed {
                        tokens.success
                    } else {
                        tokens.warning
                    })
                    .child(if replay_allowed {
                        "只读重放会在发送前二次核验记录摘要、目标与 SSH generation，并把结果追加为新记录。"
                    } else {
                        "该命令缺少领域化 plan/verify/restore，不能作为任意 shell 命令重放。"
                    }),
            )
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scrollbar()
                    .child(plain_text_section(
                        "命令（纯文本）",
                        record.command,
                        tokens.accent,
                        tokens,
                    ))
                    .child(plain_text_section(
                        "输出（纯文本）",
                        record.output,
                        tokens.success,
                        tokens,
                    )),
            )
            .into_any_element()
    }
}

fn history_list_item(
    record: CommandHistoryRecord,
    selected_id: Option<&str>,
    tokens: ThemeTokens,
    cx: &mut Context<CommandHistoryOverlay>,
) -> AnyElement {
    let id = record.id.clone();
    let selected = selected_id == Some(record.id.as_str());
    div()
        .id(SharedString::from(format!(
            "command-history-item-{}",
            record.id
        )))
        .mb_2()
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
        .p_2()
        .child(
            crate::buttons::button(SharedString::from(format!(
                "command-history-select-{}",
                record.id
            )))
            .label(text_preview(&record.title))
            .small()
            .on_click(cx.listener(move |this, _, _, cx| this.select(&id, cx))),
        )
        .child(
            div()
                .mt_1()
                .text_xs()
                .text_color(if record.risk == CommandRisk::ReadOnly {
                    tokens.success
                } else {
                    tokens.warning
                })
                .child(format!(
                    "{} · {} · {}",
                    risk_label(record.risk),
                    record.timestamp,
                    record.source
                )),
        )
        .child(
            div()
                .mt_2()
                .font_family("Cascadia Mono")
                .text_xs()
                .child(text_preview(&record.command)),
        )
        .into_any_element()
}

fn empty_message(message: &'static str, tokens: ThemeTokens) -> AnyElement {
    div()
        .p_5()
        .text_center()
        .text_sm()
        .text_color(tokens.muted)
        .child(message)
        .into_any_element()
}

fn empty_detail(tokens: ThemeTokens) -> AnyElement {
    div()
        .id("command-history-empty-detail")
        .flex_1()
        .min_w_0()
        .rounded_lg()
        .border_1()
        .border_color(tokens.border)
        .bg(tokens.surface)
        .items_center()
        .justify_center()
        .flex()
        .text_color(tokens.muted)
        .child("选择一条目标绑定记录查看完整命令与输出")
        .into_any_element()
}

fn plain_text_section(
    label: &'static str,
    text: String,
    accent: gpui::Rgba,
    tokens: ThemeTokens,
) -> AnyElement {
    div()
        .mb_4()
        .child(div().mb_1().text_xs().text_color(accent).child(label))
        .child(
            div()
                .rounded_md()
                .border_1()
                .border_color(tokens.border)
                .bg(tokens.terminal_background)
                .p_3()
                .font_family("Cascadia Mono")
                .text_xs()
                .overflow_x_scrollbar()
                .children(plain_text_lines(&text).into_iter().map(|line| {
                    // Remote content stays a GPUI text node; no HTML or Markdown parser is used.
                    div().child(if line.is_empty() {
                        " ".to_owned()
                    } else {
                        line
                    })
                })),
        )
        .into_any_element()
}

fn plain_text_lines(text: &str) -> Vec<String> {
    text.split('\n').map(ToOwned::to_owned).collect()
}

fn text_preview(text: &str) -> String {
    let preview = text
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(MAX_PREVIEW_CHARS)
        .collect::<String>();
    if preview.is_empty() {
        "（空）".to_owned()
    } else {
        preview
    }
}

const fn risk_label(risk: CommandRisk) -> &'static str {
    match risk {
        CommandRisk::ReadOnly => "只读",
        CommandRisk::Mutating => "可写或未知",
    }
}

fn replay_block_message(reason: ReplayBlockReason) -> &'static str {
    match reason {
        ReplayBlockReason::NotFound => "重放已阻止：记录不存在",
        ReplayBlockReason::TargetMismatch => "重放已阻止：记录不属于当前目标",
        ReplayBlockReason::DigestMismatch => "重放已阻止：命令摘要不匹配",
        ReplayBlockReason::RiskChanged => "重放已阻止：命令风险分类已变化",
    }
}

fn abort_task(slot: &mut Option<tokio::task::AbortHandle>) {
    if let Some(abort) = slot.take() {
        abort.abort();
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use lovelyres_core::{
        PortableStore,
        investigation::{AddCommandHistory, CommandReplayPlan},
        operations::JournalPhase,
        target::TargetIdentity,
    };
    use uuid::Uuid;

    use super::*;
    use crate::interaction::{DialogAction, DialogHost};

    fn services() -> (PathBuf, Arc<BackendServices>) {
        let root = std::env::temp_dir().join(format!(
            "lovelyres-command-history-overlay-{}",
            Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let store = PortableStore::prepare(root.clone()).unwrap();
        (root, Arc::new(BackendServices::new(store).unwrap()))
    }

    fn target(value: &str) -> TargetIdentity {
        TargetIdentity::new(value).unwrap()
    }

    fn binding(value: &str, generation: u64) -> CommandHistoryBinding {
        CommandHistoryBinding {
            connection_id: value.to_owned(),
            session_id: format!("session-{value}-{generation}"),
            target: TargetGuard {
                identity: target(value),
                generation,
            },
        }
    }

    fn add(
        repository: &CommandHistoryRepository,
        target: &TargetIdentity,
        command: &str,
        title: &str,
        output: &str,
    ) -> CommandHistoryRecord {
        repository
            .add(AddCommandHistory {
                command: command.to_owned(),
                title: title.to_owned(),
                output: output.to_owned(),
                exit_code: Some(0),
                target: target.clone(),
                source: "test".to_owned(),
            })
            .unwrap()
    }

    fn loaded_model(
        repository: &CommandHistoryRepository,
        active_binding: CommandHistoryBinding,
    ) -> CommandHistoryModel {
        let mut model = CommandHistoryModel::default();
        model.activate(Some(active_binding.clone()));
        let lease = model.begin_list(Some(active_binding.clone())).unwrap();
        let records = repository
            .list_for_target(&active_binding.target.identity)
            .unwrap();
        assert!(model.apply_list(&lease, Some(&active_binding), records));
        model
    }

    fn approve(
        model: &mut CommandHistoryModel,
        proposal: CommandHistoryMutationProposal,
        active_binding: &CommandHistoryBinding,
    ) -> CommandHistoryMutationResolution {
        let mut dialogs = DialogHost::default();
        let dialog_id = dialogs.show_dangerous(proposal.definition()).unwrap();
        let operation_id = proposal.definition().id.clone();
        model.arm_mutation(proposal, dialog_id);
        let outcome = dialogs
            .dispatch(DialogAction::ConfirmDangerous {
                dialog_id,
                operation_id,
            })
            .unwrap();
        model.resolve_mutation(&outcome, Some(active_binding))
    }

    async fn execute_mutation(
        repository: &CommandHistoryRepository,
        services: &BackendServices,
        plan: CommandHistoryMutationPlan,
        confirmation: DangerousConfirmation,
    ) -> CoreResult<InvestigationOperationOutcome> {
        match plan {
            CommandHistoryMutationPlan::Remove(plan) => {
                repository
                    .execute_remove(plan, confirmation, services.operation_journal())
                    .await
            }
            CommandHistoryMutationPlan::Clear(plan) => {
                repository
                    .execute_clear_for_target(plan, confirmation, services.operation_journal())
                    .await
            }
        }
    }

    #[test]
    fn wrong_target_cannot_create_a_destructive_proposal() {
        let (root, services) = services();
        let repository = services.investigation().command_history();
        let active = binding("host-a", 1);
        let record = add(repository, &active.target.identity, "id", "identity", "ok");
        let mut model = loaded_model(repository, active.clone());
        let other = binding("host-b", 2);

        assert!(
            model
                .propose_remove(&record.id, Some(&other), repository)
                .is_err()
        );
        assert!(matches!(
            repository
                .plan_replay(&other.target.identity, &record.id)
                .unwrap(),
            CommandReplayPlan::Blocked {
                reason: ReplayBlockReason::TargetMismatch
            }
        ));
        assert_eq!(
            repository
                .list_for_target(&active.target.identity)
                .unwrap()
                .len(),
            1
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn wrong_dialog_and_wrong_operation_do_not_authorize() {
        let (root, services) = services();
        let repository = services.investigation().command_history();
        let active = binding("host-dialog", 7);
        let record = add(repository, &active.target.identity, "id", "identity", "ok");
        let mut model = loaded_model(repository, active.clone());
        let proposal = model
            .propose_remove(&record.id, Some(&active), repository)
            .unwrap();
        let mut dialogs = DialogHost::default();
        let wrong_dialog_id = dialogs.show_alert("unrelated", "unrelated");
        let dialog_id = dialogs.show_dangerous(proposal.definition()).unwrap();
        model.arm_mutation(proposal, dialog_id);

        assert_eq!(
            model.resolve_mutation(
                &DialogOutcome::Cancelled {
                    dialog_id: wrong_dialog_id,
                },
                Some(&active)
            ),
            CommandHistoryMutationResolution::Ignored
        );
        assert_eq!(
            model.resolve_mutation(
                &DialogOutcome::DangerousApproved {
                    dialog_id,
                    operation_id: "wrong-operation".to_owned(),
                },
                Some(&active)
            ),
            CommandHistoryMutationResolution::Ignored
        );
        assert_eq!(
            repository
                .list_for_target(&active.target.identity)
                .unwrap()
                .len(),
            1
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn concurrent_clear_preserves_records_added_after_planning() {
        let (root, services) = services();
        let repository = services.investigation().command_history();
        let active = binding("host-clear", 1);
        add(repository, &active.target.identity, "id", "first", "one");
        add(
            repository,
            &active.target.identity,
            "uname",
            "second",
            "two",
        );
        let mut model = loaded_model(repository, active.clone());
        let proposal = model.propose_clear(Some(&active), repository).unwrap();
        let resolution = approve(&mut model, proposal, &active);
        let (plan, confirmation) = match resolution {
            CommandHistoryMutationResolution::Authorized {
                plan, confirmation, ..
            } => (*plan, confirmation),
            other => panic!("unexpected resolution: {other:?}"),
        };
        let late = add(repository, &active.target.identity, "pwd", "late", "/tmp");

        let outcome = execute_mutation(repository, &services, plan, confirmation)
            .await
            .unwrap();
        assert_eq!(outcome.affected_records, 2);
        assert_eq!(
            repository.list_for_target(&active.target.identity).unwrap(),
            vec![late]
        );
        let journal = services.operation_journal().entries().unwrap();
        assert!(
            journal
                .iter()
                .any(|entry| entry.phase == JournalPhase::VerificationPassed)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stale_list_and_replay_results_are_dropped_after_target_switch() {
        let (root, services) = services();
        let repository = services.investigation().command_history();
        let first = binding("host-a", 1);
        let second = binding("host-b", 2);
        let record = add(repository, &first.target.identity, "id", "identity", "ok");
        let mut model = CommandHistoryModel::default();
        model.activate(Some(first.clone()));
        let list_lease = model.begin_list(Some(first.clone())).unwrap();
        model.rebind(Some(second.clone()));
        assert!(!model.apply_list(&list_lease, Some(&second), vec![record.clone()]));

        model.rebind(Some(first.clone()));
        let current_lease = model.begin_list(Some(first.clone())).unwrap();
        assert!(model.apply_list(&current_lease, Some(&first), vec![record.clone()]));
        let replay_lease = model.begin_replay(&record.id, Some(first.clone())).unwrap();
        model.rebind(Some(second.clone()));
        assert!(!model.apply_replay(&replay_lease, Some(&second), record));
        assert!(model.records().is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn hostile_remote_text_remains_literal_and_bounded() {
        let hostile = "<img src=x onerror=alert(1)>\n<script>steal()</script>\n${danger}";
        let lines = plain_text_lines(hostile);
        assert_eq!(lines[0], "<img src=x onerror=alert(1)>");
        assert_eq!(lines[1], "<script>steal()</script>");
        assert_eq!(lines[2], "${danger}");
        assert!(!text_preview(&"x".repeat(1_000)).is_empty());
        assert!(text_preview(&"x".repeat(1_000)).chars().count() <= MAX_PREVIEW_CHARS);

        let mut model = CommandHistoryModel::default();
        model.set_query("查".repeat(MAX_SEARCH_CHARS + 50));
        assert_eq!(model.query().chars().count(), MAX_SEARCH_CHARS);
    }

    #[tokio::test]
    async fn confirmed_mutation_finishes_after_deactivate_but_presentation_is_stale() {
        let (root, services) = services();
        let repository = services.investigation().command_history();
        let active = binding("host-lifecycle", 4);
        let record = add(repository, &active.target.identity, "id", "identity", "ok");
        let mut model = loaded_model(repository, active.clone());
        let proposal = model
            .propose_remove(&record.id, Some(&active), repository)
            .unwrap();
        let resolution = approve(&mut model, proposal, &active);
        let (plan, confirmation, presentation) = match resolution {
            CommandHistoryMutationResolution::Authorized {
                plan,
                confirmation,
                presentation,
            } => (*plan, confirmation, presentation),
            other => panic!("unexpected resolution: {other:?}"),
        };
        model.deactivate();

        execute_mutation(repository, &services, plan, confirmation)
            .await
            .unwrap();
        assert!(
            repository
                .list_for_target(&active.target.identity)
                .unwrap()
                .is_empty()
        );
        assert!(!model.accepts(&presentation, Some(&active)));
        assert!(
            services
                .operation_journal()
                .entries()
                .unwrap()
                .iter()
                .any(|entry| entry.phase == JournalPhase::VerificationPassed)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn mutating_and_unknown_replay_stays_disabled() {
        let (root, services) = services();
        let repository = services.investigation().command_history();
        let active = binding("host-risk", 1);
        let record = add(
            repository,
            &active.target.identity,
            "rm -f /tmp/example",
            "remove",
            "",
        );
        assert_eq!(record.risk, CommandRisk::Mutating);
        assert!(matches!(
            repository
                .plan_replay(&active.target.identity, &record.id)
                .unwrap(),
            CommandReplayPlan::Intent { intent }
                if intent.risk == CommandRisk::Mutating
                    && intent.requires_dangerous_confirmation
        ));
        fs::remove_dir_all(root).unwrap();
    }
}
