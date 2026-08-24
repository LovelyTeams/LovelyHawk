use std::sync::Arc;

use gpui::{
    AnyElement, ClipboardItem, Context, Entity, IntoElement, Render, SharedString, Subscription,
    Window, div, prelude::*, px,
};
use gpui_component::{
    Sizable,
    button::ButtonVariants,
    input::{Input, InputEvent, InputState},
    scroll::ScrollableElement,
};
use lovelyres_core::{
    BackendServices, CoreError, CoreResult,
    investigation::{
        AiHistoryClearPlan, AiHistoryExport, AiHistoryRecord, AiHistoryRemovePlan,
        AiHistoryRepository, InvestigationOperationOutcome, MAX_AI_HISTORY,
    },
    operations::{DangerousConfirmation, OperationPlan},
};

use crate::{
    app::SharedAppState,
    interaction::{DialogAction, DialogError, DialogId, DialogOutcome},
    runtime::TokioBridge,
    theme::ThemeTokens,
};

const MAX_PREVIEW_CHARS: usize = 96;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AiHistoryRequestLease {
    activation_generation: u64,
    request_id: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AiHistoryMutationKind {
    Remove { record_id: String },
    Clear,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AiHistoryMutationPlan {
    Remove(AiHistoryRemovePlan),
    Clear(AiHistoryClearPlan),
}

impl AiHistoryMutationPlan {
    fn definition(&self) -> &OperationPlan {
        match self {
            Self::Remove(plan) => plan.definition(),
            Self::Clear(plan) => plan.definition(),
        }
    }

    fn kind(&self) -> AiHistoryMutationKind {
        match self {
            Self::Remove(plan) => AiHistoryMutationKind::Remove {
                record_id: plan.record_id().to_owned(),
            },
            Self::Clear(_) => AiHistoryMutationKind::Clear,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AiHistoryMutationProposal {
    lease: AiHistoryRequestLease,
    plan: AiHistoryMutationPlan,
}

impl AiHistoryMutationProposal {
    fn definition(&self) -> &OperationPlan {
        self.plan.definition()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingAiHistoryMutation {
    proposal: AiHistoryMutationProposal,
    dialog_id: DialogId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AiHistoryMutationResolution {
    Ignored,
    Cancelled,
    Stale,
    Authorized {
        plan: Box<AiHistoryMutationPlan>,
        confirmation: DangerousConfirmation,
        presentation: AiHistoryRequestLease,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AiHistoryExportFormat {
    PlainText,
    Json,
}

impl AiHistoryExportFormat {
    const fn label(self) -> &'static str {
        match self {
            Self::PlainText => "纯文本",
            Self::Json => "JSON",
        }
    }

    const fn extension(self) -> &'static str {
        match self {
            Self::PlainText => "txt",
            Self::Json => "json",
        }
    }

    const fn media_type(self) -> &'static str {
        match self {
            Self::PlainText => "text/plain; charset=utf-8",
            Self::Json => "application/json",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AiHistoryExportIntent {
    pub format: AiHistoryExportFormat,
    pub media_type: &'static str,
    pub suggested_name: String,
    pub record_count: usize,
    pub contents: String,
}

impl AiHistoryExportIntent {
    pub fn from_export(
        format: AiHistoryExportFormat,
        export: AiHistoryExport,
    ) -> Result<Self, serde_json::Error> {
        let record_count = export.records.len();
        let suggested_name = format!(
            "lovelyres-ai-history-{}.{}",
            export.exported_at_millis,
            format.extension()
        );
        let contents = match format {
            AiHistoryExportFormat::PlainText => ai_history_as_plain_text(&export),
            AiHistoryExportFormat::Json => serde_json::to_string_pretty(&export)?,
        };
        Ok(Self {
            format,
            media_type: format.media_type(),
            suggested_name,
            record_count,
            contents,
        })
    }
}

fn ai_history_as_plain_text(export: &AiHistoryExport) -> String {
    let mut lines = vec![
        "LovelyRes AI History Export".to_owned(),
        format!("Schema: {}", export.schema),
        format!("Exported-At-Unix-Ms: {}", export.exported_at_millis),
        format!("Count: {}", export.records.len()),
    ];
    for record in &export.records {
        lines.extend([
            String::new(),
            "----------------------------------------".to_owned(),
            format!("ID: {}", record.id),
            format!("Timestamp-Unix-Ms: {}", record.timestamp),
            format!("Provider: {}", record.provider),
            format!("Model: {}", record.model),
            format!("Source: {}", record.source),
            "Prompt (plain text):".to_owned(),
            record.prompt.clone(),
            "Result (plain text):".to_owned(),
            record.result.clone(),
        ]);
    }
    lines.push(String::new());
    lines.join("\n")
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AiHistoryListItem {
    pub id: String,
    pub timestamp: i64,
    pub provider: String,
    pub model: String,
    pub source: String,
    pub prompt_preview: String,
    pub result_preview: String,
}

impl From<&AiHistoryRecord> for AiHistoryListItem {
    fn from(record: &AiHistoryRecord) -> Self {
        Self {
            id: record.id.clone(),
            timestamp: record.timestamp,
            provider: record.provider.clone(),
            model: record.model.clone(),
            source: record.source.clone(),
            prompt_preview: text_preview(&record.prompt),
            result_preview: text_preview(&record.result),
        }
    }
}

#[derive(Debug, Default)]
pub struct AiHistoryModel {
    records: Vec<AiHistoryRecord>,
    selected_id: Option<String>,
    query: String,
    active: bool,
    activation_generation: u64,
    next_request_id: u64,
    latest_list_request_id: Option<u64>,
    latest_export_request_id: Option<u64>,
    pending_mutation: Option<PendingAiHistoryMutation>,
}

impl AiHistoryModel {
    pub fn activate(&mut self) -> u64 {
        if !self.active {
            self.active = true;
            self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
        }
        self.activation_generation
    }

    pub fn deactivate(&mut self) {
        self.active = false;
        self.latest_list_request_id = None;
        self.latest_export_request_id = None;
        self.pending_mutation = None;
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub const fn activation_generation(&self) -> u64 {
        self.activation_generation
    }

    pub fn query(&self) -> &str {
        &self.query
    }

    pub fn set_query(&mut self, query: impl Into<String>) {
        self.query = query.into();
    }

    pub fn records(&self) -> &[AiHistoryRecord] {
        &self.records
    }

    pub fn list_items(&self) -> Vec<AiHistoryListItem> {
        self.records.iter().map(AiHistoryListItem::from).collect()
    }

    pub fn selected(&self) -> Option<&AiHistoryRecord> {
        let selected_id = self.selected_id.as_deref()?;
        self.records.iter().find(|record| record.id == selected_id)
    }

    pub fn selected_id(&self) -> Option<&str> {
        self.selected_id.as_deref()
    }

    pub fn select(&mut self, id: &str) -> bool {
        let Some(record) = self.records.iter().find(|record| record.id == id) else {
            return false;
        };
        self.selected_id = Some(record.id.clone());
        true
    }

    pub const fn is_loading(&self) -> bool {
        self.latest_list_request_id.is_some()
    }

    pub fn begin_list_request(&mut self) -> Option<AiHistoryRequestLease> {
        let lease = self.new_lease()?;
        self.latest_list_request_id = Some(lease.request_id);
        Some(lease)
    }

    pub fn begin_export_request(&mut self) -> Option<AiHistoryRequestLease> {
        let lease = self.new_lease()?;
        self.latest_export_request_id = Some(lease.request_id);
        Some(lease)
    }

    pub fn new_lease(&mut self) -> Option<AiHistoryRequestLease> {
        if !self.active {
            return None;
        }
        self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
        Some(AiHistoryRequestLease {
            activation_generation: self.activation_generation,
            request_id: self.next_request_id,
        })
    }

    pub fn accepts(&self, lease: &AiHistoryRequestLease) -> bool {
        self.active && self.activation_generation == lease.activation_generation
    }

    fn propose_remove(
        &mut self,
        id: &str,
        repository: &AiHistoryRepository,
    ) -> CoreResult<AiHistoryMutationProposal> {
        if !self.active {
            return Err(CoreError::Validation {
                subject: "AI history page",
                message: "page is not active".to_owned(),
            });
        }
        if !self.records.iter().any(|record| record.id == id) {
            return Err(CoreError::Validation {
                subject: "AI history record",
                message: "selected record no longer exists".to_owned(),
            });
        }
        let lease = self.new_lease().expect("the active page produces a lease");
        Ok(AiHistoryMutationProposal {
            lease,
            plan: AiHistoryMutationPlan::Remove(repository.plan_remove(id)?),
        })
    }

    fn propose_clear(
        &mut self,
        repository: &AiHistoryRepository,
    ) -> CoreResult<AiHistoryMutationProposal> {
        if !self.active {
            return Err(CoreError::Validation {
                subject: "AI history page",
                message: "page is not active".to_owned(),
            });
        }
        if repository.list()?.is_empty() {
            return Err(CoreError::Validation {
                subject: "AI history",
                message: "there are no records to clear".to_owned(),
            });
        }
        let lease = self.new_lease().expect("the active page produces a lease");
        Ok(AiHistoryMutationProposal {
            lease,
            plan: AiHistoryMutationPlan::Clear(repository.plan_clear()?),
        })
    }

    fn arm_mutation(&mut self, proposal: AiHistoryMutationProposal, dialog_id: DialogId) {
        self.pending_mutation = Some(PendingAiHistoryMutation {
            proposal,
            dialog_id,
        });
    }

    fn pending_mutation_dialog_id(&self) -> Option<DialogId> {
        self.pending_mutation
            .as_ref()
            .map(|pending| pending.dialog_id)
    }

    fn resolve_mutation(&mut self, outcome: &DialogOutcome) -> AiHistoryMutationResolution {
        let Some(pending) = self.pending_mutation.as_ref() else {
            return AiHistoryMutationResolution::Ignored;
        };
        let matches_dialog = match outcome {
            DialogOutcome::Cancelled { dialog_id }
            | DialogOutcome::DangerousApproved { dialog_id, .. } => *dialog_id == pending.dialog_id,
            DialogOutcome::AlertDismissed { .. } | DialogOutcome::PromptSubmitted { .. } => false,
        };
        if !matches_dialog {
            return AiHistoryMutationResolution::Ignored;
        }
        let pending = self
            .pending_mutation
            .take()
            .expect("the matching pending mutation exists");
        match outcome {
            DialogOutcome::Cancelled { .. } => AiHistoryMutationResolution::Cancelled,
            DialogOutcome::DangerousApproved { operation_id, .. }
                if operation_id == &pending.proposal.definition().id =>
            {
                if !self.accepts(&pending.proposal.lease) {
                    return AiHistoryMutationResolution::Stale;
                }
                AiHistoryMutationResolution::Authorized {
                    confirmation: DangerousConfirmation::approve(pending.proposal.definition()),
                    presentation: pending.proposal.lease,
                    plan: Box::new(pending.proposal.plan),
                }
            }
            DialogOutcome::DangerousApproved { .. } => AiHistoryMutationResolution::Ignored,
            DialogOutcome::AlertDismissed { .. } | DialogOutcome::PromptSubmitted { .. } => {
                AiHistoryMutationResolution::Ignored
            }
        }
    }

    fn apply_mutation_success(
        &mut self,
        lease: &AiHistoryRequestLease,
        kind: &AiHistoryMutationKind,
    ) -> bool {
        if !self.accepts(lease) {
            return false;
        }
        match kind {
            AiHistoryMutationKind::Remove { record_id } => {
                self.records
                    .retain(|record| record.id != record_id.as_str());
                if self.selected_id.as_deref() == Some(record_id) {
                    self.selected_id = self.records.first().map(|record| record.id.clone());
                }
            }
            AiHistoryMutationKind::Clear => {
                self.records.clear();
                self.selected_id = None;
            }
        }
        true
    }

    pub fn apply_list(
        &mut self,
        lease: &AiHistoryRequestLease,
        mut records: Vec<AiHistoryRecord>,
    ) -> bool {
        if self.latest_list_request_id != Some(lease.request_id) || !self.accepts(lease) {
            return false;
        }
        self.latest_list_request_id = None;
        // The repository defines insertion order (newest first). Preserve it even if
        // the system clock moved backwards between records.
        records.truncate(MAX_AI_HISTORY);
        let prior_selected = self.selected_id.clone();
        self.records = records;
        self.selected_id = prior_selected
            .filter(|id| self.records.iter().any(|record| record.id == *id))
            .or_else(|| self.records.first().map(|record| record.id.clone()));
        true
    }

    pub fn reject_list(&mut self, lease: &AiHistoryRequestLease) -> bool {
        if self.latest_list_request_id != Some(lease.request_id) || !self.accepts(lease) {
            return false;
        }
        self.latest_list_request_id = None;
        true
    }

    pub fn finish_export(&mut self, lease: &AiHistoryRequestLease) -> bool {
        if self.latest_export_request_id != Some(lease.request_id) || !self.accepts(lease) {
            return false;
        }
        self.latest_export_request_id = None;
        true
    }
}

pub struct AiHistoryPage {
    services: Arc<BackendServices>,
    tokio: Arc<TokioBridge>,
    shared: Entity<SharedAppState>,
    model: AiHistoryModel,
    search_input: Entity<InputState>,
    list_abort: Option<tokio::task::AbortHandle>,
    export_abort: Option<tokio::task::AbortHandle>,
    notice: Option<(SharedString, bool)>,
    _subscriptions: Vec<Subscription>,
}

impl AiHistoryPage {
    pub fn new(
        services: Arc<BackendServices>,
        tokio: Arc<TokioBridge>,
        shared: Entity<SharedAppState>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let search_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder("搜索 provider、model、source、提示词或回答…")
        });
        let subscriptions = vec![cx.subscribe_in(
            &search_input,
            window,
            |page, input, event: &InputEvent, _, cx| {
                if matches!(event, InputEvent::Change) {
                    page.model.set_query(input.read(cx).value().to_string());
                    page.refresh(cx);
                }
            },
        )];
        Self {
            services,
            tokio,
            shared,
            model: AiHistoryModel::default(),
            search_input,
            list_abort: None,
            export_abort: None,
            notice: None,
            _subscriptions: subscriptions,
        }
    }

    pub fn activate(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.model.activate();
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
        abort_task(&mut self.export_abort);
        if let Some(dialog_id) = self.model.pending_mutation_dialog_id() {
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
        self.model.deactivate();
        cx.notify();
    }

    fn refresh(&mut self, cx: &mut Context<Self>) {
        let Some(lease) = self.model.begin_list_request() else {
            return;
        };
        abort_task(&mut self.list_abort);
        let query = self.model.query().to_owned();
        let repository = self.services.investigation().ai_history().clone();
        let task = self.tokio.spawn(async move {
            if query.trim().is_empty() {
                repository.list()
            } else {
                repository.search(&query)
            }
        });
        self.list_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_refresh(lease, result, cx));
                }
            });
        })
        .detach();
    }

    fn finish_refresh(
        &mut self,
        lease: AiHistoryRequestLease,
        result: Result<CoreResult<Vec<AiHistoryRecord>>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if !self.model.accepts(&lease) {
            return;
        }
        match result {
            Err(error) if error.is_cancelled() => {}
            Err(error) => {
                if self.model.reject_list(&lease) {
                    self.list_abort = None;
                    self.notice = Some((format!("AI 历史加载任务失败：{error}").into(), true));
                    cx.notify();
                }
            }
            Ok(Err(error)) => {
                if self.model.reject_list(&lease) {
                    self.list_abort = None;
                    self.notice = Some((format!("AI 历史读取失败：{error}").into(), true));
                    cx.notify();
                }
            }
            Ok(Ok(records)) => {
                if self.model.apply_list(&lease, records) {
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
        let repository = self.services.investigation().ai_history();
        match self.model.propose_remove(id, repository) {
            Ok(proposal) => self.request_mutation(proposal, cx),
            Err(error) => {
                self.notice = Some((format!("无法创建删除计划：{error}").into(), true));
                cx.notify();
            }
        }
    }

    fn request_clear(&mut self, cx: &mut Context<Self>) {
        let repository = self.services.investigation().ai_history();
        match self.model.propose_clear(repository) {
            Ok(proposal) => self.request_mutation(proposal, cx),
            Err(error) => {
                self.notice = Some((format!("无法创建清空计划：{error}").into(), true));
                cx.notify();
            }
        }
    }

    fn request_mutation(&mut self, proposal: AiHistoryMutationProposal, cx: &mut Context<Self>) {
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
        match self.model.resolve_mutation(outcome) {
            AiHistoryMutationResolution::Ignored => false,
            AiHistoryMutationResolution::Cancelled => {
                self.notice = Some(("AI 历史变更已取消".into(), false));
                cx.notify();
                true
            }
            AiHistoryMutationResolution::Stale => {
                self.notice = Some(("页面已变化，迟到的危险确认未执行".into(), true));
                cx.notify();
                true
            }
            AiHistoryMutationResolution::Authorized {
                plan,
                confirmation,
                presentation,
            } => {
                let kind = plan.kind();
                let repository = self.services.investigation().ai_history().clone();
                let journal = self.services.operation_journal().clone();
                let task = self.tokio.spawn(async move {
                    match *plan {
                        AiHistoryMutationPlan::Remove(plan) => {
                            repository
                                .execute_remove(plan, confirmation, &journal)
                                .await
                        }
                        AiHistoryMutationPlan::Clear(plan) => {
                            repository.execute_clear(plan, confirmation, &journal).await
                        }
                    }
                });
                cx.spawn(async move |page, cx| {
                    let result = task.await;
                    let _ = cx.update(|cx| {
                        if let Some(page) = page.upgrade() {
                            page.update(cx, |page, cx| {
                                page.finish_mutation(presentation, kind, result, cx)
                            });
                        }
                    });
                })
                .detach();
                true
            }
        }
    }

    fn finish_mutation(
        &mut self,
        presentation: AiHistoryRequestLease,
        kind: AiHistoryMutationKind,
        result: Result<CoreResult<InvestigationOperationOutcome>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if !self.model.accepts(&presentation) {
            return;
        }
        match result {
            Err(error) => {
                self.notice = Some((format!("AI 历史变更任务失败：{error}").into(), true));
            }
            Ok(Err(error)) => {
                self.notice = Some((format!("AI 历史变更失败：{error}").into(), true));
            }
            Ok(Ok(outcome)) => {
                let _ = self.model.apply_mutation_success(&presentation, &kind);
                self.notice = Some((
                    format!(
                        "已永久移除 {} 条 AI 历史并完成日志验证",
                        outcome.affected_records
                    )
                    .into(),
                    false,
                ));
            }
        }
        cx.notify();
    }

    fn export(&mut self, format: AiHistoryExportFormat, cx: &mut Context<Self>) {
        let Some(lease) = self.model.begin_export_request() else {
            return;
        };
        abort_task(&mut self.export_abort);
        let repository = self.services.investigation().ai_history().clone();
        let task = self.tokio.spawn(async move { repository.export() });
        self.export_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.finish_export(lease, format, result, cx);
                    });
                }
            });
        })
        .detach();
    }

    fn finish_export(
        &mut self,
        lease: AiHistoryRequestLease,
        format: AiHistoryExportFormat,
        result: Result<CoreResult<AiHistoryExport>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if !self.model.finish_export(&lease) {
            return;
        }
        self.export_abort = None;
        let export = match result {
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.notice = Some((format!("AI 历史导出任务失败：{error}").into(), true));
                cx.notify();
                return;
            }
            Ok(Err(error)) => {
                self.notice = Some((format!("AI 历史导出失败：{error}").into(), true));
                cx.notify();
                return;
            }
            Ok(Ok(export)) => export,
        };
        match AiHistoryExportIntent::from_export(format, export) {
            Ok(intent) => {
                cx.write_to_clipboard(ClipboardItem::new_string(intent.contents));
                self.notice = Some((
                    format!(
                        "已复制 {} 条记录的{}导出（{}）",
                        intent.record_count,
                        intent.format.label(),
                        intent.suggested_name
                    )
                    .into(),
                    false,
                ));
            }
            Err(error) => {
                self.notice = Some((format!("AI 历史 JSON 序列化失败：{error}").into(), true));
            }
        }
        cx.notify();
    }

    fn copy_selected_field(&mut self, field: AiHistoryTextField, cx: &mut Context<Self>) {
        let Some(record) = self.model.selected() else {
            return;
        };
        let value = match field {
            AiHistoryTextField::Prompt => record.prompt.clone(),
            AiHistoryTextField::Result => record.result.clone(),
        };
        cx.write_to_clipboard(ClipboardItem::new_string(value));
        self.notice = Some((format!("已复制{}纯文本", field.label()).into(), false));
        cx.notify();
    }
}

#[derive(Clone, Copy)]
enum AiHistoryTextField {
    Prompt,
    Result,
}

impl AiHistoryTextField {
    const fn label(self) -> &'static str {
        match self {
            Self::Prompt => "提示词",
            Self::Result => "AI 回答",
        }
    }
}

impl Render for AiHistoryPage {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens = self.shared.read(cx).theme.tokens();
        let items = self.model.list_items();
        let selected_id = self.model.selected_id().map(ToOwned::to_owned);
        let selected = self.model.selected().cloned();
        let notice = self.notice.clone();
        let query_empty = self.model.query().trim().is_empty();
        let is_loading = self.model.is_loading();
        let actions = div()
            .ml_auto()
            .flex()
            .gap_2()
            .child(
                crate::buttons::button("ai-history-refresh")
                    .label("刷新")
                    .small()
                    .on_click(cx.listener(|this, _, _, cx| this.refresh(cx))),
            )
            .child(
                crate::buttons::button("ai-history-export-text")
                    .label("复制纯文本")
                    .small()
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.export(AiHistoryExportFormat::PlainText, cx);
                    })),
            )
            .child(
                crate::buttons::button("ai-history-export-json")
                    .label("复制 JSON")
                    .small()
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.export(AiHistoryExportFormat::Json, cx);
                    })),
            )
            .child(
                crate::buttons::button("ai-history-clear")
                    .label("清空全部")
                    .small()
                    .danger()
                    .on_click(cx.listener(|this, _, _, cx| this.request_clear(cx))),
            );
        let header = div()
            .flex()
            .items_center()
            .gap_3()
            .child(
                div().child(div().text_2xl().child("AI 历史")).child(
                    div()
                        .text_xs()
                        .text_color(tokens.muted)
                        .child("便携数据目录中的本地记录；AI 内容始终作为纯文本显示"),
                ),
            )
            .child(actions);

        div()
            .id("ai-history-page")
            .size_full()
            .flex()
            .flex_col()
            .gap_3()
            .child(header)
            .when_some(notice, |page, (message, is_error)| {
                page.child(
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
                            .w(px(370.0))
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
                                    .when(is_loading && items.is_empty(), |list| {
                                        list.child(
                                            div()
                                                .p_5()
                                                .text_center()
                                                .text_sm()
                                                .text_color(tokens.muted)
                                                .child("正在读取 AI 历史…"),
                                        )
                                    })
                                    .when(!is_loading && items.is_empty(), |list| {
                                        list.child(
                                            div()
                                                .p_5()
                                                .text_center()
                                                .text_sm()
                                                .text_color(tokens.muted)
                                                .child(if query_empty {
                                                    "暂无 AI 历史记录"
                                                } else {
                                                    "没有匹配的 AI 历史记录"
                                                }),
                                        )
                                    })
                                    .children(items.into_iter().map(|item| {
                                        history_list_item(item, selected_id.as_deref(), tokens, cx)
                                    })),
                            )
                            .child(
                                div()
                                    .pt_2()
                                    .border_t_1()
                                    .border_color(tokens.border)
                                    .text_xs()
                                    .text_color(tokens.muted)
                                    .child(format!("当前筛选 {} 条", self.model.records().len())),
                            ),
                    )
                    .child(match selected {
                        Some(record) => self.render_record(record, tokens, cx),
                        None => empty_record(tokens),
                    }),
            )
    }
}

impl AiHistoryPage {
    fn render_record(
        &mut self,
        record: AiHistoryRecord,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let remove_id = record.id.clone();
        let title = format!("{} / {}", record.provider, record.model);
        let metadata = format!(
            "来源：{} · 时间：{} · ID：{}",
            record.source, record.timestamp, record.id
        );
        let header = div()
            .flex()
            .items_center()
            .gap_2()
            .child(
                div()
                    .flex_1()
                    .child(div().text_xl().child(title))
                    .child(div().text_xs().text_color(tokens.muted).child(metadata)),
            )
            .child(
                crate::buttons::button("ai-history-copy-prompt")
                    .label("复制提示词")
                    .small()
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.copy_selected_field(AiHistoryTextField::Prompt, cx);
                    })),
            )
            .child(
                crate::buttons::button("ai-history-copy-result")
                    .label("复制回答")
                    .small()
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.copy_selected_field(AiHistoryTextField::Result, cx);
                    })),
            )
            .child(
                crate::buttons::button("ai-history-remove")
                    .label("永久删除")
                    .small()
                    .danger()
                    .on_click(
                        cx.listener(move |this, _, _, cx| this.request_remove(&remove_id, cx)),
                    ),
            );
        div()
            .id("ai-history-record")
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
            .child(header)
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scrollbar()
                    .child(plain_text_section(
                        "提示词",
                        record.prompt,
                        tokens.accent,
                        tokens,
                    ))
                    .child(plain_text_section(
                        "AI 回答（纯文本）",
                        record.result,
                        tokens.success,
                        tokens,
                    )),
            )
            .into_any_element()
    }
}

fn history_list_item(
    item: AiHistoryListItem,
    selected_id: Option<&str>,
    tokens: ThemeTokens,
    cx: &mut Context<AiHistoryPage>,
) -> AnyElement {
    let select_id = item.id.clone();
    let selected = selected_id == Some(item.id.as_str());
    div()
        .id(SharedString::from(format!(
            "ai-history-list-item-{}",
            item.id
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
            crate::buttons::button(SharedString::from(format!("ai-history-select-{}", item.id)))
                .label(format!("{} / {}", item.provider, item.model))
                .small()
                .on_click(cx.listener(move |this, _, _, cx| this.select(&select_id, cx))),
        )
        .child(
            div()
                .mt_1()
                .text_xs()
                .text_color(tokens.muted)
                .child(format!("{} · {}", item.source, item.timestamp)),
        )
        .child(
            div()
                .mt_2()
                .text_sm()
                .child(format!("问：{}", item.prompt_preview)),
        )
        .child(
            div()
                .mt_1()
                .text_xs()
                .text_color(tokens.muted)
                .child(format!("答：{}", item.result_preview)),
        )
        .into_any_element()
}

fn empty_record(tokens: ThemeTokens) -> AnyElement {
    div()
        .id("ai-history-empty-record")
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
        .child("选择一条记录查看完整提示词与 AI 回答")
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
                    // Each untrusted line is a GPUI text node. No HTML/Markdown parser is involved.
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
        investigation::{AddAiHistory, HISTORY_SCHEMA_ID},
        operations::JournalPhase,
    };
    use uuid::Uuid;

    use super::*;
    use crate::interaction::{DialogAction, DialogHost};
    fn services() -> (PathBuf, Arc<BackendServices>) {
        let root =
            std::env::temp_dir().join(format!("lovelyres-ai-history-page-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let store = PortableStore::prepare(root.clone()).unwrap();
        (root, Arc::new(BackendServices::new(store).unwrap()))
    }

    fn record(index: usize, timestamp: i64) -> AiHistoryRecord {
        AiHistoryRecord {
            id: format!("ai-{index}"),
            timestamp,
            provider: format!("provider-{index}"),
            model: format!("model-{index}"),
            prompt: format!("prompt-{index}"),
            result: format!("result-{index}"),
            source: format!("source-{index}"),
        }
    }

    fn add_history(repository: &AiHistoryRepository, label: &str) -> AiHistoryRecord {
        repository
            .add(AddAiHistory {
                provider: "local".to_owned(),
                model: "model".to_owned(),
                prompt: format!("prompt-{label}"),
                result: format!("result-{label}"),
                source: "test".to_owned(),
            })
            .unwrap()
    }

    fn loaded_model(repository: &AiHistoryRepository) -> AiHistoryModel {
        let mut model = AiHistoryModel::default();
        model.activate();
        let lease = model.begin_list_request().unwrap();
        assert!(model.apply_list(&lease, repository.list().unwrap()));
        model
    }

    fn approve_mutation(
        model: &mut AiHistoryModel,
        proposal: AiHistoryMutationProposal,
    ) -> AiHistoryMutationResolution {
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
        model.resolve_mutation(&outcome)
    }

    async fn execute_mutation(
        repository: &AiHistoryRepository,
        services: &BackendServices,
        plan: AiHistoryMutationPlan,
        confirmation: DangerousConfirmation,
    ) -> CoreResult<InvestigationOperationOutcome> {
        match plan {
            AiHistoryMutationPlan::Remove(plan) => {
                repository
                    .execute_remove(plan, confirmation, services.operation_journal())
                    .await
            }
            AiHistoryMutationPlan::Clear(plan) => {
                repository
                    .execute_clear(plan, confirmation, services.operation_journal())
                    .await
            }
        }
    }

    #[test]
    fn malicious_html_is_preserved_only_as_plain_text_data() {
        let payload = "<script>steal()</script>\n<img src=x onerror=steal()>";
        assert_eq!(
            plain_text_lines(payload),
            vec!["<script>steal()</script>", "<img src=x onerror=steal()>"]
        );
        let export = AiHistoryExport {
            schema: HISTORY_SCHEMA_ID.to_owned(),
            exported_at_millis: 7,
            records: vec![AiHistoryRecord {
                id: "ai-malicious".to_owned(),
                timestamp: 6,
                provider: "local".to_owned(),
                model: "model".to_owned(),
                prompt: payload.to_owned(),
                result: payload.to_owned(),
                source: "test".to_owned(),
            }],
        };
        let intent =
            AiHistoryExportIntent::from_export(AiHistoryExportFormat::PlainText, export).unwrap();
        assert!(intent.contents.contains(payload));
        assert_eq!(intent.media_type, "text/plain; charset=utf-8");
    }

    #[test]
    fn full_text_search_covers_provider_model_source_prompt_and_result() {
        let (root, services) = services();
        let repository = services.investigation().ai_history();
        repository
            .add(AddAiHistory {
                provider: "ollama".to_owned(),
                model: "qwen-local".to_owned(),
                prompt: "分析可疑进程".to_owned(),
                result: "发现 hidden miner".to_owned(),
                source: "process-triage".to_owned(),
            })
            .unwrap();
        for query in ["OLLAMA", "qwen", "可疑", "MINER", "triage"] {
            assert_eq!(repository.search(query).unwrap().len(), 1, "{query}");
        }
        assert!(repository.search("unrelated").unwrap().is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn model_keeps_newest_first_and_enforces_repository_limit() {
        let mut model = AiHistoryModel::default();
        model.activate();
        let lease = model.begin_list_request().unwrap();
        let records = (0..=MAX_AI_HISTORY)
            .rev()
            .map(|index| record(index, index as i64))
            .collect();
        assert!(model.apply_list(&lease, records));
        assert_eq!(model.records().len(), MAX_AI_HISTORY);
        assert_eq!(
            model.records().first().unwrap().timestamp,
            MAX_AI_HISTORY as i64
        );
        assert_eq!(model.records().last().unwrap().timestamp, 1);
        assert_eq!(
            model.selected_id(),
            Some(format!("ai-{MAX_AI_HISTORY}").as_str())
        );
    }

    #[test]
    fn deactivation_and_reactivation_reject_late_generation() {
        let mut model = AiHistoryModel::default();
        let first_generation = model.activate();
        let lease = model.begin_list_request().unwrap();
        let old_export = model.begin_export_request().unwrap();
        let newest_export = model.begin_export_request().unwrap();
        assert!(!model.finish_export(&old_export));
        assert!(model.finish_export(&newest_export));
        model.deactivate();
        let next_generation = model.activate();
        assert_ne!(first_generation, next_generation);
        assert!(!model.accepts(&lease));
        assert!(!model.finish_export(&old_export));
        assert!(!model.apply_list(&lease, vec![record(1, 1)]));
        assert!(model.records().is_empty());
    }

    #[test]
    fn json_export_intent_is_typed_and_round_trips() {
        let export = AiHistoryExport {
            schema: HISTORY_SCHEMA_ID.to_owned(),
            exported_at_millis: 42,
            records: vec![record(3, 41)],
        };
        let intent =
            AiHistoryExportIntent::from_export(AiHistoryExportFormat::Json, export.clone())
                .unwrap();
        assert_eq!(intent.record_count, 1);
        assert_eq!(intent.media_type, "application/json");
        assert!(intent.suggested_name.ends_with(".json"));
        assert_eq!(
            serde_json::from_str::<AiHistoryExport>(&intent.contents).unwrap(),
            export
        );
    }

    #[test]
    fn cancelled_or_wrong_plan_confirmation_has_zero_side_effects() {
        let (root, services) = services();
        let repository = services.investigation().ai_history();
        let first = add_history(repository, "first");
        let second = add_history(repository, "second");
        let mut model = loaded_model(repository);

        let proposal = model.propose_remove(&first.id, repository).unwrap();
        let mut dialogs = DialogHost::default();
        let dialog_id = dialogs.show_dangerous(proposal.definition()).unwrap();
        model.arm_mutation(proposal, dialog_id);
        let cancelled = dialogs
            .dispatch(DialogAction::Cancel { dialog_id })
            .unwrap();
        assert_eq!(
            model.resolve_mutation(&cancelled),
            AiHistoryMutationResolution::Cancelled
        );
        assert_eq!(repository.list().unwrap().len(), 2);
        assert!(services.operation_journal().entries().unwrap().is_empty());

        let proposal = model.propose_remove(&first.id, repository).unwrap();
        let other = repository.plan_remove(&second.id).unwrap();
        let mut dialogs = DialogHost::default();
        let dialog_id = dialogs.show_dangerous(proposal.definition()).unwrap();
        model.arm_mutation(proposal, dialog_id);
        let wrong = DialogOutcome::DangerousApproved {
            dialog_id,
            operation_id: other.definition().id.clone(),
        };
        assert_eq!(
            model.resolve_mutation(&wrong),
            AiHistoryMutationResolution::Ignored
        );
        assert_eq!(repository.list().unwrap().len(), 2);
        assert!(services.operation_journal().entries().unwrap().is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn exact_remove_and_clear_confirmation_journal_and_verify() {
        let (root, services) = services();
        let repository = services.investigation().ai_history();
        let first = add_history(repository, "first");
        add_history(repository, "second");
        let mut model = loaded_model(repository);

        let proposal = model.propose_remove(&first.id, repository).unwrap();
        let AiHistoryMutationResolution::Authorized {
            plan,
            confirmation,
            presentation,
        } = approve_mutation(&mut model, proposal)
        else {
            panic!("the exact remove plan must be authorized");
        };
        let kind = plan.kind();
        let outcome = execute_mutation(repository, &services, *plan, confirmation)
            .await
            .unwrap();
        assert_eq!(outcome.affected_records, 1);
        assert!(outcome.verification.passed);
        assert!(model.apply_mutation_success(&presentation, &kind));
        assert!(
            !repository
                .list()
                .unwrap()
                .iter()
                .any(|item| item.id == first.id)
        );

        let proposal = model.propose_clear(repository).unwrap();
        let AiHistoryMutationResolution::Authorized {
            plan,
            confirmation,
            presentation,
        } = approve_mutation(&mut model, proposal)
        else {
            panic!("the exact clear plan must be authorized");
        };
        let kind = plan.kind();
        let outcome = execute_mutation(repository, &services, *plan, confirmation)
            .await
            .unwrap();
        assert_eq!(outcome.affected_records, 1);
        assert!(outcome.verification.passed);
        assert!(model.apply_mutation_success(&presentation, &kind));
        assert!(model.records().is_empty());
        assert!(repository.list().unwrap().is_empty());

        let entries = services.operation_journal().entries().unwrap();
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].phase, JournalPhase::Executed);
        assert_eq!(entries[1].phase, JournalPhase::VerificationPassed);
        assert_eq!(entries[2].phase, JournalPhase::Executed);
        assert_eq!(entries[3].phase, JournalPhase::VerificationPassed);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn deactivation_drops_only_late_presentation_not_audit_or_verification() {
        let (root, services) = services();
        let repository = services.investigation().ai_history();
        add_history(repository, "first");
        add_history(repository, "second");
        let mut model = loaded_model(repository);
        let proposal = model.propose_clear(repository).unwrap();
        let AiHistoryMutationResolution::Authorized {
            plan,
            confirmation,
            presentation,
        } = approve_mutation(&mut model, proposal)
        else {
            panic!("the exact clear plan must be authorized");
        };
        let kind = plan.kind();

        let outcome = execute_mutation(repository, &services, *plan, confirmation)
            .await
            .unwrap();
        assert!(outcome.verification.passed);
        model.deactivate();
        assert!(!model.apply_mutation_success(&presentation, &kind));
        assert_eq!(model.records().len(), 2);
        assert!(repository.list().unwrap().is_empty());
        let entries = services.operation_journal().entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].phase, JournalPhase::Executed);
        assert_eq!(entries[1].phase, JournalPhase::VerificationPassed);
        fs::remove_dir_all(root).unwrap();
    }
}
