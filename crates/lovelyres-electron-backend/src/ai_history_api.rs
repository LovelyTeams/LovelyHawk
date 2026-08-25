//! Bounded Electron boundary for portable AI history.

use std::{
    collections::HashMap,
    fmt,
    time::{Duration, Instant},
};

use lovelyres_core::{
    BackendServices, CoreError,
    investigation::{
        AiHistoryClearPlan, AiHistoryExport, AiHistoryRecord, AiHistoryRemovePlan,
        InvestigationOperationOutcome,
    },
    operations::DangerousConfirmation,
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const MAX_PAGE_SIZE: usize = 100;
const MAX_PAGE_OFFSET: usize = 500;
const MAX_QUERY_BYTES: usize = 256;
const MAX_RECORD_BYTES: usize = 6 * 1024 * 1024;
const MAX_EXPORT_BYTES: usize = 8 * 1024 * 1024;
const MAX_PENDING_MUTATIONS: usize = 32;
const MAX_HANDLE_BYTES: usize = 128;
const MUTATION_TTL: Duration = Duration::from_secs(5 * 60);
const PREVIEW_CHARS: usize = 160;

#[derive(Default)]
pub(crate) struct AiHistoryApi {
    pending: Mutex<MutationRegistry>,
}

impl fmt::Debug for AiHistoryApi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AiHistoryApi")
            .field("pending_count", &self.pending.lock().plans.len())
            .finish()
    }
}

impl AiHistoryApi {
    pub(crate) fn list(
        &self,
        services: &BackendServices,
        query: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> Result<AiHistoryListPage, AiHistoryApiError> {
        if limit == 0 || limit > MAX_PAGE_SIZE || offset > MAX_PAGE_OFFSET {
            return Err(AiHistoryApiError::InvalidPage);
        }
        if query.is_some_and(|value| value.len() > MAX_QUERY_BYTES) {
            return Err(AiHistoryApiError::InvalidQuery);
        }
        let repository = services.investigation().ai_history();
        let records = match query.map(str::trim).filter(|value| !value.is_empty()) {
            Some(value) => repository.search(value)?,
            None => repository.list()?,
        };
        let total = records.len();
        let items = records
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(AiHistorySummaryDto::from)
            .collect::<Vec<_>>();
        Ok(AiHistoryListPage {
            total,
            offset,
            has_more: offset.saturating_add(items.len()) < total,
            items,
        })
    }

    pub(crate) fn get(
        &self,
        services: &BackendServices,
        id: &str,
    ) -> Result<AiHistoryRecordDto, AiHistoryApiError> {
        validate_record_id(id)?;
        let record = services
            .investigation()
            .ai_history()
            .list()?
            .into_iter()
            .find(|record| record.id == id)
            .ok_or(AiHistoryApiError::RecordUnavailable)?;
        if estimated_record_bytes(&record) > MAX_RECORD_BYTES {
            return Err(AiHistoryApiError::RecordTooLarge);
        }
        Ok(record.into())
    }

    pub(crate) fn plan_remove(
        &self,
        services: &BackendServices,
        id: &str,
    ) -> Result<AiHistoryMutationProposal, AiHistoryApiError> {
        validate_record_id(id)?;
        let plan = services.investigation().ai_history().plan_remove(id)?;
        self.insert_plan(PendingMutation::Remove(plan), Instant::now())
    }

    pub(crate) fn plan_clear(
        &self,
        services: &BackendServices,
    ) -> Result<AiHistoryMutationProposal, AiHistoryApiError> {
        if services.investigation().ai_history().list()?.is_empty() {
            return Err(AiHistoryApiError::EmptyHistory);
        }
        let plan = services.investigation().ai_history().plan_clear()?;
        self.insert_plan(PendingMutation::Clear(plan), Instant::now())
    }

    pub(crate) async fn confirm(
        &self,
        services: &BackendServices,
        handle: &str,
    ) -> Result<AiHistoryMutationResult, AiHistoryApiError> {
        validate_handle(handle)?;
        let pending = self.pending.lock().take(handle, Instant::now())?;
        let repository = services.investigation().ai_history();
        let (kind, planned_ids, outcome) = match pending.mutation {
            PendingMutation::Remove(plan) => {
                let planned_ids = vec![plan.record_id().to_owned()];
                let confirmation = DangerousConfirmation::approve(plan.definition());
                let outcome = repository
                    .execute_remove(plan, confirmation, services.operation_journal())
                    .await?;
                ("remove", planned_ids, outcome)
            }
            PendingMutation::Clear(plan) => {
                let planned_ids = plan.record_ids().to_vec();
                let confirmation = DangerousConfirmation::approve(plan.definition());
                let outcome = repository
                    .execute_clear(plan, confirmation, services.operation_journal())
                    .await?;
                ("clear", planned_ids, outcome)
            }
        };
        let remaining = repository
            .list()?
            .into_iter()
            .filter(|record| planned_ids.iter().any(|id| id == &record.id))
            .count();
        if !outcome.verification.passed || remaining != 0 {
            return Err(AiHistoryApiError::VerificationFailed);
        }
        Ok(AiHistoryMutationResult::from_outcome(kind, outcome))
    }

    pub(crate) fn cancel(
        &self,
        handle: &str,
    ) -> Result<AiHistoryMutationCancellation, AiHistoryApiError> {
        validate_handle(handle)?;
        self.pending.lock().cancel(handle, Instant::now())?;
        Ok(AiHistoryMutationCancellation { cancelled: true })
    }

    /// Internal-only export payload for a main-process native save boundary.
    pub(crate) fn export_for_main(
        &self,
        services: &BackendServices,
        format: AiHistoryExportFormat,
    ) -> Result<InternalAiHistoryExport, AiHistoryApiError> {
        let export = services.investigation().ai_history().export()?;
        let record_count = export.records.len();
        let estimated_bytes = export.records.iter().fold(4_096usize, |total, record| {
            total.saturating_add(estimated_record_bytes(record))
        });
        if estimated_bytes > MAX_EXPORT_BYTES {
            return Err(AiHistoryApiError::ExportTooLarge);
        }
        let extension = match format {
            AiHistoryExportFormat::PlainText => "txt",
            AiHistoryExportFormat::Json => "json",
        };
        let contents = match format {
            AiHistoryExportFormat::PlainText => plain_text_export(&export),
            AiHistoryExportFormat::Json => serde_json::to_string_pretty(&export)
                .map_err(|_| AiHistoryApiError::ExportUnavailable)?,
        };
        if contents.len() > MAX_EXPORT_BYTES {
            return Err(AiHistoryApiError::ExportTooLarge);
        }
        Ok(InternalAiHistoryExport {
            suggested_name: format!(
                "lovelyres-ai-history-{}.{}",
                export.exported_at_millis, extension
            ),
            media_type: match format {
                AiHistoryExportFormat::PlainText => "text/plain; charset=utf-8",
                AiHistoryExportFormat::Json => "application/json",
            },
            record_count,
            contents,
        })
    }

    fn insert_plan(
        &self,
        mutation: PendingMutation,
        now: Instant,
    ) -> Result<AiHistoryMutationProposal, AiHistoryApiError> {
        let kind = mutation.kind();
        let affected_records = mutation.affected_records();
        let summary = match kind {
            "remove" => "永久删除这条 AI 历史？此操作不可恢复。".to_owned(),
            "clear" => format!(
                "永久清空计划中的 {affected_records} 条 AI 历史？此操作不可恢复；确认后新增记录会保留。"
            ),
            _ => unreachable!("pending mutation has a closed kind"),
        };
        let handle = self.pending.lock().insert(mutation, now)?;
        Ok(AiHistoryMutationProposal {
            handle,
            kind,
            affected_records,
            summary,
            expires_in_seconds: MUTATION_TTL.as_secs(),
        })
    }
}

pub(crate) enum AiHistoryApiError {
    Core(CoreError),
    InvalidPage,
    InvalidQuery,
    InvalidHandle,
    InvalidPlan,
    PlanCapacity,
    EmptyHistory,
    RecordUnavailable,
    RecordTooLarge,
    VerificationFailed,
    ExportUnavailable,
    ExportTooLarge,
}

impl fmt::Debug for AiHistoryApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core(_) => "Core([REDACTED])",
            Self::InvalidPage => "InvalidPage",
            Self::InvalidQuery => "InvalidQuery",
            Self::InvalidHandle => "InvalidHandle",
            Self::InvalidPlan => "InvalidPlan",
            Self::PlanCapacity => "PlanCapacity",
            Self::EmptyHistory => "EmptyHistory",
            Self::RecordUnavailable => "RecordUnavailable",
            Self::RecordTooLarge => "RecordTooLarge",
            Self::VerificationFailed => "VerificationFailed",
            Self::ExportUnavailable => "ExportUnavailable",
            Self::ExportTooLarge => "ExportTooLarge",
        })
    }
}

impl fmt::Display for AiHistoryApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core(_) => "the AI history operation failed",
            Self::InvalidPage => "the AI history page bounds are invalid",
            Self::InvalidQuery => "the AI history query is invalid",
            Self::InvalidHandle | Self::InvalidPlan => {
                "the AI history mutation plan is missing, expired, or consumed"
            }
            Self::PlanCapacity => "the AI history mutation plan registry is full",
            Self::EmptyHistory => "there is no AI history to clear",
            Self::RecordUnavailable => "the AI history record is unavailable",
            Self::RecordTooLarge => "the AI history record exceeds the response budget",
            Self::VerificationFailed => "the AI history mutation could not be verified",
            Self::ExportUnavailable => "the AI history export could not be encoded",
            Self::ExportTooLarge => "the AI history export exceeds the main-process budget",
        })
    }
}

impl std::error::Error for AiHistoryApiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Core(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CoreError> for AiHistoryApiError {
    fn from(error: CoreError) -> Self {
        Self::Core(error)
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AiHistoryListPage {
    total: usize,
    offset: usize,
    has_more: bool,
    items: Vec<AiHistorySummaryDto>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AiHistorySummaryDto {
    id: String,
    timestamp: i64,
    provider: String,
    model: String,
    source: String,
    prompt_preview: String,
    prompt_truncated: bool,
    result_preview: String,
    result_truncated: bool,
}

impl fmt::Debug for AiHistorySummaryDto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AiHistorySummaryDto([REDACTED])")
    }
}

impl From<AiHistoryRecord> for AiHistorySummaryDto {
    fn from(record: AiHistoryRecord) -> Self {
        let (prompt_preview, prompt_truncated) = preview(&record.prompt);
        let (result_preview, result_truncated) = preview(&record.result);
        Self {
            id: record.id,
            timestamp: record.timestamp,
            provider: record.provider,
            model: record.model,
            source: record.source,
            prompt_preview,
            prompt_truncated,
            result_preview,
            result_truncated,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AiHistoryRecordDto {
    id: String,
    timestamp: i64,
    provider: String,
    model: String,
    prompt: String,
    result: String,
    source: String,
}

impl fmt::Debug for AiHistoryRecordDto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AiHistoryRecordDto([REDACTED])")
    }
}

impl From<AiHistoryRecord> for AiHistoryRecordDto {
    fn from(record: AiHistoryRecord) -> Self {
        Self {
            id: record.id,
            timestamp: record.timestamp,
            provider: record.provider,
            model: record.model,
            prompt: record.prompt,
            result: record.result,
            source: record.source,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AiHistoryMutationProposal {
    handle: String,
    kind: &'static str,
    affected_records: usize,
    summary: String,
    expires_in_seconds: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AiHistoryMutationResult {
    kind: &'static str,
    affected_records: usize,
    verified: bool,
}

impl AiHistoryMutationResult {
    fn from_outcome(kind: &'static str, outcome: InvestigationOperationOutcome) -> Self {
        Self {
            kind,
            affected_records: outcome.affected_records,
            verified: outcome.verification.passed,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct AiHistoryMutationCancellation {
    cancelled: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub(crate) enum AiHistoryExportFormat {
    #[serde(rename = "text")]
    PlainText,
    #[serde(rename = "json")]
    Json,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InternalAiHistoryExport {
    suggested_name: String,
    media_type: &'static str,
    record_count: usize,
    contents: String,
}

impl fmt::Debug for InternalAiHistoryExport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InternalAiHistoryExport")
            .field("record_count", &self.record_count)
            .field("byte_count", &self.contents.len())
            .finish()
    }
}

#[derive(Default)]
struct MutationRegistry {
    plans: HashMap<String, PendingMutationEntry>,
}

impl fmt::Debug for MutationRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MutationRegistry")
            .field("plan_count", &self.plans.len())
            .finish()
    }
}

struct PendingMutationEntry {
    created_at: Instant,
    mutation: PendingMutation,
}

enum PendingMutation {
    Remove(AiHistoryRemovePlan),
    Clear(AiHistoryClearPlan),
}

impl PendingMutation {
    fn kind(&self) -> &'static str {
        match self {
            Self::Remove(_) => "remove",
            Self::Clear(_) => "clear",
        }
    }

    fn affected_records(&self) -> usize {
        match self {
            Self::Remove(_) => 1,
            Self::Clear(plan) => plan.record_ids().len(),
        }
    }
}

impl MutationRegistry {
    fn insert(
        &mut self,
        mutation: PendingMutation,
        now: Instant,
    ) -> Result<String, AiHistoryApiError> {
        self.prune(now);
        if self.plans.len() >= MAX_PENDING_MUTATIONS {
            return Err(AiHistoryApiError::PlanCapacity);
        }
        for _ in 0..8 {
            let handle = Uuid::new_v4().to_string();
            if self.plans.contains_key(&handle) {
                continue;
            }
            self.plans.insert(
                handle.clone(),
                PendingMutationEntry {
                    created_at: now,
                    mutation,
                },
            );
            return Ok(handle);
        }
        Err(AiHistoryApiError::PlanCapacity)
    }

    fn take(
        &mut self,
        handle: &str,
        now: Instant,
    ) -> Result<PendingMutationEntry, AiHistoryApiError> {
        self.prune(now);
        self.plans
            .remove(handle)
            .ok_or(AiHistoryApiError::InvalidPlan)
    }

    fn cancel(&mut self, handle: &str, now: Instant) -> Result<(), AiHistoryApiError> {
        self.take(handle, now).map(|_| ())
    }

    fn prune(&mut self, now: Instant) {
        self.plans
            .retain(|_, entry| now.duration_since(entry.created_at) < MUTATION_TTL);
    }
}

fn validate_record_id(id: &str) -> Result<(), AiHistoryApiError> {
    if id.is_empty() || id.len() > 128 || id.chars().any(char::is_control) {
        return Err(AiHistoryApiError::RecordUnavailable);
    }
    Ok(())
}

fn validate_handle(handle: &str) -> Result<(), AiHistoryApiError> {
    if handle.is_empty()
        || handle.len() > MAX_HANDLE_BYTES
        || !handle
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(AiHistoryApiError::InvalidHandle);
    }
    Ok(())
}

fn preview(value: &str) -> (String, bool) {
    let mut chars = value.chars();
    let preview = chars.by_ref().take(PREVIEW_CHARS).collect::<String>();
    (preview, chars.next().is_some())
}

fn estimated_record_bytes(record: &AiHistoryRecord) -> usize {
    [
        &record.id,
        &record.provider,
        &record.model,
        &record.prompt,
        &record.result,
        &record.source,
    ]
    .into_iter()
    .fold(std::mem::size_of::<AiHistoryRecord>(), |total, value| {
        total.saturating_add(value.len())
    })
}

fn plain_text_export(export: &AiHistoryExport) -> String {
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

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use lovelyres_core::{
        PortableStore,
        investigation::{AddAiHistory, HISTORY_SCHEMA_ID},
        operations::JournalPhase,
    };

    use super::*;

    fn services() -> (PathBuf, BackendServices) {
        let root =
            std::env::temp_dir().join(format!("lovelyres-ai-history-api-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let store = PortableStore::prepare(root.clone()).unwrap();
        (root, BackendServices::new(store).unwrap())
    }

    fn add(services: &BackendServices, label: &str) -> AiHistoryRecord {
        services
            .investigation()
            .ai_history()
            .add(AddAiHistory {
                provider: "local".to_owned(),
                model: "qwen".to_owned(),
                prompt: format!("prompt-{label}"),
                result: format!("result-{label}"),
                source: "test".to_owned(),
            })
            .unwrap()
    }

    #[test]
    fn list_get_and_search_are_bounded_and_preserve_hostile_plain_text() {
        let (root, services) = services();
        let hostile = "</script><img src=x onerror=steal()>";
        let record = services
            .investigation()
            .ai_history()
            .add(AddAiHistory {
                provider: "local".to_owned(),
                model: "qwen".to_owned(),
                prompt: hostile.to_owned(),
                result: hostile.repeat(10),
                source: "triage".to_owned(),
            })
            .unwrap();
        let api = AiHistoryApi::default();
        let page = api.list(&services, Some("TRIAGE"), 0, 1).unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].prompt_preview, hostile);
        assert!(page.items[0].result_truncated);
        let detail = api.get(&services, &record.id).unwrap();
        assert_eq!(detail.prompt, hostile);
        assert!(!format!("{detail:?}").contains(hostile));
        assert!(matches!(
            api.list(&services, None, 0, MAX_PAGE_SIZE + 1),
            Err(AiHistoryApiError::InvalidPage)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn mutation_handles_are_single_use_cancellable_ttl_and_capacity_bounded() {
        let (root, services) = services();
        let record = add(&services, "one");
        let api = AiHistoryApi::default();

        let cancelled = api.plan_remove(&services, &record.id).unwrap();
        assert!(!cancelled.handle.contains(&record.id));
        assert!(api.cancel(&cancelled.handle).unwrap().cancelled);
        assert!(matches!(
            api.confirm(&services, &cancelled.handle).await,
            Err(AiHistoryApiError::InvalidPlan)
        ));

        let expired = api.plan_remove(&services, &record.id).unwrap();
        assert!(matches!(
            api.pending
                .lock()
                .take(&expired.handle, Instant::now() + MUTATION_TTL),
            Err(AiHistoryApiError::InvalidPlan)
        ));

        for _ in 0..MAX_PENDING_MUTATIONS {
            api.plan_remove(&services, &record.id).unwrap();
        }
        assert!(matches!(
            api.plan_remove(&services, &record.id),
            Err(AiHistoryApiError::PlanCapacity)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn remove_and_clear_execute_core_plans_journal_and_verify_exact_sets() {
        let (root, services) = services();
        let first = add(&services, "first");
        add(&services, "second");
        let api = AiHistoryApi::default();

        let remove = api.plan_remove(&services, &first.id).unwrap();
        let removed = api.confirm(&services, &remove.handle).await.unwrap();
        assert_eq!(removed.kind, "remove");
        assert_eq!(removed.affected_records, 1);
        assert!(removed.verified);
        assert!(matches!(
            api.confirm(&services, &remove.handle).await,
            Err(AiHistoryApiError::InvalidPlan)
        ));

        let clear = api.plan_clear(&services).unwrap();
        let concurrent = add(&services, "concurrent");
        let cleared = api.confirm(&services, &clear.handle).await.unwrap();
        assert_eq!(cleared.kind, "clear");
        assert_eq!(cleared.affected_records, 1);
        assert_eq!(
            services.investigation().ai_history().list().unwrap(),
            vec![concurrent]
        );
        let journal = services.operation_journal().entries().unwrap();
        assert_eq!(journal.len(), 4);
        assert_eq!(journal[0].phase, JournalPhase::Executed);
        assert_eq!(journal[1].phase, JournalPhase::VerificationPassed);
        assert_eq!(journal[2].phase, JournalPhase::Executed);
        assert_eq!(journal[3].phase, JournalPhase::VerificationPassed);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn export_is_main_only_bounded_typed_and_debug_redacted() {
        let (root, services) = services();
        add(&services, "plain");
        let api = AiHistoryApi::default();
        let plain = api
            .export_for_main(&services, AiHistoryExportFormat::PlainText)
            .unwrap();
        assert_eq!(plain.record_count, 1);
        assert_eq!(plain.media_type, "text/plain; charset=utf-8");
        assert!(plain.suggested_name.ends_with(".txt"));
        assert!(plain.contents.contains("prompt-plain"));
        assert!(!format!("{plain:?}").contains("prompt-plain"));
        let json = api
            .export_for_main(&services, AiHistoryExportFormat::Json)
            .unwrap();
        let decoded = serde_json::from_str::<AiHistoryExport>(&json.contents).unwrap();
        assert_eq!(decoded.schema, HISTORY_SCHEMA_ID);
        fs::remove_dir_all(root).unwrap();
    }
}
