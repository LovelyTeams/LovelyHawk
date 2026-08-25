//! Target-bound Electron boundary for portable command history.

use std::{
    collections::HashMap,
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use lovelyres_core::{
    BackendServices, CoreError,
    investigation::{
        CommandHistoryClearPlan, CommandHistoryRecord, CommandHistoryRemovePlan, CommandReplayPlan,
        CommandRisk, InvestigationOperationOutcome, ReplayBlockReason,
    },
    operations::DangerousConfirmation,
    ssh::BoundSshSession,
    target::TargetGuard,
};
use parking_lot::Mutex;
use serde::Serialize;
use uuid::Uuid;

use crate::ssh_api::SshApi;

const MAX_PAGE_SIZE: usize = 50;
const MAX_PAGE_OFFSET: usize = 100;
const MAX_QUERY_BYTES: usize = 1_024;
const MAX_QUERY_CHARS: usize = 256;
const MAX_RECORD_BYTES: usize = 512 * 1_024;
const MAX_PENDING_MUTATIONS: usize = 32;
const MAX_HANDLE_BYTES: usize = 128;
const PREVIEW_CHARS: usize = 120;
const MUTATION_TTL: Duration = Duration::from_secs(5 * 60);

pub(crate) struct CommandHistoryApi {
    services: BackendServices,
    ssh: Arc<SshApi>,
    pending: Mutex<MutationRegistry>,
}

impl fmt::Debug for CommandHistoryApi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandHistoryApi")
            .field("pending_count", &self.pending.lock().plans.len())
            .finish()
    }
}

impl CommandHistoryApi {
    pub(crate) fn new(services: BackendServices, ssh: Arc<SshApi>) -> Self {
        Self {
            services,
            ssh,
            pending: Mutex::new(MutationRegistry::default()),
        }
    }

    pub(crate) fn list(
        &self,
        binding_handle: &str,
        query: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> Result<CommandHistoryListPage, CommandHistoryApiError> {
        if limit == 0 || limit > MAX_PAGE_SIZE || offset > MAX_PAGE_OFFSET {
            return Err(CommandHistoryApiError::InvalidPage);
        }
        if query.is_some_and(|value| {
            value.len() > MAX_QUERY_BYTES || value.chars().count() > MAX_QUERY_CHARS
        }) {
            return Err(CommandHistoryApiError::InvalidQuery);
        }
        let session = self.binding_session(binding_handle)?;
        let repository = self.services.investigation().command_history();
        let records = match query.map(str::trim).filter(|value| !value.is_empty()) {
            Some(value) => repository.search(&session.target().identity, value)?,
            None => repository.list_for_target(&session.target().identity)?,
        };
        self.ensure_binding_unchanged(binding_handle, &session)?;
        let total = records.len();
        let items = records
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(CommandHistorySummaryDto::from)
            .collect::<Vec<_>>();
        Ok(CommandHistoryListPage {
            total,
            offset,
            has_more: offset.saturating_add(items.len()) < total,
            items,
        })
    }

    pub(crate) fn get(
        &self,
        binding_handle: &str,
        record_id: &str,
    ) -> Result<CommandHistoryRecordDto, CommandHistoryApiError> {
        validate_record_id(record_id)?;
        let session = self.binding_session(binding_handle)?;
        let record = self
            .services
            .investigation()
            .command_history()
            .list_for_target(&session.target().identity)?
            .into_iter()
            .find(|record| record.id == record_id)
            .ok_or(CommandHistoryApiError::RecordUnavailable)?;
        self.ensure_binding_unchanged(binding_handle, &session)?;
        if estimated_record_bytes(&record) > MAX_RECORD_BYTES {
            return Err(CommandHistoryApiError::RecordTooLarge);
        }
        Ok(record.into())
    }

    /// Produces a closed summary only. This API never executes or returns a shell command.
    pub(crate) fn plan_replay(
        &self,
        binding_handle: &str,
        record_id: &str,
    ) -> Result<CommandReplayIntentDto, CommandHistoryApiError> {
        validate_record_id(record_id)?;
        let session = self.binding_session(binding_handle)?;
        let plan = self
            .services
            .investigation()
            .command_history()
            .plan_replay(&session.target().identity, record_id)?;
        self.ensure_binding_unchanged(binding_handle, &session)?;
        Ok(replay_intent_dto(plan))
    }

    pub(crate) fn plan_remove(
        &self,
        binding_handle: &str,
        record_id: &str,
    ) -> Result<CommandHistoryMutationProposal, CommandHistoryApiError> {
        validate_record_id(record_id)?;
        let session = self.binding_session(binding_handle)?;
        let plan = self
            .services
            .investigation()
            .command_history()
            .plan_remove(&session.target().identity, record_id)?;
        self.ensure_binding_unchanged(binding_handle, &session)?;
        self.insert_plan(
            binding_handle,
            session.target(),
            PendingMutation::Remove(plan),
            Instant::now(),
        )
    }

    pub(crate) fn plan_clear(
        &self,
        binding_handle: &str,
    ) -> Result<CommandHistoryMutationProposal, CommandHistoryApiError> {
        let session = self.binding_session(binding_handle)?;
        let plan = self
            .services
            .investigation()
            .command_history()
            .plan_clear_for_target(&session.target().identity)?;
        if plan.record_count() == 0 {
            return Err(CommandHistoryApiError::EmptyHistory);
        }
        self.ensure_binding_unchanged(binding_handle, &session)?;
        self.insert_plan(
            binding_handle,
            session.target(),
            PendingMutation::Clear(plan),
            Instant::now(),
        )
    }

    pub(crate) async fn confirm(
        &self,
        binding_handle: &str,
        mutation_handle: &str,
    ) -> Result<CommandHistoryMutationResult, CommandHistoryApiError> {
        validate_handle(mutation_handle)?;
        let session = self.binding_session(binding_handle)?;
        let pending = self.pending.lock().take_scoped(
            mutation_handle,
            binding_handle,
            Some(session.target()),
            Instant::now(),
        )?;
        let result = execute_pending(&self.services, pending.mutation).await?;
        self.ensure_binding_unchanged(binding_handle, &session)?;
        Ok(result)
    }

    pub(crate) fn cancel(
        &self,
        binding_handle: &str,
        mutation_handle: &str,
    ) -> Result<CommandHistoryMutationCancellation, CommandHistoryApiError> {
        validate_handle(mutation_handle)?;
        self.pending
            .lock()
            .take_scoped(mutation_handle, binding_handle, None, Instant::now())?;
        Ok(CommandHistoryMutationCancellation { cancelled: true })
    }

    fn insert_plan(
        &self,
        binding_handle: &str,
        target: &TargetGuard,
        mutation: PendingMutation,
        now: Instant,
    ) -> Result<CommandHistoryMutationProposal, CommandHistoryApiError> {
        let kind = mutation.kind();
        let affected_records = mutation.affected_records();
        let summary = match kind {
            "remove" => "永久删除这条目标绑定的命令历史？此操作不可恢复。".to_owned(),
            "clear" => format!(
                "永久清空计划中的 {affected_records} 条目标命令历史？确认后新增记录会保留。"
            ),
            _ => unreachable!("command-history mutation kind is closed"),
        };
        let handle = self
            .pending
            .lock()
            .insert(binding_handle, target, mutation, now)?;
        Ok(CommandHistoryMutationProposal {
            handle,
            kind,
            affected_records,
            summary,
            expires_in_seconds: MUTATION_TTL.as_secs(),
        })
    }

    fn binding_session(
        &self,
        binding_handle: &str,
    ) -> Result<BoundSshSession, CommandHistoryApiError> {
        validate_handle(binding_handle)?;
        self.ssh
            .binding_session_clone(binding_handle)
            .map_err(|_| CommandHistoryApiError::BindingUnavailable)
    }

    fn ensure_binding_unchanged(
        &self,
        binding_handle: &str,
        expected: &BoundSshSession,
    ) -> Result<(), CommandHistoryApiError> {
        let current = self.binding_session(binding_handle)?;
        if &current != expected {
            return Err(CommandHistoryApiError::BindingUnavailable);
        }
        Ok(())
    }
}

async fn execute_pending(
    services: &BackendServices,
    mutation: PendingMutation,
) -> Result<CommandHistoryMutationResult, CommandHistoryApiError> {
    let repository = services.investigation().command_history();
    let (kind, outcome) = match mutation {
        PendingMutation::Remove(plan) => {
            let confirmation = DangerousConfirmation::approve(plan.definition());
            let outcome = repository
                .execute_remove(plan, confirmation, services.operation_journal())
                .await?;
            ("remove", outcome)
        }
        PendingMutation::Clear(plan) => {
            let confirmation = DangerousConfirmation::approve(plan.definition());
            let outcome = repository
                .execute_clear_for_target(plan, confirmation, services.operation_journal())
                .await?;
            ("clear", outcome)
        }
    };
    if !outcome.verification.passed {
        return Err(CommandHistoryApiError::VerificationFailed);
    }
    Ok(CommandHistoryMutationResult::from_outcome(kind, outcome))
}

pub(crate) enum CommandHistoryApiError {
    Core(CoreError),
    InvalidPage,
    InvalidQuery,
    InvalidHandle,
    InvalidPlan,
    PlanCapacity,
    EmptyHistory,
    BindingUnavailable,
    RecordUnavailable,
    RecordTooLarge,
    VerificationFailed,
}

impl fmt::Debug for CommandHistoryApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core(_) => "Core([REDACTED])",
            Self::InvalidPage => "InvalidPage",
            Self::InvalidQuery => "InvalidQuery",
            Self::InvalidHandle => "InvalidHandle",
            Self::InvalidPlan => "InvalidPlan",
            Self::PlanCapacity => "PlanCapacity",
            Self::EmptyHistory => "EmptyHistory",
            Self::BindingUnavailable => "BindingUnavailable",
            Self::RecordUnavailable => "RecordUnavailable",
            Self::RecordTooLarge => "RecordTooLarge",
            Self::VerificationFailed => "VerificationFailed",
        })
    }
}

impl fmt::Display for CommandHistoryApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core(_) => "the command history operation failed",
            Self::InvalidPage => "the command history page bounds are invalid",
            Self::InvalidQuery => "the command history query is invalid",
            Self::InvalidHandle => "the opaque handle is invalid",
            Self::InvalidPlan => "the command history plan is missing, expired, or consumed",
            Self::PlanCapacity => "the command history plan registry is full",
            Self::EmptyHistory => "there is no command history to clear",
            Self::BindingUnavailable => "the SSH binding is unavailable or stale",
            Self::RecordUnavailable => "the command history record is unavailable",
            Self::RecordTooLarge => "the command history record exceeds the response budget",
            Self::VerificationFailed => "the command history mutation could not be verified",
        })
    }
}

impl std::error::Error for CommandHistoryApiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Core(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CoreError> for CommandHistoryApiError {
    fn from(error: CoreError) -> Self {
        Self::Core(error)
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CommandHistoryListPage {
    total: usize,
    offset: usize,
    has_more: bool,
    items: Vec<CommandHistorySummaryDto>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CommandHistorySummaryDto {
    id: String,
    title: String,
    command_preview: String,
    command_truncated: bool,
    output_preview: String,
    output_truncated: bool,
    timestamp: i64,
    exit_code: Option<i32>,
    status: &'static str,
    risk: &'static str,
    source: String,
}

impl fmt::Debug for CommandHistorySummaryDto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CommandHistorySummaryDto([REDACTED])")
    }
}

impl From<CommandHistoryRecord> for CommandHistorySummaryDto {
    fn from(record: CommandHistoryRecord) -> Self {
        let (command_preview, command_truncated) = preview(&record.command);
        let (output_preview, output_truncated) = preview(&record.output);
        Self {
            id: record.id,
            title: record.title,
            command_preview,
            command_truncated,
            output_preview,
            output_truncated,
            timestamp: record.timestamp,
            exit_code: record.exit_code,
            status: exit_status(record.exit_code),
            risk: risk_key(record.risk),
            source: record.source,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CommandHistoryRecordDto {
    id: String,
    title: String,
    command: String,
    output: String,
    timestamp: i64,
    exit_code: Option<i32>,
    status: &'static str,
    risk: &'static str,
    source: String,
}

impl fmt::Debug for CommandHistoryRecordDto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CommandHistoryRecordDto([REDACTED])")
    }
}

impl From<CommandHistoryRecord> for CommandHistoryRecordDto {
    fn from(record: CommandHistoryRecord) -> Self {
        Self {
            id: record.id,
            title: record.title,
            command: record.command,
            output: record.output,
            timestamp: record.timestamp,
            exit_code: record.exit_code,
            status: exit_status(record.exit_code),
            risk: risk_key(record.risk),
            source: record.source,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub(crate) enum CommandReplayIntentDto {
    Blocked {
        reason: &'static str,
    },
    Ready {
        #[serde(rename = "historyId")]
        history_id: String,
        risk: &'static str,
        #[serde(rename = "executionAvailable")]
        execution_available: bool,
    },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CommandHistoryMutationProposal {
    handle: String,
    kind: &'static str,
    affected_records: usize,
    summary: String,
    expires_in_seconds: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CommandHistoryMutationResult {
    kind: &'static str,
    affected_records: usize,
    verified: bool,
}

impl CommandHistoryMutationResult {
    fn from_outcome(kind: &'static str, outcome: InvestigationOperationOutcome) -> Self {
        Self {
            kind,
            affected_records: outcome.affected_records,
            verified: outcome.verification.passed,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct CommandHistoryMutationCancellation {
    cancelled: bool,
}

struct PendingMutationEntry {
    created_at: Instant,
    binding_handle: String,
    target: TargetGuard,
    mutation: PendingMutation,
}

enum PendingMutation {
    Remove(CommandHistoryRemovePlan),
    Clear(CommandHistoryClearPlan),
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
            Self::Clear(plan) => plan.record_count(),
        }
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

impl MutationRegistry {
    fn insert(
        &mut self,
        binding_handle: &str,
        target: &TargetGuard,
        mutation: PendingMutation,
        now: Instant,
    ) -> Result<String, CommandHistoryApiError> {
        self.prune(now);
        if self.plans.len() >= MAX_PENDING_MUTATIONS {
            return Err(CommandHistoryApiError::PlanCapacity);
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
                    binding_handle: binding_handle.to_owned(),
                    target: target.clone(),
                    mutation,
                },
            );
            return Ok(handle);
        }
        Err(CommandHistoryApiError::PlanCapacity)
    }

    fn take_scoped(
        &mut self,
        handle: &str,
        binding_handle: &str,
        target: Option<&TargetGuard>,
        now: Instant,
    ) -> Result<PendingMutationEntry, CommandHistoryApiError> {
        self.prune(now);
        let scoped = self.plans.get(handle).is_some_and(|entry| {
            entry.binding_handle == binding_handle
                && target.is_none_or(|expected| &entry.target == expected)
        });
        if !scoped {
            return Err(CommandHistoryApiError::InvalidPlan);
        }
        self.plans
            .remove(handle)
            .ok_or(CommandHistoryApiError::InvalidPlan)
    }

    fn prune(&mut self, now: Instant) {
        self.plans
            .retain(|_, entry| now.duration_since(entry.created_at) < MUTATION_TTL);
    }
}

fn replay_intent_dto(plan: CommandReplayPlan) -> CommandReplayIntentDto {
    match plan {
        CommandReplayPlan::Blocked { reason } => CommandReplayIntentDto::Blocked {
            reason: replay_block_reason(reason),
        },
        CommandReplayPlan::Intent { intent } if intent.risk == CommandRisk::ReadOnly => {
            CommandReplayIntentDto::Ready {
                history_id: intent.history_id,
                risk: "read-only",
                // There is deliberately no renderer-callable execution consumer yet.
                execution_available: false,
            }
        }
        CommandReplayPlan::Intent { .. } => CommandReplayIntentDto::Blocked {
            reason: "mutating-command",
        },
    }
}

const fn replay_block_reason(reason: ReplayBlockReason) -> &'static str {
    match reason {
        ReplayBlockReason::NotFound => "not-found",
        ReplayBlockReason::TargetMismatch => "target-mismatch",
        ReplayBlockReason::DigestMismatch => "digest-mismatch",
        ReplayBlockReason::RiskChanged => "risk-changed",
    }
}

const fn risk_key(risk: CommandRisk) -> &'static str {
    match risk {
        CommandRisk::ReadOnly => "read-only",
        CommandRisk::Mutating => "mutating",
    }
}

const fn exit_status(exit_code: Option<i32>) -> &'static str {
    match exit_code {
        Some(0) => "succeeded",
        Some(_) => "failed",
        None => "unknown",
    }
}

fn preview(value: &str) -> (String, bool) {
    let mut chars = value.chars();
    let preview = chars.by_ref().take(PREVIEW_CHARS).collect::<String>();
    (preview, chars.next().is_some())
}

fn estimated_record_bytes(record: &CommandHistoryRecord) -> usize {
    [
        &record.id,
        &record.title,
        &record.command,
        &record.output,
        &record.source,
    ]
    .into_iter()
    .fold(
        std::mem::size_of::<CommandHistoryRecord>(),
        |total, value| total.saturating_add(value.len()),
    )
}

fn validate_record_id(record_id: &str) -> Result<(), CommandHistoryApiError> {
    if record_id.is_empty() || record_id.len() > 128 || record_id.chars().any(char::is_control) {
        return Err(CommandHistoryApiError::RecordUnavailable);
    }
    Ok(())
}

fn validate_handle(handle: &str) -> Result<(), CommandHistoryApiError> {
    if handle.is_empty()
        || handle.len() > MAX_HANDLE_BYTES
        || !handle
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(CommandHistoryApiError::InvalidHandle);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use lovelyres_core::{
        PortableStore, investigation::AddCommandHistory, operations::JournalPhase,
        target::TargetIdentity,
    };

    use super::*;

    fn services() -> (PathBuf, BackendServices, TargetGuard) {
        let root =
            std::env::temp_dir().join(format!("lovelyres-command-history-api-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let store = PortableStore::prepare(root.clone()).unwrap();
        let services = BackendServices::new(store).unwrap();
        let guard = TargetGuard {
            identity: TargetIdentity::new("server-1").unwrap(),
            generation: 1,
        };
        (root, services, guard)
    }

    fn add(
        services: &BackendServices,
        target: &TargetGuard,
        command: &str,
        output: &str,
        exit_code: Option<i32>,
    ) -> CommandHistoryRecord {
        services
            .investigation()
            .command_history()
            .add(AddCommandHistory {
                command: command.to_owned(),
                title: format!("run {command}"),
                output: output.to_owned(),
                exit_code,
                target: target.identity.clone(),
                source: "test".to_owned(),
            })
            .unwrap()
    }

    #[test]
    fn dto_is_bounded_plain_text_and_does_not_expose_target_or_digest() {
        let (root, services, target) = services();
        let hostile = "</script><img src=x onerror=steal()>";
        let record = add(&services, &target, "uname -a", hostile, Some(7));
        let dto = CommandHistoryRecordDto::from(record.clone());
        assert_eq!(dto.output, hostile);
        assert_eq!(dto.status, "failed");
        let encoded = serde_json::to_string(&dto).unwrap();
        assert!(!encoded.contains("commandSha256"));
        assert!(!encoded.contains("server-1"));
        assert!(!format!("{dto:?}").contains(hostile));
        let summary = CommandHistorySummaryDto::from(record);
        assert_eq!(summary.output_preview, hostile);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn replay_is_closed_read_only_and_never_exposes_a_command() {
        let (root, services, target) = services();
        let read_only = add(&services, &target, "uname -a", "Linux", Some(0));
        let mutating = add(&services, &target, "rm -f /tmp/example", "", Some(0));
        let repository = services.investigation().command_history();

        let ready = replay_intent_dto(
            repository
                .plan_replay(&target.identity, &read_only.id)
                .unwrap(),
        );
        let encoded = serde_json::to_string(&ready).unwrap();
        assert!(encoded.contains("\"status\":\"ready\""));
        assert!(encoded.contains("\"executionAvailable\":false"));
        assert!(!encoded.contains("uname -a"));
        let blocked = replay_intent_dto(
            repository
                .plan_replay(&target.identity, &mutating.id)
                .unwrap(),
        );
        assert!(
            serde_json::to_string(&blocked)
                .unwrap()
                .contains("mutating-command")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn mutation_registry_is_opaque_single_use_binding_scoped_ttl_and_capped() {
        let (root, services, target) = services();
        let record = add(&services, &target, "uptime", "up", Some(0));
        let repository = services.investigation().command_history();
        let now = Instant::now();
        let mut registry = MutationRegistry::default();
        let first = registry
            .insert(
                "binding-one",
                &target,
                PendingMutation::Remove(
                    repository
                        .plan_remove(&target.identity, &record.id)
                        .unwrap(),
                ),
                now,
            )
            .unwrap();
        assert!(!first.contains("binding-one"));
        assert!(!first.contains(&record.id));
        assert!(matches!(
            registry.take_scoped(&first, "binding-two", None, now),
            Err(CommandHistoryApiError::InvalidPlan)
        ));
        let consumed = registry
            .take_scoped(&first, "binding-one", Some(&target), now)
            .unwrap();
        assert_eq!(consumed.binding_handle, "binding-one");
        assert!(matches!(
            registry.take_scoped(&first, "binding-one", Some(&target), now),
            Err(CommandHistoryApiError::InvalidPlan)
        ));

        let expired = registry
            .insert(
                "binding-one",
                &target,
                PendingMutation::Remove(
                    repository
                        .plan_remove(&target.identity, &record.id)
                        .unwrap(),
                ),
                now,
            )
            .unwrap();
        assert!(matches!(
            registry.take_scoped(&expired, "binding-one", Some(&target), now + MUTATION_TTL),
            Err(CommandHistoryApiError::InvalidPlan)
        ));
        for _ in 0..MAX_PENDING_MUTATIONS {
            registry
                .insert(
                    "binding-one",
                    &target,
                    PendingMutation::Remove(
                        repository
                            .plan_remove(&target.identity, &record.id)
                            .unwrap(),
                    ),
                    now,
                )
                .unwrap();
        }
        assert!(matches!(
            registry.insert(
                "binding-one",
                &target,
                PendingMutation::Remove(
                    repository
                        .plan_remove(&target.identity, &record.id)
                        .unwrap()
                ),
                now,
            ),
            Err(CommandHistoryApiError::PlanCapacity)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn core_remove_and_clear_are_journaled_verified_and_preserve_concurrent_additions() {
        let (root, services, target) = services();
        let first = add(&services, &target, "uptime", "up", Some(0));
        add(&services, &target, "whoami", "root", Some(0));
        let remove = services
            .investigation()
            .command_history()
            .plan_remove(&target.identity, &first.id)
            .unwrap();
        let removed = execute_pending(&services, PendingMutation::Remove(remove))
            .await
            .unwrap();
        assert_eq!(removed.affected_records, 1);
        assert!(removed.verified);

        let clear = services
            .investigation()
            .command_history()
            .plan_clear_for_target(&target.identity)
            .unwrap();
        let concurrent = add(&services, &target, "pwd", "/srv", Some(0));
        let cleared = execute_pending(&services, PendingMutation::Clear(clear))
            .await
            .unwrap();
        assert_eq!(cleared.affected_records, 1);
        assert_eq!(
            services
                .investigation()
                .command_history()
                .list_for_target(&target.identity)
                .unwrap(),
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
}
