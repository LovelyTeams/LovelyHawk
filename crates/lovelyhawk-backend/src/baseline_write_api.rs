//! Changing baseline settings on a target, and putting a change back from its
//! history — the write side of the baseline page.
//!
//! The page names settings only by catalogue item handles and history entries
//! only by the handles a history snapshot minted, and gives a value for each
//! setting it changes. The core does the rest: it re-reads the effective
//! configuration, refuses settings it cannot verify or will not write
//! (Nginx, Redis, PostgreSQL and presence checks are report-only), backs up
//! every file it touches, validates the configuration with the program's own
//! checker, reloads only when the plan says so, reads back independently and
//! restores the backups on failure; a restore re-checks that the files are
//! still exactly as the change left them before writing. This module adds a
//! handle for a plan not yet approved, a lifetime for it, and approval and
//! execution as two separate calls.

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use lovelyhawk_core::{
    BackendServices, CoreError,
    baseline::{
        BaselineChangePlan, BaselineChangeRequest, BaselineReloadPolicy, BaselineRestorePlan,
    },
    operations::DangerousConfirmation,
    target::TargetGuard,
};
use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use uuid::Uuid;

use crate::{baseline_read_api::BaselineReadApi, ssh_api::SshApi};

const MAX_HANDLE_BYTES: usize = 128;
const MAX_PLANS: usize = 16;
const MAX_CHANGES: usize = 16;
const MAX_VALUE_BYTES: usize = 256;
const MAX_PLAN_TEXT_BYTES: usize = 2_048;
/// Long enough to read what the plan says and decide; short enough that an
/// abandoned dialog cannot be executed from later.
const PLAN_TTL: Duration = Duration::from_secs(5 * 60);
const PLAN_DEADLINE: Duration = Duration::from_secs(90);
/// Backup, edit, the program's own check, a reload when asked, the read-back
/// and a possible restore of every file.
const EXECUTE_DEADLINE: Duration = Duration::from_secs(240);

/// One setting to change, named by its catalogue handle, and its new value.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BaselineChangeInput {
    item_handle: String,
    value: String,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum BaselineReloadInput {
    Defer,
    ApplyNow,
}

impl From<BaselineReloadInput> for BaselineReloadPolicy {
    fn from(value: BaselineReloadInput) -> Self {
        match value {
            BaselineReloadInput::Defer => Self::Defer,
            BaselineReloadInput::ApplyNow => Self::ApplyNow,
        }
    }
}

/// What the page may ask for: a closed set. A setting is named only by its
/// catalogue handle and a history entry only by its snapshot handles; nothing
/// here can name a file, a command or a reload of the page's choosing.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum BaselineAction {
    #[serde(rename_all = "camelCase")]
    Change {
        changes: Vec<BaselineChangeInput>,
        reload: BaselineReloadInput,
    },
    #[serde(rename_all = "camelCase")]
    Restore {
        history_handle: String,
        history_item_handle: String,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BaselinePlannedChangeDto {
    item_handle: String,
    before: String,
    after: String,
    file: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BaselinePlanDto {
    plan_handle: String,
    action: &'static str,
    summary: String,
    /// The settings a change plan writes; empty for a restore.
    changes: Vec<BaselinePlannedChangeDto>,
    /// The complete files the plan writes, backs up or puts back.
    files: Vec<String>,
    /// What happens to the running program after the write, said in words.
    reload: Option<String>,
    dangerous: bool,
    restore_description: Option<String>,
    confirmed: bool,
    expires_in_seconds: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BaselineReceiptDto {
    plan_handle: String,
    action: &'static str,
    files: Vec<String>,
    /// Whether an independent read-back found the files as planned. A
    /// command that returned zero is not the same claim.
    verified: bool,
    detail: String,
    /// The plan's own backups were put back after a failed check.
    restored: bool,
}

#[derive(Clone, PartialEq, Eq)]
struct WriteScope {
    binding_handle: String,
    session_id: String,
    connection_id: String,
    target: TargetGuard,
}

enum StoredKind {
    Change(BaselineChangePlan),
    Restore(BaselineRestorePlan),
}

struct StoredPlan {
    plan_handle: String,
    scope: WriteScope,
    kind: StoredKind,
    /// Item handles in the order of the plan's changes, for the DTO.
    item_handles: Vec<String>,
    confirmed: bool,
    expires_at: Instant,
}

impl StoredPlan {
    const fn action(&self) -> &'static str {
        match self.kind {
            StoredKind::Change(_) => "change",
            StoredKind::Restore(_) => "restore",
        }
    }

    fn files(&self) -> Vec<String> {
        match &self.kind {
            StoredKind::Change(plan) => {
                let mut files = plan
                    .changes()
                    .iter()
                    .map(|change| change.file.clone())
                    .collect::<Vec<_>>();
                files.dedup();
                files
            }
            StoredKind::Restore(plan) => plan.record().files.clone(),
        }
    }
}

#[derive(Default)]
struct PlanRegistry {
    plans: HashMap<String, StoredPlan>,
}

impl PlanRegistry {
    fn prune(&mut self, now: Instant) {
        self.plans.retain(|_, plan| plan.expires_at > now);
    }

    fn close_binding(&mut self, binding_handle: &str) {
        self.plans
            .retain(|_, plan| plan.scope.binding_handle != binding_handle);
    }

    fn store(&mut self, plan: StoredPlan) -> Result<(), BaselineWriteApiError> {
        // One dialog at a time per connection: an older plan is one the
        // operator already walked away from.
        self.plans
            .retain(|_, stored| stored.scope.binding_handle != plan.scope.binding_handle);
        if self.plans.len() >= MAX_PLANS {
            return Err(BaselineWriteApiError::Capacity);
        }
        self.plans.insert(plan.plan_handle.clone(), plan);
        Ok(())
    }

    fn plan_mut(
        &mut self,
        scope: &WriteScope,
        plan_handle: &str,
        now: Instant,
    ) -> Result<&mut StoredPlan, BaselineWriteApiError> {
        let plan = self
            .plans
            .get_mut(plan_handle)
            .ok_or(BaselineWriteApiError::PlanStale)?;
        if &plan.scope != scope || plan.expires_at <= now {
            return Err(BaselineWriteApiError::PlanStale);
        }
        Ok(plan)
    }

    fn take_confirmed(
        &mut self,
        scope: &WriteScope,
        plan_handle: &str,
        now: Instant,
    ) -> Result<StoredPlan, BaselineWriteApiError> {
        if !self.plan_mut(scope, plan_handle, now)?.confirmed {
            return Err(BaselineWriteApiError::PlanNotConfirmed);
        }
        self.plans
            .remove(plan_handle)
            .ok_or(BaselineWriteApiError::PlanStale)
    }

    fn remove(&mut self, scope: &WriteScope, plan_handle: &str) {
        if self
            .plans
            .get(plan_handle)
            .is_some_and(|plan| &plan.scope == scope)
        {
            self.plans.remove(plan_handle);
        }
    }
}

pub(crate) enum BaselineWriteApiError {
    /// The core refused the plan for a reason not named below; its words stay
    /// in the log.
    Refused,
    /// A value outside what the setting accepts.
    InvalidValue,
    /// The setting is one this tool only reports (or one it could not verify
    /// on this target), so it does not write it.
    NotWritable,
    /// Every setting asked for already has that value.
    NothingToChange,
    /// The history record carries no evidence of the files it left, so it
    /// cannot be put back without risking a later change.
    NotRestorable,
    BindingUnavailable,
    InvalidHandle,
    PlanStale,
    PlanNotConfirmed,
    Capacity,
    Deadline,
    RegistryUnavailable,
}

impl fmt::Debug for BaselineWriteApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Refused => "Refused([REDACTED])",
            Self::InvalidValue => "InvalidValue",
            Self::NotWritable => "NotWritable",
            Self::NothingToChange => "NothingToChange",
            Self::NotRestorable => "NotRestorable",
            Self::BindingUnavailable => "BindingUnavailable",
            Self::InvalidHandle => "InvalidHandle",
            Self::PlanStale => "PlanStale",
            Self::PlanNotConfirmed => "PlanNotConfirmed",
            Self::Capacity => "Capacity",
            Self::Deadline => "Deadline",
            Self::RegistryUnavailable => "RegistryUnavailable",
        })
    }
}

pub(crate) struct BaselineWriteApi {
    services: BackendServices,
    ssh_api: Arc<SshApi>,
    /// A clone of the read side; it shares the catalogue and history snapshots.
    read: BaselineReadApi,
    registry: Arc<Mutex<PlanRegistry>>,
}

impl fmt::Debug for BaselineWriteApi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let plans = self
            .registry
            .lock()
            .map(|registry| registry.plans.len())
            .unwrap_or_default();
        formatter
            .debug_struct("BaselineWriteApi")
            .field("plan_count", &plans)
            .finish()
    }
}

impl BaselineWriteApi {
    pub(crate) fn new(
        services: BackendServices,
        ssh_api: Arc<SshApi>,
        read: BaselineReadApi,
    ) -> Self {
        Self {
            services,
            ssh_api,
            read,
            registry: Arc::new(Mutex::new(PlanRegistry::default())),
        }
    }

    pub(crate) fn close_binding(&self, binding_handle: &str) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.close_binding(binding_handle);
        }
    }

    /// Describes what an action would do, without doing any of it.
    pub(crate) async fn plan(
        &self,
        binding_handle: &str,
        action: BaselineAction,
    ) -> Result<BaselinePlanDto, BaselineWriteApiError> {
        let scope = self.capture_binding(binding_handle)?;
        let session = self
            .ssh_api
            .binding_session_clone(binding_handle)
            .map_err(|_| BaselineWriteApiError::BindingUnavailable)?;
        let baseline = self.services.baseline();
        let (kind, item_handles) = match action {
            BaselineAction::Change { changes, reload } => {
                if changes.is_empty() || changes.len() > MAX_CHANGES {
                    return Err(BaselineWriteApiError::InvalidHandle);
                }
                let mut requests = Vec::with_capacity(changes.len());
                let mut handles_by_id = HashMap::new();
                for change in changes {
                    if change.value.is_empty() || change.value.len() > MAX_VALUE_BYTES {
                        return Err(BaselineWriteApiError::InvalidValue);
                    }
                    let item_id = self
                        .read
                        .item_id_for(&change.item_handle)
                        .map_err(|_| BaselineWriteApiError::InvalidHandle)?;
                    if handles_by_id
                        .insert(item_id.to_owned(), change.item_handle)
                        .is_some()
                    {
                        return Err(BaselineWriteApiError::InvalidHandle);
                    }
                    requests.push(
                        BaselineChangeRequest::new(item_id, change.value)
                            .map_err(|error| change_refusal(&error))?,
                    );
                }
                let plan = timeout(
                    PLAN_DEADLINE,
                    baseline.plan_changes(&session, requests, reload.into()),
                )
                .await
                .map_err(|_| BaselineWriteApiError::Deadline)?
                .map_err(|error| change_refusal(&error))?;
                let item_handles = plan
                    .changes()
                    .iter()
                    .map(|change| {
                        handles_by_id
                            .get(&change.item_id)
                            .cloned()
                            .ok_or(BaselineWriteApiError::Refused)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                (StoredKind::Change(plan), item_handles)
            }
            BaselineAction::Restore {
                history_handle,
                history_item_handle,
            } => {
                let record_id = self
                    .read
                    .resolve_history_record(binding_handle, &history_handle, &history_item_handle)
                    .map_err(|_| BaselineWriteApiError::InvalidHandle)?;
                let plan =
                    baseline
                        .plan_restore(&session, &record_id)
                        .map_err(|error| match error {
                            CoreError::Validation {
                                subject: "baseline restore",
                                ..
                            } => BaselineWriteApiError::NotRestorable,
                            _ => BaselineWriteApiError::Refused,
                        })?;
                (StoredKind::Restore(plan), Vec::new())
            }
        };
        self.validate_binding(&scope)?;
        let now = Instant::now();
        let stored = StoredPlan {
            plan_handle: Uuid::new_v4().to_string(),
            scope,
            kind,
            item_handles,
            confirmed: false,
            expires_at: now + PLAN_TTL,
        };
        let dto = plan_dto(&stored, now)?;
        let mut registry = self.lock_registry()?;
        registry.prune(now);
        registry.store(stored)?;
        Ok(dto)
    }

    /// Records the operator's approval of exactly this plan.
    pub(crate) fn confirm(
        &self,
        binding_handle: &str,
        plan_handle: &str,
    ) -> Result<BaselinePlanDto, BaselineWriteApiError> {
        validate_handle(plan_handle)?;
        let scope = self.capture_binding(binding_handle)?;
        let now = Instant::now();
        let mut registry = self.lock_registry()?;
        registry.prune(now);
        let plan = registry.plan_mut(&scope, plan_handle, now)?;
        plan.confirmed = true;
        plan_dto(plan, now)
    }

    /// Runs the approved plan once; the core verifies it and puts the backups
    /// back on failure.
    pub(crate) async fn execute(
        &self,
        binding_handle: &str,
        plan_handle: &str,
    ) -> Result<BaselineReceiptDto, BaselineWriteApiError> {
        validate_handle(plan_handle)?;
        let scope = self.capture_binding(binding_handle)?;
        // The plan leaves the registry before the await, so it can never run twice.
        let stored = {
            let now = Instant::now();
            let mut registry = self.lock_registry()?;
            registry.prune(now);
            registry.take_confirmed(&scope, plan_handle, now)?
        };
        let session = self
            .ssh_api
            .binding_session_clone(&scope.binding_handle)
            .map_err(|_| BaselineWriteApiError::BindingUnavailable)?;
        let action = stored.action();
        let files = stored.files();
        let baseline = self.services.baseline();
        let outcome = match stored.kind {
            StoredKind::Change(plan) => {
                let confirmation = DangerousConfirmation::approve(plan.definition());
                timeout(
                    EXECUTE_DEADLINE,
                    baseline.execute_changes(&session, plan, confirmation),
                )
                .await
            }
            StoredKind::Restore(plan) => {
                let confirmation = DangerousConfirmation::approve(plan.definition());
                timeout(
                    EXECUTE_DEADLINE,
                    baseline.execute_restore(&session, plan, confirmation),
                )
                .await
            }
        };
        self.validate_binding(&scope)?;
        let (verified, restored, detail) = match outcome {
            Err(_) => return Err(BaselineWriteApiError::Deadline),
            Ok(Ok(result)) if result.verification.passed => (
                true,
                false,
                if action == "change" {
                    "已写入并由独立读回核对：文件与计划一致，配置检查通过。这只说明配置文件已改好，不代表业务已恢复健康。".to_owned()
                } else {
                    "已放回变更前的完整文件，并由独立读回核对内容一致。这不代表服务已恢复健康，也不会自动重新应用旧配置。".to_owned()
                },
            ),
            Ok(Ok(result)) => (false, false, bounded_text(&result.verification.detail)),
            // The core puts the plan's own backups back when its read-back
            // differs, and says so in this one refusal.
            Ok(Err(CoreError::Validation {
                subject: "baseline verification",
                ..
            })) => (
                false,
                true,
                "读回核对没有通过，已用这次的备份放回原文件。请刷新扫描结果后核对。".to_owned(),
            ),
            Ok(Err(error)) => {
                tracing::warn!(operation = "BaselineAction", error = %error, "baseline action did not complete");
                (
                    false,
                    false,
                    "改动没有完成，目标上的文件请刷新扫描结果后核对；备份保留在目标的受管目录里。"
                        .to_owned(),
                )
            }
        };
        Ok(BaselineReceiptDto {
            plan_handle: stored.plan_handle,
            action,
            files,
            verified,
            detail,
            restored,
        })
    }

    /// Drops a plan the operator decided against.
    pub(crate) fn cancel(
        &self,
        binding_handle: &str,
        plan_handle: &str,
    ) -> Result<(), BaselineWriteApiError> {
        validate_handle(plan_handle)?;
        let scope = self.capture_binding(binding_handle)?;
        self.lock_registry()?.remove(&scope, plan_handle);
        Ok(())
    }

    fn capture_binding(&self, binding_handle: &str) -> Result<WriteScope, BaselineWriteApiError> {
        validate_handle(binding_handle)?;
        let session = self
            .ssh_api
            .binding_session_clone(binding_handle)
            .map_err(|_| BaselineWriteApiError::BindingUnavailable)?;
        self.services
            .target()
            .validate(session.target())
            .map_err(|_| BaselineWriteApiError::BindingUnavailable)?;
        Ok(WriteScope {
            binding_handle: binding_handle.to_owned(),
            session_id: session.session_id().to_owned(),
            connection_id: session.connection_id().to_owned(),
            target: session.target().clone(),
        })
    }

    fn validate_binding(&self, expected: &WriteScope) -> Result<(), BaselineWriteApiError> {
        if &self.capture_binding(&expected.binding_handle)? != expected {
            return Err(BaselineWriteApiError::BindingUnavailable);
        }
        Ok(())
    }

    fn lock_registry(&self) -> Result<MutexGuard<'_, PlanRegistry>, BaselineWriteApiError> {
        self.registry
            .lock()
            .map_err(|_| BaselineWriteApiError::RegistryUnavailable)
    }
}

/// Which of the named refusals a core error is.
fn change_refusal(error: &CoreError) -> BaselineWriteApiError {
    match error {
        CoreError::Validation {
            subject: "baseline value",
            ..
        } => BaselineWriteApiError::InvalidValue,
        // A report-only check, or a setting whose effective value this target
        // did not let the scan establish.
        CoreError::Validation {
            subject: "baseline change" | "baseline observation",
            ..
        } => BaselineWriteApiError::NotWritable,
        CoreError::Validation {
            subject: "baseline changes",
            message,
        } if message.contains("already match") => BaselineWriteApiError::NothingToChange,
        _ => BaselineWriteApiError::Refused,
    }
}

fn plan_dto(stored: &StoredPlan, now: Instant) -> Result<BaselinePlanDto, BaselineWriteApiError> {
    let remaining = stored.expires_at.saturating_duration_since(now).as_secs();
    let expires_in_seconds =
        u32::try_from(remaining.max(1)).map_err(|_| BaselineWriteApiError::RegistryUnavailable)?;
    let (definition, changes, reload) = match &stored.kind {
        StoredKind::Change(plan) => (
            plan.definition(),
            plan.changes()
                .iter()
                .zip(&stored.item_handles)
                .map(|(change, item_handle)| BaselinePlannedChangeDto {
                    item_handle: item_handle.clone(),
                    before: bounded_text(change.before.label()),
                    after: bounded_text(&change.after),
                    file: bounded_text(&change.file),
                })
                .collect(),
            Some(plan.reload_policy().label().to_owned()),
        ),
        StoredKind::Restore(plan) => (plan.definition(), Vec::new(), None),
    };
    Ok(BaselinePlanDto {
        plan_handle: stored.plan_handle.clone(),
        action: stored.action(),
        summary: bounded_text(&definition.summary),
        changes,
        files: stored
            .files()
            .iter()
            .map(|file| bounded_text(file))
            .collect(),
        reload,
        dangerous: definition.dangerous,
        restore_description: definition.restore_description.as_deref().map(bounded_text),
        confirmed: stored.confirmed,
        expires_in_seconds,
    })
}

/// Keeps target text printable and bounded; it is shown, never acted on.
fn bounded_text(value: &str) -> String {
    let mut output = String::new();
    for character in value.chars() {
        let character = if character.is_control() && character != '\n' {
            ' '
        } else {
            character
        };
        if output.len() + character.len_utf8() > MAX_PLAN_TEXT_BYTES {
            output.push('…');
            break;
        }
        output.push(character);
    }
    output
}

fn validate_handle(value: &str) -> Result<(), BaselineWriteApiError> {
    if value.is_empty()
        || value.len() > MAX_HANDLE_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(BaselineWriteApiError::InvalidHandle);
    }
    Ok(())
}
