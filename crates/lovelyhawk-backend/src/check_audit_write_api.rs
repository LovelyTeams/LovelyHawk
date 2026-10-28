//! Adding command collection to a target, taking it off again, and clearing
//! the collected log — the second phase of the command audit page.
//!
//! The page names commands only by the handles its own catalog snapshot
//! minted; the read side turns those back into names under the same scope and
//! expiry rules. The core does the rest: it re-reads each command's state,
//! refuses anything that is not an original program (to collect) or one of
//! its own wrappers (to take off), keeps the original under a backup name,
//! journals, verifies by reading back, and puts things back when the check
//! fails. This module adds what the core leaves out — a handle for a plan not
//! yet approved, a lifetime for it, and approval and execution as two calls.

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use lovelyhawk_core::{
    BackendServices, CoreError, audit::AuditMutationPlan, operations::DangerousConfirmation,
    target::TargetGuard,
};
use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use uuid::Uuid;

use crate::{check_audit_read_api::CheckAuditReadApi, ssh_api::SshApi};

const MAX_HANDLE_BYTES: usize = 128;
const MAX_PLANS: usize = 16;
const MAX_COMMANDS: usize = 32;
const MAX_PLAN_TEXT_BYTES: usize = 2_048;
/// Long enough to read what the plan says and decide; short enough that an
/// abandoned dialog cannot be executed from later.
const PLAN_TTL: Duration = Duration::from_secs(5 * 60);
const PLAN_DEADLINE: Duration = Duration::from_secs(60);
/// Every command's swap, check and possible put-back, one after another.
const EXECUTE_DEADLINE: Duration = Duration::from_secs(240);

/// What the page may ask for. A closed set: commands are named only by
/// catalog handles, and nothing here can name a path or a program text.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum CheckAuditAction {
    #[serde(rename_all = "camelCase")]
    Collect {
        command_handles: Vec<String>,
    },
    #[serde(rename_all = "camelCase")]
    Uncollect {
        command_handles: Vec<String>,
    },
    ClearLog {},
}

impl CheckAuditAction {
    const fn id(&self) -> &'static str {
        match self {
            Self::Collect { .. } => "collect",
            Self::Uncollect { .. } => "uncollect",
            Self::ClearLog {} => "clear-log",
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CheckAuditPlanDto {
    plan_handle: String,
    action: &'static str,
    summary: String,
    /// The commands the plan changes, as their names; display only.
    commands: Vec<String>,
    dangerous: bool,
    restore_description: Option<String>,
    confirmed: bool,
    expires_in_seconds: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CheckAuditReceiptDto {
    plan_handle: String,
    action: &'static str,
    commands: Vec<String>,
    /// Whether the target, read back afterwards, is in the state the plan
    /// said it would be. A command that returned zero is not the same claim.
    verified: bool,
    detail: String,
    restored: bool,
}

#[derive(Clone, PartialEq, Eq)]
struct WriteScope {
    binding_handle: String,
    session_id: String,
    connection_id: String,
    target: TargetGuard,
}

struct StoredPlan {
    plan_handle: String,
    action: &'static str,
    scope: WriteScope,
    plan: AuditMutationPlan,
    /// Set by `confirm` and never unset. `execute` refuses without it, and the
    /// plan leaves the registry as it is taken, so approval covers one run.
    confirmed: bool,
    expires_at: Instant,
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

    fn store(&mut self, plan: StoredPlan) -> Result<(), CheckAuditWriteApiError> {
        // One dialog at a time per connection: an older plan is one the
        // operator already walked away from.
        self.plans
            .retain(|_, stored| stored.scope.binding_handle != plan.scope.binding_handle);
        if self.plans.len() >= MAX_PLANS {
            return Err(CheckAuditWriteApiError::Capacity);
        }
        self.plans.insert(plan.plan_handle.clone(), plan);
        Ok(())
    }

    fn plan_mut(
        &mut self,
        scope: &WriteScope,
        plan_handle: &str,
        now: Instant,
    ) -> Result<&mut StoredPlan, CheckAuditWriteApiError> {
        let plan = self
            .plans
            .get_mut(plan_handle)
            .ok_or(CheckAuditWriteApiError::PlanStale)?;
        if &plan.scope != scope || plan.expires_at <= now {
            return Err(CheckAuditWriteApiError::PlanStale);
        }
        Ok(plan)
    }

    fn take_confirmed(
        &mut self,
        scope: &WriteScope,
        plan_handle: &str,
        now: Instant,
    ) -> Result<StoredPlan, CheckAuditWriteApiError> {
        if !self.plan_mut(scope, plan_handle, now)?.confirmed {
            return Err(CheckAuditWriteApiError::PlanNotConfirmed);
        }
        self.plans
            .remove(plan_handle)
            .ok_or(CheckAuditWriteApiError::PlanStale)
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

pub(crate) enum CheckAuditWriteApiError {
    /// The core refused the plan; its words stay in the log.
    Refused,
    /// The login is neither root nor allowed passwordless sudo.
    NeedsPrivilege,
    /// A command is no longer in the state the action needs (not an original
    /// program to collect, or not this tool's collection to take off).
    StateChanged,
    BindingUnavailable,
    InvalidHandle,
    /// A handle that names no command of a live catalog snapshot.
    InvalidCommand,
    PlanStale,
    PlanNotConfirmed,
    Capacity,
    Deadline,
    RegistryUnavailable,
}

impl fmt::Debug for CheckAuditWriteApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Refused => "Refused([REDACTED])",
            Self::NeedsPrivilege => "NeedsPrivilege",
            Self::StateChanged => "StateChanged",
            Self::BindingUnavailable => "BindingUnavailable",
            Self::InvalidHandle => "InvalidHandle",
            Self::InvalidCommand => "InvalidCommand",
            Self::PlanStale => "PlanStale",
            Self::PlanNotConfirmed => "PlanNotConfirmed",
            Self::Capacity => "Capacity",
            Self::Deadline => "Deadline",
            Self::RegistryUnavailable => "RegistryUnavailable",
        })
    }
}

pub(crate) struct CheckAuditWriteApi {
    services: BackendServices,
    ssh_api: Arc<SshApi>,
    /// A clone of the read side; it shares the catalog registry.
    read: CheckAuditReadApi,
    registry: Arc<Mutex<PlanRegistry>>,
}

impl fmt::Debug for CheckAuditWriteApi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let plans = self
            .registry
            .lock()
            .map(|registry| registry.plans.len())
            .unwrap_or_default();
        formatter
            .debug_struct("CheckAuditWriteApi")
            .field("plan_count", &plans)
            .finish()
    }
}

impl CheckAuditWriteApi {
    pub(crate) fn new(
        services: BackendServices,
        ssh_api: Arc<SshApi>,
        read: CheckAuditReadApi,
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
        snapshot_handle: &str,
        action: CheckAuditAction,
    ) -> Result<CheckAuditPlanDto, CheckAuditWriteApiError> {
        validate_handle(snapshot_handle)?;
        let scope = self.capture_binding(binding_handle)?;
        let session = self
            .ssh_api
            .binding_session_clone(binding_handle)
            .map_err(|_| CheckAuditWriteApiError::BindingUnavailable)?;
        let action_id = action.id();
        let audit = self.services.audit();
        let planned = match action {
            CheckAuditAction::Collect { command_handles } => {
                let names = self.resolve(binding_handle, snapshot_handle, &command_handles)?;
                timeout(PLAN_DEADLINE, audit.plan_deploy_many(&session, &names)).await
            }
            CheckAuditAction::Uncollect { command_handles } => {
                let names = self.resolve(binding_handle, snapshot_handle, &command_handles)?;
                timeout(PLAN_DEADLINE, audit.plan_restore_many(&session, &names)).await
            }
            CheckAuditAction::ClearLog {} => {
                // The catalog still has to be this binding's and live.
                self.resolve(binding_handle, snapshot_handle, &[])?;
                timeout(PLAN_DEADLINE, audit.plan_clear_log(&session)).await
            }
        };
        let plan = planned
            .map_err(|_| CheckAuditWriteApiError::Deadline)?
            .map_err(|error| match error {
                CoreError::Validation {
                    subject: "audit privilege",
                    ..
                } => CheckAuditWriteApiError::NeedsPrivilege,
                CoreError::Validation {
                    subject: "audit deployment" | "audit restore",
                    ..
                } => CheckAuditWriteApiError::StateChanged,
                _ => CheckAuditWriteApiError::Refused,
            })?;
        self.validate_binding(&scope)?;
        let now = Instant::now();
        let stored = StoredPlan {
            plan_handle: Uuid::new_v4().to_string(),
            action: action_id,
            scope,
            plan,
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
    ) -> Result<CheckAuditPlanDto, CheckAuditWriteApiError> {
        validate_handle(plan_handle)?;
        let scope = self.capture_binding(binding_handle)?;
        let now = Instant::now();
        let mut registry = self.lock_registry()?;
        registry.prune(now);
        let plan = registry.plan_mut(&scope, plan_handle, now)?;
        plan.confirmed = true;
        plan_dto(plan, now)
    }

    /// Runs the approved plan once, verifies it, and puts it back on failure.
    pub(crate) async fn execute(
        &self,
        binding_handle: &str,
        plan_handle: &str,
    ) -> Result<CheckAuditReceiptDto, CheckAuditWriteApiError> {
        validate_handle(plan_handle)?;
        let scope = self.capture_binding(binding_handle)?;
        // The plan leaves the registry before the await, so the lock is never
        // held across it and the plan can never run twice.
        let stored = {
            let now = Instant::now();
            let mut registry = self.lock_registry()?;
            registry.prune(now);
            registry.take_confirmed(&scope, plan_handle, now)?
        };
        let session = self
            .ssh_api
            .binding_session_clone(&scope.binding_handle)
            .map_err(|_| CheckAuditWriteApiError::BindingUnavailable)?;
        let commands = stored.plan.affected_commands().to_vec();
        let confirmation = DangerousConfirmation::approve(stored.plan.definition());
        let outcome = timeout(
            EXECUTE_DEADLINE,
            self.services.audit().execute_mutation(
                &session,
                stored.plan,
                confirmation,
                self.services.operation_journal(),
            ),
        )
        .await;
        self.validate_binding(&scope)?;
        match outcome {
            Err(_) => Err(CheckAuditWriteApiError::Deadline),
            // The core puts back what it reached and journals it, so a failure
            // is reported rather than retried.
            Ok(Err(error)) => {
                tracing::warn!(operation = "CheckAuditAction", error = %error, "command audit change did not complete");
                Ok(CheckAuditReceiptDto {
                    plan_handle: stored.plan_handle,
                    action: stored.action,
                    commands,
                    verified: false,
                    detail: "操作没有完成，目标上的状态请刷新后再确认一次。".to_owned(),
                    restored: false,
                })
            }
            Ok(Ok(result)) => Ok(CheckAuditReceiptDto {
                plan_handle: stored.plan_handle,
                action: stored.action,
                commands,
                verified: result.verified,
                detail: bounded_text(&result.detail),
                restored: result.restored_after_failed_verification,
            }),
        }
    }

    /// Drops a plan the operator decided against.
    pub(crate) fn cancel(
        &self,
        binding_handle: &str,
        plan_handle: &str,
    ) -> Result<(), CheckAuditWriteApiError> {
        validate_handle(plan_handle)?;
        let scope = self.capture_binding(binding_handle)?;
        self.lock_registry()?.remove(&scope, plan_handle);
        Ok(())
    }

    fn resolve(
        &self,
        binding_handle: &str,
        snapshot_handle: &str,
        command_handles: &[String],
    ) -> Result<Vec<String>, CheckAuditWriteApiError> {
        if command_handles.len() > MAX_COMMANDS
            || command_handles
                .iter()
                .any(|handle| validate_handle(handle).is_err())
        {
            return Err(CheckAuditWriteApiError::InvalidHandle);
        }
        self.read
            .resolve_commands(binding_handle, snapshot_handle, command_handles)
            .map_err(|_| CheckAuditWriteApiError::InvalidCommand)
    }

    fn capture_binding(&self, binding_handle: &str) -> Result<WriteScope, CheckAuditWriteApiError> {
        validate_handle(binding_handle)?;
        let session = self
            .ssh_api
            .binding_session_clone(binding_handle)
            .map_err(|_| CheckAuditWriteApiError::BindingUnavailable)?;
        self.services
            .target()
            .validate(session.target())
            .map_err(|_| CheckAuditWriteApiError::BindingUnavailable)?;
        Ok(WriteScope {
            binding_handle: binding_handle.to_owned(),
            session_id: session.session_id().to_owned(),
            connection_id: session.connection_id().to_owned(),
            target: session.target().clone(),
        })
    }

    fn validate_binding(&self, expected: &WriteScope) -> Result<(), CheckAuditWriteApiError> {
        if &self.capture_binding(&expected.binding_handle)? != expected {
            return Err(CheckAuditWriteApiError::BindingUnavailable);
        }
        Ok(())
    }

    fn lock_registry(&self) -> Result<MutexGuard<'_, PlanRegistry>, CheckAuditWriteApiError> {
        self.registry
            .lock()
            .map_err(|_| CheckAuditWriteApiError::RegistryUnavailable)
    }
}

fn plan_dto(
    stored: &StoredPlan,
    now: Instant,
) -> Result<CheckAuditPlanDto, CheckAuditWriteApiError> {
    let definition = stored.plan.definition();
    let remaining = stored.expires_at.saturating_duration_since(now).as_secs();
    Ok(CheckAuditPlanDto {
        plan_handle: stored.plan_handle.clone(),
        action: stored.action,
        summary: bounded_text(&definition.summary),
        commands: stored.plan.affected_commands().to_vec(),
        dangerous: definition.dangerous,
        restore_description: definition.restore_description.as_deref().map(bounded_text),
        confirmed: stored.confirmed,
        expires_in_seconds: u32::try_from(remaining.max(1))
            .map_err(|_| CheckAuditWriteApiError::RegistryUnavailable)?,
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

fn validate_handle(value: &str) -> Result<(), CheckAuditWriteApiError> {
    if value.is_empty()
        || value.len() > MAX_HANDLE_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(CheckAuditWriteApiError::InvalidHandle);
    }
    Ok(())
}
