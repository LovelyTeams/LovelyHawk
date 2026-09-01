//! Acting on a container the Docker pane already listed.
//!
//! The renderer never sends a container id. It sends the opaque handle its own
//! snapshot minted, and the read side turns that back into an identity under
//! the same scope, token and expiry rules the read paths use. A forged handle
//! names nothing, and a handle from a refreshed snapshot or a switched target
//! names nothing either.
//!
//! Every action goes through the core's plan, confirm, execute, journal,
//! verify and restore pipeline, so it is described before it runs, runs at
//! most once, and is put back when verification fails. This module adds only
//! what the core deliberately leaves out: a handle for a plan that has not
//! been approved yet, a lifetime for it, and the rule that approval and
//! execution are two separate calls.

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use lovelyres_core::{
    BackendServices,
    docker::{ContainerAction, ContainerActionRequest, DockerActionPlan},
    operations::DangerousConfirmation,
    target::TargetGuard,
};
use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use uuid::Uuid;

use crate::{docker_read_api::DockerReadApi, ssh_api::SshApi};

const MAX_HANDLE_BYTES: usize = 128;
/// One pane drives one dialog, but a second window on the same target is
/// legitimate, so this is a ceiling rather than a count of one.
const MAX_PLANS: usize = 16;
const MAX_PLAN_TEXT_BYTES: usize = 512;

/// Long enough to read what the plan says and decide; short enough that an
/// abandoned dialog cannot be executed from later.
const PLAN_TTL: Duration = Duration::from_secs(5 * 60);
const PLAN_DEADLINE: Duration = Duration::from_secs(45);
/// Execution covers the mutation, the journal write, the verification read and
/// a restore if verification failed, so it is given more room than a plan.
const EXECUTE_DEADLINE: Duration = Duration::from_secs(120);

pub(crate) struct DockerWriteApi {
    services: BackendServices,
    ssh_api: Arc<SshApi>,
    read: Arc<DockerReadApi>,
    registry: Arc<Mutex<PlanRegistry>>,
}

impl fmt::Debug for DockerWriteApi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (plans, confirmed) = self
            .registry
            .lock()
            .map(|registry| {
                (
                    registry.plans.len(),
                    registry
                        .plans
                        .values()
                        .filter(|plan| plan.confirmed)
                        .count(),
                )
            })
            .unwrap_or_default();
        formatter
            .debug_struct("DockerWriteApi")
            .field("plan_count", &plans)
            .field("confirmed_count", &confirmed)
            .finish()
    }
}

/// What the operator may do to a container the pane listed.
///
/// A closed set, parsed from a fixed string. The renderer cannot describe an
/// action that is not one of these, and cannot reach the runtime's own verbs.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum DockerWriteAction {
    Start,
    Stop,
    Restart,
    Pause,
    Unpause,
    Kill,
    Remove,
}

impl DockerWriteAction {
    const fn core(self) -> ContainerAction {
        match self {
            Self::Start => ContainerAction::Start,
            Self::Stop => ContainerAction::Stop,
            Self::Restart => ContainerAction::Restart,
            Self::Pause => ContainerAction::Pause,
            Self::Unpause => ContainerAction::Unpause,
            Self::Kill => ContainerAction::Kill,
            Self::Remove => ContainerAction::Remove,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DockerActionPlanDto {
    pub(crate) plan_handle: String,
    pub(crate) container_handle: String,
    /// The container's name as the pane showed it, so the dialog can say what
    /// it is about to act on. Display only; nothing resolves through it.
    pub(crate) container_name: String,
    pub(crate) action: String,
    pub(crate) action_label: String,
    /// What the host says the container is doing right now, read again at
    /// planning time rather than taken from the row.
    pub(crate) before_state: String,
    pub(crate) summary: String,
    pub(crate) dangerous: bool,
    pub(crate) restore_description: Option<String>,
    pub(crate) confirmed: bool,
    pub(crate) expires_in_seconds: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DockerActionReceiptDto {
    pub(crate) plan_handle: String,
    pub(crate) container_name: String,
    pub(crate) action_label: String,
    /// Whether the host, read back afterwards, is in the state the plan said
    /// it would be. A command that returned zero is not the same thing.
    pub(crate) verified: bool,
    pub(crate) detail: String,
    pub(crate) restored: bool,
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
    container_handle: String,
    container_name: String,
    action: DockerWriteAction,
    scope: WriteScope,
    plan: DockerActionPlan,
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

    fn store(&mut self, plan: StoredPlan) -> Result<(), DockerWriteApiError> {
        // A pane drives one dialog at a time, so an older plan of the same
        // binding is one the operator already walked away from. Dropping it
        // here also stops an abandoned dialog holding a slot for five minutes.
        self.plans
            .retain(|_, stored| stored.scope.binding_handle != plan.scope.binding_handle);
        if self.plans.len() >= MAX_PLANS {
            return Err(DockerWriteApiError::Capacity);
        }
        self.plans.insert(plan.plan_handle.clone(), plan);
        Ok(())
    }

    fn plan_mut(
        &mut self,
        scope: &WriteScope,
        plan_handle: &str,
        now: Instant,
    ) -> Result<&mut StoredPlan, DockerWriteApiError> {
        let plan = self
            .plans
            .get_mut(plan_handle)
            .ok_or(DockerWriteApiError::PlanStale)?;
        if &plan.scope != scope || plan.expires_at <= now {
            return Err(DockerWriteApiError::PlanStale);
        }
        Ok(plan)
    }

    /// Takes an approved plan out, so it can never run twice.
    fn take_confirmed(
        &mut self,
        scope: &WriteScope,
        plan_handle: &str,
        now: Instant,
    ) -> Result<StoredPlan, DockerWriteApiError> {
        if !self.plan_mut(scope, plan_handle, now)?.confirmed {
            return Err(DockerWriteApiError::PlanNotConfirmed);
        }
        self.plans
            .remove(plan_handle)
            .ok_or(DockerWriteApiError::PlanStale)
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

pub(crate) enum DockerWriteApiError {
    Core,
    BindingUnavailable,
    InvalidHandle,
    /// The container handle names nothing in a live snapshot of this scope.
    InvalidContainer,
    /// The action is not one this container can take from the state it is in,
    /// or the plan expired, or it belongs to someone else.
    PlanStale,
    PlanNotConfirmed,
    Capacity,
    Deadline,
    RegistryUnavailable,
}

impl fmt::Debug for DockerWriteApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core => "Core([REDACTED])",
            Self::BindingUnavailable => "BindingUnavailable",
            Self::InvalidHandle => "InvalidHandle",
            Self::InvalidContainer => "InvalidContainer",
            Self::PlanStale => "PlanStale",
            Self::PlanNotConfirmed => "PlanNotConfirmed",
            Self::Capacity => "Capacity",
            Self::Deadline => "Deadline",
            Self::RegistryUnavailable => "RegistryUnavailable",
        })
    }
}

impl DockerWriteApi {
    pub(crate) fn new(
        services: BackendServices,
        ssh_api: Arc<SshApi>,
        read: Arc<DockerReadApi>,
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
    ///
    /// The container's current state is read from the host here rather than
    /// taken from the row the operator clicked: the row may be minutes old,
    /// and the precondition the core checks has to be checked against now.
    pub(crate) async fn plan(
        &self,
        binding_handle: &str,
        snapshot_handle: &str,
        container_handle: &str,
        container_name: &str,
        action: DockerWriteAction,
    ) -> Result<DockerActionPlanDto, DockerWriteApiError> {
        let scope = self.capture_binding(binding_handle)?;
        let (session, identity) = self
            .read
            .resolve_container_for_mutation(binding_handle, snapshot_handle, container_handle)
            .map_err(|_| DockerWriteApiError::InvalidContainer)?;

        let request = ContainerActionRequest {
            container: identity,
            action: action.core(),
        };
        let plan = timeout(
            PLAN_DEADLINE,
            self.services.docker().plan_action(&session, &request),
        )
        .await
        .map_err(|_| DockerWriteApiError::Deadline)?
        .map_err(|_| DockerWriteApiError::Core)?;
        self.validate_binding(&scope)?;

        let now = Instant::now();
        let stored = StoredPlan {
            plan_handle: Uuid::new_v4().to_string(),
            container_handle: container_handle.to_owned(),
            container_name: bounded_text(container_name),
            action,
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

    /// Records the operator's approval; nothing runs until this happened.
    pub(crate) fn confirm(
        &self,
        binding_handle: &str,
        plan_handle: &str,
    ) -> Result<DockerActionPlanDto, DockerWriteApiError> {
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
    ) -> Result<DockerActionReceiptDto, DockerWriteApiError> {
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
            .map_err(|_| DockerWriteApiError::BindingUnavailable)?;

        let confirmation = DangerousConfirmation::approve(stored.plan.definition());
        let outcome = timeout(
            EXECUTE_DEADLINE,
            self.services.docker().execute_action(
                &session,
                stored.plan,
                confirmation,
                self.services.operation_journal(),
            ),
        )
        .await;
        self.validate_binding(&scope)?;

        let action_label = stored.action.core().label().to_owned();
        match outcome {
            Err(_) => Err(DockerWriteApiError::Deadline),
            // The core restores on failed verification itself and journals
            // whatever it got to, so a failure here is reported rather than
            // retried: retrying a half-applied destructive action is worse
            // than telling the operator to look.
            Ok(Err(_)) => Ok(DockerActionReceiptDto {
                plan_handle: stored.plan_handle,
                container_name: stored.container_name,
                action_label,
                verified: false,
                detail: "操作没有完成，主机上的状态请再确认一次。".to_owned(),
                restored: false,
            }),
            Ok(Ok(result)) => Ok(DockerActionReceiptDto {
                plan_handle: stored.plan_handle,
                container_name: stored.container_name,
                action_label,
                verified: result.verified,
                detail: bounded_text(&result.verification_detail),
                restored: result.restored_after_failed_verification,
            }),
        }
    }

    /// Drops a plan the operator decided against.
    pub(crate) fn cancel(
        &self,
        binding_handle: &str,
        plan_handle: &str,
    ) -> Result<(), DockerWriteApiError> {
        validate_handle(plan_handle)?;
        let scope = self.capture_binding(binding_handle)?;
        self.lock_registry()?.remove(&scope, plan_handle);
        Ok(())
    }

    fn capture_binding(&self, binding_handle: &str) -> Result<WriteScope, DockerWriteApiError> {
        validate_handle(binding_handle)?;
        let session = self
            .ssh_api
            .binding_session_clone(binding_handle)
            .map_err(|_| DockerWriteApiError::BindingUnavailable)?;
        self.services
            .target()
            .validate(session.target())
            .map_err(|_| DockerWriteApiError::BindingUnavailable)?;
        Ok(WriteScope {
            binding_handle: binding_handle.to_owned(),
            session_id: session.session_id().to_owned(),
            connection_id: session.connection_id().to_owned(),
            target: session.target().clone(),
        })
    }

    fn validate_binding(&self, expected: &WriteScope) -> Result<(), DockerWriteApiError> {
        let current = self.capture_binding(&expected.binding_handle)?;
        if &current != expected {
            return Err(DockerWriteApiError::BindingUnavailable);
        }
        Ok(())
    }

    fn lock_registry(&self) -> Result<MutexGuard<'_, PlanRegistry>, DockerWriteApiError> {
        self.registry
            .lock()
            .map_err(|_| DockerWriteApiError::RegistryUnavailable)
    }
}

fn plan_dto(stored: &StoredPlan, now: Instant) -> Result<DockerActionPlanDto, DockerWriteApiError> {
    let definition = stored.plan.definition();
    let remaining = stored.expires_at.saturating_duration_since(now).as_secs();
    Ok(DockerActionPlanDto {
        plan_handle: stored.plan_handle.clone(),
        container_handle: stored.container_handle.clone(),
        container_name: stored.container_name.clone(),
        action: stored.action.core().id().to_owned(),
        action_label: stored.action.core().label().to_owned(),
        before_state: bounded_text(stored.plan.before_state()),
        summary: bounded_text(&definition.summary),
        dangerous: definition.dangerous,
        restore_description: definition.restore_description.as_deref().map(bounded_text),
        confirmed: stored.confirmed,
        expires_in_seconds: u32::try_from(remaining.max(1))
            .map_err(|_| DockerWriteApiError::Core)?,
    })
}

/// Keeps host text printable and bounded. Nothing is judged by its shape: a
/// state or a verification detail is evidence, and hiding part of it because
/// it looked like something would hide the part worth reading.
fn bounded_text(value: &str) -> String {
    let mut text = String::with_capacity(value.len().min(MAX_PLAN_TEXT_BYTES));
    for character in value.chars() {
        let drawable = if character.is_control() {
            char::REPLACEMENT_CHARACTER
        } else {
            character
        };
        if text.len().saturating_add(drawable.len_utf8()) > MAX_PLAN_TEXT_BYTES {
            break;
        }
        text.push(drawable);
    }
    text
}

fn validate_handle(handle: &str) -> Result<(), DockerWriteApiError> {
    if handle.is_empty() || handle.len() > MAX_HANDLE_BYTES {
        return Err(DockerWriteApiError::InvalidHandle);
    }
    Ok(())
}
