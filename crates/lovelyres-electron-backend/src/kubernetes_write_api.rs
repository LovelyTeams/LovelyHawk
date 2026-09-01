//! Acting on a workload the Kubernetes pane already listed.
//!
//! The renderer never sends a namespace, a name or a UID. It sends the opaque
//! row handle its own snapshot minted, and the read side turns that back into
//! the row it was made from under the same scope and expiry rules the read
//! paths use. A forged handle names nothing, and a handle from a switched
//! target names nothing either.
//!
//! The core does the rest: it re-reads the live resource, refuses when the UID
//! or the resourceVersion moved since that row was taken, patches with a
//! closed compare-and-set document, journals, verifies by reading back, and
//! restores the exact previous revision when verification fails. This module
//! adds only what the core deliberately leaves out — a handle for a plan that
//! has not been approved yet, a lifetime for it, and the rule that approval
//! and execution are two separate calls.

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use lovelyres_core::{
    BackendServices,
    kubernetes::{KubernetesMutationPlan, KubernetesMutationRequest},
    operations::DangerousConfirmation,
    target::TargetGuard,
};
use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use uuid::Uuid;

use crate::{
    kubernetes_read_api::{KubernetesReadApi, KubernetesWorkloadRow},
    ssh_api::SshApi,
};

const MAX_HANDLE_BYTES: usize = 128;
const MAX_PLANS: usize = 16;
const MAX_PLAN_TEXT_BYTES: usize = 512;

/// Long enough to read what the plan says and decide; short enough that an
/// abandoned dialog cannot be executed from later.
const PLAN_TTL: Duration = Duration::from_secs(5 * 60);
const PLAN_DEADLINE: Duration = Duration::from_secs(45);
/// Execution covers the patch, the journal write, the read-back and a restore
/// if that read-back disagreed, so it gets more room than a plan.
const EXECUTE_DEADLINE: Duration = Duration::from_secs(120);

/// The ceiling the core enforces too. Repeated here so a request far outside
/// it is refused before a remote read happens.
const MAX_REPLICAS: u64 = 1_000;

pub(crate) struct KubernetesWriteApi {
    services: BackendServices,
    ssh_api: Arc<SshApi>,
    read: Arc<KubernetesReadApi>,
    registry: Arc<Mutex<PlanRegistry>>,
}

impl fmt::Debug for KubernetesWriteApi {
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
            .debug_struct("KubernetesWriteApi")
            .field("plan_count", &plans)
            .field("confirmed_count", &confirmed)
            .finish()
    }
}

/// What the operator may do to a workload the pane listed.
///
/// A closed set. Scaling names a count; cordon and uncordon name nothing at
/// all. Nothing here can describe a delete, an exec, or an arbitrary patch.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub(crate) enum KubernetesWriteAction {
    #[serde(rename_all = "camelCase")]
    ScaleDeployment {
        replicas: u64,
    },
    Cordon,
    Uncordon,
}

impl KubernetesWriteAction {
    const fn id(self) -> &'static str {
        match self {
            Self::ScaleDeployment { .. } => "scale-deployment",
            Self::Cordon => "cordon",
            Self::Uncordon => "uncordon",
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::ScaleDeployment { .. } => "调整副本数",
            Self::Cordon => "标记为不可调度",
            Self::Uncordon => "恢复可调度",
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KubernetesActionPlanDto {
    pub(crate) plan_handle: String,
    pub(crate) row_handle: String,
    /// The workload's name as the pane showed it, so the dialog can say what
    /// it is about to act on. Display only; nothing resolves through it.
    pub(crate) resource_name: String,
    pub(crate) action: String,
    pub(crate) action_label: String,
    pub(crate) summary: String,
    pub(crate) dangerous: bool,
    pub(crate) restore_description: Option<String>,
    pub(crate) confirmed: bool,
    pub(crate) expires_in_seconds: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KubernetesActionReceiptDto {
    pub(crate) plan_handle: String,
    pub(crate) resource_name: String,
    pub(crate) action_label: String,
    /// Whether the cluster, read back afterwards, is in the state the plan
    /// said it would be. An accepted patch is not the same claim.
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
    row_handle: String,
    resource_name: String,
    action: KubernetesWriteAction,
    scope: WriteScope,
    plan: KubernetesMutationPlan,
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

    fn store(&mut self, plan: StoredPlan) -> Result<(), KubernetesWriteApiError> {
        // A pane drives one dialog at a time, so an older plan of the same
        // binding is one the operator already walked away from.
        self.plans
            .retain(|_, stored| stored.scope.binding_handle != plan.scope.binding_handle);
        if self.plans.len() >= MAX_PLANS {
            return Err(KubernetesWriteApiError::Capacity);
        }
        self.plans.insert(plan.plan_handle.clone(), plan);
        Ok(())
    }

    fn plan_mut(
        &mut self,
        scope: &WriteScope,
        plan_handle: &str,
        now: Instant,
    ) -> Result<&mut StoredPlan, KubernetesWriteApiError> {
        let plan = self
            .plans
            .get_mut(plan_handle)
            .ok_or(KubernetesWriteApiError::PlanStale)?;
        if &plan.scope != scope || plan.expires_at <= now {
            return Err(KubernetesWriteApiError::PlanStale);
        }
        Ok(plan)
    }

    /// Takes an approved plan out, so it can never run twice.
    fn take_confirmed(
        &mut self,
        scope: &WriteScope,
        plan_handle: &str,
        now: Instant,
    ) -> Result<StoredPlan, KubernetesWriteApiError> {
        if !self.plan_mut(scope, plan_handle, now)?.confirmed {
            return Err(KubernetesWriteApiError::PlanNotConfirmed);
        }
        self.plans
            .remove(plan_handle)
            .ok_or(KubernetesWriteApiError::PlanStale)
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

pub(crate) enum KubernetesWriteApiError {
    Core,
    BindingUnavailable,
    InvalidHandle,
    /// The action does not apply to the kind of thing that handle names — a
    /// scale asked of a Node, or a cordon asked of a Deployment.
    ActionKindMismatch,
    /// The row handle names nothing in a live snapshot of this scope.
    InvalidRow,
    PlanStale,
    PlanNotConfirmed,
    Capacity,
    Deadline,
    RegistryUnavailable,
}

impl fmt::Debug for KubernetesWriteApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core => "Core([REDACTED])",
            Self::BindingUnavailable => "BindingUnavailable",
            Self::InvalidHandle => "InvalidHandle",
            Self::ActionKindMismatch => "ActionKindMismatch",
            Self::InvalidRow => "InvalidRow",
            Self::PlanStale => "PlanStale",
            Self::PlanNotConfirmed => "PlanNotConfirmed",
            Self::Capacity => "Capacity",
            Self::Deadline => "Deadline",
            Self::RegistryUnavailable => "RegistryUnavailable",
        })
    }
}

impl KubernetesWriteApi {
    pub(crate) fn new(
        services: BackendServices,
        ssh_api: Arc<SshApi>,
        read: Arc<KubernetesReadApi>,
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
        row_handle: &str,
        resource_name: &str,
        action: KubernetesWriteAction,
    ) -> Result<KubernetesActionPlanDto, KubernetesWriteApiError> {
        if let KubernetesWriteAction::ScaleDeployment { replicas } = action
            && replicas > MAX_REPLICAS
        {
            return Err(KubernetesWriteApiError::InvalidHandle);
        }
        let scope = self.capture_binding(binding_handle)?;
        let (session, row) = self
            .read
            .resolve_workload_for_mutation(binding_handle, snapshot_handle, row_handle)
            .map_err(|_| KubernetesWriteApiError::InvalidRow)?;

        // An action and a row kind that do not go together is a mistake worth
        // naming, rather than a core validation failure the operator has to
        // guess at.
        let request = match (action, row) {
            (
                KubernetesWriteAction::ScaleDeployment { replicas },
                KubernetesWorkloadRow::Deployment(deployment),
            ) => KubernetesMutationRequest::ScaleDeployment {
                deployment: *deployment,
                replicas,
            },
            (KubernetesWriteAction::Cordon, KubernetesWorkloadRow::Node(node)) => {
                KubernetesMutationRequest::SetNodeUnschedulable {
                    node: *node,
                    unschedulable: true,
                }
            }
            (KubernetesWriteAction::Uncordon, KubernetesWorkloadRow::Node(node)) => {
                KubernetesMutationRequest::SetNodeUnschedulable {
                    node: *node,
                    unschedulable: false,
                }
            }
            _ => return Err(KubernetesWriteApiError::ActionKindMismatch),
        };

        let plan = timeout(
            PLAN_DEADLINE,
            self.services.kubernetes().plan_mutation(&session, &request),
        )
        .await
        .map_err(|_| KubernetesWriteApiError::Deadline)?
        .map_err(|_| KubernetesWriteApiError::Core)?;
        self.validate_binding(&scope)?;

        let now = Instant::now();
        let stored = StoredPlan {
            plan_handle: Uuid::new_v4().to_string(),
            row_handle: row_handle.to_owned(),
            resource_name: bounded_text(resource_name),
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
    ) -> Result<KubernetesActionPlanDto, KubernetesWriteApiError> {
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
    ) -> Result<KubernetesActionReceiptDto, KubernetesWriteApiError> {
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
            .map_err(|_| KubernetesWriteApiError::BindingUnavailable)?;

        let confirmation = DangerousConfirmation::approve(stored.plan.definition());
        let outcome = timeout(
            EXECUTE_DEADLINE,
            self.services.kubernetes().execute_mutation(
                &session,
                stored.plan,
                confirmation,
                self.services.operation_journal(),
            ),
        )
        .await;
        self.validate_binding(&scope)?;

        let action_label = stored.action.label().to_owned();
        match outcome {
            Err(_) => Err(KubernetesWriteApiError::Deadline),
            // The core restores on a failed read-back itself and journals
            // whatever it reached, so a failure here is reported rather than
            // retried: retrying a half-applied patch is worse than telling the
            // operator to look.
            Ok(Err(_)) => Ok(KubernetesActionReceiptDto {
                plan_handle: stored.plan_handle,
                resource_name: stored.resource_name,
                action_label,
                verified: false,
                detail: "操作没有完成，集群里的状态请再确认一次。".to_owned(),
                restored: false,
            }),
            Ok(Ok(result)) => Ok(KubernetesActionReceiptDto {
                plan_handle: stored.plan_handle,
                resource_name: stored.resource_name,
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
    ) -> Result<(), KubernetesWriteApiError> {
        validate_handle(plan_handle)?;
        let scope = self.capture_binding(binding_handle)?;
        self.lock_registry()?.remove(&scope, plan_handle);
        Ok(())
    }

    fn capture_binding(&self, binding_handle: &str) -> Result<WriteScope, KubernetesWriteApiError> {
        validate_handle(binding_handle)?;
        let session = self
            .ssh_api
            .binding_session_clone(binding_handle)
            .map_err(|_| KubernetesWriteApiError::BindingUnavailable)?;
        self.services
            .target()
            .validate(session.target())
            .map_err(|_| KubernetesWriteApiError::BindingUnavailable)?;
        Ok(WriteScope {
            binding_handle: binding_handle.to_owned(),
            session_id: session.session_id().to_owned(),
            connection_id: session.connection_id().to_owned(),
            target: session.target().clone(),
        })
    }

    fn validate_binding(&self, expected: &WriteScope) -> Result<(), KubernetesWriteApiError> {
        let current = self.capture_binding(&expected.binding_handle)?;
        if &current != expected {
            return Err(KubernetesWriteApiError::BindingUnavailable);
        }
        Ok(())
    }

    fn lock_registry(&self) -> Result<MutexGuard<'_, PlanRegistry>, KubernetesWriteApiError> {
        self.registry
            .lock()
            .map_err(|_| KubernetesWriteApiError::RegistryUnavailable)
    }
}

fn plan_dto(
    stored: &StoredPlan,
    now: Instant,
) -> Result<KubernetesActionPlanDto, KubernetesWriteApiError> {
    let definition = stored.plan.definition();
    let remaining = stored.expires_at.saturating_duration_since(now).as_secs();
    Ok(KubernetesActionPlanDto {
        plan_handle: stored.plan_handle.clone(),
        row_handle: stored.row_handle.clone(),
        resource_name: stored.resource_name.clone(),
        action: stored.action.id().to_owned(),
        action_label: stored.action.label().to_owned(),
        summary: bounded_text(&definition.summary),
        dangerous: definition.dangerous,
        restore_description: definition.restore_description.as_deref().map(bounded_text),
        confirmed: stored.confirmed,
        expires_in_seconds: u32::try_from(remaining.max(1))
            .map_err(|_| KubernetesWriteApiError::Core)?,
    })
}

/// Keeps cluster text printable and bounded. Nothing is judged by its shape: a
/// verification detail is evidence, and hiding part of it because it looked
/// like something would hide the part worth reading.
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

fn validate_handle(handle: &str) -> Result<(), KubernetesWriteApiError> {
    if handle.is_empty() || handle.len() > MAX_HANDLE_BYTES {
        return Err(KubernetesWriteApiError::InvalidHandle);
    }
    Ok(())
}
