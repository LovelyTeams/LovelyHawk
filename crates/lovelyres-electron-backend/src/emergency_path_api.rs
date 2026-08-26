//! Acting on a file a read-only command run just named.
//!
//! The renderer sees an output line and asks for the path on it. It never
//! sends a path: the sidecar extracted every path from the output it produced
//! itself, kept them under opaque handles, and will only act on one of those.
//! A forged handle names nothing, so the worst a compromised renderer can do
//! is act on a file the host already printed to the operator.
//!
//! Each action goes through the same plan, confirm, execute and verify
//! pipeline the file browser uses, so it is described before it runs, runs at
//! most once, and is put back when verification fails.

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use lovelyres_core::{
    BackendServices,
    command_paths::paths_in_output,
    operations::{DangerousConfirmation, OperationState},
    sftp::{BoundSftpSession, RemotePath, SftpFileKind, SftpMutation, SftpPlannedOperation},
    target::TargetGuard,
};
use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use uuid::Uuid;

use crate::ssh_api::SshApi;

const MAX_HANDLE_BYTES: usize = 128;
/// Paths one binding may hold at once. A run offers at most 500, so this keeps
/// the last few runs addressable without letting a sweep grow without bound.
const MAX_STORED_PATHS: usize = 2_000;
const MAX_PLANS: usize = 16;
const MAX_PATH_DISPLAY_BYTES: usize = 1_024;
const MAX_PLAN_TEXT_BYTES: usize = 512;
/// Long enough to read a page of results and decide, short enough that a stale
/// window cannot act on a host that has moved on.
const PATH_TTL: Duration = Duration::from_secs(15 * 60);
const PLAN_TTL: Duration = Duration::from_secs(5 * 60);
const BIND_DEADLINE: Duration = Duration::from_secs(15);
const INSPECT_DEADLINE: Duration = Duration::from_secs(20);
const EXECUTE_DEADLINE: Duration = Duration::from_secs(60);

/// The bits that let a file run, cleared together so no owner keeps the
/// ability to run it and nothing is left to elevate with. The set-user-ID and
/// set-group-ID bits go with them: a file left at `4644` reads as still armed
/// and comes back with a single `chmod +x`. The sticky bit is not touched,
/// because on a directory it means something else entirely.
const EXECUTE_BITS: u32 = 0o6111;
/// The permission bits `chmod` may set, so a stored mode never carries file
/// type bits into a change.
const PERMISSION_BITS: u32 = 0o7777;

#[derive(Clone)]
pub(crate) struct EmergencyPathApi {
    services: BackendServices,
    ssh_api: Arc<SshApi>,
    registry: Arc<Mutex<PathRegistry>>,
}

/// What the operator may do to a file the output named.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum EmergencyPathAction {
    /// Clear the execute bits. The file stops running and stays readable, so
    /// it can still be examined afterwards.
    Disarm,
    /// Move the file into the recoverable backup namespace.
    Quarantine,
}

impl EmergencyPathAction {
    fn label(self) -> &'static str {
        match self {
            Self::Disarm => "disarm",
            Self::Quarantine => "quarantine",
        }
    }
}

/// A path one run's own output named, handed back as a capability.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EmergencyPathDto {
    pub(crate) path_handle: String,
    /// Which displayed output line this path was read from.
    pub(crate) line: u32,
    /// The path as the host printed it, so the menu can name what it will act
    /// on. The renderer displays it; it cannot act with it.
    pub(crate) path: String,
}

/// What the host says about the file right now.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EmergencyPathDetailDto {
    pub(crate) path_handle: String,
    pub(crate) path: String,
    pub(crate) kind: String,
    pub(crate) size: String,
    pub(crate) mode: Option<String>,
    pub(crate) owner_id: Option<u32>,
    pub(crate) group_id: Option<u32>,
    pub(crate) modified_at: Option<String>,
    /// Whether anyone can currently run it, which is what disarming changes.
    pub(crate) executable: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EmergencyPathPlanDto {
    pub(crate) plan_handle: String,
    pub(crate) path_handle: String,
    pub(crate) path: String,
    pub(crate) action: String,
    pub(crate) summary: String,
    pub(crate) dangerous: bool,
    pub(crate) restore_description: Option<String>,
    pub(crate) state: String,
    pub(crate) expires_in_seconds: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EmergencyPathReceiptDto {
    pub(crate) plan_handle: String,
    pub(crate) path: String,
    pub(crate) action: String,
    pub(crate) passed: bool,
    pub(crate) detail: String,
    pub(crate) restored: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PathScope {
    pub(crate) binding_handle: String,
    pub(crate) session_id: String,
    pub(crate) connection_id: String,
    pub(crate) target: TargetGuard,
}

struct StoredPath {
    scope: PathScope,
    path: RemotePath,
    expires_at: Instant,
}

struct PlannedPath {
    plan_handle: String,
    path_handle: String,
    path: String,
    action: EmergencyPathAction,
    scope: PathScope,
    operation: SftpPlannedOperation,
    expires_at: Instant,
}

#[derive(Default)]
struct PathRegistry {
    paths: HashMap<String, StoredPath>,
    plans: HashMap<String, PlannedPath>,
}

impl PathRegistry {
    fn prune(&mut self, now: Instant) {
        self.paths.retain(|_, stored| stored.expires_at > now);
        self.plans.retain(|_, plan| plan.expires_at > now);
    }

    fn close_binding(&mut self, binding_handle: &str) {
        self.paths
            .retain(|_, stored| stored.scope.binding_handle != binding_handle);
        self.plans
            .retain(|_, plan| plan.scope.binding_handle != binding_handle);
    }

    /// Replaces what this binding was offering, so a fresh run's handles are
    /// the only ones it can act through.
    fn replace_for_binding(&mut self, scope: &PathScope, offered: Vec<(String, RemotePath)>) {
        self.paths
            .retain(|_, stored| stored.scope.binding_handle != scope.binding_handle);
        let expires_at = Instant::now() + PATH_TTL;
        for (handle, path) in offered {
            if self.paths.len() >= MAX_STORED_PATHS {
                break;
            }
            self.paths.insert(
                handle,
                StoredPath {
                    scope: scope.clone(),
                    path,
                    expires_at,
                },
            );
        }
    }

    fn path(
        &self,
        scope: &PathScope,
        path_handle: &str,
        now: Instant,
    ) -> Result<RemotePath, EmergencyPathApiError> {
        let stored = self
            .paths
            .get(path_handle)
            .ok_or(EmergencyPathApiError::PathStale)?;
        if !still_live(&stored.scope, stored.expires_at, scope, now) {
            return Err(EmergencyPathApiError::PathStale);
        }
        Ok(stored.path.clone())
    }

    fn store_plan(&mut self, plan: PlannedPath) -> Result<(), EmergencyPathApiError> {
        // A binding drives one dialog at a time, so an older plan of the same
        // binding is one the operator already walked away from.
        self.plans
            .retain(|_, stored| stored.scope.binding_handle != plan.scope.binding_handle);
        if self.plans.len() >= MAX_PLANS {
            return Err(EmergencyPathApiError::Capacity);
        }
        self.plans.insert(plan.plan_handle.clone(), plan);
        Ok(())
    }

    fn plan_mut(
        &mut self,
        scope: &PathScope,
        plan_handle: &str,
        now: Instant,
    ) -> Result<&mut PlannedPath, EmergencyPathApiError> {
        let plan = self
            .plans
            .get_mut(plan_handle)
            .ok_or(EmergencyPathApiError::PlanStale)?;
        if !still_live(&plan.scope, plan.expires_at, scope, now) {
            return Err(EmergencyPathApiError::PlanStale);
        }
        Ok(plan)
    }

    /// Takes a confirmed plan out of the registry, so it can never run twice.
    fn take_confirmed_plan(
        &mut self,
        scope: &PathScope,
        plan_handle: &str,
        now: Instant,
    ) -> Result<PlannedPath, EmergencyPathApiError> {
        let plan = self.plan_mut(scope, plan_handle, now)?;
        if plan.operation.state() != OperationState::Confirmed {
            return Err(EmergencyPathApiError::PlanStale);
        }
        self.plans
            .remove(plan_handle)
            .ok_or(EmergencyPathApiError::PlanStale)
    }
}

pub(crate) enum EmergencyPathApiError {
    Core,
    BindingUnavailable,
    InvalidHandle,
    PathStale,
    PlanStale,
    Capacity,
    Deadline,
    RegistryUnavailable,
}

impl fmt::Debug for EmergencyPathApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core => "Core([REDACTED])",
            Self::BindingUnavailable => "BindingUnavailable",
            Self::InvalidHandle => "InvalidHandle",
            Self::PathStale => "PathStale",
            Self::PlanStale => "PlanStale",
            Self::Capacity => "Capacity",
            Self::Deadline => "Deadline",
            Self::RegistryUnavailable => "RegistryUnavailable",
        })
    }
}

impl EmergencyPathApi {
    pub(crate) fn new(services: BackendServices, ssh_api: Arc<SshApi>) -> Self {
        Self {
            services,
            ssh_api,
            registry: Arc::new(Mutex::new(PathRegistry::default())),
        }
    }

    pub(crate) fn close_binding(&self, binding_handle: &str) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.close_binding(binding_handle);
        }
    }

    /// Reads every path out of one run's output and offers each as a handle.
    ///
    /// Called with output the sidecar just received from the host, before it
    /// crosses the boundary. A path the renderer cannot see here is a path it
    /// can never ask to act on.
    /// `clipped_lines` names displayed lines that lost their tail to the
    /// per-line ceiling; what remains of those is a fragment, so no action is
    /// offered on them.
    pub(crate) fn offer(
        &self,
        scope: &PathScope,
        output: &str,
        clipped_lines: &[u32],
    ) -> Vec<EmergencyPathDto> {
        let mut offered = Vec::new();
        let mut stored = Vec::new();
        for (line, path) in paths_in_output(output) {
            if path.len() > MAX_PATH_DISPLAY_BYTES || clipped_lines.contains(&line) {
                continue;
            }
            let Ok(remote) = RemotePath::new(path.clone()) else {
                continue;
            };
            let path_handle = Uuid::new_v4().to_string();
            offered.push(EmergencyPathDto {
                path_handle: path_handle.clone(),
                line,
                path,
            });
            stored.push((path_handle, remote));
        }
        let Ok(mut registry) = self.registry.lock() else {
            // Without a registry the handles resolve to nothing, and offering
            // an action that cannot run is worse than offering none.
            return Vec::new();
        };
        registry.prune(Instant::now());
        registry.replace_for_binding(scope, stored);
        offered
    }

    /// What the host says about the file right now. Reads nothing else.
    pub(crate) async fn inspect(
        &self,
        binding_handle: &str,
        path_handle: &str,
    ) -> Result<EmergencyPathDetailDto, EmergencyPathApiError> {
        validate_handle(path_handle)?;
        let scope = self.capture_binding(binding_handle)?;
        let path = {
            let now = Instant::now();
            let mut registry = self.lock_registry()?;
            registry.prune(now);
            registry.path(&scope, path_handle, now)?
        };
        let session = self.bind_sftp(&scope).await?;
        let metadata = timeout(
            INSPECT_DEADLINE,
            self.services.sftp().metadata(&session, &path, false),
        )
        .await
        .map_err(|_| EmergencyPathApiError::Deadline)?
        .map_err(|_| EmergencyPathApiError::Core)?;
        self.validate_binding(&scope)?;
        let permissions = metadata.permissions.map(|mode| mode & PERMISSION_BITS);
        Ok(EmergencyPathDetailDto {
            path_handle: path_handle.to_owned(),
            path: path.as_str().to_owned(),
            kind: match metadata.kind {
                SftpFileKind::File => "file",
                SftpFileKind::Directory => "directory",
                SftpFileKind::Symlink => "symlink",
                SftpFileKind::Other => "other",
            }
            .to_owned(),
            size: metadata.size.to_string(),
            mode: permissions.map(|mode| format!("{mode:04o}")),
            owner_id: metadata.uid,
            group_id: metadata.gid,
            modified_at: metadata.modified_at.map(|at| at.to_rfc3339()),
            executable: permissions.is_some_and(|mode| mode & EXECUTE_BITS != 0),
        })
    }

    /// Describes what an action would do, without doing any of it.
    pub(crate) async fn plan(
        &self,
        binding_handle: &str,
        path_handle: &str,
        action: EmergencyPathAction,
    ) -> Result<EmergencyPathPlanDto, EmergencyPathApiError> {
        validate_handle(path_handle)?;
        let scope = self.capture_binding(binding_handle)?;
        let path = {
            let now = Instant::now();
            let mut registry = self.lock_registry()?;
            registry.prune(now);
            registry.path(&scope, path_handle, now)?
        };
        let session = self.bind_sftp(&scope).await?;
        let mutation = self.build_mutation(&session, &path, action).await?;
        self.validate_binding(&scope)?;
        let operation = self
            .services
            .sftp()
            .plan(&session, mutation)
            .map_err(|_| EmergencyPathApiError::Core)?;
        self.validate_binding(&scope)?;

        let now = Instant::now();
        let plan = PlannedPath {
            plan_handle: Uuid::new_v4().to_string(),
            path_handle: path_handle.to_owned(),
            path: path.as_str().to_owned(),
            action,
            scope,
            operation,
            expires_at: now + PLAN_TTL,
        };
        let dto = plan_dto(&plan, now)?;
        let mut registry = self.lock_registry()?;
        registry.prune(now);
        registry.store_plan(plan)?;
        Ok(dto)
    }

    /// Records the operator's approval; nothing runs until this happened.
    pub(crate) fn confirm(
        &self,
        binding_handle: &str,
        plan_handle: &str,
    ) -> Result<EmergencyPathPlanDto, EmergencyPathApiError> {
        validate_handle(plan_handle)?;
        let scope = self.capture_binding(binding_handle)?;
        let now = Instant::now();
        let mut registry = self.lock_registry()?;
        registry.prune(now);
        let plan = registry.plan_mut(&scope, plan_handle, now)?;
        let confirmation = DangerousConfirmation::approve(plan.operation.definition());
        plan.operation
            .confirm(confirmation)
            .map_err(|_| EmergencyPathApiError::PlanStale)?;
        plan_dto(plan, now)
    }

    /// Runs the confirmed plan once, verifies it, and puts it back on failure.
    pub(crate) async fn execute(
        &self,
        binding_handle: &str,
        plan_handle: &str,
    ) -> Result<EmergencyPathReceiptDto, EmergencyPathApiError> {
        validate_handle(plan_handle)?;
        let scope = self.capture_binding(binding_handle)?;
        // The plan leaves the registry before the await, so the lock is never
        // held across it and the plan can never run twice.
        let mut plan = {
            let now = Instant::now();
            let mut registry = self.lock_registry()?;
            registry.prune(now);
            registry.take_confirmed_plan(&scope, plan_handle, now)?
        };
        let outcome = timeout(EXECUTE_DEADLINE, plan.operation.execute_and_verify()).await;
        self.validate_binding(&scope)?;
        let verification = match outcome {
            Err(_) => return Err(EmergencyPathApiError::Deadline),
            Ok(Err(_)) => {
                let restored = plan.operation.restore().await.is_ok();
                return Ok(EmergencyPathReceiptDto {
                    plan_handle: plan.plan_handle,
                    path: plan.path,
                    action: plan.action.label().to_owned(),
                    passed: false,
                    detail: "操作未能完成。".to_owned(),
                    restored,
                });
            }
            Ok(Ok(verification)) => verification,
        };
        let restored = if verification.passed {
            false
        } else {
            plan.operation.restore().await.is_ok()
        };
        Ok(EmergencyPathReceiptDto {
            plan_handle: plan.plan_handle,
            path: plan.path,
            action: plan.action.label().to_owned(),
            passed: verification.passed,
            detail: bounded_text(&verification.detail),
            restored,
        })
    }

    /// Drops a plan the operator decided against.
    pub(crate) fn cancel(
        &self,
        binding_handle: &str,
        plan_handle: &str,
    ) -> Result<(), EmergencyPathApiError> {
        validate_handle(plan_handle)?;
        let scope = self.capture_binding(binding_handle)?;
        let mut registry = self.lock_registry()?;
        if registry
            .plans
            .get(plan_handle)
            .is_some_and(|plan| plan.scope == scope)
        {
            registry.plans.remove(plan_handle);
        }
        Ok(())
    }

    /// Turns a capability and an action into the one mutation the core takes.
    async fn build_mutation(
        &self,
        session: &BoundSftpSession,
        path: &RemotePath,
        action: EmergencyPathAction,
    ) -> Result<SftpMutation, EmergencyPathApiError> {
        match action {
            EmergencyPathAction::Disarm => {
                let metadata = timeout(
                    INSPECT_DEADLINE,
                    self.services.sftp().metadata(session, path, false),
                )
                .await
                .map_err(|_| EmergencyPathApiError::Deadline)?
                .map_err(|_| EmergencyPathApiError::Core)?;
                let expected_mode = metadata
                    .permissions
                    .map(|mode| mode & PERMISSION_BITS)
                    .ok_or(EmergencyPathApiError::Core)?;
                // Nothing to disarm, and a chmod to the mode it already has
                // would verify as a change that never happened.
                if expected_mode & EXECUTE_BITS == 0 {
                    return Err(EmergencyPathApiError::Core);
                }
                // The expected mode makes the change fail rather than apply to
                // a file that was altered between reading it and acting on it.
                Ok(SftpMutation::ChmodIfMode {
                    path: path.clone(),
                    expected_mode,
                    mode: expected_mode & !EXECUTE_BITS,
                })
            }
            EmergencyPathAction::Quarantine => Ok(SftpMutation::Remove { path: path.clone() }),
        }
    }

    fn capture_binding(&self, binding_handle: &str) -> Result<PathScope, EmergencyPathApiError> {
        validate_handle(binding_handle)?;
        let session = self
            .ssh_api
            .binding_session_clone(binding_handle)
            .map_err(|_| EmergencyPathApiError::BindingUnavailable)?;
        self.services
            .target()
            .validate(session.target())
            .map_err(|_| EmergencyPathApiError::BindingUnavailable)?;
        Ok(PathScope {
            binding_handle: binding_handle.to_owned(),
            session_id: session.session_id().to_owned(),
            connection_id: session.connection_id().to_owned(),
            target: session.target().clone(),
        })
    }

    fn validate_binding(&self, expected: &PathScope) -> Result<(), EmergencyPathApiError> {
        let current = self.capture_binding(&expected.binding_handle)?;
        if &current != expected {
            return Err(EmergencyPathApiError::BindingUnavailable);
        }
        Ok(())
    }

    async fn bind_sftp(
        &self,
        scope: &PathScope,
    ) -> Result<BoundSftpSession, EmergencyPathApiError> {
        let session = timeout(
            BIND_DEADLINE,
            self.services
                .sftp()
                .bind_session(scope.target.clone(), &scope.session_id),
        )
        .await
        .map_err(|_| EmergencyPathApiError::Deadline)?
        .map_err(|_| EmergencyPathApiError::BindingUnavailable)?;
        if session.session_id() != scope.session_id
            || session.connection_id() != scope.connection_id
        {
            return Err(EmergencyPathApiError::BindingUnavailable);
        }
        Ok(session)
    }

    fn lock_registry(&self) -> Result<MutexGuard<'_, PathRegistry>, EmergencyPathApiError> {
        self.registry
            .lock()
            .map_err(|_| EmergencyPathApiError::RegistryUnavailable)
    }
}

fn plan_dto(
    plan: &PlannedPath,
    now: Instant,
) -> Result<EmergencyPathPlanDto, EmergencyPathApiError> {
    let definition = plan.operation.definition();
    let remaining = plan.expires_at.saturating_duration_since(now).as_secs();
    Ok(EmergencyPathPlanDto {
        plan_handle: plan.plan_handle.clone(),
        path_handle: plan.path_handle.clone(),
        path: plan.path.clone(),
        action: plan.action.label().to_owned(),
        summary: bounded_text(&definition.summary),
        dangerous: definition.dangerous,
        restore_description: definition.restore_description.as_deref().map(bounded_text),
        state: match plan.operation.state() {
            OperationState::Planned => "planned".to_owned(),
            OperationState::Confirmed => "confirmed".to_owned(),
            _ => "spent".to_owned(),
        },
        expires_in_seconds: u32::try_from(remaining.max(1))
            .map_err(|_| EmergencyPathApiError::Core)?,
    })
}

/// Plan text is written by the core, but it still crosses a boundary: keep it
/// drawable in a dialog. A control character becomes a replacement character
/// rather than disappearing, so nothing the core said is silently dropped.
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

/// Whether a stored capability still belongs to the caller asking for it.
///
/// The binding, the session, the connection and the target generation all have
/// to be the ones it was minted under. A window that reconnected, or that is
/// now looking at a different host, is a different caller.
fn still_live(stored: &PathScope, expires_at: Instant, asking: &PathScope, now: Instant) -> bool {
    stored == asking && expires_at > now
}

fn validate_handle(handle: &str) -> Result<(), EmergencyPathApiError> {
    if handle.is_empty() || handle.len() > MAX_HANDLE_BYTES {
        return Err(EmergencyPathApiError::InvalidHandle);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use lovelyres_core::target::{TargetContext, TargetIdentity};

    use super::*;

    fn scope(binding: &str, identity: &str, generation: usize) -> PathScope {
        let target = TargetContext::new();
        let mut guard = target
            .activate(TargetIdentity::new(identity).unwrap())
            .unwrap();
        for _ in 0..generation {
            guard = target
                .activate(TargetIdentity::new(identity).unwrap())
                .unwrap();
        }
        PathScope {
            binding_handle: binding.to_owned(),
            session_id: format!("session-{identity}"),
            connection_id: identity.to_owned(),
            target: guard,
        }
    }

    fn offered(paths: &[&str]) -> Vec<(String, RemotePath)> {
        paths
            .iter()
            .enumerate()
            .map(|(index, path)| (format!("handle-{index}"), RemotePath::new(*path).unwrap()))
            .collect()
    }

    #[test]
    fn hands_back_only_the_paths_the_asking_binding_was_offered() {
        let mine = scope("binding-a", "target-a", 0);
        let theirs = scope("binding-b", "target-b", 0);
        let mut registry = PathRegistry::default();
        registry.replace_for_binding(&mine, offered(&["/tmp/.x", "/tmp/.y"]));

        let now = Instant::now();
        assert_eq!(
            registry.path(&mine, "handle-0", now).unwrap().as_str(),
            "/tmp/.x",
        );
        // Another binding cannot spend a capability it was never handed.
        assert!(matches!(
            registry.path(&theirs, "handle-0", now),
            Err(EmergencyPathApiError::PathStale),
        ));
        // Nor can a handle nobody was handed at all.
        assert!(matches!(
            registry.path(&mine, "handle-forged", now),
            Err(EmergencyPathApiError::PathStale),
        ));
    }

    #[test]
    fn refuses_a_capability_from_a_target_that_moved_on() {
        let before = scope("binding-a", "target-a", 0);
        let after = scope("binding-a", "target-a", 1);
        let mut registry = PathRegistry::default();
        registry.replace_for_binding(&before, offered(&["/tmp/.x"]));
        assert!(matches!(
            registry.path(&after, "handle-0", Instant::now()),
            Err(EmergencyPathApiError::PathStale),
        ));
    }

    #[test]
    fn a_fresh_run_replaces_what_the_previous_one_offered() {
        let scope = scope("binding-a", "target-a", 0);
        let mut registry = PathRegistry::default();
        registry.replace_for_binding(&scope, offered(&["/tmp/.x", "/tmp/.y"]));
        registry.replace_for_binding(&scope, offered(&["/tmp/.z"]));

        let now = Instant::now();
        assert_eq!(
            registry.path(&scope, "handle-0", now).unwrap().as_str(),
            "/tmp/.z",
        );
        // The second run offered one path, so the first run's second handle is
        // gone rather than left pointing at a line nobody is looking at.
        assert!(matches!(
            registry.path(&scope, "handle-1", now),
            Err(EmergencyPathApiError::PathStale),
        ));
        assert_eq!(registry.paths.len(), 1);
    }

    #[test]
    fn stops_offering_at_the_ceiling() {
        let scope = scope("binding-a", "target-a", 0);
        let mut registry = PathRegistry::default();
        let many: Vec<String> = (0..MAX_STORED_PATHS + 50)
            .map(|index| format!("/tmp/.f{index}"))
            .collect();
        let refs: Vec<&str> = many.iter().map(String::as_str).collect();
        registry.replace_for_binding(&scope, offered(&refs));
        assert_eq!(registry.paths.len(), MAX_STORED_PATHS);
    }

    #[test]
    fn an_expired_capability_names_nothing() {
        let scope = scope("binding-a", "target-a", 0);
        let mut registry = PathRegistry::default();
        registry.replace_for_binding(&scope, offered(&["/tmp/.x"]));
        let later = Instant::now() + PATH_TTL + Duration::from_secs(1);
        assert!(matches!(
            registry.path(&scope, "handle-0", later),
            Err(EmergencyPathApiError::PathStale),
        ));
        registry.prune(later);
        assert!(registry.paths.is_empty());
    }

    #[test]
    fn closing_a_binding_takes_its_capabilities_with_it() {
        let mine = scope("binding-a", "target-a", 0);
        let theirs = scope("binding-b", "target-b", 0);
        let mut registry = PathRegistry::default();
        registry.replace_for_binding(&mine, offered(&["/tmp/.x"]));
        registry.replace_for_binding(&theirs, offered(&["/tmp/.y"]));
        registry.close_binding("binding-a");

        let now = Instant::now();
        assert!(matches!(
            registry.path(&mine, "handle-0", now),
            Err(EmergencyPathApiError::PathStale),
        ));
        // A neighbouring window keeps working.
        assert_eq!(
            registry.path(&theirs, "handle-0", now).unwrap().as_str(),
            "/tmp/.y",
        );
    }

    #[test]
    fn a_capability_is_live_only_for_the_caller_it_was_minted_for() {
        // Plans are held under the same rule as paths, and a plan cannot be
        // built without a live session, so the rule itself is checked here.
        let mine = scope("binding-a", "target-a", 0);
        let now = Instant::now();
        let expires_at = now + PLAN_TTL;

        assert!(still_live(&mine, expires_at, &mine, now));
        // A different window, a reconnected session, and a target that was
        // reactivated under the same name are each a different caller.
        assert!(!still_live(
            &mine,
            expires_at,
            &scope("binding-b", "target-a", 0),
            now
        ));
        assert!(!still_live(
            &mine,
            expires_at,
            &scope("binding-a", "target-b", 0),
            now
        ));
        assert!(!still_live(
            &mine,
            expires_at,
            &scope("binding-a", "target-a", 1),
            now
        ));
        // And an expired capability is nobody's.
        assert!(!still_live(&mine, expires_at, &mine, expires_at));
        assert!(!still_live(
            &mine,
            expires_at,
            &mine,
            expires_at + Duration::from_secs(1)
        ));
    }

    #[test]
    fn disarming_clears_every_way_to_run_a_file_and_nothing_else() {
        // 4755 is the classic planted backdoor: runnable by anyone, and
        // running as root. What is left has to be neither.
        assert_eq!(0o4755 & !EXECUTE_BITS, 0o0644);
        assert_eq!(0o2755 & !EXECUTE_BITS, 0o0644);
        assert_eq!(0o0755 & !EXECUTE_BITS, 0o0644);
        // The sticky bit belongs to directories and means something else.
        assert_eq!(0o1777 & !EXECUTE_BITS, 0o1666);
        // Read and write are untouched, so the file can still be examined.
        assert_eq!(0o0700 & !EXECUTE_BITS, 0o0600);
    }
}
