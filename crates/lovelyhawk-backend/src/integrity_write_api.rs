//! Creating a file-integrity baseline: the one integrity action that writes.
//!
//! It is kept apart from the read-only comparison boundary in
//! `integrity_api.rs`, which stays free of anything that changes a target.
//! A baseline writes one manifest under the application's own directory on
//! the target (the files it records are only read), so the window asks first
//! and then follows the run through start, poll and cancel, never a single
//! call that could hold the main window's queue for minutes.

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use lovelyhawk_core::{
    BackendServices, integrity::INTEGRITY_PRESETS, ssh::BoundSshSession, target::TargetGuard,
};
use serde::Serialize;
use tokio::task::AbortHandle;
use uuid::Uuid;

use crate::{
    integrity_api::{INTEGRITY_PRESET_IDS, IntegrityApiError},
    ssh_api::SshApi,
};

const MAX_HANDLE_BYTES: usize = 128;
const MAX_CREATIONS: usize = 8;
const MAX_RUNNING_CREATIONS: usize = 4;
/// The core gives a baseline ten minutes; the record outlives it a little.
const RUNNING_TTL: Duration = Duration::from_secs(11 * 60);
const FINISHED_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Clone)]
pub(crate) struct IntegrityWriteApi {
    services: BackendServices,
    ssh_api: Arc<SshApi>,
    registry: Arc<Mutex<CreationRegistry>>,
}

impl fmt::Debug for IntegrityWriteApi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = self
            .registry
            .lock()
            .map(|registry| registry.creations.len())
            .unwrap_or_default();
        formatter
            .debug_struct("IntegrityWriteApi")
            .field("creation_count", &count)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
struct CreationScope {
    binding_handle: String,
    session_id: String,
    connection_id: String,
    target: TargetGuard,
}

impl CreationScope {
    fn from_session(binding_handle: &str, session: &BoundSshSession) -> Self {
        Self {
            binding_handle: binding_handle.to_owned(),
            session_id: session.session_id().to_owned(),
            connection_id: session.connection_id().to_owned(),
            target: session.target().clone(),
        }
    }
}

enum CreationState {
    Running,
    Completed {
        file_count: usize,
        path_count: usize,
    },
    Failed,
    Cancelled,
}

struct Creation {
    scope: CreationScope,
    state: CreationState,
    abort: Option<AbortHandle>,
    expires_at: Instant,
}

#[derive(Default)]
struct CreationRegistry {
    creations: HashMap<String, Creation>,
}

impl CreationRegistry {
    fn prune(&mut self, now: Instant) {
        self.creations.retain(|_, creation| {
            if creation.expires_at > now {
                return true;
            }
            if let Some(abort) = creation.abort.take() {
                abort.abort();
            }
            false
        });
    }

    /// One creation per target at a time, and a few in all.
    fn begin(&mut self, scope: CreationScope, now: Instant) -> Result<String, IntegrityApiError> {
        let running = |creation: &&Creation| matches!(creation.state, CreationState::Running);
        if self
            .creations
            .values()
            .filter(running)
            .any(|creation| creation.scope.binding_handle == scope.binding_handle)
            || self.creations.values().filter(running).count() >= MAX_RUNNING_CREATIONS
        {
            return Err(IntegrityApiError::Capacity);
        }
        if self.creations.len() >= MAX_CREATIONS {
            let oldest = self
                .creations
                .iter()
                .filter(|(_, creation)| !matches!(creation.state, CreationState::Running))
                .min_by_key(|(_, creation)| creation.expires_at)
                .map(|(handle, _)| handle.clone())
                .ok_or(IntegrityApiError::Capacity)?;
            self.creations.remove(&oldest);
        }
        let handle = Uuid::new_v4().to_string();
        self.creations.insert(
            handle.clone(),
            Creation {
                scope,
                state: CreationState::Running,
                abort: None,
                expires_at: now + RUNNING_TTL,
            },
        );
        Ok(handle)
    }

    fn scoped(
        &mut self,
        scope: &CreationScope,
        handle: &str,
    ) -> Result<&mut Creation, IntegrityApiError> {
        self.creations
            .get_mut(handle)
            .filter(|creation| &creation.scope == scope)
            .ok_or(IntegrityApiError::OperationUnavailable)
    }

    /// A result arriving for a creation that was cancelled, closed or
    /// replaced changes nothing.
    fn finish(&mut self, scope: &CreationScope, handle: &str, state: CreationState, now: Instant) {
        if let Ok(creation) = self.scoped(scope, handle)
            && matches!(creation.state, CreationState::Running)
        {
            creation.state = state;
            creation.abort = None;
            creation.expires_at = now + FINISHED_TTL;
        }
    }

    fn close_binding(&mut self, binding_handle: &str) {
        self.creations.retain(|_, creation| {
            if creation.scope.binding_handle != binding_handle {
                return true;
            }
            if let Some(abort) = creation.abort.take() {
                abort.abort();
            }
            false
        });
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IntegrityCreationStartedDto {
    operation_handle: String,
    expires_in_seconds: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IntegrityCreationPollDto {
    operation_handle: String,
    stage: &'static str,
    /// How many files the new baseline records, once it is complete.
    file_count: Option<usize>,
    /// How many of the chosen locations it covers.
    path_count: Option<usize>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IntegrityCreationCancellationDto {
    cancelled: bool,
}

impl IntegrityWriteApi {
    pub(crate) fn new(services: BackendServices, ssh_api: Arc<SshApi>) -> Self {
        Self {
            services,
            ssh_api,
            registry: Arc::new(Mutex::new(CreationRegistry::default())),
        }
    }

    pub(crate) fn close_binding(&self, binding_handle: &str) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.close_binding(binding_handle);
        }
    }

    /// Starts recording the chosen preset locations. Only preset ids are
    /// accepted: the window names a location from the fixed list, never a
    /// path of its own.
    pub(crate) fn start_creation(
        self: &Arc<Self>,
        binding_handle: &str,
        preset_ids: &[String],
    ) -> Result<IntegrityCreationStartedDto, IntegrityApiError> {
        let paths = preset_paths(preset_ids)?;
        let (session, scope) = self.capture_binding(binding_handle)?;
        let handle = {
            let now = Instant::now();
            let mut registry = self.lock_registry()?;
            registry.prune(now);
            registry.begin(scope.clone(), now)?
        };
        let api = Arc::clone(self);
        let task_scope = scope.clone();
        let task_handle = handle.clone();
        let task = tokio::spawn(async move {
            let path_count = paths.len();
            let result = api
                .services
                .integrity()
                .create_baseline(&session, paths)
                .await;
            let still_bound = api.validate_binding(&task_scope).is_ok();
            let state = match result {
                Ok(baseline) if still_bound => CreationState::Completed {
                    file_count: baseline.file_count,
                    path_count,
                },
                Ok(_) => CreationState::Failed,
                Err(error) => {
                    tracing::warn!(
                        error = %IntegrityApiError::Core(error),
                        "integrity baseline creation failed"
                    );
                    CreationState::Failed
                }
            };
            if let Ok(mut registry) = api.registry.lock() {
                registry.finish(&task_scope, &task_handle, state, Instant::now());
            }
        });
        let attached = self
            .lock_registry()
            .map(|mut registry| match registry.scoped(&scope, &handle) {
                Ok(creation) if matches!(creation.state, CreationState::Running) => {
                    creation.abort = Some(task.abort_handle());
                    true
                }
                _ => false,
            })
            .unwrap_or(false);
        if !attached {
            task.abort();
            return Err(IntegrityApiError::OperationUnavailable);
        }
        Ok(IntegrityCreationStartedDto {
            operation_handle: handle,
            expires_in_seconds: RUNNING_TTL.as_secs(),
        })
    }

    pub(crate) fn poll_creation(
        &self,
        binding_handle: &str,
        operation_handle: &str,
    ) -> Result<IntegrityCreationPollDto, IntegrityApiError> {
        validate_handle(operation_handle)?;
        let (_, scope) = self.capture_binding(binding_handle)?;
        let mut registry = self.lock_registry()?;
        registry.prune(Instant::now());
        let creation = registry.scoped(&scope, operation_handle)?;
        let (stage, file_count, path_count) = match creation.state {
            CreationState::Running => ("running", None, None),
            CreationState::Completed {
                file_count,
                path_count,
            } => ("completed", Some(file_count), Some(path_count)),
            CreationState::Failed => ("failed", None, None),
            CreationState::Cancelled => ("cancelled", None, None),
        };
        Ok(IntegrityCreationPollDto {
            operation_handle: operation_handle.to_owned(),
            stage,
            file_count,
            path_count,
        })
    }

    /// Stops a creation that is still running. One that already finished
    /// keeps its result: the baseline exists and stays listed.
    pub(crate) fn cancel_creation(
        &self,
        binding_handle: &str,
        operation_handle: &str,
    ) -> Result<IntegrityCreationCancellationDto, IntegrityApiError> {
        validate_handle(operation_handle)?;
        let (_, scope) = self.capture_binding(binding_handle)?;
        let mut registry = self.lock_registry()?;
        let creation = registry.scoped(&scope, operation_handle)?;
        let cancelled = matches!(creation.state, CreationState::Running);
        if cancelled {
            if let Some(abort) = creation.abort.take() {
                abort.abort();
            }
            creation.state = CreationState::Cancelled;
            creation.expires_at = Instant::now() + FINISHED_TTL;
        }
        Ok(IntegrityCreationCancellationDto { cancelled })
    }

    fn capture_binding(
        &self,
        binding_handle: &str,
    ) -> Result<(BoundSshSession, CreationScope), IntegrityApiError> {
        validate_handle(binding_handle)?;
        let session = self
            .ssh_api
            .binding_session_clone(binding_handle)
            .map_err(|_| IntegrityApiError::BindingUnavailable)?;
        self.services
            .target()
            .validate(session.target())
            .map_err(|_| IntegrityApiError::BindingUnavailable)?;
        let scope = CreationScope::from_session(binding_handle, &session);
        Ok((session, scope))
    }

    fn validate_binding(&self, expected: &CreationScope) -> Result<(), IntegrityApiError> {
        let (_, current) = self.capture_binding(&expected.binding_handle)?;
        if &current != expected {
            return Err(IntegrityApiError::BindingUnavailable);
        }
        Ok(())
    }

    fn lock_registry(&self) -> Result<MutexGuard<'_, CreationRegistry>, IntegrityApiError> {
        self.registry
            .lock()
            .map_err(|_| IntegrityApiError::RegistryUnavailable)
    }
}

/// The preset locations, from their ids, in the catalogue's order. An unknown,
/// repeated or missing id refuses the whole request.
fn preset_paths(preset_ids: &[String]) -> Result<Vec<String>, IntegrityApiError> {
    if preset_ids.is_empty() || preset_ids.len() > INTEGRITY_PRESET_IDS.len() {
        return Err(IntegrityApiError::InvalidBounds);
    }
    let mut chosen = [false; INTEGRITY_PRESETS.len()];
    for id in preset_ids {
        let index = INTEGRITY_PRESET_IDS
            .iter()
            .position(|known| known == id)
            .ok_or(IntegrityApiError::InvalidBounds)?;
        if std::mem::replace(&mut chosen[index], true) {
            return Err(IntegrityApiError::InvalidBounds);
        }
    }
    Ok(INTEGRITY_PRESETS
        .iter()
        .zip(chosen)
        .filter(|(_, chosen)| *chosen)
        .map(|((_, path, _), _)| (*path).to_owned())
        .collect())
}

fn validate_handle(value: &str) -> Result<(), IntegrityApiError> {
    if value.is_empty()
        || value.len() > MAX_HANDLE_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(IntegrityApiError::InvalidHandle);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use lovelyhawk_core::target::{TargetContext, TargetIdentity};

    use super::*;

    fn scope(binding: &str) -> CreationScope {
        let context = TargetContext::new();
        CreationScope {
            binding_handle: binding.to_owned(),
            session_id: format!("{binding}-session"),
            connection_id: format!("{binding}-connection"),
            target: context
                .activate(TargetIdentity::new(format!("{binding}-target")).unwrap())
                .unwrap(),
        }
    }

    #[test]
    fn only_preset_ids_choose_what_is_recorded() {
        let ids = |values: &[&str]| {
            values
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>()
        };
        let chosen = preset_paths(&ids(&["etc", "web-root"])).unwrap();
        // The catalogue's order, whatever order they were asked in.
        let expected: Vec<String> = INTEGRITY_PRESETS
            .iter()
            .zip(INTEGRITY_PRESET_IDS)
            .filter(|(_, id)| *id == "etc" || *id == "web-root")
            .map(|((_, path, _), _)| (*path).to_owned())
            .collect();
        assert_eq!(chosen, expected);
        for refused in [
            ids(&[]),
            ids(&["/etc"]),
            ids(&["etc", "etc"]),
            ids(&["etc; rm -rf /"]),
            ids(&[
                "web-root",
                "usr-bin",
                "usr-sbin",
                "bin",
                "etc",
                "usr-local-bin",
                "etc",
            ]),
        ] {
            assert!(
                matches!(
                    preset_paths(&refused),
                    Err(IntegrityApiError::InvalidBounds)
                ),
                "{refused:?}"
            );
        }
    }

    #[test]
    fn one_creation_per_target_and_late_results_change_nothing() {
        let now = Instant::now();
        let mut registry = CreationRegistry::default();
        let mine = scope("binding-one");
        let first = registry.begin(mine.clone(), now).unwrap();
        // A second while the first runs is refused for this target only.
        assert!(matches!(
            registry.begin(mine.clone(), now),
            Err(IntegrityApiError::Capacity)
        ));
        let other = scope("binding-two");
        let theirs = registry.begin(other.clone(), now).unwrap();
        // Another target cannot read or finish this one.
        assert!(registry.scoped(&other, &first).is_err());
        registry.finish(
            &other,
            &first,
            CreationState::Completed {
                file_count: 9,
                path_count: 1,
            },
            now,
        );
        assert!(matches!(
            registry.scoped(&mine, &first).unwrap().state,
            CreationState::Running
        ));
        // Cancelled first, then the result arrives: it stays cancelled.
        registry.scoped(&mine, &first).unwrap().state = CreationState::Cancelled;
        registry.finish(
            &mine,
            &first,
            CreationState::Completed {
                file_count: 9,
                path_count: 1,
            },
            now,
        );
        assert!(matches!(
            registry.scoped(&mine, &first).unwrap().state,
            CreationState::Cancelled
        ));
        // Closing a binding takes its creations with it.
        registry.close_binding("binding-two");
        assert!(registry.scoped(&other, &theirs).is_err());
        assert!(registry.scoped(&mine, &first).is_ok());
    }
}
