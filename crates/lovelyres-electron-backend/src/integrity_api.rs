//! Read-only, target-bound Electron boundary for file-integrity comparison.
//!
//! Phase 0 intentionally excludes baseline creation and quarantine because both
//! persist remote changes. The renderer can only list existing baselines and
//! start, poll, or cancel a comparison through opaque capabilities.

use std::{
    collections::{HashMap, VecDeque},
    fmt,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use lovelyres_core::{
    BackendServices, CoreError,
    integrity::{
        INTEGRITY_PRESETS, IntegrityBaseline, IntegrityDiff, IntegrityDiffKind, IntegritySeverity,
    },
    ssh::BoundSshSession,
    target::TargetGuard,
};
use serde::Serialize;
use tokio::task::AbortHandle;
use uuid::Uuid;

use crate::ssh_api::SshApi;

const MAX_HANDLE_BYTES: usize = 128;
const MAX_PRESETS: usize = 6;
const MAX_BASELINES_PER_LIST: usize = 64;
const MAX_BASELINE_HANDLES: usize = 128;
const MAX_BASELINE_PATHS: usize = 16;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_BASELINE_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_DIFF_ENTRIES: usize = 500;
const MAX_DIFF_TOTAL_ENTRIES: usize = 5_000;
const MAX_DIFF_PATH_BYTES: usize = 256 * 1024;
const MAX_COMPARISON_BYTES: usize = 768 * 1024;
const MAX_OPERATIONS: usize = 16;
const MAX_ACTIVE_OPERATIONS: usize = 4;
const MAX_ACTIVE_OPERATIONS_PER_BINDING: usize = 1;
const MAX_OPERATION_REGISTRY_BYTES: usize = 8 * 1024 * 1024;
const MAX_OPERATION_EVENTS: usize = 8;
const MAX_POLL_EVENTS: usize = 8;
const MAX_PUBLIC_U64: u64 = 9_007_199_254_740_991;
const BASELINE_HANDLE_TTL: Duration = Duration::from_secs(10 * 60);
const RUNNING_OPERATION_TTL: Duration = Duration::from_secs(5 * 60);
const TERMINAL_OPERATION_TTL: Duration = Duration::from_secs(5 * 60);
const REDACTED_INTEGRITY_PATH: &str = "[SENSITIVE INTEGRITY PATH REDACTED]";

const PRESET_IDS: [&str; MAX_PRESETS] = [
    "web-root",
    "usr-bin",
    "usr-sbin",
    "bin",
    "etc",
    "usr-local-bin",
];

#[derive(Clone)]
pub(crate) struct IntegrityApi {
    services: BackendServices,
    ssh_api: Arc<SshApi>,
    registry: Arc<Mutex<Registry>>,
}

impl fmt::Debug for IntegrityApi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (baselines, operations, active, bytes) = self
            .registry
            .lock()
            .map(|registry| {
                (
                    registry.baselines.len(),
                    registry.operations.len(),
                    registry.active_operations(),
                    registry.operation_bytes,
                )
            })
            .unwrap_or_default();
        formatter
            .debug_struct("IntegrityApi")
            .field("baseline_handle_count", &baselines)
            .field("operation_count", &operations)
            .field("active_operation_count", &active)
            .field("operation_bytes", &bytes)
            .finish()
    }
}

impl IntegrityApi {
    pub(crate) fn new(services: BackendServices, ssh_api: Arc<SshApi>) -> Self {
        Self {
            services,
            ssh_api,
            registry: Arc::new(Mutex::new(Registry::default())),
        }
    }

    pub(crate) fn close_binding(&self, binding_handle: &str) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.close_binding(binding_handle);
        }
    }

    pub(crate) fn catalog() -> IntegrityPresetCatalogDto {
        IntegrityPresetCatalogDto {
            presets: INTEGRITY_PRESETS
                .iter()
                .enumerate()
                .map(
                    |(index, (label, path, default_selected))| IntegrityPresetDto {
                        id: PRESET_IDS[index],
                        label,
                        path,
                        default_selected: *default_selected,
                    },
                )
                .collect(),
            maximum_selected: MAX_PRESETS,
        }
    }

    pub(crate) fn list_baselines(
        &self,
        binding_handle: &str,
    ) -> Result<IntegrityBaselineListDto, IntegrityApiError> {
        let (_, scope) = self.capture_binding(binding_handle)?;
        let baselines = self.services.integrity().list(&scope.target)?;
        self.validate_binding(&scope)?;
        let mut registry = self.lock_registry()?;
        let now = Instant::now();
        registry.prune(now);
        registry.register_baseline_list(scope, baselines, now)
    }

    pub(crate) fn start_comparison(
        self: &Arc<Self>,
        binding_handle: &str,
        baseline_handle: &str,
    ) -> Result<IntegrityComparisonStartedDto, IntegrityApiError> {
        validate_handle(baseline_handle)?;
        let (session, scope) = self.capture_binding(binding_handle)?;
        let (operation_handle, core_baseline_id) = {
            let mut registry = self.lock_registry()?;
            let now = Instant::now();
            registry.prune(now);
            let core_baseline_id = registry.resolve_baseline(&scope, baseline_handle, now)?;
            let operation_handle = registry.begin_operation(
                scope.clone(),
                baseline_handle.to_owned(),
                core_baseline_id.clone(),
                now,
            )?;
            (operation_handle, core_baseline_id)
        };
        if let Err(error) = self.validate_binding(&scope) {
            self.remove_operation(&scope, &operation_handle);
            return Err(error);
        }

        let task_api = Arc::clone(self);
        let task_scope = scope.clone();
        let task_operation = operation_handle.clone();
        let task_baseline = baseline_handle.to_owned();
        let task = tokio::spawn(async move {
            task_api
                .run_comparison(
                    session,
                    task_scope,
                    task_operation,
                    task_baseline,
                    core_baseline_id,
                )
                .await;
        });
        let abort = task.abort_handle();
        let attached = self
            .lock_registry()
            .map(|mut registry| registry.attach_abort(&scope, &operation_handle, abort))
            .unwrap_or(false);
        if !attached {
            task.abort();
            return Err(IntegrityApiError::OperationUnavailable);
        }

        Ok(IntegrityComparisonStartedDto {
            operation_handle,
            baseline_handle: baseline_handle.to_owned(),
            stage: "running",
            expires_in_seconds: RUNNING_OPERATION_TTL.as_secs(),
        })
    }

    pub(crate) fn poll_comparison(
        &self,
        binding_handle: &str,
        operation_handle: &str,
        after_event: u64,
        limit: usize,
    ) -> Result<IntegrityComparisonPollDto, IntegrityApiError> {
        validate_handle(operation_handle)?;
        if after_event > MAX_PUBLIC_U64 || limit == 0 || limit > MAX_POLL_EVENTS {
            return Err(IntegrityApiError::InvalidBounds);
        }
        let (_, scope) = self.capture_binding(binding_handle)?;
        let result = {
            let mut registry = self.lock_registry()?;
            registry.prune(Instant::now());
            registry.poll(&scope, operation_handle, after_event, limit)?
        };
        self.validate_binding(&scope)?;
        Ok(result)
    }

    pub(crate) fn cancel_comparison(
        &self,
        binding_handle: &str,
        operation_handle: &str,
    ) -> Result<IntegrityComparisonCancellationDto, IntegrityApiError> {
        validate_handle(operation_handle)?;
        let (_, scope) = self.capture_binding(binding_handle)?;
        {
            let mut registry = self.lock_registry()?;
            registry.prune(Instant::now());
            registry.cancel(&scope, operation_handle, Instant::now())?;
        }
        self.validate_binding(&scope)?;
        Ok(IntegrityComparisonCancellationDto { cancelled: true })
    }

    async fn run_comparison(
        self: Arc<Self>,
        session: BoundSshSession,
        scope: BindingScope,
        operation_handle: String,
        baseline_handle: String,
        core_baseline_id: String,
    ) {
        let result = self
            .services
            .integrity()
            .compare(&session, &core_baseline_id)
            .await;
        match result {
            Ok(diff) => {
                if self.validate_binding(&scope).is_err() {
                    self.close_scope(&scope);
                    return;
                }
                let result = self.lock_registry().and_then(|mut registry| {
                    registry.prune(Instant::now());
                    registry.finish_success(
                        &scope,
                        &operation_handle,
                        &baseline_handle,
                        &core_baseline_id,
                        diff,
                        Instant::now(),
                    )
                });
                if let Err(error) = result {
                    tracing::warn!(error = %error, "integrity comparison result was rejected");
                    self.finish_failed(&scope, &operation_handle, "comparison-rejected");
                }
            }
            Err(error) => {
                tracing::warn!(
                    error = %IntegrityApiError::Core(error),
                    "integrity comparison failed"
                );
                if self.validate_binding(&scope).is_err() {
                    self.close_scope(&scope);
                } else {
                    self.finish_failed(&scope, &operation_handle, "comparison-failed");
                }
            }
        }
    }

    fn finish_failed(&self, scope: &BindingScope, operation_handle: &str, code: &'static str) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.finish_failed(scope, operation_handle, code, Instant::now());
        }
    }

    fn close_scope(&self, scope: &BindingScope) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.close_scope(scope);
        }
    }

    fn remove_operation(&self, scope: &BindingScope, operation_handle: &str) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.remove_scoped_operation(scope, operation_handle);
        }
    }

    fn capture_binding(
        &self,
        binding_handle: &str,
    ) -> Result<(BoundSshSession, BindingScope), IntegrityApiError> {
        validate_handle(binding_handle)?;
        let session = self
            .ssh_api
            .binding_session_clone(binding_handle)
            .map_err(|_| IntegrityApiError::BindingUnavailable)?;
        self.services
            .target()
            .validate(session.target())
            .map_err(|_| IntegrityApiError::BindingUnavailable)?;
        let scope = BindingScope::from_session(binding_handle, &session);
        Ok((session, scope))
    }

    fn validate_binding(
        &self,
        expected: &BindingScope,
    ) -> Result<BoundSshSession, IntegrityApiError> {
        let (session, current) = self.capture_binding(&expected.binding_handle)?;
        if &current != expected {
            return Err(IntegrityApiError::BindingUnavailable);
        }
        Ok(session)
    }

    fn lock_registry(&self) -> Result<MutexGuard<'_, Registry>, IntegrityApiError> {
        self.registry
            .lock()
            .map_err(|_| IntegrityApiError::RegistryUnavailable)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IntegrityPresetCatalogDto {
    presets: Vec<IntegrityPresetDto>,
    maximum_selected: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IntegrityPresetDto {
    id: &'static str,
    label: &'static str,
    path: &'static str,
    default_selected: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IntegrityBaselineDto {
    baseline_handle: String,
    created_at: String,
    paths: Vec<String>,
    paths_truncated: bool,
    redacted_path_count: usize,
    text_projected: bool,
    file_count: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IntegrityBaselineListDto {
    items: Vec<IntegrityBaselineDto>,
    truncated: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IntegrityComparisonDto {
    baseline_handle: String,
    added: usize,
    removed: usize,
    modified: usize,
    displayed: usize,
    redacted_path_count: usize,
    text_projected: bool,
    truncated: bool,
    entries: Vec<IntegrityFindingDto>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct IntegrityFindingDto {
    path: String,
    path_redacted: bool,
    path_truncated: bool,
    path_projected: bool,
    kind: &'static str,
    severity: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IntegrityComparisonStartedDto {
    operation_handle: String,
    baseline_handle: String,
    stage: &'static str,
    expires_in_seconds: u64,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct IntegrityOperationEventDto {
    sequence: u64,
    kind: &'static str,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IntegrityComparisonPollDto {
    operation_handle: String,
    baseline_handle: String,
    stage: &'static str,
    events: Vec<IntegrityOperationEventDto>,
    next_event_cursor: u64,
    events_truncated: bool,
    comparison: Option<IntegrityComparisonDto>,
    error_code: Option<&'static str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IntegrityComparisonCancellationDto {
    cancelled: bool,
}

pub(crate) enum IntegrityApiError {
    Core(CoreError),
    BindingUnavailable,
    InvalidHandle,
    InvalidBounds,
    BaselineUnavailable,
    OperationUnavailable,
    ComparisonUnavailable,
    Capacity,
    RegistryUnavailable,
}

impl fmt::Debug for IntegrityApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core(_) => "Core([REDACTED])",
            Self::BindingUnavailable => "BindingUnavailable",
            Self::InvalidHandle => "InvalidHandle",
            Self::InvalidBounds => "InvalidBounds",
            Self::BaselineUnavailable => "BaselineUnavailable",
            Self::OperationUnavailable => "OperationUnavailable",
            Self::ComparisonUnavailable => "ComparisonUnavailable",
            Self::Capacity => "Capacity",
            Self::RegistryUnavailable => "RegistryUnavailable",
        })
    }
}

impl fmt::Display for IntegrityApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core(_) => "the integrity operation failed",
            Self::BindingUnavailable => "the SSH binding is missing or stale",
            Self::InvalidHandle => "the integrity capability is invalid",
            Self::InvalidBounds => "the integrity request bounds are invalid",
            Self::BaselineUnavailable => "the integrity baseline is missing or stale",
            Self::OperationUnavailable => "the integrity comparison is missing or stale",
            Self::ComparisonUnavailable => "the integrity comparison result was rejected",
            Self::Capacity => "the integrity capability registry is full",
            Self::RegistryUnavailable => "the integrity capability registry is unavailable",
        })
    }
}

impl std::error::Error for IntegrityApiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Core(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CoreError> for IntegrityApiError {
    fn from(error: CoreError) -> Self {
        Self::Core(error)
    }
}

#[derive(Clone, Eq, PartialEq)]
struct BindingScope {
    binding_handle: String,
    session_id: String,
    connection_id: String,
    target: TargetGuard,
}

impl BindingScope {
    fn from_session(binding_handle: &str, session: &BoundSshSession) -> Self {
        Self {
            binding_handle: binding_handle.to_owned(),
            session_id: session.session_id().to_owned(),
            connection_id: session.connection_id().to_owned(),
            target: session.target().clone(),
        }
    }

    fn sensitive_literals(&self) -> [&str; 4] {
        [
            &self.binding_handle,
            &self.session_id,
            &self.connection_id,
            self.target.identity.as_str(),
        ]
    }
}

impl fmt::Debug for BindingScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BindingScope([REDACTED])")
    }
}

#[derive(Default)]
struct Registry {
    baselines: HashMap<String, BaselineEntry>,
    operations: HashMap<String, OperationEntry>,
    operation_bytes: usize,
}

impl fmt::Debug for Registry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IntegrityRegistry")
            .field("baseline_handle_count", &self.baselines.len())
            .field("operation_count", &self.operations.len())
            .field("active_operation_count", &self.active_operations())
            .field("operation_bytes", &self.operation_bytes)
            .finish()
    }
}

struct BaselineEntry {
    scope: BindingScope,
    core_id: String,
    expires_at: Instant,
    touched_at: Instant,
}

struct OperationEntry {
    scope: BindingScope,
    baseline_handle: String,
    core_baseline_id: String,
    state: OperationState,
    abort: Option<AbortHandle>,
    events: VecDeque<IntegrityOperationEventDto>,
    next_sequence: u64,
    bytes: usize,
    expires_at: Instant,
    touched_at: Instant,
}

enum OperationState {
    Running,
    Completed(IntegrityComparisonDto),
    Cancelled,
    Failed { code: &'static str },
}

impl Registry {
    fn prune(&mut self, now: Instant) {
        self.baselines.retain(|_, entry| entry.expires_at > now);
        let expired = self
            .operations
            .iter()
            .filter_map(|(handle, entry)| (entry.expires_at <= now).then_some(handle.clone()))
            .collect::<Vec<_>>();
        for handle in expired {
            self.remove_operation(&handle);
        }
    }

    fn active_operations(&self) -> usize {
        self.operations
            .values()
            .filter(|entry| matches!(entry.state, OperationState::Running))
            .count()
    }

    fn active_operations_for_binding(&self, binding_handle: &str) -> usize {
        self.operations
            .values()
            .filter(|entry| {
                entry.scope.binding_handle == binding_handle
                    && matches!(entry.state, OperationState::Running)
            })
            .count()
    }

    fn close_binding(&mut self, binding_handle: &str) {
        self.baselines
            .retain(|_, entry| entry.scope.binding_handle != binding_handle);
        let operations = self
            .operations
            .iter()
            .filter_map(|(handle, entry)| {
                (entry.scope.binding_handle == binding_handle).then_some(handle.clone())
            })
            .collect::<Vec<_>>();
        for handle in operations {
            self.remove_operation(&handle);
        }
    }

    fn close_scope(&mut self, scope: &BindingScope) {
        self.baselines.retain(|_, entry| &entry.scope != scope);
        let operations = self
            .operations
            .iter()
            .filter_map(|(handle, entry)| (&entry.scope == scope).then_some(handle.clone()))
            .collect::<Vec<_>>();
        for handle in operations {
            self.remove_operation(&handle);
        }
    }

    fn register_baseline_list(
        &mut self,
        scope: BindingScope,
        baselines: Vec<IntegrityBaseline>,
        now: Instant,
    ) -> Result<IntegrityBaselineListDto, IntegrityApiError> {
        let total = baselines.len();
        let mut items = Vec::new();
        let mut response_bytes = 0usize;
        for baseline in baselines.into_iter().take(MAX_BASELINES_PER_LIST) {
            let dto = self.register_baseline(scope.clone(), baseline, now)?;
            let bytes = serde_json::to_vec(&dto)
                .map_err(|_| IntegrityApiError::BaselineUnavailable)?
                .len();
            if response_bytes.saturating_add(bytes) > MAX_BASELINE_RESPONSE_BYTES {
                break;
            }
            response_bytes = response_bytes.saturating_add(bytes);
            items.push(dto);
        }
        let truncated = items.len() < total;
        Ok(IntegrityBaselineListDto { items, truncated })
    }

    fn register_baseline(
        &mut self,
        scope: BindingScope,
        baseline: IntegrityBaseline,
        now: Instant,
    ) -> Result<IntegrityBaselineDto, IntegrityApiError> {
        if baseline.target != scope.target.identity
            || baseline.paths.len() > MAX_BASELINE_PATHS
            || baseline.file_count as u128 > MAX_PUBLIC_U64 as u128
        {
            return Err(IntegrityApiError::BaselineUnavailable);
        }
        let projected = project_paths(&baseline.paths, &scope.sensitive_literals());
        let handle = if let Some((handle, entry)) = self
            .baselines
            .iter_mut()
            .find(|(_, entry)| entry.scope == scope && entry.core_id == baseline.id)
        {
            entry.expires_at = now + BASELINE_HANDLE_TTL;
            entry.touched_at = now;
            handle.clone()
        } else {
            while self.baselines.len() >= MAX_BASELINE_HANDLES {
                let Some(oldest) = self
                    .baselines
                    .iter()
                    .min_by_key(|(_, entry)| entry.touched_at)
                    .map(|(handle, _)| handle.clone())
                else {
                    break;
                };
                self.baselines.remove(&oldest);
            }
            if self.baselines.len() >= MAX_BASELINE_HANDLES {
                return Err(IntegrityApiError::Capacity);
            }
            let handle = unique_handle(&self.baselines)?;
            self.baselines.insert(
                handle.clone(),
                BaselineEntry {
                    scope,
                    core_id: baseline.id,
                    expires_at: now + BASELINE_HANDLE_TTL,
                    touched_at: now,
                },
            );
            handle
        };
        Ok(IntegrityBaselineDto {
            baseline_handle: handle,
            created_at: baseline.created_at.to_rfc3339(),
            paths: projected.values,
            paths_truncated: projected.truncated,
            redacted_path_count: projected.redacted_count,
            text_projected: projected.text_projected,
            file_count: baseline.file_count,
        })
    }

    fn resolve_baseline(
        &mut self,
        scope: &BindingScope,
        handle: &str,
        now: Instant,
    ) -> Result<String, IntegrityApiError> {
        let entry = self
            .baselines
            .get_mut(handle)
            .filter(|entry| &entry.scope == scope && entry.expires_at > now)
            .ok_or(IntegrityApiError::BaselineUnavailable)?;
        entry.expires_at = now + BASELINE_HANDLE_TTL;
        entry.touched_at = now;
        Ok(entry.core_id.clone())
    }

    fn begin_operation(
        &mut self,
        scope: BindingScope,
        baseline_handle: String,
        core_baseline_id: String,
        now: Instant,
    ) -> Result<String, IntegrityApiError> {
        if self.active_operations() >= MAX_ACTIVE_OPERATIONS
            || self.active_operations_for_binding(&scope.binding_handle)
                >= MAX_ACTIVE_OPERATIONS_PER_BINDING
        {
            return Err(IntegrityApiError::Capacity);
        }
        while self.operations.len() >= MAX_OPERATIONS {
            let Some(oldest) = self
                .operations
                .iter()
                .filter(|(_, entry)| !matches!(entry.state, OperationState::Running))
                .min_by_key(|(_, entry)| entry.touched_at)
                .map(|(handle, _)| handle.clone())
            else {
                return Err(IntegrityApiError::Capacity);
            };
            self.remove_operation(&oldest);
        }
        let handle = unique_handle(&self.operations)?;
        let mut entry = OperationEntry {
            scope,
            baseline_handle,
            core_baseline_id,
            state: OperationState::Running,
            abort: None,
            events: VecDeque::new(),
            next_sequence: 0,
            bytes: 0,
            expires_at: now + RUNNING_OPERATION_TTL,
            touched_at: now,
        };
        push_event(&mut entry, "started");
        self.operations.insert(handle.clone(), entry);
        Ok(handle)
    }

    fn attach_abort(
        &mut self,
        scope: &BindingScope,
        operation_handle: &str,
        abort: AbortHandle,
    ) -> bool {
        let Some(operation) = self
            .operations
            .get_mut(operation_handle)
            .filter(|entry| &entry.scope == scope)
        else {
            return false;
        };
        if matches!(operation.state, OperationState::Running) {
            operation.abort = Some(abort);
        }
        true
    }

    fn finish_success(
        &mut self,
        scope: &BindingScope,
        operation_handle: &str,
        baseline_handle: &str,
        core_baseline_id: &str,
        diff: IntegrityDiff,
        now: Instant,
    ) -> Result<(), IntegrityApiError> {
        let operation = self
            .operations
            .get(operation_handle)
            .filter(|entry| {
                &entry.scope == scope
                    && entry.baseline_handle == baseline_handle
                    && entry.core_baseline_id == core_baseline_id
                    && matches!(entry.state, OperationState::Running)
            })
            .ok_or(IntegrityApiError::OperationUnavailable)?;
        if diff.baseline_id != operation.core_baseline_id {
            return Err(IntegrityApiError::ComparisonUnavailable);
        }
        let dto = project_comparison(
            baseline_handle.to_owned(),
            diff,
            &scope.sensitive_literals(),
        )?;
        let bytes = serde_json::to_vec(&dto)
            .map_err(|_| IntegrityApiError::ComparisonUnavailable)?
            .len();
        if bytes > MAX_COMPARISON_BYTES {
            return Err(IntegrityApiError::ComparisonUnavailable);
        }
        while self.operation_bytes.saturating_add(bytes) > MAX_OPERATION_REGISTRY_BYTES {
            let Some(oldest) = self
                .operations
                .iter()
                .filter(|(handle, entry)| {
                    handle.as_str() != operation_handle
                        && !matches!(entry.state, OperationState::Running)
                })
                .min_by_key(|(_, entry)| entry.touched_at)
                .map(|(handle, _)| handle.clone())
            else {
                return Err(IntegrityApiError::Capacity);
            };
            self.remove_operation(&oldest);
        }
        let operation = self
            .operations
            .get_mut(operation_handle)
            .filter(|entry| &entry.scope == scope && matches!(entry.state, OperationState::Running))
            .ok_or(IntegrityApiError::OperationUnavailable)?;
        operation.abort = None;
        operation.bytes = bytes;
        operation.state = OperationState::Completed(dto);
        operation.expires_at = now + TERMINAL_OPERATION_TTL;
        operation.touched_at = now;
        push_event(operation, "completed");
        self.operation_bytes = self.operation_bytes.saturating_add(bytes);
        Ok(())
    }

    fn finish_failed(
        &mut self,
        scope: &BindingScope,
        operation_handle: &str,
        code: &'static str,
        now: Instant,
    ) {
        if let Some(operation) = self
            .operations
            .get_mut(operation_handle)
            .filter(|entry| &entry.scope == scope && matches!(entry.state, OperationState::Running))
        {
            operation.abort = None;
            operation.state = OperationState::Failed { code };
            operation.expires_at = now + TERMINAL_OPERATION_TTL;
            operation.touched_at = now;
            push_event(operation, "failed");
        }
    }

    fn cancel(
        &mut self,
        scope: &BindingScope,
        operation_handle: &str,
        now: Instant,
    ) -> Result<(), IntegrityApiError> {
        let operation = self
            .operations
            .get_mut(operation_handle)
            .filter(|entry| &entry.scope == scope)
            .ok_or(IntegrityApiError::OperationUnavailable)?;
        match operation.state {
            OperationState::Running => {
                if let Some(abort) = operation.abort.take() {
                    abort.abort();
                }
                operation.state = OperationState::Cancelled;
                operation.expires_at = now + TERMINAL_OPERATION_TTL;
                operation.touched_at = now;
                push_event(operation, "cancelled");
                Ok(())
            }
            OperationState::Cancelled => Ok(()),
            OperationState::Completed(_) | OperationState::Failed { .. } => {
                Err(IntegrityApiError::OperationUnavailable)
            }
        }
    }

    fn poll(
        &mut self,
        scope: &BindingScope,
        operation_handle: &str,
        after_event: u64,
        limit: usize,
    ) -> Result<IntegrityComparisonPollDto, IntegrityApiError> {
        let operation = self
            .operations
            .get_mut(operation_handle)
            .filter(|entry| &entry.scope == scope)
            .ok_or(IntegrityApiError::OperationUnavailable)?;
        if after_event > operation.next_sequence {
            return Err(IntegrityApiError::InvalidBounds);
        }
        let first_available = operation
            .events
            .front()
            .map_or(operation.next_sequence.saturating_add(1), |event| {
                event.sequence
            });
        let events_truncated = after_event.saturating_add(1) < first_available;
        let effective_after = if events_truncated {
            first_available.saturating_sub(1)
        } else {
            after_event
        };
        let events = operation
            .events
            .iter()
            .filter(|event| event.sequence > effective_after)
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();
        let next_event_cursor = events
            .last()
            .map_or(effective_after, |event| event.sequence);
        let (stage, comparison, error_code) = match &operation.state {
            OperationState::Running => ("running", None, None),
            OperationState::Completed(dto) => ("completed", Some(dto.clone()), None),
            OperationState::Cancelled => ("cancelled", None, None),
            OperationState::Failed { code } => ("failed", None, Some(*code)),
        };
        operation.touched_at = Instant::now();
        Ok(IntegrityComparisonPollDto {
            operation_handle: operation_handle.to_owned(),
            baseline_handle: operation.baseline_handle.clone(),
            stage,
            events,
            next_event_cursor,
            events_truncated,
            comparison,
            error_code,
        })
    }

    fn remove_scoped_operation(&mut self, scope: &BindingScope, operation_handle: &str) {
        if self
            .operations
            .get(operation_handle)
            .is_some_and(|entry| &entry.scope == scope)
        {
            self.remove_operation(operation_handle);
        }
    }

    fn remove_operation(&mut self, operation_handle: &str) {
        if let Some(mut operation) = self.operations.remove(operation_handle) {
            if let Some(abort) = operation.abort.take() {
                abort.abort();
            }
            self.operation_bytes = self.operation_bytes.saturating_sub(operation.bytes);
        }
    }
}

fn push_event(operation: &mut OperationEntry, kind: &'static str) {
    if operation.next_sequence >= MAX_PUBLIC_U64 {
        return;
    }
    operation.next_sequence += 1;
    if operation.events.len() == MAX_OPERATION_EVENTS {
        operation.events.pop_front();
    }
    operation.events.push_back(IntegrityOperationEventDto {
        sequence: operation.next_sequence,
        kind,
    });
}

struct ProjectedPaths {
    values: Vec<String>,
    redacted_count: usize,
    text_projected: bool,
    truncated: bool,
}

struct ProjectedPath {
    value: String,
    redacted: bool,
    projected: bool,
    truncated: bool,
}

fn project_paths(paths: &[String], sensitive_literals: &[&str]) -> ProjectedPaths {
    let mut values = Vec::new();
    let mut bytes = 0usize;
    let mut redacted_count = 0usize;
    let mut text_projected = false;
    let mut truncated = paths.len() > MAX_BASELINE_PATHS;
    for path in paths.iter().take(MAX_BASELINE_PATHS) {
        let projected = project_path(path, MAX_PATH_BYTES, sensitive_literals);
        if bytes.saturating_add(projected.value.len()) > MAX_BASELINE_RESPONSE_BYTES {
            truncated = true;
            break;
        }
        bytes = bytes.saturating_add(projected.value.len());
        redacted_count += usize::from(projected.redacted);
        text_projected |= projected.projected;
        truncated |= projected.truncated;
        values.push(projected.value);
    }
    ProjectedPaths {
        values,
        redacted_count,
        text_projected,
        truncated,
    }
}

fn project_comparison(
    baseline_handle: String,
    diff: IntegrityDiff,
    sensitive_literals: &[&str],
) -> Result<IntegrityComparisonDto, IntegrityApiError> {
    if diff.added > MAX_DIFF_TOTAL_ENTRIES
        || diff.removed > MAX_DIFF_TOTAL_ENTRIES
        || diff.modified > MAX_DIFF_TOTAL_ENTRIES
    {
        return Err(IntegrityApiError::ComparisonUnavailable);
    }
    let source_count = diff.entries.len();
    let mut entries = Vec::new();
    let mut path_bytes = 0usize;
    let mut redacted_path_count = 0usize;
    let mut text_projected = false;
    let mut truncated = diff.truncated || source_count > MAX_DIFF_ENTRIES;
    for entry in diff.entries.into_iter().take(MAX_DIFF_ENTRIES) {
        let path = project_path(&entry.path, MAX_PATH_BYTES, sensitive_literals);
        if path_bytes.saturating_add(path.value.len()) > MAX_DIFF_PATH_BYTES {
            truncated = true;
            break;
        }
        path_bytes = path_bytes.saturating_add(path.value.len());
        redacted_path_count += usize::from(path.redacted);
        text_projected |= path.projected;
        truncated |= path.truncated;
        entries.push(IntegrityFindingDto {
            path: path.value,
            path_redacted: path.redacted,
            path_truncated: path.truncated,
            path_projected: path.projected,
            kind: diff_kind_key(entry.kind),
            severity: severity_key(entry.severity),
        });
    }
    let displayed = entries.len();
    let counts = entries.iter().fold([0usize; 3], |mut counts, entry| {
        match entry.kind {
            "added" => counts[0] += 1,
            "removed" => counts[1] += 1,
            "modified" => counts[2] += 1,
            _ => {}
        }
        counts
    });
    if counts[0] > diff.added || counts[1] > diff.removed || counts[2] > diff.modified {
        return Err(IntegrityApiError::ComparisonUnavailable);
    }
    Ok(IntegrityComparisonDto {
        baseline_handle,
        added: diff.added,
        removed: diff.removed,
        modified: diff.modified,
        displayed,
        redacted_path_count,
        text_projected,
        truncated: truncated || displayed < source_count,
        entries,
    })
}

fn project_path(value: &str, maximum_bytes: usize, sensitive_literals: &[&str]) -> ProjectedPath {
    if is_sensitive_text(value, sensitive_literals)
        || !value.starts_with('/')
        || value.split('/').any(|component| component == "..")
    {
        return ProjectedPath {
            value: REDACTED_INTEGRITY_PATH.to_owned(),
            redacted: true,
            projected: true,
            truncated: false,
        };
    }
    let mut output = String::with_capacity(value.len().min(maximum_bytes));
    let mut projected = false;
    for character in value.chars() {
        let replacement = if character.is_control() {
            projected = true;
            '\u{fffd}'
        } else {
            character
        };
        if output.len().saturating_add(replacement.len_utf8()) > maximum_bytes {
            return ProjectedPath {
                value: output,
                redacted: false,
                projected: true,
                truncated: true,
            };
        }
        output.push(replacement);
    }
    ProjectedPath {
        value: output,
        redacted: false,
        projected,
        truncated: false,
    }
}

fn is_sensitive_text(value: &str, sensitive_literals: &[&str]) -> bool {
    value.contains(REDACTED_INTEGRITY_PATH)
        || sensitive_literals
            .iter()
            .any(|literal| !literal.is_empty() && value.contains(*literal))
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

fn unique_handle<T>(existing: &HashMap<String, T>) -> Result<String, IntegrityApiError> {
    for _ in 0..8 {
        let handle = Uuid::new_v4().to_string();
        if !existing.contains_key(&handle) {
            return Ok(handle);
        }
    }
    Err(IntegrityApiError::Capacity)
}

const fn diff_kind_key(kind: IntegrityDiffKind) -> &'static str {
    match kind {
        IntegrityDiffKind::Added => "added",
        IntegrityDiffKind::Removed => "removed",
        IntegrityDiffKind::Modified => "modified",
    }
}

const fn severity_key(severity: IntegritySeverity) -> &'static str {
    match severity {
        IntegritySeverity::High => "high",
        IntegritySeverity::Medium => "medium",
    }
}

#[cfg(test)]
mod tests {
    use lovelyres_core::{integrity::IntegrityDiffEntry, target::TargetIdentity};

    use super::*;

    fn scope(name: &str, generation: u64) -> BindingScope {
        BindingScope {
            binding_handle: format!("binding-{name}"),
            session_id: format!("session-{name}"),
            connection_id: name.to_owned(),
            target: TargetGuard {
                identity: TargetIdentity::new(name).unwrap(),
                generation,
            },
        }
    }

    fn baseline(scope: &BindingScope, id: &str, paths: Vec<String>) -> IntegrityBaseline {
        IntegrityBaseline {
            id: id.to_owned(),
            target: scope.target.identity.clone(),
            created_at: serde_json::from_str("\"2026-08-24T00:00:00Z\"").unwrap(),
            paths,
            remote_manifest: format!("/tmp/.lovelyres_fim/baseline-{id}.manifest"),
            file_count: 7,
            manifest_sha256: "a".repeat(64),
        }
    }

    fn diff(id: &str, paths: &[(&str, IntegrityDiffKind)]) -> IntegrityDiff {
        let mut counts = [0usize; 3];
        let entries = paths
            .iter()
            .map(|(path, kind)| {
                match kind {
                    IntegrityDiffKind::Added => counts[0] += 1,
                    IntegrityDiffKind::Removed => counts[1] += 1,
                    IntegrityDiffKind::Modified => counts[2] += 1,
                }
                IntegrityDiffEntry {
                    path: (*path).to_owned(),
                    kind: *kind,
                    severity: if *kind == IntegrityDiffKind::Modified {
                        IntegritySeverity::Medium
                    } else {
                        IntegritySeverity::High
                    },
                }
            })
            .collect();
        IntegrityDiff {
            baseline_id: id.to_owned(),
            entries,
            added: counts[0],
            removed: counts[1],
            modified: counts[2],
            truncated: false,
        }
    }

    fn register_baseline(registry: &mut Registry, current: &BindingScope, now: Instant) -> String {
        registry
            .register_baseline(
                current.clone(),
                baseline(current, "core-baseline", vec!["/usr/bin".to_owned()]),
                now,
            )
            .unwrap()
            .baseline_handle
    }

    #[test]
    fn phase_zero_surface_is_exact_five_and_contains_no_mutation() {
        let catalog = IntegrityApi::catalog();
        assert_eq!(catalog.presets.len(), MAX_PRESETS);
        assert_eq!(
            catalog
                .presets
                .iter()
                .filter(|preset| preset.default_selected)
                .count(),
            4
        );
        let source = include_str!("integrity_api.rs");
        for forbidden in [
            ["create", "_baseline("].concat(),
            ["plan", "_quarantine("].concat(),
            ["confirm", "_quarantine("].concat(),
            ["execute", "_quarantine("].concat(),
            ["Dangerous", "Confirmation"].concat(),
        ] {
            assert!(
                !source.contains(&forbidden),
                "unexpected mutation: {forbidden}"
            );
        }
    }

    #[test]
    fn baseline_handles_are_target_epoch_ttl_and_text_projection_bound() {
        let now = Instant::now();
        let current = scope("server-one", 1);
        let changed = scope("server-one", 2);
        let sensitive = format!(
            "/srv/password=hunter/https://user:pass@example.test/{}/{}",
            current.binding_handle, current.session_id
        );
        let mut registry = Registry::default();
        let dto = registry
            .register_baseline(
                current.clone(),
                baseline(
                    &current,
                    "secret-core-id",
                    vec![sensitive, "/srv/<script>plain()</script>\0".to_owned()],
                ),
                now,
            )
            .unwrap();
        assert_eq!(dto.redacted_path_count, 1);
        assert!(dto.text_projected);
        assert_eq!(dto.paths[0], REDACTED_INTEGRITY_PATH);
        assert!(dto.paths[1].contains("<script>plain()</script>"));
        assert!(!dto.paths[1].contains('\0'));
        let json = serde_json::to_string(&dto).unwrap();
        assert!(!json.contains("hunter"));
        assert!(!json.contains("user:pass"));
        assert!(!json.contains("secret-core-id"));
        assert!(matches!(
            registry.resolve_baseline(&changed, &dto.baseline_handle, now),
            Err(IntegrityApiError::BaselineUnavailable)
        ));
        assert!(matches!(
            registry.resolve_baseline(
                &current,
                &dto.baseline_handle,
                now + BASELINE_HANDLE_TTL + Duration::from_secs(1),
            ),
            Err(IntegrityApiError::BaselineUnavailable)
        ));
    }

    #[test]
    fn comparison_projection_is_plain_redacted_bounded_and_consistent() {
        let current = scope("server-one", 1);
        let literals = current.sensitive_literals();
        let sensitive = format!("/srv/token=secret/{}", literals[3]);
        let dto = project_comparison(
            "baseline-handle".to_owned(),
            diff(
                "core-baseline",
                &[
                    ("/srv/<img src=x onerror=steal()>", IntegrityDiffKind::Added),
                    (&sensitive, IntegrityDiffKind::Modified),
                    ("/srv/control\u{7f}", IntegrityDiffKind::Removed),
                ],
            ),
            &literals,
        )
        .unwrap();
        assert_eq!(dto.displayed, 3);
        assert_eq!(dto.redacted_path_count, 1);
        assert!(dto.text_projected);
        assert!(dto.entries[0].path.contains("<img src=x onerror=steal()>"));
        assert_eq!(dto.entries[1].path, REDACTED_INTEGRITY_PATH);
        assert!(dto.entries[1].path_redacted);
        assert!(!dto.entries[2].path.contains('\u{7f}'));
        let json = serde_json::to_string(&dto).unwrap();
        assert!(!json.contains("token=secret"));
        assert!(!json.contains("server-one"));

        let entries = (0..(MAX_DIFF_ENTRIES + 20))
            .map(|index| IntegrityDiffEntry {
                path: format!("/srv/{index}"),
                kind: IntegrityDiffKind::Modified,
                severity: IntegritySeverity::Medium,
            })
            .collect::<Vec<_>>();
        let source_count = entries.len();
        let bounded = project_comparison(
            "baseline-handle".to_owned(),
            IntegrityDiff {
                baseline_id: "core-baseline".to_owned(),
                entries,
                added: 0,
                removed: 0,
                modified: source_count,
                truncated: false,
            },
            &[],
        )
        .unwrap();
        assert_eq!(bounded.displayed, MAX_DIFF_ENTRIES);
        assert!(bounded.truncated);
        assert!(serde_json::to_vec(&bounded).unwrap().len() <= MAX_COMPARISON_BYTES);
    }

    #[test]
    fn operation_poll_cursor_cancel_and_late_completion_fail_closed() {
        let now = Instant::now();
        let current = scope("server-one", 1);
        let mut registry = Registry::default();
        let baseline_handle = register_baseline(&mut registry, &current, now);
        let operation = registry
            .begin_operation(
                current.clone(),
                baseline_handle.clone(),
                "core-baseline".to_owned(),
                now,
            )
            .unwrap();
        let first = registry.poll(&current, &operation, 0, 1).unwrap();
        assert_eq!(first.events.len(), 1);
        assert_eq!(first.next_event_cursor, 1);
        registry.cancel(&current, &operation, now).unwrap();
        let cancelled = registry
            .poll(&current, &operation, 1, MAX_POLL_EVENTS)
            .unwrap();
        assert_eq!(cancelled.stage, "cancelled");
        assert_eq!(cancelled.events[0].kind, "cancelled");
        assert!(cancelled.comparison.is_none());
        assert!(matches!(
            registry.finish_success(
                &current,
                &operation,
                &baseline_handle,
                "core-baseline",
                diff("core-baseline", &[("/srv/late", IntegrityDiffKind::Added)]),
                now,
            ),
            Err(IntegrityApiError::OperationUnavailable)
        ));
        assert!(matches!(
            registry.poll(&current, &operation, u64::MAX, 1),
            Err(IntegrityApiError::InvalidBounds)
        ));
    }

    #[test]
    fn close_binding_reclaims_handles_operations_bytes_and_preserves_other_binding() {
        let now = Instant::now();
        let closed = scope("server-one", 1);
        let retained = scope("server-two", 1);
        let mut registry = Registry::default();
        let closed_baseline = register_baseline(&mut registry, &closed, now);
        let retained_baseline = register_baseline(&mut registry, &retained, now);
        let closed_operation = registry
            .begin_operation(
                closed.clone(),
                closed_baseline.clone(),
                "core-baseline".to_owned(),
                now,
            )
            .unwrap();
        let retained_operation = registry
            .begin_operation(
                retained.clone(),
                retained_baseline,
                "core-baseline".to_owned(),
                now,
            )
            .unwrap();
        registry
            .finish_success(
                &closed,
                &closed_operation,
                &closed_baseline,
                "core-baseline",
                diff("core-baseline", &[("/srv/one", IntegrityDiffKind::Added)]),
                now,
            )
            .unwrap();
        assert!(registry.operation_bytes > 0);

        registry.close_binding(&closed.binding_handle);
        assert!(!registry.operations.contains_key(&closed_operation));
        assert!(registry.operations.contains_key(&retained_operation));
        assert!(
            registry
                .baselines
                .values()
                .all(|entry| entry.scope.binding_handle == retained.binding_handle)
        );
        assert_eq!(registry.operation_bytes, 0);
        assert!(matches!(
            registry.finish_success(
                &closed,
                &closed_operation,
                &closed_baseline,
                "core-baseline",
                diff("core-baseline", &[("/srv/late", IntegrityDiffKind::Added)]),
                now,
            ),
            Err(IntegrityApiError::OperationUnavailable)
        ));
    }

    #[test]
    fn operation_concurrency_capacity_target_epoch_and_ttl_are_bounded() {
        let now = Instant::now();
        let mut registry = Registry::default();
        let mut operations = Vec::new();
        for index in 0..MAX_ACTIVE_OPERATIONS {
            let current = scope(&format!("server-{index}"), 1);
            let baseline_handle = register_baseline(&mut registry, &current, now);
            operations.push(
                registry
                    .begin_operation(current, baseline_handle, "core-baseline".to_owned(), now)
                    .unwrap(),
            );
        }
        let overflow = scope("overflow", 1);
        let baseline_handle = register_baseline(&mut registry, &overflow, now);
        assert!(matches!(
            registry.begin_operation(overflow, baseline_handle, "core-baseline".to_owned(), now,),
            Err(IntegrityApiError::Capacity)
        ));

        let old_epoch = scope("same-server", 1);
        let new_epoch = scope("same-server", 2);
        registry.operations.clear();
        let baseline_handle = register_baseline(&mut registry, &old_epoch, now);
        let operation = registry
            .begin_operation(
                old_epoch.clone(),
                baseline_handle,
                "core-baseline".to_owned(),
                now,
            )
            .unwrap();
        assert!(matches!(
            registry.poll(&new_epoch, &operation, 0, 1),
            Err(IntegrityApiError::OperationUnavailable)
        ));
        registry.operations.get_mut(&operation).unwrap().expires_at = now;
        registry.prune(now);
        assert!(!registry.operations.contains_key(&operation));
        assert_eq!(registry.operation_bytes, 0);
        assert_eq!(operations.len(), MAX_ACTIVE_OPERATIONS);
    }

    #[test]
    fn debug_and_public_errors_are_fixed_and_redacted() {
        let current = scope("secret-connection", 77);
        assert!(!format!("{current:?}").contains("secret-connection"));
        let error = IntegrityApiError::Core(CoreError::Validation {
            subject: "password=hunter",
            message: "do-not-print".to_owned(),
        });
        assert_eq!(error.to_string(), "the integrity operation failed");
        assert!(!format!("{error:?}").contains("do-not-print"));
    }
}
