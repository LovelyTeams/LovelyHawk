//! Standalone read-only Electron boundary for middleware discovery and configuration review.
//!
//! Core owns discovery commands, configuration paths, include graphs, digests, history evidence,
//! and every mutation primitive. This adapter retains those values only inside target-scoped,
//! expiring snapshots and publishes bounded opaque handles plus safe read summaries.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use lovelyres_core::{
    BackendServices, CoreError,
    middleware::{
        MiddlewareChangeRecord, MiddlewareChangeState, MiddlewareConfigRole,
        MiddlewareConfigurationBundle, MiddlewareInstance, MiddlewareProduct,
    },
    middleware_document::MiddlewareDocumentNodeKind,
    ssh::BoundSshSession,
    target::TargetGuard,
};
use serde::Serialize;
use uuid::Uuid;

use crate::ssh_api::SshApi;

const MAX_HANDLE_BYTES: usize = 128;
const MAX_DISCOVERY_INSTANCES: usize = 32;
const MAX_CONFIGURATION_FILES: usize = 64;
const MAX_NODES_PER_FILE: usize = 256;
const MAX_CONFIGURATION_NODES: usize = 1024;
const MAX_HISTORY_ENTRIES: usize = 128;
const MAX_VERSION_BYTES: usize = 256;
const MAX_STATUS_TEXT_BYTES: usize = 256;
const MAX_NODE_NAME_BYTES: usize = 128;
const MAX_RAW_TEXT_PER_FILE_BYTES: usize = 128 * 1024;
const MAX_RAW_TEXT_TOTAL_BYTES: usize = 512 * 1024;
const MAX_DISCOVERY_TEXT_BYTES: usize = 32 * 1024;
const MAX_NODE_TEXT_BYTES: usize = 128 * 1024;
const MAX_DISCOVERY_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_CONFIGURATION_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_HISTORY_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_DISCOVERY_RAW_BYTES: usize = 384 * 1024;
const MAX_HISTORY_RAW_BYTES: usize = 384 * 1024;
const MAX_SNAPSHOT_BYTES: usize = 512 * 1024;
const MAX_SNAPSHOTS: usize = 8;
const MAX_REGISTRY_BYTES: usize = 2 * 1024 * 1024;
const MAX_GLOBAL_READS: usize = 4;
const MAX_READS_PER_BINDING: usize = 1;
const SNAPSHOT_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Clone)]
pub(crate) struct MiddlewareReadApi {
    services: BackendServices,
    ssh_api: Arc<SshApi>,
    registry: Arc<Mutex<MiddlewareRegistry>>,
    concurrency: Arc<Mutex<ConcurrencyState>>,
}

impl fmt::Debug for MiddlewareReadApi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (snapshot_count, snapshot_bytes, active_snapshot_reads) = self
            .registry
            .lock()
            .map(|registry| {
                (
                    registry.snapshots.len(),
                    registry.total_bytes,
                    registry
                        .snapshots
                        .values()
                        .map(|snapshot| snapshot.active_reads)
                        .sum::<usize>(),
                )
            })
            .unwrap_or_default();
        let active_reads = self
            .concurrency
            .lock()
            .map(|state| state.total)
            .unwrap_or_default();
        formatter
            .debug_struct("MiddlewareReadApi")
            .field("snapshot_count", &snapshot_count)
            .field("snapshot_bytes", &snapshot_bytes)
            .field("active_snapshot_reads", &active_snapshot_reads)
            .field("active_reads", &active_reads)
            .finish()
    }
}

impl MiddlewareReadApi {
    pub(crate) fn new(services: BackendServices, ssh_api: Arc<SshApi>) -> Self {
        Self {
            services,
            ssh_api,
            registry: Arc::new(Mutex::new(MiddlewareRegistry::default())),
            concurrency: Arc::new(Mutex::new(ConcurrencyState::default())),
        }
    }

    pub(crate) fn close_binding(&self, binding_handle: &str) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.close_binding(binding_handle);
        }
    }

    pub(crate) async fn discover(
        &self,
        binding_handle: &str,
    ) -> Result<MiddlewareDiscoveryDto, MiddlewareReadApiError> {
        let (session, scope) = self.capture_binding(binding_handle)?;
        self.prune_registry(&scope)?;
        let _permit = self.acquire_read(&scope)?;
        let instances = self.services.middleware().discover(&session).await?;
        self.validate_binding(&scope)?;
        let (snapshot, dto) = build_discovery_snapshot(scope.clone(), instances)?;
        ensure_serialized_bound(&dto, MAX_DISCOVERY_RESPONSE_BYTES)?;
        let handle = snapshot.handle.clone();
        self.lock_registry()?.insert(snapshot)?;
        if let Err(error) = self.validate_binding(&scope) {
            self.remove_snapshot(&handle);
            return Err(error);
        }
        Ok(dto)
    }

    pub(crate) async fn load_configuration(
        &self,
        binding_handle: &str,
        discovery_handle: &str,
        instance_handle: &str,
    ) -> Result<MiddlewareConfigurationDto, MiddlewareReadApiError> {
        validate_handle(discovery_handle)?;
        validate_handle(instance_handle)?;
        let (session, scope) = self.capture_binding(binding_handle)?;
        let _permit = self.acquire_read(&scope)?;
        let (access, instance, _snapshot_permit) =
            self.begin_instance_read(&scope, discovery_handle, instance_handle)?;
        let bundle = self
            .services
            .middleware()
            .load_configuration(&session, &instance)
            .await?;
        self.validate_binding(&scope)?;
        self.verify_instance_access(&access)?;
        if bundle.target() != &scope.target || bundle.instance().id() != instance.id() {
            return Err(MiddlewareReadApiError::SnapshotStale);
        }
        let dto = project_configuration(discovery_handle, instance_handle, bundle)?;
        ensure_serialized_bound(&dto, MAX_CONFIGURATION_RESPONSE_BYTES)?;
        self.validate_binding(&scope)?;
        self.verify_instance_access(&access)?;
        Ok(dto)
    }

    pub(crate) async fn list_history(
        &self,
        binding_handle: &str,
    ) -> Result<MiddlewareHistoryDto, MiddlewareReadApiError> {
        let (session, scope) = self.capture_binding(binding_handle)?;
        self.prune_registry(&scope)?;
        let _permit = self.acquire_read(&scope)?;
        let records = self.services.middleware().history(session.target())?;
        self.validate_binding(&scope)?;
        let (snapshot, dto) = build_history_snapshot(scope.clone(), records)?;
        ensure_serialized_bound(&dto, MAX_HISTORY_RESPONSE_BYTES)?;
        let handle = snapshot.handle.clone();
        self.lock_registry()?.insert(snapshot)?;
        if let Err(error) = self.validate_binding(&scope) {
            self.remove_snapshot(&handle);
            return Err(error);
        }
        Ok(dto)
    }

    fn capture_binding(
        &self,
        binding_handle: &str,
    ) -> Result<(BoundSshSession, BindingScope), MiddlewareReadApiError> {
        validate_handle(binding_handle)?;
        let session = self
            .ssh_api
            .binding_session_clone(binding_handle)
            .map_err(|_| MiddlewareReadApiError::BindingUnavailable)?;
        self.services
            .target()
            .validate(session.target())
            .map_err(|_| MiddlewareReadApiError::BindingUnavailable)?;
        let scope = BindingScope::from_session(binding_handle, &session);
        Ok((session, scope))
    }

    fn validate_binding(&self, expected: &BindingScope) -> Result<(), MiddlewareReadApiError> {
        let (_, current) = self.capture_binding(&expected.binding_handle)?;
        if &current != expected {
            return Err(MiddlewareReadApiError::BindingUnavailable);
        }
        Ok(())
    }

    fn acquire_read(&self, scope: &BindingScope) -> Result<ReadPermit, MiddlewareReadApiError> {
        ReadPermit::acquire(Arc::clone(&self.concurrency), scope.concurrency_key())
    }

    fn begin_instance_read(
        &self,
        scope: &BindingScope,
        discovery_handle: &str,
        instance_handle: &str,
    ) -> Result<(SnapshotAccess, MiddlewareInstance, SnapshotPermit), MiddlewareReadApiError> {
        let mut registry = self.lock_registry()?;
        registry.prune(Instant::now(), Some(scope));
        let (access, instance) =
            registry.begin_instance_read(scope, discovery_handle, instance_handle)?;
        let permit = SnapshotPermit {
            registry: Arc::clone(&self.registry),
            handle: discovery_handle.to_owned(),
            token: access.token,
        };
        Ok((access, instance, permit))
    }

    fn verify_instance_access(
        &self,
        access: &SnapshotAccess,
    ) -> Result<(), MiddlewareReadApiError> {
        self.lock_registry()?.verify_instance(access)
    }

    fn prune_registry(&self, scope: &BindingScope) -> Result<(), MiddlewareReadApiError> {
        self.lock_registry()?.prune(Instant::now(), Some(scope));
        Ok(())
    }

    fn remove_snapshot(&self, handle: &str) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.remove(handle);
        }
    }

    fn lock_registry(&self) -> Result<MutexGuard<'_, MiddlewareRegistry>, MiddlewareReadApiError> {
        self.registry
            .lock()
            .map_err(|_| MiddlewareReadApiError::RegistryUnavailable)
    }
}

pub(crate) enum MiddlewareReadApiError {
    Core,
    BindingUnavailable,
    InvalidHandle,
    InvalidData,
    InvalidSnapshot,
    SnapshotStale,
    OutputLimit,
    ConcurrencyLimit,
    RegistryUnavailable,
}

impl fmt::Debug for MiddlewareReadApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core => "Core([REDACTED])",
            Self::BindingUnavailable => "BindingUnavailable",
            Self::InvalidHandle => "InvalidHandle",
            Self::InvalidData => "InvalidData",
            Self::InvalidSnapshot => "InvalidSnapshot",
            Self::SnapshotStale => "SnapshotStale",
            Self::OutputLimit => "OutputLimit",
            Self::ConcurrencyLimit => "ConcurrencyLimit",
            Self::RegistryUnavailable => "RegistryUnavailable",
        })
    }
}

impl fmt::Display for MiddlewareReadApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core => "the middleware read operation failed",
            Self::BindingUnavailable => "the SSH binding is missing or stale",
            Self::InvalidHandle => "the middleware handle is invalid",
            Self::InvalidData => "the middleware result is invalid",
            Self::InvalidSnapshot => "the middleware discovery is missing or expired",
            Self::SnapshotStale => "the middleware result no longer matches its discovery",
            Self::OutputLimit => "the middleware result exceeded its public limit",
            Self::ConcurrencyLimit => "the middleware read concurrency limit was reached",
            Self::RegistryUnavailable => "the middleware registry is unavailable",
        })
    }
}

impl std::error::Error for MiddlewareReadApiError {}

impl From<CoreError> for MiddlewareReadApiError {
    fn from(error: CoreError) -> Self {
        // The renderer only ever sees a fixed message, so without this the
        // reason a page failed is lost before anyone can read it.
        tracing::warn!(operation = "MiddlewareRead", error = %error, "core operation failed");
        Self::Core
    }
}

#[derive(Clone, PartialEq, Eq)]
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

    fn concurrency_key(&self) -> String {
        format!(
            "{}\0{}\0{}\0{}\0{}",
            self.binding_handle,
            self.session_id,
            self.connection_id,
            self.target.identity.as_str(),
            self.target.generation,
        )
    }

    fn storage_bytes(&self) -> usize {
        self.binding_handle
            .len()
            .saturating_add(self.session_id.len())
            .saturating_add(self.connection_id.len())
            .saturating_add(self.target.identity.as_str().len())
            .saturating_add(128)
    }
}

impl fmt::Debug for BindingScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MiddlewareBindingScope([REDACTED])")
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MiddlewareDiscoveryDto {
    discovery_handle: String,
    expires_in_seconds: u64,
    instances: Vec<MiddlewareInstanceDto>,
    discovered_count: usize,
    displayed: usize,
    redacted_field_count: usize,
    truncated: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MiddlewareInstanceDto {
    instance_handle: String,
    title: String,
    product: &'static str,
    version: String,
    status: &'static str,
    status_text: String,
    active: bool,
    redacted: bool,
    text_truncated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MiddlewareConfigurationDto {
    discovery_handle: String,
    instance_handle: String,
    product: &'static str,
    loaded_at: String,
    total_bytes: String,
    file_count: usize,
    unresolved_include_count: usize,
    directory_manifest_count: usize,
    files: Vec<MiddlewareConfigurationFileDto>,
    displayed: usize,
    displayed_nodes: usize,
    redacted_field_count: usize,
    truncated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MiddlewareConfigurationFileDto {
    file_handle: String,
    ordinal: usize,
    role: &'static str,
    byte_length: String,
    content_mode: &'static str,
    raw_text: Option<String>,
    raw_text_unavailable_reason: &'static str,
    node_count: usize,
    displayed_nodes: usize,
    nodes: Vec<MiddlewareNodeDto>,
    contains_sensitive_values: bool,
    redacted_field_count: usize,
    truncated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MiddlewareNodeDto {
    kind: &'static str,
    name: Option<String>,
    depth: usize,
    editable: bool,
    sensitive: bool,
    redacted: bool,
    text_truncated: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MiddlewareHistoryDto {
    history_handle: String,
    expires_in_seconds: u64,
    entries: Vec<MiddlewareHistoryEntryDto>,
    record_count: usize,
    displayed: usize,
    truncated: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MiddlewareHistoryEntryDto {
    history_item_handle: String,
    product: &'static str,
    state: &'static str,
    summary: String,
    old_bytes: String,
    new_bytes: String,
    created_at: String,
    updated_at: String,
}

#[derive(Default)]
struct ConcurrencyState {
    total: usize,
    per_binding: HashMap<String, usize>,
}

struct ReadPermit {
    state: Arc<Mutex<ConcurrencyState>>,
    key: String,
}

impl ReadPermit {
    fn acquire(
        state: Arc<Mutex<ConcurrencyState>>,
        key: String,
    ) -> Result<Self, MiddlewareReadApiError> {
        {
            let mut current = state
                .lock()
                .map_err(|_| MiddlewareReadApiError::RegistryUnavailable)?;
            let binding_reads = current.per_binding.get(&key).copied().unwrap_or_default();
            if current.total >= MAX_GLOBAL_READS || binding_reads >= MAX_READS_PER_BINDING {
                return Err(MiddlewareReadApiError::ConcurrencyLimit);
            }
            current.total += 1;
            current.per_binding.insert(key.clone(), binding_reads + 1);
        }
        Ok(Self { state, key })
    }
}

impl Drop for ReadPermit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            state.total = state.total.saturating_sub(1);
            if let Some(count) = state.per_binding.get_mut(&self.key) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    state.per_binding.remove(&self.key);
                }
            }
        }
    }
}

#[derive(Default)]
struct MiddlewareRegistry {
    snapshots: HashMap<String, MiddlewareSnapshot>,
    total_bytes: usize,
}

struct MiddlewareSnapshot {
    handle: String,
    token: Uuid,
    scope: BindingScope,
    data: SnapshotData,
    stored_bytes: usize,
    expires_at: Instant,
    touched_at: Instant,
    active_reads: usize,
}

enum SnapshotData {
    Discovery {
        instances: HashMap<String, MiddlewareInstance>,
    },
    History,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SnapshotKind {
    Discovery,
    History,
}

impl SnapshotData {
    const fn kind(&self) -> SnapshotKind {
        match self {
            Self::Discovery { .. } => SnapshotKind::Discovery,
            Self::History => SnapshotKind::History,
        }
    }
}

#[derive(Clone)]
struct SnapshotAccess {
    handle: String,
    token: Uuid,
    scope: BindingScope,
    instance_handle: String,
}

struct SnapshotPermit {
    registry: Arc<Mutex<MiddlewareRegistry>>,
    handle: String,
    token: Uuid,
}

impl Drop for SnapshotPermit {
    fn drop(&mut self) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.release_read(&self.handle, self.token);
        }
    }
}

impl MiddlewareRegistry {
    fn close_binding(&mut self, binding_handle: &str) {
        let handles = self
            .snapshots
            .iter()
            .filter_map(|(handle, snapshot)| {
                (snapshot.scope.binding_handle == binding_handle).then_some(handle.clone())
            })
            .collect::<Vec<_>>();
        for handle in handles {
            self.remove(&handle);
        }
    }

    fn prune(&mut self, now: Instant, current: Option<&BindingScope>) {
        let stale = self
            .snapshots
            .iter()
            .filter_map(|(handle, snapshot)| {
                let binding_changed = current.is_some_and(|current| {
                    snapshot.scope.binding_handle == current.binding_handle
                        && snapshot.scope != *current
                });
                (snapshot.active_reads == 0 && (snapshot.expires_at <= now || binding_changed))
                    .then_some(handle.clone())
            })
            .collect::<Vec<_>>();
        for handle in stale {
            self.remove(&handle);
        }
    }

    fn insert(&mut self, snapshot: MiddlewareSnapshot) -> Result<(), MiddlewareReadApiError> {
        self.prune(Instant::now(), Some(&snapshot.scope));
        if snapshot.stored_bytes > MAX_SNAPSHOT_BYTES
            || self.snapshots.contains_key(&snapshot.handle)
        {
            return Err(MiddlewareReadApiError::OutputLimit);
        }
        if self.snapshots.values().any(|existing| {
            existing.scope == snapshot.scope
                && existing.data.kind() == snapshot.data.kind()
                && existing.active_reads > 0
        }) {
            return Err(MiddlewareReadApiError::SnapshotStale);
        }
        let replaced = self
            .snapshots
            .iter()
            .filter_map(|(handle, existing)| {
                (existing.scope == snapshot.scope
                    && existing.data.kind() == snapshot.data.kind()
                    && existing.active_reads == 0)
                    .then_some(handle.clone())
            })
            .collect::<Vec<_>>();
        for handle in replaced {
            self.remove(&handle);
        }
        self.make_room(snapshot.stored_bytes)?;
        self.total_bytes = self.total_bytes.saturating_add(snapshot.stored_bytes);
        self.snapshots.insert(snapshot.handle.clone(), snapshot);
        Ok(())
    }

    fn make_room(&mut self, incoming: usize) -> Result<(), MiddlewareReadApiError> {
        while self.snapshots.len() >= MAX_SNAPSHOTS
            || self.total_bytes.saturating_add(incoming) > MAX_REGISTRY_BYTES
        {
            let candidate = self
                .snapshots
                .iter()
                .filter(|(_, snapshot)| snapshot.active_reads == 0)
                .min_by_key(|(_, snapshot)| snapshot.touched_at)
                .map(|(handle, _)| handle.clone())
                .ok_or(MiddlewareReadApiError::OutputLimit)?;
            self.remove(&candidate);
        }
        if self.total_bytes.saturating_add(incoming) > MAX_REGISTRY_BYTES {
            return Err(MiddlewareReadApiError::OutputLimit);
        }
        Ok(())
    }

    fn begin_instance_read(
        &mut self,
        scope: &BindingScope,
        discovery_handle: &str,
        instance_handle: &str,
    ) -> Result<(SnapshotAccess, MiddlewareInstance), MiddlewareReadApiError> {
        let snapshot = self
            .snapshots
            .get_mut(discovery_handle)
            .filter(|snapshot| &snapshot.scope == scope && snapshot.expires_at > Instant::now())
            .ok_or(MiddlewareReadApiError::InvalidSnapshot)?;
        let SnapshotData::Discovery { instances } = &snapshot.data else {
            return Err(MiddlewareReadApiError::InvalidSnapshot);
        };
        let instance = instances
            .get(instance_handle)
            .cloned()
            .ok_or(MiddlewareReadApiError::InvalidHandle)?;
        snapshot.active_reads += 1;
        snapshot.touched_at = Instant::now();
        Ok((
            SnapshotAccess {
                handle: discovery_handle.to_owned(),
                token: snapshot.token,
                scope: scope.clone(),
                instance_handle: instance_handle.to_owned(),
            },
            instance,
        ))
    }

    fn verify_instance(&self, access: &SnapshotAccess) -> Result<(), MiddlewareReadApiError> {
        let snapshot = self
            .snapshots
            .get(&access.handle)
            .filter(|snapshot| {
                snapshot.token == access.token
                    && snapshot.scope == access.scope
                    && snapshot.expires_at > Instant::now()
            })
            .ok_or(MiddlewareReadApiError::SnapshotStale)?;
        let SnapshotData::Discovery { instances } = &snapshot.data else {
            return Err(MiddlewareReadApiError::SnapshotStale);
        };
        if !instances.contains_key(&access.instance_handle) {
            return Err(MiddlewareReadApiError::SnapshotStale);
        }
        Ok(())
    }

    fn release_read(&mut self, handle: &str, token: Uuid) {
        if let Some(snapshot) = self
            .snapshots
            .get_mut(handle)
            .filter(|snapshot| snapshot.token == token)
        {
            snapshot.active_reads = snapshot.active_reads.saturating_sub(1);
        }
    }

    fn remove(&mut self, handle: &str) {
        if let Some(snapshot) = self.snapshots.remove(handle) {
            self.total_bytes = self.total_bytes.saturating_sub(snapshot.stored_bytes);
        }
    }

    #[cfg(test)]
    fn resolve_history_snapshot(
        &self,
        scope: &BindingScope,
        history_handle: &str,
        now: Instant,
    ) -> Result<(), MiddlewareReadApiError> {
        let snapshot = self
            .snapshots
            .get(history_handle)
            .filter(|snapshot| &snapshot.scope == scope && snapshot.expires_at > now)
            .ok_or(MiddlewareReadApiError::InvalidHandle)?;
        let SnapshotData::History = &snapshot.data else {
            return Err(MiddlewareReadApiError::InvalidHandle);
        };
        Ok(())
    }
}

fn build_discovery_snapshot(
    scope: BindingScope,
    instances: Vec<MiddlewareInstance>,
) -> Result<(MiddlewareSnapshot, MiddlewareDiscoveryDto), MiddlewareReadApiError> {
    let discovered_count = instances.len();
    if discovered_count > MAX_DISCOVERY_INSTANCES {
        return Err(MiddlewareReadApiError::InvalidData);
    }
    let discovery_handle = unique_handle("middleware-discovery", |_| false)?;
    let mut stored = HashMap::with_capacity(discovered_count);
    let mut items = Vec::with_capacity(discovered_count);
    let mut raw_bytes = scope.storage_bytes().saturating_add(discovery_handle.len());
    let mut text_budget = TextBudget::new(MAX_DISCOVERY_TEXT_BYTES);
    let mut redacted_field_count = 0usize;
    let mut truncated = false;
    for (index, instance) in instances.into_iter().enumerate() {
        if instance.target() != &scope.target {
            return Err(MiddlewareReadApiError::InvalidData);
        }
        let estimate = format!("{instance:?}")
            .len()
            .saturating_add(std::mem::size_of::<MiddlewareInstance>())
            .saturating_add(4 * 1024);
        if raw_bytes.saturating_add(estimate) > MAX_DISCOVERY_RAW_BYTES {
            truncated = true;
            break;
        }
        let instance_handle = unique_handle("middleware-instance", |candidate| {
            stored.contains_key(candidate)
        })?;
        let (version, version_redacted, version_truncated) =
            text_budget.take_public(instance.version(), MAX_VERSION_BYTES);
        let status_source = format!("{} / {}", instance.active_state(), instance.sub_state());
        let (status_text, status_redacted, status_truncated) =
            text_budget.take_public(&status_source, MAX_STATUS_TEXT_BYTES);
        let redacted = version_redacted || status_redacted;
        redacted_field_count += usize::from(version_redacted) + usize::from(status_redacted);
        truncated |= version_truncated || status_truncated;
        items.push(MiddlewareInstanceDto {
            instance_handle: instance_handle.clone(),
            title: format!("{} 实例 {}", instance.product().label(), index + 1),
            product: product_key(instance.product()),
            version,
            status: public_instance_status(&instance),
            status_text,
            active: instance.is_active(),
            redacted,
            text_truncated: version_truncated || status_truncated,
        });
        raw_bytes = raw_bytes
            .saturating_add(estimate)
            .saturating_add(instance_handle.len());
        stored.insert(instance_handle, instance);
    }
    let displayed = items.len();
    truncated |= displayed < discovered_count;
    let dto = MiddlewareDiscoveryDto {
        discovery_handle: discovery_handle.clone(),
        expires_in_seconds: SNAPSHOT_TTL.as_secs(),
        instances: items,
        discovered_count,
        displayed,
        redacted_field_count,
        truncated,
    };
    let response_bytes = serialized_bytes(&dto)?;
    let stored_bytes = raw_bytes.saturating_add(response_bytes);
    if stored_bytes > MAX_SNAPSHOT_BYTES {
        return Err(MiddlewareReadApiError::OutputLimit);
    }
    let now = Instant::now();
    Ok((
        MiddlewareSnapshot {
            handle: discovery_handle,
            token: Uuid::new_v4(),
            scope,
            data: SnapshotData::Discovery { instances: stored },
            stored_bytes,
            expires_at: now + SNAPSHOT_TTL,
            touched_at: now,
            active_reads: 0,
        },
        dto,
    ))
}

fn project_configuration(
    discovery_handle: &str,
    instance_handle: &str,
    bundle: MiddlewareConfigurationBundle,
) -> Result<MiddlewareConfigurationDto, MiddlewareReadApiError> {
    let file_count = bundle.files().len();
    let unresolved_include_count = bundle.unresolved_includes().len();
    let directory_manifest_count = bundle.directory_manifest_count();
    if file_count > 256
        || unresolved_include_count > 65_536
        || directory_manifest_count > 256
        || bundle.total_bytes() > 16 * 1024 * 1024
    {
        return Err(MiddlewareReadApiError::InvalidData);
    }
    let product = bundle.instance().product();
    let loaded_at = bundle.loaded_at().to_rfc3339();
    let total_bytes = bundle.total_bytes().to_string();
    let mut raw_budget = MAX_RAW_TEXT_TOTAL_BYTES;
    let mut node_budget = TextBudget::new(MAX_NODE_TEXT_BYTES);
    let mut remaining_nodes = MAX_CONFIGURATION_NODES;
    let mut files = Vec::with_capacity(file_count.min(MAX_CONFIGURATION_FILES));
    let mut displayed_nodes = 0usize;
    let mut redacted_field_count = 0usize;
    let mut truncated = file_count > MAX_CONFIGURATION_FILES;
    let mut handles = HashSet::new();
    for (index, snapshot) in bundle
        .files()
        .iter()
        .take(MAX_CONFIGURATION_FILES)
        .enumerate()
    {
        if snapshot.target() != bundle.target()
            || snapshot.instance_id() != bundle.instance().id()
            || snapshot.product() != product
        {
            return Err(MiddlewareReadApiError::InvalidData);
        }
        let draft = snapshot.create_draft()?;
        let raw_selection = select_safe_raw_text(draft.safe_raw_text(), raw_budget);
        if let Some(raw_text) = &raw_selection.raw_text {
            raw_budget = raw_budget.saturating_sub(raw_text.len());
        }
        let file_handle =
            unique_handle("middleware-file", |candidate| handles.contains(candidate))?;
        handles.insert(file_handle.clone());
        let node_limit = remaining_nodes.min(MAX_NODES_PER_FILE);
        let (nodes, node_redacted, node_truncated) =
            project_nodes(&draft, node_limit, &mut node_budget);
        remaining_nodes = remaining_nodes.saturating_sub(nodes.len());
        displayed_nodes = displayed_nodes.saturating_add(nodes.len());
        let file_truncated = node_truncated || raw_selection.truncated;
        truncated |= file_truncated;
        let file_redacted = node_redacted + usize::from(raw_selection.redacted);
        redacted_field_count = redacted_field_count.saturating_add(file_redacted);
        files.push(MiddlewareConfigurationFileDto {
            file_handle,
            ordinal: index + 1,
            role: role_key(snapshot.role()),
            byte_length: snapshot.byte_len().to_string(),
            content_mode: if raw_selection.raw_text.is_some() {
                "raw-text"
            } else {
                "structured-only"
            },
            raw_text: raw_selection.raw_text,
            raw_text_unavailable_reason: raw_selection.reason,
            node_count: draft.nodes().len(),
            displayed_nodes: nodes.len(),
            nodes,
            contains_sensitive_values: draft.contains_sensitive_values(),
            redacted_field_count: file_redacted,
            truncated: file_truncated,
        });
    }
    let displayed = files.len();
    if displayed < file_count || remaining_nodes == 0 && files.iter().any(|file| file.truncated) {
        truncated = true;
    }
    Ok(MiddlewareConfigurationDto {
        discovery_handle: discovery_handle.to_owned(),
        instance_handle: instance_handle.to_owned(),
        product: product_key(product),
        loaded_at,
        total_bytes,
        file_count,
        unresolved_include_count,
        directory_manifest_count,
        files,
        displayed,
        displayed_nodes,
        redacted_field_count,
        truncated,
    })
}

struct RawTextSelection {
    raw_text: Option<String>,
    reason: &'static str,
    redacted: bool,
    truncated: bool,
}

fn select_safe_raw_text(value: Option<&str>, remaining: usize) -> RawTextSelection {
    let Some(value) = value else {
        return RawTextSelection {
            raw_text: None,
            reason: "not-safe-text",
            redacted: false,
            truncated: false,
        };
    };
    let sanitized = sanitize_plain_text(value);
    if sanitized.len() > MAX_RAW_TEXT_PER_FILE_BYTES || sanitized.len() > remaining {
        return RawTextSelection {
            raw_text: None,
            reason: "size-limit",
            redacted: false,
            truncated: true,
        };
    }
    RawTextSelection {
        raw_text: Some(sanitized),
        reason: "available",
        redacted: false,
        truncated: false,
    }
}

fn project_nodes(
    draft: &lovelyres_core::middleware::MiddlewareDraft,
    maximum: usize,
    budget: &mut TextBudget,
) -> (Vec<MiddlewareNodeDto>, usize, bool) {
    let node_count = draft.nodes().len();
    let mut redacted_count = 0usize;
    let mut truncated = node_count > maximum;
    let mut nodes = Vec::with_capacity(node_count.min(maximum));
    for (index, node) in draft.nodes().iter().take(maximum).enumerate() {
        let (name, redacted, text_truncated) =
            node.name.as_deref().map_or((None, false, false), |name| {
                let (name, redacted, truncated) = budget.take_public(name, MAX_NODE_NAME_BYTES);
                (Some(name), redacted, truncated)
            });
        redacted_count += usize::from(redacted);
        truncated |= text_truncated;
        let sensitive = draft
            .editable_value(index)
            .is_some_and(|value| value.sensitive);
        nodes.push(MiddlewareNodeDto {
            kind: node_kind_key(node.kind),
            name,
            depth: node.depth,
            editable: node.editable_value.is_some(),
            sensitive,
            redacted,
            text_truncated,
        });
    }
    (nodes, redacted_count, truncated)
}

fn build_history_snapshot(
    scope: BindingScope,
    records: Vec<MiddlewareChangeRecord>,
) -> Result<(MiddlewareSnapshot, MiddlewareHistoryDto), MiddlewareReadApiError> {
    let record_count = records.len();
    let history_handle = unique_handle("middleware-history", |_| false)?;
    let mut handles = HashSet::with_capacity(record_count.min(MAX_HISTORY_ENTRIES));
    let mut entries = Vec::with_capacity(record_count.min(MAX_HISTORY_ENTRIES));
    let mut projected_bytes = scope.storage_bytes().saturating_add(history_handle.len());
    let mut truncated = record_count > MAX_HISTORY_ENTRIES;
    for record in records.into_iter().take(MAX_HISTORY_ENTRIES) {
        if record.target != scope.target.identity {
            return Err(MiddlewareReadApiError::InvalidData);
        }
        let encoded_bytes = serialized_bytes(&record)?.saturating_add(256);
        if projected_bytes.saturating_add(encoded_bytes) > MAX_HISTORY_RAW_BYTES {
            truncated = true;
            break;
        }
        let history_item_handle =
            unique_handle("middleware-record", |candidate| handles.contains(candidate))?;
        entries.push(MiddlewareHistoryEntryDto {
            history_item_handle: history_item_handle.clone(),
            product: product_key(record.product),
            state: change_state_key(record.state),
            summary: format!(
                "{} 配置记录：{} B → {} B",
                record.product.label(),
                record.old_bytes,
                record.new_bytes,
            ),
            old_bytes: record.old_bytes.to_string(),
            new_bytes: record.new_bytes.to_string(),
            created_at: record.created_at.to_rfc3339(),
            updated_at: record.updated_at.to_rfc3339(),
        });
        projected_bytes = projected_bytes
            .saturating_add(encoded_bytes)
            .saturating_add(history_item_handle.len());
        handles.insert(history_item_handle);
    }
    let displayed = entries.len();
    truncated |= displayed < record_count;
    let dto = MiddlewareHistoryDto {
        history_handle: history_handle.clone(),
        expires_in_seconds: SNAPSHOT_TTL.as_secs(),
        entries,
        record_count,
        displayed,
        truncated,
    };
    let response_bytes = serialized_bytes(&dto)?;
    let stored_bytes = scope
        .storage_bytes()
        .saturating_add(history_handle.len())
        .saturating_add(response_bytes);
    if stored_bytes > MAX_SNAPSHOT_BYTES {
        return Err(MiddlewareReadApiError::OutputLimit);
    }
    let now = Instant::now();
    Ok((
        MiddlewareSnapshot {
            handle: history_handle,
            token: Uuid::new_v4(),
            scope,
            data: SnapshotData::History,
            stored_bytes,
            expires_at: now + SNAPSHOT_TTL,
            touched_at: now,
            active_reads: 0,
        },
        dto,
    ))
}

struct TextBudget {
    remaining: usize,
}

impl TextBudget {
    const fn new(maximum: usize) -> Self {
        Self { remaining: maximum }
    }

    fn take_public(&mut self, value: &str, maximum: usize) -> (String, bool, bool) {
        let sanitized = sanitize_plain_text(value);
        let maximum = maximum.min(self.remaining);
        let (bounded, truncated) = bounded_text(&sanitized, maximum);
        self.remaining = self.remaining.saturating_sub(bounded.len());
        (bounded, false, truncated)
    }
}

fn sanitize_plain_text(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '\n' | '\r' | '\t' => character,
            value if value.is_control() => '�',
            value => value,
        })
        .collect()
}

fn bounded_text(value: &str, maximum: usize) -> (String, bool) {
    if value.len() <= maximum {
        return (value.to_owned(), false);
    }
    let mut end = maximum;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    (value[..end].to_owned(), true)
}

const fn product_key(product: MiddlewareProduct) -> &'static str {
    match product {
        MiddlewareProduct::Nginx => "nginx",
        MiddlewareProduct::ApacheHttpd => "apache-httpd",
        MiddlewareProduct::Redis => "redis",
        MiddlewareProduct::Tomcat => "tomcat",
    }
}

fn public_instance_status(instance: &MiddlewareInstance) -> &'static str {
    match instance.active_state() {
        "active" => "active",
        "inactive" => "inactive",
        "failed" => "failed",
        "activating" => "activating",
        "deactivating" => "deactivating",
        "reloading" => "reloading",
        _ => "unknown",
    }
}

const fn role_key(role: MiddlewareConfigRole) -> &'static str {
    match role {
        MiddlewareConfigRole::Primary => "primary",
        MiddlewareConfigRole::Included => "included",
        MiddlewareConfigRole::TomcatWeb => "tomcat-web",
        MiddlewareConfigRole::TomcatContext => "tomcat-context",
        MiddlewareConfigRole::Properties => "properties",
        MiddlewareConfigRole::Logging => "logging",
        MiddlewareConfigRole::Users => "users",
        MiddlewareConfigRole::Other => "other",
    }
}

const fn node_kind_key(kind: MiddlewareDocumentNodeKind) -> &'static str {
    match kind {
        MiddlewareDocumentNodeKind::Preamble => "preamble",
        MiddlewareDocumentNodeKind::Whitespace => "whitespace",
        MiddlewareDocumentNodeKind::Comment => "comment",
        MiddlewareDocumentNodeKind::Directive => "directive",
        MiddlewareDocumentNodeKind::BlockStart => "block-start",
        MiddlewareDocumentNodeKind::BlockEnd => "block-end",
        MiddlewareDocumentNodeKind::ElementStart => "element-start",
        MiddlewareDocumentNodeKind::ElementEnd => "element-end",
        MiddlewareDocumentNodeKind::Attribute => "attribute",
        MiddlewareDocumentNodeKind::Text => "text",
        MiddlewareDocumentNodeKind::Cdata => "cdata",
        MiddlewareDocumentNodeKind::ProcessingInstruction => "processing-instruction",
        MiddlewareDocumentNodeKind::Declaration => "declaration",
        MiddlewareDocumentNodeKind::Opaque => "opaque",
    }
}

const fn change_state_key(state: MiddlewareChangeState) -> &'static str {
    match state {
        MiddlewareChangeState::RecoveryPending => "recovery-pending",
        MiddlewareChangeState::Applied => "applied",
        MiddlewareChangeState::AutomaticallyRestored => "automatically-restored",
        MiddlewareChangeState::RestoreFailed => "restore-failed",
    }
}

fn validate_handle(value: &str) -> Result<(), MiddlewareReadApiError> {
    if value.is_empty()
        || value.len() > MAX_HANDLE_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(MiddlewareReadApiError::InvalidHandle);
    }
    Ok(())
}

fn unique_handle(
    prefix: &str,
    exists: impl Fn(&str) -> bool,
) -> Result<String, MiddlewareReadApiError> {
    for _ in 0..16 {
        let candidate = format!("{prefix}-{}", Uuid::new_v4().simple());
        if candidate.len() <= MAX_HANDLE_BYTES && !exists(&candidate) {
            return Ok(candidate);
        }
    }
    Err(MiddlewareReadApiError::OutputLimit)
}

fn serialized_bytes(value: &impl Serialize) -> Result<usize, MiddlewareReadApiError> {
    serde_json::to_vec(value)
        .map(|encoded| encoded.len())
        .map_err(|_| MiddlewareReadApiError::InvalidData)
}

fn ensure_serialized_bound(
    value: &impl Serialize,
    maximum: usize,
) -> Result<(), MiddlewareReadApiError> {
    if serialized_bytes(value)? > maximum {
        return Err(MiddlewareReadApiError::OutputLimit);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use lovelyres_core::target::TargetIdentity;
    use serde_json::json;

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

    fn record(target: &BindingScope, state: &str) -> MiddlewareChangeRecord {
        serde_json::from_value(json!({
            "id": "11111111-1111-4111-8111-111111111111",
            "operation_id": "22222222-2222-4222-8222-222222222222",
            "target": target.target.identity.as_str(),
            "instance_id": "raw-instance-id",
            "product": "nginx",
            "unit": "nginx.service",
            "binary_path": "/usr/sbin/nginx",
            "fragment_path": "/usr/lib/systemd/system/nginx.service",
            "runtime_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "primary_config": "/etc/nginx/nginx.conf",
            "config_root": "/etc/nginx",
            "discovered_config_root": true,
            "path": "/etc/nginx/conf.d/site.conf",
            "remote_backup": "/var/lib/lovelyres/backups/site.conf",
            "old_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "new_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "old_bytes": 100,
            "new_bytes": 120,
            "validator": "nginx-config-test",
            "activation": "reload",
            "state": state,
            "created_at": "2026-08-24T01:02:03Z",
            "updated_at": "2026-08-24T01:03:04Z"
        }))
        .unwrap()
    }

    #[test]
    fn remote_text_is_plain_bounded_and_credential_like_values_are_redacted() {
        let mut budget = TextBudget::new(4096);
        for hostile in [
            "</code><script>plain()</script>",
            "<img src=x onerror=plain()>",
            "<button onclick=plain()>plain</button>",
        ] {
            let (value, redacted, truncated) = budget.take_public(hostile, 256);
            assert_eq!(value, hostile);
            assert!(!redacted);
            assert!(!truncated);
        }
        // A configuration line that sets a token is the finding, not a leak.
        let (value, redacted, _) = budget.take_public("token=remote-secret", 256);
        assert_eq!(value, "token=remote-secret");
        assert!(!redacted);
        let (value, _, _) = budget.take_public("line\u{0}tail", 256);
        assert_eq!(value, "line�tail");
        let (value, _, truncated) = budget.take_public("界界", 4);
        assert_eq!(value, "界");
        assert!(truncated);
    }

    #[test]
    fn raw_configuration_requires_core_permission_and_sidecar_budgets() {
        let safe = select_safe_raw_text(Some("events {}\nhttp {}"), 1024);
        assert_eq!(safe.raw_text.as_deref(), Some("events {}\nhttp {}"));
        assert_eq!(safe.reason, "available");
        let core_denied = select_safe_raw_text(None, 1024);
        assert!(core_denied.raw_text.is_none());
        assert_eq!(core_denied.reason, "not-safe-text");
        // A configuration that sets a password is the configuration.
        let credential_like = select_safe_raw_text(Some("password=secret"), 1024);
        assert_eq!(credential_like.raw_text.as_deref(), Some("password=secret"));
        assert!(!credential_like.redacted);
        let oversized = "x".repeat(MAX_RAW_TEXT_PER_FILE_BYTES + 1);
        let bounded = select_safe_raw_text(Some(&oversized), oversized.len());
        assert!(bounded.raw_text.is_none());
        assert!(bounded.truncated);
        assert_eq!(bounded.reason, "size-limit");
    }

    #[test]
    fn history_projection_hides_all_raw_identity_path_digest_and_command_evidence() {
        let current = scope("server", 1);
        let raw = record(&current, "applied");
        let forbidden = [
            raw.id.clone(),
            raw.operation_id.clone(),
            raw.instance_id.clone(),
            raw.unit.clone(),
            raw.binary_path.as_str().to_owned(),
            raw.path.as_str().to_owned(),
            raw.remote_backup.as_str().to_owned(),
            raw.old_sha256.clone(),
            raw.new_sha256.clone(),
        ];
        let (snapshot, dto) = build_history_snapshot(current.clone(), vec![raw]).unwrap();
        let text = serde_json::to_string(&dto).unwrap();
        for value in forbidden {
            assert!(!text.contains(&value), "leaked {value}");
        }
        assert!(!text.contains("nginx -t"));
        assert_eq!(dto.displayed, 1);
        let now = Instant::now();
        let mut registry = MiddlewareRegistry::default();
        registry.insert(snapshot).unwrap();
        assert!(
            registry
                .resolve_history_snapshot(&current, &dto.history_handle, now)
                .is_ok()
        );
        assert!(
            registry
                .resolve_history_snapshot(&scope("server", 2), &dto.history_handle, now)
                .is_err()
        );
        assert!(
            registry
                .resolve_history_snapshot(&current, &dto.history_handle, now + SNAPSHOT_TTL)
                .is_err()
        );
    }

    #[test]
    fn history_refresh_and_target_epoch_invalidate_old_snapshots() {
        let current = scope("server", 1);
        let next = scope("server", 2);
        let (first, first_dto) =
            build_history_snapshot(current.clone(), vec![record(&current, "applied")]).unwrap();
        let (second, second_dto) = build_history_snapshot(
            current.clone(),
            vec![record(&current, "automatically-restored")],
        )
        .unwrap();
        let mut registry = MiddlewareRegistry::default();
        registry.insert(first).unwrap();
        registry.insert(second).unwrap();
        assert!(!registry.snapshots.contains_key(&first_dto.history_handle));
        assert!(registry.snapshots.contains_key(&second_dto.history_handle));
        registry.prune(Instant::now(), Some(&next));
        assert!(registry.snapshots.is_empty());
        assert_eq!(registry.total_bytes, 0);
    }

    #[test]
    fn snapshot_scope_binds_handle_session_connection_and_target_guard() {
        let current = scope("server", 1);
        let (snapshot, dto) =
            build_history_snapshot(current.clone(), vec![record(&current, "applied")]).unwrap();
        let mut registry = MiddlewareRegistry::default();
        registry.insert(snapshot).unwrap();

        let mut wrong_handle = current.clone();
        wrong_handle.binding_handle = "binding-reused".to_owned();
        let mut wrong_session = current.clone();
        wrong_session.session_id = "session-reused".to_owned();
        let mut wrong_connection = current.clone();
        wrong_connection.connection_id = "connection-reused".to_owned();
        let mut wrong_target = current.clone();
        wrong_target.target.identity = TargetIdentity::new("other-server").unwrap();
        let mut wrong_generation = current.clone();
        wrong_generation.target.generation += 1;

        for candidate in [
            wrong_handle,
            wrong_session,
            wrong_connection,
            wrong_target,
            wrong_generation,
        ] {
            assert!(
                registry
                    .resolve_history_snapshot(&candidate, &dto.history_handle, Instant::now())
                    .is_err()
            );
        }
    }

    #[test]
    fn close_binding_removes_only_its_current_and_stale_snapshots() {
        let current = scope("server", 1);
        let mut stale = current.clone();
        stale.session_id = "session-server-stale".to_owned();
        stale.target.generation += 1;
        let other = scope("other", 1);

        let (mut current_snapshot, current_dto) =
            build_history_snapshot(current.clone(), vec![record(&current, "applied")]).unwrap();
        current_snapshot.active_reads = 1;
        let (stale_snapshot, stale_dto) = build_history_snapshot(
            stale.clone(),
            vec![record(&stale, "automatically-restored")],
        )
        .unwrap();
        let (other_snapshot, other_dto) =
            build_history_snapshot(other.clone(), vec![record(&other, "applied")]).unwrap();
        let other_bytes = other_snapshot.stored_bytes;

        let mut registry = MiddlewareRegistry::default();
        registry.insert(current_snapshot).unwrap();
        registry.insert(stale_snapshot).unwrap();
        registry.insert(other_snapshot).unwrap();
        registry.close_binding(&current.binding_handle);

        assert!(!registry.snapshots.contains_key(&current_dto.history_handle));
        assert!(!registry.snapshots.contains_key(&stale_dto.history_handle));
        assert!(registry.snapshots.contains_key(&other_dto.history_handle));
        assert_eq!(registry.total_bytes, other_bytes);
    }

    #[test]
    fn read_concurrency_is_bounded_globally_and_per_binding() {
        let state = Arc::new(Mutex::new(ConcurrencyState::default()));
        let permits = (0..MAX_GLOBAL_READS)
            .map(|index| ReadPermit::acquire(Arc::clone(&state), format!("binding-{index}")))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(ReadPermit::acquire(Arc::clone(&state), "extra".to_owned()).is_err());
        drop(permits);
        let first = ReadPermit::acquire(Arc::clone(&state), "same".to_owned()).unwrap();
        assert!(ReadPermit::acquire(Arc::clone(&state), "same".to_owned()).is_err());
        drop(first);
    }

    #[test]
    fn source_uses_only_three_core_reads_and_never_projects_forbidden_fields() {
        let source = include_str!("middleware_read_api.rs");
        for required in [
            ".middleware().discover(&session).await",
            ".load_configuration(&session, &instance)",
            ".middleware().history(session.target())",
            ".create_draft()",
            ".safe_raw_text()",
        ] {
            assert!(
                source.contains(required),
                "missing read boundary {required}"
            );
        }
        for forbidden in [
            ["plan_", "change"].concat(),
            ["execute_", "change"].concat(),
            ["plan_", "restore"].concat(),
            ["execute_", "restore"].concat(),
            ["confirm_", "middleware"].concat(),
            ["open_", "terminal"].concat(),
            ["open_", "file"].concat(),
            ["export_", "middleware"].concat(),
        ] {
            assert!(
                !source.contains(&forbidden),
                "forbidden surface {forbidden}"
            );
        }
        let history = build_history_snapshot(
            scope("server", 1),
            vec![record(&scope("server", 1), "applied")],
        )
        .unwrap()
        .1;
        let keys = serde_json::to_value(history).unwrap();
        let text = serde_json::to_string(&keys).unwrap();
        for forbidden_key in [
            "sessionId",
            "guard",
            "generation",
            "identity",
            "binaryPath",
            "configRoot",
            "primaryConfig",
            "remoteBackup",
            "sha256",
            "digest",
            "shell",
            "command",
        ] {
            assert!(!text.contains(forbidden_key));
        }
    }
}
