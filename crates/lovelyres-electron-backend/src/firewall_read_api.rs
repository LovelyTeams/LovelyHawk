//! Standalone Electron boundary for target-bound, read-only firewall investigation.
//!
//! Core owns remote command construction and the portable change history. The renderer receives
//! bounded plain text plus opaque snapshot/change capabilities; raw change identities, operation
//! identities, digests, managed paths, and every mutation/resolution primitive remain private.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use lovelyres_core::{
    BackendServices, CoreError,
    firewall::{
        FirewallBackend, FirewallChangeRecord, FirewallChangeState, FirewallEngine,
        FirewallInspection, FirewallMutationRequest,
    },
    ssh::BoundSshSession,
    target::TargetGuard,
};
use serde::Serialize;
use uuid::Uuid;

use crate::ssh_api::SshApi;

const MAX_HANDLE_BYTES: usize = 128;
const MAX_RULE_BYTES: usize = 256 * 1024;
const MAX_INSPECTION_RESPONSE_BYTES: usize = 320 * 1024;
const MAX_HISTORY_ENTRIES: usize = 256;
const MAX_HISTORY_LABEL_BYTES: usize = 512;
const MAX_HISTORY_ENTRY_BYTES: usize = 2 * 1024;
const MAX_HISTORY_RESPONSE_BYTES: usize = 512 * 1024;
const MAX_SNAPSHOT_BYTES: usize = 768 * 1024;
const MAX_SNAPSHOTS: usize = 12;
const MAX_REGISTRY_BYTES: usize = 4 * 1024 * 1024;
const MAX_GLOBAL_READS: usize = 8;
const MAX_READS_PER_BINDING: usize = 2;
const SNAPSHOT_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Clone)]
pub(crate) struct FirewallReadApi {
    services: BackendServices,
    ssh_api: Arc<SshApi>,
    snapshots: Arc<Mutex<SnapshotRegistry>>,
    concurrency: Arc<Mutex<ConcurrencyState>>,
}

impl fmt::Debug for FirewallReadApi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (snapshot_count, snapshot_bytes) = self
            .snapshots
            .lock()
            .map(|registry| (registry.snapshots.len(), registry.total_bytes))
            .unwrap_or_default();
        let active_reads = self
            .concurrency
            .lock()
            .map(|state| state.total)
            .unwrap_or_default();
        formatter
            .debug_struct("FirewallReadApi")
            .field("snapshot_count", &snapshot_count)
            .field("snapshot_bytes", &snapshot_bytes)
            .field("active_reads", &active_reads)
            .finish()
    }
}

impl FirewallReadApi {
    pub(crate) fn new(services: BackendServices, ssh_api: Arc<SshApi>) -> Self {
        Self {
            services,
            ssh_api,
            snapshots: Arc::new(Mutex::new(SnapshotRegistry::default())),
            concurrency: Arc::new(Mutex::new(ConcurrencyState::default())),
        }
    }

    pub(crate) async fn inspect(
        &self,
        binding_handle: &str,
    ) -> Result<FirewallInspectionDto, FirewallReadApiError> {
        let (session, scope) = self.capture_binding(binding_handle)?;
        self.prune_snapshots(&scope)?;
        let _permit = self.acquire_read(&scope)?;
        let inspection = self.services.firewall().inspect(&session).await?;
        self.validate_binding(&scope)?;
        if inspection.target != scope.target {
            return Err(FirewallReadApiError::BindingUnavailable);
        }
        let result =
            self.lock_snapshots()?
                .insert_inspection(scope.clone(), inspection, Instant::now())?;
        if let Err(error) = self.validate_binding(&scope) {
            self.remove_snapshot(&result.snapshot_handle);
            return Err(error);
        }
        Ok(result)
    }

    pub(crate) async fn list_history(
        &self,
        binding_handle: &str,
    ) -> Result<FirewallHistoryDto, FirewallReadApiError> {
        let (session, scope) = self.capture_binding(binding_handle)?;
        self.prune_snapshots(&scope)?;
        let _permit = self.acquire_read(&scope)?;
        let changes = self.services.firewall().list_changes(session.target())?;
        self.validate_binding(&scope)?;
        let result =
            self.lock_snapshots()?
                .insert_history(scope.clone(), changes, Instant::now())?;
        if let Err(error) = self.validate_binding(&scope) {
            self.remove_snapshot(&result.history_handle);
            return Err(error);
        }
        Ok(result)
    }

    pub(crate) fn close_binding(&self, binding_handle: &str) {
        if let Ok(mut registry) = self.snapshots.lock() {
            registry.close_binding(binding_handle);
        }
    }

    fn capture_binding(
        &self,
        binding_handle: &str,
    ) -> Result<(BoundSshSession, BindingScope), FirewallReadApiError> {
        validate_handle(binding_handle)?;
        let session = self
            .ssh_api
            .binding_session_clone(binding_handle)
            .map_err(|_| FirewallReadApiError::BindingUnavailable)?;
        self.services
            .target()
            .validate(session.target())
            .map_err(|_| FirewallReadApiError::BindingUnavailable)?;
        let scope = BindingScope::from_session(binding_handle, &session);
        Ok((session, scope))
    }

    fn validate_binding(
        &self,
        expected: &BindingScope,
    ) -> Result<BoundSshSession, FirewallReadApiError> {
        let (session, current) = self.capture_binding(&expected.binding_handle)?;
        if &current != expected {
            return Err(FirewallReadApiError::BindingUnavailable);
        }
        Ok(session)
    }

    fn acquire_read(&self, scope: &BindingScope) -> Result<ReadPermit, FirewallReadApiError> {
        ReadPermit::acquire(Arc::clone(&self.concurrency), scope.concurrency_key())
    }

    fn prune_snapshots(&self, scope: &BindingScope) -> Result<(), FirewallReadApiError> {
        self.lock_snapshots()?.prune(Instant::now(), Some(scope));
        Ok(())
    }

    fn remove_snapshot(&self, handle: &str) {
        if let Ok(mut registry) = self.snapshots.lock() {
            registry.remove(handle);
        }
    }

    fn lock_snapshots(&self) -> Result<MutexGuard<'_, SnapshotRegistry>, FirewallReadApiError> {
        self.snapshots
            .lock()
            .map_err(|_| FirewallReadApiError::RegistryUnavailable)
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FirewallInspectionDto {
    snapshot_handle: String,
    backend: &'static str,
    engine: &'static str,
    active: bool,
    rules: String,
    rules_truncated: bool,
    captured_at: String,
    expires_in_seconds: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FirewallHistoryDto {
    history_handle: String,
    entries: Vec<FirewallHistoryEntryDto>,
    displayed: usize,
    truncated: bool,
    expires_in_seconds: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FirewallHistoryEntryDto {
    change_handle: String,
    backend: &'static str,
    engine: &'static str,
    change_kind: &'static str,
    label: String,
    state: &'static str,
    ssh_port: u16,
    created_at: String,
    deadman_deadline: String,
    updated_at: String,
    text_truncated: bool,
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
            .saturating_add(std::mem::size_of::<u64>())
    }
}

impl fmt::Debug for BindingScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FirewallBindingScope([REDACTED])")
    }
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
    ) -> Result<Self, FirewallReadApiError> {
        {
            let mut current = state
                .lock()
                .map_err(|_| FirewallReadApiError::RegistryUnavailable)?;
            let binding_reads = current.per_binding.get(&key).copied().unwrap_or_default();
            if current.total >= MAX_GLOBAL_READS || binding_reads >= MAX_READS_PER_BINDING {
                return Err(FirewallReadApiError::ConcurrencyLimit);
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
struct SnapshotRegistry {
    snapshots: HashMap<String, SnapshotEntry>,
    total_bytes: usize,
}

impl fmt::Debug for SnapshotRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FirewallSnapshotRegistry")
            .field("snapshot_count", &self.snapshots.len())
            .field("total_bytes", &self.total_bytes)
            .finish()
    }
}

struct SnapshotEntry {
    scope: BindingScope,
    data: SnapshotData,
    bytes: usize,
    expires_at: Instant,
    touched_at: Instant,
}

enum SnapshotData {
    Inspection { _rules: String },
    History { changes: HashMap<String, String> },
}

impl SnapshotRegistry {
    fn prune(&mut self, now: Instant, current: Option<&BindingScope>) {
        let stale = self
            .snapshots
            .iter()
            .filter_map(|(handle, entry)| {
                let binding_changed = current.is_some_and(|current| {
                    entry.scope.binding_handle == current.binding_handle && entry.scope != *current
                });
                (entry.expires_at <= now || binding_changed).then_some(handle.clone())
            })
            .collect::<Vec<_>>();
        for handle in stale {
            self.remove(&handle);
        }
    }

    fn close_binding(&mut self, binding_handle: &str) {
        let mut removed_bytes = 0usize;
        self.snapshots.retain(|_, entry| {
            let keep = entry.scope.binding_handle != binding_handle;
            if !keep {
                removed_bytes = removed_bytes.saturating_add(entry.bytes);
            }
            keep
        });
        self.total_bytes = self.total_bytes.saturating_sub(removed_bytes);
    }

    fn insert_inspection(
        &mut self,
        scope: BindingScope,
        inspection: FirewallInspection,
        now: Instant,
    ) -> Result<FirewallInspectionDto, FirewallReadApiError> {
        self.prune(now, Some(&scope));
        let snapshot_handle = self.unique_snapshot_handle()?;
        let (rules, changed) = bounded_multiline(&inspection.rules, MAX_RULE_BYTES);
        let dto = FirewallInspectionDto {
            snapshot_handle: snapshot_handle.clone(),
            backend: backend_key(inspection.backend),
            engine: engine_key(inspection.engine),
            active: inspection.active,
            rules: rules.clone(),
            rules_truncated: inspection.rules_truncated || changed,
            captured_at: inspection.captured_at.to_rfc3339(),
            expires_in_seconds: SNAPSHOT_TTL.as_secs(),
        };
        let response_bytes = serialized_bytes(&dto)?;
        if response_bytes > MAX_INSPECTION_RESPONSE_BYTES {
            return Err(FirewallReadApiError::OutputLimit);
        }
        let bytes = response_bytes
            .saturating_add(rules.len())
            .saturating_add(scope.storage_bytes());
        self.make_room(bytes)?;
        self.total_bytes = self.total_bytes.saturating_add(bytes);
        self.snapshots.insert(
            snapshot_handle,
            SnapshotEntry {
                scope,
                data: SnapshotData::Inspection { _rules: rules },
                bytes,
                expires_at: now + SNAPSHOT_TTL,
                touched_at: now,
            },
        );
        Ok(dto)
    }

    fn insert_history(
        &mut self,
        scope: BindingScope,
        source: Vec<FirewallChangeRecord>,
        now: Instant,
    ) -> Result<FirewallHistoryDto, FirewallReadApiError> {
        self.prune(now, Some(&scope));
        let source_count = source.len();
        let reusable = self.reusable_history_handles(&scope);
        let mut used_handles = self.all_change_handles();
        let mut seen_ids = HashSet::new();
        let mut changes = HashMap::new();
        let mut entries = Vec::new();
        let mut response_bytes = 1024usize;
        let mut storage_bytes = 0usize;
        for change in source.into_iter().take(MAX_HISTORY_ENTRIES) {
            if !seen_ids.insert(change.id.clone()) {
                continue;
            }
            let change_handle = reusable
                .get(&change.id)
                .cloned()
                .unwrap_or(self.unique_change_handle(&used_handles)?);
            used_handles.insert(change_handle.clone());
            let entry = project_history_entry(change_handle.clone(), &change);
            let entry_bytes = serialized_bytes(&entry)?;
            let raw_bytes = change_handle.len().saturating_add(change.id.len());
            if entry_bytes > MAX_HISTORY_ENTRY_BYTES
                || response_bytes.saturating_add(entry_bytes) > MAX_HISTORY_RESPONSE_BYTES
                || response_bytes
                    .saturating_add(entry_bytes)
                    .saturating_add(storage_bytes)
                    .saturating_add(raw_bytes)
                    > MAX_SNAPSHOT_BYTES
            {
                break;
            }
            response_bytes = response_bytes.saturating_add(entry_bytes);
            storage_bytes = storage_bytes.saturating_add(raw_bytes);
            changes.insert(change_handle, change.id);
            entries.push(entry);
        }
        let displayed = entries.len();
        let history_handle = self.unique_snapshot_handle()?;
        let dto = FirewallHistoryDto {
            history_handle: history_handle.clone(),
            entries,
            displayed,
            truncated: displayed < source_count,
            expires_in_seconds: SNAPSHOT_TTL.as_secs(),
        };
        let response_bytes = serialized_bytes(&dto)?;
        if response_bytes > MAX_HISTORY_RESPONSE_BYTES {
            return Err(FirewallReadApiError::OutputLimit);
        }
        let bytes = response_bytes
            .saturating_add(storage_bytes)
            .saturating_add(scope.storage_bytes());
        self.make_room(bytes)?;
        self.total_bytes = self.total_bytes.saturating_add(bytes);
        self.snapshots.insert(
            history_handle,
            SnapshotEntry {
                scope,
                data: SnapshotData::History { changes },
                bytes,
                expires_at: now + SNAPSHOT_TTL,
                touched_at: now,
            },
        );
        Ok(dto)
    }

    fn reusable_history_handles(&self, scope: &BindingScope) -> HashMap<String, String> {
        let mut snapshots = self
            .snapshots
            .values()
            .filter(|entry| &entry.scope == scope)
            .collect::<Vec<_>>();
        snapshots.sort_by_key(|entry| entry.touched_at);
        snapshots
            .into_iter()
            .flat_map(|entry| match &entry.data {
                SnapshotData::History { changes } => changes
                    .iter()
                    .map(|(handle, raw_id)| (raw_id.clone(), handle.clone()))
                    .collect::<Vec<_>>(),
                SnapshotData::Inspection { .. } => Vec::new(),
            })
            .collect()
    }

    fn all_change_handles(&self) -> HashSet<String> {
        self.snapshots
            .values()
            .flat_map(|entry| match &entry.data {
                SnapshotData::History { changes } => changes.keys().cloned().collect::<Vec<_>>(),
                SnapshotData::Inspection { .. } => Vec::new(),
            })
            .collect()
    }

    fn unique_snapshot_handle(&self) -> Result<String, FirewallReadApiError> {
        unique_handle(|handle| self.handle_in_use(handle))
    }

    fn unique_change_handle(&self, used: &HashSet<String>) -> Result<String, FirewallReadApiError> {
        unique_handle(|handle| used.contains(handle) || self.handle_in_use(handle))
    }

    fn handle_in_use(&self, handle: &str) -> bool {
        self.snapshots.contains_key(handle)
            || self.snapshots.values().any(|entry| match &entry.data {
                SnapshotData::History { changes } => changes.contains_key(handle),
                SnapshotData::Inspection { .. } => false,
            })
    }

    fn make_room(&mut self, bytes: usize) -> Result<(), FirewallReadApiError> {
        if bytes > MAX_SNAPSHOT_BYTES || bytes > MAX_REGISTRY_BYTES {
            return Err(FirewallReadApiError::RegistryCapacity);
        }
        while self.snapshots.len() >= MAX_SNAPSHOTS
            || self.total_bytes.saturating_add(bytes) > MAX_REGISTRY_BYTES
        {
            let Some(oldest) = self
                .snapshots
                .iter()
                .min_by_key(|(_, entry)| entry.touched_at)
                .map(|(handle, _)| handle.clone())
            else {
                break;
            };
            self.remove(&oldest);
        }
        if self.snapshots.len() >= MAX_SNAPSHOTS
            || self.total_bytes.saturating_add(bytes) > MAX_REGISTRY_BYTES
        {
            return Err(FirewallReadApiError::RegistryCapacity);
        }
        Ok(())
    }

    fn remove(&mut self, handle: &str) {
        if let Some(snapshot) = self.snapshots.remove(handle) {
            self.total_bytes = self.total_bytes.saturating_sub(snapshot.bytes);
        }
    }
}

fn project_history_entry(
    change_handle: String,
    change: &FirewallChangeRecord,
) -> FirewallHistoryEntryDto {
    let (label, text_truncated) =
        bounded_single_line(&change.request.label(), MAX_HISTORY_LABEL_BYTES);
    FirewallHistoryEntryDto {
        change_handle,
        backend: backend_key(change.backend),
        engine: engine_key(change.engine),
        change_kind: request_key(&change.request),
        label,
        state: state_key(change.state),
        ssh_port: change.ssh_port,
        created_at: change.created_at.to_rfc3339(),
        deadman_deadline: change.deadman_deadline.to_rfc3339(),
        updated_at: change.updated_at.to_rfc3339(),
        text_truncated,
    }
}

const fn backend_key(value: FirewallBackend) -> &'static str {
    match value {
        FirewallBackend::Iptables => "iptables",
        FirewallBackend::Nftables => "nftables",
        FirewallBackend::Ufw => "ufw",
        FirewallBackend::Firewalld => "firewalld",
        FirewallBackend::Unknown => "unknown",
    }
}

const fn engine_key(value: FirewallEngine) -> &'static str {
    match value {
        FirewallEngine::Iptables => "iptables",
        FirewallEngine::Nftables => "nftables",
        FirewallEngine::Unavailable => "unavailable",
    }
}

const fn request_key(value: &FirewallMutationRequest) -> &'static str {
    match value {
        FirewallMutationRequest::BlockIpv4 { .. } => "block-ipv4",
        FirewallMutationRequest::TemporaryBlockIpv4 { .. } => "temporary-block-ipv4",
        FirewallMutationRequest::AllowTcpPort { .. } => "allow-tcp-port",
        FirewallMutationRequest::IsolateInbound => "isolate-inbound",
    }
}

const fn state_key(value: FirewallChangeState) -> &'static str {
    match value {
        FirewallChangeState::AwaitingKeep => "awaiting-keep",
        FirewallChangeState::Kept => "kept",
        FirewallChangeState::Restored => "restored",
        FirewallChangeState::AutoRestored => "auto-restored",
    }
}

fn bounded_multiline(value: &str, maximum_bytes: usize) -> (String, bool) {
    let mut output = String::with_capacity(value.len().min(maximum_bytes));
    let mut changed = false;
    let mut characters = value.chars().peekable();
    while let Some(character) = characters.next() {
        let projected = match character {
            '\r' => {
                if characters.peek() == Some(&'\n') {
                    characters.next();
                }
                changed = true;
                '\n'
            }
            '\n' | '\t' => character,
            value if value.is_control() => {
                changed = true;
                '\u{fffd}'
            }
            value => value,
        };
        if output.len().saturating_add(projected.len_utf8()) > maximum_bytes {
            changed = true;
            break;
        }
        output.push(projected);
    }
    if output.len() < value.len() && !changed {
        changed = true;
    }
    (output, changed)
}

fn bounded_single_line(value: &str, maximum_bytes: usize) -> (String, bool) {
    let mut output = String::with_capacity(value.len().min(maximum_bytes));
    let mut changed = false;
    for character in value.chars() {
        let projected = if character.is_control() {
            changed = true;
            '\u{fffd}'
        } else {
            character
        };
        if output.len().saturating_add(projected.len_utf8()) > maximum_bytes {
            changed = true;
            break;
        }
        output.push(projected);
    }
    (output, changed)
}

fn serialized_bytes<T: Serialize>(value: &T) -> Result<usize, FirewallReadApiError> {
    serde_json::to_vec(value)
        .map(|value| value.len())
        .map_err(|_| FirewallReadApiError::OutputLimit)
}

fn validate_handle(handle: &str) -> Result<(), FirewallReadApiError> {
    let canonical = Uuid::parse_str(handle)
        .is_ok_and(|parsed| handle.len() == 36 && parsed.to_string() == handle);
    if handle.is_empty() || handle.len() > MAX_HANDLE_BYTES || !canonical {
        return Err(FirewallReadApiError::InvalidHandle);
    }
    Ok(())
}

fn unique_handle(collision: impl Fn(&str) -> bool) -> Result<String, FirewallReadApiError> {
    for _ in 0..8 {
        let handle = Uuid::new_v4().to_string();
        if !collision(&handle) {
            return Ok(handle);
        }
    }
    Err(FirewallReadApiError::RegistryCapacity)
}

pub(crate) enum FirewallReadApiError {
    Core,
    BindingUnavailable,
    InvalidHandle,
    RegistryCapacity,
    RegistryUnavailable,
    ConcurrencyLimit,
    OutputLimit,
}

impl fmt::Debug for FirewallReadApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core => "Core([REDACTED])",
            Self::BindingUnavailable => "BindingUnavailable",
            Self::InvalidHandle => "InvalidHandle",
            Self::RegistryCapacity => "RegistryCapacity",
            Self::RegistryUnavailable => "RegistryUnavailable",
            Self::ConcurrencyLimit => "ConcurrencyLimit",
            Self::OutputLimit => "OutputLimit",
        })
    }
}

impl fmt::Display for FirewallReadApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core => "the firewall read operation failed",
            Self::BindingUnavailable => "the SSH binding is missing or stale",
            Self::InvalidHandle => "the firewall capability is invalid",
            Self::RegistryCapacity => "the firewall snapshot registry is full",
            Self::RegistryUnavailable => "the firewall snapshot registry is unavailable",
            Self::ConcurrencyLimit => "too many firewall reads are active",
            Self::OutputLimit => "the firewall result exceeded its safety limit",
        })
    }
}

impl std::error::Error for FirewallReadApiError {}

impl From<CoreError> for FirewallReadApiError {
    fn from(error: CoreError) -> Self {
        // A host that went away is not a failure of this feature. One lost
        // connection reported once beats a dozen features each announcing
        // their own breakage.
        if matches!(error, CoreError::SshDisconnected { .. }) {
            return Self::BindingUnavailable;
        }
        Self::Core
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use lovelyres_core::{PortableStore, target::TargetIdentity};

    use super::*;

    fn scope(name: &str, generation: u64) -> BindingScope {
        scope_with_binding("11111111-1111-4111-8111-111111111111", name, generation)
    }

    fn scope_with_binding(binding_handle: &str, name: &str, generation: u64) -> BindingScope {
        BindingScope {
            binding_handle: binding_handle.to_owned(),
            session_id: format!("session-{generation}"),
            connection_id: name.to_owned(),
            target: TargetGuard {
                identity: TargetIdentity::new(name).unwrap(),
                generation,
            },
        }
    }

    #[derive(Debug)]
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("lovelyres-firewall-read-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn read_api() -> (TestRoot, FirewallReadApi) {
        let root = TestRoot::new();
        let services =
            BackendServices::new(PortableStore::prepare(root.0.clone()).unwrap()).unwrap();
        let ssh_api = Arc::new(SshApi::new(services.clone()));
        (root, FirewallReadApi::new(services, ssh_api))
    }

    fn change(id: &str, target: &str, state: FirewallChangeState) -> FirewallChangeRecord {
        let simple = id.replace('-', "");
        serde_json::from_value(serde_json::json!({
            "id": id,
            "operation_id": "operation-secret",
            "last_operation_id": "last-operation-secret",
            "target": target,
            "backend": "firewalld",
            "engine": "iptables",
            "request": { "kind": "block-ipv4", "source": "203.0.113.7" },
            "ssh_port": 2222,
            "remote_root": format!("/tmp/.lovelyres_fw/{id}"),
            "object_name": format!("LR_{}", &simple[..16]).to_ascii_uppercase(),
            "preflight_sha256": "ab".repeat(32),
            "state": state,
            "created_at": "2026-08-24T00:00:00Z",
            "deadman_deadline": "2026-08-24T00:01:00Z",
            "updated_at": "2026-08-24T00:00:30Z"
        }))
        .unwrap()
    }

    fn inspection(rules: String) -> FirewallInspection {
        let captured_at = change(
            "33333333-3333-4333-8333-333333333333",
            "target-a",
            FirewallChangeState::Restored,
        )
        .created_at;
        FirewallInspection {
            target: scope("target-a", 1).target,
            backend: FirewallBackend::Nftables,
            engine: FirewallEngine::Nftables,
            active: true,
            rules,
            rules_truncated: false,
            rules_sha256: "secret-digest".to_owned(),
            captured_at,
        }
    }

    #[test]
    fn inspection_is_plain_bounded_and_excludes_target_and_digest() {
        let mut registry = SnapshotRegistry::default();
        let dto = registry
            .insert_inspection(
                scope("target-a", 1),
                inspection(format!(
                    "<script>steal()</script>\0\r\n{}",
                    "x".repeat(MAX_RULE_BYTES)
                )),
                Instant::now(),
            )
            .unwrap();
        let json = serde_json::to_string(&dto).unwrap();
        assert!(json.contains("<script>steal()</script>"));
        assert!(!json.contains("secret-digest"));
        assert!(!json.contains("target-a"));
        assert!(!json.contains("\\u0000"));
        assert!(dto.rules.len() <= MAX_RULE_BYTES);
        assert!(dto.rules_truncated);
        assert!(serialized_bytes(&dto).unwrap() <= MAX_INSPECTION_RESPONSE_BYTES);
    }

    #[test]
    fn history_projection_uses_stable_target_scoped_handles_and_hides_raw_identity() {
        let now = Instant::now();
        let raw_id = "22222222-2222-4222-8222-222222222222";
        let mut registry = SnapshotRegistry::default();
        let first = registry
            .insert_history(
                scope("target-a", 1),
                vec![change(
                    raw_id,
                    "target-a",
                    FirewallChangeState::AwaitingKeep,
                )],
                now,
            )
            .unwrap();
        let handle = first.entries[0].change_handle.clone();
        let second = registry
            .insert_history(
                scope("target-a", 1),
                vec![change(
                    raw_id,
                    "target-a",
                    FirewallChangeState::AwaitingKeep,
                )],
                now + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(second.entries[0].change_handle, handle);
        let json = serde_json::to_string(&second).unwrap();
        let simple = raw_id.replace('-', "");
        let remote_root = format!("/tmp/.lovelyres_fw/{raw_id}");
        let object_name = format!("LR_{}", &simple[..16]).to_ascii_uppercase();
        for secret in [
            raw_id,
            "operation-secret",
            "last-operation-secret",
            &remote_root,
            &object_name,
            &"ab".repeat(32),
        ] {
            assert!(!json.contains(secret));
        }
        let other = registry
            .insert_history(
                scope("target-b", 1),
                vec![change(raw_id, "target-b", FirewallChangeState::Kept)],
                now + Duration::from_secs(2),
            )
            .unwrap();
        assert_ne!(other.entries[0].change_handle, handle);
    }

    #[test]
    fn target_switch_expiry_and_capacity_remove_old_capabilities() {
        let now = Instant::now();
        let mut registry = SnapshotRegistry::default();
        let first = registry
            .insert_inspection(scope("target-a", 1), inspection("rules".to_owned()), now)
            .unwrap();
        registry.prune(now, Some(&scope("target-a", 2)));
        assert!(!registry.snapshots.contains_key(&first.snapshot_handle));
        for generation in 2..=(MAX_SNAPSHOTS as u64 + 4) {
            registry
                .insert_inspection(
                    scope(&format!("target-{generation}"), generation),
                    inspection("rules".to_owned()),
                    now + Duration::from_secs(generation),
                )
                .unwrap();
        }
        assert!(registry.snapshots.len() <= MAX_SNAPSHOTS);
        assert!(registry.total_bytes <= MAX_REGISTRY_BYTES);
        registry.prune(now + SNAPSHOT_TTL + Duration::from_secs(100), None);
        assert!(registry.snapshots.is_empty());
    }

    #[test]
    fn close_binding_immediately_invalidates_only_its_inspection_and_history_capabilities() {
        let (_root, api) = read_api();
        let now = Instant::now();
        let closed_binding = "11111111-1111-4111-8111-111111111111";
        let retained_binding = "22222222-2222-4222-8222-222222222222";
        let closed_scope = scope_with_binding(closed_binding, "target-a", 1);
        let retained_scope = scope_with_binding(retained_binding, "target-b", 1);
        let (
            closed_inspection,
            closed_history,
            closed_change,
            retained_inspection,
            retained_history,
            retained_change,
            retained_bytes,
        ) = {
            let mut registry = api.snapshots.lock().unwrap();
            let closed_inspection = registry
                .insert_inspection(
                    closed_scope.clone(),
                    inspection("closed rules".to_owned()),
                    now,
                )
                .unwrap()
                .snapshot_handle;
            let closed_history = registry
                .insert_history(
                    closed_scope,
                    vec![change(
                        "33333333-3333-4333-8333-333333333333",
                        "target-a",
                        FirewallChangeState::AwaitingKeep,
                    )],
                    now,
                )
                .unwrap();
            let retained_inspection = registry
                .insert_inspection(
                    retained_scope.clone(),
                    inspection("retained rules".to_owned()),
                    now,
                )
                .unwrap()
                .snapshot_handle;
            let retained_history = registry
                .insert_history(
                    retained_scope,
                    vec![change(
                        "44444444-4444-4444-8444-444444444444",
                        "target-b",
                        FirewallChangeState::Kept,
                    )],
                    now,
                )
                .unwrap();
            let closed_change = closed_history.entries[0].change_handle.clone();
            let retained_change = retained_history.entries[0].change_handle.clone();
            let retained_bytes: usize = registry
                .snapshots
                .iter()
                .filter(|(_, entry)| entry.scope.binding_handle == retained_binding)
                .map(|(_, entry)| entry.bytes)
                .sum();
            (
                closed_inspection,
                closed_history.history_handle,
                closed_change,
                retained_inspection,
                retained_history.history_handle,
                retained_change,
                retained_bytes,
            )
        };

        api.close_binding(closed_binding);

        let registry = api.snapshots.lock().unwrap();
        for invalidated in [closed_inspection, closed_history, closed_change] {
            assert!(!registry.handle_in_use(&invalidated));
        }
        for retained in [retained_inspection, retained_history, retained_change] {
            assert!(registry.handle_in_use(&retained));
        }
        assert_eq!(registry.total_bytes, retained_bytes);
        assert!(
            registry
                .snapshots
                .values()
                .all(|entry| entry.scope.binding_handle == retained_binding)
        );
    }

    #[test]
    fn hostile_labels_are_single_line_and_utf8_bounded() {
        let (label, truncated) = bounded_single_line(
            &format!("</button><script>steal()</script>\n{}", "界".repeat(300)),
            MAX_HISTORY_LABEL_BYTES,
        );
        assert!(label.contains("<script>steal()</script>"));
        assert!(!label.contains('\n'));
        assert!(label.len() <= MAX_HISTORY_LABEL_BYTES);
        assert!(truncated);
    }

    #[test]
    fn concurrency_is_bounded_and_released() {
        let state = Arc::new(Mutex::new(ConcurrencyState::default()));
        let permits = (0..MAX_READS_PER_BINDING)
            .map(|_| ReadPermit::acquire(Arc::clone(&state), "binding".to_owned()).unwrap())
            .collect::<Vec<_>>();
        assert!(ReadPermit::acquire(Arc::clone(&state), "binding".to_owned()).is_err());
        drop(permits);
        assert!(ReadPermit::acquire(state, "binding".to_owned()).is_ok());
    }

    #[test]
    fn handles_are_canonical_and_debug_is_redacted() {
        assert!(validate_handle("11111111-1111-4111-8111-111111111111").is_ok());
        assert!(validate_handle("{11111111-1111-4111-8111-111111111111}").is_err());
        let binding = scope("secret-target", 42);
        assert!(!format!("{binding:?}").contains("secret-target"));
        let error = FirewallReadApiError::from(CoreError::Validation {
            subject: "secret",
            message: "hidden".to_owned(),
        });
        assert!(!format!("{error:?}").contains("hidden"));
        assert!(!error.to_string().contains("hidden"));
    }
}
