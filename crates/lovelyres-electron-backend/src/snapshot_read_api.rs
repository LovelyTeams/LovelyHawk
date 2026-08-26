//! Bounded read-only Electron boundary for stored directory and forensic snapshots.
//!
//! Core snapshot ids, target metadata, digests, and remote archive paths remain
//! sidecar-owned. Renderer requests are limited to target-bound opaque handles.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use lovelyres_core::{
    BackendServices, CoreError,
    snapshot::{
        DirectorySnapshot, ForensicCollector, ForensicFieldDiff, ForensicSnapshot,
        ForensicSnapshotDiff, SnapshotItemKind, SnapshotPreset,
    },
    ssh::BoundSshSession,
    target::TargetGuard,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ssh_api::SshApi;

const MAX_HANDLE_BYTES: usize = 128;
const MAX_DIRECTORY_SNAPSHOTS: usize = 64;
const MAX_FORENSIC_SNAPSHOTS: usize = 10;
const MAX_SNAPSHOTS: usize = MAX_DIRECTORY_SNAPSHOTS + MAX_FORENSIC_SNAPSHOTS;
const MAX_DIRECTORY_ITEMS: usize = 8;
const MAX_COLLECTORS: usize = 12;
const MAX_CATALOGS: usize = 8;
const MAX_CATALOG_BYTES: usize = 128 * 1024;
const MAX_REGISTRY_BYTES: usize = 1024 * 1024;
const MAX_ACTIVE_LISTS: usize = 2;
const MAX_ACTIVE_READS_PER_CATALOG: usize = 3;
const MAX_ACTIVE_READS_GLOBAL: usize = 8;
const MAX_FORENSIC_LINES: usize = 2_048;
const MAX_FORENSIC_LINES_PER_FIELD: usize = 512;
const MAX_FORENSIC_LINE_BYTES: usize = 4 * 1024;
const MAX_FORENSIC_TEXT_BYTES: usize = 512 * 1024;
const MAX_DIFF_LINES: usize = 1_000;
const MAX_DIFF_LINES_PER_DIRECTION: usize = 200;
const MAX_DIFF_LINE_BYTES: usize = 4 * 1024;
const MAX_DIFF_TEXT_BYTES: usize = 512 * 1024;
const MAX_LIST_RESPONSE_BYTES: usize = 128 * 1024;
const MAX_DETAIL_RESPONSE_BYTES: usize = 768 * 1024;
const MAX_DIFF_RESPONSE_BYTES: usize = 768 * 1024;
const SNAPSHOT_TTL: Duration = Duration::from_secs(5 * 60);
const REDACTED_LINE: &str = "[SENSITIVE SNAPSHOT TEXT REDACTED]";
const FAILED_COLLECTOR_LINE: &str = "[FORENSIC COLLECTOR FAILED]";
const FULL_REDACTION_COLLECTOR_COUNT: usize = 7;
const MAX_POLICY_MARKER_BYTES: usize = REDACTED_LINE.len();

#[derive(Clone)]
pub(crate) struct SnapshotReadApi {
    services: BackendServices,
    ssh_api: Arc<SshApi>,
    registry: Arc<Mutex<SnapshotRegistry>>,
}

impl fmt::Debug for SnapshotReadApi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (catalogs, bytes, reads, lists) = self
            .registry
            .lock()
            .map(|registry| {
                (
                    registry.catalogs.len(),
                    registry.total_bytes(),
                    registry.active_reads_global,
                    registry.active_list_bindings.len(),
                )
            })
            .unwrap_or_default();
        formatter
            .debug_struct("SnapshotReadApi")
            .field("catalog_count", &catalogs)
            .field("registry_bytes", &bytes)
            .field("active_reads", &reads)
            .field("active_lists", &lists)
            .finish()
    }
}

impl SnapshotReadApi {
    pub(crate) fn new(services: BackendServices, ssh_api: Arc<SshApi>) -> Self {
        Self {
            services,
            ssh_api,
            registry: Arc::new(Mutex::new(SnapshotRegistry::default())),
        }
    }

    pub(crate) fn list_snapshots(
        &self,
        binding_handle: &str,
    ) -> Result<SnapshotListDto, SnapshotReadApiError> {
        let (session, scope) = self.capture_binding(binding_handle)?;
        let _permit = self.begin_list(&scope)?;
        let directory = self.services.snapshots().list_directory(session.target())?;
        let forensic = self.services.snapshots().list_forensic(session.target())?;
        self.validate_binding(&scope)?;
        let (candidates, truncated) = build_candidates(directory, forensic)?;
        let mut registry = self.lock_registry()?;
        registry.prune(Instant::now());
        let dto = registry.replace_catalog(scope.clone(), candidates, truncated)?;
        drop(registry);
        self.validate_binding(&scope)?;
        Ok(dto)
    }

    pub(crate) fn get_detail(
        &self,
        binding_handle: &str,
        snapshot_handle: &str,
    ) -> Result<SnapshotDetailDto, SnapshotReadApiError> {
        validate_handle(snapshot_handle)?;
        let (session, scope) = self.capture_binding(binding_handle)?;
        let (access, records, _permit) = self.begin_read(&scope, &[snapshot_handle])?;
        let record = records
            .first()
            .ok_or(SnapshotReadApiError::InvalidSnapshot)?;
        let dto = match record.kind {
            StoredSnapshotKind::Directory => {
                let snapshots = self.services.snapshots().list_directory(session.target())?;
                if snapshots.len() > MAX_DIRECTORY_SNAPSHOTS {
                    return Err(SnapshotReadApiError::Capacity);
                }
                let snapshot = snapshots
                    .into_iter()
                    .find(|snapshot| record.matches_directory(snapshot))
                    .ok_or(SnapshotReadApiError::SnapshotStale)?;
                SnapshotDetailDto::Directory(project_directory_detail(record, snapshot)?)
            }
            StoredSnapshotKind::Forensic => {
                let snapshots = self.services.snapshots().list_forensic(session.target())?;
                if snapshots.len() > MAX_FORENSIC_SNAPSHOTS {
                    return Err(SnapshotReadApiError::Capacity);
                }
                let snapshot = snapshots
                    .into_iter()
                    .find(|snapshot| record.matches_forensic(snapshot))
                    .ok_or(SnapshotReadApiError::SnapshotStale)?;
                SnapshotDetailDto::Forensic(project_forensic_detail(record, snapshot)?)
            }
        };
        self.validate_binding(&scope)?;
        self.verify_access(&access, &records)?;
        ensure_serialized_bound(&dto, MAX_DETAIL_RESPONSE_BYTES)?;
        self.validate_binding(&scope)?;
        self.verify_access(&access, &records)?;
        Ok(dto)
    }

    pub(crate) fn diff_forensic(
        &self,
        binding_handle: &str,
        input: SnapshotDiffInput,
    ) -> Result<SnapshotDiffDto, SnapshotReadApiError> {
        let input = input.validate()?;
        let (session, scope) = self.capture_binding(binding_handle)?;
        let handles = [
            input.older_snapshot_handle.as_str(),
            input.newer_snapshot_handle.as_str(),
        ];
        let (access, records, _permit) = self.begin_read(&scope, &handles)?;
        let older = records
            .first()
            .ok_or(SnapshotReadApiError::InvalidSnapshot)?;
        let newer = records
            .get(1)
            .ok_or(SnapshotReadApiError::InvalidSnapshot)?;
        if older.kind != StoredSnapshotKind::Forensic
            || newer.kind != StoredSnapshotKind::Forensic
            || older.captured_at >= newer.captured_at
        {
            return Err(SnapshotReadApiError::InvalidInput);
        }
        let diff = self.services.snapshots().diff_forensic(
            session.target(),
            &older.raw_id,
            &newer.raw_id,
        )?;
        let snapshots = self.services.snapshots().list_forensic(session.target())?;
        if snapshots.len() > MAX_FORENSIC_SNAPSHOTS {
            return Err(SnapshotReadApiError::Capacity);
        }
        let older_snapshot = snapshots
            .iter()
            .find(|snapshot| older.matches_forensic(snapshot))
            .ok_or(SnapshotReadApiError::SnapshotStale)?;
        let newer_snapshot = snapshots
            .iter()
            .find(|snapshot| newer.matches_forensic(snapshot))
            .ok_or(SnapshotReadApiError::SnapshotStale)?;
        self.validate_binding(&scope)?;
        self.verify_access(&access, &records)?;
        let dto = project_diff(older, newer, older_snapshot, newer_snapshot, diff)?;
        ensure_serialized_bound(&dto, MAX_DIFF_RESPONSE_BYTES)?;
        self.validate_binding(&scope)?;
        self.verify_access(&access, &records)?;
        Ok(dto)
    }

    pub(crate) fn close_binding(&self, binding_handle: &str) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.close_binding(binding_handle);
        }
    }

    fn capture_binding(
        &self,
        binding_handle: &str,
    ) -> Result<(BoundSshSession, BindingScope), SnapshotReadApiError> {
        validate_handle(binding_handle)?;
        let session = self
            .ssh_api
            .binding_session_clone(binding_handle)
            .map_err(|_| SnapshotReadApiError::BindingUnavailable)?;
        self.services
            .target()
            .validate(session.target())
            .map_err(|_| SnapshotReadApiError::BindingUnavailable)?;
        let scope = BindingScope::from_session(binding_handle, &session);
        Ok((session, scope))
    }

    fn validate_binding(&self, expected: &BindingScope) -> Result<(), SnapshotReadApiError> {
        let (_, current) = self.capture_binding(&expected.binding_handle)?;
        if &current != expected {
            return Err(SnapshotReadApiError::BindingUnavailable);
        }
        Ok(())
    }

    fn begin_list(&self, scope: &BindingScope) -> Result<ListPermit, SnapshotReadApiError> {
        let mut registry = self.lock_registry()?;
        registry.prune(Instant::now());
        registry.begin_list(scope)?;
        Ok(ListPermit {
            registry: Arc::clone(&self.registry),
            binding_handle: scope.binding_handle.clone(),
        })
    }

    fn begin_read(
        &self,
        scope: &BindingScope,
        handles: &[&str],
    ) -> Result<(SnapshotAccess, Vec<StoredSnapshot>, ReadPermit), SnapshotReadApiError> {
        let mut registry = self.lock_registry()?;
        registry.prune(Instant::now());
        let (access, records) = registry.begin_read(scope, handles)?;
        let permit = ReadPermit {
            registry: Arc::clone(&self.registry),
            binding_handle: scope.binding_handle.clone(),
            token: access.token,
        };
        Ok((access, records, permit))
    }

    fn verify_access(
        &self,
        access: &SnapshotAccess,
        records: &[StoredSnapshot],
    ) -> Result<(), SnapshotReadApiError> {
        let registry = self.lock_registry()?;
        let current = registry.verify(access)?;
        for expected in records {
            if !current.records.iter().any(|record| record == expected) {
                return Err(SnapshotReadApiError::SnapshotStale);
            }
        }
        Ok(())
    }

    fn lock_registry(&self) -> Result<MutexGuard<'_, SnapshotRegistry>, SnapshotReadApiError> {
        self.registry
            .lock()
            .map_err(|_| SnapshotReadApiError::RegistryUnavailable)
    }
}

pub(crate) enum SnapshotReadApiError {
    Core,
    BindingUnavailable,
    InvalidHandle,
    InvalidInput,
    InvalidSnapshot,
    SnapshotStale,
    Capacity,
    RegistryUnavailable,
}

impl fmt::Debug for SnapshotReadApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core => "Core([REDACTED])",
            Self::BindingUnavailable => "BindingUnavailable",
            Self::InvalidHandle => "InvalidHandle",
            Self::InvalidInput => "InvalidInput",
            Self::InvalidSnapshot => "InvalidSnapshot",
            Self::SnapshotStale => "SnapshotStale",
            Self::Capacity => "Capacity",
            Self::RegistryUnavailable => "RegistryUnavailable",
        })
    }
}

impl fmt::Display for SnapshotReadApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core => "the snapshot investigation failed",
            Self::BindingUnavailable => "the SSH binding is missing or stale",
            Self::InvalidHandle => "the snapshot handle is invalid",
            Self::InvalidInput => "the snapshot request is invalid",
            Self::InvalidSnapshot => "the snapshot capability is missing or stale",
            Self::SnapshotStale => "the snapshot changed while it was being read",
            Self::Capacity => "the snapshot read boundary reached its capacity",
            Self::RegistryUnavailable => "the snapshot registry is unavailable",
        })
    }
}

impl std::error::Error for SnapshotReadApiError {}

impl From<CoreError> for SnapshotReadApiError {
    fn from(error: CoreError) -> Self {
        // The renderer only ever sees a fixed message, so without this the
        // reason a page failed is lost before anyone can read it.
        tracing::warn!(operation = "SnapshotRead", error = %error, "core operation failed");
        // A host that went away is not a failure of this feature. One lost
        // connection reported once beats a dozen features each announcing
        // their own breakage.
        if matches!(error, CoreError::SshDisconnected { .. }) {
            return Self::BindingUnavailable;
        }
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
}

impl fmt::Debug for BindingScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BindingScope([REDACTED])")
    }
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SnapshotDiffInput {
    older_snapshot_handle: String,
    newer_snapshot_handle: String,
}

impl fmt::Debug for SnapshotDiffInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SnapshotDiffInput([OPAQUE])")
    }
}

impl SnapshotDiffInput {
    fn validate(self) -> Result<Self, SnapshotReadApiError> {
        validate_handle(&self.older_snapshot_handle)?;
        validate_handle(&self.newer_snapshot_handle)?;
        if self.older_snapshot_handle == self.newer_snapshot_handle {
            return Err(SnapshotReadApiError::InvalidInput);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PublicSnapshotKind {
    Directory,
    Forensic,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SnapshotListDto {
    expires_in_seconds: u64,
    snapshots: Vec<SnapshotListItemDto>,
    directory_count: usize,
    forensic_count: usize,
    truncated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SnapshotListItemDto {
    snapshot_handle: String,
    kind: PublicSnapshotKind,
    captured_at: String,
    item_count: usize,
    completed_collectors: Option<usize>,
    failed_collectors: Option<usize>,
}

#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum SnapshotDetailDto {
    Directory(DirectorySnapshotDetailDto),
    Forensic(ForensicSnapshotDetailDto),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DirectorySnapshotDetailDto {
    snapshot_handle: String,
    kind: PublicSnapshotKind,
    captured_at: String,
    items: Vec<DirectorySnapshotItemDto>,
    truncated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DirectorySnapshotItemDto {
    preset: PublicSnapshotPreset,
    kind: PublicSnapshotItemKind,
    bytes: String,
    present: bool,
    archive_availability: PublicArchiveAvailability,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PublicArchiveAvailability {
    NotChecked,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PublicSnapshotPreset {
    Etc,
    CurrentCrontab,
    Passwd,
    Shadow,
    AuthorizedKeys,
    WebRoot,
    CronSpool,
    RootHome,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PublicSnapshotItemKind {
    File,
    Directory,
    Crontab,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ForensicSnapshotDetailDto {
    snapshot_handle: String,
    kind: PublicSnapshotKind,
    captured_at: String,
    total_collectors: usize,
    completed_collectors: usize,
    failed_collectors: usize,
    fields: Vec<ForensicFieldDto>,
    redacted_line_count: usize,
    truncated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ForensicFieldDto {
    collector: PublicForensicCollector,
    text: String,
    redacted_line_count: usize,
    truncated: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
enum PublicForensicCollector {
    Processes,
    NetworkConnections,
    ListeningPorts,
    LoginHistory,
    CronJobs,
    StartupServices,
    AuthorizedKeys,
    Sudoers,
    RunningUsers,
    LoadedModules,
    RecentModifiedFiles,
    EnvVariables,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SnapshotDiffDto {
    older_snapshot_handle: String,
    newer_snapshot_handle: String,
    fields: Vec<ForensicDiffFieldDto>,
    added_line_count: usize,
    removed_line_count: usize,
    redacted_line_count: usize,
    truncated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ForensicDiffFieldDto {
    collector: PublicForensicCollector,
    added: Vec<String>,
    removed: Vec<String>,
    redacted_line_count: usize,
    truncated: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StoredSnapshotKind {
    Directory,
    Forensic,
}

impl StoredSnapshotKind {
    const fn public(self) -> PublicSnapshotKind {
        match self {
            Self::Directory => PublicSnapshotKind::Directory,
            Self::Forensic => PublicSnapshotKind::Forensic,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct StoredSnapshot {
    handle: String,
    raw_id: String,
    integrity: String,
    kind: StoredSnapshotKind,
    captured_at: String,
    item_count: usize,
    completed_collectors: Option<usize>,
    failed_collectors: Option<usize>,
}

impl StoredSnapshot {
    fn matches_directory(&self, snapshot: &DirectorySnapshot) -> bool {
        self.kind == StoredSnapshotKind::Directory
            && self.raw_id == snapshot.id
            && self.integrity == snapshot.record_sha256
            && self.captured_at == snapshot.created_at.to_rfc3339()
            && self.item_count == snapshot.items.len()
    }

    fn matches_forensic(&self, snapshot: &ForensicSnapshot) -> bool {
        self.kind == StoredSnapshotKind::Forensic
            && self.raw_id == snapshot.id
            && self.integrity == snapshot.sha256
            && self.captured_at == snapshot.timestamp.to_rfc3339()
            && self.item_count == snapshot.collection.total
            && self.completed_collectors == Some(snapshot.collection.completed)
            && self.failed_collectors == Some(snapshot.collection.failed)
    }

    fn same_source_as(&self, candidate: &SnapshotCandidate) -> bool {
        self.raw_id == candidate.raw_id
            && self.integrity == candidate.integrity
            && self.kind == candidate.kind
    }

    fn list_dto(&self) -> SnapshotListItemDto {
        SnapshotListItemDto {
            snapshot_handle: self.handle.clone(),
            kind: self.kind.public(),
            captured_at: self.captured_at.clone(),
            item_count: self.item_count,
            completed_collectors: self.completed_collectors,
            failed_collectors: self.failed_collectors,
        }
    }
}

struct SnapshotCandidate {
    raw_id: String,
    integrity: String,
    kind: StoredSnapshotKind,
    captured_at: String,
    item_count: usize,
    completed_collectors: Option<usize>,
    failed_collectors: Option<usize>,
}

struct SnapshotCatalog {
    token: Uuid,
    scope: BindingScope,
    created_at: Instant,
    expires_at: Instant,
    active_reads: usize,
    stored_bytes: usize,
    records: Vec<StoredSnapshot>,
}

#[derive(Clone)]
struct SnapshotAccess {
    binding_handle: String,
    token: Uuid,
    scope: BindingScope,
}

#[derive(Default)]
struct SnapshotRegistry {
    catalogs: HashMap<String, SnapshotCatalog>,
    active_reads_global: usize,
    active_list_bindings: HashSet<String>,
}

impl SnapshotRegistry {
    fn prune(&mut self, now: Instant) {
        self.catalogs
            .retain(|_, catalog| catalog.expires_at > now || catalog.active_reads > 0);
    }

    fn total_bytes(&self) -> usize {
        self.catalogs
            .values()
            .map(|catalog| catalog.stored_bytes)
            .sum()
    }

    fn begin_list(&mut self, scope: &BindingScope) -> Result<(), SnapshotReadApiError> {
        if self.active_list_bindings.len() >= MAX_ACTIVE_LISTS
            || !self
                .active_list_bindings
                .insert(scope.binding_handle.clone())
        {
            return Err(SnapshotReadApiError::Capacity);
        }
        Ok(())
    }

    fn release_list(&mut self, binding_handle: &str) {
        self.active_list_bindings.remove(binding_handle);
    }

    fn close_binding(&mut self, binding_handle: &str) {
        self.active_list_bindings.remove(binding_handle);
        self.catalogs.remove(binding_handle);
    }

    fn replace_catalog(
        &mut self,
        scope: BindingScope,
        candidates: Vec<SnapshotCandidate>,
        truncated: bool,
    ) -> Result<SnapshotListDto, SnapshotReadApiError> {
        let previous = self
            .catalogs
            .get(&scope.binding_handle)
            .filter(|catalog| catalog.scope == scope);
        let mut records = Vec::with_capacity(candidates.len());
        let mut used_handles = HashSet::new();
        for candidate in candidates {
            let reused = previous.and_then(|catalog| {
                catalog
                    .records
                    .iter()
                    .find(|record| record.same_source_as(&candidate))
                    .map(|record| record.handle.clone())
            });
            let handle = match reused {
                Some(handle) if used_handles.insert(handle.clone()) => handle,
                _ => unique_snapshot_handle(&used_handles)?,
            };
            used_handles.insert(handle.clone());
            records.push(StoredSnapshot {
                handle,
                raw_id: candidate.raw_id,
                integrity: candidate.integrity,
                kind: candidate.kind,
                captured_at: candidate.captured_at,
                item_count: candidate.item_count,
                completed_collectors: candidate.completed_collectors,
                failed_collectors: candidate.failed_collectors,
            });
        }
        let stored_bytes = records.iter().try_fold(512_usize, |total, record| {
            total
                .checked_add(record.handle.len())
                .and_then(|total| total.checked_add(record.raw_id.len()))
                .and_then(|total| total.checked_add(record.integrity.len()))
                .and_then(|total| total.checked_add(record.captured_at.len()))
                .and_then(|total| total.checked_add(128))
                .ok_or(SnapshotReadApiError::Capacity)
        })?;
        if records.len() > MAX_SNAPSHOTS || stored_bytes > MAX_CATALOG_BYTES {
            return Err(SnapshotReadApiError::Capacity);
        }
        self.catalogs.remove(&scope.binding_handle);
        while self.catalogs.len() >= MAX_CATALOGS
            || self.total_bytes().saturating_add(stored_bytes) > MAX_REGISTRY_BYTES
        {
            let candidate = self
                .catalogs
                .iter()
                .filter(|(_, catalog)| catalog.active_reads == 0)
                .min_by_key(|(_, catalog)| catalog.created_at)
                .map(|(binding, _)| binding.clone())
                .ok_or(SnapshotReadApiError::Capacity)?;
            self.catalogs.remove(&candidate);
        }
        let directory_count = records
            .iter()
            .filter(|record| record.kind == StoredSnapshotKind::Directory)
            .count();
        let forensic_count = records.len().saturating_sub(directory_count);
        let dto = SnapshotListDto {
            expires_in_seconds: SNAPSHOT_TTL.as_secs(),
            snapshots: records.iter().map(StoredSnapshot::list_dto).collect(),
            directory_count,
            forensic_count,
            truncated,
        };
        ensure_serialized_bound(&dto, MAX_LIST_RESPONSE_BYTES)?;
        let now = Instant::now();
        self.catalogs.insert(
            scope.binding_handle.clone(),
            SnapshotCatalog {
                token: Uuid::new_v4(),
                scope,
                created_at: now,
                expires_at: now + SNAPSHOT_TTL,
                active_reads: 0,
                stored_bytes,
                records,
            },
        );
        Ok(dto)
    }

    fn begin_read(
        &mut self,
        scope: &BindingScope,
        handles: &[&str],
    ) -> Result<(SnapshotAccess, Vec<StoredSnapshot>), SnapshotReadApiError> {
        if handles.is_empty()
            || handles.len() > 2
            || self.active_reads_global >= MAX_ACTIVE_READS_GLOBAL
        {
            return Err(SnapshotReadApiError::Capacity);
        }
        if handles
            .iter()
            .any(|handle| validate_handle(handle).is_err())
            || handles.iter().copied().collect::<HashSet<_>>().len() != handles.len()
        {
            return Err(SnapshotReadApiError::InvalidHandle);
        }
        let catalog = self
            .catalogs
            .get_mut(&scope.binding_handle)
            .filter(|catalog| catalog.scope == *scope && catalog.expires_at > Instant::now())
            .ok_or(SnapshotReadApiError::InvalidSnapshot)?;
        if catalog.active_reads >= MAX_ACTIVE_READS_PER_CATALOG {
            return Err(SnapshotReadApiError::Capacity);
        }
        let records = handles
            .iter()
            .map(|handle| {
                catalog
                    .records
                    .iter()
                    .find(|record| record.handle == *handle)
                    .cloned()
                    .ok_or(SnapshotReadApiError::InvalidSnapshot)
            })
            .collect::<Result<Vec<_>, _>>()?;
        catalog.active_reads += 1;
        self.active_reads_global += 1;
        Ok((
            SnapshotAccess {
                binding_handle: scope.binding_handle.clone(),
                token: catalog.token,
                scope: scope.clone(),
            },
            records,
        ))
    }

    fn release_read(&mut self, binding_handle: &str, token: Uuid) {
        self.active_reads_global = self.active_reads_global.saturating_sub(1);
        if let Some(catalog) = self
            .catalogs
            .get_mut(binding_handle)
            .filter(|catalog| catalog.token == token)
        {
            catalog.active_reads = catalog.active_reads.saturating_sub(1);
        }
    }

    fn verify(&self, access: &SnapshotAccess) -> Result<&SnapshotCatalog, SnapshotReadApiError> {
        self.catalogs
            .get(&access.binding_handle)
            .filter(|catalog| {
                catalog.token == access.token
                    && catalog.scope == access.scope
                    && catalog.expires_at > Instant::now()
            })
            .ok_or(SnapshotReadApiError::SnapshotStale)
    }
}

struct ListPermit {
    registry: Arc<Mutex<SnapshotRegistry>>,
    binding_handle: String,
}

impl Drop for ListPermit {
    fn drop(&mut self) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.release_list(&self.binding_handle);
        }
    }
}

struct ReadPermit {
    registry: Arc<Mutex<SnapshotRegistry>>,
    binding_handle: String,
    token: Uuid,
}

impl Drop for ReadPermit {
    fn drop(&mut self) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.release_read(&self.binding_handle, self.token);
        }
    }
}

fn build_candidates(
    directory: Vec<DirectorySnapshot>,
    forensic: Vec<ForensicSnapshot>,
) -> Result<(Vec<SnapshotCandidate>, bool), SnapshotReadApiError> {
    let truncated =
        directory.len() > MAX_DIRECTORY_SNAPSHOTS || forensic.len() > MAX_FORENSIC_SNAPSHOTS;
    let mut seen_directory = HashSet::new();
    let mut seen_forensic = HashSet::new();
    let mut candidates = Vec::with_capacity(MAX_SNAPSHOTS);
    for snapshot in directory.into_iter().take(MAX_DIRECTORY_SNAPSHOTS) {
        if snapshot.items.is_empty()
            || snapshot.items.len() > MAX_DIRECTORY_ITEMS
            || !seen_directory.insert(snapshot.id.clone())
        {
            return Err(SnapshotReadApiError::SnapshotStale);
        }
        candidates.push(SnapshotCandidate {
            raw_id: snapshot.id,
            integrity: snapshot.record_sha256,
            kind: StoredSnapshotKind::Directory,
            captured_at: snapshot.created_at.to_rfc3339(),
            item_count: snapshot.items.len(),
            completed_collectors: None,
            failed_collectors: None,
        });
    }
    for snapshot in forensic.into_iter().take(MAX_FORENSIC_SNAPSHOTS) {
        if snapshot.collection.total != MAX_COLLECTORS
            || snapshot.collection.completed != snapshot.collection.total
            || snapshot.collection.failed > snapshot.collection.total
            || !seen_forensic.insert(snapshot.id.clone())
        {
            return Err(SnapshotReadApiError::SnapshotStale);
        }
        candidates.push(SnapshotCandidate {
            raw_id: snapshot.id,
            integrity: snapshot.sha256,
            kind: StoredSnapshotKind::Forensic,
            captured_at: snapshot.timestamp.to_rfc3339(),
            item_count: snapshot.collection.total,
            completed_collectors: Some(snapshot.collection.completed),
            failed_collectors: Some(snapshot.collection.failed),
        });
    }
    candidates.sort_by(|left, right| {
        right
            .captured_at
            .cmp(&left.captured_at)
            .then_with(|| kind_order(left.kind).cmp(&kind_order(right.kind)))
    });
    Ok((candidates, truncated))
}

const fn kind_order(kind: StoredSnapshotKind) -> u8 {
    match kind {
        StoredSnapshotKind::Directory => 0,
        StoredSnapshotKind::Forensic => 1,
    }
}

fn project_directory_detail(
    record: &StoredSnapshot,
    snapshot: DirectorySnapshot,
) -> Result<DirectorySnapshotDetailDto, SnapshotReadApiError> {
    if snapshot.items.is_empty() || snapshot.items.len() > MAX_DIRECTORY_ITEMS {
        return Err(SnapshotReadApiError::SnapshotStale);
    }
    let mut presets = BTreeSet::new();
    let items = snapshot
        .items
        .into_iter()
        .map(|item| {
            if !presets.insert(item.preset) {
                return Err(SnapshotReadApiError::SnapshotStale);
            }
            Ok(DirectorySnapshotItemDto {
                preset: public_preset(item.preset),
                kind: public_item_kind(item.kind),
                bytes: item.bytes.to_string(),
                present: item.present,
                archive_availability: PublicArchiveAvailability::NotChecked,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(DirectorySnapshotDetailDto {
        snapshot_handle: record.handle.clone(),
        kind: PublicSnapshotKind::Directory,
        captured_at: record.captured_at.clone(),
        items,
        truncated: false,
    })
}

fn project_forensic_detail(
    record: &StoredSnapshot,
    snapshot: ForensicSnapshot,
) -> Result<ForensicSnapshotDetailDto, SnapshotReadApiError> {
    if snapshot.collection.total != MAX_COLLECTORS
        || snapshot.collection.completed != snapshot.collection.total
        || snapshot.collection.failed > snapshot.collection.total
    {
        return Err(SnapshotReadApiError::SnapshotStale);
    }
    let sensitive = forensic_sensitive_values(&snapshot);
    let mut budget = LineBudget::new(
        MAX_FORENSIC_LINES - FULL_REDACTION_COLLECTOR_COUNT,
        MAX_FORENSIC_TEXT_BYTES - FULL_REDACTION_COLLECTOR_COUNT * MAX_POLICY_MARKER_BYTES,
    );
    let mut fields = Vec::with_capacity(MAX_COLLECTORS);
    let mut redacted_line_count = 0;
    let mut truncated = false;
    for collector in ForensicCollector::ALL {
        let field = project_text_field(snapshot.data.get(collector), &sensitive, &mut budget);
        redacted_line_count += field.redacted_line_count;
        truncated |= field.truncated;
        fields.push(ForensicFieldDto {
            collector: public_collector(collector),
            text: field.text,
            redacted_line_count: field.redacted_line_count,
            truncated: field.truncated,
        });
    }
    Ok(ForensicSnapshotDetailDto {
        snapshot_handle: record.handle.clone(),
        kind: PublicSnapshotKind::Forensic,
        captured_at: record.captured_at.clone(),
        total_collectors: snapshot.collection.total,
        completed_collectors: snapshot.collection.completed,
        failed_collectors: snapshot.collection.failed,
        fields,
        redacted_line_count,
        truncated,
    })
}

fn project_diff(
    older_record: &StoredSnapshot,
    newer_record: &StoredSnapshot,
    older_snapshot: &ForensicSnapshot,
    newer_snapshot: &ForensicSnapshot,
    diff: ForensicSnapshotDiff,
) -> Result<SnapshotDiffDto, SnapshotReadApiError> {
    if diff.older_id != older_record.raw_id || diff.newer_id != newer_record.raw_id {
        return Err(SnapshotReadApiError::SnapshotStale);
    }
    let mut by_collector = diff
        .fields
        .into_iter()
        .map(|field| (field.collector, field))
        .collect::<BTreeMap<_, _>>();
    if by_collector.len() != MAX_COLLECTORS {
        return Err(SnapshotReadApiError::SnapshotStale);
    }
    let mut sensitive = forensic_sensitive_values(older_snapshot);
    sensitive.extend(forensic_sensitive_values(newer_snapshot));
    sensitive.sort();
    sensitive.dedup();
    let maximum_policy_markers = FULL_REDACTION_COLLECTOR_COUNT * 2;
    let mut budget = LineBudget::new(
        MAX_DIFF_LINES - maximum_policy_markers,
        MAX_DIFF_TEXT_BYTES - maximum_policy_markers * MAX_POLICY_MARKER_BYTES,
    );
    let mut fields = Vec::with_capacity(MAX_COLLECTORS);
    let mut added_line_count = 0;
    let mut removed_line_count = 0;
    let mut redacted_line_count = 0;
    let mut truncated = false;
    for collector in ForensicCollector::ALL {
        let field = by_collector
            .remove(&collector)
            .ok_or(SnapshotReadApiError::SnapshotStale)?;
        let projected = project_diff_field(field, &sensitive, &mut budget);
        added_line_count += projected.added.len();
        removed_line_count += projected.removed.len();
        redacted_line_count += projected.redacted_line_count;
        truncated |= projected.truncated;
        fields.push(projected);
    }
    if !by_collector.is_empty() {
        return Err(SnapshotReadApiError::SnapshotStale);
    }
    Ok(SnapshotDiffDto {
        older_snapshot_handle: older_record.handle.clone(),
        newer_snapshot_handle: newer_record.handle.clone(),
        fields,
        added_line_count,
        removed_line_count,
        redacted_line_count,
        truncated,
    })
}

struct ProjectedTextField {
    text: String,
    redacted_line_count: usize,
    truncated: bool,
}

fn project_text_field(
    source: &str,
    sensitive: &[String],
    budget: &mut LineBudget,
) -> ProjectedTextField {
    let source_lines = source.lines().count();
    let mut output = Vec::new();
    let mut redacted = 0;
    let mut truncated = false;
    for line in source.lines().take(MAX_FORENSIC_LINES_PER_FIELD) {
        let Some(projected) = budget.take(line, sensitive, MAX_FORENSIC_LINE_BYTES) else {
            truncated = true;
            break;
        };
        redacted += usize::from(projected.redacted);
        truncated |= projected.truncated;
        output.push(projected.text);
    }
    truncated |= output.len() < source_lines;
    ProjectedTextField {
        text: output.join("\n"),
        redacted_line_count: redacted,
        truncated,
    }
}

fn project_diff_field(
    source: ForensicFieldDiff,
    sensitive: &[String],
    budget: &mut LineBudget,
) -> ForensicDiffFieldDto {
    let added_source_len = source.added.len();
    let removed_source_len = source.removed.len();
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut redacted_line_count = 0;
    let mut truncated = false;
    for line in source.added.into_iter().take(MAX_DIFF_LINES_PER_DIRECTION) {
        let Some(projected) = budget.take(&line, sensitive, MAX_DIFF_LINE_BYTES) else {
            truncated = true;
            break;
        };
        redacted_line_count += usize::from(projected.redacted);
        truncated |= projected.truncated;
        added.push(projected.text);
    }
    for line in source
        .removed
        .into_iter()
        .take(MAX_DIFF_LINES_PER_DIRECTION)
    {
        let Some(projected) = budget.take(&line, sensitive, MAX_DIFF_LINE_BYTES) else {
            truncated = true;
            break;
        };
        redacted_line_count += usize::from(projected.redacted);
        truncated |= projected.truncated;
        removed.push(projected.text);
    }
    truncated |= added.len() < added_source_len || removed.len() < removed_source_len;
    ForensicDiffFieldDto {
        collector: public_collector(source.collector),
        added,
        removed,
        redacted_line_count,
        truncated,
    }
}

struct ProjectedLine {
    text: String,
    redacted: bool,
    truncated: bool,
}

struct LineBudget {
    remaining_lines: usize,
    remaining_bytes: usize,
}

impl LineBudget {
    const fn new(remaining_lines: usize, remaining_bytes: usize) -> Self {
        Self {
            remaining_lines,
            remaining_bytes,
        }
    }

    fn take(
        &mut self,
        value: &str,
        sensitive: &[String],
        maximum_bytes: usize,
    ) -> Option<ProjectedLine> {
        if self.remaining_lines == 0 || self.remaining_bytes == 0 {
            return None;
        }
        let failed = is_collector_failure(value);
        let redacted = contains_sensitive_material(value, sensitive);
        let normalized = if failed {
            FAILED_COLLECTOR_LINE.to_owned()
        } else if redacted {
            REDACTED_LINE.to_owned()
        } else {
            normalize_plain_text(value)
        };
        if (failed || redacted) && self.remaining_bytes < normalized.len() {
            return None;
        }
        let limit = maximum_bytes.min(self.remaining_bytes);
        let (text, truncated) = bounded_text(&normalized, limit);
        if text.is_empty() && !normalized.is_empty() {
            return None;
        }
        self.remaining_lines -= 1;
        self.remaining_bytes = self.remaining_bytes.saturating_sub(text.len());
        Some(ProjectedLine {
            text,
            redacted: redacted || failed,
            truncated,
        })
    }
}

fn is_collector_failure(value: &str) -> bool {
    value.starts_with("(failed to collect:") || value.starts_with("(collection failed:")
}

fn forensic_sensitive_values(snapshot: &ForensicSnapshot) -> Vec<String> {
    [
        snapshot.id.as_str(),
        snapshot.server.as_str(),
        snapshot.target.identity.as_str(),
        snapshot.target.session_id.as_str(),
        snapshot.target.host.as_str(),
        snapshot.target.username.as_str(),
        snapshot.target.host_key_fingerprint.as_str(),
    ]
    .into_iter()
    .filter(|value| !value.is_empty())
    .map(|value| value.to_ascii_lowercase())
    .collect()
}

/// A collected line is scrubbed only when it embeds one of our own values —
/// the snapshot id, the target identity, its session or its host key. What the
/// line says about the target is the evidence and is shown as collected.
fn contains_sensitive_material(value: &str, sensitive: &[String]) -> bool {
    let lower = value.to_ascii_lowercase();
    sensitive
        .iter()
        .any(|marker| lower.contains(marker.as_str()))
}

fn normalize_plain_text(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() && character != '\t' {
                '\u{fffd}'
            } else {
                character
            }
        })
        .collect()
}

fn bounded_text(value: &str, maximum_bytes: usize) -> (String, bool) {
    if value.len() <= maximum_bytes {
        return (value.to_owned(), false);
    }
    let mut boundary = maximum_bytes.min(value.len());
    while boundary > 0 && !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    (value[..boundary].to_owned(), true)
}

const fn public_preset(preset: SnapshotPreset) -> PublicSnapshotPreset {
    match preset {
        SnapshotPreset::Etc => PublicSnapshotPreset::Etc,
        SnapshotPreset::CurrentCrontab => PublicSnapshotPreset::CurrentCrontab,
        SnapshotPreset::Passwd => PublicSnapshotPreset::Passwd,
        SnapshotPreset::Shadow => PublicSnapshotPreset::Shadow,
        SnapshotPreset::AuthorizedKeys => PublicSnapshotPreset::AuthorizedKeys,
        SnapshotPreset::WebRoot => PublicSnapshotPreset::WebRoot,
        SnapshotPreset::CronSpool => PublicSnapshotPreset::CronSpool,
        SnapshotPreset::RootHome => PublicSnapshotPreset::RootHome,
    }
}

const fn public_item_kind(kind: SnapshotItemKind) -> PublicSnapshotItemKind {
    match kind {
        SnapshotItemKind::File => PublicSnapshotItemKind::File,
        SnapshotItemKind::Directory => PublicSnapshotItemKind::Directory,
        SnapshotItemKind::Crontab => PublicSnapshotItemKind::Crontab,
    }
}

const fn public_collector(collector: ForensicCollector) -> PublicForensicCollector {
    match collector {
        ForensicCollector::Processes => PublicForensicCollector::Processes,
        ForensicCollector::NetworkConnections => PublicForensicCollector::NetworkConnections,
        ForensicCollector::ListeningPorts => PublicForensicCollector::ListeningPorts,
        ForensicCollector::LoginHistory => PublicForensicCollector::LoginHistory,
        ForensicCollector::CronJobs => PublicForensicCollector::CronJobs,
        ForensicCollector::StartupServices => PublicForensicCollector::StartupServices,
        ForensicCollector::AuthorizedKeys => PublicForensicCollector::AuthorizedKeys,
        ForensicCollector::Sudoers => PublicForensicCollector::Sudoers,
        ForensicCollector::RunningUsers => PublicForensicCollector::RunningUsers,
        ForensicCollector::LoadedModules => PublicForensicCollector::LoadedModules,
        ForensicCollector::RecentModifiedFiles => PublicForensicCollector::RecentModifiedFiles,
        ForensicCollector::EnvVariables => PublicForensicCollector::EnvVariables,
    }
}

fn validate_handle(value: &str) -> Result<(), SnapshotReadApiError> {
    if value.is_empty()
        || value.len() > MAX_HANDLE_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(SnapshotReadApiError::InvalidHandle);
    }
    Ok(())
}

fn unique_snapshot_handle(used: &HashSet<String>) -> Result<String, SnapshotReadApiError> {
    for _ in 0..8 {
        let handle = Uuid::new_v4().to_string();
        validate_handle(&handle)?;
        if !used.contains(&handle) {
            return Ok(handle);
        }
    }
    Err(SnapshotReadApiError::Capacity)
}

fn ensure_serialized_bound<T: Serialize>(
    value: &T,
    maximum_bytes: usize,
) -> Result<(), SnapshotReadApiError> {
    let encoded = serde_json::to_vec(value).map_err(|_| SnapshotReadApiError::Capacity)?;
    if encoded.len() > maximum_bytes {
        return Err(SnapshotReadApiError::Capacity);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use lovelyres_core::{
        snapshot::{
            DirectorySnapshotItem, ForensicCollectionSummary, ForensicData, ForensicFieldDiff,
            ForensicSnapshotDiff, ForensicTarget,
        },
        target::TargetIdentity,
    };
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

    fn directory(id: &str, timestamp: &str) -> DirectorySnapshot {
        DirectorySnapshot {
            id: id.to_owned(),
            target: TargetIdentity::new("server").unwrap(),
            created_at: timestamp.parse().unwrap(),
            remote_root: format!("/tmp/.lovelyres_snap/{id}"),
            items: vec![DirectorySnapshotItem {
                preset: SnapshotPreset::Etc,
                source: "/etc".to_owned(),
                kind: SnapshotItemKind::Directory,
                archive_path: format!("/tmp/.lovelyres_snap/{id}/etc.tar"),
                archive_sha256: "a".repeat(64),
                content_sha256: "b".repeat(64),
                bytes: 42,
                present: true,
            }],
            record_sha256: "c".repeat(64),
        }
    }

    fn forensic(id: &str, timestamp: &str, processes: &str) -> ForensicSnapshot {
        let data = ForensicData {
            processes: processes.to_owned(),
            ..ForensicData::default()
        };
        ForensicSnapshot {
            id: id.to_owned(),
            timestamp: timestamp.parse().unwrap(),
            server: "host-secret.test".to_owned(),
            target: ForensicTarget {
                identity: TargetIdentity::new("server").unwrap(),
                session_id: "session-secret".to_owned(),
                host: "host-secret.test".to_owned(),
                port: 22,
                username: "operator-secret".to_owned(),
                host_key_fingerprint: "SHA256:fingerprint-secret".to_owned(),
            },
            collection: ForensicCollectionSummary {
                total: MAX_COLLECTORS,
                completed: MAX_COLLECTORS,
                failed: 0,
            },
            data,
            sha256: "d".repeat(64),
        }
    }

    #[test]
    fn catalog_maps_raw_ids_to_stable_opaque_binding_handles() {
        let (candidates, truncated) = build_candidates(
            vec![directory(
                "11111111-1111-4111-8111-111111111111",
                "2026-08-23T00:00:00Z",
            )],
            vec![forensic(
                "snap-22222222-2222-4222-8222-222222222222",
                "2026-08-24T00:00:00Z",
                "process",
            )],
        )
        .unwrap();
        let mut registry = SnapshotRegistry::default();
        let first = registry
            .replace_catalog(scope("server", 1), candidates, truncated)
            .unwrap();
        let first_handles = first
            .snapshots
            .iter()
            .map(|item| item.snapshot_handle.clone())
            .collect::<Vec<_>>();
        let (late_access, _) = registry
            .begin_read(&scope("server", 1), &[&first_handles[0]])
            .unwrap();
        let (candidates, truncated) = build_candidates(
            vec![directory(
                "11111111-1111-4111-8111-111111111111",
                "2026-08-23T00:00:00Z",
            )],
            vec![forensic(
                "snap-22222222-2222-4222-8222-222222222222",
                "2026-08-24T00:00:00Z",
                "process",
            )],
        )
        .unwrap();
        let refreshed = registry
            .replace_catalog(scope("server", 1), candidates, truncated)
            .unwrap();
        assert_eq!(
            first_handles,
            refreshed
                .snapshots
                .iter()
                .map(|item| item.snapshot_handle.clone())
                .collect::<Vec<_>>()
        );
        assert!(registry.verify(&late_access).is_err());
        registry.release_read(&late_access.binding_handle, late_access.token);
        let text = serde_json::to_string(&refreshed).unwrap();
        assert!(!text.contains("11111111"));
        assert!(!text.contains("22222222"));
        assert!(!text.contains("host-secret"));
        assert!(!text.contains("SHA256"));
    }

    #[test]
    fn registry_is_ttl_target_concurrency_and_capacity_bounded() {
        let mut registry = SnapshotRegistry::default();
        let binding = scope("server", 1);
        let (candidates, _) = build_candidates(
            Vec::new(),
            vec![forensic(
                "snap-22222222-2222-4222-8222-222222222222",
                "2026-08-24T00:00:00Z",
                "process",
            )],
        )
        .unwrap();
        let dto = registry
            .replace_catalog(binding.clone(), candidates, false)
            .unwrap();
        let handle = dto.snapshots[0].snapshot_handle.clone();
        let (first, _) = registry.begin_read(&binding, &[&handle]).unwrap();
        let (second, _) = registry.begin_read(&binding, &[&handle]).unwrap();
        let (third, _) = registry.begin_read(&binding, &[&handle]).unwrap();
        assert!(registry.begin_read(&binding, &[&handle]).is_err());
        assert!(
            registry
                .begin_read(&scope("server", 2), &[&handle])
                .is_err()
        );
        registry
            .catalogs
            .get_mut(&binding.binding_handle)
            .unwrap()
            .expires_at = Instant::now();
        assert!(registry.verify(&first).is_err());
        registry.begin_list(&binding).unwrap();
        assert!(registry.begin_list(&binding).is_err());
        registry.release_list(&binding.binding_handle);
        for access in [first, second, third] {
            registry.release_read(&access.binding_handle, access.token);
        }
        registry.prune(Instant::now() + Duration::from_secs(1));
        assert!(registry.catalogs.is_empty());

        for index in 0..MAX_CATALOGS + 1 {
            registry
                .replace_catalog(scope(&format!("capacity-{index}"), 1), Vec::new(), false)
                .unwrap();
        }
        assert_eq!(registry.catalogs.len(), MAX_CATALOGS);

        let closed = scope("closed", 1);
        registry
            .replace_catalog(closed.clone(), Vec::new(), false)
            .unwrap();
        registry.begin_list(&closed).unwrap();
        registry.close_binding(&closed.binding_handle);
        assert!(!registry.catalogs.contains_key(&closed.binding_handle));
        assert!(
            !registry
                .active_list_bindings
                .contains(&closed.binding_handle)
        );
    }

    #[test]
    fn details_omit_paths_digests_and_targets_but_keep_what_was_collected() {
        let directory = directory(
            "11111111-1111-4111-8111-111111111111",
            "2026-08-23T00:00:00Z",
        );
        let record = StoredSnapshot {
            handle: "opaque-directory".to_owned(),
            raw_id: directory.id.clone(),
            integrity: directory.record_sha256.clone(),
            kind: StoredSnapshotKind::Directory,
            captured_at: directory.created_at.to_rfc3339(),
            item_count: 1,
            completed_collectors: None,
            failed_collectors: None,
        };
        let dto = project_directory_detail(&record, directory).unwrap();
        let text = serde_json::to_string(&dto).unwrap();
        assert!(text.contains("opaque-directory"));
        assert!(!text.contains("/etc"));
        assert!(!text.contains(".tar"));
        assert!(!text.contains(&"a".repeat(64)));

        let mut forensic = forensic(
            "snap-22222222-2222-4222-8222-222222222222",
            "2026-08-24T00:00:00Z",
            "mysql -uroot -pS3cr3t",
        );
        forensic.data.network_connections = "</pre><script>x()</script>".to_owned();
        forensic.data.startup_services = "safe.service\nPASSWORD = secret".to_owned();
        forensic.data.login_history = "PASSWORD = secret".to_owned();
        forensic.data.cron_jobs = "backup --token hidden".to_owned();
        forensic.data.authorized_keys =
            "-----BEGIN OPENSSH PRIVATE KEY-----\nprivate-material\n-----END OPENSSH PRIVATE KEY-----"
                .to_owned();
        forensic.data.sudoers = "operator ALL=(ALL) NOPASSWD: /bin/sh".to_owned();
        forensic.data.recent_modified_files = "/etc/shadow\n/usr/local/private/app.conf".to_owned();
        forensic.data.env_variables = "PASSWORD = secret".to_owned();
        let record = StoredSnapshot {
            handle: "opaque-forensic".to_owned(),
            raw_id: forensic.id.clone(),
            integrity: forensic.sha256.clone(),
            kind: StoredSnapshotKind::Forensic,
            captured_at: forensic.timestamp.to_rfc3339(),
            item_count: MAX_COLLECTORS,
            completed_collectors: Some(MAX_COLLECTORS),
            failed_collectors: Some(0),
        };
        let dto = project_forensic_detail(&record, forensic).unwrap();
        let text = serde_json::to_string(&dto).unwrap();
        assert!(text.contains("</pre><script>x()</script>"));
        // Everything a collector read is shown. A sudoers NOPASSWD line, a
        // process running with -p on the command line and a modified
        // /etc/shadow are the findings, not things to hide.
        for shown in [
            "PASSWORD = secret",
            "backup --token hidden",
            "NOPASSWD",
            "/etc/shadow",
            "/usr/local/private/app.conf",
        ] {
            assert!(text.contains(shown), "collector projection dropped {shown}");
        }
        assert!(!text.contains("host-secret.test"));
        assert!(!text.contains("session-secret"));
        assert!(!text.contains("fingerprint-secret"));
        // These seven used to come back as a single marker.
        let once_hidden = dto
            .fields
            .iter()
            .filter(|field| {
                matches!(
                    field.collector,
                    PublicForensicCollector::Processes
                        | PublicForensicCollector::LoginHistory
                        | PublicForensicCollector::CronJobs
                        | PublicForensicCollector::AuthorizedKeys
                        | PublicForensicCollector::Sudoers
                        | PublicForensicCollector::RecentModifiedFiles
                        | PublicForensicCollector::EnvVariables
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(once_hidden.len(), 7);
        assert!(once_hidden.iter().all(|field| field.text != REDACTED_LINE));
        let startup = dto
            .fields
            .iter()
            .find(|field| field.collector == PublicForensicCollector::StartupServices)
            .unwrap();
        assert_eq!(startup.text, "safe.service\nPASSWORD = secret");
    }

    #[test]
    fn every_collector_diff_shows_what_changed_and_scrubs_only_our_own_handles() {
        let older_snapshot = forensic(
            "snap-11111111-1111-4111-8111-111111111111",
            "2026-08-23T00:00:00Z",
            "host-one",
        );
        let newer_snapshot = forensic(
            "snap-22222222-2222-4222-8222-222222222222",
            "2026-08-24T00:00:00Z",
            "host-two",
        );
        let record = |snapshot: &ForensicSnapshot, handle: &str| StoredSnapshot {
            handle: handle.to_owned(),
            raw_id: snapshot.id.clone(),
            integrity: snapshot.sha256.clone(),
            kind: StoredSnapshotKind::Forensic,
            captured_at: snapshot.timestamp.to_rfc3339(),
            item_count: MAX_COLLECTORS,
            completed_collectors: Some(MAX_COLLECTORS),
            failed_collectors: Some(0),
        };
        let fields = ForensicCollector::ALL
            .into_iter()
            .map(|collector| {
                let (added, removed) = (
                    vec![
                        match collector {
                            ForensicCollector::Processes => "mysql -uroot -pNewSecret",
                            ForensicCollector::AuthorizedKeys => {
                                "ssh-ed25519 AAAAC3NzaC1 attacker@host"
                            }
                            ForensicCollector::RecentModifiedFiles => "/etc/new-secret.conf",
                            _ => "PASSWORD = new-secret",
                        }
                        .to_owned(),
                    ],
                    vec![
                        match collector {
                            ForensicCollector::Processes => "mysql -uroot -pOldSecret",
                            ForensicCollector::AuthorizedKeys => "ssh-ed25519 AAAAC3NzaC1 ops@host",
                            ForensicCollector::RecentModifiedFiles => "/etc/old-secret.conf",
                            _ => "PASSWORD = old-secret",
                        }
                        .to_owned(),
                    ],
                );
                ForensicFieldDiff {
                    collector,
                    added,
                    removed,
                }
            })
            .collect();
        let dto = project_diff(
            &record(&older_snapshot, "older-opaque"),
            &record(&newer_snapshot, "newer-opaque"),
            &older_snapshot,
            &newer_snapshot,
            ForensicSnapshotDiff {
                older_id: older_snapshot.id.clone(),
                newer_id: newer_snapshot.id.clone(),
                fields,
            },
        )
        .unwrap();
        // Seven collectors used to come back as a marker on both directions:
        // processes, login history, cron, authorized_keys, sudoers, recently
        // modified files and environment variables. Those are the first things
        // read after an incident, so the diff now says what actually changed.
        for field in &dto.fields {
            assert_eq!(
                field.added.len(),
                1,
                "{:?} lost its added line",
                field.collector
            );
            assert_eq!(
                field.removed.len(),
                1,
                "{:?} lost its removed line",
                field.collector
            );
            assert_eq!(field.redacted_line_count, 0);
        }
        let text = serde_json::to_string(&dto).unwrap();
        for shown in [
            "-pNewSecret",
            "-pOldSecret",
            "PASSWORD =",
            "ssh-ed25519 AAAAC3NzaC1 attacker@host",
            "/etc/new-secret.conf",
        ] {
            assert!(text.contains(shown), "diff projection dropped {shown}");
        }
        // Our own capabilities still never reach a DTO.
        for hidden in [
            older_snapshot.id.as_str(),
            newer_snapshot.id.as_str(),
            older_snapshot.target.session_id.as_str(),
        ] {
            assert!(!text.contains(hidden), "diff projection leaked {hidden}");
        }

        // A collector that failed still reports the failure, not its detail.
        let mut budget = LineBudget::new(1, FAILED_COLLECTOR_LINE.len());
        let failed = project_text_field(
            "(failed to collect: hostile backend detail)",
            &[],
            &mut budget,
        );
        assert_eq!(failed.text, FAILED_COLLECTOR_LINE);
        assert_eq!(failed.redacted_line_count, 1);
    }

    #[test]
    fn diff_is_line_count_text_and_sensitive_metadata_bounded() {
        let older_snapshot = forensic(
            "snap-11111111-1111-4111-8111-111111111111",
            "2026-08-23T00:00:00Z",
            "old",
        );
        let newer_snapshot = forensic(
            "snap-22222222-2222-4222-8222-222222222222",
            "2026-08-24T00:00:00Z",
            "new",
        );
        let record = |snapshot: &ForensicSnapshot, handle: &str| StoredSnapshot {
            handle: handle.to_owned(),
            raw_id: snapshot.id.clone(),
            integrity: snapshot.sha256.clone(),
            kind: StoredSnapshotKind::Forensic,
            captured_at: snapshot.timestamp.to_rfc3339(),
            item_count: MAX_COLLECTORS,
            completed_collectors: Some(MAX_COLLECTORS),
            failed_collectors: Some(0),
        };
        let mut fields = ForensicCollector::ALL
            .into_iter()
            .map(|collector| ForensicFieldDiff {
                collector,
                added: Vec::new(),
                removed: Vec::new(),
            })
            .collect::<Vec<_>>();
        fields[0].added = vec!["mysql -uroot -pNewSecret".to_owned()];
        fields[0].removed = vec!["PASSWORD = old-secret".to_owned()];
        fields[1].added = (0..300)
            .map(|index| format!("token=secret-{index}"))
            .collect();
        fields[1].removed = vec!["</pre><script>old()</script>".to_owned()];
        let dto = project_diff(
            &record(&older_snapshot, "older-opaque"),
            &record(&newer_snapshot, "newer-opaque"),
            &older_snapshot,
            &newer_snapshot,
            ForensicSnapshotDiff {
                older_id: older_snapshot.id.clone(),
                newer_id: newer_snapshot.id.clone(),
                fields,
            },
        )
        .unwrap();
        let text = serde_json::to_string(&dto).unwrap();
        assert!(dto.truncated);
        assert!(dto.added_line_count <= MAX_DIFF_LINES);
        assert!(
            dto.fields
                .iter()
                .find(|field| { field.collector == PublicForensicCollector::NetworkConnections })
                .is_some_and(|field| field.added.len() <= MAX_DIFF_LINES_PER_DIRECTION)
        );
        assert!(text.contains("</pre><script>old()</script>"));
        assert!(!text.contains("11111111"));
        assert!(text.len() <= MAX_DIFF_RESPONSE_BYTES);
    }

    #[test]
    fn inputs_are_exact_and_source_calls_only_three_core_read_methods() {
        assert!(
            serde_json::from_value::<SnapshotDiffInput>(json!({
                "olderSnapshotHandle": "older",
                "newerSnapshotHandle": "newer"
            }))
            .unwrap()
            .validate()
            .is_ok()
        );
        assert!(
            serde_json::from_value::<SnapshotDiffInput>(json!({
                "olderSnapshotHandle": "same",
                "newerSnapshotHandle": "same"
            }))
            .unwrap()
            .validate()
            .is_err()
        );
        assert!(
            build_candidates(
                vec![
                    directory(
                        "11111111-1111-4111-8111-111111111111",
                        "2026-08-23T00:00:00Z",
                    ),
                    directory(
                        "11111111-1111-4111-8111-111111111111",
                        "2026-08-24T00:00:00Z",
                    ),
                ],
                Vec::new(),
            )
            .is_err()
        );
        let (bounded, truncated) = bounded_text(&"取证".repeat(2_000), 4_097);
        assert!(truncated);
        assert!(bounded.len() <= 4_097);
        assert!(std::str::from_utf8(bounded.as_bytes()).is_ok());
        let mut marker_budget = LineBudget::new(1, 1);
        // The budget refuses a line because it is out of room, not because of
        // what the line says.
        assert!(marker_budget.take("token=secret", &[], 4_096).is_some());
        assert!(marker_budget.take("another line", &[], 4_096).is_none());
        assert!(
            ensure_serialized_bound(
                &"x".repeat(MAX_LIST_RESPONSE_BYTES),
                MAX_LIST_RESPONSE_BYTES,
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<SnapshotDiffInput>(json!({
                "olderSnapshotHandle": "older",
                "newerSnapshotHandle": "newer",
                "snapshotId": "raw"
            }))
            .is_err()
        );
        let source = include_str!("snapshot_read_api.rs");
        for required in [
            ".snapshots().list_directory(",
            ".snapshots().list_forensic(",
            ".snapshots().diff_forensic(",
        ] {
            assert!(source.contains(required), "missing core call {required}");
        }
        for forbidden in [
            ["plan_", "directory_snapshot"].concat(),
            ["capture_", "forensic"].concat(),
            ["plan_", "restore_item"].concat(),
            ["plan_", "delete_directory"].concat(),
            ["export_", "forensic"].concat(),
            ["execute_", "bound"].concat(),
            ["open_", "terminal"].concat(),
        ] {
            assert!(
                !source.contains(&forbidden),
                "forbidden surface {forbidden}"
            );
        }
    }
}
