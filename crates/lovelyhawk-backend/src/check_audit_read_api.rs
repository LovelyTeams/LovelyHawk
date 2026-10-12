//! Bounded read-only desktop boundary for command-audit investigation.
//!
//! Command construction, remote log paths, and analysis rules remain owned by
//! `AuditService`. Renderer-selected custom names are only catalog entries and
//! are validated again by core before any target probe.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use lovelyhawk_core::{
    BackendServices, CoreError,
    audit::{
        AuditAnalysis, AuditCommandState, AuditLogEntry, AuditLogReport, AuditLogSource,
        AuditStatusReport, DEFAULT_AUDIT_COMMANDS,
    },
    ssh::BoundSshSession,
    target::TargetGuard,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ssh_api::SshApi;

const MAX_HANDLE_BYTES: usize = 128;
const MAX_CUSTOM_COMMANDS: usize = 15;
const MAX_COMMANDS: usize = 32;
const MAX_COMMAND_NAME_BYTES: usize = 128;
const MAX_SNAPSHOTS: usize = 8;
const MAX_SNAPSHOT_BYTES: usize = 64 * 1024;
const MAX_REGISTRY_BYTES: usize = 512 * 1024;
const MAX_ACTIVE_READS_PER_SNAPSHOT: usize = 2;
const MAX_READS_PER_BINDING: usize = 2;
const MAX_GLOBAL_READS: usize = 8;
const MAX_LOG_ENTRIES: usize = 200;
const MAX_SEARCH_BYTES: usize = 256;
const MAX_STATUS_TEXT_BYTES: usize = 256 * 1024;
const MAX_LOG_TEXT_BYTES: usize = 512 * 1024;
const MAX_ANALYSIS_TEXT_BYTES: usize = 256 * 1024;
const MAX_CATALOG_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_STATUS_RESPONSE_BYTES: usize = 512 * 1024;
const MAX_LOG_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_COMMAND_COUNTS: usize = 8;
const MAX_CYCLES: usize = 100;
const MAX_SUGGESTIONS: usize = 64;
const MIN_ITEM_TEXT_BYTES: usize = 128;
const SNAPSHOT_TTL: Duration = Duration::from_secs(5 * 60);
/// The text the frozen `redacted` flag would have to be paired with.
///
/// Nothing sets that flag any more, and the window no longer tells anyone that
/// fields were hidden — but it still refuses a row claiming to be redacted
/// without exactly this string, so the definition stays here rather than
/// drifting out of step with the check that enforces it.
#[allow(
    dead_code,
    reason = "paired with a frozen flag the window still checks"
)]
const REDACTED_TEXT: &str = "[SENSITIVE AUDIT TEXT REDACTED]";

#[derive(Clone)]
pub(crate) struct CheckAuditReadApi {
    services: BackendServices,
    ssh_api: Arc<SshApi>,
    registry: Arc<Mutex<AuditCatalogRegistry>>,
    concurrency: Arc<Mutex<ConcurrencyState>>,
}

impl fmt::Debug for CheckAuditReadApi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (snapshots, bytes, active_reads) = self
            .registry
            .lock()
            .map(|registry| {
                (
                    registry.snapshots.len(),
                    registry.total_bytes(),
                    registry
                        .snapshots
                        .values()
                        .map(|snapshot| snapshot.active_reads)
                        .sum::<usize>(),
                )
            })
            .unwrap_or_default();
        formatter
            .debug_struct("CheckAuditReadApi")
            .field("snapshot_count", &snapshots)
            .field("snapshot_bytes", &bytes)
            .field("active_reads", &active_reads)
            .finish()
    }
}

impl CheckAuditReadApi {
    pub(crate) fn new(services: BackendServices, ssh_api: Arc<SshApi>) -> Self {
        Self {
            services,
            ssh_api,
            registry: Arc::new(Mutex::new(AuditCatalogRegistry::default())),
            concurrency: Arc::new(Mutex::new(ConcurrencyState::default())),
        }
    }

    pub(crate) fn close_binding(&self, binding_handle: &str) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.close_binding(binding_handle);
        }
    }

    pub(crate) fn get_catalog(
        &self,
        binding_handle: &str,
        input: CheckAuditCatalogInput,
    ) -> Result<CheckAuditCatalogDto, CheckAuditReadApiError> {
        let (_, scope) = self.capture_binding(binding_handle)?;
        let custom_names = input.validate()?;
        let (snapshot, dto) = build_catalog(scope.clone(), custom_names)?;
        ensure_serialized_bound(&dto, MAX_CATALOG_RESPONSE_BYTES)?;
        self.validate_binding(&scope)?;
        let handle = snapshot.handle.clone();
        let mut registry = self.lock_registry()?;
        registry.prune(Instant::now());
        registry.insert(snapshot)?;
        drop(registry);
        if let Err(error) = self.validate_binding(&scope) {
            self.remove_snapshot(&handle);
            return Err(error);
        }
        Ok(dto)
    }

    pub(crate) async fn collect_status(
        &self,
        binding_handle: &str,
        snapshot_handle: &str,
    ) -> Result<CheckAuditStatusDto, CheckAuditReadApiError> {
        validate_handle(snapshot_handle)?;
        let (session, scope) = self.capture_binding(binding_handle)?;
        let _read_permit = self.acquire_read(&scope)?;
        let (access, commands, _permit) = self.begin_read(&scope, snapshot_handle)?;
        let names = commands
            .iter()
            .map(|command| command.name.clone())
            .collect::<Vec<_>>();
        let report = self.services.audit().statuses(&session, &names).await?;
        self.validate_binding(&scope)?;
        self.verify_access(&access, &commands)?;
        let dto = project_status(snapshot_handle, &commands, report)?;
        ensure_serialized_bound(&dto, MAX_STATUS_RESPONSE_BYTES)?;
        self.validate_binding(&scope)?;
        self.verify_access(&access, &commands)?;
        Ok(dto)
    }

    pub(crate) async fn read_log(
        &self,
        binding_handle: &str,
        snapshot_handle: &str,
        input: CheckAuditLogInput,
    ) -> Result<CheckAuditLogDto, CheckAuditReadApiError> {
        validate_handle(snapshot_handle)?;
        let input = input.validate()?;
        let (session, scope) = self.capture_binding(binding_handle)?;
        let _read_permit = self.acquire_read(&scope)?;
        let (access, commands, _permit) = self.begin_read(&scope, snapshot_handle)?;
        let report = self
            .services
            .audit()
            .read_log(&session, input.limit)
            .await?;
        self.validate_binding(&scope)?;
        self.verify_access(&access, &commands)?;
        let analysis = self.services.audit().analyze(&report.entries);
        let dto = project_log(
            snapshot_handle,
            input.limit,
            input.search.as_deref(),
            report,
            analysis,
        )?;
        ensure_serialized_bound(&dto, MAX_LOG_RESPONSE_BYTES)?;
        self.validate_binding(&scope)?;
        self.verify_access(&access, &commands)?;
        Ok(dto)
    }

    /// The command names a live catalog snapshot of this binding minted these
    /// handles for, in the order given. A handle the snapshot did not mint, a
    /// repeated one, or a snapshot of another binding or past its time names
    /// nothing. With no handles, only the snapshot itself is checked.
    pub(crate) fn resolve_commands(
        &self,
        binding_handle: &str,
        snapshot_handle: &str,
        command_handles: &[String],
    ) -> Result<Vec<String>, CheckAuditReadApiError> {
        validate_handle(snapshot_handle)?;
        let (_, scope) = self.capture_binding(binding_handle)?;
        let mut registry = self.lock_registry()?;
        let now = Instant::now();
        registry.prune(now);
        let snapshot = registry
            .snapshots
            .get(snapshot_handle)
            .filter(|snapshot| snapshot.scope == scope && snapshot.expires_at > now)
            .ok_or(CheckAuditReadApiError::InvalidSnapshot)?;
        let mut names = Vec::with_capacity(command_handles.len());
        for handle in command_handles {
            let name = snapshot
                .commands
                .iter()
                .find(|command| &command.command_handle == handle)
                .map(|command| command.name.clone())
                .ok_or(CheckAuditReadApiError::InvalidSnapshot)?;
            if names.contains(&name) {
                return Err(CheckAuditReadApiError::InvalidInput);
            }
            names.push(name);
        }
        Ok(names)
    }

    fn capture_binding(
        &self,
        binding_handle: &str,
    ) -> Result<(BoundSshSession, BindingScope), CheckAuditReadApiError> {
        validate_handle(binding_handle)?;
        let session = self
            .ssh_api
            .binding_session_clone(binding_handle)
            .map_err(|_| CheckAuditReadApiError::BindingUnavailable)?;
        self.services
            .target()
            .validate(session.target())
            .map_err(|_| CheckAuditReadApiError::BindingUnavailable)?;
        let scope = BindingScope::from_session(binding_handle, &session);
        Ok((session, scope))
    }

    fn validate_binding(&self, expected: &BindingScope) -> Result<(), CheckAuditReadApiError> {
        let (_, current) = self.capture_binding(&expected.binding_handle)?;
        if &current != expected {
            return Err(CheckAuditReadApiError::BindingUnavailable);
        }
        Ok(())
    }

    fn acquire_read(&self, scope: &BindingScope) -> Result<ReadPermit, CheckAuditReadApiError> {
        ReadPermit::acquire(Arc::clone(&self.concurrency), scope.binding_handle.clone())
    }

    fn begin_read(
        &self,
        scope: &BindingScope,
        snapshot_handle: &str,
    ) -> Result<(CatalogAccess, Vec<StoredCommand>, CatalogPermit), CheckAuditReadApiError> {
        let mut registry = self.lock_registry()?;
        registry.prune(Instant::now());
        let (access, commands) = registry.begin_read(scope, snapshot_handle)?;
        let permit = CatalogPermit {
            registry: Arc::clone(&self.registry),
            snapshot_handle: snapshot_handle.to_owned(),
            token: access.token,
        };
        Ok((access, commands, permit))
    }

    fn verify_access(
        &self,
        access: &CatalogAccess,
        commands: &[StoredCommand],
    ) -> Result<(), CheckAuditReadApiError> {
        let registry = self.lock_registry()?;
        let current = registry.verify(access)?;
        if current.commands != commands {
            return Err(CheckAuditReadApiError::SnapshotStale);
        }
        Ok(())
    }

    fn remove_snapshot(&self, handle: &str) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.snapshots.remove(handle);
        }
    }

    fn lock_registry(
        &self,
    ) -> Result<MutexGuard<'_, AuditCatalogRegistry>, CheckAuditReadApiError> {
        self.registry
            .lock()
            .map_err(|_| CheckAuditReadApiError::RegistryUnavailable)
    }
}

pub(crate) enum CheckAuditReadApiError {
    Core,
    BindingUnavailable,
    InvalidHandle,
    InvalidInput,
    InvalidSnapshot,
    SnapshotStale,
    ConcurrencyLimit,
    Capacity,
    RegistryUnavailable,
}

impl fmt::Debug for CheckAuditReadApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core => "Core([REDACTED])",
            Self::BindingUnavailable => "BindingUnavailable",
            Self::InvalidHandle => "InvalidHandle",
            Self::InvalidInput => "InvalidInput",
            Self::InvalidSnapshot => "InvalidSnapshot",
            Self::SnapshotStale => "SnapshotStale",
            Self::ConcurrencyLimit => "ConcurrencyLimit",
            Self::Capacity => "Capacity",
            Self::RegistryUnavailable => "RegistryUnavailable",
        })
    }
}

impl fmt::Display for CheckAuditReadApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core => "the command-audit investigation failed",
            Self::BindingUnavailable => "the SSH binding is missing or stale",
            Self::InvalidHandle => "the command-audit handle is invalid",
            Self::InvalidInput => "the command-audit input is invalid",
            Self::InvalidSnapshot => "the command-audit catalog is missing or stale",
            Self::SnapshotStale => "the command-audit result no longer matches its catalog",
            Self::ConcurrencyLimit => "the command-audit read concurrency limit was reached",
            Self::Capacity => "the command-audit registry is full",
            Self::RegistryUnavailable => "the command-audit registry is unavailable",
        })
    }
}

impl std::error::Error for CheckAuditReadApiError {}

impl From<CoreError> for CheckAuditReadApiError {
    fn from(error: CoreError) -> Self {
        // The renderer only ever sees a fixed message, so without this the
        // reason a page failed is lost before anyone can read it.
        tracing::warn!(operation = "CheckAuditRead", error = %error, "core operation failed");
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
        formatter.write_str("BindingScope([REDACTED])")
    }
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CheckAuditCatalogInput {
    custom_command_names: Vec<String>,
}

impl fmt::Debug for CheckAuditCatalogInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CheckAuditCatalogInput")
            .field("custom_command_count", &self.custom_command_names.len())
            .field("custom_command_names", &"[REDACTED]")
            .finish()
    }
}

impl CheckAuditCatalogInput {
    fn validate(self) -> Result<Vec<String>, CheckAuditReadApiError> {
        if self.custom_command_names.len() > MAX_CUSTOM_COMMANDS {
            return Err(CheckAuditReadApiError::InvalidInput);
        }
        let defaults = DEFAULT_AUDIT_COMMANDS
            .iter()
            .copied()
            .collect::<HashSet<_>>();
        let mut seen = HashSet::new();
        let mut names = Vec::with_capacity(self.custom_command_names.len());
        for name in self.custom_command_names {
            if name.trim() != name
                || !valid_command_name(&name)
                || defaults.contains(name.as_str())
                || !seen.insert(name.clone())
            {
                return Err(CheckAuditReadApiError::InvalidInput);
            }
            names.push(name);
        }
        names.sort();
        Ok(names)
    }
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CheckAuditLogInput {
    limit: usize,
    search: Option<String>,
}

impl fmt::Debug for CheckAuditLogInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CheckAuditLogInput")
            .field("limit", &self.limit)
            .field("search", &"[REDACTED]")
            .finish()
    }
}

struct ValidatedLogInput {
    limit: usize,
    search: Option<String>,
}

impl CheckAuditLogInput {
    fn validate(self) -> Result<ValidatedLogInput, CheckAuditReadApiError> {
        if self.limit == 0 || self.limit > MAX_LOG_ENTRIES {
            return Err(CheckAuditReadApiError::InvalidInput);
        }
        let search = match self.search {
            None => None,
            Some(value) => {
                if value.trim() != value
                    || value.is_empty()
                    || value.len() > MAX_SEARCH_BYTES
                    || value.chars().any(char::is_control)
                {
                    return Err(CheckAuditReadApiError::InvalidInput);
                }
                Some(value)
            }
        };
        Ok(ValidatedLogInput {
            limit: self.limit,
            search,
        })
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CheckAuditCatalogDto {
    snapshot_handle: String,
    expires_in_seconds: u64,
    commands: Vec<CheckAuditCatalogCommandDto>,
    custom_count: usize,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct CheckAuditCatalogCommandDto {
    command_handle: String,
    name: String,
    is_default: bool,
    critical: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CheckAuditStatusDto {
    snapshot_handle: String,
    is_root: bool,
    commands: Vec<CheckAuditCommandStatusDto>,
    redacted_field_count: usize,
    truncated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CheckAuditCommandStatusDto {
    command_handle: String,
    name: String,
    state: PublicCommandState,
    critical: bool,
    display_location: Option<String>,
    location_redacted: bool,
    text_truncated: bool,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PublicCommandState {
    Original,
    Instrumented,
    Missing,
    ForeignScript,
    CoreutilsShim,
    MultiCall,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CheckAuditLogDto {
    snapshot_handle: String,
    limit: usize,
    /// What was found where the log belongs; only "read" means the counts
    /// below describe a log.
    log_state: &'static str,
    fetched_count: usize,
    /// Lines that were not audit records, shown as written.
    malformed_count: usize,
    matched_count: usize,
    displayed_count: usize,
    suspicious_count: usize,
    matched_suspicious_count: usize,
    entries: Vec<PublicAuditLogEntryDto>,
    command_counts: Vec<PublicAuditCommandCountDto>,
    cycles: Vec<PublicAuditCycleDto>,
    suggestions: Vec<PublicAuditSuggestionDto>,
    redacted_field_count: usize,
    truncated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicAuditLogEntryDto {
    timestamp: String,
    command: String,
    args: String,
    user: String,
    pid: u32,
    ppid: u32,
    caller: String,
    suspicious: bool,
    /// Not an audit record: `args` carries the line as written and the
    /// other text fields are empty.
    malformed: bool,
    redacted: bool,
    text_truncated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicAuditCommandCountDto {
    command: String,
    count: usize,
    redacted: bool,
    text_truncated: bool,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PublicCycleCategory {
    FileRead,
    ServiceCheck,
    Network,
    Database,
    Process,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicAuditCycleDto {
    command: String,
    args: String,
    interval_seconds: Option<u64>,
    count: usize,
    last_seen: String,
    category: PublicCycleCategory,
    redacted: bool,
    text_truncated: bool,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PublicSuggestionSeverity {
    Critical,
    Warning,
    Info,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicAuditSuggestionDto {
    severity: PublicSuggestionSeverity,
    title: String,
    description: String,
    redacted: bool,
    text_truncated: bool,
}

#[derive(Default)]
struct ConcurrencyState {
    total: usize,
    per_binding: HashMap<String, usize>,
}

struct ReadPermit {
    state: Arc<Mutex<ConcurrencyState>>,
    binding_handle: String,
}

impl ReadPermit {
    fn acquire(
        state: Arc<Mutex<ConcurrencyState>>,
        binding_handle: String,
    ) -> Result<Self, CheckAuditReadApiError> {
        {
            let mut current = state
                .lock()
                .map_err(|_| CheckAuditReadApiError::RegistryUnavailable)?;
            let binding_reads = current
                .per_binding
                .get(&binding_handle)
                .copied()
                .unwrap_or_default();
            if current.total >= MAX_GLOBAL_READS || binding_reads >= MAX_READS_PER_BINDING {
                return Err(CheckAuditReadApiError::ConcurrencyLimit);
            }
            current.total += 1;
            current
                .per_binding
                .insert(binding_handle.clone(), binding_reads + 1);
        }
        Ok(Self {
            state,
            binding_handle,
        })
    }
}

impl Drop for ReadPermit {
    fn drop(&mut self) {
        if let Ok(mut current) = self.state.lock() {
            current.total = current.total.saturating_sub(1);
            if let Some(binding_reads) = current.per_binding.get_mut(&self.binding_handle) {
                *binding_reads = binding_reads.saturating_sub(1);
                if *binding_reads == 0 {
                    current.per_binding.remove(&self.binding_handle);
                }
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct StoredCommand {
    command_handle: String,
    name: String,
    is_default: bool,
    critical: bool,
}

struct AuditCatalogSnapshot {
    handle: String,
    token: Uuid,
    scope: BindingScope,
    created_at: Instant,
    expires_at: Instant,
    active_reads: usize,
    stored_bytes: usize,
    commands: Vec<StoredCommand>,
}

#[derive(Clone)]
struct CatalogAccess {
    handle: String,
    token: Uuid,
    scope: BindingScope,
}

impl CatalogAccess {
    fn matches(&self, snapshot: &AuditCatalogSnapshot, now: Instant) -> bool {
        snapshot.token == self.token && snapshot.scope == self.scope && snapshot.expires_at > now
    }
}

#[derive(Default)]
struct AuditCatalogRegistry {
    snapshots: HashMap<String, AuditCatalogSnapshot>,
}

impl AuditCatalogRegistry {
    fn close_binding(&mut self, binding_handle: &str) {
        self.snapshots
            .retain(|_, snapshot| snapshot.scope.binding_handle != binding_handle);
    }

    fn prune(&mut self, now: Instant) {
        self.snapshots
            .retain(|_, snapshot| snapshot.expires_at > now || snapshot.active_reads > 0);
    }

    fn total_bytes(&self) -> usize {
        self.snapshots
            .values()
            .map(|snapshot| snapshot.stored_bytes)
            .sum()
    }

    fn active_reads(&self) -> usize {
        self.snapshots
            .values()
            .map(|snapshot| snapshot.active_reads)
            .sum()
    }

    fn insert(&mut self, snapshot: AuditCatalogSnapshot) -> Result<(), CheckAuditReadApiError> {
        if self.snapshots.contains_key(&snapshot.handle)
            || snapshot.commands.len() > MAX_COMMANDS
            || snapshot.stored_bytes > MAX_SNAPSHOT_BYTES
        {
            return Err(CheckAuditReadApiError::Capacity);
        }
        self.snapshots
            .retain(|_, existing| existing.scope != snapshot.scope);
        while self.snapshots.len() >= MAX_SNAPSHOTS
            || self.total_bytes().saturating_add(snapshot.stored_bytes) > MAX_REGISTRY_BYTES
        {
            let candidate = self
                .snapshots
                .iter()
                .filter(|(_, existing)| existing.active_reads == 0)
                .min_by_key(|(_, existing)| existing.created_at)
                .map(|(handle, _)| handle.clone())
                .ok_or(CheckAuditReadApiError::Capacity)?;
            self.snapshots.remove(&candidate);
        }
        self.snapshots.insert(snapshot.handle.clone(), snapshot);
        Ok(())
    }

    fn begin_read(
        &mut self,
        scope: &BindingScope,
        handle: &str,
    ) -> Result<(CatalogAccess, Vec<StoredCommand>), CheckAuditReadApiError> {
        if self.active_reads() >= MAX_GLOBAL_READS {
            return Err(CheckAuditReadApiError::Capacity);
        }
        let snapshot = self
            .snapshots
            .get_mut(handle)
            .filter(|snapshot| &snapshot.scope == scope && snapshot.expires_at > Instant::now())
            .ok_or(CheckAuditReadApiError::InvalidSnapshot)?;
        if snapshot.active_reads >= MAX_ACTIVE_READS_PER_SNAPSHOT {
            return Err(CheckAuditReadApiError::Capacity);
        }
        snapshot.active_reads += 1;
        Ok((
            CatalogAccess {
                handle: handle.to_owned(),
                token: snapshot.token,
                scope: scope.clone(),
            },
            snapshot.commands.clone(),
        ))
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

    fn verify(
        &self,
        access: &CatalogAccess,
    ) -> Result<&AuditCatalogSnapshot, CheckAuditReadApiError> {
        self.snapshots
            .get(&access.handle)
            .filter(|snapshot| access.matches(snapshot, Instant::now()))
            .ok_or(CheckAuditReadApiError::SnapshotStale)
    }
}

struct CatalogPermit {
    registry: Arc<Mutex<AuditCatalogRegistry>>,
    snapshot_handle: String,
    token: Uuid,
}

impl Drop for CatalogPermit {
    fn drop(&mut self) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.release_read(&self.snapshot_handle, self.token);
        }
    }
}

fn build_catalog(
    scope: BindingScope,
    custom_names: Vec<String>,
) -> Result<(AuditCatalogSnapshot, CheckAuditCatalogDto), CheckAuditReadApiError> {
    if DEFAULT_AUDIT_COMMANDS
        .len()
        .saturating_add(custom_names.len())
        > MAX_COMMANDS
    {
        return Err(CheckAuditReadApiError::InvalidInput);
    }
    let snapshot_handle = unique_handle()?;
    let mut stored_bytes = scope
        .storage_bytes()
        .saturating_add(snapshot_handle.len())
        .saturating_add(128);
    let mut commands = Vec::with_capacity(DEFAULT_AUDIT_COMMANDS.len() + custom_names.len());
    let mut dto_commands = Vec::with_capacity(commands.capacity());
    for (name, is_default) in DEFAULT_AUDIT_COMMANDS
        .iter()
        .map(|name| ((*name).to_owned(), true))
        .chain(custom_names.iter().cloned().map(|name| (name, false)))
    {
        let command_handle = unique_command_handle(&commands)?;
        let critical = is_critical_command(&name);
        stored_bytes = stored_bytes
            .saturating_add(command_handle.len())
            .saturating_add(name.len())
            .saturating_add(64);
        commands.push(StoredCommand {
            command_handle: command_handle.clone(),
            name: name.clone(),
            is_default,
            critical,
        });
        dto_commands.push(CheckAuditCatalogCommandDto {
            command_handle,
            name,
            is_default,
            critical,
        });
    }
    if stored_bytes > MAX_SNAPSHOT_BYTES {
        return Err(CheckAuditReadApiError::Capacity);
    }
    let now = Instant::now();
    let snapshot = AuditCatalogSnapshot {
        handle: snapshot_handle.clone(),
        token: Uuid::new_v4(),
        scope,
        created_at: now,
        expires_at: now + SNAPSHOT_TTL,
        active_reads: 0,
        stored_bytes,
        commands,
    };
    let dto = CheckAuditCatalogDto {
        snapshot_handle,
        expires_in_seconds: SNAPSHOT_TTL.as_secs(),
        commands: dto_commands,
        custom_count: custom_names.len(),
    };
    Ok((snapshot, dto))
}

fn project_status(
    snapshot_handle: &str,
    commands: &[StoredCommand],
    report: AuditStatusReport,
) -> Result<CheckAuditStatusDto, CheckAuditReadApiError> {
    if report.commands.len() != commands.len() {
        return Err(CheckAuditReadApiError::SnapshotStale);
    }
    let mut by_name = report
        .commands
        .into_iter()
        .map(|status| (status.name.clone(), status))
        .collect::<HashMap<_, _>>();
    if by_name.len() != commands.len() {
        return Err(CheckAuditReadApiError::SnapshotStale);
    }
    let mut budget = TextBudget::new(MAX_STATUS_TEXT_BYTES);
    let mut redacted_field_count = 0;
    let mut truncated = false;
    let mut projected = Vec::with_capacity(commands.len());
    for command in commands {
        let status = by_name
            .remove(&command.name)
            .ok_or(CheckAuditReadApiError::SnapshotStale)?;
        if status.critical != command.critical {
            return Err(CheckAuditReadApiError::SnapshotStale);
        }
        let (display_location, location_redacted, location_truncated) =
            status.path.map_or((None, false, false), |value| {
                let (value, redacted, truncated) = budget.take_public(&value, 4 * 1024);
                (Some(value), redacted, truncated)
            });
        redacted_field_count += usize::from(location_redacted);
        truncated |= location_truncated;
        projected.push(CheckAuditCommandStatusDto {
            command_handle: command.command_handle.clone(),
            name: command.name.clone(),
            state: match status.state {
                AuditCommandState::Original => PublicCommandState::Original,
                AuditCommandState::Instrumented => PublicCommandState::Instrumented,
                AuditCommandState::Missing => PublicCommandState::Missing,
                AuditCommandState::ForeignScript => PublicCommandState::ForeignScript,
                AuditCommandState::CoreutilsShim => PublicCommandState::CoreutilsShim,
                AuditCommandState::MultiCall => PublicCommandState::MultiCall,
            },
            critical: command.critical,
            display_location,
            location_redacted,
            text_truncated: location_truncated,
        });
    }
    if !by_name.is_empty() {
        return Err(CheckAuditReadApiError::SnapshotStale);
    }
    Ok(CheckAuditStatusDto {
        snapshot_handle: snapshot_handle.to_owned(),
        is_root: report.is_root,
        commands: projected,
        redacted_field_count,
        truncated,
    })
}

fn project_log(
    snapshot_handle: &str,
    limit: usize,
    search: Option<&str>,
    report: AuditLogReport,
    analysis: AuditAnalysis,
) -> Result<CheckAuditLogDto, CheckAuditReadApiError> {
    let actual_suspicious_count = report
        .entries
        .iter()
        .filter(|entry| entry.suspicious)
        .count();
    let mut count_commands = HashSet::new();
    let count_sum = report
        .command_counts
        .iter()
        .try_fold(0_usize, |total, count| {
            if !count_commands.insert(count.command.as_str()) || count.count == 0 {
                return Err(CheckAuditReadApiError::SnapshotStale);
            }
            total
                .checked_add(count.count)
                .ok_or(CheckAuditReadApiError::SnapshotStale)
        })?;
    let cycle_count_sum = analysis.cycles.iter().try_fold(0_usize, |total, cycle| {
        total
            .checked_add(cycle.count)
            .ok_or(CheckAuditReadApiError::SnapshotStale)
    })?;
    let actual_malformed_count = report
        .entries
        .iter()
        .filter(|entry| entry.malformed)
        .count();
    if report.entries.len() > limit
        || (report.source != AuditLogSource::Read && !report.entries.is_empty())
        || report.malformed_count != actual_malformed_count
        || report.suspicious_count != actual_suspicious_count
        || report.command_counts.len() > MAX_COMMAND_COUNTS
        || count_sum > report.entries.len()
        || report
            .command_counts
            .iter()
            .any(|count| count.count > report.entries.len())
        || cycle_count_sum > report.entries.len()
        || analysis.suggestions.len() > analysis.cycles.len()
    {
        return Err(CheckAuditReadApiError::SnapshotStale);
    }
    let fetched_count = report.entries.len();
    let matching = report
        .entries
        .iter()
        .filter(|entry| search.is_none_or(|query| entry_matches(entry, query)))
        .collect::<Vec<_>>();
    let matched_count = matching.len();
    let matched_suspicious_count = matching.iter().filter(|entry| entry.suspicious).count();
    let mut log_budget = TextBudget::new(MAX_LOG_TEXT_BYTES);
    let mut redacted_field_count = 0;
    let mut text_truncated = false;
    let mut entries = Vec::new();
    for entry in matching {
        if log_budget.remaining() < MIN_ITEM_TEXT_BYTES {
            break;
        }
        let projected = project_log_entry(entry, &mut log_budget);
        redacted_field_count += projected.redacted_fields;
        text_truncated |= projected.dto.text_truncated;
        entries.push(projected.dto);
    }
    let displayed_count = entries.len();
    let mut command_counts = Vec::with_capacity(report.command_counts.len());
    for count in report.command_counts {
        let (command, redacted, truncated) = log_budget.take_public(&count.command, 128);
        redacted_field_count += usize::from(redacted);
        text_truncated |= truncated;
        command_counts.push(PublicAuditCommandCountDto {
            command,
            count: count.count,
            redacted,
            text_truncated: truncated,
        });
    }
    let mut analysis_budget = TextBudget::new(MAX_ANALYSIS_TEXT_BYTES);
    let (cycles, cycle_redactions, cycles_truncated) =
        project_cycles(analysis.cycles, fetched_count, &mut analysis_budget)?;
    let (suggestions, suggestion_redactions, suggestions_truncated) =
        project_suggestions(analysis.suggestions, &mut analysis_budget);
    redacted_field_count = redacted_field_count
        .saturating_add(cycle_redactions)
        .saturating_add(suggestion_redactions);
    Ok(CheckAuditLogDto {
        snapshot_handle: snapshot_handle.to_owned(),
        limit,
        log_state: match report.source {
            AuditLogSource::Read => "read",
            AuditLogSource::Absent => "absent",
            AuditLogSource::NotRegularFile => "not-regular-file",
            AuditLogSource::Unreadable => "unreadable",
        },
        fetched_count,
        malformed_count: report.malformed_count,
        matched_count,
        displayed_count,
        suspicious_count: report.suspicious_count,
        matched_suspicious_count,
        entries,
        command_counts,
        cycles,
        suggestions,
        redacted_field_count,
        truncated: displayed_count < matched_count
            || text_truncated
            || cycles_truncated
            || suggestions_truncated,
    })
}

struct ProjectedLogEntry {
    dto: PublicAuditLogEntryDto,
    redacted_fields: usize,
}

fn project_log_entry(entry: &AuditLogEntry, budget: &mut TextBudget) -> ProjectedLogEntry {
    let (timestamp, timestamp_redacted, timestamp_truncated) =
        budget.take_public(&entry.timestamp, 64);
    let (command, command_redacted, command_truncated) = budget.take_public(&entry.command, 128);
    // A line that is no record is shown as written, in place of arguments.
    let (args, args_redacted, args_truncated) = if entry.malformed {
        budget.take_public(&entry.raw, 2 * 1024)
    } else {
        budget.take_public(&entry.args, 2 * 1024)
    };
    let (user, user_redacted, user_truncated) = budget.take_public(&entry.user, 128);
    let (caller, caller_redacted, caller_truncated) = budget.take_public(&entry.caller, 256);
    let raw_redacted = false;
    let redacted_fields = [
        timestamp_redacted,
        command_redacted,
        args_redacted,
        user_redacted,
        caller_redacted,
        raw_redacted,
    ]
    .into_iter()
    .filter(|value| *value)
    .count();
    ProjectedLogEntry {
        dto: PublicAuditLogEntryDto {
            timestamp,
            command,
            args,
            user,
            pid: entry.pid,
            ppid: entry.ppid,
            caller,
            suspicious: entry.suspicious,
            malformed: entry.malformed,
            redacted: redacted_fields > 0,
            text_truncated: timestamp_truncated
                || command_truncated
                || args_truncated
                || user_truncated
                || caller_truncated,
        },
        redacted_fields,
    }
}

fn project_cycles(
    source: Vec<lovelyhawk_core::audit::AuditCycle>,
    maximum_count: usize,
    budget: &mut TextBudget,
) -> Result<(Vec<PublicAuditCycleDto>, usize, bool), CheckAuditReadApiError> {
    if source
        .iter()
        .any(|cycle| cycle.count < 2 || cycle.count > maximum_count)
    {
        return Err(CheckAuditReadApiError::SnapshotStale);
    }
    let source_len = source.len();
    let mut cycles = Vec::new();
    let mut redacted_fields = 0;
    let mut text_truncated = false;
    for cycle in source.into_iter().take(MAX_CYCLES) {
        if budget.remaining() < MIN_ITEM_TEXT_BYTES {
            break;
        }
        let (command, command_redacted, command_truncated) =
            budget.take_public(&cycle.command, 128);
        let (args, args_redacted, args_truncated) = budget.take_public(&cycle.args, 2 * 1024);
        let (last_seen, last_seen_redacted, last_seen_truncated) =
            budget.take_public(&cycle.last_seen, 64);
        redacted_fields += [command_redacted, args_redacted, last_seen_redacted]
            .into_iter()
            .filter(|value| *value)
            .count();
        let truncated = command_truncated || args_truncated || last_seen_truncated;
        text_truncated |= truncated;
        cycles.push(PublicAuditCycleDto {
            command,
            args,
            interval_seconds: cycle.interval_seconds,
            count: cycle.count,
            last_seen,
            category: match cycle.category {
                lovelyhawk_core::audit::AuditCycleCategory::FileRead => {
                    PublicCycleCategory::FileRead
                }
                lovelyhawk_core::audit::AuditCycleCategory::ServiceCheck => {
                    PublicCycleCategory::ServiceCheck
                }
                lovelyhawk_core::audit::AuditCycleCategory::Network => PublicCycleCategory::Network,
                lovelyhawk_core::audit::AuditCycleCategory::Database => {
                    PublicCycleCategory::Database
                }
                lovelyhawk_core::audit::AuditCycleCategory::Process => PublicCycleCategory::Process,
            },
            redacted: command_redacted || args_redacted || last_seen_redacted,
            text_truncated: truncated,
        });
    }
    let projected_len = cycles.len();
    Ok((
        cycles,
        redacted_fields,
        source_len > MAX_CYCLES || projected_len < source_len || text_truncated,
    ))
}

fn project_suggestions(
    source: Vec<lovelyhawk_core::audit::AuditSuggestion>,
    budget: &mut TextBudget,
) -> (Vec<PublicAuditSuggestionDto>, usize, bool) {
    let source_len = source.len();
    let mut suggestions = Vec::new();
    let mut redacted_fields = 0;
    let mut text_truncated = false;
    for suggestion in source.into_iter().take(MAX_SUGGESTIONS) {
        if budget.remaining() < MIN_ITEM_TEXT_BYTES {
            break;
        }
        let (title, title_redacted, title_truncated) = budget.take_public(&suggestion.title, 256);
        let (description, description_redacted, description_truncated) =
            budget.take_public(&suggestion.description, 512);
        redacted_fields += usize::from(title_redacted) + usize::from(description_redacted);
        let truncated = title_truncated || description_truncated;
        text_truncated |= truncated;
        suggestions.push(PublicAuditSuggestionDto {
            severity: match suggestion.severity {
                lovelyhawk_core::audit::AuditSuggestionSeverity::Critical => {
                    PublicSuggestionSeverity::Critical
                }
                lovelyhawk_core::audit::AuditSuggestionSeverity::Warning => {
                    PublicSuggestionSeverity::Warning
                }
                lovelyhawk_core::audit::AuditSuggestionSeverity::Info => {
                    PublicSuggestionSeverity::Info
                }
            },
            title,
            description,
            redacted: title_redacted || description_redacted,
            text_truncated: truncated,
        });
    }
    let projected_len = suggestions.len();
    (
        suggestions,
        redacted_fields,
        source_len > MAX_SUGGESTIONS || projected_len < source_len || text_truncated,
    )
}

fn entry_matches(entry: &AuditLogEntry, search: &str) -> bool {
    let needle = search.to_lowercase();
    [
        entry.timestamp.as_str(),
        entry.command.as_str(),
        entry.args.as_str(),
        entry.user.as_str(),
        entry.caller.as_str(),
        entry.raw.as_str(),
    ]
    .iter()
    .any(|value| value.to_lowercase().contains(&needle))
}

struct TextBudget {
    remaining: usize,
}

impl TextBudget {
    const fn new(remaining: usize) -> Self {
        Self { remaining }
    }

    const fn remaining(&self) -> usize {
        self.remaining
    }

    /// Bounds a piece of text without ever removing anything from inside it.
    ///
    /// The middle value is still `redacted`, and it is always false: nothing
    /// here hides content any more. Filtering by credential shape used to
    /// swallow the very lines an audit is read for, so it was removed — but the
    /// flag stayed, and with it a branch that could not be taken and a page
    /// that told operators fields had been hidden when none had. The flag is
    /// kept only because the response shape is frozen; it is not a decision.
    fn take_public(&mut self, value: &str, maximum_bytes: usize) -> (String, bool, bool) {
        let limit = maximum_bytes.min(self.remaining);
        let (value, truncated) = bounded_text(value, limit);
        self.remaining = self.remaining.saturating_sub(value.len());
        (value, false, truncated)
    }
}

fn bounded_text(value: &str, maximum_bytes: usize) -> (String, bool) {
    if value.len() <= maximum_bytes {
        return (value.to_owned(), false);
    }
    let mut end = maximum_bytes.min(value.len());
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    (value[..end].to_owned(), true)
}

fn ensure_serialized_bound<T: Serialize>(
    value: &T,
    maximum_bytes: usize,
) -> Result<(), CheckAuditReadApiError> {
    let encoded = serde_json::to_vec(value).map_err(|_| CheckAuditReadApiError::Capacity)?;
    if encoded.len() > maximum_bytes {
        return Err(CheckAuditReadApiError::Capacity);
    }
    Ok(())
}

fn valid_command_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && name.len() <= MAX_COMMAND_NAME_BYTES
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
}

fn is_critical_command(name: &str) -> bool {
    matches!(name, "bash" | "sh" | "cat")
}

fn validate_handle(value: &str) -> Result<(), CheckAuditReadApiError> {
    if value.is_empty()
        || value.len() > MAX_HANDLE_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(CheckAuditReadApiError::InvalidHandle);
    }
    Ok(())
}

fn unique_handle() -> Result<String, CheckAuditReadApiError> {
    let handle = Uuid::new_v4().to_string();
    validate_handle(&handle)?;
    Ok(handle)
}

fn unique_command_handle(existing: &[StoredCommand]) -> Result<String, CheckAuditReadApiError> {
    for _ in 0..8 {
        let handle = unique_handle()?;
        if !existing
            .iter()
            .any(|command| command.command_handle == handle)
        {
            return Ok(handle);
        }
    }
    Err(CheckAuditReadApiError::Capacity)
}

#[cfg(test)]
mod tests {
    use lovelyhawk_core::{
        audit::{
            AuditCommandCount, AuditCommandStatus, AuditCycle, AuditCycleCategory, AuditLogEntry,
            AuditSuggestion, AuditSuggestionSeverity,
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

    fn catalog(name: &str) -> (AuditCatalogSnapshot, CheckAuditCatalogDto) {
        build_catalog(scope(name, 1), vec!["openssl".to_owned()]).unwrap()
    }

    fn entry(args: &str) -> AuditLogEntry {
        AuditLogEntry {
            timestamp: "2026-08-24 01:02:03".to_owned(),
            command: "cat".to_owned(),
            args: args.to_owned(),
            user: "operator".to_owned(),
            pid: 10,
            ppid: 1,
            caller: "check<script>".to_owned(),
            raw: args.to_owned(),
            suspicious: true,
            malformed: false,
        }
    }

    #[test]
    fn catalog_contains_fixed_defaults_and_strict_custom_opaque_handles() {
        let (_, dto) = build_catalog(
            scope("server", 1),
            CheckAuditCatalogInput {
                custom_command_names: vec!["z-tool".to_owned(), "openssl".to_owned()],
            }
            .validate()
            .unwrap(),
        )
        .unwrap();
        let value = serde_json::to_value(dto).unwrap();
        assert_eq!(value["commands"].as_array().unwrap().len(), 19);
        assert_eq!(value["customCount"], 2);
        assert!(value["commands"][0].get("commandHandle").is_some());
        assert!(value["commands"][0].get("path").is_none());
        assert!(value.get("sessionId").is_none());
        assert!(value.get("generation").is_none());
        assert!(serde_json::to_vec(&value).unwrap().len() <= MAX_CATALOG_RESPONSE_BYTES);
        assert!(
            ensure_serialized_bound(
                &"x".repeat(MAX_CATALOG_RESPONSE_BYTES),
                MAX_CATALOG_RESPONSE_BYTES,
            )
            .is_err()
        );
    }

    #[test]
    fn custom_names_and_log_queries_fail_closed() {
        for invalid in ["", "cat;id", "../cat", "-rf", "a b", "a\nwhoami"] {
            assert!(
                CheckAuditCatalogInput {
                    custom_command_names: vec![invalid.to_owned()],
                }
                .validate()
                .is_err()
            );
        }
        assert!(
            CheckAuditCatalogInput {
                custom_command_names: vec!["cat".to_owned()],
            }
            .validate()
            .is_err()
        );
        assert!(
            CheckAuditCatalogInput {
                custom_command_names: (0..MAX_CUSTOM_COMMANDS)
                    .map(|index| format!("custom-{index}"))
                    .collect(),
            }
            .validate()
            .is_ok()
        );
        assert!(
            CheckAuditCatalogInput {
                custom_command_names: (0..=MAX_CUSTOM_COMMANDS)
                    .map(|index| format!("custom-{index}"))
                    .collect(),
            }
            .validate()
            .is_err()
        );
        assert!(
            serde_json::from_value::<CheckAuditCatalogInput>(json!({
                "customCommandNames": [],
                "command": "id"
            }))
            .is_err()
        );
        for value in [
            json!({"limit": 0, "search": null}),
            json!({"limit": 201, "search": null}),
            json!({"limit": 10, "search": "x\ncommand"}),
            json!({"limit": 10, "search": null, "path": "/var/log/audit.log"}),
        ] {
            assert!(
                serde_json::from_value::<CheckAuditLogInput>(value)
                    .unwrap_or(CheckAuditLogInput {
                        limit: 0,
                        search: None,
                    })
                    .validate()
                    .is_err()
            );
        }
        assert!(
            CheckAuditLogInput {
                limit: 1,
                search: Some("猫".repeat(85)),
            }
            .validate()
            .is_ok()
        );
        assert!(
            CheckAuditLogInput {
                limit: 1,
                search: Some("猫".repeat(86)),
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn public_errors_and_debug_views_never_echo_attacker_text() {
        let secret = "password=never-echo-this";
        let public_error: CheckAuditReadApiError = CoreError::Validation {
            subject: "hostile audit output",
            message: secret.to_owned(),
        }
        .into();
        assert_eq!(
            public_error.to_string(),
            "the command-audit investigation failed"
        );
        assert_eq!(format!("{public_error:?}"), "Core([REDACTED])");
        assert!(!public_error.to_string().contains(secret));
        assert!(!format!("{public_error:?}").contains(secret));

        let catalog_input = CheckAuditCatalogInput {
            custom_command_names: vec![secret.to_owned()],
        };
        let log_input = CheckAuditLogInput {
            limit: 1,
            search: Some(secret.to_owned()),
        };
        assert!(!format!("{catalog_input:?}").contains(secret));
        assert!(!format!("{log_input:?}").contains(secret));
        assert!(!format!("{:?}", scope(secret, 1)).contains(secret));
    }

    #[test]
    fn registry_is_target_ttl_concurrency_and_capacity_bounded() {
        let now = Instant::now();
        let (first, _) = catalog("server-0");
        let first_handle = first.handle.clone();
        let first_scope = first.scope.clone();
        let mut registry = AuditCatalogRegistry::default();
        registry.insert(first).unwrap();
        let (access, _) = registry.begin_read(&first_scope, &first_handle).unwrap();
        registry.begin_read(&first_scope, &first_handle).unwrap();
        assert!(registry.begin_read(&first_scope, &first_handle).is_err());
        assert!(
            registry
                .begin_read(&scope("other", 1), &first_handle)
                .is_err()
        );
        registry
            .snapshots
            .get_mut(&first_handle)
            .unwrap()
            .expires_at = now;
        assert!(registry.verify(&access).is_err());
        registry.release_read(&first_handle, access.token);
        registry.release_read(&first_handle, access.token);
        registry.prune(now + Duration::from_secs(1));
        assert!(!registry.snapshots.contains_key(&first_handle));

        for index in 0..MAX_SNAPSHOTS {
            let (snapshot, _) = catalog(&format!("server-{index}"));
            registry.insert(snapshot).unwrap();
        }
        let handles = registry.snapshots.keys().cloned().collect::<Vec<_>>();
        let (replacement, _) = catalog("replacement");
        registry.insert(replacement).unwrap();
        assert_eq!(registry.snapshots.len(), MAX_SNAPSHOTS);
        assert!(
            handles
                .iter()
                .any(|handle| !registry.snapshots.contains_key(handle))
        );

        let (mut oversized, _) = catalog("oversized");
        oversized.stored_bytes = MAX_SNAPSHOT_BYTES + 1;
        assert!(matches!(
            registry.insert(oversized),
            Err(CheckAuditReadApiError::Capacity)
        ));
        let (mut oversized_items, _) = catalog("oversized-items");
        oversized_items.commands = vec![oversized_items.commands[0].clone(); MAX_COMMANDS + 1];
        assert!(matches!(
            registry.insert(oversized_items),
            Err(CheckAuditReadApiError::Capacity)
        ));
        assert!(registry.total_bytes() <= MAX_REGISTRY_BYTES);
    }

    #[test]
    fn binding_scope_checks_every_identity_component() {
        let original = scope("server", 1);
        let (snapshot, _) = catalog("server");
        let handle = snapshot.handle.clone();
        let mut registry = AuditCatalogRegistry::default();
        registry.insert(snapshot).unwrap();

        let mut wrong_handle = original.clone();
        wrong_handle.binding_handle = "binding-other".to_owned();
        let mut wrong_session = original.clone();
        wrong_session.session_id = "session-other".to_owned();
        let mut wrong_connection = original.clone();
        wrong_connection.connection_id = "connection-other".to_owned();
        let mut wrong_target = original.clone();
        wrong_target.target.identity = TargetIdentity::new("other-server").unwrap();
        let mut wrong_generation = original.clone();
        wrong_generation.target.generation += 1;

        for candidate in [
            wrong_handle,
            wrong_session,
            wrong_connection,
            wrong_target,
            wrong_generation,
        ] {
            assert!(matches!(
                registry.begin_read(&candidate, &handle),
                Err(CheckAuditReadApiError::InvalidSnapshot)
            ));
        }
    }

    #[test]
    fn read_concurrency_is_bounded_globally_and_per_binding() {
        let state = Arc::new(Mutex::new(ConcurrencyState::default()));
        let permits = (0..MAX_GLOBAL_READS)
            .map(|index| ReadPermit::acquire(Arc::clone(&state), format!("binding-{index}")))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(matches!(
            ReadPermit::acquire(Arc::clone(&state), "binding-extra".to_owned()),
            Err(CheckAuditReadApiError::ConcurrencyLimit)
        ));
        drop(permits);

        let same_binding = (0..MAX_READS_PER_BINDING)
            .map(|_| ReadPermit::acquire(Arc::clone(&state), "binding-same".to_owned()))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(matches!(
            ReadPermit::acquire(Arc::clone(&state), "binding-same".to_owned()),
            Err(CheckAuditReadApiError::ConcurrencyLimit)
        ));
        drop(same_binding);
        assert_eq!(state.lock().unwrap().total, 0);
        assert!(state.lock().unwrap().per_binding.is_empty());
    }

    #[test]
    fn close_binding_removes_only_its_capabilities_and_rejects_late_results() {
        let current = scope("server", 1);
        let mut stale = current.clone();
        stale.session_id = "session-server-stale".to_owned();
        stale.target.generation += 1;
        let other = scope("other", 1);
        let (current_snapshot, _) = build_catalog(current.clone(), Vec::new()).unwrap();
        let current_handle = current_snapshot.handle.clone();
        let (stale_snapshot, _) = build_catalog(stale, Vec::new()).unwrap();
        let stale_handle = stale_snapshot.handle.clone();
        let (other_snapshot, _) = build_catalog(other.clone(), Vec::new()).unwrap();
        let other_handle = other_snapshot.handle.clone();
        let other_bytes = other_snapshot.stored_bytes;

        let mut registry = AuditCatalogRegistry::default();
        registry.insert(current_snapshot).unwrap();
        registry.insert(stale_snapshot).unwrap();
        registry.insert(other_snapshot).unwrap();
        let (late_access, late_commands) = registry.begin_read(&current, &current_handle).unwrap();

        registry.close_binding(&current.binding_handle);

        assert!(!registry.snapshots.contains_key(&current_handle));
        assert!(!registry.snapshots.contains_key(&stale_handle));
        assert!(registry.snapshots.contains_key(&other_handle));
        assert_eq!(registry.total_bytes(), other_bytes);
        assert!(matches!(
            registry.verify(&late_access),
            Err(CheckAuditReadApiError::SnapshotStale)
        ));
        registry.release_read(&current_handle, late_access.token);
        let (_, kept_commands) = registry.begin_read(&other, &other_handle).unwrap();
        assert_eq!(kept_commands.len(), late_commands.len());
    }

    #[test]
    fn status_projection_uses_handles_and_omits_digests_and_backup_paths() {
        let (snapshot, dto) = catalog("server");
        let report = AuditStatusReport {
            is_root: false,
            commands: snapshot
                .commands
                .iter()
                .map(|command| AuditCommandStatus {
                    name: command.name.clone(),
                    path: Some(if command.name == "cat" {
                        "/usr/bin/token=path-secret".to_owned()
                    } else {
                        format!("/usr/bin/{}", command.name)
                    }),
                    state: AuditCommandState::Original,
                    critical: command.critical,
                    backup_path: Some("/secret/backup".to_owned()),
                    original_sha256: Some("a".repeat(64)),
                    wrapper_sha256: Some("b".repeat(64)),
                })
                .collect(),
        };
        let projected = project_status(&dto.snapshot_handle, &snapshot.commands, report).unwrap();
        let text = serde_json::to_string(&projected).unwrap();
        assert!(text.len() <= MAX_STATUS_RESPONSE_BYTES);
        assert!(text.contains("path-secret"));
        assert!(!text.contains("backup"));
        assert!(!text.contains(&"a".repeat(64)));
        assert!(!text.contains(&"b".repeat(64)));
    }

    #[test]
    fn log_projection_filters_hostile_plain_text_without_dropping_lines() {
        let report = AuditLogReport {
            source: AuditLogSource::Read,
            malformed_count: 0,
            entries: vec![
                entry("</td><script>steal()</script>"),
                entry("authorization: Bearer audit-secret"),
            ],
            suspicious_count: 2,
            command_counts: vec![AuditCommandCount {
                command: "cat".to_owned(),
                count: 2,
            }],
        };
        let analysis = AuditAnalysis {
            cycles: vec![AuditCycle {
                command: "cat".to_owned(),
                args: "authorization: Bearer cycle-secret".to_owned(),
                interval_seconds: Some(10),
                count: 2,
                last_seen: "now".to_owned(),
                category: AuditCycleCategory::FileRead,
            }],
            suggestions: vec![AuditSuggestion {
                id: "action-id".to_owned(),
                severity: AuditSuggestionSeverity::Critical,
                title: "Review </div><script>x()</script>".to_owned(),
                description: "token=suggestion-secret".to_owned(),
                check_command: "cat /etc/shadow".to_owned(),
                fix_command: "rm -rf /".to_owned(),
            }],
        };
        let dto = project_log("snapshot-1", 10, Some("steal()"), report, analysis).unwrap();
        let text = serde_json::to_string(&dto).unwrap();
        assert!(text.len() <= MAX_LOG_RESPONSE_BYTES);
        assert_eq!(dto.fetched_count, 2);
        assert_eq!(dto.matched_count, 1);
        assert!(text.contains("</td><script>steal()</script>"));
        // The second entry is filtered out by the keyword, not blanked.
        assert!(!text.contains("audit-secret"));
        assert!(text.contains("cycle-secret"));
        assert!(text.contains("suggestion-secret"));
        assert!(!text.contains("action-id"));
        assert!(!text.contains("/etc/shadow"));
        assert!(!text.contains("rm -rf"));
    }

    #[test]
    fn log_state_and_lines_that_are_no_record_reach_the_page_as_they_are() {
        let empty = || AuditAnalysis {
            cycles: Vec::new(),
            suggestions: Vec::new(),
        };
        for (source, state) in [
            (AuditLogSource::Absent, "absent"),
            (AuditLogSource::NotRegularFile, "not-regular-file"),
            (AuditLogSource::Unreadable, "unreadable"),
        ] {
            let report = AuditLogReport {
                source,
                entries: Vec::new(),
                suspicious_count: 0,
                malformed_count: 0,
                command_counts: Vec::new(),
            };
            let dto = project_log("snapshot-1", 10, None, report, empty()).unwrap();
            assert_eq!(dto.log_state, state);
            assert_eq!(dto.fetched_count, 0);
        }
        // A state that read nothing cannot come with entries.
        let report = AuditLogReport {
            source: AuditLogSource::Absent,
            entries: vec![entry("x")],
            suspicious_count: 1,
            malformed_count: 0,
            command_counts: vec![AuditCommandCount {
                command: "cat".to_owned(),
                count: 1,
            }],
        };
        assert!(project_log("snapshot-1", 10, None, report, empty()).is_err());

        let mut odd = entry("");
        odd.malformed = true;
        odd.command = String::new();
        odd.caller = String::new();
        odd.raw = "rm -rf /tmp/x </pre>".to_owned();
        let report = AuditLogReport {
            source: AuditLogSource::Read,
            entries: vec![odd.clone(), entry("/etc/passwd")],
            suspicious_count: 2,
            malformed_count: 1,
            command_counts: vec![AuditCommandCount {
                command: "cat".to_owned(),
                count: 1,
            }],
        };
        let dto = project_log("snapshot-1", 10, Some("rm -rf"), report, empty()).unwrap();
        assert_eq!(dto.log_state, "read");
        assert_eq!(dto.malformed_count, 1);
        assert_eq!(dto.matched_count, 1);
        assert!(dto.entries[0].malformed);
        assert_eq!(dto.entries[0].args, "rm -rf /tmp/x </pre>");
        assert!(dto.entries[0].command.is_empty());
        // The count of lines that are no record must be the true one.
        let report = AuditLogReport {
            source: AuditLogSource::Read,
            entries: vec![odd],
            suspicious_count: 1,
            malformed_count: 0,
            command_counts: Vec::new(),
        };
        assert!(project_log("snapshot-1", 10, None, report, empty()).is_err());
    }

    #[test]
    fn projections_enforce_item_text_and_unicode_byte_bounds() {
        let oversized_unicode = "猫".repeat(2_000);
        let (bounded, truncated) = bounded_text(&oversized_unicode, 2_048);
        assert!(truncated);
        assert!(bounded.len() <= 2_048);
        assert!(bounded.is_char_boundary(bounded.len()));

        let (snapshot, dto) = catalog("unicode-status");
        let command = snapshot.commands[0].clone();
        let projected = project_status(
            &dto.snapshot_handle,
            std::slice::from_ref(&command),
            AuditStatusReport {
                is_root: false,
                commands: vec![AuditCommandStatus {
                    name: command.name.clone(),
                    path: Some(oversized_unicode.clone()),
                    state: AuditCommandState::Original,
                    critical: command.critical,
                    backup_path: None,
                    original_sha256: None,
                    wrapper_sha256: None,
                }],
            },
        )
        .unwrap();
        assert!(projected.truncated);
        assert!(projected.commands[0].text_truncated);
        let location = projected.commands[0].display_location.as_ref().unwrap();
        assert!(location.len() <= 4 * 1_024);
        assert!(location.is_char_boundary(location.len()));

        let report = AuditLogReport {
            source: AuditLogSource::Read,
            malformed_count: 0,
            entries: vec![entry("plain text"); MAX_LOG_ENTRIES + 1],
            suspicious_count: MAX_LOG_ENTRIES + 1,
            command_counts: vec![AuditCommandCount {
                command: "cat".to_owned(),
                count: MAX_LOG_ENTRIES + 1,
            }],
        };
        assert!(matches!(
            project_log(
                "snapshot-1",
                MAX_LOG_ENTRIES,
                None,
                report,
                AuditAnalysis {
                    cycles: Vec::new(),
                    suggestions: Vec::new(),
                },
            ),
            Err(CheckAuditReadApiError::SnapshotStale)
        ));

        let impossible_cycles = (0..2)
            .map(|index| AuditCycle {
                command: "cat".to_owned(),
                args: format!("/tmp/file-{index}"),
                interval_seconds: Some(10),
                count: 2,
                last_seen: "2026-08-24 01:02:03".to_owned(),
                category: AuditCycleCategory::FileRead,
            })
            .collect();
        assert!(matches!(
            project_log(
                "snapshot-1",
                2,
                None,
                AuditLogReport {
                    source: AuditLogSource::Read,
                    malformed_count: 0,
                    entries: vec![entry("first"), entry("second")],
                    suspicious_count: 2,
                    command_counts: vec![AuditCommandCount {
                        command: "cat".to_owned(),
                        count: 2,
                    }],
                },
                AuditAnalysis {
                    cycles: impossible_cycles,
                    suggestions: Vec::new(),
                },
            ),
            Err(CheckAuditReadApiError::SnapshotStale)
        ));
    }

    #[test]
    fn source_only_calls_core_read_service_without_mutation_or_generic_execution() {
        let source = include_str!("check_audit_read_api.rs");
        for required in [
            ".audit().statuses(",
            ".audit()\n            .read_log(",
            ".audit().analyze(",
        ] {
            assert!(source.contains(required), "missing core call {required}");
        }
        for forbidden in [
            ["plan_", "deploy"].concat(),
            ["plan_", "restore"].concat(),
            ["plan_", "clear_log"].concat(),
            ["execute_", "mutation"].concat(),
            ["build_", "status_command"].concat(),
            ["execute_", "bound"].concat(),
            ["open_", "terminal"].concat(),
            ["export_", "audit"].concat(),
        ] {
            assert!(
                !source.contains(&forbidden),
                "forbidden surface {forbidden}"
            );
        }
    }
}
