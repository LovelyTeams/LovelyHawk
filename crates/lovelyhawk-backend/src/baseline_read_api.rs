//! Standalone desktop boundary for target-bound, read-only baseline inspection.
//!
//! Core owns the catalog, remote scan command, portable history, target guards, and every
//! mutation primitive. This adapter exposes only bounded catalog metadata, current observations,
//! compliance, and safe history summaries. Raw record/operation identities, digests, paths, and
//! backup evidence stay behind target-scoped opaque handles.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use lovelyhawk_core::{
    BackendServices, CoreError,
    baseline::{
        BaselineCategory, BaselineChangeRecord, BaselineChangeState, BaselineComponent,
        BaselineDefinition, BaselineFileView, BaselineObservedValue, BaselineRemediation,
        BaselineRisk, BaselineScan, BaselineValueKind, PRESENCE_MARKER,
    },
    ssh::BoundSshSession,
    target::TargetGuard,
};
use serde::Serialize;
use uuid::Uuid;

use crate::ssh_api::SshApi;

const MAX_HANDLE_BYTES: usize = 128;
/// The catalogue covers the operating system, SSH, four databases and two web
/// servers, so the ceiling is set above what the catalogue can grow to rather
/// than at what it happened to be. It is still a fixed bound: the list is
/// compiled in, and a scan that returned more rows than this would be refused.
const MAX_CATALOG_ITEMS: usize = 160;
const MAX_STATUS_ITEMS: usize = 160;
const MAX_HISTORY_ENTRIES: usize = 256;
const MAX_OPTIONS: usize = 16;
const MAX_TITLE_BYTES: usize = 256;
const MAX_DESCRIPTION_BYTES: usize = 2 * 1024;
const MAX_RECOMMENDATION_BYTES: usize = 128;
const MAX_OPTION_BYTES: usize = 128;
const MAX_OBSERVED_BYTES: usize = 512;
const MAX_HISTORY_SUMMARY_BYTES: usize = 1024;
const MAX_CATALOG_TEXT_BYTES: usize = 128 * 1024;
const MAX_STATUS_TEXT_BYTES: usize = 64 * 1024;
const MAX_HISTORY_TEXT_BYTES: usize = 128 * 1024;
const MAX_CATALOG_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_SCAN_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_HISTORY_RESPONSE_BYTES: usize = 512 * 1024;
const MAX_SNAPSHOT_BYTES: usize = 768 * 1024;
const MAX_SNAPSHOTS: usize = 12;
const MAX_REGISTRY_BYTES: usize = 4 * 1024 * 1024;
const MAX_GLOBAL_READS: usize = 4;
const MAX_READS_PER_BINDING: usize = 1;
const SNAPSHOT_TTL: Duration = Duration::from_secs(5 * 60);
/// The text the frozen `redacted` flag would have to be paired with.
///
/// Nothing sets that flag any more — hiding by credential shape swallowed the
/// evidence a baseline is read for — but the window still refuses a row that
/// claims to be redacted without carrying exactly this string, so the two sides
/// must not drift apart. Kept as the definition of a flag, not as a decision.
#[allow(
    dead_code,
    reason = "paired with a frozen flag the window still checks"
)]
const REDACTED_TEXT: &str = "[SENSITIVE BASELINE TEXT REDACTED]";
/// What a check that only reports whether a directive is set says instead of
/// the value, which for those checks is a credential.
const PRESENCE_LABEL: &str = "已设置";
/// The instruction beside a check: at most a handful of lines, each of them a
/// configuration line rather than prose.
const MAX_FIX_LINES: usize = 8;
const MAX_FIX_LINE_BYTES: usize = 256;
const MAX_FIX_FILE_BYTES: usize = 4 * 1024;
/// A configuration file the operator is meant to read on screen. The core cuts
/// at the same ceiling; this is the boundary saying so again.
const MAX_FILE_TEXT_BYTES: usize = 256 * 1024;
const MAX_FILE_LINES: usize = 4_000;
const MAX_FILE_MENTIONS: usize = 256;
const MAX_FILE_RESPONSE_BYTES: usize = 384 * 1024;

#[derive(Clone)]
pub(crate) struct BaselineReadApi {
    services: BackendServices,
    ssh_api: Arc<SshApi>,
    catalog: Arc<CatalogProjection>,
    snapshots: Arc<Mutex<SnapshotRegistry>>,
    concurrency: Arc<Mutex<ConcurrencyState>>,
}

impl fmt::Debug for BaselineReadApi {
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
            .debug_struct("BaselineReadApi")
            .field("catalog_item_count", &self.catalog.dto.items.len())
            .field("catalog_bytes", &self.catalog.stored_bytes)
            .field("snapshot_count", &snapshot_count)
            .field("snapshot_bytes", &snapshot_bytes)
            .field("active_reads", &active_reads)
            .finish()
    }
}

impl BaselineReadApi {
    pub(crate) fn new(
        services: BackendServices,
        ssh_api: Arc<SshApi>,
    ) -> Result<Self, BaselineReadApiError> {
        let catalog = Arc::new(CatalogProjection::build(services.baseline().catalog())?);
        Ok(Self {
            services,
            ssh_api,
            catalog,
            snapshots: Arc::new(Mutex::new(SnapshotRegistry::default())),
            concurrency: Arc::new(Mutex::new(ConcurrencyState::default())),
        })
    }

    pub(crate) fn get_catalog(&self) -> Result<BaselineCatalogDto, BaselineReadApiError> {
        ensure_serialized_bound(&self.catalog.dto, MAX_CATALOG_RESPONSE_BYTES)?;
        Ok(self.catalog.dto.clone())
    }

    pub(crate) async fn scan(
        &self,
        binding_handle: &str,
    ) -> Result<BaselineScanDto, BaselineReadApiError> {
        let (session, scope) = self.capture_binding(binding_handle)?;
        self.prune_snapshots(&scope)?;
        let _permit = self.acquire_read(&scope)?;
        let scan = self.services.baseline().scan(&session).await?;
        self.validate_binding(&scope)?;
        if scan.target != scope.target {
            return Err(BaselineReadApiError::BindingUnavailable);
        }
        let result = self.lock_snapshots()?.insert_scan(
            scope.clone(),
            scan,
            &self.catalog,
            Instant::now(),
        )?;
        if let Err(error) = self.validate_binding(&scope) {
            self.remove_snapshot(&result.scan_handle);
            return Err(error);
        }
        Ok(result)
    }

    /// Reads the configuration file one catalogue item is checked against.
    ///
    /// The caller names an item, not a file. The path comes from the fixed
    /// catalogue inside the core, so a forged handle reaches nothing and a
    /// real one can only ever open one of the six files the checks live in.
    pub(crate) async fn read_setting_file(
        &self,
        binding_handle: &str,
        item_handle: &str,
    ) -> Result<BaselineFileDto, BaselineReadApiError> {
        validate_handle(item_handle)?;
        let item_id = self.catalog.id_for(item_handle)?;
        let (session, scope) = self.capture_binding(binding_handle)?;
        let _permit = self.acquire_read(&scope)?;
        let view = self
            .services
            .baseline()
            .read_setting_file(&session, item_id)
            .await?;
        self.validate_binding(&scope)?;
        let dto = project_file_view(item_handle, &view)?;
        ensure_serialized_bound(&dto, MAX_FILE_RESPONSE_BYTES)?;
        self.validate_binding(&scope)?;
        Ok(dto)
    }

    pub(crate) async fn list_history(
        &self,
        binding_handle: &str,
    ) -> Result<BaselineHistoryDto, BaselineReadApiError> {
        let (session, scope) = self.capture_binding(binding_handle)?;
        self.prune_snapshots(&scope)?;
        let _permit = self.acquire_read(&scope)?;
        let records = self.services.baseline().list_history(session.target())?;
        self.validate_binding(&scope)?;
        let result = self.lock_snapshots()?.insert_history(
            scope.clone(),
            records,
            &self.catalog,
            Instant::now(),
        )?;
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

    /// The catalogue entry an item handle stands for, for planning a change.
    pub(crate) fn item_id_for(
        &self,
        item_handle: &str,
    ) -> Result<&'static str, BaselineReadApiError> {
        validate_handle(item_handle)?;
        self.catalog.id_for(item_handle)
    }

    /// The change record a history entry of a live history snapshot of this
    /// binding stands for. A handle from another binding, another snapshot
    /// or past its time names nothing.
    pub(crate) fn resolve_history_record(
        &self,
        binding_handle: &str,
        history_handle: &str,
        history_item_handle: &str,
    ) -> Result<String, BaselineReadApiError> {
        validate_handle(history_handle)?;
        validate_handle(history_item_handle)?;
        let (_, scope) = self.capture_binding(binding_handle)?;
        let registry = self.lock_snapshots()?;
        let now = Instant::now();
        let snapshot = registry
            .snapshots
            .get(history_handle)
            .filter(|snapshot| snapshot.scope == scope && snapshot.expires_at > now)
            .ok_or(BaselineReadApiError::InvalidHandle)?;
        let SnapshotData::History { records } = &snapshot.data else {
            return Err(BaselineReadApiError::InvalidHandle);
        };
        records
            .get(history_item_handle)
            .cloned()
            .ok_or(BaselineReadApiError::InvalidHandle)
    }

    fn capture_binding(
        &self,
        binding_handle: &str,
    ) -> Result<(BoundSshSession, BindingScope), BaselineReadApiError> {
        validate_handle(binding_handle)?;
        let session = self
            .ssh_api
            .binding_session_clone(binding_handle)
            .map_err(|_| BaselineReadApiError::BindingUnavailable)?;
        self.services
            .target()
            .validate(session.target())
            .map_err(|_| BaselineReadApiError::BindingUnavailable)?;
        let scope = BindingScope::from_session(binding_handle, &session);
        Ok((session, scope))
    }

    fn validate_binding(&self, expected: &BindingScope) -> Result<(), BaselineReadApiError> {
        let (_, current) = self.capture_binding(&expected.binding_handle)?;
        if &current != expected {
            return Err(BaselineReadApiError::BindingUnavailable);
        }
        Ok(())
    }

    fn acquire_read(&self, scope: &BindingScope) -> Result<ReadPermit, BaselineReadApiError> {
        ReadPermit::acquire(Arc::clone(&self.concurrency), scope.concurrency_key())
    }

    fn prune_snapshots(&self, scope: &BindingScope) -> Result<(), BaselineReadApiError> {
        self.lock_snapshots()?.prune(Instant::now(), Some(scope));
        Ok(())
    }

    fn remove_snapshot(&self, handle: &str) {
        if let Ok(mut registry) = self.snapshots.lock() {
            registry.remove(handle);
        }
    }

    fn lock_snapshots(&self) -> Result<MutexGuard<'_, SnapshotRegistry>, BaselineReadApiError> {
        self.snapshots
            .lock()
            .map_err(|_| BaselineReadApiError::RegistryUnavailable)
    }
}

pub(crate) enum BaselineReadApiError {
    Core,
    BindingUnavailable,
    InvalidHandle,
    InvalidData,
    OutputLimit,
    ConcurrencyLimit,
    RegistryUnavailable,
}

impl fmt::Debug for BaselineReadApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core => "Core([REDACTED])",
            Self::BindingUnavailable => "BindingUnavailable",
            Self::InvalidHandle => "InvalidHandle",
            Self::InvalidData => "InvalidData",
            Self::OutputLimit => "OutputLimit",
            Self::ConcurrencyLimit => "ConcurrencyLimit",
            Self::RegistryUnavailable => "RegistryUnavailable",
        })
    }
}

impl fmt::Display for BaselineReadApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core => "the baseline read operation failed",
            Self::BindingUnavailable => "the SSH binding is missing or stale",
            Self::InvalidHandle => "the baseline handle is invalid",
            Self::InvalidData => "the baseline result is invalid",
            Self::OutputLimit => "the baseline result exceeded its public limit",
            Self::ConcurrencyLimit => "the baseline read concurrency limit was reached",
            Self::RegistryUnavailable => "the baseline registry is unavailable",
        })
    }
}

impl std::error::Error for BaselineReadApiError {}

impl From<CoreError> for BaselineReadApiError {
    fn from(error: CoreError) -> Self {
        // The renderer only ever sees a fixed message, so without this the
        // reason a page failed is lost before anyone can read it.
        tracing::warn!(operation = "BaselineRead", error = %error, "core operation failed");
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
        formatter.write_str("BaselineBindingScope([REDACTED])")
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BaselineCatalogDto {
    items: Vec<BaselineCatalogItemDto>,
    displayed: usize,
    truncated: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BaselineCatalogItemDto {
    item_handle: String,
    category: &'static str,
    /// Which piece of software this check is about. Fixed at compile time.
    component: &'static str,
    risk: &'static str,
    value_kind: PublicBaselineValueKind,
    title: String,
    description: String,
    recommendation: String,
    /// Whether this tool would write the change, or only report it.
    writable: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum PublicBaselineValueKind {
    Choice { options: Vec<String> },
    Integer { minimum: u32, maximum: u32 },
}

/// One of the six fixed configuration files, as it stands on the target.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BaselineFileDto {
    item_handle: String,
    /// The file this check reads. Fixed by the catalogue, so it is a label
    /// rather than something the window can act on.
    path: String,
    key: String,
    exists: bool,
    text: String,
    line_count: usize,
    mentions: Vec<BaselineFileMentionDto>,
    truncated: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BaselineFileMentionDto {
    line: u32,
    commented: bool,
    effective: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BaselineScanDto {
    scan_handle: String,
    captured_at: String,
    expires_in_seconds: u64,
    statuses: Vec<BaselineStatusDto>,
    displayed: usize,
    compliant_count: usize,
    non_compliant_count: usize,
    redacted_field_count: usize,
    truncated: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BaselineStatusDto {
    item_handle: String,
    observed_kind: &'static str,
    observed: String,
    compliant: bool,
    redacted: bool,
    text_truncated: bool,
    /// What to change on this target to bring this setting to the recommended
    /// value. A label and an instruction; the window cannot act on it.
    fix: BaselineFixDto,
}

/// The instruction for one setting: which file, which lines, what to run.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BaselineFixDto {
    file: String,
    lines: Vec<String>,
    reload: Option<String>,
    /// Set when this tool will not make the change itself, and why.
    manual_reason: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BaselineHistoryDto {
    history_handle: String,
    expires_in_seconds: u64,
    entries: Vec<BaselineHistoryEntryDto>,
    displayed: usize,
    redacted_field_count: usize,
    truncated: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BaselineHistoryEntryDto {
    history_item_handle: String,
    state: &'static str,
    /// Whether a restore can be planned from this entry: an applied change
    /// that carries the evidence of the complete files it left. Older
    /// records stay readable only.
    restorable: bool,
    summary: String,
    change_count: usize,
    created_at: String,
    updated_at: String,
    redacted: bool,
    text_truncated: bool,
}

struct CatalogProjection {
    dto: BaselineCatalogDto,
    handles_by_id: HashMap<String, String>,
    /// The way back: a handle the window was given resolves to the catalogue
    /// entry it stands for, and to nothing else.
    ids_by_handle: HashMap<String, &'static str>,
    titles_by_id: HashMap<String, String>,
    stored_bytes: usize,
}

impl fmt::Debug for CatalogProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BaselineCatalogProjection")
            .field("item_count", &self.dto.items.len())
            .field("stored_bytes", &self.stored_bytes)
            .finish()
    }
}

impl CatalogProjection {
    fn build(definitions: &[BaselineDefinition]) -> Result<Self, BaselineReadApiError> {
        if definitions.is_empty() || definitions.len() > MAX_CATALOG_ITEMS {
            return Err(BaselineReadApiError::InvalidData);
        }
        let mut handles = HashSet::new();
        let mut raw_ids = HashSet::new();
        let mut handles_by_id = HashMap::with_capacity(definitions.len());
        let mut titles_by_id = HashMap::with_capacity(definitions.len());
        let mut items = Vec::with_capacity(definitions.len());
        let mut text_bytes = 0usize;
        for definition in definitions {
            if !raw_ids.insert(definition.id) {
                return Err(BaselineReadApiError::InvalidData);
            }
            let item_handle =
                unique_handle("baseline-item", |candidate| handles.contains(candidate))?;
            handles.insert(item_handle.clone());
            let title = trusted_catalog_text(definition.title, MAX_TITLE_BYTES)?;
            let description = trusted_catalog_text(definition.description, MAX_DESCRIPTION_BYTES)?;
            // A presence check has no value to recommend, only the fact of
            // being set. The core says that with a marker so nothing has to
            // parse Chinese; the window is where it becomes words.
            let recommendation = if definition.component == BaselineComponent::Redis
                && definition.value_kind == BaselineValueKind::Boolean
            {
                if definition.recommendation == "on" {
                    "yes"
                } else {
                    "no"
                }
                .to_owned()
            } else if definition.component == BaselineComponent::Redis
                && definition.value_kind == BaselineValueKind::Presence
            {
                match definition.id {
                    "redis-bind" => "按业务范围限定监听地址",
                    "redis-requirepass" => "核对认证与 ACL",
                    "redis-rename-command" => "用 ACL 核对危险命令权限",
                    "redis-logfile" => "核对日志收集与留存",
                    _ => PRESENCE_LABEL,
                }
                .to_owned()
            } else if definition.id == "nginx-ssl-protocols" {
                "仅启用实例支持的 TLS 1.2/1.3".to_owned()
            } else if definition.id == "postgresql-logging-collector" {
                "核对实际日志去向与持久留存".to_owned()
            } else if definition.value_kind == BaselineValueKind::Presence {
                PRESENCE_LABEL.to_owned()
            } else {
                trusted_catalog_text(definition.recommendation, MAX_RECOMMENDATION_BYTES)?
            };
            let value_kind = match definition.value_kind {
                BaselineValueKind::Choice(options) => {
                    if options.is_empty() || options.len() > MAX_OPTIONS {
                        return Err(BaselineReadApiError::InvalidData);
                    }
                    let mut seen = HashSet::new();
                    let mut public_options = Vec::with_capacity(options.len());
                    for option in options {
                        let option = trusted_catalog_text(option, MAX_OPTION_BYTES)?;
                        if !seen.insert(option.clone()) {
                            return Err(BaselineReadApiError::InvalidData);
                        }
                        public_options.push(option);
                    }
                    if !public_options
                        .iter()
                        .any(|option| option == &recommendation)
                    {
                        return Err(BaselineReadApiError::InvalidData);
                    }
                    PublicBaselineValueKind::Choice {
                        options: public_options,
                    }
                }
                BaselineValueKind::Integer { minimum, maximum } => {
                    let recommended = recommendation
                        .parse::<u32>()
                        .map_err(|_| BaselineReadApiError::InvalidData)?;
                    if minimum > maximum || !(minimum..=maximum).contains(&recommended) {
                        return Err(BaselineReadApiError::InvalidData);
                    }
                    PublicBaselineValueKind::Integer { minimum, maximum }
                }
                // A truth value is a choice of two, whatever the file spells
                // it; the window offers the two it would ask for.
                BaselineValueKind::Boolean if definition.component == BaselineComponent::Redis => {
                    PublicBaselineValueKind::Choice {
                        options: vec!["yes".to_owned(), "no".to_owned()],
                    }
                }
                BaselineValueKind::Boolean => PublicBaselineValueKind::Choice {
                    options: vec!["on".to_owned(), "off".to_owned()],
                },
                // Nothing to choose: the check reports only whether the
                // directive is set, because its value is a credential.
                BaselineValueKind::Presence => PublicBaselineValueKind::Choice {
                    options: vec![recommendation.clone()],
                },
            };
            text_bytes = text_bytes
                .saturating_add(title.len())
                .saturating_add(description.len())
                .saturating_add(recommendation.len());
            if let PublicBaselineValueKind::Choice { options } = &value_kind {
                text_bytes = text_bytes.saturating_add(
                    options
                        .iter()
                        .map(String::len)
                        .fold(0usize, usize::saturating_add),
                );
            }
            if text_bytes > MAX_CATALOG_TEXT_BYTES {
                return Err(BaselineReadApiError::OutputLimit);
            }
            handles_by_id.insert(definition.id.to_owned(), item_handle.clone());
            titles_by_id.insert(definition.id.to_owned(), title.clone());
            items.push(BaselineCatalogItemDto {
                item_handle,
                category: category_key(definition.category),
                component: component_key(definition.component),
                risk: risk_key(definition.risk),
                value_kind,
                title,
                description,
                recommendation,
                writable: definition.is_writable(),
            });
        }
        let dto = BaselineCatalogDto {
            displayed: items.len(),
            items,
            truncated: false,
        };
        let response_bytes = serialized_bytes(&dto)?;
        if response_bytes > MAX_CATALOG_RESPONSE_BYTES {
            return Err(BaselineReadApiError::OutputLimit);
        }
        let stored_bytes = response_bytes
            .saturating_add(
                handles_by_id
                    .iter()
                    .map(|(raw_id, handle)| raw_id.len().saturating_add(handle.len()))
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(
                titles_by_id
                    .iter()
                    .map(|(raw_id, title)| raw_id.len().saturating_add(title.len()))
                    .fold(0usize, usize::saturating_add),
            );
        if stored_bytes > MAX_CATALOG_RESPONSE_BYTES {
            return Err(BaselineReadApiError::OutputLimit);
        }
        let ids_by_handle = definitions
            .iter()
            .filter_map(|definition| {
                handles_by_id
                    .get(definition.id)
                    .map(|handle| (handle.clone(), definition.id))
            })
            .collect::<HashMap<_, _>>();
        if ids_by_handle.len() != handles_by_id.len() {
            return Err(BaselineReadApiError::InvalidData);
        }
        Ok(Self {
            dto,
            handles_by_id,
            ids_by_handle,
            titles_by_id,
            stored_bytes,
        })
    }

    /// The catalogue entry a handle stands for, or nothing.
    fn id_for(&self, item_handle: &str) -> Result<&'static str, BaselineReadApiError> {
        self.ids_by_handle
            .get(item_handle)
            .copied()
            .ok_or(BaselineReadApiError::InvalidHandle)
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
    ) -> Result<Self, BaselineReadApiError> {
        {
            let mut current = state
                .lock()
                .map_err(|_| BaselineReadApiError::RegistryUnavailable)?;
            let binding_reads = current.per_binding.get(&key).copied().unwrap_or_default();
            if current.total >= MAX_GLOBAL_READS || binding_reads >= MAX_READS_PER_BINDING {
                return Err(BaselineReadApiError::ConcurrencyLimit);
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
            .debug_struct("BaselineSnapshotRegistry")
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
    Scan {
        _statuses: Vec<BaselineStatusDto>,
    },
    /// The record id each history entry handle stands for; never sent.
    History {
        records: HashMap<String, String>,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SnapshotKind {
    Scan,
    History,
}

impl SnapshotData {
    const fn kind(&self) -> SnapshotKind {
        match self {
            Self::Scan { .. } => SnapshotKind::Scan,
            Self::History { .. } => SnapshotKind::History,
        }
    }
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

    fn insert_scan(
        &mut self,
        scope: BindingScope,
        scan: BaselineScan,
        catalog: &CatalogProjection,
        now: Instant,
    ) -> Result<BaselineScanDto, BaselineReadApiError> {
        self.prune(now, Some(&scope));
        if scan.target != scope.target {
            return Err(BaselineReadApiError::InvalidData);
        }
        let scan_handle = self.unique_snapshot_handle("baseline-scan")?;
        let dto = project_scan(scan_handle.clone(), scan, catalog)?;
        let response_bytes = serialized_bytes(&dto)?;
        if response_bytes > MAX_SCAN_RESPONSE_BYTES {
            return Err(BaselineReadApiError::OutputLimit);
        }
        let bytes = response_bytes
            .saturating_add(scope.storage_bytes())
            .saturating_add(
                dto.statuses
                    .iter()
                    .map(|status| {
                        status
                            .item_handle
                            .len()
                            .saturating_add(status.observed.len())
                    })
                    .fold(0usize, usize::saturating_add),
            );
        self.insert_snapshot(
            scan_handle,
            scope,
            SnapshotData::Scan {
                _statuses: dto.statuses.clone(),
            },
            bytes,
            now,
        )?;
        Ok(dto)
    }

    fn insert_history(
        &mut self,
        scope: BindingScope,
        records: Vec<BaselineChangeRecord>,
        catalog: &CatalogProjection,
        now: Instant,
    ) -> Result<BaselineHistoryDto, BaselineReadApiError> {
        self.prune(now, Some(&scope));
        let history_handle = self.unique_snapshot_handle("baseline-history")?;
        let (dto, record_ids) = project_history(history_handle.clone(), &scope, records, catalog)?;
        let response_bytes = serialized_bytes(&dto)?;
        if response_bytes > MAX_HISTORY_RESPONSE_BYTES {
            return Err(BaselineReadApiError::OutputLimit);
        }
        let bytes = response_bytes
            .saturating_add(scope.storage_bytes())
            .saturating_add(
                record_ids
                    .iter()
                    .map(|(handle, id)| handle.len() + id.len())
                    .sum(),
            );
        self.insert_snapshot(
            history_handle,
            scope,
            SnapshotData::History {
                records: record_ids,
            },
            bytes,
            now,
        )?;
        Ok(dto)
    }

    fn insert_snapshot(
        &mut self,
        handle: String,
        scope: BindingScope,
        data: SnapshotData,
        bytes: usize,
        now: Instant,
    ) -> Result<(), BaselineReadApiError> {
        if bytes > MAX_SNAPSHOT_BYTES || self.snapshots.contains_key(&handle) {
            return Err(BaselineReadApiError::OutputLimit);
        }
        let kind = data.kind();
        let replaced = self
            .snapshots
            .iter()
            .filter_map(|(existing_handle, existing)| {
                (existing.scope == scope && existing.data.kind() == kind)
                    .then_some(existing_handle.clone())
            })
            .collect::<Vec<_>>();
        for existing_handle in replaced {
            self.remove(&existing_handle);
        }
        self.make_room(bytes)?;
        self.total_bytes = self.total_bytes.saturating_add(bytes);
        self.snapshots.insert(
            handle,
            SnapshotEntry {
                scope,
                data,
                bytes,
                expires_at: now + SNAPSHOT_TTL,
                touched_at: now,
            },
        );
        Ok(())
    }

    fn make_room(&mut self, incoming: usize) -> Result<(), BaselineReadApiError> {
        while self.snapshots.len() >= MAX_SNAPSHOTS
            || self.total_bytes.saturating_add(incoming) > MAX_REGISTRY_BYTES
        {
            let oldest = self
                .snapshots
                .iter()
                .min_by_key(|(_, entry)| entry.touched_at)
                .map(|(handle, _)| handle.clone())
                .ok_or(BaselineReadApiError::OutputLimit)?;
            self.remove(&oldest);
        }
        if self.total_bytes.saturating_add(incoming) > MAX_REGISTRY_BYTES {
            return Err(BaselineReadApiError::OutputLimit);
        }
        Ok(())
    }

    fn remove(&mut self, handle: &str) {
        if let Some(entry) = self.snapshots.remove(handle) {
            self.total_bytes = self.total_bytes.saturating_sub(entry.bytes);
        }
    }

    fn unique_snapshot_handle(&self, prefix: &str) -> Result<String, BaselineReadApiError> {
        unique_handle(prefix, |candidate| self.snapshots.contains_key(candidate))
    }

    #[cfg(test)]
    fn resolve_history(
        &self,
        scope: &BindingScope,
        history_handle: &str,
        now: Instant,
    ) -> Result<(), BaselineReadApiError> {
        let snapshot = self
            .snapshots
            .get(history_handle)
            .filter(|snapshot| &snapshot.scope == scope && snapshot.expires_at > now)
            .ok_or(BaselineReadApiError::InvalidHandle)?;
        if snapshot.data.kind() != SnapshotKind::History {
            return Err(BaselineReadApiError::InvalidHandle);
        }
        Ok(())
    }
}

fn project_scan(
    scan_handle: String,
    scan: BaselineScan,
    catalog: &CatalogProjection,
) -> Result<BaselineScanDto, BaselineReadApiError> {
    let total = scan.statuses.len();
    let mut seen = HashSet::new();
    let mut budget = TextBudget::new(MAX_STATUS_TEXT_BYTES);
    let mut statuses = Vec::with_capacity(total.min(MAX_STATUS_ITEMS));
    let mut compliant_count = 0usize;
    let mut redacted_field_count = 0usize;
    let mut truncated = total > MAX_STATUS_ITEMS;
    for status in scan.statuses.into_iter().take(MAX_STATUS_ITEMS) {
        if status.compliant
            && matches!(
                status.observed,
                BaselineObservedValue::Unverified
                    | BaselineObservedValue::Unsupported
                    | BaselineObservedValue::Conditional
                    | BaselineObservedValue::NotInstalled
            )
        {
            return Err(BaselineReadApiError::InvalidData);
        }
        if !seen.insert(status.item_id.clone()) {
            return Err(BaselineReadApiError::InvalidData);
        }
        let item_handle = catalog
            .handles_by_id
            .get(&status.item_id)
            .cloned()
            .ok_or(BaselineReadApiError::InvalidData)?;
        let definition = lovelyhawk_core::baseline::definition(&status.item_id)
            .map_err(|_| BaselineReadApiError::InvalidData)?;
        let fix = project_fix(&definition.remediation(&status.source_file))?;
        let (observed_kind, observed, redacted, text_truncated) = match status.observed {
            BaselineObservedValue::Missing => ("missing", "未设置".to_owned(), false, false),
            BaselineObservedValue::Unverified => (
                "unverified",
                "无法判断（尚未核实配置）".to_owned(),
                false,
                false,
            ),
            BaselineObservedValue::Unsupported => (
                "unsupported",
                "不支持（符号链接或特殊文件）".to_owned(),
                false,
                false,
            ),
            // The software this check is about is not on this target. Saying
            // "not set" here would put it among the findings; it is not one.
            BaselineObservedValue::NotInstalled => {
                ("not-installed", "未安装".to_owned(), false, false)
            }
            // Written behind a `Match`, so it holds for some connections and
            // not others. Reporting the value alone would say this machine is
            // configured a way it is only sometimes configured.
            BaselineObservedValue::Conditional => (
                "conditional",
                "写在 Match 条件块里，只对部分连接生效".to_owned(),
                false,
                false,
            ),
            // A presence check reports a marker rather than the value it
            // found, because the value is the credential the check is about.
            BaselineObservedValue::Value(value)
                if definition.id == "redis-requirepass" && value == "no-auth-directive" =>
            {
                ("value", "候选文件未声明口令或 ACL".to_owned(), false, false)
            }
            BaselineObservedValue::Value(value)
                if definition.id == "postgresql-listen-addresses" && value == "wildcard-listen" =>
            {
                ("value", "候选地址包含通配监听".to_owned(), false, false)
            }
            BaselineObservedValue::Value(value) if value == PRESENCE_MARKER => {
                ("value", PRESENCE_LABEL.to_owned(), false, false)
            }
            BaselineObservedValue::Value(value) => {
                let (value, redacted, truncated) = budget.take_public(&value, MAX_OBSERVED_BYTES);
                ("value", value, redacted, truncated)
            }
        };
        compliant_count += usize::from(status.compliant);
        redacted_field_count += usize::from(redacted);
        truncated |= text_truncated;
        statuses.push(BaselineStatusDto {
            item_handle,
            observed_kind,
            observed,
            compliant: status.compliant,
            redacted,
            text_truncated,
            fix,
        });
    }
    let displayed = statuses.len();
    Ok(BaselineScanDto {
        scan_handle,
        captured_at: scan.captured_at.to_rfc3339(),
        expires_in_seconds: SNAPSHOT_TTL.as_secs(),
        statuses,
        displayed,
        compliant_count,
        non_compliant_count: displayed.saturating_sub(compliant_count),
        redacted_field_count,
        truncated,
    })
}

/// The remediation, bounded the way every other public string is.
///
/// It is built from the catalogue and from a path the core has already checked
/// against that catalogue, so there is nothing here the target chose. The
/// bounds are the boundary saying so anyway.
fn project_fix(fix: &BaselineRemediation) -> Result<BaselineFixDto, BaselineReadApiError> {
    if fix.lines.is_empty() || fix.lines.len() > MAX_FIX_LINES {
        return Err(BaselineReadApiError::InvalidData);
    }
    let file = trusted_catalog_text(&fix.file, MAX_FIX_FILE_BYTES)?;
    let mut lines = Vec::with_capacity(fix.lines.len());
    for line in &fix.lines {
        lines.push(trusted_catalog_text(line, MAX_FIX_LINE_BYTES)?);
    }
    Ok(BaselineFixDto {
        file,
        lines,
        reload: match &fix.reload {
            Some(reload) => Some(trusted_catalog_text(reload, MAX_FIX_LINE_BYTES)?),
            None => None,
        },
        manual_reason: match fix.manual_reason {
            Some(reason) => Some(trusted_catalog_text(reason, MAX_FIX_LINE_BYTES)?),
            None => None,
        },
    })
}

fn project_file_view(
    item_handle: &str,
    view: &BaselineFileView,
) -> Result<BaselineFileDto, BaselineReadApiError> {
    // The core already replaced control characters and cut at its own ceiling.
    // Re-checking here is what makes the boundary a boundary rather than a
    // pass-through that trusts whatever arrived.
    if view.text.len() > MAX_FILE_TEXT_BYTES {
        return Err(BaselineReadApiError::OutputLimit);
    }
    let lines = if view.text.is_empty() {
        0
    } else {
        view.text.lines().count()
    };
    if lines > MAX_FILE_LINES {
        return Err(BaselineReadApiError::OutputLimit);
    }
    if view
        .text
        .chars()
        .any(|character| character != '\n' && character != '\t' && character.is_control())
    {
        return Err(BaselineReadApiError::InvalidData);
    }
    if view.mentions.len() > MAX_FILE_MENTIONS {
        return Err(BaselineReadApiError::OutputLimit);
    }
    let mut effective_seen = false;
    let mut mentions = Vec::with_capacity(view.mentions.len());
    for mention in &view.mentions {
        // A mark that points past the end of the text would draw a highlight
        // on a line the operator cannot see.
        if usize::try_from(mention.line).is_ok_and(|line| line >= lines) {
            return Err(BaselineReadApiError::InvalidData);
        }
        if mention.effective {
            // At most one line is in force; two would be a contradiction.
            if effective_seen || mention.commented {
                return Err(BaselineReadApiError::InvalidData);
            }
            effective_seen = true;
        }
        mentions.push(BaselineFileMentionDto {
            line: mention.line,
            commented: mention.commented,
            effective: mention.effective,
        });
    }
    Ok(BaselineFileDto {
        item_handle: item_handle.to_owned(),
        path: trusted_catalog_text(&view.path, MAX_TITLE_BYTES)?,
        key: trusted_catalog_text(view.key, MAX_RECOMMENDATION_BYTES)?,
        exists: view.exists,
        text: view.text.clone(),
        line_count: lines,
        mentions,
        truncated: view.truncated,
    })
}

fn project_history(
    history_handle: String,
    scope: &BindingScope,
    records: Vec<BaselineChangeRecord>,
    catalog: &CatalogProjection,
) -> Result<(BaselineHistoryDto, HashMap<String, String>), BaselineReadApiError> {
    let total = records.len();
    let mut record_ids = HashMap::with_capacity(total.min(MAX_HISTORY_ENTRIES));
    let mut entries = Vec::with_capacity(total.min(MAX_HISTORY_ENTRIES));
    let mut used_handles = HashSet::with_capacity(total.min(MAX_HISTORY_ENTRIES));
    let mut budget = TextBudget::new(MAX_HISTORY_TEXT_BYTES);
    let mut redacted_field_count = 0usize;
    let mut truncated = total > MAX_HISTORY_ENTRIES;
    for record in records.into_iter().take(MAX_HISTORY_ENTRIES) {
        if record.target != scope.target.identity || record.changes.is_empty() {
            return Err(BaselineReadApiError::InvalidData);
        }
        let history_item_handle = unique_handle("baseline-record", |candidate| {
            used_handles.contains(candidate)
        })?;
        let (summary, redacted, text_truncated) = history_summary(&record, catalog, &mut budget)?;
        redacted_field_count += usize::from(redacted);
        truncated |= text_truncated;
        record_ids.insert(history_item_handle.clone(), record.id.clone());
        entries.push(BaselineHistoryEntryDto {
            history_item_handle: history_item_handle.clone(),
            state: change_state_key(record.state),
            restorable: record.restorable(),
            summary,
            change_count: record.changes.len(),
            created_at: record.created_at.to_rfc3339(),
            updated_at: record.updated_at.to_rfc3339(),
            redacted,
            text_truncated,
        });
        used_handles.insert(history_item_handle);
    }
    let displayed = entries.len();
    Ok((
        BaselineHistoryDto {
            history_handle,
            expires_in_seconds: SNAPSHOT_TTL.as_secs(),
            entries,
            displayed,
            redacted_field_count,
            truncated,
        },
        record_ids,
    ))
}

fn history_summary(
    record: &BaselineChangeRecord,
    catalog: &CatalogProjection,
    budget: &mut TextBudget,
) -> Result<(String, bool, bool), BaselineReadApiError> {
    if record.changes.len() > 64 {
        return Err(BaselineReadApiError::OutputLimit);
    }
    let mut parts = Vec::new();
    for change in record.changes.iter().take(3) {
        let title = catalog
            .titles_by_id
            .get(&change.item_id)
            .ok_or(BaselineReadApiError::InvalidData)?;
        let (before, _, _) = bounded_public_text(change.before.label(), MAX_RECOMMENDATION_BYTES);
        let (after, _, _) = bounded_public_text(&change.after, MAX_RECOMMENDATION_BYTES);
        parts.push(format!("{title}（{before} → {after}）"));
    }
    // Both directions, and which one stands: "restored → no" read as though
    // the restore had set `no`, when it had put `yes` back.
    let state = match record.state {
        BaselineChangeState::Applied => "已应用",
        BaselineChangeState::Restored => "已撤销",
    };
    let suffix = if record.changes.len() > parts.len() {
        format!("；另有 {} 项", record.changes.len() - parts.len())
    } else {
        String::new()
    };
    let raw = format!(
        "{state} {} 项基线改动：{}{}",
        record.changes.len(),
        parts.join("；"),
        suffix,
    );
    let (summary, _, text_truncated) = budget.take_public(&raw, MAX_HISTORY_SUMMARY_BYTES);
    Ok((summary, false, text_truncated || record.changes.len() > 3))
}

struct TextBudget {
    remaining: usize,
}

impl TextBudget {
    const fn new(maximum: usize) -> Self {
        Self { remaining: maximum }
    }

    fn take_public(&mut self, value: &str, maximum: usize) -> (String, bool, bool) {
        let (value, redacted, first_truncated) = bounded_public_text(value, maximum);
        let (value, budget_truncated) = bounded_text(&value, self.remaining);
        self.remaining = self.remaining.saturating_sub(value.len());
        (value, redacted, first_truncated || budget_truncated)
    }
}

/// Cleans control characters and bounds the size. Nothing else.
///
/// The middle value is `redacted` and is always false — the same story as the
/// audit reader: hiding by credential shape swallowed evidence, so it went, and
/// what remained was a flag no code could set and a notice no operator could
/// ever see fire.
fn bounded_public_text(value: &str, maximum: usize) -> (String, bool, bool) {
    let sanitized = value
        .chars()
        .map(|character| {
            if character.is_control() {
                '�'
            } else {
                character
            }
        })
        .collect::<String>();
    let (value, truncated) = bounded_text(&sanitized, maximum);
    (value, false, truncated)
}

fn trusted_catalog_text(value: &str, maximum: usize) -> Result<String, BaselineReadApiError> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(BaselineReadApiError::InvalidData);
    }
    Ok(value.to_owned())
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

const fn category_key(category: BaselineCategory) -> &'static str {
    match category {
        BaselineCategory::Ssh => "ssh",
        BaselineCategory::Password => "password",
        BaselineCategory::Kernel => "kernel",
        BaselineCategory::Network => "network",
        BaselineCategory::Authentication => "authentication",
        BaselineCategory::Logging => "logging",
        BaselineCategory::FilePermissions => "file-permissions",
        BaselineCategory::AccessControl => "access-control",
        BaselineCategory::Transport => "transport",
        BaselineCategory::ServiceHardening => "service-hardening",
    }
}

const fn component_key(component: BaselineComponent) -> &'static str {
    match component {
        BaselineComponent::System => "system",
        BaselineComponent::Ssh => "ssh",
        BaselineComponent::MySql => "mysql",
        BaselineComponent::PostgreSql => "postgresql",
        BaselineComponent::Redis => "redis",
        BaselineComponent::MongoDb => "mongodb",
        BaselineComponent::Nginx => "nginx",
        BaselineComponent::Apache => "apache",
        BaselineComponent::Tomcat => "tomcat",
        BaselineComponent::OpenGauss => "opengauss",
        BaselineComponent::TiDb => "tidb",
        BaselineComponent::HaProxy => "haproxy",
    }
}

const fn risk_key(risk: BaselineRisk) -> &'static str {
    match risk {
        BaselineRisk::Critical => "critical",
        BaselineRisk::High => "high",
        BaselineRisk::Medium => "medium",
        BaselineRisk::Low => "low",
    }
}

const fn change_state_key(state: BaselineChangeState) -> &'static str {
    match state {
        BaselineChangeState::Applied => "applied",
        BaselineChangeState::Restored => "restored",
    }
}

fn validate_handle(value: &str) -> Result<(), BaselineReadApiError> {
    if value.is_empty()
        || value.len() > MAX_HANDLE_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(BaselineReadApiError::InvalidHandle);
    }
    Ok(())
}

fn unique_handle(
    prefix: &str,
    exists: impl Fn(&str) -> bool,
) -> Result<String, BaselineReadApiError> {
    for _ in 0..16 {
        let candidate = format!("{prefix}-{}", Uuid::new_v4().simple());
        if candidate.len() <= MAX_HANDLE_BYTES && !exists(&candidate) {
            return Ok(candidate);
        }
    }
    Err(BaselineReadApiError::OutputLimit)
}

fn serialized_bytes(value: &impl Serialize) -> Result<usize, BaselineReadApiError> {
    serde_json::to_vec(value)
        .map(|encoded| encoded.len())
        .map_err(|_| BaselineReadApiError::InvalidData)
}

fn ensure_serialized_bound(
    value: &impl Serialize,
    maximum: usize,
) -> Result<(), BaselineReadApiError> {
    if serialized_bytes(value)? > maximum {
        return Err(BaselineReadApiError::OutputLimit);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use lovelyhawk_core::{
        PortableStore,
        baseline::{BASELINE_CATALOG, BaselineStatus},
        target::TargetIdentity,
    };
    use serde_json::json;

    use super::*;

    fn scope(name: &str, generation: u64) -> BindingScope {
        scope_with_binding(&format!("binding-{name}"), name, generation)
    }

    fn scope_with_binding(binding_handle: &str, name: &str, generation: u64) -> BindingScope {
        BindingScope {
            binding_handle: binding_handle.to_owned(),
            session_id: format!("session-{name}"),
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
                std::env::temp_dir().join(format!("lovelyres-baseline-read-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn read_api() -> (TestRoot, BaselineReadApi) {
        let root = TestRoot::new();
        let services =
            BackendServices::new(PortableStore::prepare(root.0.clone()).unwrap()).unwrap();
        let ssh_api = Arc::new(SshApi::new(services.clone()));
        (
            root,
            BaselineReadApi::new(services, ssh_api).expect("static baseline catalog is valid"),
        )
    }

    fn catalog() -> CatalogProjection {
        CatalogProjection::build(BASELINE_CATALOG).unwrap()
    }

    fn scan(target: &BindingScope, observed: BaselineObservedValue) -> BaselineScan {
        BaselineScan {
            target: target.target.clone(),
            statuses: vec![BaselineStatus {
                item_id: BASELINE_CATALOG[0].id.to_owned(),
                observed,
                compliant: false,
                source_file: BASELINE_CATALOG[0].file().to_owned(),
            }],
            captured_at: record(target, "no").created_at,
        }
    }

    #[test]
    fn unverified_scan_projection_cannot_become_a_public_pass() {
        let catalog = catalog();
        let tls = catalog
            .dto
            .items
            .iter()
            .find(|item| item.title.contains("过时 TLS"))
            .unwrap();
        assert_eq!(tls.recommendation, "仅启用实例支持的 TLS 1.2/1.3");
        assert!(!tls.writable);
        let mut captured = scan(&scope("target", 1), BaselineObservedValue::Unverified);
        let projected =
            project_scan("scan-unverified".to_owned(), captured.clone(), &catalog).unwrap();
        assert_eq!(projected.statuses[0].observed_kind, "unverified");
        assert_eq!(projected.statuses[0].observed, "无法判断（尚未核实配置）");
        assert_eq!(projected.compliant_count, 0);
        captured.statuses[0].compliant = true;
        assert!(project_scan("scan-forged".to_owned(), captured, &catalog).is_err());
    }

    #[test]
    fn redis_catalog_and_findings_distinguish_acl_and_candidate_scope() {
        let catalog = catalog();
        let items = catalog
            .dto
            .items
            .iter()
            .filter(|item| item.component == "redis")
            .collect::<Vec<_>>();
        assert_eq!(items.len(), 7);
        assert!(items.iter().all(|item| !item.writable));
        let protection = items
            .iter()
            .find(|item| item.title == "保持保护模式")
            .unwrap();
        assert_eq!(protection.recommendation, "yes");
        assert!(
            matches!(&protection.value_kind, PublicBaselineValueKind::Choice { options } if options == &["yes", "no"])
        );
        assert!(
            items
                .iter()
                .any(|item| item.recommendation == "核对认证与 ACL")
        );
        let mut captured = scan(
            &scope("redis", 1),
            BaselineObservedValue::Value("no-auth-directive".into()),
        );
        captured.statuses[0].item_id = "redis-requirepass".into();
        captured.statuses[0].source_file = "/etc/redis/redis.conf".into();
        let projected = project_scan("redis-candidate".into(), captured, &catalog).unwrap();
        assert_eq!(projected.statuses[0].observed, "候选文件未声明口令或 ACL");
        assert!(!projected.statuses[0].compliant);
        assert!(
            projected.statuses[0]
                .fix
                .manual_reason
                .as_ref()
                .unwrap()
                .contains("实际实例")
        );
        assert!(projected.statuses[0].fix.reload.is_none());
    }

    #[test]
    fn postgresql_catalog_preserves_contextual_logging_and_candidate_source_language() {
        let catalog = catalog();
        let items = catalog
            .dto
            .items
            .iter()
            .filter(|item| item.component == "postgresql")
            .collect::<Vec<_>>();
        assert_eq!(items.len(), 7);
        assert!(items.iter().all(|item| !item.writable));
        assert!(items.iter().any(|item| item.title == "核对日志持久留存"
            && item.recommendation == "核对实际日志去向与持久留存"));
        let mut captured = scan(
            &scope("target", 1),
            BaselineObservedValue::Value("wildcard-listen".into()),
        );
        captured.statuses[0].item_id = "postgresql-listen-addresses".into();
        captured.statuses[0].source_file = "/var/lib/postgresql/data/postgresql.conf".into();
        for definition in BASELINE_CATALOG.iter().filter(|definition| {
            definition.component == lovelyhawk_core::baseline::BaselineComponent::PostgreSql
                && definition.id != "postgresql-listen-addresses"
        }) {
            captured.statuses.push(BaselineStatus {
                item_id: definition.id.to_owned(),
                observed: BaselineObservedValue::Unverified,
                compliant: false,
                source_file: "/var/lib/postgresql/data/postgresql.conf".into(),
            });
        }
        let projected = project_scan("postgresql-scan".into(), captured, &catalog).unwrap();
        assert_eq!(projected.statuses.len(), 7);
        assert_eq!(projected.statuses[0].observed, "候选地址包含通配监听");
        assert_eq!(projected.statuses[0].observed_kind, "value");
        assert_eq!(projected.compliant_count, 0);
    }

    fn record(target: &BindingScope, after: &str) -> BaselineChangeRecord {
        serde_json::from_value(json!({
            "id": "11111111-1111-4111-8111-111111111111",
            "operation_id": "22222222-2222-4222-8222-222222222222",
            "last_operation_id": "33333333-3333-4333-8333-333333333333",
            "target": target.target.identity.as_str(),
            "changes": [{
                "item_id": BASELINE_CATALOG[0].id,
                "before": { "state": "missing" },
                "after": after,
                "file": "/etc/ssh/sshd_config",
            }],
            "files": ["/etc/ssh/sshd_config"],
            "backups": [{
                "file": "/etc/ssh/sshd_config",
                "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            }],
            "remote_root": "/var/lib/lovelyres/managed-baseline/secret",
            "reload_policy": "apply-now",
            "digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "state": "applied",
            "created_at": "2026-08-24T01:02:03Z",
            "updated_at": "2026-08-24T01:03:04Z",
        }))
        .unwrap()
    }

    #[test]
    fn catalog_is_bounded_opaque_and_contains_only_safe_read_metadata() {
        let catalog = catalog();
        let value = serde_json::to_value(&catalog.dto).unwrap();
        assert_eq!(
            value["items"].as_array().unwrap().len(),
            BASELINE_CATALOG.len()
        );
        assert_eq!(value["displayed"], BASELINE_CATALOG.len());
        let handles = value["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["itemHandle"].as_str().unwrap())
            .collect::<HashSet<_>>();
        assert_eq!(handles.len(), BASELINE_CATALOG.len());
        let text = serde_json::to_string(&value).unwrap();
        assert!(!text.contains(BASELINE_CATALOG[0].id));
        assert!(!text.contains("/etc/"));
        assert!(!text.contains("checkCommand"));
        assert!(!text.contains("applyCommand"));
        assert!(text.len() <= MAX_CATALOG_RESPONSE_BYTES);
    }

    #[test]
    fn scan_projection_escapes_nothing_and_uses_opaque_items() {
        let target = scope("server", 1);
        let catalog = catalog();
        let hostile = scan(
            &target,
            BaselineObservedValue::Value("</code><script>plain()</script>".to_owned()),
        );
        let hostile_dto = project_scan("scan-hostile".to_owned(), hostile, &catalog).unwrap();
        let hostile_text = serde_json::to_string(&hostile_dto).unwrap();
        assert!(hostile_text.contains("</code><script>plain()</script>"));
        assert!(!hostile_text.contains(BASELINE_CATALOG[0].id));
        assert!(!hostile_dto.statuses[0].redacted);

        let sensitive = scan(
            &target,
            BaselineObservedValue::Value("authorization: Bearer scan-secret".to_owned()),
        );
        let sensitive_dto = project_scan("scan-sensitive".to_owned(), sensitive, &catalog).unwrap();
        let sensitive_text = serde_json::to_string(&sensitive_dto).unwrap();
        // A baseline observation that reads like a credential is the finding.
        assert!(sensitive_text.contains("authorization: Bearer scan-secret"));
        assert_eq!(sensitive_dto.redacted_field_count, 0);
        assert!(!sensitive_dto.statuses[0].redacted);
    }

    #[test]
    fn history_registry_hides_raw_evidence_and_is_target_epoch_ttl_scoped() {
        let current = scope("server", 1);
        let next_epoch = scope("server", 2);
        let catalog = catalog();
        let raw = record(&current, "</article><script>history()</script>");
        let raw_id = raw.id.clone();
        let raw_operation = raw.operation_id.clone();
        let raw_path = raw.files[0].clone();
        let raw_digest = raw.digest.clone();
        let now = Instant::now();
        let mut registry = SnapshotRegistry::default();
        let dto = registry
            .insert_history(current.clone(), vec![raw], &catalog, now)
            .unwrap();
        let text = serde_json::to_string(&dto).unwrap();
        assert!(text.contains("</article><script>history()</script>"));
        for secret in [&raw_id, &raw_operation, &raw_path, &raw_digest] {
            assert!(!text.contains(secret));
        }
        assert!(!text.contains("remoteRoot"));
        assert!(!text.contains("backups"));
        assert!(
            registry
                .resolve_history(&current, &dto.history_handle, now)
                .is_ok()
        );
        assert!(
            registry
                .resolve_history(&next_epoch, &dto.history_handle, now)
                .is_err()
        );
        assert!(
            registry
                .resolve_history(&current, &dto.history_handle, now + SNAPSHOT_TTL)
                .is_err()
        );
    }

    #[test]
    fn history_summary_keeps_the_values_it_read() {
        let current = scope("server", 1);
        let catalog = catalog();
        let (dto, record_ids) = project_history(
            "history-sensitive".to_owned(),
            &current,
            vec![record(&current, "token=history-secret")],
            &catalog,
        )
        .unwrap();
        let text = serde_json::to_string(&dto).unwrap();
        assert!(text.contains("history-secret"));
        assert_eq!(dto.redacted_field_count, 0);
        // The record id stays behind the handle; the page never sees it.
        let id = record_ids.get(&dto.entries[0].history_item_handle).unwrap();
        assert!(!text.contains(id.as_str()));
        // A record without evidence of the files it left is not restorable.
        assert!(!dto.entries[0].restorable);
        // The summary names both values, so neither state reads as the other.
        assert!(
            dto.entries[0].summary.starts_with("已应用 1 项基线改动："),
            "{}",
            dto.entries[0].summary
        );
        assert!(dto.entries[0].summary.contains(" → "));
        let mut restored = record(&current, "no");
        restored.state = BaselineChangeState::Restored;
        let (dto, _) = project_history(
            "history-restored".to_owned(),
            &current,
            vec![restored],
            &catalog,
        )
        .unwrap();
        assert!(
            dto.entries[0].summary.starts_with("已撤销 1 项基线改动："),
            "{}",
            dto.entries[0].summary
        );
    }

    #[test]
    fn registry_and_reads_enforce_capacity_concurrency_and_refresh_invalidation() {
        let state = Arc::new(Mutex::new(ConcurrencyState::default()));
        let permits = (0..MAX_GLOBAL_READS)
            .map(|index| ReadPermit::acquire(Arc::clone(&state), format!("binding-{index}")))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(ReadPermit::acquire(Arc::clone(&state), "binding-extra".to_owned()).is_err());
        drop(permits);
        let first = ReadPermit::acquire(Arc::clone(&state), "same".to_owned()).unwrap();
        assert!(ReadPermit::acquire(Arc::clone(&state), "same".to_owned()).is_err());
        drop(first);

        let current = scope("server", 1);
        let catalog = catalog();
        let now = Instant::now();
        let mut registry = SnapshotRegistry::default();
        let first = registry
            .insert_scan(
                current.clone(),
                scan(&current, BaselineObservedValue::Missing),
                &catalog,
                now,
            )
            .unwrap();
        let second = registry
            .insert_scan(
                current.clone(),
                scan(&current, BaselineObservedValue::Missing),
                &catalog,
                now + Duration::from_secs(1),
            )
            .unwrap();
        assert!(!registry.snapshots.contains_key(&first.scan_handle));
        assert!(registry.snapshots.contains_key(&second.scan_handle));
        registry.prune(now + SNAPSHOT_TTL + Duration::from_secs(2), None);
        assert!(registry.snapshots.is_empty());
        assert_eq!(registry.total_bytes, 0);
    }

    #[test]
    fn close_binding_immediately_invalidates_only_its_scan_and_history_capabilities() {
        let (_root, api) = read_api();
        let now = Instant::now();
        let closed_binding = "11111111-1111-4111-8111-111111111111";
        let retained_binding = "22222222-2222-4222-8222-222222222222";
        let closed_scope = scope_with_binding(closed_binding, "closed-target", 1);
        let retained_scope = scope_with_binding(retained_binding, "retained-target", 1);
        let (closed_scan, closed_history, retained_scan, retained_history, retained_bytes) = {
            let mut registry = api.snapshots.lock().unwrap();
            let closed_scan = registry
                .insert_scan(
                    closed_scope.clone(),
                    scan(&closed_scope, BaselineObservedValue::Missing),
                    &api.catalog,
                    now,
                )
                .unwrap()
                .scan_handle;
            let closed_history = registry
                .insert_history(
                    closed_scope.clone(),
                    vec![record(&closed_scope, "no")],
                    &api.catalog,
                    now,
                )
                .unwrap();
            let retained_scan = registry
                .insert_scan(
                    retained_scope.clone(),
                    scan(&retained_scope, BaselineObservedValue::Missing),
                    &api.catalog,
                    now,
                )
                .unwrap()
                .scan_handle;
            let retained_history = registry
                .insert_history(
                    retained_scope.clone(),
                    vec![record(&retained_scope, "no")],
                    &api.catalog,
                    now,
                )
                .unwrap();
            let retained_bytes = registry
                .snapshots
                .values()
                .filter(|entry| entry.scope.binding_handle == retained_binding)
                .map(|entry| entry.bytes)
                .sum::<usize>();
            (
                closed_scan,
                closed_history.history_handle,
                retained_scan,
                retained_history.history_handle,
                retained_bytes,
            )
        };

        api.close_binding(closed_binding);

        let registry = api.snapshots.lock().unwrap();
        assert!(!registry.snapshots.contains_key(&closed_scan));
        assert!(!registry.snapshots.contains_key(&closed_history));
        assert!(
            registry
                .resolve_history(&closed_scope, &closed_history, now)
                .is_err()
        );
        assert!(registry.snapshots.contains_key(&retained_scan));
        assert!(registry.snapshots.contains_key(&retained_history));
        assert!(
            registry
                .resolve_history(&retained_scope, &retained_history, now)
                .is_ok()
        );
        assert_eq!(registry.total_bytes, retained_bytes);
        assert!(
            registry
                .snapshots
                .values()
                .all(|entry| entry.scope.binding_handle == retained_binding)
        );
    }

    #[test]
    fn source_calls_only_the_three_read_service_methods() {
        let source = include_str!("baseline_read_api.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for required in [
            ".baseline().catalog()",
            ".baseline().scan(&session).await",
            ".list_history(session.target())",
        ] {
            assert!(
                production.contains(required),
                "missing core read call {required}"
            );
        }
        for forbidden in [
            ["plan_", "changes"].concat(),
            ["execute_", "changes"].concat(),
            ["plan_", "restore"].concat(),
            ["execute_", "restore"].concat(),
            ["confirm_", "baseline"].concat(),
            ["open_", "terminal"].concat(),
            ["open_", "file"].concat(),
            ["export_", "baseline"].concat(),
            ["execute_", "bound"].concat(),
        ] {
            assert!(
                !production.contains(&forbidden),
                "forbidden phase-one surface {forbidden}"
            );
        }
        assert_eq!(
            production
                .matches("if let Err(error) = self.validate_binding(&scope)")
                .count(),
            2,
            "scan and history must validate again after publishing their snapshot"
        );
        assert_eq!(
            production.matches("self.remove_snapshot(&result.").count(),
            2,
            "a late stale result must remove the capability it just inserted"
        );
    }
}
