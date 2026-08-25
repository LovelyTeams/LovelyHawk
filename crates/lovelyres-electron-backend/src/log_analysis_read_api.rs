//! Bounded, read-only Electron boundary for target log investigation.
//!
//! Remote paths remain sidecar-owned source capabilities. The renderer can
//! display their hostile text but can only read through opaque source handles.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use lovelyres_core::{
    BackendServices, CoreError,
    log_analysis::{
        IocSearchQuery, IocSearchResult, JournalQuery, LogAnalysisResult, LogCalendarDay, LogEntry,
        LogFileInfo, LogQuery, MultiLogQuery, MultiLogResult, ThreatLevel, ThreatSummary,
    },
    ssh::BoundSshSession,
    target::TargetGuard,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ssh_api::SshApi;

const MAX_HANDLE_BYTES: usize = 128;
const MAX_SNAPSHOTS: usize = 8;
const MAX_SNAPSHOT_BYTES: usize = 1024 * 1024;
const MAX_REGISTRY_BYTES: usize = 4 * 1024 * 1024;
const MAX_ACTIVE_READS: usize = 3;
const MAX_ACTIVE_DISCOVERIES: usize = 2;
const MAX_FILE_SOURCES: usize = 100;
const MAX_SOURCES: usize = MAX_FILE_SOURCES + 1;
const MAX_PAGE: usize = 10_000;
const MAX_PAGE_SIZE: usize = 200;
const MAX_KEYWORD_BYTES: usize = 256;
const MAX_JOURNAL_UNIT_BYTES: usize = 128;
const MAX_CORRELATION_SOURCES: usize = 8;
const MAX_CORRELATION_LINE_LIMIT: usize = 200;
const MAX_CORRELATION_ENTRIES: usize = 1_000;
const MAX_IOC_SOURCES: usize = 8;
const MAX_IOC_INDICATORS: usize = 16;
const MAX_IOC_PAIRS: usize = 64;
const MAX_IOC_BYTES: usize = 256;
const MAX_IOC_RESULTS: usize = 64;
const MAX_SOURCE_TEXT_BYTES: usize = 512 * 1024;
const MAX_READ_TEXT_BYTES: usize = 512 * 1024;
const MAX_CORRELATION_TEXT_BYTES: usize = 1024 * 1024;
const MAX_IOC_TEXT_BYTES: usize = 512 * 1024;
const MAX_ENTRY_TIMESTAMP_BYTES: usize = 128;
const MAX_ENTRY_LEVEL_BYTES: usize = 32;
const MAX_ENTRY_SERVICE_BYTES: usize = 256;
const MAX_ENTRY_MESSAGE_BYTES: usize = 8 * 1024;
const MAX_ENTRY_RAW_BYTES: usize = 16 * 1024;
const MAX_PUBLIC_U64: u64 = 9_007_199_254_740_991;
const MIN_ITEM_TEXT_BYTES: usize = 128;
const SNAPSHOT_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Clone)]
pub(crate) struct LogAnalysisReadApi {
    services: BackendServices,
    ssh_api: Arc<SshApi>,
    registry: Arc<Mutex<SourceRegistry>>,
}

impl fmt::Debug for LogAnalysisReadApi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (snapshots, bytes, active_reads, discoveries) = self
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
                    registry.active_discoveries,
                )
            })
            .unwrap_or_default();
        formatter
            .debug_struct("LogAnalysisReadApi")
            .field("snapshot_count", &snapshots)
            .field("snapshot_bytes", &bytes)
            .field("active_reads", &active_reads)
            .field("active_discoveries", &discoveries)
            .finish()
    }
}

impl LogAnalysisReadApi {
    pub(crate) fn new(services: BackendServices, ssh_api: Arc<SshApi>) -> Self {
        Self {
            services,
            ssh_api,
            registry: Arc::new(Mutex::new(SourceRegistry::default())),
        }
    }

    pub(crate) fn close_binding(&self, binding_handle: &str) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.close_binding(binding_handle);
        }
    }

    pub(crate) async fn discover_sources(
        &self,
        binding_handle: &str,
    ) -> Result<LogSourceSnapshotDto, LogAnalysisReadApiError> {
        let (session, scope) = self.capture_binding(binding_handle)?;
        let _permit = self.begin_discovery(&scope)?;
        let journal_probe = JournalQuery {
            page: 1,
            page_size: 1,
            unit: None,
            filter: None,
            date_filter: None,
        };
        let service = self.services.log_analysis();
        let (files, journal) = tokio::join!(
            service.list_files(&session),
            service.read_journal(&session, &journal_probe, false),
        );
        self.validate_binding(&scope)?;
        if files.is_err() && journal.is_err() {
            return Err(LogAnalysisReadApiError::Core);
        }
        let partial = files.is_err() || journal.is_err();
        let (entry, dto) =
            build_source_snapshot(scope, files.unwrap_or_default(), journal.is_ok(), partial)?;
        let mut registry = self.lock_registry()?;
        registry.prune(Instant::now());
        registry.insert(entry)?;
        Ok(dto)
    }

    pub(crate) async fn read_source(
        &self,
        binding_handle: &str,
        snapshot_handle: &str,
        source_handle: &str,
        input: LogSourceReadInput,
    ) -> Result<LogSourceReadDto, LogAnalysisReadApiError> {
        validate_handle(snapshot_handle)?;
        validate_handle(source_handle)?;
        let validated = input.validate()?;
        let (session, scope) = self.capture_binding(binding_handle)?;
        let (access, source, _permit) =
            self.begin_source_read(&scope, snapshot_handle, source_handle)?;
        let result = match &source {
            StoredSource::File { path, .. } => {
                if validated.journal_unit.is_some() {
                    return Err(LogAnalysisReadApiError::InvalidQuery);
                }
                let query = LogQuery {
                    log_path: path.clone(),
                    page: validated.page,
                    page_size: validated.page_size,
                    filter: validated.keyword.clone(),
                    date_filter: validated.date,
                };
                self.services
                    .log_analysis()
                    .read_file(&session, &query, true)
                    .await?
            }
            StoredSource::Journal { .. } => {
                let query = JournalQuery {
                    page: validated.page,
                    page_size: validated.page_size,
                    unit: validated.journal_unit.clone(),
                    filter: validated.keyword.clone(),
                    date_filter: validated.date,
                };
                self.services
                    .log_analysis()
                    .read_journal(&session, &query, true)
                    .await?
            }
        };
        self.validate_binding(&scope)?;
        self.verify_source(&access, source_handle, &source)?;
        project_read_result(
            snapshot_handle,
            source_handle,
            source.kind(),
            validated.page,
            validated.page_size,
            result,
        )
    }

    pub(crate) async fn correlate_sources(
        &self,
        binding_handle: &str,
        snapshot_handle: &str,
        input: LogCorrelationInput,
    ) -> Result<LogCorrelationDto, LogAnalysisReadApiError> {
        validate_handle(snapshot_handle)?;
        input.validate()?;
        let (session, scope) = self.capture_binding(binding_handle)?;
        let (access, sources, _permit) =
            self.begin_many_source_read(&scope, snapshot_handle, &input.source_handles)?;
        let mut paths = Vec::with_capacity(sources.len());
        let mut path_index = HashMap::new();
        for (handle, source) in &sources {
            let StoredSource::File {
                path, display_name, ..
            } = source
            else {
                return Err(LogAnalysisReadApiError::InvalidSourceKind);
            };
            paths.push(path.clone());
            path_index.insert(path.clone(), (handle.clone(), display_name.clone()));
        }
        let result = self
            .services
            .log_analysis()
            .analyze_multi(
                &session,
                &MultiLogQuery {
                    log_paths: paths.clone(),
                    line_limit: input.line_limit,
                },
            )
            .await?;
        self.validate_binding(&scope)?;
        self.verify_sources(&access, &sources)?;
        if result.sources != paths {
            return Err(LogAnalysisReadApiError::SnapshotStale);
        }
        if result.entries.len() > input.line_limit.saturating_mul(paths.len()) {
            return Err(LogAnalysisReadApiError::SnapshotStale);
        }
        project_correlation_result(snapshot_handle, &input.source_handles, &path_index, result)
    }

    pub(crate) async fn search_iocs(
        &self,
        binding_handle: &str,
        snapshot_handle: &str,
        input: LogIocSearchInput,
    ) -> Result<LogIocSearchDto, LogAnalysisReadApiError> {
        validate_handle(snapshot_handle)?;
        let indicators = input.validate()?;
        let (session, scope) = self.capture_binding(binding_handle)?;
        let (access, sources, _permit) =
            self.begin_many_source_read(&scope, snapshot_handle, &input.source_handles)?;
        let mut paths = Vec::with_capacity(sources.len());
        let mut path_index = HashMap::new();
        for (handle, source) in &sources {
            let StoredSource::File {
                path, display_name, ..
            } = source
            else {
                return Err(LogAnalysisReadApiError::InvalidSourceKind);
            };
            paths.push(path.clone());
            path_index.insert(path.clone(), (handle.clone(), display_name.clone()));
        }
        let result = self
            .services
            .log_analysis()
            .search_iocs(
                &session,
                &IocSearchQuery {
                    indicators: indicators.clone(),
                    log_paths: paths,
                },
            )
            .await?;
        self.validate_binding(&scope)?;
        self.verify_sources(&access, &sources)?;
        project_ioc_result(snapshot_handle, &path_index, &indicators, result)
    }

    fn capture_binding(
        &self,
        binding_handle: &str,
    ) -> Result<(BoundSshSession, BindingScope), LogAnalysisReadApiError> {
        validate_handle(binding_handle)?;
        let session = self
            .ssh_api
            .binding_session_clone(binding_handle)
            .map_err(|_| LogAnalysisReadApiError::BindingUnavailable)?;
        self.services
            .target()
            .validate(session.target())
            .map_err(|_| LogAnalysisReadApiError::BindingUnavailable)?;
        let scope = BindingScope::from_session(binding_handle, &session);
        Ok((session, scope))
    }

    fn validate_binding(&self, expected: &BindingScope) -> Result<(), LogAnalysisReadApiError> {
        let (_, current) = self.capture_binding(&expected.binding_handle)?;
        if &current != expected {
            return Err(LogAnalysisReadApiError::BindingUnavailable);
        }
        Ok(())
    }

    fn begin_discovery(
        &self,
        scope: &BindingScope,
    ) -> Result<DiscoveryPermit, LogAnalysisReadApiError> {
        let mut registry = self.lock_registry()?;
        registry.prune(Instant::now());
        registry.begin_discovery(scope)?;
        Ok(DiscoveryPermit {
            registry: Arc::clone(&self.registry),
            binding_handle: scope.binding_handle.clone(),
        })
    }

    fn begin_source_read(
        &self,
        scope: &BindingScope,
        snapshot_handle: &str,
        source_handle: &str,
    ) -> Result<(SnapshotAccess, StoredSource, SnapshotPermit), LogAnalysisReadApiError> {
        let (access, sources, permit) =
            self.begin_many_source_read(scope, snapshot_handle, &[source_handle.to_owned()])?;
        let source = sources
            .into_iter()
            .next()
            .map(|(_, source)| source)
            .ok_or(LogAnalysisReadApiError::InvalidSource)?;
        Ok((access, source, permit))
    }

    fn begin_many_source_read(
        &self,
        scope: &BindingScope,
        snapshot_handle: &str,
        source_handles: &[String],
    ) -> Result<SourceReadAccess, LogAnalysisReadApiError> {
        if source_handles.is_empty() || source_handles.len() > MAX_SOURCES {
            return Err(LogAnalysisReadApiError::InvalidQuery);
        }
        let mut seen = HashSet::new();
        for handle in source_handles {
            validate_handle(handle)?;
            if !seen.insert(handle.as_str()) {
                return Err(LogAnalysisReadApiError::InvalidQuery);
            }
        }
        let mut registry = self.lock_registry()?;
        registry.prune(Instant::now());
        let access = registry.begin_read(scope, snapshot_handle)?;
        let sources = source_handles
            .iter()
            .map(|handle| {
                registry
                    .source(&access, handle)
                    .map(|source| (handle.clone(), source))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let permit = SnapshotPermit {
            registry: Arc::clone(&self.registry),
            snapshot_handle: snapshot_handle.to_owned(),
            token: access.token,
        };
        Ok((access, sources, permit))
    }

    fn verify_source(
        &self,
        access: &SnapshotAccess,
        source_handle: &str,
        expected: &StoredSource,
    ) -> Result<(), LogAnalysisReadApiError> {
        let registry = self.lock_registry()?;
        if registry.source(access, source_handle)?.stable_key() != expected.stable_key() {
            return Err(LogAnalysisReadApiError::SnapshotStale);
        }
        Ok(())
    }

    fn verify_sources(
        &self,
        access: &SnapshotAccess,
        expected: &[(String, StoredSource)],
    ) -> Result<(), LogAnalysisReadApiError> {
        for (handle, source) in expected {
            self.verify_source(access, handle, source)?;
        }
        Ok(())
    }

    fn lock_registry(&self) -> Result<MutexGuard<'_, SourceRegistry>, LogAnalysisReadApiError> {
        self.registry
            .lock()
            .map_err(|_| LogAnalysisReadApiError::RegistryUnavailable)
    }
}

pub(crate) enum LogAnalysisReadApiError {
    Core,
    BindingUnavailable,
    InvalidHandle,
    InvalidQuery,
    InvalidDate,
    InvalidSource,
    InvalidSourceKind,
    InvalidSnapshot,
    SnapshotStale,
    Capacity,
    RegistryUnavailable,
}

impl fmt::Debug for LogAnalysisReadApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core => "Core([REDACTED])",
            Self::BindingUnavailable => "BindingUnavailable",
            Self::InvalidHandle => "InvalidHandle",
            Self::InvalidQuery => "InvalidQuery",
            Self::InvalidDate => "InvalidDate",
            Self::InvalidSource => "InvalidSource",
            Self::InvalidSourceKind => "InvalidSourceKind",
            Self::InvalidSnapshot => "InvalidSnapshot",
            Self::SnapshotStale => "SnapshotStale",
            Self::Capacity => "Capacity",
            Self::RegistryUnavailable => "RegistryUnavailable",
        })
    }
}

impl fmt::Display for LogAnalysisReadApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core => "the log investigation operation failed",
            Self::BindingUnavailable => "the SSH binding is missing or stale",
            Self::InvalidHandle => "the log investigation handle is invalid",
            Self::InvalidQuery => "the log investigation query is invalid",
            Self::InvalidDate => "the log investigation date is invalid",
            Self::InvalidSource => "the log source is missing or stale",
            Self::InvalidSourceKind => "the log source does not support this operation",
            Self::InvalidSnapshot => "the log source snapshot is missing or stale",
            Self::SnapshotStale => "the log result no longer matches its source snapshot",
            Self::Capacity => "the log investigation registry is full",
            Self::RegistryUnavailable => "the log investigation registry is unavailable",
        })
    }
}

impl std::error::Error for LogAnalysisReadApiError {}

impl From<CoreError> for LogAnalysisReadApiError {
    fn from(_: CoreError) -> Self {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum LogSourceKind {
    File,
    Journal,
}

#[derive(Clone, PartialEq, Eq)]
enum StoredSource {
    File {
        path: String,
        display_name: String,
        display_location: String,
        size_bytes: u64,
        modified: String,
    },
    Journal {
        display_name: String,
        display_location: String,
    },
}

type StoredSources = Vec<(String, StoredSource)>;
type SourceReadAccess = (SnapshotAccess, StoredSources, SnapshotPermit);

impl StoredSource {
    const fn kind(&self) -> LogSourceKind {
        match self {
            Self::File { .. } => LogSourceKind::File,
            Self::Journal { .. } => LogSourceKind::Journal,
        }
    }

    fn stable_key(&self) -> String {
        match self {
            Self::File { path, .. } => format!("file:{path}"),
            Self::Journal { .. } => "journal:system".to_owned(),
        }
    }

    fn estimated_bytes(&self) -> usize {
        match self {
            Self::File {
                path,
                display_name,
                display_location,
                modified,
                ..
            } => 128_usize
                .saturating_add(path.len())
                .saturating_add(display_name.len())
                .saturating_add(display_location.len())
                .saturating_add(modified.len()),
            Self::Journal {
                display_name,
                display_location,
            } => 128_usize
                .saturating_add(display_name.len())
                .saturating_add(display_location.len()),
        }
    }
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LogSourceReadInput {
    page: usize,
    page_size: usize,
    keyword: Option<String>,
    date: Option<String>,
    journal_unit: Option<String>,
}

impl fmt::Debug for LogSourceReadInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LogSourceReadInput")
            .field("page", &self.page)
            .field("page_size", &self.page_size)
            .field("keyword", &"[REDACTED]")
            .field("date_present", &self.date.is_some())
            .field("journal_unit", &"[REDACTED]")
            .finish()
    }
}

struct ValidatedReadInput {
    page: usize,
    page_size: usize,
    keyword: Option<String>,
    date: Option<LogCalendarDay>,
    journal_unit: Option<String>,
}

impl LogSourceReadInput {
    fn validate(self) -> Result<ValidatedReadInput, LogAnalysisReadApiError> {
        if self.page == 0
            || self.page > MAX_PAGE
            || self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
        {
            return Err(LogAnalysisReadApiError::InvalidQuery);
        }
        let keyword = validate_optional_text(self.keyword, MAX_KEYWORD_BYTES, false)?;
        let journal_unit = validate_optional_text(self.journal_unit, MAX_JOURNAL_UNIT_BYTES, true)?;
        let date = self
            .date
            .map(|date| {
                LogCalendarDay::parse(&date).map_err(|_| LogAnalysisReadApiError::InvalidDate)
            })
            .transpose()?;
        Ok(ValidatedReadInput {
            page: self.page,
            page_size: self.page_size,
            keyword,
            date,
            journal_unit,
        })
    }
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LogCorrelationInput {
    source_handles: Vec<String>,
    line_limit: usize,
}

impl fmt::Debug for LogCorrelationInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LogCorrelationInput")
            .field("source_count", &self.source_handles.len())
            .field("line_limit", &self.line_limit)
            .finish()
    }
}

impl LogCorrelationInput {
    fn validate(&self) -> Result<(), LogAnalysisReadApiError> {
        validate_source_handles(&self.source_handles, 2, MAX_CORRELATION_SOURCES)?;
        if self.line_limit == 0 || self.line_limit > MAX_CORRELATION_LINE_LIMIT {
            return Err(LogAnalysisReadApiError::InvalidQuery);
        }
        Ok(())
    }
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LogIocSearchInput {
    source_handles: Vec<String>,
    indicators: Vec<String>,
}

impl fmt::Debug for LogIocSearchInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LogIocSearchInput")
            .field("source_count", &self.source_handles.len())
            .field("indicator_count", &self.indicators.len())
            .field("indicators", &"[REDACTED]")
            .finish()
    }
}

impl LogIocSearchInput {
    fn validate(&self) -> Result<Vec<String>, LogAnalysisReadApiError> {
        validate_source_handles(&self.source_handles, 1, MAX_IOC_SOURCES)?;
        if self.indicators.is_empty()
            || self.indicators.len() > MAX_IOC_INDICATORS
            || self
                .indicators
                .len()
                .checked_mul(self.source_handles.len())
                .is_none_or(|count| count > MAX_IOC_PAIRS)
        {
            return Err(LogAnalysisReadApiError::InvalidQuery);
        }
        let mut seen = HashSet::new();
        let mut indicators = Vec::with_capacity(self.indicators.len());
        for value in &self.indicators {
            let value = value.trim();
            if value.is_empty()
                || value.len() > MAX_IOC_BYTES
                || value.chars().any(char::is_control)
                || !seen.insert(value)
            {
                return Err(LogAnalysisReadApiError::InvalidQuery);
            }
            indicators.push(value.to_owned());
        }
        Ok(indicators)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LogSourceSnapshotDto {
    snapshot_handle: String,
    expires_in_seconds: u64,
    sources: Vec<LogSourceDto>,
    partial: bool,
    truncated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LogSourceDto {
    source_handle: String,
    kind: LogSourceKind,
    display_name: String,
    display_location: String,
    size_bytes: Option<u64>,
    modified: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LogSourceReadDto {
    snapshot_handle: String,
    source_handle: String,
    source_kind: LogSourceKind,
    page: usize,
    page_size: usize,
    entry_count: usize,
    highlighted_count: usize,
    has_more: bool,
    entries: Vec<PublicLogEntryDto>,
    threat_summary: ThreatSummaryDto,
    truncated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicLogEntryDto {
    timestamp: String,
    level: String,
    service: String,
    message: String,
    raw_text: String,
    highlighted: bool,
    source_handle: Option<String>,
    source_name: Option<String>,
    text_truncated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ThreatSummaryDto {
    brute_force_count: usize,
    successful_login_count: usize,
    privilege_escalation_count: usize,
    suspicious_activity_count: usize,
    top_source_ips: Vec<ThreatIpDto>,
    top_target_users: Vec<ThreatUserDto>,
    hourly_distribution: Vec<usize>,
    threat_level: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ThreatIpDto {
    ip: String,
    count: usize,
    last_seen: String,
    action_type: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ThreatUserDto {
    username: String,
    count: usize,
    success_count: usize,
    fail_count: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LogCorrelationDto {
    snapshot_handle: String,
    source_handles: Vec<String>,
    coverage: &'static str,
    total_observed: usize,
    entries: Vec<PublicLogEntryDto>,
    threat_summary: ThreatSummaryDto,
    truncated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LogIocSearchDto {
    snapshot_handle: String,
    results: Vec<LogIocMatchDto>,
    total_matches: usize,
    truncated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LogIocMatchDto {
    indicator: String,
    source_handle: String,
    source_name: String,
    count: usize,
    sample_lines: Vec<String>,
    text_truncated: bool,
}

#[derive(Default)]
struct SourceRegistry {
    snapshots: HashMap<String, SourceSnapshot>,
    active_discoveries: usize,
    discovering_bindings: HashSet<String>,
}

struct SourceSnapshot {
    handle: String,
    token: Uuid,
    scope: BindingScope,
    created_at: Instant,
    expires_at: Instant,
    active_reads: usize,
    stored_bytes: usize,
    sources: HashMap<String, StoredSource>,
}

#[derive(Clone)]
struct SnapshotAccess {
    handle: String,
    token: Uuid,
    scope: BindingScope,
}

impl SnapshotAccess {
    fn matches(&self, snapshot: &SourceSnapshot, now: Instant) -> bool {
        snapshot.token == self.token && snapshot.scope == self.scope && snapshot.expires_at > now
    }
}

impl SourceRegistry {
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

    fn begin_discovery(&mut self, scope: &BindingScope) -> Result<(), LogAnalysisReadApiError> {
        if self.active_discoveries >= MAX_ACTIVE_DISCOVERIES
            || self.discovering_bindings.contains(&scope.binding_handle)
        {
            return Err(LogAnalysisReadApiError::Capacity);
        }
        self.active_discoveries += 1;
        self.discovering_bindings
            .insert(scope.binding_handle.clone());
        Ok(())
    }

    fn release_discovery(&mut self, binding_handle: &str) {
        if self.discovering_bindings.remove(binding_handle) {
            self.active_discoveries = self.active_discoveries.saturating_sub(1);
        }
    }

    fn insert(&mut self, snapshot: SourceSnapshot) -> Result<(), LogAnalysisReadApiError> {
        if self.snapshots.contains_key(&snapshot.handle)
            || snapshot.stored_bytes > MAX_SNAPSHOT_BYTES
        {
            return Err(LogAnalysisReadApiError::Capacity);
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
                .ok_or(LogAnalysisReadApiError::Capacity)?;
            self.snapshots.remove(&candidate);
        }
        self.snapshots.insert(snapshot.handle.clone(), snapshot);
        Ok(())
    }

    fn begin_read(
        &mut self,
        scope: &BindingScope,
        handle: &str,
    ) -> Result<SnapshotAccess, LogAnalysisReadApiError> {
        let snapshot = self
            .snapshots
            .get_mut(handle)
            .filter(|snapshot| &snapshot.scope == scope && snapshot.expires_at > Instant::now())
            .ok_or(LogAnalysisReadApiError::InvalidSnapshot)?;
        if snapshot.active_reads >= MAX_ACTIVE_READS {
            return Err(LogAnalysisReadApiError::Capacity);
        }
        snapshot.active_reads += 1;
        Ok(SnapshotAccess {
            handle: handle.to_owned(),
            token: snapshot.token,
            scope: scope.clone(),
        })
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

    fn verify(&self, access: &SnapshotAccess) -> Result<&SourceSnapshot, LogAnalysisReadApiError> {
        self.snapshots
            .get(&access.handle)
            .filter(|snapshot| access.matches(snapshot, Instant::now()))
            .ok_or(LogAnalysisReadApiError::SnapshotStale)
    }

    fn source(
        &self,
        access: &SnapshotAccess,
        handle: &str,
    ) -> Result<StoredSource, LogAnalysisReadApiError> {
        self.verify(access)?
            .sources
            .get(handle)
            .cloned()
            .ok_or(LogAnalysisReadApiError::InvalidSource)
    }
}

struct DiscoveryPermit {
    registry: Arc<Mutex<SourceRegistry>>,
    binding_handle: String,
}

impl Drop for DiscoveryPermit {
    fn drop(&mut self) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.release_discovery(&self.binding_handle);
        }
    }
}

struct SnapshotPermit {
    registry: Arc<Mutex<SourceRegistry>>,
    snapshot_handle: String,
    token: Uuid,
}

impl Drop for SnapshotPermit {
    fn drop(&mut self) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.release_read(&self.snapshot_handle, self.token);
        }
    }
}

fn build_source_snapshot(
    scope: BindingScope,
    files: Vec<LogFileInfo>,
    journal_available: bool,
    partial: bool,
) -> Result<(SourceSnapshot, LogSourceSnapshotDto), LogAnalysisReadApiError> {
    let snapshot_handle = unique_handle()?;
    let mut budget = TextBudget::new(MAX_SOURCE_TEXT_BYTES);
    let source_was_full = files.len() >= MAX_FILE_SOURCES;
    let readable_count = files.iter().filter(|file| file.readable).count();
    let mut projection_truncated = false;
    let mut included_files = 0;
    let mut sources = HashMap::new();
    let mut source_keys = HashSet::new();
    let mut items = Vec::new();
    let mut stored_bytes = 0_usize;
    for file in files
        .into_iter()
        .filter(|file| file.readable)
        .take(MAX_FILE_SOURCES)
    {
        if budget.remaining() < MIN_ITEM_TEXT_BYTES || file.size > MAX_PUBLIC_U64 {
            projection_truncated = true;
            break;
        }
        let stable_key = format!("file:{}", file.path);
        if !source_keys.insert(stable_key) {
            return Err(LogAnalysisReadApiError::SnapshotStale);
        }
        let source_handle = unique_map_handle(&sources)?;
        let (display_name, name_truncated) = budget.take(&file.name, 256);
        let (display_location, location_truncated) = budget.take(&file.path, 4 * 1024);
        let (modified, modified_truncated) = budget.take(&file.modified, 64);
        let source = StoredSource::File {
            path: file.path,
            display_name: display_name.clone(),
            display_location: display_location.clone(),
            size_bytes: file.size,
            modified: modified.clone(),
        };
        stored_bytes = stored_bytes
            .saturating_add(source_handle.len())
            .saturating_add(source.estimated_bytes());
        sources.insert(source_handle.clone(), source);
        included_files += 1;
        items.push(LogSourceDto {
            source_handle,
            kind: LogSourceKind::File,
            display_name,
            display_location,
            size_bytes: Some(file.size),
            modified,
        });
        if name_truncated || location_truncated || modified_truncated {
            projection_truncated = true;
            break;
        }
    }
    if journal_available && items.len() < MAX_SOURCES && budget.remaining() >= MIN_ITEM_TEXT_BYTES {
        let source_handle = unique_map_handle(&sources)?;
        let (display_name, _) = budget.take("systemd Journal", 256);
        let (display_location, _) = budget.take("systemd journal", 4 * 1024);
        let source = StoredSource::Journal {
            display_name: display_name.clone(),
            display_location: display_location.clone(),
        };
        stored_bytes = stored_bytes
            .saturating_add(source_handle.len())
            .saturating_add(source.estimated_bytes());
        sources.insert(source_handle.clone(), source);
        items.push(LogSourceDto {
            source_handle,
            kind: LogSourceKind::Journal,
            display_name,
            display_location,
            size_bytes: None,
            modified: String::new(),
        });
    } else if journal_available {
        projection_truncated = true;
    }
    if stored_bytes > MAX_SNAPSHOT_BYTES {
        return Err(LogAnalysisReadApiError::Capacity);
    }
    let truncated = source_was_full
        || included_files < readable_count
        || projection_truncated
        || budget.remaining() < MIN_ITEM_TEXT_BYTES;
    let now = Instant::now();
    let snapshot = SourceSnapshot {
        handle: snapshot_handle.clone(),
        token: Uuid::new_v4(),
        scope,
        created_at: now,
        expires_at: now + SNAPSHOT_TTL,
        active_reads: 0,
        stored_bytes,
        sources,
    };
    let dto = LogSourceSnapshotDto {
        snapshot_handle,
        expires_in_seconds: SNAPSHOT_TTL.as_secs(),
        sources: items,
        partial,
        truncated,
    };
    Ok((snapshot, dto))
}

fn project_read_result(
    snapshot_handle: &str,
    source_handle: &str,
    source_kind: LogSourceKind,
    page: usize,
    page_size: usize,
    result: LogAnalysisResult,
) -> Result<LogSourceReadDto, LogAnalysisReadApiError> {
    if result.entries.len() > page_size
        || result.total_count != result.entries.len()
        || result.highlighted_count > result.total_count
    {
        return Err(LogAnalysisReadApiError::SnapshotStale);
    }
    let threat = result
        .threat_summary
        .ok_or(LogAnalysisReadApiError::SnapshotStale)?;
    let mut budget = TextBudget::new(MAX_READ_TEXT_BYTES);
    let mut entries = Vec::new();
    let mut projection_truncated = false;
    let source_len = result.entries.len();
    for entry in result.entries {
        if budget.remaining() < MIN_ITEM_TEXT_BYTES {
            break;
        }
        let projected = project_entry(entry, None, None, &mut budget);
        projection_truncated |= projected.text_truncated;
        entries.push(projected);
    }
    let highlighted_count = entries.iter().filter(|entry| entry.highlighted).count();
    let projected_len = entries.len();
    let (threat_summary, threat_truncated) = project_threat_summary(threat, page_size)?;
    Ok(LogSourceReadDto {
        snapshot_handle: snapshot_handle.to_owned(),
        source_handle: source_handle.to_owned(),
        source_kind,
        page,
        page_size,
        entry_count: entries.len(),
        highlighted_count,
        has_more: result.total_count == page_size,
        entries,
        threat_summary,
        truncated: source_len > projected_len
            || projection_truncated
            || threat_truncated
            || budget.remaining() < MIN_ITEM_TEXT_BYTES,
    })
}

fn project_correlation_result(
    snapshot_handle: &str,
    source_handles: &[String],
    path_index: &HashMap<String, (String, String)>,
    result: MultiLogResult,
) -> Result<LogCorrelationDto, LogAnalysisReadApiError> {
    if result.total_count != result.entries.len() || result.entries.len() > 10_000 {
        return Err(LogAnalysisReadApiError::SnapshotStale);
    }
    let source_len = result.entries.len();
    let mut budget = TextBudget::new(MAX_CORRELATION_TEXT_BYTES);
    let mut entries = Vec::new();
    let mut projection_truncated = false;
    for entry in result.entries.into_iter().take(MAX_CORRELATION_ENTRIES) {
        if budget.remaining() < MIN_ITEM_TEXT_BYTES {
            break;
        }
        let path = entry
            .source
            .as_deref()
            .ok_or(LogAnalysisReadApiError::SnapshotStale)?;
        let (source_handle, source_name) = path_index
            .get(path)
            .ok_or(LogAnalysisReadApiError::SnapshotStale)?;
        let projected = project_entry(
            entry,
            Some(source_handle.as_str()),
            Some(source_name.as_str()),
            &mut budget,
        );
        projection_truncated |= projected.text_truncated;
        entries.push(projected);
    }
    let projected_len = entries.len();
    let (threat_summary, threat_truncated) = project_threat_summary(
        result.threat_summary,
        MAX_CORRELATION_SOURCES * MAX_CORRELATION_LINE_LIMIT,
    )?;
    Ok(LogCorrelationDto {
        snapshot_handle: snapshot_handle.to_owned(),
        source_handles: source_handles.to_vec(),
        coverage: "bounded-best-effort",
        total_observed: source_len,
        entries,
        threat_summary,
        truncated: source_len > MAX_CORRELATION_ENTRIES
            || source_len > projected_len
            || projection_truncated
            || threat_truncated
            || budget.remaining() < MIN_ITEM_TEXT_BYTES,
    })
}

fn project_ioc_result(
    snapshot_handle: &str,
    path_index: &HashMap<String, (String, String)>,
    indicators: &[String],
    result: IocSearchResult,
) -> Result<LogIocSearchDto, LogAnalysisReadApiError> {
    let allowed = indicators
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let computed_total = result.results.iter().try_fold(0_usize, |total, item| {
        total
            .checked_add(item.count)
            .ok_or(LogAnalysisReadApiError::SnapshotStale)
    })?;
    if result.results.len() > 256 || computed_total != result.total_matches {
        return Err(LogAnalysisReadApiError::SnapshotStale);
    }
    let source_len = result.results.len();
    if source_len > MAX_IOC_PAIRS {
        return Err(LogAnalysisReadApiError::SnapshotStale);
    }
    let mut budget = TextBudget::new(MAX_IOC_TEXT_BYTES);
    let mut results = Vec::new();
    let mut projection_truncated = false;
    let mut seen_pairs = HashSet::new();
    for item in result.results.into_iter().take(MAX_IOC_RESULTS) {
        if !allowed.contains(item.indicator.as_str())
            || item.count > 1_000_000
            || item.sample_lines.len() > 3
            || !seen_pairs.insert((item.indicator.clone(), item.log_file.clone()))
        {
            return Err(LogAnalysisReadApiError::SnapshotStale);
        }
        if budget.remaining() < MIN_ITEM_TEXT_BYTES {
            break;
        }
        let (source_handle, source_name) = path_index
            .get(&item.log_file)
            .ok_or(LogAnalysisReadApiError::SnapshotStale)?;
        let (indicator, indicator_truncated) = budget.take(&item.indicator, MAX_IOC_BYTES);
        let (source_name, source_name_truncated) = budget.take(source_name, 256);
        let mut samples = Vec::new();
        let mut samples_truncated = false;
        for sample in item.sample_lines {
            let (sample, truncated) = budget.take(&sample, 4 * 1024);
            samples_truncated |= truncated;
            samples.push(sample);
        }
        let text_truncated = indicator_truncated || source_name_truncated || samples_truncated;
        projection_truncated |= text_truncated;
        results.push(LogIocMatchDto {
            indicator,
            source_handle: source_handle.clone(),
            source_name,
            count: item.count,
            sample_lines: samples,
            text_truncated,
        });
    }
    let projected_len = results.len();
    Ok(LogIocSearchDto {
        snapshot_handle: snapshot_handle.to_owned(),
        results,
        total_matches: result.total_matches,
        truncated: source_len > MAX_IOC_RESULTS
            || source_len > projected_len
            || projection_truncated
            || budget.remaining() < MIN_ITEM_TEXT_BYTES,
    })
}

fn project_entry(
    entry: LogEntry,
    source_handle: Option<&str>,
    source_name: Option<&str>,
    budget: &mut TextBudget,
) -> PublicLogEntryDto {
    // Every field is shown as the target wrote it. Filtering on credential-like
    // shapes used to blank the whole line, which threw away the auth.log
    // evidence an operator is reading the page for.
    let (timestamp, timestamp_truncated) = budget.take(&entry.timestamp, MAX_ENTRY_TIMESTAMP_BYTES);
    let (level, level_truncated) = budget.take(&entry.level, MAX_ENTRY_LEVEL_BYTES);
    let (service, service_truncated) = budget.take(&entry.service, MAX_ENTRY_SERVICE_BYTES);
    let (message, message_truncated) = budget.take(&entry.message, MAX_ENTRY_MESSAGE_BYTES);
    let (raw_text, raw_truncated) = budget.take(&entry.raw, MAX_ENTRY_RAW_BYTES);
    let (source_name, source_name_truncated) = source_name
        .map(|name| budget.take(name, 256))
        .map_or((None, false), |(name, truncated)| (Some(name), truncated));
    PublicLogEntryDto {
        timestamp,
        level,
        service,
        message,
        raw_text,
        highlighted: entry.highlighted,
        source_handle: source_handle.map(str::to_owned),
        source_name,
        text_truncated: timestamp_truncated
            || level_truncated
            || service_truncated
            || message_truncated
            || raw_truncated
            || source_name_truncated,
    }
}

fn project_threat_summary(
    summary: ThreatSummary,
    maximum_count: usize,
) -> Result<(ThreatSummaryDto, bool), LogAnalysisReadApiError> {
    if summary.brute_force_count > maximum_count
        || summary.successful_login_count > maximum_count
        || summary.privilege_escalation_count > maximum_count
        || summary.suspicious_activity_count > maximum_count
        || summary.top_source_ips.len() > 20
        || summary.top_target_users.len() > 20
        || summary.hourly_distribution.len() != 24
        || summary
            .top_source_ips
            .iter()
            .any(|item| item.count > maximum_count)
        || summary.top_target_users.iter().any(|item| {
            item.count > maximum_count
                || item.success_count > maximum_count
                || item.fail_count > maximum_count
                || item.success_count.saturating_add(item.fail_count) != item.count
        })
        || summary
            .hourly_distribution
            .iter()
            .any(|count| *count > maximum_count)
    {
        return Err(LogAnalysisReadApiError::SnapshotStale);
    }
    let mut text_truncated = false;
    let top_source_ips = summary
        .top_source_ips
        .into_iter()
        .map(|item| {
            let (ip, ip_truncated) = bounded_text(&item.ip, 64);
            let (last_seen, last_seen_truncated) = bounded_text(&item.last_seen, 128);
            let (action_type, action_type_truncated) = bounded_text(&item.action_type, 64);
            text_truncated |= ip_truncated || last_seen_truncated || action_type_truncated;
            ThreatIpDto {
                ip,
                count: item.count,
                last_seen,
                action_type,
            }
        })
        .collect();
    let top_target_users = summary
        .top_target_users
        .into_iter()
        .map(|item| {
            let (username, username_truncated) = bounded_text(&item.username, 64);
            text_truncated |= username_truncated;
            ThreatUserDto {
                username,
                count: item.count,
                success_count: item.success_count,
                fail_count: item.fail_count,
            }
        })
        .collect();
    Ok((
        ThreatSummaryDto {
            brute_force_count: summary.brute_force_count,
            successful_login_count: summary.successful_login_count,
            privilege_escalation_count: summary.privilege_escalation_count,
            suspicious_activity_count: summary.suspicious_activity_count,
            top_source_ips,
            top_target_users,
            hourly_distribution: summary.hourly_distribution,
            threat_level: match summary.threat_level {
                ThreatLevel::None => "none",
                ThreatLevel::Low => "low",
                ThreatLevel::Medium => "medium",
                ThreatLevel::High => "high",
                ThreatLevel::Critical => "critical",
            },
        },
        text_truncated,
    ))
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

    fn take(&mut self, value: &str, maximum_bytes: usize) -> (String, bool) {
        let limit = maximum_bytes.min(self.remaining);
        let (value, truncated) = bounded_text(value, limit);
        self.remaining = self.remaining.saturating_sub(value.len());
        (value, truncated)
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

fn validate_optional_text(
    value: Option<String>,
    maximum_bytes: usize,
    systemd_unit: bool,
) -> Result<Option<String>, LogAnalysisReadApiError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > maximum_bytes || value.chars().any(char::is_control) {
        return Err(LogAnalysisReadApiError::InvalidQuery);
    }
    if systemd_unit
        && !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@' | b':')
        })
    {
        return Err(LogAnalysisReadApiError::InvalidQuery);
    }
    Ok(Some(value.to_owned()))
}

fn validate_source_handles(
    handles: &[String],
    minimum: usize,
    maximum: usize,
) -> Result<(), LogAnalysisReadApiError> {
    if handles.len() < minimum || handles.len() > maximum {
        return Err(LogAnalysisReadApiError::InvalidQuery);
    }
    let mut seen = HashSet::new();
    for handle in handles {
        validate_handle(handle)?;
        if !seen.insert(handle.as_str()) {
            return Err(LogAnalysisReadApiError::InvalidQuery);
        }
    }
    Ok(())
}

fn validate_handle(value: &str) -> Result<(), LogAnalysisReadApiError> {
    if value.is_empty()
        || value.len() > MAX_HANDLE_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(LogAnalysisReadApiError::InvalidHandle);
    }
    Ok(())
}

fn unique_handle() -> Result<String, LogAnalysisReadApiError> {
    let handle = Uuid::new_v4().to_string();
    validate_handle(&handle)?;
    Ok(handle)
}

fn unique_map_handle<T>(existing: &HashMap<String, T>) -> Result<String, LogAnalysisReadApiError> {
    for _ in 0..8 {
        let handle = unique_handle()?;
        if !existing.contains_key(&handle) {
            return Ok(handle);
        }
    }
    Err(LogAnalysisReadApiError::Capacity)
}

#[cfg(test)]
mod tests {
    use lovelyres_core::{
        log_analysis::{
            IocMatch, IpCount, LogAnalysisResult, MultiLogResult, ThreatSummary, UserCount,
        },
        target::TargetIdentity,
    };

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

    fn file(path: &str) -> LogFileInfo {
        LogFileInfo {
            path: path.to_owned(),
            name: path.rsplit('/').next().unwrap().to_owned(),
            size: 42,
            modified: "1700000000".to_owned(),
            readable: true,
        }
    }

    fn threat() -> ThreatSummary {
        ThreatSummary {
            brute_force_count: 1,
            successful_login_count: 0,
            privilege_escalation_count: 0,
            suspicious_activity_count: 0,
            top_source_ips: vec![IpCount {
                ip: "192.0.2.1".to_owned(),
                count: 1,
                last_seen: "now".to_owned(),
                action_type: "failed_login".to_owned(),
            }],
            top_target_users: vec![UserCount {
                username: "root".to_owned(),
                count: 1,
                success_count: 0,
                fail_count: 1,
            }],
            hourly_distribution: vec![0; 24],
            threat_level: ThreatLevel::Low,
        }
    }

    fn entry(raw: &str, source: Option<&str>) -> LogEntry {
        LogEntry {
            timestamp: "2026-08-24 01:02:03".to_owned(),
            level: "ERROR".to_owned(),
            service: "sshd".to_owned(),
            message: raw.to_owned(),
            raw: raw.to_owned(),
            highlighted: true,
            source: source.map(str::to_owned),
        }
    }

    fn snapshot(now: Instant, name: &str) -> (SourceSnapshot, LogSourceSnapshotDto) {
        let (mut snapshot, dto) =
            build_source_snapshot(scope(name, 1), vec![file("/var/log/auth.log")], true, false)
                .unwrap();
        snapshot.created_at = now;
        snapshot.expires_at = now + SNAPSHOT_TTL;
        (snapshot, dto)
    }

    #[test]
    fn source_snapshot_uses_opaque_capabilities_and_only_readable_discovery_rows() {
        let (_, dto) = build_source_snapshot(
            scope("server", 1),
            vec![
                file("/var/log/auth.log"),
                file("/var/log/token=path-secret"),
                LogFileInfo {
                    path: "/var/log/secure".to_owned(),
                    name: "secure".to_owned(),
                    size: 0,
                    modified: String::new(),
                    readable: false,
                },
            ],
            true,
            false,
        )
        .unwrap();
        let value = serde_json::to_value(&dto).unwrap();
        assert_eq!(value["sources"].as_array().unwrap().len(), 3);
        assert!(value.to_string().contains("/var/log/auth.log"));
        // A path that happens to contain a credential word is still a path the
        // operator has to see to know which file this row is.
        assert!(value.to_string().contains("/var/log/token=path-secret"));
        // Unreadable files are dropped at discovery, so this one never appears.
        assert!(!value.to_string().contains("/var/log/secure"));
        assert!(!value.to_string().contains("session-server"));
        assert!(!value.to_string().contains("generation"));
        assert!(value["sources"][0]["sourceHandle"].as_str().is_some());
        assert!(value["sources"][0].get("path").is_none());
    }

    #[test]
    fn registry_is_target_ttl_concurrency_and_eviction_bounded() {
        let now = Instant::now();
        let (first, _) = snapshot(now, "server-0");
        let first_handle = first.handle.clone();
        let first_scope = first.scope.clone();
        let mut registry = SourceRegistry::default();
        registry.insert(first).unwrap();
        let access = registry.begin_read(&first_scope, &first_handle).unwrap();
        for _ in 1..MAX_ACTIVE_READS {
            registry.begin_read(&first_scope, &first_handle).unwrap();
        }
        assert!(matches!(
            registry.begin_read(&first_scope, &first_handle),
            Err(LogAnalysisReadApiError::Capacity)
        ));
        let token = access.token;
        for _ in 0..MAX_ACTIVE_READS {
            registry.release_read(&first_handle, token);
        }
        registry
            .snapshots
            .get_mut(&first_handle)
            .unwrap()
            .expires_at = now;
        assert!(matches!(
            registry.verify(&access),
            Err(LogAnalysisReadApiError::SnapshotStale)
        ));
        registry.prune(now);
        assert!(!registry.snapshots.contains_key(&first_handle));

        let mut handles = Vec::new();
        for index in 0..=MAX_SNAPSHOTS {
            let (mut snapshot, _) = snapshot(now, &format!("evict-{index}"));
            snapshot.created_at = now + Duration::from_millis(index as u64);
            handles.push(snapshot.handle.clone());
            registry.insert(snapshot).unwrap();
        }
        assert_eq!(registry.snapshots.len(), MAX_SNAPSHOTS);
        assert!(!registry.snapshots.contains_key(&handles[0]));
        assert!(registry.total_bytes() <= MAX_REGISTRY_BYTES);
    }

    #[test]
    fn close_binding_removes_only_its_capabilities_and_rejects_late_results() {
        let now = Instant::now();
        let (current, _) = snapshot(now, "server");
        let current_handle = current.handle.clone();
        let current_scope = current.scope.clone();
        let (mut stale, _) = snapshot(now, "server-stale");
        stale.scope.binding_handle = current_scope.binding_handle.clone();
        stale.scope.target.generation += 1;
        let stale_handle = stale.handle.clone();
        let (other, _) = snapshot(now, "other");
        let other_handle = other.handle.clone();
        let other_scope = other.scope.clone();

        let mut registry = SourceRegistry::default();
        registry.insert(current).unwrap();
        registry.insert(stale).unwrap();
        registry.insert(other).unwrap();
        registry.begin_discovery(&current_scope).unwrap();
        let late_access = registry
            .begin_read(&current_scope, &current_handle)
            .unwrap();

        registry.close_binding(&current_scope.binding_handle);

        assert!(!registry.snapshots.contains_key(&current_handle));
        assert!(!registry.snapshots.contains_key(&stale_handle));
        assert!(registry.snapshots.contains_key(&other_handle));
        assert_eq!(registry.active_discoveries, 1);
        assert!(
            registry
                .discovering_bindings
                .contains(&current_scope.binding_handle)
        );
        assert!(matches!(
            registry.verify(&late_access),
            Err(LogAnalysisReadApiError::SnapshotStale)
        ));
        assert!(registry.begin_read(&other_scope, &other_handle).is_ok());
        registry.release_discovery(&current_scope.binding_handle);
        assert_eq!(registry.active_discoveries, 0);
    }

    #[test]
    fn typed_queries_reject_paths_controls_invalid_dates_and_unsafe_journal_units() {
        let parsed = serde_json::from_value::<LogSourceReadInput>(serde_json::json!({
            "page": 1,
            "pageSize": 100,
            "keyword": "failed",
            "date": "2026-08-24",
            "journalUnit": "sshd.service"
        }))
        .unwrap();
        assert!(parsed.validate().is_ok());
        assert!(
            serde_json::from_value::<LogSourceReadInput>(serde_json::json!({
                "page": 1,
                "pageSize": 100,
                "keyword": null,
                "date": null,
                "journalUnit": null,
                "path": "/var/log/auth.log"
            }))
            .is_err()
        );
        for unit in ["sshd.service;id", "sshd.service\n--root", "$(id)"] {
            assert!(
                LogSourceReadInput {
                    page: 1,
                    page_size: 100,
                    keyword: None,
                    date: None,
                    journal_unit: Some(unit.to_owned()),
                }
                .validate()
                .is_err()
            );
        }
        assert!(
            LogSourceReadInput {
                page: 1,
                page_size: 100,
                keyword: None,
                date: Some("2026-02-30".to_owned()),
                journal_unit: None,
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn read_projection_preserves_hostile_text_and_every_logged_line() {
        let hostile = "</pre><script>steal()</script>";
        let mut metadata_secret = entry("safe raw text", None);
        metadata_secret.service = "token=service-secret".to_owned();
        let mut summary = threat();
        summary.top_source_ips[0].last_seen = "token=summary-secret".to_owned();
        summary.top_source_ips[0].action_type = "x".repeat(1_000);
        summary.top_target_users[0].username = "password:user-secret".to_owned();
        let result = LogAnalysisResult {
            entries: vec![
                entry(hostile, None),
                entry("authorization: Bearer secret-value", None),
                metadata_secret,
            ],
            total_count: 3,
            highlighted_count: 3,
            threat_summary: Some(summary),
        };
        let dto = project_read_result(
            "snapshot-1",
            "source-1",
            LogSourceKind::File,
            1,
            100,
            result,
        )
        .unwrap();
        let json = serde_json::to_string(&dto).unwrap();
        assert!(json.contains(hostile));
        // An auth.log line that mentions a bearer token is the evidence, not a
        // leak: blanking it threw away what the page exists to show.
        assert!(json.contains("authorization: Bearer secret-value"));
        assert!(json.contains("token=service-secret"));
        assert!(json.contains("token=summary-secret"));
        assert!(json.contains("password:user-secret"));
        // Size limits still apply; only the credential filter is gone.
        assert!(dto.truncated);
        assert!(json.len() <= MAX_READ_TEXT_BYTES + 16 * 1024);
    }

    #[test]
    fn correlation_replaces_raw_paths_with_snapshot_bound_source_handles() {
        let path = "/var/log/auth.log".to_owned();
        let index = HashMap::from([(path.clone(), ("source-1".to_owned(), "auth.log".to_owned()))]);
        let dto = project_correlation_result(
            "snapshot-1",
            &["source-1".to_owned(), "source-2".to_owned()],
            &index,
            MultiLogResult {
                entries: vec![entry("hostile <img src=x onerror=steal()>", Some(&path))],
                total_count: 1,
                sources: vec![path.clone()],
                threat_summary: threat(),
            },
        )
        .unwrap();
        let value = serde_json::to_value(dto).unwrap();
        assert_eq!(value["entries"][0]["sourceHandle"], "source-1");
        assert_eq!(value["entries"][0]["sourceName"], "auth.log");
        assert!(!value.to_string().contains(&path));
        assert_eq!(value["coverage"], "bounded-best-effort");
    }

    #[test]
    fn ioc_projection_is_source_bound_bounded_and_redacts_samples() {
        let path = "/var/log/auth.log".to_owned();
        let index = HashMap::from([(path.clone(), ("source-1".to_owned(), "auth.log".to_owned()))]);
        let result = IocSearchResult {
            results: vec![IocMatch {
                indicator: "192.0.2.1".to_owned(),
                log_file: path,
                count: 1,
                sample_lines: vec!["password=remote-secret".to_owned()],
            }],
            total_matches: 1,
        };
        let dto =
            project_ioc_result("snapshot-1", &index, &["192.0.2.1".to_owned()], result).unwrap();
        let json = serde_json::to_string(&dto).unwrap();
        assert!(json.contains("source-1"));
        assert!(json.contains("password=remote-secret"));
    }

    #[test]
    fn source_only_calls_core_read_service_and_has_no_rule_ai_export_file_or_terminal_surface() {
        let source = include_str!("log_analysis_read_api.rs");
        for required in [
            ".list_files(&session)",
            ".read_file(&session",
            ".read_journal(&session",
            ".analyze_multi(",
            ".search_iocs(",
        ] {
            assert!(
                source.contains(required),
                "missing core read call: {required}"
            );
        }
        for forbidden in [
            ["generate_", "log_read_command"].concat(),
            ["generate_", "journalctl_command"].concat(),
            ["generate_", "ioc_search_command"].concat(),
            ["list_", "rules"].concat(),
            ["add_", "rule"].concat(),
            ["remove_", "rule"].concat(),
            ["export_", "logs"].concat(),
            ["open_", "terminal"].concat(),
            ["read_", "arbitrary_file"].concat(),
            ["execute_", "bound"].concat(),
            ["shell", ".execute"].concat(),
        ] {
            assert!(
                !source.contains(&forbidden),
                "unexpected surface: {forbidden}"
            );
        }
    }
}
