//! Bounded, redacted diagnostic-log capture for the desktop backend.
//!
//! The layer records structured `tracing` events, never backend stderr. Its public DTOs are
//! suitable for the renderer only after the finite desktop IPC boundary validates them. The
//! sidecar composition root installs this layer into its single subscriber. Once the host knows
//! its portable data directory it can also hand the same redacted entries to a small rolling log
//! file there, so a crash or a restart leaves something to read.

use std::{
    collections::VecDeque,
    error::Error as StdError,
    fmt,
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tracing::{Event, Level, Metadata, Subscriber, field::Visit};
use tracing_subscriber::{Layer, layer::Context as LayerContext};

const DIAGNOSTIC_CAPACITY: usize = 500;
const DISPLAY_ENTRY_LIMIT: usize = 100;
const MAX_SEARCH_BYTES: usize = 256;
const MAX_MODULE_BYTES: usize = 256;
const MAX_MESSAGE_BYTES: usize = 4 * 1024;
const MAX_FIELD_NAME_BYTES: usize = 64;
const MAX_FIELD_BYTES: usize = 4 * 1024;
const MAX_DETAILS_BYTES: usize = 16 * 1024;
const MAX_FIELDS: usize = 32;
const PREVIEW_MAX_BYTES: usize = 128 * 1024;
const EXPORT_MAX_BYTES: usize = 256 * 1024;
const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;
/// The current log file; older ones are `lovelyhawk.1.log` and `lovelyhawk.2.log`.
pub const LOG_FILE_NAME: &str = "lovelyhawk.log";
const MAX_LOG_FILE_BYTES: u64 = 2 * 1024 * 1024;
/// The current file and two older ones: about six megabytes in all.
const KEPT_LOG_FILES: usize = 3;

const LOG_FILE_MEMORY_ONLY: u8 = 0;
const LOG_FILE_WRITING: u8 = 1;
const LOG_FILE_FAILED: u8 = 2;

const REDACTED: &str = "[REDACTED]";
const SENSITIVE_FIELD_REDACTED: &str = "[SENSITIVE FIELD]";
const DEBUG_REDACTED: &str = "[DEBUG VALUE REDACTED]";
const ERROR_REDACTED: &str = "[ERROR DETAIL REDACTED]";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticLogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DiagnosticLogFilterInput {
    pub(crate) minimum_level: Option<DiagnosticLogLevel>,
    pub(crate) search: String,
}

impl fmt::Debug for DiagnosticLogFilterInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiagnosticLogFilterInput")
            .field("minimum_level", &self.minimum_level)
            .field("search_bytes", &self.search.len())
            .field("search", &"[REDACTED]")
            .finish()
    }
}

impl DiagnosticLogFilterInput {
    fn validate(&self) -> Result<(), DiagnosticLogApiError> {
        if self.search.len() > MAX_SEARCH_BYTES {
            return Err(DiagnosticLogApiError::SearchTooLong);
        }
        if self.search.chars().any(char::is_control) {
            return Err(DiagnosticLogApiError::SearchContainsControl);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DiagnosticLogDetailDto {
    pub(crate) name: String,
    pub(crate) value: String,
}

impl fmt::Debug for DiagnosticLogDetailDto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiagnosticLogDetailDto")
            .field("name", &"[REDACTED]")
            .field("value", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DiagnosticLogEntryDto {
    pub(crate) sequence: u64,
    pub(crate) timestamp_unix_ms: u64,
    pub(crate) level: DiagnosticLogLevel,
    pub(crate) module: String,
    pub(crate) message: String,
    pub(crate) details: Vec<DiagnosticLogDetailDto>,
}

impl fmt::Debug for DiagnosticLogEntryDto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiagnosticLogEntryDto")
            .field("sequence", &self.sequence)
            .field("timestamp_unix_ms", &self.timestamp_unix_ms)
            .field("level", &self.level)
            .field("module", &"[REDACTED]")
            .field("message", &"[REDACTED]")
            .field("detail_count", &self.details.len())
            .finish()
    }
}

impl DiagnosticLogEntryDto {
    fn as_text(&self) -> String {
        let details = if self.details.is_empty() {
            String::new()
        } else {
            let projected = self
                .details
                .iter()
                .map(|detail| {
                    if is_sensitive_field(&detail.name) {
                        DiagnosticLogDetailDto {
                            name: SENSITIVE_FIELD_REDACTED.to_owned(),
                            value: REDACTED.to_owned(),
                        }
                    } else {
                        detail.clone()
                    }
                })
                .collect::<Vec<_>>();
            serde_json::to_string(&projected)
                .map(|value| format!(" | {value}"))
                .unwrap_or_else(|_| {
                    " | [{\"name\":\"details\",\"value\":\"unavailable\"}]".to_owned()
                })
        };
        format!(
            "[{}] [{}] [{}] {}{}",
            self.timestamp_unix_ms,
            level_label(self.level),
            self.module,
            self.message,
            details
        )
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DiagnosticLogSnapshotDto {
    pub(crate) capacity: usize,
    pub(crate) total_buffered: usize,
    pub(crate) total_matched: usize,
    pub(crate) displayed: usize,
    pub(crate) current_level: DiagnosticLogLevel,
    pub(crate) generation: u64,
    pub(crate) entries: Vec<DiagnosticLogEntryDto>,
    /// Whether entries also go to the log file in the data directory: "writing",
    /// "memory-only" (no file yet) or "failed" (writing stopped after an error).
    pub(crate) log_file: &'static str,
}

impl fmt::Debug for DiagnosticLogSnapshotDto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiagnosticLogSnapshotDto")
            .field("capacity", &self.capacity)
            .field("total_buffered", &self.total_buffered)
            .field("total_matched", &self.total_matched)
            .field("displayed", &self.displayed)
            .field("current_level", &self.current_level)
            .field("generation", &self.generation)
            .field("entries", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DiagnosticLogLevelResult {
    pub(crate) level: DiagnosticLogLevel,
    pub(crate) persisted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DiagnosticLogClearResult {
    pub(crate) cleared_entries: usize,
    pub(crate) volatile_only: bool,
    pub(crate) persisted_files_affected: bool,
    pub(crate) generation: u64,
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DiagnosticLogPreviewDto {
    pub(crate) content: String,
    pub(crate) entry_count: usize,
    pub(crate) truncated: bool,
}

impl fmt::Debug for DiagnosticLogPreviewDto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiagnosticLogPreviewDto")
            .field("content", &"[REDACTED]")
            .field("entry_count", &self.entry_count)
            .field("truncated", &self.truncated)
            .finish()
    }
}

/// Internal backend-to-host payload. The desktop host must validate it and return only a basename.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DiagnosticLogExportPayload {
    pub(crate) format: &'static str,
    pub(crate) suggested_name: String,
    pub(crate) media_type: &'static str,
    pub(crate) entry_count: usize,
    pub(crate) truncated: bool,
    pub(crate) contents: String,
}

impl fmt::Debug for DiagnosticLogExportPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiagnosticLogExportPayload")
            .field("format", &self.format)
            .field("suggested_name", &self.suggested_name)
            .field("media_type", &self.media_type)
            .field("entry_count", &self.entry_count)
            .field("truncated", &self.truncated)
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

struct LogBufferState {
    entries: VecDeque<DiagnosticLogEntryDto>,
    generation: u64,
}

/// The log file under the portable data directory, rolled over at a fixed size so it never
/// grows without bound. It receives the same redacted entries the overlay shows.
struct RollingLogFile {
    directory: PathBuf,
    /// None only while the current file is being moved aside: Windows cannot rename a
    /// file that is still open.
    file: Option<File>,
    written: u64,
}

impl RollingLogFile {
    fn open(directory: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(directory)?;
        let file = Self::open_current(directory)?;
        let written = file.metadata()?.len();
        Ok(Self {
            directory: directory.to_owned(),
            file: Some(file),
            written,
        })
    }

    fn open_current(directory: &Path) -> std::io::Result<File> {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(directory.join(LOG_FILE_NAME))
    }

    fn rolled(&self, index: usize) -> PathBuf {
        self.directory.join(format!("lovelyhawk.{index}.log"))
    }

    fn write_line(&mut self, line: &str) -> std::io::Result<()> {
        let length = line.len() as u64;
        if self.written > 0 && self.written.saturating_add(length) > MAX_LOG_FILE_BYTES {
            self.roll_over()?;
        }
        let file = match self.file.as_mut() {
            Some(file) => file,
            None => self.file.insert(Self::open_current(&self.directory)?),
        };
        // Written whole and flushed at once: what survives a crash is complete lines.
        file.write_all(line.as_bytes())?;
        file.flush()?;
        self.written = self.written.saturating_add(length);
        Ok(())
    }

    fn roll_over(&mut self) -> std::io::Result<()> {
        let oldest = self.rolled(KEPT_LOG_FILES - 1);
        if oldest.exists() {
            std::fs::remove_file(&oldest)?;
        }
        for index in (1..KEPT_LOG_FILES - 1).rev() {
            let from = self.rolled(index);
            if from.exists() {
                std::fs::rename(&from, self.rolled(index + 1))?;
            }
        }
        self.file = None;
        std::fs::rename(self.directory.join(LOG_FILE_NAME), self.rolled(1))?;
        self.file = Some(Self::open_current(&self.directory)?);
        self.written = 0;
        Ok(())
    }
}

/// One line per entry: time, level, module, message, then its details.
fn log_file_line(entry: &DiagnosticLogEntryDto) -> String {
    let time = i64::try_from(entry.timestamp_unix_ms)
        .ok()
        .and_then(chrono::DateTime::from_timestamp_millis)
        .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        .unwrap_or_else(|| "-".to_owned());
    let level = match entry.level {
        DiagnosticLogLevel::Debug => "DEBUG",
        DiagnosticLogLevel::Info => "INFO",
        DiagnosticLogLevel::Warn => "WARN",
        DiagnosticLogLevel::Error => "ERROR",
    };
    let mut line = format!("{time} {level} {} {}", entry.module, entry.message);
    for detail in &entry.details {
        line.push_str(&format!(" {}={}", detail.name, detail.value));
    }
    // A line break inside the text would forge the next entry.
    let mut line = line.replace(['\r', '\n'], " ");
    line.push('\n');
    line
}

/// Shared capture state. Its `Debug` output intentionally contains neither entries nor fields.
pub struct DiagnosticLogCapture {
    state: Mutex<LogBufferState>,
    minimum_level: AtomicU8,
    next_sequence: AtomicU64,
    file: Mutex<Option<RollingLogFile>>,
    file_state: AtomicU8,
}

impl fmt::Debug for DiagnosticLogCapture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiagnosticLogCapture")
            .field("capacity", &DIAGNOSTIC_CAPACITY)
            .field("buffered", &self.state.lock().entries.len())
            .field("minimum_level", &self.level())
            .field("entries", &"[REDACTED]")
            .finish()
    }
}

impl DiagnosticLogCapture {
    pub fn new(level: DiagnosticLogLevel) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(LogBufferState {
                entries: VecDeque::with_capacity(DIAGNOSTIC_CAPACITY),
                generation: 0,
            }),
            minimum_level: AtomicU8::new(level_rank(level)),
            next_sequence: AtomicU64::new(1),
            file: Mutex::new(None),
            file_state: AtomicU8::new(LOG_FILE_MEMORY_ONLY),
        })
    }

    /// Starts writing every captured entry, redacted as the overlay shows it, to
    /// `directory/lovelyhawk.log`, beginning with what is already buffered. Called once the
    /// host holds the data directory's single-instance lock, so one process writes the file.
    pub fn persist_to(&self, directory: &Path) -> std::io::Result<()> {
        let mut file = RollingLogFile::open(directory)?;
        let (buffered, _) = self.snapshot();
        let mut sink = self.file.lock();
        for entry in &buffered {
            file.write_line(&log_file_line(entry))?;
        }
        *sink = Some(file);
        self.file_state.store(LOG_FILE_WRITING, Ordering::Release);
        Ok(())
    }

    fn file_state(&self) -> &'static str {
        match self.file_state.load(Ordering::Acquire) {
            LOG_FILE_WRITING => "writing",
            LOG_FILE_FAILED => "failed",
            _ => "memory-only",
        }
    }

    /// Returns the capture layer for composition into the sidecar's single subscriber.
    pub fn layer(self: &Arc<Self>) -> DiagnosticLogLayer {
        DiagnosticLogLayer {
            capture: Arc::clone(self),
        }
    }

    fn level(&self) -> DiagnosticLogLevel {
        level_from_rank(self.minimum_level.load(Ordering::Acquire))
    }

    fn set_level(&self, level: DiagnosticLogLevel) {
        self.minimum_level
            .store(level_rank(level), Ordering::Release);
    }

    fn allows(&self, metadata: &Metadata<'_>) -> bool {
        let configured = self.minimum_level.load(Ordering::Acquire);
        // This program's own crates follow the chosen level; everything else is held to
        // warnings. The crates were renamed to lovelyhawk_*: matching the old prefix had
        // quietly reduced the program's own records to warnings too.
        let minimum = if metadata.target().starts_with("lovelyhawk") {
            configured
        } else {
            configured.max(level_rank(DiagnosticLogLevel::Warn))
        };
        tracing_level_rank(metadata.level()) >= minimum
    }

    fn push(&self, entry: DiagnosticLogEntryDto) {
        let line = log_file_line(&entry);
        {
            let mut state = self.state.lock();
            if state.entries.len() == DIAGNOSTIC_CAPACITY {
                state.entries.pop_front();
            }
            state.entries.push_back(entry);
            state.generation = next_public_generation(state.generation);
        }
        let mut sink = self.file.lock();
        // A file that cannot be written stops being written, and the overlay says so;
        // logging the failure from inside the logger would only recurse.
        if let Some(file) = sink.as_mut()
            && file.write_line(&line).is_err()
        {
            *sink = None;
            self.file_state.store(LOG_FILE_FAILED, Ordering::Release);
        }
    }

    fn record(&self, metadata: &Metadata<'_>, visitor: EventVisitor) {
        let Ok(sequence) =
            self.next_sequence
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    (current <= MAX_SAFE_JSON_INTEGER).then(|| current.saturating_add(1))
                })
        else {
            return;
        };
        let timestamp_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| {
                u64::try_from(duration.as_millis())
                    .unwrap_or(MAX_SAFE_JSON_INTEGER)
                    .min(MAX_SAFE_JSON_INTEGER)
            })
            .unwrap_or(0);
        self.push(DiagnosticLogEntryDto {
            sequence,
            timestamp_unix_ms,
            level: tracing_level(metadata.level()),
            module: project_public_text(metadata.target(), MAX_MODULE_BYTES),
            message: visitor
                .message
                .unwrap_or_else(|| project_public_text(metadata.name(), MAX_MESSAGE_BYTES)),
            details: visitor.details,
        });
    }

    fn clear(&self) -> DiagnosticLogClearResult {
        let mut state = self.state.lock();
        let cleared_entries = state.entries.len();
        state.entries.clear();
        state.generation = next_public_generation(state.generation);
        DiagnosticLogClearResult {
            cleared_entries,
            volatile_only: true,
            persisted_files_affected: false,
            generation: state.generation,
        }
    }

    fn snapshot(&self) -> (Vec<DiagnosticLogEntryDto>, u64) {
        let state = self.state.lock();
        (state.entries.iter().cloned().collect(), state.generation)
    }
}

#[derive(Clone, Debug)]
pub struct DiagnosticLogLayer {
    capture: Arc<DiagnosticLogCapture>,
}

impl<S> Layer<S> for DiagnosticLogLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _: LayerContext<'_, S>) {
        if !self.capture.allows(event.metadata()) {
            return;
        }
        let mut visitor = EventVisitor::default();
        event.record(&mut visitor);
        self.capture.record(event.metadata(), visitor);
    }
}

#[derive(Default)]
struct EventVisitor {
    message: Option<String>,
    details: Vec<DiagnosticLogDetailDto>,
    details_bytes: usize,
}

impl EventVisitor {
    fn record_text(&mut self, field: &tracing::field::Field, value: &str) {
        let name = field.name();
        if name == "message" {
            self.message = Some(project_public_text(value, MAX_MESSAGE_BYTES));
            return;
        }
        let value = if is_sensitive_field(name) {
            REDACTED.to_owned()
        } else {
            project_public_text(value, MAX_FIELD_BYTES)
        };
        self.push_detail(name, value);
    }

    fn record_fixed(&mut self, field: &tracing::field::Field, value: &'static str) {
        let name = field.name();
        let value = if is_sensitive_field(name) {
            REDACTED
        } else {
            value
        };
        self.push_detail(name, value.to_owned());
    }

    fn push_detail(&mut self, name: &str, value: String) {
        if self.details.len() >= MAX_FIELDS {
            return;
        }
        let name = bounded_plain_text(name, MAX_FIELD_NAME_BYTES);
        if self.details_bytes + name.len() >= MAX_DETAILS_BYTES {
            return;
        }
        let remaining = MAX_DETAILS_BYTES - self.details_bytes - name.len();
        let value = truncate_utf8(&value, remaining.min(MAX_FIELD_BYTES));
        self.details_bytes += name.len() + value.len();
        self.details.push(DiagnosticLogDetailDto { name, value });
    }
}

impl Visit for EventVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        // `tracing` encodes the event's message as `fmt::Arguments` through this callback. All
        // other arbitrary Debug implementations are untrusted and must never reach the renderer.
        if field.name() == "message" {
            self.message = Some(project_public_text(
                &format!("{value:?}"),
                MAX_MESSAGE_BYTES,
            ));
        } else {
            self.record_fixed(field, DEBUG_REDACTED);
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.record_text(field, value);
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.record_text(field, if value { "true" } else { "false" });
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.record_text(field, &value.to_string());
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.record_text(field, &value.to_string());
    }

    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        self.record_text(field, &value.to_string());
    }

    fn record_error(&mut self, field: &tracing::field::Field, _: &(dyn StdError + 'static)) {
        // Error Display/Debug implementations may contain credentials or local paths.
        self.record_fixed(field, ERROR_REDACTED);
    }
}

#[derive(Clone, Debug)]
pub(crate) struct DiagnosticLogApi {
    capture: Arc<DiagnosticLogCapture>,
}

impl DiagnosticLogApi {
    pub(crate) fn new(capture: Arc<DiagnosticLogCapture>) -> Self {
        Self { capture }
    }

    pub(crate) fn list(
        &self,
        filter: DiagnosticLogFilterInput,
    ) -> Result<DiagnosticLogSnapshotDto, DiagnosticLogApiError> {
        filter.validate()?;
        let (entries, generation) = self.capture.snapshot();
        let total_buffered = entries.len();
        let mut matched = filter_entries(&entries, &filter);
        let total_matched = matched.len();
        let start = matched.len().saturating_sub(DISPLAY_ENTRY_LIMIT);
        matched = matched.split_off(start);
        matched.reverse();
        Ok(DiagnosticLogSnapshotDto {
            capacity: DIAGNOSTIC_CAPACITY,
            total_buffered,
            total_matched,
            displayed: matched.len(),
            current_level: self.capture.level(),
            generation,
            entries: matched,
            log_file: self.capture.file_state(),
        })
    }

    pub(crate) fn set_level(&self, level: DiagnosticLogLevel) -> DiagnosticLogLevelResult {
        self.capture.set_level(level);
        DiagnosticLogLevelResult {
            level,
            // Persistence belongs to the settings repository and is not implied by this API.
            persisted: false,
        }
    }

    pub(crate) fn clear_buffer(&self) -> DiagnosticLogClearResult {
        self.capture.clear()
    }

    pub(crate) fn preview(
        &self,
        filter: DiagnosticLogFilterInput,
    ) -> Result<DiagnosticLogPreviewDto, DiagnosticLogApiError> {
        filter.validate()?;
        let (entries, _) = self.capture.snapshot();
        let matched = filter_entries(&entries, &filter);
        let (content, entry_count, truncated) = bounded_text(&matched, PREVIEW_MAX_BYTES);
        Ok(DiagnosticLogPreviewDto {
            content,
            entry_count,
            truncated,
        })
    }

    pub(crate) fn prepare_export(
        &self,
        filter: DiagnosticLogFilterInput,
    ) -> Result<DiagnosticLogExportPayload, DiagnosticLogApiError> {
        filter.validate()?;
        let (entries, _) = self.capture.snapshot();
        let matched = filter_entries(&entries, &filter);
        let (contents, entry_count, truncated) = bounded_text(&matched, EXPORT_MAX_BYTES);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        Ok(DiagnosticLogExportPayload {
            format: "text",
            suggested_name: format!("LovelyHawk-diagnostics-{timestamp}.log"),
            media_type: "text/plain; charset=utf-8",
            entry_count,
            truncated,
            contents,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DiagnosticLogApiError {
    SearchTooLong,
    SearchContainsControl,
}

impl fmt::Display for DiagnosticLogApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SearchTooLong => {
                formatter.write_str("diagnostic log search exceeds the boundary")
            }
            Self::SearchContainsControl => {
                formatter.write_str("diagnostic log search contains unsupported text")
            }
        }
    }
}

impl StdError for DiagnosticLogApiError {}

fn filter_entries(
    entries: &[DiagnosticLogEntryDto],
    filter: &DiagnosticLogFilterInput,
) -> Vec<DiagnosticLogEntryDto> {
    let needle = filter.search.to_lowercase();
    entries
        .iter()
        .filter(|entry| {
            filter
                .minimum_level
                .is_none_or(|minimum| level_rank(entry.level) >= level_rank(minimum))
                && (needle.is_empty()
                    || entry.module.to_lowercase().contains(&needle)
                    || entry.message.to_lowercase().contains(&needle)
                    || entry.details.iter().any(|detail| {
                        detail.name.to_lowercase().contains(&needle)
                            || detail.value.to_lowercase().contains(&needle)
                    }))
        })
        .cloned()
        .collect()
}

fn bounded_text(entries: &[DiagnosticLogEntryDto], maximum_bytes: usize) -> (String, usize, bool) {
    let mut selected = Vec::new();
    let mut total_bytes = 0;
    for entry in entries.iter().rev() {
        let line = entry.as_text();
        let separator = usize::from(!selected.is_empty());
        if total_bytes + separator + line.len() > maximum_bytes {
            break;
        }
        total_bytes += separator + line.len();
        selected.push(line);
    }
    selected.reverse();
    let entry_count = selected.len();
    (
        selected.join("\n"),
        entry_count,
        entry_count < entries.len(),
    )
}

const fn level_rank(level: DiagnosticLogLevel) -> u8 {
    match level {
        DiagnosticLogLevel::Debug => 1,
        DiagnosticLogLevel::Info => 2,
        DiagnosticLogLevel::Warn => 3,
        DiagnosticLogLevel::Error => 4,
    }
}

const fn level_from_rank(rank: u8) -> DiagnosticLogLevel {
    match rank {
        0 | 1 => DiagnosticLogLevel::Debug,
        2 => DiagnosticLogLevel::Info,
        3 => DiagnosticLogLevel::Warn,
        _ => DiagnosticLogLevel::Error,
    }
}

const fn tracing_level(level: &Level) -> DiagnosticLogLevel {
    match *level {
        Level::TRACE | Level::DEBUG => DiagnosticLogLevel::Debug,
        Level::INFO => DiagnosticLogLevel::Info,
        Level::WARN => DiagnosticLogLevel::Warn,
        Level::ERROR => DiagnosticLogLevel::Error,
    }
}

const fn tracing_level_rank(level: &Level) -> u8 {
    match *level {
        Level::TRACE => 0,
        Level::DEBUG => 1,
        Level::INFO => 2,
        Level::WARN => 3,
        Level::ERROR => 4,
    }
}

const fn level_label(level: DiagnosticLogLevel) -> &'static str {
    match level {
        DiagnosticLogLevel::Debug => "DEBUG",
        DiagnosticLogLevel::Info => "INFO",
        DiagnosticLogLevel::Warn => "WARN",
        DiagnosticLogLevel::Error => "ERROR",
    }
}

fn is_sensitive_field(name: &str) -> bool {
    let normalized = name.to_ascii_lowercase();
    [
        "password",
        "passwd",
        "passphrase",
        "secret",
        "token",
        "authorization",
        "api_key",
        "apikey",
        "private_key",
        "credential",
        "cookie",
        "session_id",
        "archive_root",
        "data_root",
        "local_path",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
}

fn project_public_text(value: &str, maximum_bytes: usize) -> String {
    let detection = detection_text(value, maximum_bytes.saturating_add(64));
    if contains_sensitive_material(&detection) {
        REDACTED.to_owned()
    } else {
        bounded_plain_text(value, maximum_bytes)
    }
}

fn detection_text(value: &str, maximum_bytes: usize) -> String {
    let mut detection = String::with_capacity(value.len().min(maximum_bytes));
    for character in value.chars() {
        if character.is_control() {
            continue;
        }
        if detection.len() + character.len_utf8() > maximum_bytes {
            break;
        }
        detection.push(character);
    }
    detection
}

fn contains_sensitive_material(value: &str) -> bool {
    const MARKERS: &[&str] = &[
        "password=",
        "password:",
        "password\"",
        "password'",
        "password_",
        "_password",
        "--password",
        "passwd=",
        "passphrase=",
        "passphrase:",
        "passphrase\"",
        "passphrase'",
        "secret=",
        "secret:",
        "secret\"",
        "secret'",
        "secret_",
        "_secret",
        "--secret",
        "token=",
        "token:",
        "token\"",
        "token'",
        "token_",
        "_token",
        "--token",
        "authorization=",
        "authorization:",
        "authorization\"",
        "authorization'",
        "api_key=",
        "api_key:",
        "api-key:",
        "apikey=",
        "apikey:",
        "apikey\"",
        "apikey'",
        "private_key=",
        "private-key",
        "access_key",
        "access-key",
        "client_secret",
        "client-secret",
        "private key-----",
        "credential=",
        "credential:",
        "credential\"",
        "credential'",
        "cookie:",
        "set-cookie:",
        "session_id=",
        "session_id:",
        "session-id:",
        "sessionid\"",
        "sessionid'",
        "fingerprint=",
        "bearer ",
    ];
    MARKERS
        .iter()
        .any(|marker| contains_ascii_case_insensitive(value, marker))
        || contains_uri_userinfo(value)
}

fn contains_ascii_case_insensitive(value: &str, marker: &str) -> bool {
    value
        .as_bytes()
        .windows(marker.len())
        .any(|candidate| candidate.eq_ignore_ascii_case(marker.as_bytes()))
}

fn contains_uri_userinfo(value: &str) -> bool {
    let mut remaining = value;
    while let Some(marker) = remaining.find("://") {
        remaining = &remaining[marker + 3..];
        let authority = remaining
            .split(|character: char| {
                character == '/'
                    || character == '?'
                    || character == '#'
                    || character.is_ascii_whitespace()
            })
            .next()
            .unwrap_or_default();
        if authority.contains('@') {
            return true;
        }
    }
    false
}

fn next_public_generation(current: u64) -> u64 {
    current.saturating_add(1).min(MAX_SAFE_JSON_INTEGER)
}

fn bounded_plain_text(value: &str, maximum_bytes: usize) -> String {
    let mut normalized = String::with_capacity(value.len().min(maximum_bytes));
    for character in value.chars() {
        match character {
            '\n' => normalized.push_str("\\n"),
            '\r' => normalized.push_str("\\r"),
            '\t' => normalized.push_str("\\t"),
            character if character.is_control() => normalized.push('�'),
            character => normalized.push(character),
        }
        if normalized.len() > maximum_bytes + 16 {
            break;
        }
    }
    truncate_utf8(&normalized, maximum_bytes)
}

fn truncate_utf8(value: &str, maximum_bytes: usize) -> String {
    if value.len() <= maximum_bytes {
        return value.to_owned();
    }
    const SUFFIX: &str = "…[truncated]";
    if maximum_bytes <= SUFFIX.len() {
        let mut end = maximum_bytes;
        while !SUFFIX.is_char_boundary(end) {
            end -= 1;
        }
        return SUFFIX[..end].to_owned();
    }
    let mut end = maximum_bytes - SUFFIX.len();
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{}", &value[..end], SUFFIX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::prelude::*;

    fn filter(search: &str, minimum_level: Option<DiagnosticLogLevel>) -> DiagnosticLogFilterInput {
        DiagnosticLogFilterInput {
            minimum_level,
            search: search.to_owned(),
        }
    }

    fn entry(sequence: u64, level: DiagnosticLogLevel, message: &str) -> DiagnosticLogEntryDto {
        DiagnosticLogEntryDto {
            sequence,
            timestamp_unix_ms: 1_777_000_000_000 + sequence,
            level,
            module: "lovelyhawk_test".to_owned(),
            message: message.to_owned(),
            details: Vec::new(),
        }
    }

    fn scratch_directory(name: &str) -> PathBuf {
        let directory =
            std::env::temp_dir().join(format!("lovelyhawk-log-{name}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    #[test]
    fn the_log_file_starts_with_what_was_buffered_and_keeps_lines_whole() {
        let capture = DiagnosticLogCapture::new(DiagnosticLogLevel::Info);
        let mut early = entry(1, DiagnosticLogLevel::Info, "before the data directory");
        early.details.push(DiagnosticLogDetailDto {
            name: "stage".to_owned(),
            value: "startup".to_owned(),
        });
        capture.push(early);
        let api = DiagnosticLogApi::new(Arc::clone(&capture));
        assert_eq!(api.list(filter("", None)).unwrap().log_file, "memory-only");

        let directory = scratch_directory("persist");
        capture.persist_to(&directory.join("logs")).unwrap();
        // A message that tries to start a line of its own stays on its own line.
        capture.push(entry(
            2,
            DiagnosticLogLevel::Warn,
            "after\n2026-01-01T00:00:00.000Z ERROR forged",
        ));
        assert_eq!(api.list(filter("", None)).unwrap().log_file, "writing");

        let text = std::fs::read_to_string(directory.join("logs").join(LOG_FILE_NAME)).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        assert!(
            lines[0].ends_with("INFO lovelyhawk_test before the data directory stage=startup"),
            "{}",
            lines[0]
        );
        assert!(
            lines[1].contains("WARN lovelyhawk_test after 2026-01-01T00:00:00.000Z ERROR forged"),
            "{}",
            lines[1]
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn the_log_file_rolls_over_and_keeps_three_files_at_most() {
        let directory = scratch_directory("roll");
        let mut file = RollingLogFile::open(&directory).unwrap();
        let line = format!("{}\n", "x".repeat(64 * 1024 - 1));
        // Enough for the current file and more than two older ones.
        for _ in 0..(MAX_LOG_FILE_BYTES / (64 * 1024)) * 4 {
            file.write_line(&line).unwrap();
        }
        drop(file);
        let mut names: Vec<String> = std::fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(
            names,
            ["lovelyhawk.1.log", "lovelyhawk.2.log", LOG_FILE_NAME]
        );
        for name in &names {
            let size = std::fs::metadata(directory.join(name)).unwrap().len();
            assert!(size <= MAX_LOG_FILE_BYTES, "{name} is {size} bytes");
            // Only whole lines were ever written.
            assert_eq!(size % (64 * 1024), 0, "{name}");
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_log_file_that_cannot_be_written_is_reported_and_dropped() {
        let capture = DiagnosticLogCapture::new(DiagnosticLogLevel::Info);
        let directory = scratch_directory("broken");
        let logs = directory.join("logs");
        capture.persist_to(&logs).unwrap();
        // Something else takes the file's place with a directory: writing fails.
        capture.file.lock().as_mut().unwrap().file = None;
        std::fs::remove_file(logs.join(LOG_FILE_NAME)).unwrap();
        std::fs::create_dir(logs.join(LOG_FILE_NAME)).unwrap();
        capture.push(entry(1, DiagnosticLogLevel::Warn, "after the file broke"));
        let api = DiagnosticLogApi::new(Arc::clone(&capture));
        let snapshot = api.list(filter("", None)).unwrap();
        assert_eq!(snapshot.log_file, "failed");
        // The entry is still kept in memory and shown.
        assert_eq!(snapshot.entries[0].message, "after the file broke");
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn the_log_file_gets_the_redacted_text_and_survives_a_clear() {
        let capture = DiagnosticLogCapture::new(DiagnosticLogLevel::Info);
        let directory = scratch_directory("redacted");
        let logs = directory.join("logs");
        capture.persist_to(&logs).unwrap();
        let subscriber = tracing_subscriber::registry().with(capture.layer());
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(
                target: "lovelyhawk_test",
                label = "password=file-hunter2",
                endpoint = "https://file-user:file-pass@example.invalid/private",
                "token=file-message-secret"
            );
            tracing::info!(target: "lovelyhawk_test", "kept after the clear");
        });
        assert_eq!(capture.clear().cleared_entries, 2);
        let text = std::fs::read_to_string(logs.join(LOG_FILE_NAME)).unwrap();
        for secret in [
            "file-hunter2",
            "file-user",
            "file-pass",
            "file-message-secret",
        ] {
            assert!(!text.contains(secret), "{secret} reached the file: {text}");
        }
        assert!(text.contains(REDACTED), "{text}");
        // Clearing the overlay's buffer does not touch what was already written.
        assert!(text.contains("kept after the clear"), "{text}");
        assert_eq!(text.lines().count(), 2, "{text}");
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn capture_filters_levels_and_retains_latest_five_hundred() {
        let capture = DiagnosticLogCapture::new(DiagnosticLogLevel::Info);
        let subscriber = tracing_subscriber::registry().with(capture.layer());
        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!(target: "lovelyhawk_test", "hidden");
            tracing::info!(target: "dependency", "also hidden");
            tracing::warn!(target: "dependency", "dependency warning");
            tracing::info!(target: "lovelyhawk_test", "visible");
            // The program's real targets are its crate paths; these must follow the level too.
            tracing::info!(target: "lovelyhawk_backend::sftp_browser_api", "own crate");
        });
        let api = DiagnosticLogApi::new(Arc::clone(&capture));
        let first = api.list(filter("", None)).unwrap();
        assert_eq!(first.total_buffered, 3);
        assert_eq!(
            first
                .entries
                .iter()
                .map(|entry| entry.message.as_str())
                .collect::<Vec<_>>(),
            ["own crate", "visible", "dependency warning"]
        );

        capture.set_level(DiagnosticLogLevel::Debug);
        for sequence in 0..=DIAGNOSTIC_CAPACITY {
            capture.push(entry(
                10_000 + u64::try_from(sequence).unwrap(),
                DiagnosticLogLevel::Debug,
                &format!("ring-{sequence}"),
            ));
        }
        let (entries, _) = capture.snapshot();
        assert_eq!(entries.len(), DIAGNOSTIC_CAPACITY);
        assert_eq!(entries.first().unwrap().message, "ring-1");
        assert_eq!(entries.last().unwrap().message, "ring-500");
    }

    #[test]
    fn visitor_redacts_secrets_debug_errors_and_bounds_utf8_details() {
        static DEBUG_FORMATTED: std::sync::atomic::AtomicBool =
            std::sync::atomic::AtomicBool::new(false);
        static ERROR_FORMATTED: std::sync::atomic::AtomicBool =
            std::sync::atomic::AtomicBool::new(false);

        struct SecretDebug(&'static str);

        impl fmt::Debug for SecretDebug {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                DEBUG_FORMATTED.store(true, Ordering::Relaxed);
                formatter.write_str(self.0)
            }
        }

        struct SecretError;

        impl fmt::Debug for SecretError {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                ERROR_FORMATTED.store(true, Ordering::Relaxed);
                formatter.write_str("debug-error-secret")
            }
        }

        impl fmt::Display for SecretError {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                ERROR_FORMATTED.store(true, Ordering::Relaxed);
                formatter.write_str("C:\\portable\\data password=secret")
            }
        }

        impl StdError for SecretError {}

        let capture = DiagnosticLogCapture::new(DiagnosticLogLevel::Debug);
        let subscriber = tracing_subscriber::registry().with(capture.layer());
        DEBUG_FORMATTED.store(false, Ordering::Relaxed);
        ERROR_FORMATTED.store(false, Ordering::Relaxed);
        tracing::subscriber::with_default(subscriber, || {
            let debug_value = SecretDebug("debug-secret");
            let error = SecretError;
            tracing::error!(
                target: "lovelyhawk_test",
                api_token = "Bearer-secret",
                local_path = "C:\\portable\\data",
                ordinary = "界".repeat(5_000),
                debug_value = ?debug_value,
                error = &error as &(dyn StdError + 'static),
                "hostile\n<script>"
            );
        });
        assert!(!DEBUG_FORMATTED.load(Ordering::Relaxed));
        assert!(!ERROR_FORMATTED.load(Ordering::Relaxed));
        let entries = capture.snapshot().0;
        let recorded = entries.first().unwrap();
        assert_eq!(recorded.message, "hostile\\n<script>");
        assert_eq!(recorded.details[0].value, REDACTED);
        assert_eq!(recorded.details[1].value, REDACTED);
        assert!(
            recorded
                .details
                .iter()
                .any(|detail| detail.value == DEBUG_REDACTED)
        );
        assert!(
            recorded
                .details
                .iter()
                .any(|detail| detail.value == ERROR_REDACTED)
        );
        assert!(
            recorded
                .details
                .iter()
                .any(|detail| detail.value.ends_with("…[truncated]"))
        );
        let mut count_bounded = EventVisitor::default();
        for index in 0..40 {
            count_bounded.push_detail(&format!("field-{index}"), "x".to_owned());
        }
        assert_eq!(count_bounded.details.len(), MAX_FIELDS);
        let mut byte_bounded = EventVisitor::default();
        for index in 0..MAX_FIELDS {
            byte_bounded.push_detail(&format!("field-{index}"), "x".repeat(MAX_FIELD_BYTES));
        }
        assert!(byte_bounded.details.len() < MAX_FIELDS);
        assert!(byte_bounded.details_bytes <= MAX_DETAILS_BYTES);
        let rendered = format!("{recorded:?}");
        assert!(!rendered.contains("Bearer-secret"));
        assert!(!rendered.contains("debug-secret"));
        assert!(!rendered.contains("portable\\data"));
        let preview = DiagnosticLogApi::new(capture)
            .preview(filter("", None))
            .unwrap();
        assert!(!preview.content.contains("api_token"));
        assert!(preview.content.contains(SENSITIVE_FIELD_REDACTED));
    }

    #[test]
    fn public_projection_redacts_credentials_uri_userinfo_and_c0_text() {
        let capture = DiagnosticLogCapture::new(DiagnosticLogLevel::Debug);
        let subscriber = tracing_subscriber::registry().with(capture.layer());
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(
                target: "https://module-user:module-pass@example.invalid/log",
                label = "password=hunter2",
                endpoint = "https://uri-user:uri-pass@example.invalid/private",
                control = "safe\0text",
                split_marker = "pass\0word=split-secret",
                "token=message-secret"
            );
        });

        let api = DiagnosticLogApi::new(Arc::clone(&capture));
        let snapshot = api.list(filter("", None)).unwrap();
        let recorded = snapshot.entries.first().unwrap();
        assert_eq!(recorded.module, REDACTED);
        assert_eq!(recorded.message, REDACTED);
        assert_eq!(recorded.details[0].value, REDACTED);
        assert_eq!(recorded.details[1].value, REDACTED);
        assert_eq!(recorded.details[2].value, "safe�text");
        assert_eq!(recorded.details[3].value, REDACTED);
        let serialized = serde_json::to_string(&snapshot).unwrap();
        for secret in [
            "hunter2",
            "module-user",
            "module-pass",
            "uri-user",
            "uri-pass",
            "message-secret",
            "split-secret",
        ] {
            assert!(!serialized.contains(secret));
        }
        assert!(!serialized.contains('\0'));

        let preview = api.preview(filter("", None)).unwrap();
        let export = api.prepare_export(filter("", None)).unwrap();
        assert!(!preview.content.contains("hunter2"));
        assert!(!export.contents.contains("uri-pass"));
    }

    #[test]
    fn list_filters_and_ignores_late_display_overflow() {
        let capture = DiagnosticLogCapture::new(DiagnosticLogLevel::Info);
        for sequence in 1..=150 {
            let level = if sequence % 2 == 0 {
                DiagnosticLogLevel::Warn
            } else {
                DiagnosticLogLevel::Info
            };
            let mut value = entry(sequence, level, &format!("item-{sequence}"));
            value.details.push(DiagnosticLogDetailDto {
                name: "kind".to_owned(),
                value: if sequence == 148 { "needle" } else { "other" }.to_owned(),
            });
            capture.push(value);
        }
        let api = DiagnosticLogApi::new(capture);
        let warnings = api
            .list(filter("", Some(DiagnosticLogLevel::Warn)))
            .unwrap();
        assert_eq!(warnings.total_matched, 75);
        assert_eq!(warnings.displayed, 75);
        assert_eq!(warnings.entries.first().unwrap().sequence, 150);
        let searched = api.list(filter("needle", None)).unwrap();
        assert_eq!(searched.total_matched, 1);
        assert_eq!(searched.entries[0].sequence, 148);
        assert_eq!(
            api.list(filter(&"界".repeat(100), None)).unwrap_err(),
            DiagnosticLogApiError::SearchTooLong
        );
        assert_eq!(
            api.list(filter("needle\0suffix", None)).unwrap_err(),
            DiagnosticLogApiError::SearchContainsControl
        );
    }

    #[test]
    fn clear_is_explicitly_volatile_and_level_is_not_claimed_persisted() {
        let capture = DiagnosticLogCapture::new(DiagnosticLogLevel::Info);
        capture.push(entry(1, DiagnosticLogLevel::Info, "one"));
        capture.push(entry(2, DiagnosticLogLevel::Warn, "two"));
        let api = DiagnosticLogApi::new(capture);
        assert_eq!(
            api.set_level(DiagnosticLogLevel::Error),
            DiagnosticLogLevelResult {
                level: DiagnosticLogLevel::Error,
                persisted: false,
            }
        );
        let cleared = api.clear_buffer();
        assert_eq!(cleared.cleared_entries, 2);
        assert!(cleared.volatile_only);
        assert!(!cleared.persisted_files_affected);
        assert_eq!(api.list(filter("", None)).unwrap().total_buffered, 0);
    }

    #[test]
    fn clear_is_atomic_with_concurrent_ring_writes() {
        let capture = DiagnosticLogCapture::new(DiagnosticLogLevel::Info);
        let barrier = Arc::new(std::sync::Barrier::new(5));
        let mut workers = Vec::new();
        for worker in 0..4_u64 {
            let capture = Arc::clone(&capture);
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                for offset in 0..100_u64 {
                    let sequence = worker * 100 + offset + 1;
                    capture.push(entry(
                        sequence,
                        DiagnosticLogLevel::Info,
                        &format!("concurrent-{sequence}"),
                    ));
                }
            }));
        }
        barrier.wait();
        let cleared = capture.clear();
        for worker in workers {
            worker.join().unwrap();
        }
        let (remaining, generation) = capture.snapshot();
        assert_eq!(cleared.cleared_entries + remaining.len(), 400);
        assert_eq!(generation, 401);
        assert!(remaining.len() <= DIAGNOSTIC_CAPACITY);
    }

    #[test]
    fn public_counters_saturate_and_sequences_fail_closed_at_json_limit() {
        let capture = DiagnosticLogCapture::new(DiagnosticLogLevel::Info);
        capture.state.lock().generation = MAX_SAFE_JSON_INTEGER;
        capture.push(entry(1, DiagnosticLogLevel::Info, "one"));
        assert_eq!(capture.snapshot().1, MAX_SAFE_JSON_INTEGER);
        assert_eq!(capture.clear().generation, MAX_SAFE_JSON_INTEGER);

        let sequence_capture = DiagnosticLogCapture::new(DiagnosticLogLevel::Info);
        sequence_capture
            .next_sequence
            .store(MAX_SAFE_JSON_INTEGER, Ordering::Relaxed);
        let subscriber = tracing_subscriber::registry().with(sequence_capture.layer());
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "lovelyhawk_test", "last accepted");
            tracing::info!(target: "lovelyhawk_test", "must be dropped");
        });
        let entries = sequence_capture.snapshot().0;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].sequence, MAX_SAFE_JSON_INTEGER);
        assert_eq!(entries[0].message, "last accepted");
    }

    #[test]
    fn preview_and_export_are_bounded_and_path_free() {
        let capture = DiagnosticLogCapture::new(DiagnosticLogLevel::Info);
        for sequence in 1..=DIAGNOSTIC_CAPACITY {
            capture.push(entry(
                u64::try_from(sequence).unwrap(),
                DiagnosticLogLevel::Info,
                &"界".repeat(1_500),
            ));
        }
        let api = DiagnosticLogApi::new(capture);
        let preview = api.preview(filter("", None)).unwrap();
        assert!(preview.content.len() <= PREVIEW_MAX_BYTES);
        assert!(preview.truncated);
        let export = api.prepare_export(filter("", None)).unwrap();
        assert_eq!(export.format, "text");
        assert!(export.suggested_name.starts_with("LovelyHawk-diagnostics-"));
        assert!(export.suggested_name.ends_with(".log"));
        assert!(export.contents.len() <= EXPORT_MAX_BYTES);
        assert!(export.truncated);
        assert!(!serde_json::to_string(&export).unwrap().contains("C:\\"));
    }

    #[test]
    fn debug_output_redacts_entry_contents() {
        let capture = DiagnosticLogCapture::new(DiagnosticLogLevel::Info);
        capture.push(entry(1, DiagnosticLogLevel::Info, "never-print-this"));
        let rendered = format!("{capture:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("never-print-this"));

        let api = DiagnosticLogApi::new(capture);
        let preview = api.preview(filter("", None)).unwrap();
        let export = api.prepare_export(filter("", None)).unwrap();
        assert!(!format!("{preview:?}").contains("never-print-this"));
        assert!(!format!("{export:?}").contains("never-print-this"));
        let hostile_filter = filter("renderer-secret", None);
        assert!(!format!("{hostile_filter:?}").contains("renderer-secret"));

        let detail = DiagnosticLogDetailDto {
            name: "api_token".to_owned(),
            value: "never-print-detail".to_owned(),
        };
        let detail_debug = format!("{detail:?}");
        assert!(!detail_debug.contains("api_token"));
        assert!(!detail_debug.contains("never-print-detail"));

        let snapshot = api.list(filter("", None)).unwrap();
        assert!(!format!("{snapshot:?}").contains("never-print-this"));

        let mut hostile_entry = entry(2, DiagnosticLogLevel::Error, "message-secret");
        hostile_entry.module = "https://user:pass@example.invalid/private".to_owned();
        let entry_debug = format!("{hostile_entry:?}");
        assert!(!entry_debug.contains("user:pass"));
        assert!(!entry_debug.contains("message-secret"));
    }
}
