use std::{
    collections::{BTreeMap, VecDeque},
    error::Error as StdError,
    fmt,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
};

use anyhow::{Context as _, Result};
use chrono::{SecondsFormat, Utc};
use lovelyres_core::settings::ApplicationLogLevel;
use parking_lot::Mutex;
use tracing::{Event, Level, Metadata, Subscriber, field::Visit};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    Layer,
    layer::{Context as LayerContext, Filter, SubscriberExt as _},
    util::SubscriberInitExt as _,
};

const DIAGNOSTIC_CAPACITY: usize = 500;
const MAX_MESSAGE_BYTES: usize = 4 * 1024;
const MAX_FIELD_BYTES: usize = 4 * 1024;
const MAX_DETAILS_BYTES: usize = 16 * 1024;
const MAX_FIELDS: usize = 32;
const PREVIEW_MAX_BYTES: usize = 128 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiagnosticLogEntry {
    pub timestamp: String,
    pub level: ApplicationLogLevel,
    pub module: String,
    pub message: String,
    pub details: BTreeMap<String, String>,
}

impl DiagnosticLogEntry {
    fn as_text(&self) -> String {
        let details = if self.details.is_empty() {
            String::new()
        } else {
            format!(
                " | {}",
                serde_json::to_string(&self.details)
                    .unwrap_or_else(|_| "{\"details\":\"unavailable\"}".to_owned())
            )
        };
        format!(
            "[{}] [{}] [{}] {}{}",
            self.timestamp,
            self.level.as_str().to_ascii_uppercase(),
            self.module,
            self.message,
            details
        )
    }
}

#[derive(Debug)]
struct LogBuffer {
    entries: Mutex<VecDeque<DiagnosticLogEntry>>,
    capacity: usize,
}

impl LogBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            entries: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
        }
    }

    fn push(&self, entry: DiagnosticLogEntry) {
        let mut entries = self.entries.lock();
        if entries.len() == self.capacity {
            entries.pop_front();
        }
        entries.push_back(entry);
    }

    fn entries(&self) -> Vec<DiagnosticLogEntry> {
        self.entries.lock().iter().cloned().collect()
    }

    fn clear(&self) {
        self.entries.lock().clear();
    }
}

#[derive(Clone, Debug)]
struct DynamicLevelFilter {
    minimum: Arc<AtomicU8>,
}

impl DynamicLevelFilter {
    fn new(level: ApplicationLogLevel) -> Self {
        Self {
            minimum: Arc::new(AtomicU8::new(application_level_rank(level))),
        }
    }

    fn set(&self, level: ApplicationLogLevel) {
        self.minimum
            .store(application_level_rank(level), Ordering::Release);
        tracing::callsite::rebuild_interest_cache();
    }

    fn level(&self) -> ApplicationLogLevel {
        application_level_from_rank(self.minimum.load(Ordering::Acquire))
    }

    fn allows(&self, metadata: &Metadata<'_>) -> bool {
        self.allows_parts(metadata.level(), metadata.target())
    }

    fn allows_parts(&self, level: &Level, target: &str) -> bool {
        let configured = self.minimum.load(Ordering::Acquire);
        let minimum = if target.starts_with("lovelyres") {
            configured
        } else {
            configured.max(application_level_rank(ApplicationLogLevel::Warn))
        };
        tracing_level_rank(level) >= minimum
    }
}

impl<S> Filter<S> for DynamicLevelFilter
where
    S: Subscriber,
{
    fn enabled(&self, metadata: &Metadata<'_>, _: &LayerContext<'_, S>) -> bool {
        self.allows(metadata)
    }
}

#[derive(Clone, Debug)]
struct CaptureLayer {
    buffer: Arc<LogBuffer>,
}

impl<S> Layer<S> for CaptureLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _: LayerContext<'_, S>) {
        let mut visitor = EventVisitor::default();
        event.record(&mut visitor);
        let metadata = event.metadata();
        self.buffer.push(DiagnosticLogEntry {
            timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            level: application_level(metadata.level()),
            module: truncate_utf8(metadata.target(), 256),
            message: visitor
                .message
                .unwrap_or_else(|| metadata.name().to_owned()),
            details: visitor.fields,
        });
    }
}

#[derive(Default)]
struct EventVisitor {
    message: Option<String>,
    fields: BTreeMap<String, String>,
    details_bytes: usize,
}

impl EventVisitor {
    fn record_value(&mut self, field: &tracing::field::Field, value: String) {
        let name = field.name();
        let value = if is_secret_field(name) {
            "[REDACTED]".to_owned()
        } else {
            truncate_utf8(&value, MAX_FIELD_BYTES)
        };
        if name == "message" {
            self.message = Some(truncate_utf8(&value, MAX_MESSAGE_BYTES));
        } else if self.fields.len() < MAX_FIELDS
            && self.details_bytes + name.len() < MAX_DETAILS_BYTES
        {
            let remaining = MAX_DETAILS_BYTES - self.details_bytes - name.len();
            let value = truncate_utf8(&value, remaining.min(MAX_FIELD_BYTES));
            self.details_bytes += name.len() + value.len();
            self.fields.insert(name.to_owned(), value);
        }
    }
}

impl Visit for EventVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        self.record_value(field, format!("{value:?}"));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.record_value(field, value.to_owned());
    }

    fn record_error(&mut self, field: &tracing::field::Field, value: &(dyn StdError + 'static)) {
        let mut rendered = value.to_string();
        let mut source = value.source();
        for _ in 0..3 {
            let Some(cause) = source else { break };
            rendered.push_str(" <- ");
            rendered.push_str(&cause.to_string());
            source = cause.source();
        }
        self.record_value(field, rendered);
    }
}

/// Keeps the non-blocking writer and native diagnostic buffer alive with the app.
#[derive(Debug)]
pub struct LogGuard {
    _worker: WorkerGuard,
    buffer: Arc<LogBuffer>,
    filter: DynamicLevelFilter,
}

impl LogGuard {
    pub fn level(&self) -> ApplicationLogLevel {
        self.filter.level()
    }

    pub fn set_level(&self, level: ApplicationLogLevel) {
        self.filter.set(level);
    }

    pub fn entries(&self) -> Vec<DiagnosticLogEntry> {
        self.buffer.entries()
    }

    pub fn clear(&self) {
        self.buffer.clear();
    }

    pub fn export_as_text(&self) -> String {
        self.entries()
            .iter()
            .map(DiagnosticLogEntry::as_text)
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn preview_as_text(&self, maximum_entries: usize) -> String {
        let entries = self.entries();
        let start = entries.len().saturating_sub(maximum_entries);
        let mut total = 0;
        let mut lines = Vec::new();
        for entry in entries[start..].iter().rev() {
            let line = entry.as_text();
            if total + line.len() + 1 > PREVIEW_MAX_BYTES {
                break;
            }
            total += line.len() + 1;
            lines.push(line);
        }
        lines.reverse();
        lines.join("\n")
    }
}

pub fn initialize(logs_dir: &Path, level: ApplicationLogLevel) -> Result<Arc<LogGuard>> {
    let appender = tracing_appender::rolling::daily(logs_dir, "lovelyres.log");
    let (writer, worker) = tracing_appender::non_blocking(appender);
    let buffer = Arc::new(LogBuffer::new(DIAGNOSTIC_CAPACITY));
    let filter = DynamicLevelFilter::new(level);

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_target(true)
                .with_writer(writer)
                .with_filter(filter.clone()),
        )
        .with(
            CaptureLayer {
                buffer: buffer.clone(),
            }
            .with_filter(filter.clone()),
        )
        .try_init()
        .context("failed to initialize portable file logging")?;
    Ok(Arc::new(LogGuard {
        _worker: worker,
        buffer,
        filter,
    }))
}

const fn application_level_rank(level: ApplicationLogLevel) -> u8 {
    match level {
        ApplicationLogLevel::Debug => 1,
        ApplicationLogLevel::Info => 2,
        ApplicationLogLevel::Warn => 3,
        ApplicationLogLevel::Error => 4,
    }
}

const fn application_level_from_rank(rank: u8) -> ApplicationLogLevel {
    match rank {
        0 | 1 => ApplicationLogLevel::Debug,
        2 => ApplicationLogLevel::Info,
        3 => ApplicationLogLevel::Warn,
        _ => ApplicationLogLevel::Error,
    }
}

fn application_level(level: &Level) -> ApplicationLogLevel {
    match *level {
        Level::TRACE | Level::DEBUG => ApplicationLogLevel::Debug,
        Level::INFO => ApplicationLogLevel::Info,
        Level::WARN => ApplicationLogLevel::Warn,
        Level::ERROR => ApplicationLogLevel::Error,
    }
}

fn tracing_level_rank(level: &Level) -> u8 {
    match *level {
        Level::TRACE => 0,
        Level::DEBUG => 1,
        Level::INFO => 2,
        Level::WARN => 3,
        Level::ERROR => 4,
    }
}

fn is_secret_field(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "password",
        "passwd",
        "secret",
        "token",
        "authorization",
        "api_key",
        "private_key",
        "credential",
    ]
    .iter()
    .any(|needle| name.contains(needle))
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

    struct TestCallsite;

    static TEST_CALLSITE: TestCallsite = TestCallsite;

    impl tracing::callsite::Callsite for TestCallsite {
        fn set_interest(&self, _: tracing::subscriber::Interest) {}

        fn metadata(&self) -> &Metadata<'_> {
            unreachable!("the test field set only needs a stable callsite identifier")
        }
    }

    fn entry(level: ApplicationLogLevel, message: &str) -> DiagnosticLogEntry {
        DiagnosticLogEntry {
            timestamp: "2026-08-12T12:34:56.789Z".to_owned(),
            level,
            module: "lovelyres_test".to_owned(),
            message: message.to_owned(),
            details: BTreeMap::new(),
        }
    }

    #[test]
    fn minimum_level_filters_native_and_dependency_events() {
        let filter = DynamicLevelFilter::new(ApplicationLogLevel::Info);
        assert!(!filter.allows_parts(&Level::DEBUG, "lovelyres_core"));
        assert!(filter.allows_parts(&Level::INFO, "lovelyres_core"));
        assert!(filter.allows_parts(&Level::WARN, "dependency"));
        assert!(!filter.allows_parts(&Level::INFO, "dependency"));
    }

    #[test]
    fn debug_level_captures_debug_events() {
        let filter = DynamicLevelFilter::new(ApplicationLogLevel::Info);
        assert!(!filter.allows_parts(&Level::DEBUG, "lovelyres_gpui"));
        filter.set(ApplicationLogLevel::Debug);
        assert!(filter.allows_parts(&Level::DEBUG, "lovelyres_gpui"));
    }

    #[test]
    fn ring_buffer_retains_only_the_latest_five_hundred_entries() {
        let buffer = LogBuffer::new(DIAGNOSTIC_CAPACITY);
        for index in 0..=DIAGNOSTIC_CAPACITY {
            buffer.push(entry(ApplicationLogLevel::Info, &format!("entry-{index}")));
        }
        let entries = buffer.entries();
        assert_eq!(entries.len(), DIAGNOSTIC_CAPACITY);
        assert_eq!(entries.first().unwrap().message, "entry-1");
        assert_eq!(entries.last().unwrap().message, "entry-500");
        buffer.clear();
        assert!(buffer.entries().is_empty());
    }

    #[test]
    fn capture_layer_records_module_message_and_rfc3339_timestamp() {
        let buffer = Arc::new(LogBuffer::new(DIAGNOSTIC_CAPACITY));
        let subscriber = tracing_subscriber::registry().with(
            CaptureLayer {
                buffer: buffer.clone(),
            }
            .with_filter(DynamicLevelFilter::new(ApplicationLogLevel::Info)),
        );
        tracing::subscriber::with_default(subscriber, || {
            tracing::error!(target: "lovelyres_test", "连接失败");
        });

        let entries = buffer.entries();
        let value = entries.first().unwrap();
        assert_eq!(value.module, "lovelyres_test");
        assert_eq!(value.message, "连接失败");
        assert!(chrono::DateTime::parse_from_rfc3339(&value.timestamp).is_ok());
    }

    #[test]
    fn entry_without_details_omits_separator() {
        let text = entry(ApplicationLogLevel::Info, "无附加信息").as_text();
        assert_eq!(
            text,
            "[2026-08-12T12:34:56.789Z] [INFO] [lovelyres_test] 无附加信息"
        );
        assert!(!text.contains(" | "));
    }

    #[test]
    fn ordinary_fields_serialize_as_json() {
        let mut value = entry(ApplicationLogLevel::Info, "连接");
        value
            .details
            .insert("host".to_owned(), "10.0.0.1".to_owned());
        value.details.insert("port".to_owned(), "22".to_owned());
        let text = value.as_text();
        assert!(text.contains("\"host\":\"10.0.0.1\""));
        assert!(text.contains("\"port\":\"22\""));
    }

    #[derive(Debug)]
    struct NamedError(&'static str);

    impl fmt::Display for NamedError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(self.0)
        }
    }

    impl StdError for NamedError {}

    #[test]
    fn error_details_export_readably() {
        let fields = tracing::field::FieldSet::new(
            &["error"],
            tracing::callsite::Identifier(&TEST_CALLSITE),
        );
        let mut visitor = EventVisitor::default();
        visitor.record_error(&fields.field("error").unwrap(), &NamedError("Error: boom"));
        let mut value = entry(ApplicationLogLevel::Error, "加载失败");
        value.details = visitor.fields;
        let text = value.as_text();
        assert!(text.contains("Error: boom"));
        assert!(!text.contains("| {}"));
    }

    #[test]
    fn nested_error_and_data_fields_export_readably() {
        let fields = tracing::field::FieldSet::new(
            &["error", "data"],
            tracing::callsite::Identifier(&TEST_CALLSITE),
        );
        let mut visitor = EventVisitor::default();
        visitor.record_error(
            &fields.field("error").unwrap(),
            &NamedError("TypeError: bad json"),
        );
        visitor.record_str(&fields.field("data").unwrap(), "x");
        let mut value = entry(ApplicationLogLevel::Warn, "解析失败");
        value.details = visitor.fields;
        let text = value.as_text();
        assert!(text.contains("TypeError: bad json"));
        assert!(text.contains("\"data\":\"x\""));
    }

    #[test]
    fn visitor_bounds_hostile_values_and_redacts_secrets() {
        let fields = tracing::field::FieldSet::new(
            &["api_token", "payload"],
            tracing::callsite::Identifier(&TEST_CALLSITE),
        );
        let mut visitor = EventVisitor::default();
        visitor.record_str(&fields.field("api_token").unwrap(), "Bearer-secret");
        visitor.record_str(&fields.field("payload").unwrap(), &"界".repeat(5_000));

        assert_eq!(visitor.fields["api_token"], "[REDACTED]");
        assert!(!format!("{:?}", visitor.fields).contains("Bearer-secret"));
        assert!(visitor.fields["payload"].ends_with("…[truncated]"));
        assert!(visitor.fields["payload"].is_char_boundary(visitor.fields["payload"].len()));
    }

    #[test]
    fn owned_field_map_replaces_web_circular_reference_fallback() {
        let mut details = BTreeMap::new();
        details.insert("name".to_owned(), "a".to_owned());
        details.insert("self".to_owned(), "[unsupported reference]".to_owned());
        let mut value = entry(ApplicationLogLevel::Warn, "循环");
        value.details = details;
        assert!(value.as_text().contains("unsupported reference"));
    }
}
