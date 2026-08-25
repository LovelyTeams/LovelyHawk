//! Capability-bound Electron boundary for disposal report snapshots.

use std::{
    collections::HashMap,
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use lovelyres_core::{
    BackendServices, CoreError,
    report::{DisposalReport, DisposalReportSummary, ReportFormat},
    ssh::BoundSshSession,
    target::TargetGuard,
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ssh_api::SshApi;

const MAX_REPORTS: usize = 8;
const MAX_HANDLE_BYTES: usize = 128;
const MAX_FORMAT_BYTES: usize = 512 * 1024;
const MAX_SUMMARY_BYTES: usize = 16 * 1024;
const MAX_TOTAL_REPORT_BYTES: usize = 4 * 1024 * 1024;
const REPORT_TTL: Duration = Duration::from_secs(5 * 60);

pub(crate) struct DisposalReportApi {
    services: BackendServices,
    ssh: Arc<SshApi>,
    reports: Mutex<ReportRegistry>,
}

impl fmt::Debug for DisposalReportApi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DisposalReportApi")
            .field("report_count", &self.reports.lock().reports.len())
            .finish()
    }
}

impl DisposalReportApi {
    pub(crate) fn new(services: BackendServices, ssh: Arc<SshApi>) -> Self {
        Self {
            services,
            ssh,
            reports: Mutex::new(ReportRegistry::default()),
        }
    }

    pub(crate) fn generate(
        &self,
        binding_handle: &str,
    ) -> Result<DisposalReportSnapshotDto, DisposalReportApiError> {
        let session = self.binding_session(binding_handle)?;
        // The label is derived inside the sidecar. Renderer labels are never trusted report input.
        let label = format!("SSH connection {}", session.connection_id());
        // First phase deliberately excludes detection until a trusted sidecar snapshot exists.
        let report = self
            .services
            .report()
            .generate(session.target(), label, None)?;
        self.ensure_binding_unchanged(binding_handle, &session)?;
        if report.snapshot.target != *session.target() || report.snapshot.detection.is_some() {
            return Err(DisposalReportApiError::ReportUnavailable);
        }
        let summary_text = summary_text(&report.summary);
        if summary_text.len() > MAX_SUMMARY_BYTES {
            return Err(DisposalReportApiError::ReportTooLarge);
        }
        let handle = self.reports.lock().insert(
            binding_handle,
            session.target(),
            report,
            summary_text,
            Instant::now(),
        )?;
        let stored =
            self.reports
                .lock()
                .get(binding_handle, session.target(), &handle, Instant::now())?;
        Ok(DisposalReportSnapshotDto::from_stored(handle, &stored))
    }

    pub(crate) fn content(
        &self,
        binding_handle: &str,
        report_handle: &str,
        format: DisposalReportPreviewFormat,
    ) -> Result<DisposalReportContentDto, DisposalReportApiError> {
        validate_handle(report_handle)?;
        let session = self.binding_session(binding_handle)?;
        let stored = self.reports.lock().get(
            binding_handle,
            session.target(),
            report_handle,
            Instant::now(),
        )?;
        self.ensure_binding_unchanged(binding_handle, &session)?;
        let content = format.content(&stored).to_owned();
        Ok(DisposalReportContentDto { format, content })
    }

    /// Internal-only payload for a main-process native save boundary.
    pub(crate) fn export_for_main(
        &self,
        binding_handle: &str,
        report_handle: &str,
        format: ReportFormat,
    ) -> Result<InternalDisposalReportExport, DisposalReportApiError> {
        validate_handle(report_handle)?;
        let session = self.binding_session(binding_handle)?;
        let stored = self.reports.lock().get(
            binding_handle,
            session.target(),
            report_handle,
            Instant::now(),
        )?;
        self.ensure_binding_unchanged(binding_handle, &session)?;
        let (format_key, extension, media_type, contents) = match format {
            ReportFormat::Markdown => (
                "markdown",
                "md",
                "text/markdown; charset=utf-8",
                stored.report.markdown.clone(),
            ),
            ReportFormat::Html => (
                "html",
                "html",
                "text/html; charset=utf-8",
                stored.report.html.clone(),
            ),
        };
        Ok(InternalDisposalReportExport {
            format: format_key,
            suggested_name: format!(
                "LovelyRes-disposal-{}.{}",
                stored.report.snapshot.generated_at.format("%Y%m%d-%H%M%S"),
                extension
            ),
            media_type,
            operation_count: stored.report.summary.total,
            contents,
        })
    }

    fn binding_session(
        &self,
        binding_handle: &str,
    ) -> Result<BoundSshSession, DisposalReportApiError> {
        validate_handle(binding_handle)?;
        self.ssh
            .binding_session_clone(binding_handle)
            .map_err(|_| DisposalReportApiError::BindingUnavailable)
    }

    fn ensure_binding_unchanged(
        &self,
        binding_handle: &str,
        expected: &BoundSshSession,
    ) -> Result<(), DisposalReportApiError> {
        let current = self.binding_session(binding_handle)?;
        if &current != expected {
            return Err(DisposalReportApiError::BindingUnavailable);
        }
        Ok(())
    }
}

pub(crate) enum DisposalReportApiError {
    Core(CoreError),
    InvalidHandle,
    BindingUnavailable,
    ReportUnavailable,
    ReportCapacity,
    ReportTooLarge,
}

impl fmt::Debug for DisposalReportApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core(_) => "Core([REDACTED])",
            Self::InvalidHandle => "InvalidHandle",
            Self::BindingUnavailable => "BindingUnavailable",
            Self::ReportUnavailable => "ReportUnavailable",
            Self::ReportCapacity => "ReportCapacity",
            Self::ReportTooLarge => "ReportTooLarge",
        })
    }
}

impl fmt::Display for DisposalReportApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core(_) => "the disposal report operation failed",
            Self::InvalidHandle => "the opaque report handle is invalid",
            Self::BindingUnavailable => "the SSH binding is unavailable or stale",
            Self::ReportUnavailable => "the disposal report is missing, expired, or stale",
            Self::ReportCapacity => "the disposal report registry is full",
            Self::ReportTooLarge => "the disposal report exceeds the local content budget",
        })
    }
}

impl std::error::Error for DisposalReportApiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Core(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CoreError> for DisposalReportApiError {
    fn from(error: CoreError) -> Self {
        Self::Core(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum DisposalReportPreviewFormat {
    Summary,
    Markdown,
    Html,
}

impl DisposalReportPreviewFormat {
    fn content(self, stored: &StoredReport) -> &str {
        match self {
            Self::Summary => &stored.summary_text,
            Self::Markdown => &stored.report.markdown,
            Self::Html => &stored.report.html,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DisposalReportSnapshotDto {
    handle: String,
    generated_at: String,
    snapshot_sha256: String,
    detection_included: bool,
    empty: bool,
    summary: DisposalReportSummaryDto,
}

impl fmt::Debug for DisposalReportSnapshotDto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DisposalReportSnapshotDto")
            .field("operation_count", &self.summary.total)
            .field("detection_included", &self.detection_included)
            .finish()
    }
}

impl DisposalReportSnapshotDto {
    fn from_stored(handle: String, stored: &StoredReport) -> Self {
        Self {
            handle,
            generated_at: stored.report.snapshot.generated_at.to_rfc3339(),
            snapshot_sha256: stored.report.snapshot_sha256.clone(),
            detection_included: false,
            empty: stored.report.summary.total == 0,
            summary: DisposalReportSummaryDto::from(&stored.report.summary),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DisposalReportSummaryDto {
    total: usize,
    succeeded: usize,
    failed: usize,
    restored: usize,
    uncertain: usize,
    recoverable: usize,
    by_source: Vec<DisposalReportSourceCountDto>,
}

impl From<&DisposalReportSummary> for DisposalReportSummaryDto {
    fn from(summary: &DisposalReportSummary) -> Self {
        Self {
            total: summary.total,
            succeeded: summary.succeeded,
            failed: summary.failed,
            restored: summary.restored,
            uncertain: summary.uncertain,
            recoverable: summary.recoverable,
            by_source: summary
                .by_source
                .iter()
                .map(|(source, count)| DisposalReportSourceCountDto {
                    source: source.clone(),
                    count: *count,
                })
                .collect(),
        }
    }
}

#[derive(Debug, Serialize)]
struct DisposalReportSourceCountDto {
    source: String,
    count: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DisposalReportContentDto {
    format: DisposalReportPreviewFormat,
    content: String,
}

impl fmt::Debug for DisposalReportContentDto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DisposalReportContentDto")
            .field("format", &self.format)
            .field("byte_count", &self.content.len())
            .finish()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InternalDisposalReportExport {
    format: &'static str,
    suggested_name: String,
    media_type: &'static str,
    operation_count: usize,
    contents: String,
}

impl fmt::Debug for InternalDisposalReportExport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InternalDisposalReportExport")
            .field("format", &self.format)
            .field("operation_count", &self.operation_count)
            .field("byte_count", &self.contents.len())
            .finish()
    }
}

struct StoredReport {
    binding_handle: String,
    target: TargetGuard,
    created_at: Instant,
    byte_count: usize,
    summary_text: String,
    report: Arc<DisposalReport>,
}

#[derive(Default)]
struct ReportRegistry {
    reports: HashMap<String, StoredReport>,
    total_bytes: usize,
}

impl fmt::Debug for ReportRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReportRegistry")
            .field("report_count", &self.reports.len())
            .field("total_bytes", &self.total_bytes)
            .finish()
    }
}

impl ReportRegistry {
    fn insert(
        &mut self,
        binding_handle: &str,
        target: &TargetGuard,
        report: DisposalReport,
        summary_text: String,
        now: Instant,
    ) -> Result<String, DisposalReportApiError> {
        self.prune(now);
        let markdown_bytes = report.markdown.len();
        let html_bytes = report.html.len();
        let summary_bytes = summary_text.len();
        if markdown_bytes > MAX_FORMAT_BYTES
            || html_bytes > MAX_FORMAT_BYTES
            || summary_bytes > MAX_SUMMARY_BYTES
        {
            return Err(DisposalReportApiError::ReportTooLarge);
        }
        let byte_count = markdown_bytes
            .saturating_add(html_bytes)
            .saturating_add(summary_bytes);
        if self.reports.len() >= MAX_REPORTS
            || self.total_bytes.saturating_add(byte_count) > MAX_TOTAL_REPORT_BYTES
        {
            return Err(DisposalReportApiError::ReportCapacity);
        }
        for _ in 0..8 {
            let handle = Uuid::new_v4().to_string();
            if self.reports.contains_key(&handle) {
                continue;
            }
            self.reports.insert(
                handle.clone(),
                StoredReport {
                    binding_handle: binding_handle.to_owned(),
                    target: target.clone(),
                    created_at: now,
                    byte_count,
                    summary_text,
                    report: Arc::new(report),
                },
            );
            self.total_bytes = self.total_bytes.saturating_add(byte_count);
            return Ok(handle);
        }
        Err(DisposalReportApiError::ReportCapacity)
    }

    fn get(
        &mut self,
        binding_handle: &str,
        target: &TargetGuard,
        handle: &str,
        now: Instant,
    ) -> Result<Arc<StoredReport>, DisposalReportApiError> {
        self.prune(now);
        let stored = self
            .reports
            .get(handle)
            .filter(|stored| stored.binding_handle == binding_handle && &stored.target == target)
            .ok_or(DisposalReportApiError::ReportUnavailable)?;
        Ok(Arc::new(StoredReport {
            binding_handle: stored.binding_handle.clone(),
            target: stored.target.clone(),
            created_at: stored.created_at,
            byte_count: stored.byte_count,
            summary_text: stored.summary_text.clone(),
            report: Arc::clone(&stored.report),
        }))
    }

    fn prune(&mut self, now: Instant) {
        self.reports.retain(|_, stored| {
            let keep = now.duration_since(stored.created_at) < REPORT_TTL;
            if !keep {
                self.total_bytes = self.total_bytes.saturating_sub(stored.byte_count);
            }
            keep
        });
    }
}

fn summary_text(summary: &DisposalReportSummary) -> String {
    let mut lines = vec![
        "LovelyRes 处置交付报告摘要".to_owned(),
        format!("审计操作：{}", summary.total),
        format!("成功：{}", summary.succeeded),
        format!("失败：{}", summary.failed),
        format!("已恢复：{}", summary.restored),
        format!("待核验：{}", summary.uncertain),
        format!("可恢复：{}", summary.recoverable),
        "检测：第一阶段未附带可信 detection snapshot".to_owned(),
    ];
    for (source, count) in &summary.by_source {
        lines.push(format!("来源 {source}：{count}"));
    }
    lines.join("\n")
}

fn validate_handle(handle: &str) -> Result<(), DisposalReportApiError> {
    if handle.is_empty()
        || handle.len() > MAX_HANDLE_BYTES
        || !handle
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(DisposalReportApiError::InvalidHandle);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use lovelyres_core::{PortableStore, target::TargetIdentity};

    use super::*;

    fn services() -> (PathBuf, BackendServices, TargetGuard) {
        let root =
            std::env::temp_dir().join(format!("lovelyres-disposal-report-api-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let store = PortableStore::prepare(root.clone()).unwrap();
        let services = BackendServices::new(store).unwrap();
        let target = services
            .target()
            .activate(TargetIdentity::new("server-1").unwrap())
            .unwrap();
        (root, services, target)
    }

    fn report(services: &BackendServices, target: &TargetGuard, marker: &str) -> DisposalReport {
        let mut report = services
            .report()
            .generate(target, "sidecar-derived label", None)
            .unwrap();
        report.markdown.push_str(marker);
        report.html.push_str(marker);
        report
    }

    #[test]
    fn registry_is_opaque_binding_target_ttl_count_and_byte_bounded() {
        let (root, services, target) = services();
        let now = Instant::now();
        let mut registry = ReportRegistry::default();
        let first_report = report(&services, &target, "plain");
        let first_summary = summary_text(&first_report.summary);
        let handle = registry
            .insert("binding-one", &target, first_report, first_summary, now)
            .unwrap();
        assert!(!handle.contains("binding-one"));
        assert!(!handle.contains("server-1"));
        assert!(registry.get("binding-one", &target, &handle, now).is_ok());
        assert!(registry.get("binding-two", &target, &handle, now).is_err());
        assert!(
            registry
                .get(
                    "binding-one",
                    &TargetGuard {
                        identity: target.identity.clone(),
                        generation: target.generation + 1,
                    },
                    &handle,
                    now,
                )
                .is_err()
        );
        assert!(
            registry
                .get("binding-one", &target, &handle, now + REPORT_TTL)
                .is_err()
        );

        let mut capped = ReportRegistry::default();
        for index in 0..MAX_REPORTS {
            let value = report(&services, &target, &format!("plain-{index}"));
            let summary = summary_text(&value.summary);
            capped
                .insert("binding", &target, value, summary, now)
                .unwrap();
        }
        let overflow = report(&services, &target, "overflow");
        let overflow_summary = summary_text(&overflow.summary);
        assert!(matches!(
            capped.insert("binding", &target, overflow, overflow_summary, now),
            Err(DisposalReportApiError::ReportCapacity)
        ));

        let mut byte_capped = ReportRegistry::default();
        for _ in 0..6 {
            let mut value = report(&services, &target, "bytes");
            value.markdown = "m".repeat(300 * 1024);
            value.html = "h".repeat(300 * 1024);
            let summary = summary_text(&value.summary);
            byte_capped
                .insert("binding", &target, value, summary, now)
                .unwrap();
        }
        let mut byte_overflow = report(&services, &target, "bytes-overflow");
        byte_overflow.markdown = "m".repeat(300 * 1024);
        byte_overflow.html = "h".repeat(300 * 1024);
        let byte_overflow_summary = summary_text(&byte_overflow.summary);
        assert!(matches!(
            byte_capped.insert(
                "binding",
                &target,
                byte_overflow,
                byte_overflow_summary,
                now
            ),
            Err(DisposalReportApiError::ReportCapacity)
        ));

        let mut oversized = report(&services, &target, "small");
        oversized.markdown = "x".repeat(MAX_FORMAT_BYTES + 1);
        assert!(matches!(
            ReportRegistry::default().insert(
                "binding",
                &target,
                oversized,
                "summary".to_owned(),
                now
            ),
            Err(DisposalReportApiError::ReportTooLarge)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn report_dto_exposes_no_target_operations_or_detection_and_content_is_plain() {
        let hostile = "</pre><script>steal()</script>";
        let (root, services, target) = services();
        let value = report(&services, &target, hostile);
        let summary = summary_text(&value.summary);
        let now = Instant::now();
        let mut registry = ReportRegistry::default();
        let handle = registry
            .insert("binding", &target, value, summary, now)
            .unwrap();
        let stored = registry.get("binding", &target, &handle, now).unwrap();
        let dto = DisposalReportSnapshotDto::from_stored(handle.clone(), &stored);
        let encoded = serde_json::to_string(&dto).unwrap();
        assert!(encoded.contains("\"detectionIncluded\":false"));
        assert!(!encoded.contains("server-1"));
        assert!(!encoded.contains("operations"));
        assert!(!encoded.contains("detection\""));
        assert!(!format!("{dto:?}").contains(&handle));
        let markdown = DisposalReportContentDto {
            format: DisposalReportPreviewFormat::Markdown,
            content: stored.report.markdown.clone(),
        };
        assert!(markdown.content.contains(hostile));
        assert!(!format!("{markdown:?}").contains(hostile));
        assert!(!format!("{registry:?}").contains(hostile));
        assert!(!format!("{registry:?}").contains(&handle));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn internal_exports_are_typed_bounded_and_debug_redacted() {
        let (root, services, target) = services();
        let value = report(&services, &target, "do-not-log-body");
        let payload = InternalDisposalReportExport {
            format: "markdown",
            suggested_name: "LovelyRes-disposal-20260824-010203.md".to_owned(),
            media_type: "text/markdown; charset=utf-8",
            operation_count: value.summary.total,
            contents: value.markdown,
        };
        assert_eq!(payload.operation_count, 0);
        assert!(!format!("{payload:?}").contains("do-not-log-body"));
        fs::remove_dir_all(root).unwrap();
    }
}
