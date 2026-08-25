//! Bounded, target-bound Electron boundary for quick detection.
//!
//! The renderer selects only closed detection module ids. Opaque SSH bindings
//! are resolved here, while core owns the immutable plan and every remote
//! command. Reports are projected into a bounded display DTO before they enter
//! the sidecar registry.

use std::{
    collections::{HashMap, VecDeque},
    fmt,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use lovelyres_core::{
    BackendServices, CoreError,
    detection::{
        DetectionCancellation, DetectionCategory, DetectionFinding, DetectionKind,
        DetectionModuleReport, DetectionOutcome, DetectionScanEvent, DetectionScanPlan,
        DetectionScanProfile, DetectionScanReport, DetectionScanRequest, DetectionScanStatus,
        DetectionSeverity, DetectionSummary, detection_event_channel,
    },
    ssh::BoundSshSession,
    target::TargetGuard,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ssh_api::SshApi;

const MAX_HANDLE_BYTES: usize = 128;
const MAX_PLAN_MODULES: usize = 13;
const MAX_FINDINGS_INPUT: usize = 200;
const MAX_PLANS: usize = 16;
const MAX_SCANS: usize = 8;
const MAX_REPORTS: usize = 24;
const MAX_EVENTS_PER_SCAN: usize = 64;
const MAX_POLL_EVENTS: usize = 32;
const MAX_HISTORY_OFFSET: usize = 56;
const MAX_HISTORY_PAGE: usize = 8;
const MAX_REPORT_FINDINGS: usize = 400;
const MAX_FINDINGS_PER_REPORT_MODULE: usize = 100;
const MAX_REPORT_TEXT_BUDGET: usize = 512 * 1024;
const MAX_REPORT_BYTES: usize = 1024 * 1024;
const MAX_REPORT_REGISTRY_BYTES: usize = 12 * 1024 * 1024;
const MAX_PUBLIC_U64: u64 = 9_007_199_254_740_991;
const MAX_SUMMARY_COUNT: usize = MAX_PLAN_MODULES * MAX_FINDINGS_INPUT;
const MAX_DROPPED_PROGRESS_EVENTS: usize = 1_024;
const REDACTED_QUICK_DETECTION_TEXT: &str = "[SENSITIVE QUICK DETECTION TEXT REDACTED]";
const MAX_REDACTED_REPORT_FIELDS: usize = MAX_REPORT_FINDINGS * 3 + MAX_PLAN_MODULES;
const REDACTION_RESERVE_BYTES: usize =
    MAX_REDACTED_REPORT_FIELDS * REDACTED_QUICK_DETECTION_TEXT.len();
const MAX_PUBLIC_REPORT_TEXT_BUDGET: usize = MAX_REPORT_TEXT_BUDGET - REDACTION_RESERVE_BYTES;
const PLAN_TTL: Duration = Duration::from_secs(5 * 60);
const RUNNING_SCAN_TTL: Duration = Duration::from_secs(30 * 60);
const TERMINAL_SCAN_TTL: Duration = Duration::from_secs(10 * 60);
const REPORT_TTL: Duration = Duration::from_secs(10 * 60);

#[derive(Clone)]
pub(crate) struct QuickDetectionApi {
    services: BackendServices,
    ssh_api: Arc<SshApi>,
    registry: Arc<Mutex<Registry>>,
}

impl fmt::Debug for QuickDetectionApi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (plans, scans, reports, report_bytes) = self
            .registry
            .lock()
            .map(|registry| {
                (
                    registry.plans.len(),
                    registry.scans.len(),
                    registry.reports.len(),
                    registry.report_bytes,
                )
            })
            .unwrap_or_default();
        formatter
            .debug_struct("QuickDetectionApi")
            .field("plan_count", &plans)
            .field("scan_count", &scans)
            .field("report_count", &reports)
            .field("report_bytes", &report_bytes)
            .finish()
    }
}

impl QuickDetectionApi {
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

    pub(crate) fn catalog() -> QuickDetectionCatalogDto {
        QuickDetectionCatalogDto {
            modules: DetectionKind::ALL
                .into_iter()
                .map(QuickDetectionModuleCatalogDto::from)
                .collect(),
            profiles: vec![
                QuickDetectionProfileDto {
                    id: "selected",
                    label: "自选模块",
                    module_ids: Vec::new(),
                },
                QuickDetectionProfileDto {
                    id: "competition-triage",
                    label: "首分钟只读排查",
                    module_ids: DetectionKind::COMPETITION_TRIAGE
                        .into_iter()
                        .map(|kind| kind.id())
                        .collect(),
                },
            ],
            maximum_findings_per_module: MAX_FINDINGS_INPUT,
        }
    }

    pub(crate) fn plan_scan(
        &self,
        binding_handle: &str,
        input: QuickDetectionPlanInput,
    ) -> Result<QuickDetectionPlanDto, QuickDetectionApiError> {
        let (session, scope) = self.capture_binding(binding_handle)?;
        let request = input.into_core()?;
        let plan = self.services.detection().plan_scan(&session, request)?;
        self.validate_binding(&scope)?;

        let dto = QuickDetectionPlanDto {
            plan_handle: String::new(),
            profile: profile_key(plan.profile()),
            module_ids: plan.modules().iter().map(|kind| kind.id()).collect(),
            module_count: plan.modules().len(),
            maximum_findings_per_module: plan.max_findings(),
            expires_in_seconds: PLAN_TTL.as_secs(),
            summary: format!(
                "{} 个封闭检测模块 · 并发上限 {} · 每模块最多 {} 项",
                plan.modules().len(),
                plan.concurrency(),
                plan.max_findings()
            ),
        };
        let mut registry = self.lock_registry()?;
        registry.prune(Instant::now());
        let handle = registry.insert_plan(scope, plan, Instant::now())?;
        Ok(QuickDetectionPlanDto {
            plan_handle: handle,
            ..dto
        })
    }

    pub(crate) fn start_scan(
        self: &Arc<Self>,
        binding_handle: &str,
        plan_handle: &str,
    ) -> Result<QuickDetectionScanStartedDto, QuickDetectionApiError> {
        validate_handle("quick-detection plan handle", plan_handle)?;
        let (session, scope) = self.capture_binding(binding_handle)?;
        let (plan, scan_handle, cancellation, events, receiver, total) = {
            let mut registry = self.lock_registry()?;
            let now = Instant::now();
            registry.prune(now);
            let plan = registry.take_plan(&scope, plan_handle, now)?;
            let total = plan.modules().len();
            let cancellation = DetectionCancellation::default();
            let (events, receiver) = detection_event_channel(MAX_EVENTS_PER_SCAN)?;
            let scan_handle = registry.insert_scan(
                scope.clone(),
                plan.id().to_owned(),
                total,
                cancellation.clone(),
                now,
            )?;
            (plan, scan_handle, cancellation, events, receiver, total)
        };

        if let Err(error) = self.validate_binding(&scope) {
            cancellation.cancel();
            self.remove_scan(&scan_handle, &scope);
            return Err(error);
        }

        let event_api = Arc::clone(self);
        let event_handle = scan_handle.clone();
        let event_scope = scope.clone();
        tokio::spawn(async move {
            while let Some(event) = receiver.recv().await {
                event_api.record_event(&event_handle, &event_scope, event);
            }
        });

        let run_api = Arc::clone(self);
        let run_handle = scan_handle.clone();
        tokio::spawn(async move {
            let result = run_api
                .services
                .detection()
                .run_scan(&session, plan, cancellation, events)
                .await;
            run_api.finish_scan(&run_handle, &scope, result);
        });

        Ok(QuickDetectionScanStartedDto {
            scan_handle,
            stage: "running",
            total,
            expires_in_seconds: RUNNING_SCAN_TTL.as_secs(),
        })
    }

    pub(crate) fn poll_scan(
        &self,
        binding_handle: &str,
        scan_handle: &str,
        after_event: u64,
        limit: usize,
    ) -> Result<QuickDetectionPollDto, QuickDetectionApiError> {
        validate_handle("quick-detection scan handle", scan_handle)?;
        if after_event > MAX_PUBLIC_U64 || limit == 0 || limit > MAX_POLL_EVENTS {
            return Err(QuickDetectionApiError::InvalidBounds);
        }
        let (_, scope) = self.capture_binding(binding_handle)?;
        let dto = {
            let mut registry = self.lock_registry()?;
            registry.prune(Instant::now());
            registry.poll(&scope, scan_handle, after_event, limit)?
        };
        self.validate_binding(&scope)?;
        Ok(dto)
    }

    pub(crate) fn cancel_scan(
        &self,
        binding_handle: &str,
        scan_handle: &str,
    ) -> Result<QuickDetectionCancellationDto, QuickDetectionApiError> {
        validate_handle("quick-detection scan handle", scan_handle)?;
        let (_, scope) = self.capture_binding(binding_handle)?;
        {
            let mut registry = self.lock_registry()?;
            registry.prune(Instant::now());
            registry.cancel(&scope, scan_handle)?;
        }
        self.validate_binding(&scope)?;
        Ok(QuickDetectionCancellationDto {
            cancel_requested: true,
        })
    }

    pub(crate) fn list_history(
        &self,
        binding_handle: &str,
        offset: usize,
        limit: usize,
    ) -> Result<QuickDetectionHistoryPageDto, QuickDetectionApiError> {
        if offset > MAX_HISTORY_OFFSET || limit == 0 || limit > MAX_HISTORY_PAGE {
            return Err(QuickDetectionApiError::InvalidBounds);
        }
        let (_, scope) = self.capture_binding(binding_handle)?;
        let reports = self
            .services
            .detection()
            .history_for_target(&scope.target)?;
        self.validate_binding(&scope)?;
        let total = reports.len().min(MAX_HISTORY_OFFSET + MAX_HISTORY_PAGE);
        let selected = reports.into_iter().skip(offset).take(limit);
        let mut registry = self.lock_registry()?;
        let now = Instant::now();
        registry.prune(now);
        let mut items = Vec::new();
        for report in selected {
            let handle = registry.register_report(scope.clone(), report.clone(), now)?;
            items.push(history_summary(handle, &report)?);
        }
        Ok(QuickDetectionHistoryPageDto {
            total,
            offset,
            has_more: offset.saturating_add(items.len()) < total,
            items,
        })
    }

    pub(crate) fn get_report(
        &self,
        binding_handle: &str,
        report_handle: &str,
    ) -> Result<QuickDetectionReportDto, QuickDetectionApiError> {
        validate_handle("quick-detection report handle", report_handle)?;
        let (_, scope) = self.capture_binding(binding_handle)?;
        let report = {
            let mut registry = self.lock_registry()?;
            registry.prune(Instant::now());
            registry.report(&scope, report_handle, Instant::now())?
        };
        self.validate_binding(&scope)?;
        Ok(report)
    }

    fn capture_binding(
        &self,
        binding_handle: &str,
    ) -> Result<(BoundSshSession, BindingScope), QuickDetectionApiError> {
        validate_handle("SSH binding handle", binding_handle)?;
        let session = self
            .ssh_api
            .binding_session_clone(binding_handle)
            .map_err(|_| QuickDetectionApiError::BindingUnavailable)?;
        self.services
            .target()
            .validate(session.target())
            .map_err(|_| QuickDetectionApiError::BindingUnavailable)?;
        let scope = BindingScope::from_session(binding_handle, &session);
        Ok((session, scope))
    }

    fn validate_binding(
        &self,
        expected: &BindingScope,
    ) -> Result<BoundSshSession, QuickDetectionApiError> {
        let (session, current) = self.capture_binding(&expected.binding_handle)?;
        if &current != expected {
            return Err(QuickDetectionApiError::BindingUnavailable);
        }
        Ok(session)
    }

    fn finish_scan(
        &self,
        scan_handle: &str,
        scope: &BindingScope,
        result: Result<DetectionScanReport, CoreError>,
    ) {
        let report = match result {
            Ok(report) => {
                if self.validate_binding(scope).is_err() || report.target != scope.target {
                    self.finish_failed(scan_handle, scope, "binding-stale");
                    return;
                }
                report
            }
            Err(error) => {
                tracing::warn!(
                    error = %QuickDetectionApiError::Core(error),
                    "quick-detection scan failed"
                );
                self.finish_failed(scan_handle, scope, "scan-failed");
                return;
            }
        };

        let result = self.lock_registry().and_then(|mut registry| {
            registry.prune(Instant::now());
            registry.finish_report(scope, scan_handle, report, Instant::now())
        });
        if let Err(error) = result {
            tracing::warn!(error = %error, "quick-detection report was rejected");
            self.finish_failed(scan_handle, scope, "report-rejected");
        }
    }

    fn finish_failed(&self, scan_handle: &str, scope: &BindingScope, code: &'static str) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.finish_failed(scope, scan_handle, code, Instant::now());
        }
    }

    fn record_event(&self, scan_handle: &str, scope: &BindingScope, event: DetectionScanEvent) {
        if self.validate_binding(scope).is_err() {
            if let Ok(mut registry) = self.registry.lock() {
                registry.close_scope(scope);
            }
            return;
        }
        if let Ok(mut registry) = self.registry.lock() {
            registry.record_event(scope, scan_handle, event);
        }
    }

    fn remove_scan(&self, scan_handle: &str, scope: &BindingScope) {
        if let Ok(mut registry) = self.registry.lock()
            && registry
                .scans
                .get(scan_handle)
                .is_some_and(|scan| &scan.scope == scope)
        {
            registry.scans.remove(scan_handle);
        }
    }

    fn lock_registry(&self) -> Result<MutexGuard<'_, Registry>, QuickDetectionApiError> {
        self.registry
            .lock()
            .map_err(|_| QuickDetectionApiError::RegistryUnavailable)
    }
}

pub(crate) enum QuickDetectionApiError {
    Core(CoreError),
    BindingUnavailable,
    InvalidInput,
    InvalidBounds,
    InvalidHandle,
    PlanUnavailable,
    ScanUnavailable,
    ReportUnavailable,
    Capacity,
    RegistryUnavailable,
}

impl fmt::Debug for QuickDetectionApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core(_) => "Core([REDACTED])",
            Self::BindingUnavailable => "BindingUnavailable",
            Self::InvalidInput => "InvalidInput",
            Self::InvalidBounds => "InvalidBounds",
            Self::InvalidHandle => "InvalidHandle",
            Self::PlanUnavailable => "PlanUnavailable",
            Self::ScanUnavailable => "ScanUnavailable",
            Self::ReportUnavailable => "ReportUnavailable",
            Self::Capacity => "Capacity",
            Self::RegistryUnavailable => "RegistryUnavailable",
        })
    }
}

impl fmt::Display for QuickDetectionApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core(_) => "the quick-detection operation failed",
            Self::BindingUnavailable => "the SSH binding is missing or stale",
            Self::InvalidInput => "the quick-detection request is invalid",
            Self::InvalidBounds => "the quick-detection bounds are invalid",
            Self::InvalidHandle => "the quick-detection handle is invalid",
            Self::PlanUnavailable => "the quick-detection plan is missing or stale",
            Self::ScanUnavailable => "the quick-detection scan is missing or stale",
            Self::ReportUnavailable => "the quick-detection report is missing or stale",
            Self::Capacity => "the quick-detection registry is full",
            Self::RegistryUnavailable => "the quick-detection registry is unavailable",
        })
    }
}

impl std::error::Error for QuickDetectionApiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Core(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CoreError> for QuickDetectionApiError {
    fn from(error: CoreError) -> Self {
        Self::Core(error)
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct QuickDetectionPlanInput {
    pub(crate) profile: String,
    pub(crate) module_ids: Vec<String>,
    pub(crate) maximum_findings_per_module: usize,
}

// Keep request conversion separate from serde so tests and the future RPC
// adapter exercise the same closed-enum validation.
impl QuickDetectionPlanInput {
    fn into_core(self) -> Result<DetectionScanRequest, QuickDetectionApiError> {
        if self.maximum_findings_per_module == 0
            || self.maximum_findings_per_module > MAX_FINDINGS_INPUT
            || self.module_ids.len() > MAX_PLAN_MODULES
            || self
                .module_ids
                .iter()
                .any(|value| value.is_empty() || value.len() > 64)
        {
            return Err(QuickDetectionApiError::InvalidInput);
        }
        let request = match self.profile.as_str() {
            "selected" => {
                let modules = self
                    .module_ids
                    .iter()
                    .map(|value| kind_from_key(value).ok_or(QuickDetectionApiError::InvalidInput))
                    .collect::<Result<Vec<_>, _>>()?;
                DetectionScanRequest::selected(modules)?
            }
            "competition-triage" if self.module_ids.is_empty() => {
                DetectionScanRequest::competition_triage()
            }
            _ => return Err(QuickDetectionApiError::InvalidInput),
        };
        request
            .with_max_findings(self.maximum_findings_per_module)
            .map_err(QuickDetectionApiError::from)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct QuickDetectionCatalogDto {
    modules: Vec<QuickDetectionModuleCatalogDto>,
    profiles: Vec<QuickDetectionProfileDto>,
    maximum_findings_per_module: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct QuickDetectionModuleCatalogDto {
    id: &'static str,
    label: &'static str,
    description: &'static str,
    category: &'static str,
    category_label: &'static str,
}

impl From<DetectionKind> for QuickDetectionModuleCatalogDto {
    fn from(kind: DetectionKind) -> Self {
        Self {
            id: kind.id(),
            label: kind.label(),
            description: kind.description(),
            category: category_key(kind.category()),
            category_label: kind.category().label(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct QuickDetectionProfileDto {
    id: &'static str,
    label: &'static str,
    module_ids: Vec<&'static str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct QuickDetectionPlanDto {
    plan_handle: String,
    profile: &'static str,
    module_ids: Vec<&'static str>,
    module_count: usize,
    maximum_findings_per_module: usize,
    expires_in_seconds: u64,
    summary: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct QuickDetectionScanStartedDto {
    scan_handle: String,
    stage: &'static str,
    total: usize,
    expires_in_seconds: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct QuickDetectionCancellationDto {
    cancel_requested: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct QuickDetectionPollDto {
    scan_handle: String,
    stage: &'static str,
    completed: usize,
    total: usize,
    current_module: Option<&'static str>,
    cancel_requested: bool,
    events: Vec<QuickDetectionEventDto>,
    next_event_cursor: u64,
    events_truncated: bool,
    report_handle: Option<String>,
    error_code: Option<&'static str>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct QuickDetectionEventDto {
    sequence: u64,
    kind: &'static str,
    module: Option<&'static str>,
    outcome: Option<&'static str>,
    completed: usize,
    total: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct QuickDetectionHistoryPageDto {
    total: usize,
    offset: usize,
    has_more: bool,
    items: Vec<QuickDetectionHistoryItemDto>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct QuickDetectionHistoryItemDto {
    report_handle: String,
    profile: &'static str,
    started_at: String,
    duration_ms: u64,
    status: &'static str,
    overall_score: u8,
    module_count: usize,
    summary: QuickDetectionSummaryDto,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct QuickDetectionReportDto {
    report_handle: String,
    profile: &'static str,
    started_at: String,
    duration_ms: u64,
    status: &'static str,
    overall_score: u8,
    summary: QuickDetectionSummaryDto,
    dropped_progress_events: usize,
    redacted_field_count: usize,
    text_projected: bool,
    truncated: bool,
    modules: Vec<QuickDetectionModuleReportDto>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct QuickDetectionSummaryDto {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
    failed_modules: usize,
    not_applicable_modules: usize,
    error_modules: usize,
    cancelled_modules: usize,
}

impl From<&DetectionSummary> for QuickDetectionSummaryDto {
    fn from(summary: &DetectionSummary) -> Self {
        Self {
            critical: summary.critical,
            high: summary.high,
            medium: summary.medium,
            low: summary.low,
            info: summary.info,
            failed_modules: summary.failed_modules,
            not_applicable_modules: summary.not_applicable_modules,
            error_modules: summary.error_modules,
            cancelled_modules: summary.cancelled_modules,
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct QuickDetectionModuleReportDto {
    id: &'static str,
    label: &'static str,
    category: &'static str,
    outcome: &'static str,
    score: u8,
    duration_ms: u64,
    findings: Vec<QuickDetectionFindingDto>,
    findings_truncated: bool,
    raw_text: String,
    raw_text_redacted: bool,
    raw_text_truncated: bool,
    raw_text_projected: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct QuickDetectionFindingDto {
    title: String,
    description: String,
    severity: &'static str,
    recommendation: Option<String>,
    redacted: bool,
    text_truncated: bool,
    text_projected: bool,
}

#[derive(Default)]
struct Registry {
    plans: HashMap<String, PlanEntry>,
    scans: HashMap<String, ScanEntry>,
    reports: HashMap<String, ReportEntry>,
    report_bytes: usize,
}

impl fmt::Debug for Registry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QuickDetectionRegistry")
            .field("plan_count", &self.plans.len())
            .field("scan_count", &self.scans.len())
            .field("report_count", &self.reports.len())
            .field("report_bytes", &self.report_bytes)
            .finish()
    }
}

struct PlanEntry {
    scope: BindingScope,
    plan: DetectionScanPlan,
    expires_at: Instant,
}

struct ScanEntry {
    scope: BindingScope,
    plan_id: String,
    cancellation: DetectionCancellation,
    state: ScanState,
    completed: usize,
    total: usize,
    current_module: Option<DetectionKind>,
    events: VecDeque<QuickDetectionEventDto>,
    next_sequence: u64,
    expires_at: Instant,
}

enum ScanState {
    Running,
    Cancelling,
    Completed {
        report_handle: String,
        cancelled: bool,
    },
    Failed {
        code: &'static str,
    },
}

struct ReportEntry {
    scope: BindingScope,
    core_id: String,
    dto: QuickDetectionReportDto,
    bytes: usize,
    expires_at: Instant,
    touched_at: Instant,
}

impl Registry {
    fn prune(&mut self, now: Instant) {
        self.plans.retain(|_, entry| entry.expires_at > now);
        self.scans.retain(|_, entry| {
            let keep = entry.expires_at > now;
            if !keep {
                entry.cancellation.cancel();
            }
            keep
        });
        let expired = self
            .reports
            .iter()
            .filter_map(|(handle, report)| (report.expires_at <= now).then_some(handle.clone()))
            .collect::<Vec<_>>();
        for handle in expired {
            self.remove_report(&handle);
        }
    }

    fn close_binding(&mut self, binding_handle: &str) {
        self.plans
            .retain(|_, entry| entry.scope.binding_handle != binding_handle);
        self.scans.retain(|_, entry| {
            let keep = entry.scope.binding_handle != binding_handle;
            if !keep {
                entry.cancellation.cancel();
            }
            keep
        });
        let reports = self
            .reports
            .iter()
            .filter_map(|(handle, entry)| {
                (entry.scope.binding_handle == binding_handle).then_some(handle.clone())
            })
            .collect::<Vec<_>>();
        for handle in reports {
            self.remove_report(&handle);
        }
    }

    fn close_scope(&mut self, scope: &BindingScope) {
        self.plans.retain(|_, entry| &entry.scope != scope);
        self.scans.retain(|_, entry| {
            let keep = &entry.scope != scope;
            if !keep {
                entry.cancellation.cancel();
            }
            keep
        });
        let reports = self
            .reports
            .iter()
            .filter_map(|(handle, entry)| (&entry.scope == scope).then_some(handle.clone()))
            .collect::<Vec<_>>();
        for handle in reports {
            self.remove_report(&handle);
        }
    }

    fn insert_plan(
        &mut self,
        scope: BindingScope,
        plan: DetectionScanPlan,
        now: Instant,
    ) -> Result<String, QuickDetectionApiError> {
        self.plans.retain(|_, entry| entry.scope != scope);
        if self.plans.len() >= MAX_PLANS {
            return Err(QuickDetectionApiError::Capacity);
        }
        let handle = unique_handle(&self.plans)?;
        self.plans.insert(
            handle.clone(),
            PlanEntry {
                scope,
                plan,
                expires_at: now + PLAN_TTL,
            },
        );
        Ok(handle)
    }

    fn take_plan(
        &mut self,
        scope: &BindingScope,
        handle: &str,
        now: Instant,
    ) -> Result<DetectionScanPlan, QuickDetectionApiError> {
        let entry = self
            .plans
            .remove(handle)
            .ok_or(QuickDetectionApiError::PlanUnavailable)?;
        if entry.expires_at <= now || &entry.scope != scope {
            return Err(QuickDetectionApiError::PlanUnavailable);
        }
        Ok(entry.plan)
    }

    fn insert_scan(
        &mut self,
        scope: BindingScope,
        plan_id: String,
        total: usize,
        cancellation: DetectionCancellation,
        now: Instant,
    ) -> Result<String, QuickDetectionApiError> {
        if total == 0 || total > MAX_PLAN_MODULES {
            return Err(QuickDetectionApiError::InvalidBounds);
        }
        self.scans.retain(|_, scan| {
            scan.scope != scope || matches!(scan.state, ScanState::Running | ScanState::Cancelling)
        });
        if self.scans.len() >= MAX_SCANS {
            self.scans
                .retain(|_, scan| matches!(scan.state, ScanState::Running | ScanState::Cancelling));
        }
        if self.scans.len() >= MAX_SCANS
            || self.scans.values().any(|scan| {
                scan.scope == scope
                    && matches!(scan.state, ScanState::Running | ScanState::Cancelling)
            })
        {
            return Err(QuickDetectionApiError::Capacity);
        }
        let handle = unique_handle(&self.scans)?;
        self.scans.insert(
            handle.clone(),
            ScanEntry {
                scope,
                plan_id,
                cancellation,
                state: ScanState::Running,
                completed: 0,
                total,
                current_module: None,
                events: VecDeque::new(),
                next_sequence: 0,
                expires_at: now + RUNNING_SCAN_TTL,
            },
        );
        Ok(handle)
    }

    fn cancel(&mut self, scope: &BindingScope, handle: &str) -> Result<(), QuickDetectionApiError> {
        let scan = self
            .scans
            .get_mut(handle)
            .filter(|scan| &scan.scope == scope)
            .ok_or(QuickDetectionApiError::ScanUnavailable)?;
        match scan.state {
            ScanState::Running => {
                scan.cancellation.cancel();
                scan.state = ScanState::Cancelling;
                Ok(())
            }
            ScanState::Cancelling => Ok(()),
            ScanState::Completed { .. } | ScanState::Failed { .. } => {
                Err(QuickDetectionApiError::ScanUnavailable)
            }
        }
    }

    fn record_event(&mut self, scope: &BindingScope, handle: &str, event: DetectionScanEvent) {
        let Some(scan) = self
            .scans
            .get_mut(handle)
            .filter(|scan| &scan.scope == scope)
        else {
            return;
        };
        if !matches!(scan.state, ScanState::Running | ScanState::Cancelling) {
            return;
        }
        let valid_bounds = match &event {
            DetectionScanEvent::ModuleStarted { ordinal, total, .. } => {
                *total == scan.total
                    && (1..=MAX_PLAN_MODULES).contains(total)
                    && (1..=*total).contains(ordinal)
            }
            DetectionScanEvent::ModuleFinished {
                completed, total, ..
            } => {
                *total == scan.total
                    && (1..=MAX_PLAN_MODULES).contains(total)
                    && *completed <= *total
            }
            DetectionScanEvent::ScanFinished { total, .. } => {
                *total == scan.total && (1..=MAX_PLAN_MODULES).contains(total)
            }
        };
        if !valid_bounds || scan.next_sequence >= MAX_PUBLIC_U64 {
            return;
        }
        let event_scan_id = match &event {
            DetectionScanEvent::ModuleStarted { scan_id, .. }
            | DetectionScanEvent::ModuleFinished { scan_id, .. }
            | DetectionScanEvent::ScanFinished { scan_id, .. } => scan_id,
        };
        if event_scan_id != &scan.plan_id {
            return;
        }
        scan.next_sequence = scan.next_sequence.saturating_add(1);
        let sequence = scan.next_sequence;
        let dto = match event {
            DetectionScanEvent::ModuleStarted {
                module,
                total,
                ordinal: _,
                scan_id: _,
            } => {
                scan.current_module = Some(module);
                QuickDetectionEventDto {
                    sequence,
                    kind: "module-started",
                    module: Some(module.id()),
                    outcome: None,
                    completed: scan.completed,
                    total,
                }
            }
            DetectionScanEvent::ModuleFinished {
                module,
                outcome,
                completed,
                total,
                scan_id: _,
            } => {
                scan.completed = completed.min(total);
                if scan.current_module == Some(module) {
                    scan.current_module = None;
                }
                QuickDetectionEventDto {
                    sequence,
                    kind: "module-finished",
                    module: Some(module.id()),
                    outcome: Some(outcome_key(outcome)),
                    completed: scan.completed,
                    total,
                }
            }
            DetectionScanEvent::ScanFinished {
                total, scan_id: _, ..
            } => {
                scan.completed = total;
                scan.current_module = None;
                QuickDetectionEventDto {
                    sequence,
                    kind: "scan-finished",
                    module: None,
                    outcome: None,
                    completed: total,
                    total,
                }
            }
        };
        if scan.events.len() == MAX_EVENTS_PER_SCAN {
            scan.events.pop_front();
        }
        scan.events.push_back(dto);
    }

    fn poll(
        &self,
        scope: &BindingScope,
        handle: &str,
        after_event: u64,
        limit: usize,
    ) -> Result<QuickDetectionPollDto, QuickDetectionApiError> {
        let scan = self
            .scans
            .get(handle)
            .filter(|scan| &scan.scope == scope)
            .ok_or(QuickDetectionApiError::ScanUnavailable)?;
        if after_event > scan.next_sequence {
            return Err(QuickDetectionApiError::InvalidBounds);
        }
        let first_available = scan
            .events
            .front()
            .map_or(scan.next_sequence + 1, |event| event.sequence);
        let events_truncated = after_event.saturating_add(1) < first_available;
        let effective_after = if events_truncated {
            first_available.saturating_sub(1)
        } else {
            after_event
        };
        let events = scan
            .events
            .iter()
            .filter(|event| event.sequence > effective_after)
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();
        let next_event_cursor = events
            .last()
            .map_or(effective_after, |event| event.sequence);
        let (stage, cancel_requested, report_handle, error_code) = match &scan.state {
            ScanState::Running => ("running", false, None, None),
            ScanState::Cancelling => ("cancelling", true, None, None),
            ScanState::Completed {
                report_handle,
                cancelled,
            } => (
                if *cancelled { "cancelled" } else { "completed" },
                *cancelled,
                Some(report_handle.clone()),
                None,
            ),
            ScanState::Failed { code } => ("failed", false, None, Some(*code)),
        };
        Ok(QuickDetectionPollDto {
            scan_handle: handle.to_owned(),
            stage,
            completed: scan.completed,
            total: scan.total,
            current_module: scan.current_module.map(DetectionKind::id),
            cancel_requested,
            events,
            next_event_cursor,
            events_truncated,
            report_handle,
            error_code,
        })
    }

    fn finish_report(
        &mut self,
        scope: &BindingScope,
        scan_handle: &str,
        report: DetectionScanReport,
        now: Instant,
    ) -> Result<(), QuickDetectionApiError> {
        let scan = self
            .scans
            .get(scan_handle)
            .filter(|scan| &scan.scope == scope)
            .ok_or(QuickDetectionApiError::ScanUnavailable)?;
        if report.id != scan.plan_id || report.target != scope.target {
            return Err(QuickDetectionApiError::ReportUnavailable);
        }
        let cancelled = report.status == DetectionScanStatus::Cancelled;
        let total = report.modules.len();
        let report_handle = self.register_report(scope.clone(), report, now)?;
        let scan = self
            .scans
            .get_mut(scan_handle)
            .filter(|scan| &scan.scope == scope)
            .ok_or(QuickDetectionApiError::ScanUnavailable)?;
        scan.completed = total;
        scan.total = total;
        scan.current_module = None;
        scan.state = ScanState::Completed {
            report_handle,
            cancelled,
        };
        scan.expires_at = now + TERMINAL_SCAN_TTL;
        Ok(())
    }

    fn finish_failed(
        &mut self,
        scope: &BindingScope,
        scan_handle: &str,
        code: &'static str,
        now: Instant,
    ) {
        if let Some(scan) = self
            .scans
            .get_mut(scan_handle)
            .filter(|scan| &scan.scope == scope)
        {
            scan.current_module = None;
            scan.state = ScanState::Failed { code };
            scan.expires_at = now + TERMINAL_SCAN_TTL;
        }
    }

    fn register_report(
        &mut self,
        scope: BindingScope,
        report: DetectionScanReport,
        now: Instant,
    ) -> Result<String, QuickDetectionApiError> {
        if let Some((handle, entry)) = self
            .reports
            .iter_mut()
            .find(|(_, entry)| entry.scope == scope && entry.core_id == report.id)
        {
            entry.expires_at = now + REPORT_TTL;
            entry.touched_at = now;
            return Ok(handle.clone());
        }
        let handle = unique_handle(&self.reports)?;
        let dto = project_report(handle.clone(), &report, &scope.sensitive_literals())?;
        let bytes = serde_json::to_vec(&dto)
            .map_err(|_| QuickDetectionApiError::ReportUnavailable)?
            .len();
        if bytes > MAX_REPORT_BYTES {
            return Err(QuickDetectionApiError::Capacity);
        }
        while self.reports.len() >= MAX_REPORTS
            || self.report_bytes.saturating_add(bytes) > MAX_REPORT_REGISTRY_BYTES
        {
            let Some(oldest) = self
                .reports
                .iter()
                .min_by_key(|(_, entry)| entry.touched_at)
                .map(|(handle, _)| handle.clone())
            else {
                break;
            };
            self.remove_report(&oldest);
        }
        if self.reports.len() >= MAX_REPORTS
            || self.report_bytes.saturating_add(bytes) > MAX_REPORT_REGISTRY_BYTES
        {
            return Err(QuickDetectionApiError::Capacity);
        }
        self.report_bytes = self.report_bytes.saturating_add(bytes);
        self.reports.insert(
            handle.clone(),
            ReportEntry {
                scope,
                core_id: report.id,
                dto,
                bytes,
                expires_at: now + REPORT_TTL,
                touched_at: now,
            },
        );
        Ok(handle)
    }

    fn report(
        &mut self,
        scope: &BindingScope,
        handle: &str,
        now: Instant,
    ) -> Result<QuickDetectionReportDto, QuickDetectionApiError> {
        let report = self
            .reports
            .get_mut(handle)
            .filter(|report| &report.scope == scope)
            .ok_or(QuickDetectionApiError::ReportUnavailable)?;
        report.touched_at = now;
        report.expires_at = now + REPORT_TTL;
        Ok(report.dto.clone())
    }

    fn remove_report(&mut self, handle: &str) {
        if let Some(report) = self.reports.remove(handle) {
            self.report_bytes = self.report_bytes.saturating_sub(report.bytes);
        }
    }
}

fn project_report(
    report_handle: String,
    report: &DetectionScanReport,
    sensitive_literals: &[&str],
) -> Result<QuickDetectionReportDto, QuickDetectionApiError> {
    validate_report_metadata(report)?;
    let mut budget = TextBudget::new(MAX_PUBLIC_REPORT_TEXT_BUDGET);
    let mut remaining_findings = MAX_REPORT_FINDINGS;
    let projected_modules = report
        .modules
        .iter()
        .map(|module| {
            project_module(
                module,
                &mut budget,
                &mut remaining_findings,
                sensitive_literals,
            )
        })
        .collect::<Vec<_>>();
    let redacted_field_count = projected_modules
        .iter()
        .map(|module| module.redacted_field_count)
        .sum();
    let text_projected = projected_modules.iter().any(|module| module.text_projected);
    let truncated = projected_modules.iter().any(|module| module.truncated);
    let modules = projected_modules
        .into_iter()
        .map(|module| module.dto)
        .collect();
    Ok(QuickDetectionReportDto {
        report_handle,
        profile: profile_key(report.profile),
        started_at: report.started_at.to_rfc3339(),
        duration_ms: report.duration_ms,
        status: scan_status_key(report.status),
        overall_score: report.overall_score,
        summary: QuickDetectionSummaryDto::from(&report.summary),
        dropped_progress_events: report.dropped_progress_events,
        redacted_field_count,
        text_projected,
        truncated,
        modules,
    })
}

struct ProjectedModule {
    dto: QuickDetectionModuleReportDto,
    redacted_field_count: usize,
    text_projected: bool,
    truncated: bool,
}

fn project_module(
    module: &DetectionModuleReport,
    budget: &mut TextBudget,
    remaining_findings: &mut usize,
    sensitive_literals: &[&str],
) -> ProjectedModule {
    let take = module
        .findings
        .len()
        .min(MAX_FINDINGS_PER_REPORT_MODULE)
        .min(*remaining_findings);
    *remaining_findings = remaining_findings.saturating_sub(take);
    let findings = module
        .findings
        .iter()
        .take(take)
        .map(|finding| project_finding(finding, budget, sensitive_literals))
        .collect::<Vec<_>>();
    let raw_text = budget.take_public(&module.raw_text, 64 * 1024, true, sensitive_literals);
    let findings_truncated = take < module.findings.len();
    let redacted_field_count = findings
        .iter()
        .map(|finding| finding.redacted_field_count)
        .sum::<usize>()
        + usize::from(raw_text.redacted);
    let text_projected =
        raw_text.projected || findings.iter().any(|finding| finding.dto.text_projected);
    let raw_text_truncated = module.raw_text_truncated || raw_text.truncated;
    let truncated = findings_truncated
        || raw_text_truncated
        || findings.iter().any(|finding| finding.dto.text_truncated);
    ProjectedModule {
        dto: QuickDetectionModuleReportDto {
            id: module.kind.id(),
            label: module.kind.label(),
            category: category_key(module.kind.category()),
            outcome: outcome_key(module.outcome),
            score: module.score,
            duration_ms: module.duration_ms,
            findings: findings.into_iter().map(|finding| finding.dto).collect(),
            findings_truncated,
            raw_text: raw_text.value,
            raw_text_redacted: raw_text.redacted,
            raw_text_truncated,
            raw_text_projected: raw_text.projected,
        },
        redacted_field_count,
        text_projected,
        truncated,
    }
}

struct ProjectedFinding {
    dto: QuickDetectionFindingDto,
    redacted_field_count: usize,
}

fn project_finding(
    finding: &DetectionFinding,
    budget: &mut TextBudget,
    sensitive_literals: &[&str],
) -> ProjectedFinding {
    let title = budget.take_public(&finding.title, 512, false, sensitive_literals);
    let description = budget.take_public(&finding.description, 2 * 1024, false, sensitive_literals);
    let recommendation = finding
        .recommendation
        .as_deref()
        .map(|value| budget.take_public(value, 2 * 1024, false, sensitive_literals));
    let redacted_field_count = usize::from(title.redacted)
        + usize::from(description.redacted)
        + usize::from(
            recommendation
                .as_ref()
                .is_some_and(|projection| projection.redacted),
        );
    let redacted = redacted_field_count > 0;
    let text_truncated = title.truncated
        || description.truncated
        || recommendation
            .as_ref()
            .is_some_and(|projection| projection.truncated);
    let text_projected = title.projected
        || description.projected
        || recommendation
            .as_ref()
            .is_some_and(|projection| projection.projected);
    ProjectedFinding {
        dto: QuickDetectionFindingDto {
            title: title.value,
            description: description.value,
            severity: severity_key(finding.severity),
            recommendation: recommendation.map(|projection| projection.value),
            redacted,
            text_truncated,
            text_projected,
        },
        redacted_field_count,
    }
}

fn history_summary(
    report_handle: String,
    report: &DetectionScanReport,
) -> Result<QuickDetectionHistoryItemDto, QuickDetectionApiError> {
    validate_report_metadata(report)?;
    Ok(QuickDetectionHistoryItemDto {
        report_handle,
        profile: profile_key(report.profile),
        started_at: report.started_at.to_rfc3339(),
        duration_ms: report.duration_ms,
        status: scan_status_key(report.status),
        overall_score: report.overall_score,
        module_count: report.modules.len(),
        summary: QuickDetectionSummaryDto::from(&report.summary),
    })
}

fn validate_report_metadata(report: &DetectionScanReport) -> Result<(), QuickDetectionApiError> {
    let summary = &report.summary;
    let summary_counts = [
        summary.critical,
        summary.high,
        summary.medium,
        summary.low,
        summary.info,
        summary.failed_modules,
        summary.not_applicable_modules,
        summary.error_modules,
        summary.cancelled_modules,
    ];
    if report.modules.is_empty()
        || report.modules.len() > MAX_PLAN_MODULES
        || report.duration_ms > MAX_PUBLIC_U64
        || report.dropped_progress_events > MAX_DROPPED_PROGRESS_EVENTS
        || summary_counts
            .iter()
            .any(|count| *count > MAX_SUMMARY_COUNT)
        || report
            .modules
            .iter()
            .any(|module| module.duration_ms > MAX_PUBLIC_U64)
    {
        return Err(QuickDetectionApiError::ReportUnavailable);
    }
    Ok(())
}

struct TextBudget {
    remaining: usize,
}

struct PublicTextProjection {
    value: String,
    redacted: bool,
    truncated: bool,
    projected: bool,
}

impl TextBudget {
    const fn new(remaining: usize) -> Self {
        Self { remaining }
    }

    fn take_public(
        &mut self,
        value: &str,
        field_limit: usize,
        multiline: bool,
        sensitive_literals: &[&str],
    ) -> PublicTextProjection {
        if is_sensitive_text(value, sensitive_literals) {
            return PublicTextProjection {
                value: REDACTED_QUICK_DETECTION_TEXT.to_owned(),
                redacted: true,
                truncated: false,
                projected: true,
            };
        }
        let limit = field_limit.min(self.remaining);
        let (output, projected, truncated) = normalize_bounded_text(value, limit, multiline);
        self.remaining = self.remaining.saturating_sub(output.len());
        PublicTextProjection {
            value: output,
            redacted: false,
            truncated,
            projected,
        }
    }
}

fn normalize_bounded_text(
    value: &str,
    maximum_bytes: usize,
    multiline: bool,
) -> (String, bool, bool) {
    let mut output = String::with_capacity(value.len().min(maximum_bytes));
    let mut projected = false;
    for character in value.chars() {
        let replacement =
            if !character.is_control() || multiline && matches!(character, '\n' | '\t') {
                character
            } else {
                projected = true;
                '\u{fffd}'
            };
        if output.len().saturating_add(replacement.len_utf8()) > maximum_bytes {
            return (output, true, true);
        }
        output.push(replacement);
    }
    (output, projected, false)
}

fn is_sensitive_text(value: &str, sensitive_literals: &[&str]) -> bool {
    value.contains(REDACTED_QUICK_DETECTION_TEXT)
        || contains_sensitive_material(value)
        || sensitive_literals
            .iter()
            .any(|literal| !literal.is_empty() && value.contains(*literal))
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

fn validate_handle(_subject: &'static str, value: &str) -> Result<(), QuickDetectionApiError> {
    if value.is_empty()
        || value.len() > MAX_HANDLE_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(QuickDetectionApiError::InvalidHandle);
    }
    Ok(())
}

fn unique_handle<T>(existing: &HashMap<String, T>) -> Result<String, QuickDetectionApiError> {
    for _ in 0..8 {
        let handle = Uuid::new_v4().to_string();
        if !existing.contains_key(&handle) {
            return Ok(handle);
        }
    }
    Err(QuickDetectionApiError::Capacity)
}

const fn profile_key(profile: DetectionScanProfile) -> &'static str {
    match profile {
        DetectionScanProfile::Selected => "selected",
        DetectionScanProfile::CompetitionTriage => "competition-triage",
    }
}

const fn category_key(category: DetectionCategory) -> &'static str {
    match category {
        DetectionCategory::Security => "security",
        DetectionCategory::Competition => "competition",
        DetectionCategory::Performance => "performance",
    }
}

const fn outcome_key(outcome: DetectionOutcome) -> &'static str {
    match outcome {
        DetectionOutcome::Passed => "passed",
        DetectionOutcome::Failed => "failed",
        DetectionOutcome::NotApplicable => "not-applicable",
        DetectionOutcome::Error => "error",
        DetectionOutcome::Cancelled => "cancelled",
    }
}

const fn severity_key(severity: DetectionSeverity) -> &'static str {
    match severity {
        DetectionSeverity::Info => "info",
        DetectionSeverity::Low => "low",
        DetectionSeverity::Medium => "medium",
        DetectionSeverity::High => "high",
        DetectionSeverity::Critical => "critical",
    }
}

const fn scan_status_key(status: DetectionScanStatus) -> &'static str {
    match status {
        DetectionScanStatus::Completed => "completed",
        DetectionScanStatus::Partial => "partial",
        DetectionScanStatus::Cancelled => "cancelled",
    }
}

fn kind_from_key(key: &str) -> Option<DetectionKind> {
    DetectionKind::ALL.into_iter().find(|kind| kind.id() == key)
}

#[cfg(test)]
mod tests {
    use lovelyres_core::target::TargetIdentity;

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

    fn report(scope: &BindingScope, id: &str, hostile: &str) -> DetectionScanReport {
        DetectionScanReport {
            id: id.to_owned(),
            target: scope.target.clone(),
            profile: DetectionScanProfile::Selected,
            started_at: serde_json::from_str("\"2026-08-24T00:00:00Z\"").unwrap(),
            duration_ms: 7,
            status: DetectionScanStatus::Completed,
            overall_score: 42,
            modules: vec![DetectionModuleReport {
                kind: DetectionKind::WebshellScan,
                outcome: DetectionOutcome::Failed,
                score: 42,
                findings: vec![DetectionFinding {
                    title: hostile.to_owned(),
                    description: hostile.to_owned(),
                    severity: DetectionSeverity::Critical,
                    recommendation: Some(hostile.to_owned()),
                    remediation: None,
                }],
                raw_text: hostile.to_owned(),
                raw_text_truncated: false,
                duration_ms: 5,
            }],
            summary: DetectionSummary {
                critical: 1,
                failed_modules: 1,
                ..DetectionSummary::default()
            },
            dropped_progress_events: 0,
        }
    }

    fn scan_entry(scope: BindingScope, plan_id: &str, total: usize, now: Instant) -> ScanEntry {
        ScanEntry {
            scope,
            plan_id: plan_id.to_owned(),
            cancellation: DetectionCancellation::default(),
            state: ScanState::Running,
            completed: 0,
            total,
            current_module: None,
            events: VecDeque::new(),
            next_sequence: 0,
            expires_at: now + RUNNING_SCAN_TTL,
        }
    }

    #[test]
    fn plan_input_is_closed_unique_and_bounded() {
        assert!(
            serde_json::from_value::<QuickDetectionPlanInput>(serde_json::json!({
                "profile": "selected",
                "moduleIds": ["ssh-audit"],
                "maximumFindingsPerModule": 200
            }))
            .is_ok()
        );
        assert!(
            serde_json::from_value::<QuickDetectionPlanInput>(serde_json::json!({
                "profile": "selected",
                "moduleIds": ["ssh-audit"],
                "maximumFindingsPerModule": 200,
                "command": "id"
            }))
            .is_err()
        );
        let selected = QuickDetectionPlanInput {
            profile: "selected".to_owned(),
            module_ids: vec!["ssh-audit".to_owned(), "port-scan".to_owned()],
            maximum_findings_per_module: 200,
        }
        .into_core()
        .unwrap();
        assert_eq!(selected.modules().len(), 2);
        assert!(
            QuickDetectionPlanInput {
                profile: "selected".to_owned(),
                module_ids: vec!["ssh-audit".to_owned(), "ssh-audit".to_owned()],
                maximum_findings_per_module: 200,
            }
            .into_core()
            .is_err()
        );
        assert!(
            QuickDetectionPlanInput {
                profile: "competition-triage".to_owned(),
                module_ids: vec!["ssh-audit".to_owned()],
                maximum_findings_per_module: 200,
            }
            .into_core()
            .is_err()
        );
        assert!(
            QuickDetectionPlanInput {
                profile: "arbitrary".to_owned(),
                module_ids: Vec::new(),
                maximum_findings_per_module: 200,
            }
            .into_core()
            .is_err()
        );
    }

    #[test]
    fn catalog_is_closed_and_triage_does_not_include_performance_modules() {
        let catalog = QuickDetectionApi::catalog();
        assert_eq!(catalog.modules.len(), 13);
        assert_eq!(catalog.profiles.len(), 2);
        assert_eq!(catalog.profiles[1].module_ids.len(), 6);
        for id in ["cpu-test", "memory-test", "disk-test", "network-test"] {
            assert!(!catalog.profiles[1].module_ids.contains(&id));
        }
    }

    #[test]
    fn event_polling_is_cursor_bounded_target_scoped_and_reports_truncation() {
        let now = Instant::now();
        let first = scope("server-one", 1);
        let second = scope("server-two", 2);
        let mut registry = Registry::default();
        registry.scans.insert(
            "scan-one".to_owned(),
            scan_entry(first.clone(), "plan-one", MAX_PLAN_MODULES, now),
        );
        for index in 0..=MAX_EVENTS_PER_SCAN {
            registry.record_event(
                &first,
                "scan-one",
                DetectionScanEvent::ModuleStarted {
                    scan_id: "plan-one".to_owned(),
                    module: DetectionKind::PortScan,
                    ordinal: index % MAX_PLAN_MODULES + 1,
                    total: MAX_PLAN_MODULES,
                },
            );
        }
        let page = registry
            .poll(&first, "scan-one", 0, MAX_POLL_EVENTS)
            .unwrap();
        assert!(page.events_truncated);
        assert_eq!(page.events.len(), MAX_POLL_EVENTS);
        assert!(matches!(
            registry.poll(&second, "scan-one", 0, 1),
            Err(QuickDetectionApiError::ScanUnavailable)
        ));
        assert!(matches!(
            registry.poll(&first, "scan-one", u64::MAX, 1),
            Err(QuickDetectionApiError::InvalidBounds)
        ));
    }

    #[test]
    fn cancellation_is_idempotent_and_expiry_cancels_orphaned_work() {
        let now = Instant::now();
        let current = scope("server-one", 1);
        let mut registry = Registry::default();
        registry.scans.insert(
            "scan-one".to_owned(),
            scan_entry(current.clone(), "plan-one", 1, now),
        );
        let token = registry.scans["scan-one"].cancellation.clone();
        registry.cancel(&current, "scan-one").unwrap();
        registry.cancel(&current, "scan-one").unwrap();
        assert!(token.is_cancelled());
        registry.scans.get_mut("scan-one").unwrap().expires_at = now;
        registry.prune(now);
        assert!(!registry.scans.contains_key("scan-one"));
    }

    #[test]
    fn report_handles_are_opaque_target_scoped_bounded_and_hostile_text_is_plain() {
        let now = Instant::now();
        let first = scope("server-one", 1);
        let second = scope("server-two", 1);
        let hostile = "</script><img src=x onerror=steal()>";
        let mut registry = Registry::default();
        let handle = registry
            .register_report(
                first.clone(),
                report(&first, "core-report-id", hostile),
                now,
            )
            .unwrap();
        assert!(!handle.contains("server-one"));
        assert!(!handle.contains("core-report-id"));
        let dto = registry.report(&first, &handle, now).unwrap();
        let json = serde_json::to_string(&dto).unwrap();
        assert!(json.contains(hostile));
        assert!(!json.contains("session-one"));
        assert!(!json.contains("generation"));
        assert!(matches!(
            registry.report(&second, &handle, now),
            Err(QuickDetectionApiError::ReportUnavailable)
        ));

        let oversized = "界".repeat(MAX_REPORT_TEXT_BUDGET);
        let projected = project_report(
            "opaque".to_owned(),
            &report(&first, "large", &oversized),
            &first.sensitive_literals(),
        )
        .unwrap();
        let bytes = serde_json::to_vec(&projected).unwrap().len();
        assert!(bytes <= MAX_REPORT_BYTES);
        assert!(projected.modules[0].raw_text_truncated);
        assert!(projected.truncated);
    }

    #[test]
    fn report_and_history_projection_redact_credentials_uri_scope_literals_and_c0() {
        let current = scope("server-one", 7);
        let literals = current.sensitive_literals();
        let sensitive = format!(
            "password=hunter https://user:pass@example.test {} {} {} {}",
            literals[0], literals[1], literals[2], literals[3]
        );
        let projected = project_report(
            "report-handle".to_owned(),
            &report(&current, "sensitive", &sensitive),
            &literals,
        )
        .unwrap();
        let json = serde_json::to_string(&projected).unwrap();
        assert_eq!(projected.redacted_field_count, 4);
        assert!(projected.text_projected);
        assert!(!projected.truncated);
        assert_eq!(projected.modules[0].raw_text, REDACTED_QUICK_DETECTION_TEXT);
        assert!(projected.modules[0].raw_text_redacted);
        assert!(projected.modules[0].raw_text_projected);
        assert!(projected.modules[0].findings[0].redacted);
        assert!(projected.modules[0].findings[0].text_projected);
        assert!(!json.contains("hunter"));
        assert!(!json.contains("user:pass"));
        for literal in literals {
            assert!(!json.contains(literal));
        }

        let controlled = "<script>plain()</script>\0line\nnext\u{7f}";
        let projected = project_report(
            "report-handle".to_owned(),
            &report(&current, "controlled", controlled),
            &[],
        )
        .unwrap();
        let json = serde_json::to_string(&projected).unwrap();
        assert!(json.contains("<script>plain()</script>"));
        assert!(!json.contains("\\u0000"));
        assert!(!json.contains("\\u007f"));
        assert!(projected.text_projected);
        assert!(!projected.truncated);

        let history = history_summary(
            "report-handle".to_owned(),
            &report(&current, "history", &sensitive),
        )
        .unwrap();
        let history_json = serde_json::to_string(&history).unwrap();
        assert!(!history_json.contains("hunter"));
        assert!(!history_json.contains("user:pass"));
    }

    #[test]
    fn close_binding_cancels_scans_reclaims_reports_and_blocks_late_resurrection() {
        let now = Instant::now();
        let closed = scope("server-one", 1);
        let retained = scope("server-two", 1);
        let mut registry = Registry::default();
        registry.scans.insert(
            "closed-scan".to_owned(),
            scan_entry(closed.clone(), "closed-plan", 1, now),
        );
        registry.scans.insert(
            "retained-scan".to_owned(),
            scan_entry(retained.clone(), "retained-plan", 1, now),
        );
        let closed_token = registry.scans["closed-scan"].cancellation.clone();
        let retained_token = registry.scans["retained-scan"].cancellation.clone();
        registry
            .register_report(
                closed.clone(),
                report(&closed, "closed-report", "plain"),
                now,
            )
            .unwrap();
        registry
            .register_report(
                retained.clone(),
                report(&retained, "retained-report", "plain"),
                now,
            )
            .unwrap();
        let retained_bytes = registry
            .reports
            .values()
            .find(|entry| entry.scope == retained)
            .unwrap()
            .bytes;

        registry.close_binding(&closed.binding_handle);
        assert!(closed_token.is_cancelled());
        assert!(!retained_token.is_cancelled());
        assert!(!registry.scans.contains_key("closed-scan"));
        assert!(registry.scans.contains_key("retained-scan"));
        assert!(
            registry
                .reports
                .values()
                .all(|entry| entry.scope == retained)
        );
        assert_eq!(registry.report_bytes, retained_bytes);

        registry.record_event(
            &closed,
            "closed-scan",
            DetectionScanEvent::ScanFinished {
                scan_id: "closed-plan".to_owned(),
                status: DetectionScanStatus::Completed,
                total: 1,
            },
        );
        assert!(matches!(
            registry.finish_report(
                &closed,
                "closed-scan",
                report(&closed, "closed-plan", "late"),
                now,
            ),
            Err(QuickDetectionApiError::ScanUnavailable)
        ));
        assert!(
            registry
                .reports
                .values()
                .all(|entry| entry.scope == retained)
        );
    }

    #[test]
    fn scan_capacity_target_epoch_and_report_ttl_fail_closed() {
        let now = Instant::now();
        let mut registry = Registry::default();
        for index in 0..MAX_SCANS {
            let current = scope(&format!("server-{index}"), 1);
            registry
                .insert_scan(
                    current,
                    format!("plan-{index}"),
                    1,
                    DetectionCancellation::default(),
                    now,
                )
                .unwrap();
        }
        let overflow = scope("overflow", 1);
        assert!(matches!(
            registry.insert_scan(
                overflow,
                "overflow-plan".to_owned(),
                1,
                DetectionCancellation::default(),
                now,
            ),
            Err(QuickDetectionApiError::Capacity)
        ));
        registry.close_binding("binding-server-0");
        let replacement = scope("replacement", 1);
        registry
            .insert_scan(
                replacement,
                "replacement-plan".to_owned(),
                1,
                DetectionCancellation::default(),
                now,
            )
            .unwrap();

        let old_epoch = scope("same-server", 1);
        let new_epoch = scope("same-server", 2);
        let handle = registry
            .register_report(
                old_epoch.clone(),
                report(&old_epoch, "epoch-report", "plain"),
                now,
            )
            .unwrap();
        assert!(matches!(
            registry.report(&new_epoch, &handle, now),
            Err(QuickDetectionApiError::ReportUnavailable)
        ));
        registry.reports.get_mut(&handle).unwrap().expires_at = now;
        registry.prune(now);
        assert!(!registry.reports.contains_key(&handle));
        assert_eq!(
            registry.report_bytes,
            registry
                .reports
                .values()
                .map(|entry| entry.bytes)
                .sum::<usize>()
        );

        let mut epoch_registry = Registry::default();
        epoch_registry.scans.insert(
            "old-epoch".to_owned(),
            scan_entry(old_epoch.clone(), "old-plan", 1, now),
        );
        epoch_registry.scans.insert(
            "new-epoch".to_owned(),
            scan_entry(new_epoch.clone(), "new-plan", 1, now),
        );
        let old_token = epoch_registry.scans["old-epoch"].cancellation.clone();
        let new_token = epoch_registry.scans["new-epoch"].cancellation.clone();
        epoch_registry.close_scope(&old_epoch);
        assert!(old_token.is_cancelled());
        assert!(!new_token.is_cancelled());
        assert!(!epoch_registry.scans.contains_key("old-epoch"));
        assert!(epoch_registry.scans.contains_key("new-epoch"));
    }

    #[test]
    fn registry_capacity_evicts_old_reports_and_never_exposes_sensitive_debug_fields() {
        let now = Instant::now();
        let current = scope("server-one", 1);
        let mut registry = Registry::default();
        for index in 0..=MAX_REPORTS {
            registry
                .register_report(
                    current.clone(),
                    report(&current, &format!("report-{index}"), "plain"),
                    now + Duration::from_millis(index as u64),
                )
                .unwrap();
        }
        assert_eq!(registry.reports.len(), MAX_REPORTS);
        assert!(registry.report_bytes <= MAX_REPORT_REGISTRY_BYTES);
        let debug = format!("{registry:?}");
        assert!(!debug.contains("server-one"));
        assert!(!debug.contains("session-one"));
        assert!(!debug.contains("plain"));
    }

    #[test]
    fn public_source_has_no_generic_command_path_or_remediation_surface() {
        let source = include_str!("quick_detection_api.rs");
        for forbidden in [
            ["shell", ".execute"].concat(),
            ["inner", "HTML"].concat(),
            ["Detection", "RemediationRequest"].concat(),
            ["DangerousConfirmation", "::approve"].concat(),
            ["execute", "_changes"].concat(),
            ["execute", "_and_verify"].concat(),
        ] {
            assert!(
                !source.contains(&forbidden),
                "unexpected surface: {forbidden}"
            );
        }
        let error = QuickDetectionApiError::InvalidInput;
        assert_eq!(error.to_string(), "the quick-detection request is invalid");
        assert!(!format!("{error:?}").contains("password=hunter"));
    }
}
