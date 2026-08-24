use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::Arc,
};

use gpui::{
    AnyElement, ClipboardItem, Context, Entity, IntoElement, Render, ScrollHandle, SharedString,
    Subscription, Window, div, prelude::*, px,
};
use gpui_component::{
    Disableable, Sizable,
    button::ButtonVariants,
    input::{Input, InputEvent, InputState},
    scroll::ScrollableElement,
};
use lovelyres_core::{
    BackendServices, CoreError, CoreResult,
    baseline::{BaselineChangePlan, BaselineOperationOutcome},
    compliance::{ComplianceRuleStatus, ComplianceStandard, generate_compliance_summary},
    detection::{
        DetectionCancellation, DetectionKind, DetectionModuleReport, DetectionOutcome,
        DetectionRemediation, DetectionRemediationRequest, DetectionScanEvent, DetectionScanPlan,
        DetectionScanReport, DetectionScanRequest, DetectionScanStatus, DetectionSeverity,
        detection_event_channel, detection_report_json,
    },
    operations::{DangerousConfirmation, OperationPlan, OperationState},
    sftp::SftpPlannedOperation,
    ssh::BoundSshSession,
    target::TargetGuard,
};

use crate::{app::SharedAppState, runtime::TokioBridge, theme::ThemeTokens};

const HISTORY_LIMIT: usize = 8;
const HISTORY_RAW_CHARS: usize = 8 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuickDetectionBinding {
    connection_id: String,
    session_id: String,
    target: TargetGuard,
}

impl QuickDetectionBinding {
    fn from_session(session: &BoundSshSession) -> Self {
        Self {
            connection_id: session.connection_id().to_owned(),
            session_id: session.session_id().to_owned(),
            target: session.target().clone(),
        }
    }

    fn capture(shared: &SharedAppState) -> Option<Self> {
        shared
            .active_ssh
            .as_ref()
            .map(|active| Self::from_session(&active.session))
    }

    fn label(&self) -> String {
        format!(
            "目标 {} · generation {}",
            self.target.identity.as_str(),
            self.target.generation
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ScanLease {
    activation_generation: u64,
    request_id: u64,
    binding: QuickDetectionBinding,
    plan_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RemediationLease {
    activation_generation: u64,
    request_id: u64,
    binding: QuickDetectionBinding,
    module: DetectionKind,
    remediation: DetectionRemediation,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum ResultFilter {
    #[default]
    All,
    Risk,
    Passed,
    Error,
    NotApplicable,
}

impl ResultFilter {
    const ALL: [Self; 5] = [
        Self::All,
        Self::Risk,
        Self::Passed,
        Self::Error,
        Self::NotApplicable,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::All => "全部",
            Self::Risk => "风险",
            Self::Passed => "通过",
            Self::Error => "错误/取消",
            Self::NotApplicable => "N/A",
        }
    }

    const fn accepts(self, outcome: DetectionOutcome) -> bool {
        match self {
            Self::All => true,
            Self::Risk => matches!(outcome, DetectionOutcome::Failed),
            Self::Passed => matches!(outcome, DetectionOutcome::Passed),
            Self::Error => matches!(
                outcome,
                DetectionOutcome::Error | DetectionOutcome::Cancelled
            ),
            Self::NotApplicable => matches!(outcome, DetectionOutcome::NotApplicable),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum DetailMode {
    #[default]
    Findings,
    RawText,
    Compliance,
}

#[derive(Debug)]
pub struct QuickDetectionModel {
    active: bool,
    activation_generation: u64,
    next_request_id: u64,
    binding: Option<QuickDetectionBinding>,
    selected_modules: BTreeSet<DetectionKind>,
    plan: Option<DetectionScanPlan>,
    running: bool,
    active_lease: Option<ScanLease>,
    completed: usize,
    total: usize,
    current_task: Option<DetectionKind>,
    module_progress: BTreeMap<DetectionKind, DetectionOutcome>,
    current_report: Option<DetectionScanReport>,
    history: VecDeque<DetectionScanReport>,
    selected_result: Option<DetectionKind>,
    query: String,
    filter: ResultFilter,
    detail_mode: DetailMode,
    compliance_standard: ComplianceStandard,
    next_remediation_request_id: u64,
    active_remediation: Option<RemediationLease>,
}

impl Default for QuickDetectionModel {
    fn default() -> Self {
        Self {
            active: false,
            activation_generation: 0,
            next_request_id: 0,
            binding: None,
            selected_modules: DetectionKind::COMPETITION_TRIAGE.into_iter().collect(),
            plan: None,
            running: false,
            active_lease: None,
            completed: 0,
            total: 0,
            current_task: None,
            module_progress: BTreeMap::new(),
            current_report: None,
            history: VecDeque::new(),
            selected_result: None,
            query: String::new(),
            filter: ResultFilter::All,
            detail_mode: DetailMode::Findings,
            compliance_standard: ComplianceStandard::Cis,
            next_remediation_request_id: 0,
            active_remediation: None,
        }
    }
}

impl QuickDetectionModel {
    pub fn activate(&mut self, binding: Option<QuickDetectionBinding>) {
        self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
        self.active = true;
        self.rebind(binding);
    }

    pub fn deactivate(&mut self) {
        self.active = false;
        self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
        self.running = false;
        self.active_lease = None;
        self.active_remediation = None;
        self.current_task = None;
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    fn rebind(&mut self, binding: Option<QuickDetectionBinding>) {
        if self.binding == binding {
            return;
        }
        self.binding = binding;
        self.plan = None;
        self.running = false;
        self.active_lease = None;
        self.completed = 0;
        self.total = 0;
        self.current_task = None;
        self.module_progress.clear();
        self.current_report = None;
        self.selected_result = None;
        self.active_remediation = None;
    }

    fn toggle_module(&mut self, kind: DetectionKind) {
        if !self.selected_modules.remove(&kind) {
            self.selected_modules.insert(kind);
        }
        self.plan = None;
    }

    fn select_all(&mut self) {
        self.selected_modules = DetectionKind::ALL.into_iter().collect();
        self.plan = None;
    }

    fn select_triage(&mut self) {
        self.selected_modules = DetectionKind::COMPETITION_TRIAGE.into_iter().collect();
        self.plan = None;
    }

    fn set_plan(&mut self, plan: DetectionScanPlan) -> bool {
        if !self.active
            || self.binding.as_ref().map(|binding| &binding.target) != Some(plan.target())
        {
            return false;
        }
        self.plan = Some(plan);
        true
    }

    fn begin_scan(&mut self) -> CoreResult<ScanLease> {
        if !self.active {
            return Err(CoreError::Validation {
                subject: "quick detection page",
                message: "page is not active".to_owned(),
            });
        }
        if self.running {
            return Err(CoreError::Validation {
                subject: "quick detection scan",
                message: "a scan is already running".to_owned(),
            });
        }
        let binding = self.binding.clone().ok_or(CoreError::NoActiveTarget)?;
        let plan = self.plan.as_ref().ok_or(CoreError::Validation {
            subject: "quick detection plan",
            message: "create a plan before running".to_owned(),
        })?;
        if plan.target() != &binding.target {
            return Err(CoreError::Validation {
                subject: "quick detection plan",
                message: "plan target no longer matches the active SSH target".to_owned(),
            });
        }
        self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
        let lease = ScanLease {
            activation_generation: self.activation_generation,
            request_id: self.next_request_id,
            binding,
            plan_id: plan.id().to_owned(),
        };
        self.running = true;
        self.active_lease = Some(lease.clone());
        self.completed = 0;
        self.total = plan.modules().len();
        self.current_task = None;
        self.module_progress.clear();
        Ok(lease)
    }

    fn accepts(&self, lease: &ScanLease, binding: Option<&QuickDetectionBinding>) -> bool {
        self.active
            && self.activation_generation == lease.activation_generation
            && binding == Some(&lease.binding)
            && self.active_lease.as_ref() == Some(lease)
    }

    fn apply_event(
        &mut self,
        lease: &ScanLease,
        binding: Option<&QuickDetectionBinding>,
        event: DetectionScanEvent,
    ) -> bool {
        if !self.accepts(lease, binding) {
            return false;
        }
        match event {
            DetectionScanEvent::ModuleStarted {
                scan_id,
                module,
                total,
                ..
            } if scan_id == lease.plan_id => {
                self.current_task = Some(module);
                self.total = total;
            }
            DetectionScanEvent::ModuleFinished {
                scan_id,
                module,
                outcome,
                completed,
                total,
            } if scan_id == lease.plan_id => {
                self.module_progress.insert(module, outcome);
                self.completed = completed;
                self.total = total;
            }
            DetectionScanEvent::ScanFinished { scan_id, total, .. } if scan_id == lease.plan_id => {
                self.completed = total;
                self.total = total;
                self.current_task = None;
            }
            _ => return false,
        }
        true
    }

    fn finish_scan(
        &mut self,
        lease: &ScanLease,
        binding: Option<&QuickDetectionBinding>,
        report: DetectionScanReport,
    ) -> bool {
        if report.id != lease.plan_id
            || report.target != lease.binding.target
            || !self.accepts(lease, binding)
        {
            return false;
        }
        self.running = false;
        self.active_lease = None;
        self.completed = report.modules.len();
        self.total = report.modules.len();
        self.current_task = None;
        self.selected_result = report.modules.first().map(|module| module.kind);
        self.active_remediation = None;
        self.history.push_front(compact_history(&report));
        self.history.truncate(HISTORY_LIMIT);
        self.current_report = Some(report);
        true
    }

    fn reject_scan(&mut self, lease: &ScanLease, binding: Option<&QuickDetectionBinding>) -> bool {
        if !self.accepts(lease, binding) {
            return false;
        }
        self.running = false;
        self.active_lease = None;
        self.current_task = None;
        true
    }

    fn set_query(&mut self, value: impl Into<String>) {
        self.query = value.into().chars().take(512).collect();
    }

    fn filtered_modules(&self) -> Vec<&DetectionModuleReport> {
        let Some(report) = &self.current_report else {
            return Vec::new();
        };
        let query = self.query.trim().to_lowercase();
        report
            .modules
            .iter()
            .filter(|module| self.filter.accepts(module.outcome))
            .filter(|module| {
                query.is_empty()
                    || module.kind.id().contains(&query)
                    || module.kind.label().to_lowercase().contains(&query)
                    || module.raw_text.to_lowercase().contains(&query)
                    || module.findings.iter().any(|finding| {
                        finding.title.to_lowercase().contains(&query)
                            || finding.description.to_lowercase().contains(&query)
                    })
            })
            .collect()
    }

    fn selected_report(&self) -> Option<&DetectionModuleReport> {
        let selected = self.selected_result?;
        self.current_report
            .as_ref()?
            .modules
            .iter()
            .find(|module| module.kind == selected)
    }

    fn select_result(&mut self, kind: DetectionKind) {
        if self
            .current_report
            .as_ref()
            .is_some_and(|report| report.modules.iter().any(|module| module.kind == kind))
        {
            if self.selected_result != Some(kind) {
                self.active_remediation = None;
            }
            self.selected_result = Some(kind);
        }
    }

    fn load_history(&mut self, id: &str) -> bool {
        let Some(report) = self.history.iter().find(|report| report.id == id).cloned() else {
            return false;
        };
        if self.binding.as_ref().map(|binding| &binding.target) != Some(&report.target) {
            return false;
        }
        self.selected_result = report.modules.first().map(|module| module.kind);
        self.active_remediation = None;
        self.current_report = Some(report);
        true
    }

    fn begin_remediation(
        &mut self,
        remediation: DetectionRemediation,
    ) -> CoreResult<RemediationLease> {
        if !self.active {
            return Err(CoreError::Validation {
                subject: "quick detection remediation",
                message: "page is not active".to_owned(),
            });
        }
        if self.running {
            return Err(CoreError::Validation {
                subject: "quick detection remediation",
                message: "wait for the active scan to finish".to_owned(),
            });
        }
        if self.active_remediation.is_some() {
            return Err(CoreError::Validation {
                subject: "quick detection remediation",
                message: "another remediation request is active".to_owned(),
            });
        }
        let binding = self.binding.clone().ok_or(CoreError::NoActiveTarget)?;
        let module = self.selected_result.ok_or(CoreError::Validation {
            subject: "quick detection remediation",
            message: "select a detection module first".to_owned(),
        })?;
        let report = self.current_report.as_ref().ok_or(CoreError::Validation {
            subject: "quick detection remediation",
            message: "no current target report is loaded".to_owned(),
        })?;
        if report.target != binding.target
            || !report.modules.iter().any(|report| {
                report.kind == module
                    && report
                        .findings
                        .iter()
                        .any(|finding| finding.remediation == Some(remediation))
            })
        {
            return Err(CoreError::Validation {
                subject: "quick detection remediation",
                message: "the selected finding no longer belongs to the active target".to_owned(),
            });
        }
        self.next_remediation_request_id = self.next_remediation_request_id.wrapping_add(1).max(1);
        let lease = RemediationLease {
            activation_generation: self.activation_generation,
            request_id: self.next_remediation_request_id,
            binding,
            module,
            remediation,
        };
        self.active_remediation = Some(lease.clone());
        Ok(lease)
    }

    fn accepts_remediation(
        &self,
        lease: &RemediationLease,
        binding: Option<&QuickDetectionBinding>,
    ) -> bool {
        self.active
            && self.activation_generation == lease.activation_generation
            && binding == Some(&lease.binding)
            && self.active_remediation.as_ref() == Some(lease)
            && self.selected_result == Some(lease.module)
            && self.current_report.as_ref().is_some_and(|report| {
                report.target == lease.binding.target
                    && report.modules.iter().any(|module| {
                        module.kind == lease.module
                            && module
                                .findings
                                .iter()
                                .any(|finding| finding.remediation == Some(lease.remediation))
                    })
            })
    }

    fn finish_remediation(
        &mut self,
        lease: &RemediationLease,
        binding: Option<&QuickDetectionBinding>,
    ) -> bool {
        if !self.accepts_remediation(lease, binding) {
            return false;
        }
        self.active_remediation = None;
        true
    }

    fn invalidate_remediation(&mut self) {
        self.active_remediation = None;
    }

    fn apply_persisted_history(
        &mut self,
        activation_generation: u64,
        binding: &QuickDetectionBinding,
        reports: Vec<DetectionScanReport>,
    ) -> bool {
        if !self.active
            || self.activation_generation != activation_generation
            || self.binding.as_ref() != Some(binding)
        {
            return false;
        }
        self.history = reports
            .into_iter()
            .filter(|report| report.target == binding.target)
            .take(HISTORY_LIMIT)
            .collect();
        true
    }
}

fn compact_history(report: &DetectionScanReport) -> DetectionScanReport {
    let mut report = report.clone();
    for module in &mut report.modules {
        let raw_text = std::mem::take(&mut module.raw_text);
        let mut chars = raw_text.chars();
        module.raw_text = chars.by_ref().take(HISTORY_RAW_CHARS).collect();
        module.raw_text_truncated |= chars.next().is_some();
    }
    report
}

#[derive(Debug)]
struct PendingDetectionRemediation {
    lease: RemediationLease,
    remediation: DetectionRemediation,
    plan: DetectionRemediationPlan,
}

#[derive(Debug)]
enum DetectionRemediationPlan {
    Baseline(Box<BaselineChangePlan>),
    Sftp(Box<SftpPlannedOperation>),
}

impl DetectionRemediationPlan {
    fn definition(&self) -> &OperationPlan {
        match self {
            Self::Baseline(plan) => plan.definition(),
            Self::Sftp(plan) => plan.definition(),
        }
    }

    fn change_summary(&self) -> String {
        match self {
            Self::Baseline(plan) => plan
                .changes()
                .iter()
                .map(|change| {
                    format!(
                        "{}：{} → {}",
                        change.item_id,
                        change.before.label(),
                        change.after
                    )
                })
                .collect::<Vec<_>>()
                .join("；"),
            Self::Sftp(plan) => {
                let metadata = &plan.definition().metadata;
                match (
                    metadata.get("path"),
                    metadata.get("expected-mode"),
                    metadata.get("mode"),
                ) {
                    (Some(path), Some(expected), Some(mode)) => {
                        format!("{path}：权限 {expected} → {mode}")
                    }
                    _ => plan.definition().summary.clone(),
                }
            }
        }
    }
}

#[derive(Debug)]
struct DetectionRemediationOutcome {
    verified_changes: usize,
}

async fn prepare_remediation_plan(
    services: Arc<BackendServices>,
    session: BoundSshSession,
    request: DetectionRemediationRequest,
) -> CoreResult<DetectionRemediationPlan> {
    match request {
        DetectionRemediationRequest::Baseline {
            request,
            reload_policy,
        } => services
            .baseline()
            .plan_changes(&session, vec![request], reload_policy)
            .await
            .map(Box::new)
            .map(DetectionRemediationPlan::Baseline),
        DetectionRemediationRequest::Sftp(mutation) => {
            let bound = services
                .sftp()
                .bind_session(session.target().clone(), session.session_id())
                .await?;
            services
                .sftp()
                .plan(&bound, mutation)
                .map(Box::new)
                .map(DetectionRemediationPlan::Sftp)
        }
    }
}

async fn execute_remediation_plan(
    services: Arc<BackendServices>,
    session: BoundSshSession,
    plan: DetectionRemediationPlan,
) -> CoreResult<DetectionRemediationOutcome> {
    let confirmation = DangerousConfirmation::approve(plan.definition());
    match plan {
        DetectionRemediationPlan::Baseline(plan) => services
            .baseline()
            .execute_changes(&session, *plan, confirmation)
            .await
            .map(
                |outcome: BaselineOperationOutcome| DetectionRemediationOutcome {
                    verified_changes: outcome.record.changes.len(),
                },
            ),
        DetectionRemediationPlan::Sftp(mut operation) => {
            operation.confirm(confirmation)?;
            let result = operation.execute_and_verify().await;
            let needs_restore = result
                .as_ref()
                .is_ok_and(|verification| !verification.passed)
                || operation.state() == OperationState::VerificationFailed;
            if needs_restore {
                operation.restore().await?;
                return Err(CoreError::Validation {
                    subject: "detection remediation verification",
                    message: "verification failed; the captured permission mode was restored"
                        .to_owned(),
                });
            }
            result.map(|_| DetectionRemediationOutcome {
                verified_changes: 1,
            })
        }
    }
}

pub struct QuickDetectionPage {
    services: Arc<BackendServices>,
    tokio: Arc<TokioBridge>,
    shared: Entity<SharedAppState>,
    model: QuickDetectionModel,
    search_input: Entity<InputState>,
    page_scroll: ScrollHandle,
    module_scroll: ScrollHandle,
    cancellation: Option<DetectionCancellation>,
    remediation_plan_abort: Option<tokio::task::AbortHandle>,
    remediation_execution_active: bool,
    pending_remediation: Option<PendingDetectionRemediation>,
    error: Option<SharedString>,
    notice: Option<SharedString>,
    _subscriptions: Vec<Subscription>,
}

impl QuickDetectionPage {
    pub fn new(
        services: Arc<BackendServices>,
        tokio: Arc<TokioBridge>,
        shared: Entity<SharedAppState>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let search_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("筛选模块、发现或原始文本…"));
        let subscriptions = vec![
            cx.subscribe_in(
                &search_input,
                window,
                |page, input, event: &InputEvent, _, cx| {
                    if matches!(event, InputEvent::Change) {
                        page.model.set_query(input.read(cx).value().to_string());
                        cx.notify();
                    }
                },
            ),
            cx.observe(&shared, |page, _, cx| page.handle_shared_change(cx)),
        ];
        Self {
            services,
            tokio,
            shared,
            model: QuickDetectionModel::default(),
            search_input,
            page_scroll: ScrollHandle::new(),
            module_scroll: ScrollHandle::new(),
            cancellation: None,
            remediation_plan_abort: None,
            remediation_execution_active: false,
            pending_remediation: None,
            error: None,
            notice: None,
            _subscriptions: subscriptions,
        }
    }

    pub fn activate(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.model.activate(self.current_binding(cx));
        self.load_persisted_history(cx);
        self.search_input
            .update(cx, |input, cx| input.focus(window, cx));
        if self.model.binding.is_none() {
            self.error = Some("未连接目标，无法创建快速检测计划".into());
        }
        cx.notify();
    }

    pub fn deactivate(&mut self, cx: &mut Context<Self>) {
        self.cancel_active();
        self.invalidate_remediation_plan();
        self.model.deactivate();
        cx.notify();
    }

    pub const fn is_active(&self) -> bool {
        self.model.is_active()
    }

    pub fn current_report_for(&self, target: &TargetGuard) -> Option<DetectionScanReport> {
        self.model
            .current_report
            .as_ref()
            .filter(|report| report.target == *target)
            .cloned()
    }

    fn current_binding(&self, cx: &Context<Self>) -> Option<QuickDetectionBinding> {
        QuickDetectionBinding::capture(self.shared.read(cx))
    }

    fn current_session(&self, cx: &Context<Self>) -> Option<BoundSshSession> {
        self.shared
            .read(cx)
            .active_ssh
            .as_ref()
            .map(|active| active.session.clone())
    }

    fn handle_shared_change(&mut self, cx: &mut Context<Self>) {
        if !self.model.is_active() {
            return;
        }
        let binding = self.current_binding(cx);
        if self.model.binding == binding {
            return;
        }
        self.cancel_active();
        self.invalidate_remediation_plan();
        self.model.rebind(binding);
        self.load_persisted_history(cx);
        self.error = if self.model.binding.is_some() {
            None
        } else {
            Some("活动 SSH 目标已断开，扫描已取消".into())
        };
        self.notice = Some("目标已变化；旧计划与晚到结果均已作废".into());
        cx.notify();
    }

    fn toggle_module(&mut self, kind: DetectionKind, cx: &mut Context<Self>) {
        if self.model.running {
            return;
        }
        self.model.toggle_module(kind);
        self.notice = Some("模块选择已变化，请重新生成不可变计划".into());
        cx.notify();
    }

    fn select_all(&mut self, cx: &mut Context<Self>) {
        if self.model.running {
            return;
        }
        self.model.select_all();
        self.notice = Some(format!("已选择全部 {} 项封闭检测", DetectionKind::ALL.len()).into());
        cx.notify();
    }

    fn select_triage(&mut self, cx: &mut Context<Self>) {
        if self.model.running {
            return;
        }
        self.model.select_triage();
        self.notice = Some("已选择 6 项首分钟只读预设".into());
        cx.notify();
    }

    fn create_plan(&mut self, cx: &mut Context<Self>) {
        if self.model.running {
            return;
        }
        let Some(session) = self.current_session(cx) else {
            self.error = Some("未连接目标，无法创建计划".into());
            cx.notify();
            return;
        };
        let request = DetectionScanRequest::selected(self.model.selected_modules.iter().copied());
        let plan =
            request.and_then(|request| self.services.detection().plan_scan(&session, request));
        match plan {
            Ok(plan) => {
                let summary = plan.summary();
                if self.model.set_plan(plan) {
                    self.error = None;
                    self.notice = Some(summary.into());
                }
            }
            Err(error) => self.error = Some(format!("无法创建检测计划：{error}").into()),
        }
        cx.notify();
    }

    fn start_scan(&mut self, cx: &mut Context<Self>) {
        if self.remediation_plan_abort.is_some()
            || self.pending_remediation.is_some()
            || self.remediation_execution_active
        {
            self.error = Some("请先完成或取消当前修复计划".into());
            cx.notify();
            return;
        }
        let Some(session) = self.current_session(cx) else {
            self.error = Some("未连接目标，无法执行计划".into());
            cx.notify();
            return;
        };
        let plan = match self.model.plan.clone() {
            Some(plan) => plan,
            None => {
                self.error = Some("请先生成计划并核对摘要".into());
                cx.notify();
                return;
            }
        };
        let lease = match self.model.begin_scan() {
            Ok(lease) => lease,
            Err(error) => {
                self.error = Some(format!("无法开始检测：{error}").into());
                cx.notify();
                return;
            }
        };
        let (events, receiver) = match detection_event_channel(16) {
            Ok(channel) => channel,
            Err(error) => {
                let _ = self
                    .model
                    .reject_scan(&lease, self.current_binding(cx).as_ref());
                self.error = Some(format!("无法创建进度通道：{error}").into());
                return;
            }
        };
        let cancellation = DetectionCancellation::default();
        self.cancellation = Some(cancellation.clone());
        self.error = None;
        self.notice =
            Some("检测已启动；磁盘项仅写入并清理随机临时文件，取消会终止未完成命令".into());

        let event_lease = lease.clone();
        cx.spawn(async move |page, cx| {
            while let Some(event) = receiver.recv().await {
                let _ = cx.update(|cx| {
                    if let Some(page) = page.upgrade() {
                        page.update(cx, |page, cx| {
                            let binding = page.current_binding(cx);
                            if page
                                .model
                                .apply_event(&event_lease, binding.as_ref(), event)
                            {
                                cx.notify();
                            }
                        });
                    }
                });
            }
        })
        .detach();

        let service = self.services.detection().clone();
        let task = self
            .tokio
            .spawn(async move { service.run_scan(&session, plan, cancellation, events).await });
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_scan(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_scan(
        &mut self,
        lease: ScanLease,
        result: Result<CoreResult<DetectionScanReport>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            return;
        }
        self.cancellation = None;
        match result {
            Ok(Ok(report)) => {
                let status = report.status;
                if self.model.finish_scan(&lease, binding.as_ref(), report) {
                    self.notice = Some(
                        match status {
                            DetectionScanStatus::Completed => "检测完成".to_owned(),
                            DetectionScanStatus::Partial => {
                                "检测部分完成；错误模块不参与可信评分".to_owned()
                            }
                            DetectionScanStatus::Cancelled => {
                                "检测已取消；部分结果已保存到当前目标的便携历史".to_owned()
                            }
                        }
                        .into(),
                    );
                }
            }
            Ok(Err(error)) => {
                let _ = self.model.reject_scan(&lease, binding.as_ref());
                self.error = Some(format!("检测失败：{error}").into());
            }
            Err(error) if error.is_cancelled() => {
                let _ = self.model.reject_scan(&lease, binding.as_ref());
            }
            Err(error) => {
                let _ = self.model.reject_scan(&lease, binding.as_ref());
                self.error = Some(format!("检测任务失败：{error}").into());
            }
        }
        cx.notify();
    }

    fn cancel_active(&mut self) {
        if let Some(cancellation) = self.cancellation.take() {
            cancellation.cancel();
        }
    }

    fn invalidate_remediation_plan(&mut self) {
        if let Some(abort) = self.remediation_plan_abort.take() {
            abort.abort();
        }
        self.pending_remediation = None;
        self.model.invalidate_remediation();
    }

    fn cancel_scan(&mut self, cx: &mut Context<Self>) {
        if let Some(cancellation) = &self.cancellation {
            cancellation.cancel();
            self.notice = Some("正在取消；已发出的封闭检测命令将通过取消令牌终止".into());
            cx.notify();
        }
    }

    fn select_result(&mut self, kind: DetectionKind, cx: &mut Context<Self>) {
        if self.model.selected_result != Some(kind) {
            self.invalidate_remediation_plan();
        }
        self.model.select_result(kind);
        cx.notify();
    }

    fn load_history(&mut self, id: &str, cx: &mut Context<Self>) {
        self.invalidate_remediation_plan();
        if self.model.load_history(id) {
            self.notice = Some("已载入当前目标的便携历史快照".into());
            cx.notify();
        }
    }

    fn load_persisted_history(&mut self, cx: &mut Context<Self>) {
        let Some(binding) = self.model.binding.clone() else {
            return;
        };
        let activation_generation = self.model.activation_generation;
        let target = binding.target.clone();
        let service = self.services.detection().clone();
        let task = self
            .tokio
            .spawn(async move { service.history_for_target(&target) });
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                let Some(page) = page.upgrade() else {
                    return;
                };
                page.update(cx, |page, cx| match result {
                    Ok(Ok(reports)) => {
                        if page.model.apply_persisted_history(
                            activation_generation,
                            &binding,
                            reports,
                        ) {
                            cx.notify();
                        }
                    }
                    Ok(Err(error)) => {
                        if page.model.active
                            && page.model.activation_generation == activation_generation
                            && page.model.binding.as_ref() == Some(&binding)
                        {
                            page.error = Some(format!("无法读取检测历史：{error}").into());
                            cx.notify();
                        }
                    }
                    Err(error) if error.is_cancelled() => {}
                    Err(error) => {
                        if page.model.active
                            && page.model.activation_generation == activation_generation
                            && page.model.binding.as_ref() == Some(&binding)
                        {
                            page.error = Some(format!("检测历史任务失败：{error}").into());
                            cx.notify();
                        }
                    }
                });
            });
        })
        .detach();
    }

    fn copy_report_json(&mut self, cx: &mut Context<Self>) {
        let Some(report) = self.model.current_report.as_ref() else {
            self.error = Some("尚无可导出的当前目标报告".into());
            cx.notify();
            return;
        };
        let Some(binding) = self.model.binding.as_ref() else {
            self.error = Some("活动目标已断开，拒绝导出旧目标报告".into());
            cx.notify();
            return;
        };
        if report.target != binding.target {
            self.error = Some("报告与当前目标不一致，拒绝导出".into());
            cx.notify();
            return;
        }
        match detection_report_json(report) {
            Ok(json) => {
                cx.write_to_clipboard(ClipboardItem::new_string(json));
                self.error = None;
                self.notice = Some("已复制 lovelyres-detection-report/v1 JSON".into());
            }
            Err(error) => self.error = Some(format!("无法导出检测报告：{error}").into()),
        }
        cx.notify();
    }

    fn set_filter(&mut self, filter: ResultFilter, cx: &mut Context<Self>) {
        self.model.filter = filter;
        cx.notify();
    }

    fn set_detail_mode(&mut self, mode: DetailMode, cx: &mut Context<Self>) {
        self.model.detail_mode = mode;
        cx.notify();
    }

    fn set_compliance_standard(&mut self, standard: ComplianceStandard, cx: &mut Context<Self>) {
        self.model.compliance_standard = standard;
        cx.notify();
    }

    fn copy_compliance_report(&mut self, cx: &mut Context<Self>) {
        let Some(report) = self.model.current_report.as_ref() else {
            self.error = Some("尚无当前目标的检测报告".into());
            cx.notify();
            return;
        };
        let summary = generate_compliance_summary(self.model.compliance_standard, Some(report));
        cx.write_to_clipboard(ClipboardItem::new_string(summary.to_markdown()));
        self.notice = Some(format!("已复制 {} 合规报告", summary.standard.label()).into());
        cx.notify();
    }

    fn prepare_remediation(&mut self, remediation: DetectionRemediation, cx: &mut Context<Self>) {
        if self.remediation_plan_abort.is_some()
            || self.pending_remediation.is_some()
            || self.remediation_execution_active
        {
            return;
        }
        let Some(session) = self.current_session(cx) else {
            self.error = Some("未连接可信目标，无法生成修复计划".into());
            cx.notify();
            return;
        };
        let lease = match self.model.begin_remediation(remediation) {
            Ok(lease) => lease,
            Err(error) => {
                self.error = Some(format!("无法开始安全修复：{error}").into());
                cx.notify();
                return;
            }
        };
        let request = match remediation.request() {
            Ok(request) => request,
            Err(error) => {
                let binding = self.current_binding(cx);
                let _ = self.model.finish_remediation(&lease, binding.as_ref());
                self.error = Some(format!("修复目录配置错误：{error}").into());
                cx.notify();
                return;
            }
        };
        self.error = None;
        self.notice = Some("正在重读目标状态并生成不可变修复计划…".into());
        let services = self.services.clone();
        let task = self
            .tokio
            .spawn(prepare_remediation_plan(services, session, request));
        self.remediation_plan_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.finish_remediation_plan(lease, remediation, result, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_remediation_plan(
        &mut self,
        lease: RemediationLease,
        remediation: DetectionRemediation,
        result: Result<CoreResult<DetectionRemediationPlan>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts_remediation(&lease, binding.as_ref()) {
            return;
        }
        self.remediation_plan_abort = None;
        match result {
            Ok(Ok(plan)) => {
                self.pending_remediation = Some(PendingDetectionRemediation {
                    lease,
                    remediation,
                    plan,
                });
                self.error = None;
                self.notice = None;
            }
            Ok(Err(error)) => {
                let _ = self.model.finish_remediation(&lease, binding.as_ref());
                self.error = Some(format!("无法生成修复计划：{error}").into());
            }
            Err(error) if error.is_cancelled() => {
                let _ = self.model.finish_remediation(&lease, binding.as_ref());
            }
            Err(error) => {
                let _ = self.model.finish_remediation(&lease, binding.as_ref());
                self.error = Some(format!("修复计划任务异常终止：{error}").into());
            }
        }
        cx.notify();
    }

    fn cancel_pending_remediation(&mut self, cx: &mut Context<Self>) {
        let Some(pending) = self.pending_remediation.take() else {
            return;
        };
        let binding = self.current_binding(cx);
        let _ = self
            .model
            .finish_remediation(&pending.lease, binding.as_ref());
        self.notice = Some("修复计划已取消；目标未发生变化".into());
        cx.notify();
    }

    fn approve_pending_remediation(&mut self, cx: &mut Context<Self>) {
        if self.remediation_execution_active {
            return;
        }
        let Some(pending) = self.pending_remediation.take() else {
            return;
        };
        let binding = self.current_binding(cx);
        if !self
            .model
            .accepts_remediation(&pending.lease, binding.as_ref())
        {
            self.model.invalidate_remediation();
            self.error = Some("目标、报告或选中发现已变化，旧修复计划已作废".into());
            cx.notify();
            return;
        }
        let Some(session) = self.current_session(cx) else {
            self.model.invalidate_remediation();
            self.error = Some("目标已断开，修复计划未执行".into());
            cx.notify();
            return;
        };
        if session.target() != &pending.lease.binding.target {
            self.model.invalidate_remediation();
            self.error = Some("当前 SSH 会话与修复计划目标不一致".into());
            cx.notify();
            return;
        }
        let lease = pending.lease;
        let remediation = pending.remediation;
        let services = self.services.clone();
        let task = self
            .tokio
            .spawn(execute_remediation_plan(services, session, pending.plan));
        self.remediation_execution_active = true;
        self.error = None;
        self.notice = Some("正在应用受管变更、记录审计并读回验证…".into());
        // Once confirmed, execution is detached so navigation cannot interrupt
        // journal/verification or the managed compensation path.
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.finish_remediation_execution(lease, remediation, result, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_remediation_execution(
        &mut self,
        lease: RemediationLease,
        remediation: DetectionRemediation,
        result: Result<CoreResult<DetectionRemediationOutcome>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        self.remediation_execution_active = false;
        let binding = self.current_binding(cx);
        if !self.model.finish_remediation(&lease, binding.as_ref()) {
            return;
        }
        match result {
            Ok(Ok(outcome)) => {
                self.error = None;
                self.notice = Some(
                    format!(
                        "{}已完成，{} 项配置读回验证通过；请重新检测确认风险状态",
                        remediation.label(),
                        outcome.verified_changes
                    )
                    .into(),
                );
            }
            Ok(Err(error)) => {
                self.error = Some(format!("安全修复失败：{error}").into());
            }
            Err(error) => {
                self.error = Some(format!("安全修复任务异常终止：{error}").into());
            }
        }
        cx.notify();
    }

    fn render_modules(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let rows = DetectionKind::ALL
            .into_iter()
            .enumerate()
            .map(|(index, kind)| {
                let selected = self.model.selected_modules.contains(&kind);
                div()
                    .py_2()
                    .border_b_1()
                    .border_color(tokens.border)
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .gap_2()
                            .child(
                                crate::buttons::button(("quick-detection-module", index))
                                    .label(format!(
                                        "{} {}",
                                        if selected { "☑" } else { "☐" },
                                        kind.label()
                                    ))
                                    .small()
                                    .disabled(self.model.running)
                                    .on_click(cx.listener(move |page, _, _, cx| {
                                        page.toggle_module(kind, cx)
                                    })),
                            )
                            .child(
                                div()
                                    .px_2()
                                    .py_1()
                                    .rounded_md()
                                    .bg(tokens.surface_alt)
                                    .text_xs()
                                    .text_color(tokens.muted)
                                    .child(kind.category().label()),
                            ),
                    )
                    .child(
                        div()
                            .mt_1()
                            .text_xs()
                            .text_color(tokens.muted)
                            .child(kind.description()),
                    )
            });
        div()
            .relative()
            .flex_1()
            .min_h_0()
            .child(
                div()
                    .id("quick-detection-module-scroll")
                    .size_full()
                    .overflow_y_scroll()
                    .track_scroll(&self.module_scroll)
                    .flex()
                    .flex_col()
                    .children(rows),
            )
            .vertical_scrollbar(&self.module_scroll)
            .into_any_element()
    }

    fn render_plan(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let plan = self
            .model
            .plan
            .as_ref()
            .map(DetectionScanPlan::summary)
            .unwrap_or_else(|| "选择模块后生成计划；模块改变会使旧计划失效。".to_owned());
        let progress = if self.model.running {
            format!(
                "进度 {}/{} · {}",
                self.model.completed,
                self.model.total,
                self.model
                    .current_task
                    .map(DetectionKind::label)
                    .unwrap_or("等待命令完成")
            )
        } else {
            "未运行".to_owned()
        };
        div()
            .flex()
            .flex_col()
            .gap_2()
            .child(div().text_xs().text_color(tokens.muted).child(plan))
            .child(
                div().flex().gap_2().children([
                    crate::buttons::button("quick-detection-all")
                        .label(format!("全部 {} 项", DetectionKind::ALL.len()))
                        .small()
                        .disabled(self.model.running)
                        .on_click(cx.listener(|page, _, _, cx| page.select_all(cx))),
                    crate::buttons::button("quick-detection-triage")
                        .label("首分钟 6 项")
                        .small()
                        .disabled(self.model.running)
                        .on_click(cx.listener(|page, _, _, cx| page.select_triage(cx))),
                    crate::buttons::button("quick-detection-plan")
                        .label("生成计划")
                        .small()
                        .disabled(self.model.running || self.model.selected_modules.is_empty())
                        .on_click(cx.listener(|page, _, _, cx| page.create_plan(cx))),
                ]),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(
                        crate::buttons::button("quick-detection-run")
                            .label("执行检测计划")
                            .small()
                            .disabled(self.model.running || self.model.plan.is_none())
                            .on_click(cx.listener(|page, _, _, cx| page.start_scan(cx))),
                    )
                    .child(
                        crate::buttons::button("quick-detection-cancel")
                            .label("取消")
                            .small()
                            .danger()
                            .disabled(!self.model.running)
                            .on_click(cx.listener(|page, _, _, cx| page.cancel_scan(cx))),
                    )
                    .child(div().text_xs().text_color(tokens.muted).child(progress)),
            )
            .into_any_element()
    }

    fn render_history(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let current_target = self.model.binding.as_ref().map(|binding| &binding.target);
        let rows = self
            .model
            .history
            .iter()
            .filter(|report| Some(&report.target) == current_target)
            .enumerate()
            .map(|(index, report)| {
                let id = report.id.clone();
                crate::buttons::button(("quick-detection-history", index))
                    .label(format!(
                        "{} · {} 分 · {:?}",
                        report.started_at.format("%H:%M:%S"),
                        report.overall_score,
                        report.status
                    ))
                    .xsmall()
                    .on_click(cx.listener(move |page, _, _, cx| page.load_history(&id, cx)))
            });
        div()
            .mt_2()
            .pt_2()
            .border_t_1()
            .border_color(tokens.border)
            .child(
                div()
                    .text_xs()
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .child("便携历史（当前目标最近 8 次）"),
            )
            .child(div().mt_1().flex().flex_col().gap_1().children(rows))
            .into_any_element()
    }

    fn render_result_list(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let filters = ResultFilter::ALL
            .into_iter()
            .enumerate()
            .map(|(index, filter)| {
                crate::buttons::button(("quick-detection-filter", index))
                    .label(filter.label())
                    .xsmall()
                    .on_click(cx.listener(move |page, _, _, cx| page.set_filter(filter, cx)))
            });
        let rows = self
            .model
            .filtered_modules()
            .into_iter()
            .enumerate()
            .map(|(index, module)| {
                let kind = module.kind;
                let color = outcome_color(module.outcome, tokens);
                div()
                    .py_2()
                    .border_b_1()
                    .border_color(tokens.border)
                    .child(
                        crate::buttons::button(("quick-detection-result", index))
                            .label(kind.label())
                            .small()
                            .on_click(
                                cx.listener(move |page, _, _, cx| page.select_result(kind, cx)),
                            ),
                    )
                    .child(div().mt_1().text_xs().text_color(color).child(format!(
                        "{} · {} 分 · {} 个发现",
                        outcome_label(module.outcome),
                        module.score,
                        module.findings.len()
                    )))
            });
        div()
            .flex()
            .flex_col()
            .min_h_0()
            .child(div().flex().flex_wrap().gap_1().children(filters))
            .child(div().mt_2().child(Input::new(&self.search_input).small()))
            .child(
                div()
                    .mt_2()
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scrollbar()
                    .children(rows),
            )
            .into_any_element()
    }

    fn render_detail(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        if self.model.detail_mode == DetailMode::Compliance {
            return self.render_compliance(tokens, cx);
        }
        let Some(module) = self.model.selected_report() else {
            return div()
                .flex_1()
                .items_center()
                .justify_center()
                .text_color(tokens.muted)
                .child("完成扫描或选择历史后查看结果")
                .into_any_element();
        };
        let remediation_count = module
            .findings
            .iter()
            .filter(|finding| finding.remediation.is_some())
            .count();
        let pending_remediation = self.render_pending_remediation(tokens, cx);
        let body = match self.model.detail_mode {
            DetailMode::Findings => self.render_findings(module, tokens, cx),
            DetailMode::RawText => self.render_raw(module, tokens),
            DetailMode::Compliance => self.render_compliance(tokens, cx),
        };
        div()
            .flex_1()
            .min_h_0()
            .flex()
            .flex_col()
            .gap_2()
            .child(
                div()
                    .child(
                        div()
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child(module.kind.label()),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(outcome_color(module.outcome, tokens))
                            .child(format!(
                                "{} · {} 分 · {} ms",
                                outcome_label(module.outcome),
                                module.score,
                                module.duration_ms
                            )),
                    ),
            )
            .child(
                div().flex().flex_wrap().gap_2().children([
                    crate::buttons::button("quick-detection-findings")
                        .label("类型化报告")
                        .small()
                        .on_click(cx.listener(|page, _, _, cx| {
                            page.set_detail_mode(DetailMode::Findings, cx)
                        })),
                    crate::buttons::button("quick-detection-raw")
                        .label("原始文本")
                        .small()
                        .on_click(cx.listener(|page, _, _, cx| {
                            page.set_detail_mode(DetailMode::RawText, cx)
                        })),
                    crate::buttons::button("quick-detection-compliance")
                        .label("合规视图")
                        .small()
                        .on_click(cx.listener(|page, _, _, cx| {
                            page.set_detail_mode(DetailMode::Compliance, cx)
                        })),
                    crate::buttons::button("quick-detection-remediation-summary")
                        .label(format!("安全修复 {remediation_count}"))
                        .small()
                        .danger()
                        .disabled(remediation_count == 0)
                        .on_click(cx.listener(|page, _, _, cx| {
                            page.set_detail_mode(DetailMode::Findings, cx)
                        })),
                    crate::buttons::button("quick-detection-ai-disabled")
                        .label("AI 方案（待迁移）")
                        .small()
                        .disabled(true),
                    crate::buttons::button("quick-detection-export-json")
                        .label("复制 JSON")
                        .small()
                        .disabled(self.model.current_report.is_none())
                        .on_click(cx.listener(|page, _, _, cx| page.copy_report_json(cx))),
                ]),
            )
            .when_some(pending_remediation, |view, pending| view.child(pending))
            .child(body)
            .into_any_element()
    }

    fn render_compliance(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let summary = generate_compliance_summary(
            self.model.compliance_standard,
            self.model.current_report.as_ref(),
        );
        let standard_buttons =
            ComplianceStandard::ALL
                .into_iter()
                .enumerate()
                .map(|(index, standard)| {
                    crate::buttons::button(("quick-detection-compliance-standard", index))
                        .label(standard.label())
                        .small()
                        .when(self.model.compliance_standard == standard, |button| {
                            button.primary()
                        })
                        .on_click(cx.listener(move |page, _, _, cx| {
                            page.set_compliance_standard(standard, cx)
                        }))
                });
        let rule_rows = summary.results.iter().enumerate().map(|(index, result)| {
            let status_color = compliance_status_color(result.status, tokens);
            div()
                .id(("quick-detection-compliance-rule", index))
                .py_2()
                .border_b_1()
                .border_color(tokens.border)
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap_2()
                        .child(
                            div()
                                .min_w_0()
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .child(result.rule.title),
                        )
                        .child(
                            div()
                                .flex_none()
                                .text_xs()
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .text_color(status_color)
                                .child(result.status.label()),
                        ),
                )
                .child(
                    div()
                        .mt_1()
                        .text_xs()
                        .text_color(tokens.muted)
                        .child(format!(
                            "{} · {} · {} · {}",
                            result.rule.clause,
                            result.rule.category,
                            result.rule.check,
                            result.details
                        )),
                )
                .child(div().mt_1().text_xs().child(result.rule.description))
        });
        div()
            .flex_1()
            .min_h_0()
            .flex()
            .flex_col()
            .gap_2()
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap_2()
                    .child(
                        div()
                            .child(
                                div()
                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                    .child("合规检查"),
                            )
                            .child(
                                div().text_xs().text_color(tokens.muted).child(
                                    "仅映射当前目标的 typed 检测回执；未执行的检查保持待检测",
                                ),
                            ),
                    )
                    .child(
                        crate::buttons::button("quick-detection-compliance-copy")
                            .label("复制 Markdown 报告")
                            .small()
                            .disabled(self.model.current_report.is_none())
                            .on_click(
                                cx.listener(|page, _, _, cx| page.copy_compliance_report(cx)),
                            ),
                    ),
            )
            .child(div().flex().gap_2().children(standard_buttons))
            .child(div().grid().grid_cols(3).gap_2().children([
                compliance_metric("通过率", format!("{}%", summary.percent), tokens),
                compliance_metric(
                    "通过 / 失败",
                    format!("{} / {}", summary.passed, summary.failed),
                    tokens,
                ),
                compliance_metric(
                    "待检测 / N/A / 错误",
                    format!(
                        "{} / {} / {}",
                        summary.pending, summary.not_applicable, summary.errors
                    ),
                    tokens,
                ),
            ]))
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scrollbar()
                    .children(rule_rows),
            )
            .into_any_element()
    }

    fn render_pending_remediation(
        &self,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> Option<AnyElement> {
        let pending = self.pending_remediation.as_ref()?;
        let summary = pending.plan.definition().summary.clone();
        let restore = pending
            .plan
            .definition()
            .restore_description
            .clone()
            .unwrap_or_else(|| "无自动恢复".to_owned());
        let changes = pending.plan.change_summary();
        Some(
            div()
                .rounded_md()
                .border_1()
                .border_color(tokens.warning)
                .bg(tokens.surface_alt)
                .p_3()
                .child(
                    div()
                        .font_weight(gpui::FontWeight::SEMIBOLD)
                        .text_color(tokens.warning)
                        .child(format!("确认执行：{}", pending.remediation.label())),
                )
                .child(
                    div()
                        .mt_1()
                        .text_sm()
                        .child(pending.remediation.explanation()),
                )
                .child(
                    div()
                        .mt_1()
                        .text_xs()
                        .text_color(tokens.muted)
                        .child(summary),
                )
                .child(
                    div()
                        .mt_1()
                        .text_xs()
                        .text_color(tokens.muted)
                        .child(changes),
                )
                .child(
                    div()
                        .mt_1()
                        .text_xs()
                        .text_color(tokens.muted)
                        .child(format!("失败恢复：{restore}")),
                )
                .child(
                    div()
                        .mt_3()
                        .flex()
                        .gap_2()
                        .child(
                            crate::buttons::button("quick-detection-remediation-cancel")
                                .label("取消")
                                .small()
                                .on_click(cx.listener(|page, _, _, cx| {
                                    page.cancel_pending_remediation(cx)
                                })),
                        )
                        .child(
                            crate::buttons::button("quick-detection-remediation-confirm")
                                .label("确认备份并修复")
                                .small()
                                .danger()
                                .on_click(cx.listener(|page, _, _, cx| {
                                    page.approve_pending_remediation(cx)
                                })),
                        ),
                )
                .into_any_element(),
        )
    }

    fn render_findings(
        &self,
        module: &DetectionModuleReport,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        if module.findings.is_empty() {
            return div()
                .flex_1()
                .items_center()
                .justify_center()
                .text_color(tokens.success)
                .child("未发现风险项")
                .into_any_element();
        }
        let remediation_busy = self.remediation_plan_abort.is_some()
            || self.pending_remediation.is_some()
            || self.remediation_execution_active;
        let findings = module.findings.iter().enumerate().map(|(index, finding)| {
            let remediation = finding.remediation;
            div()
                .mb_2()
                .rounded_md()
                .border_1()
                .border_color(tokens.border)
                .p_3()
                .child(
                    div()
                        .font_weight(gpui::FontWeight::SEMIBOLD)
                        .text_color(severity_color(finding.severity, tokens))
                        .child(finding.title.clone()),
                )
                .child(div().mt_1().text_sm().child(finding.description.clone()))
                .when_some(finding.recommendation.clone(), |view, recommendation| {
                    view.child(
                        div()
                            .mt_2()
                            .text_xs()
                            .text_color(tokens.muted)
                            .child(format!("建议：{recommendation}")),
                    )
                })
                .when_some(remediation, |view, remediation| {
                    view.child(
                        crate::buttons::button(("quick-detection-remediation", index))
                            .label(remediation.label())
                            .small()
                            .danger()
                            .disabled(remediation_busy)
                            .on_click(cx.listener(move |page, _, _, cx| {
                                page.prepare_remediation(remediation, cx)
                            })),
                    )
                })
        });
        div()
            .flex_1()
            .min_h_0()
            .overflow_y_scrollbar()
            .children(findings)
            .into_any_element()
    }

    fn render_raw(&self, module: &DetectionModuleReport, tokens: ThemeTokens) -> AnyElement {
        div()
            .flex_1()
            .min_h_0()
            .overflow_y_scrollbar()
            .rounded_md()
            .bg(tokens.terminal_background)
            .p_3()
            .font_family("Cascadia Mono")
            .text_xs()
            .text_color(tokens.text)
            .child(if module.raw_text.is_empty() {
                "（无原始输出）".to_owned()
            } else {
                module.raw_text.clone()
            })
            .when(module.raw_text_truncated, |view| {
                view.child(
                    div()
                        .mt_2()
                        .text_color(tokens.warning)
                        .child("原始文本已在 Core 边界截断"),
                )
            })
            .into_any_element()
    }
}

impl Render for QuickDetectionPage {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens = self.shared.read(cx).theme.tokens();
        let target = self
            .model
            .binding
            .as_ref()
            .map(QuickDetectionBinding::label)
            .unwrap_or_else(|| "未连接目标".to_owned());
        let score = self
            .model
            .current_report
            .as_ref()
            .map(|report| report.overall_score.to_string())
            .unwrap_or_else(|| "-".to_owned());
        div()
            .relative()
            .size_full()
            .min_h_0()
            .bg(tokens.background)
            .text_color(tokens.text)
            .child(
                div()
                    .id("quick-detection-page-scroll")
                    .size_full()
                    .overflow_y_scroll()
                    .track_scroll(&self.page_scroll)
                    .flex()
                    .flex_col()
                    .gap_3()
                    .p_4()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(
                                div()
                                    .child(
                                        div()
                                            .text_lg()
                                            .font_weight(gpui::FontWeight::SEMIBOLD)
                                            .child("快速检测 · 原生封闭检测"),
                                    )
                                    .child(div().text_xs().text_color(tokens.muted).child(target)),
                            )
                            .child(
                                div()
                                    .text_sm()
                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                    .child(format!("可信评分 {score}")),
                            )
                    )
                    .child(
                        div()
                            .rounded_md()
                            .border_1()
                            .border_color(tokens.warning)
                            .bg(tokens.surface_alt)
                            .p_2()
                            .text_xs()
                            .child("已接通 13 项 target-bound 检测：磁盘项仅使用并清理随机 100 MiB 临时文件，网络不可达时明确显示 N/A。报告自动写入当前目标的便携历史并可复制 typed JSON；SSH root 登录、密码认证和认证尝试次数提供受管基线修复，其余加固与 AI 仍待迁移。"),
                    )
                    .when_some(self.error.clone(), |view, error| {
                        view.child(
                            div()
                                .rounded_md()
                                .bg(tokens.surface_alt)
                                .p_2()
                                .text_color(tokens.danger)
                                .child(error),
                        )
                    })
                    .when_some(self.notice.clone(), |view, notice| {
                        view.child(div().text_xs().text_color(tokens.warning).child(notice))
                    })
                    .child(
                        div()
                            .min_h(px(360.0))
                            .flex_1()
                            .flex()
                            .gap_3()
                            .child(
                                div()
                                    .w(px(360.0))
                                    .min_w(px(320.0))
                                    .min_h_0()
                                    .flex()
                                    .flex_col()
                                    .gap_2()
                                    .rounded_lg()
                                    .border_1()
                                    .border_color(tokens.border)
                                    .bg(tokens.surface)
                                    .p_3()
                                    .child(
                                        div()
                                            .font_weight(gpui::FontWeight::SEMIBOLD)
                                            .child("模块与计划"),
                                    )
                                    .child(self.render_modules(tokens, cx))
                                    .child(self.render_plan(tokens, cx))
                                    .child(self.render_history(tokens, cx)),
                            )
                            .child(
                                div()
                                    .w(px(330.0))
                                    .min_w(px(280.0))
                                    .min_h_0()
                                    .flex()
                                    .flex_col()
                                    .rounded_lg()
                                    .border_1()
                                    .border_color(tokens.border)
                                    .bg(tokens.surface)
                                    .p_3()
                                    .child(self.render_result_list(tokens, cx)),
                            )
                            .child(
                                div()
                                    .flex_1()
                                    .min_w_0()
                                    .min_h_0()
                                    .flex()
                                    .flex_col()
                                    .rounded_lg()
                                    .border_1()
                                    .border_color(tokens.border)
                                    .bg(tokens.surface)
                                    .p_3()
                                    .child(self.render_detail(tokens, cx)),
                            ),
                    ),
            )
            .vertical_scrollbar(&self.page_scroll)
    }
}

fn outcome_label(outcome: DetectionOutcome) -> &'static str {
    match outcome {
        DetectionOutcome::Passed => "通过",
        DetectionOutcome::Failed => "发现风险",
        DetectionOutcome::NotApplicable => "不适用",
        DetectionOutcome::Error => "检测错误",
        DetectionOutcome::Cancelled => "已取消",
    }
}

fn outcome_color(outcome: DetectionOutcome, tokens: ThemeTokens) -> gpui::Rgba {
    match outcome {
        DetectionOutcome::Passed => tokens.success,
        DetectionOutcome::Failed => tokens.danger,
        DetectionOutcome::NotApplicable => tokens.muted,
        DetectionOutcome::Error => tokens.warning,
        DetectionOutcome::Cancelled => tokens.muted,
    }
}

fn severity_color(severity: DetectionSeverity, tokens: ThemeTokens) -> gpui::Rgba {
    match severity {
        DetectionSeverity::Critical | DetectionSeverity::High => tokens.danger,
        DetectionSeverity::Medium | DetectionSeverity::Low => tokens.warning,
        DetectionSeverity::Info => tokens.muted,
    }
}

fn compliance_status_color(status: ComplianceRuleStatus, tokens: ThemeTokens) -> gpui::Rgba {
    match status {
        ComplianceRuleStatus::Passed => tokens.success,
        ComplianceRuleStatus::Failed => tokens.danger,
        ComplianceRuleStatus::Pending | ComplianceRuleStatus::NotApplicable => tokens.muted,
        ComplianceRuleStatus::Error => tokens.warning,
    }
}

fn compliance_metric(label: &'static str, value: String, tokens: ThemeTokens) -> impl IntoElement {
    div()
        .rounded_md()
        .border_1()
        .border_color(tokens.border)
        .bg(tokens.surface_alt)
        .p_2()
        .child(div().text_xs().text_color(tokens.muted).child(label))
        .child(
            div()
                .mt_1()
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .child(value),
        )
}

#[cfg(test)]
mod tests {
    use std::{fs, sync::Arc};

    use gpui::{AppContext as _, ScrollDelta, ScrollWheelEvent, TestAppContext, point, size};
    use lovelyres_core::{
        BackendServices, PortableStore,
        target::{TargetContext, TargetIdentity},
    };
    use uuid::Uuid;

    use super::*;

    fn app_shell_scroll_mount(page: Entity<QuickDetectionPage>) -> AnyElement {
        div()
            .size_full()
            .min_h_0()
            .flex()
            .flex_col()
            .child(crate::app::scroll_managed_workspace(
                crate::app::constrained_workspace_page(page),
            ))
            .into_any_element()
    }

    fn binding(target: &TargetContext, identity: &str) -> QuickDetectionBinding {
        QuickDetectionBinding {
            connection_id: identity.to_owned(),
            session_id: format!("session-{identity}"),
            target: target
                .activate(TargetIdentity::new(identity).unwrap())
                .unwrap(),
        }
    }

    fn lease(
        model: &mut QuickDetectionModel,
        binding: &QuickDetectionBinding,
        id: &str,
    ) -> ScanLease {
        let lease = ScanLease {
            activation_generation: model.activation_generation,
            request_id: 1,
            binding: binding.clone(),
            plan_id: id.to_owned(),
        };
        model.running = true;
        model.active_lease = Some(lease.clone());
        lease
    }

    fn report(binding: &QuickDetectionBinding, id: &str) -> DetectionScanReport {
        DetectionScanReport {
            id: id.to_owned(),
            target: binding.target.clone(),
            profile: lovelyres_core::detection::DetectionScanProfile::Selected,
            started_at: serde_json::from_str("\"2026-08-11T00:00:00Z\"").unwrap(),
            duration_ms: 5,
            status: DetectionScanStatus::Completed,
            overall_score: 60,
            modules: vec![DetectionModuleReport {
                kind: DetectionKind::WebshellScan,
                outcome: DetectionOutcome::Failed,
                score: 60,
                findings: vec![lovelyres_core::detection::DetectionFinding {
                    title: "<img src=x onerror=alert(1)>".to_owned(),
                    description: "<script>remote()</script>".to_owned(),
                    severity: DetectionSeverity::Critical,
                    recommendation: None,
                    remediation: None,
                }],
                raw_text: "<iframe src=javascript:alert(1)>".to_owned(),
                raw_text_truncated: false,
                duration_ms: 1,
            }],
            summary: Default::default(),
            dropped_progress_events: 0,
        }
    }

    fn remediation_report(binding: &QuickDetectionBinding, id: &str) -> DetectionScanReport {
        let mut report = report(binding, id);
        report.modules.insert(
            0,
            DetectionModuleReport {
                kind: DetectionKind::SshAudit,
                outcome: DetectionOutcome::Failed,
                score: 70,
                findings: vec![lovelyres_core::detection::DetectionFinding {
                    title: "SSH 允许 root 登录".to_owned(),
                    description: "PermitRootLogin 当前允许直接 root 登录".to_owned(),
                    severity: DetectionSeverity::High,
                    recommendation: Some("使用受管基线修复".to_owned()),
                    remediation: Some(DetectionRemediation::DisableSshRootLogin),
                }],
                raw_text: "permitrootlogin yes".to_owned(),
                raw_text_truncated: false,
                duration_ms: 1,
            },
        );
        report
    }

    #[gpui::test]
    fn short_viewport_can_reach_the_page_bottom_and_last_detection_module(cx: &mut TestAppContext) {
        let root = std::env::temp_dir().join(format!("lovelyres-quick-scroll-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let services =
            Arc::new(BackendServices::new(PortableStore::prepare(root.clone()).unwrap()).unwrap());
        let tokio = TokioBridge::new().unwrap();

        cx.update(gpui_component::init);
        let cx = cx.add_empty_window();
        let page = cx.update(|window, cx| {
            let shared = cx.new(|_| SharedAppState::default());
            cx.new(|cx| QuickDetectionPage::new(services, tokio, shared, window, cx))
        });

        let short_viewport = size(px(1_200.0), px(240.0));
        cx.draw(point(px(0.0), px(0.0)), short_viewport, |_, _| {
            app_shell_scroll_mount(page.clone())
        });
        let page_scroll = page.update(cx, |page, _| page.page_scroll.clone());
        assert!(
            page_scroll.max_offset().height > px(0.0),
            "the complete quick-detection page must overflow a short viewport"
        );
        cx.simulate_event(ScrollWheelEvent {
            position: point(px(1_100.0), px(24.0)),
            delta: ScrollDelta::Pixels(point(px(0.0), px(-5_000.0))),
            ..Default::default()
        });
        cx.draw(point(px(0.0), px(0.0)), short_viewport, |_, _| {
            app_shell_scroll_mount(page.clone())
        });
        assert_eq!(
            page_scroll.offset().y,
            -page_scroll.max_offset().height,
            "a wheel gesture on fixed page chrome must reach the page bottom"
        );

        page_scroll.set_offset(point(px(0.0), px(0.0)));
        let compact_viewport = size(px(1_200.0), px(560.0));
        cx.draw(point(px(0.0), px(0.0)), compact_viewport, |_, _| {
            app_shell_scroll_mount(page.clone())
        });
        let module_scroll = page.update(cx, |page, _| page.module_scroll.clone());
        assert!(
            module_scroll.max_offset().height > px(0.0),
            "all detection modules must remain in a bounded scrolling column"
        );
        cx.simulate_event(ScrollWheelEvent {
            position: module_scroll.bounds().center(),
            delta: ScrollDelta::Pixels(point(px(0.0), px(-5_000.0))),
            ..Default::default()
        });
        cx.draw(point(px(0.0), px(0.0)), compact_viewport, |_, _| {
            app_shell_scroll_mount(page.clone())
        });
        assert_eq!(module_scroll.offset().y, -module_scroll.max_offset().height);
        assert_eq!(
            module_scroll.bottom_item(),
            DetectionKind::ALL.len() - 1,
            "the last detection module must be reachable by wheel scrolling"
        );

        let _ = fs::remove_dir_all(root);
    }

    #[gpui::test]
    fn lifecycle_and_target_switch_reject_late_scan_results(_cx: &mut TestAppContext) {
        let target = TargetContext::new();
        let first = binding(&target, "host-a");
        let mut model = QuickDetectionModel::default();
        model.activate(Some(first.clone()));
        let first_lease = lease(&mut model, &first, "scan-a");
        model.deactivate();
        assert!(!model.finish_scan(&first_lease, Some(&first), report(&first, "scan-a")));

        model.activate(Some(first.clone()));
        let stale = lease(&mut model, &first, "scan-b");
        let second = binding(&target, "host-b");
        model.rebind(Some(second.clone()));
        assert!(!model.finish_scan(&stale, Some(&second), report(&first, "scan-b")));
        assert!(model.current_report.is_none());
    }

    #[test]
    fn remediation_lease_requires_exact_target_report_module_and_page_generation() {
        let target = TargetContext::new();
        let first = binding(&target, "host-a");
        let mut model = QuickDetectionModel::default();
        model.activate(Some(first.clone()));
        let scan = lease(&mut model, &first, "scan-a");
        assert!(model.finish_scan(&scan, Some(&first), remediation_report(&first, "scan-a")));

        let remediation = model
            .begin_remediation(DetectionRemediation::DisableSshRootLogin)
            .unwrap();
        assert!(model.accepts_remediation(&remediation, Some(&first)));

        model.select_result(DetectionKind::WebshellScan);
        assert!(!model.accepts_remediation(&remediation, Some(&first)));
        assert!(
            model
                .begin_remediation(DetectionRemediation::DisableSshRootLogin)
                .is_err()
        );

        model.select_result(DetectionKind::SshAudit);
        let second_remediation = model
            .begin_remediation(DetectionRemediation::DisableSshRootLogin)
            .unwrap();
        model.deactivate();
        assert!(!model.accepts_remediation(&second_remediation, Some(&first)));

        model.activate(Some(first.clone()));
        let scan = lease(&mut model, &first, "scan-b");
        assert!(model.finish_scan(&scan, Some(&first), remediation_report(&first, "scan-b")));
        let stale_target = model
            .begin_remediation(DetectionRemediation::DisableSshRootLogin)
            .unwrap();
        let second = binding(&target, "host-b");
        model.rebind(Some(second.clone()));
        assert!(!model.accepts_remediation(&stale_target, Some(&second)));
    }

    #[test]
    fn file_permission_remediation_lease_binds_the_detected_mode() {
        let target = TargetContext::new();
        let current = binding(&target, "host-a");
        let mut model = QuickDetectionModel::default();
        model.activate(Some(current.clone()));
        let scan = lease(&mut model, &current, "scan-a");
        let remediation = DetectionRemediation::RepairSensitiveFilePermissions {
            file: lovelyres_core::detection::SensitiveSystemFile::Passwd,
            expected_mode: 0o666,
        };
        let mut report = remediation_report(&current, "scan-a");
        report.modules[0].findings[0].remediation = Some(remediation);
        assert!(model.finish_scan(&scan, Some(&current), report));

        let exact = model.begin_remediation(remediation).unwrap();
        assert!(model.accepts_remediation(&exact, Some(&current)));
        assert!(model.finish_remediation(&exact, Some(&current)));
        assert!(
            model
                .begin_remediation(DetectionRemediation::RepairSensitiveFilePermissions {
                    file: lovelyres_core::detection::SensitiveSystemFile::Passwd,
                    expected_mode: 0o664,
                })
                .is_err()
        );
    }

    #[test]
    fn remediation_ui_uses_managed_baseline_and_sftp_plans_without_a_raw_command_surface() {
        let source = include_str!("quick_detection.rs");
        for required in [
            "remediation.request()",
            "DetectionRemediationRequest::Baseline",
            "DetectionRemediationRequest::Sftp",
            ".plan_changes(&session",
            ".bind_session(session.target().clone(), session.session_id())",
            "DangerousConfirmation::approve",
            ".execute_changes(&session",
            "operation.execute_and_verify().await",
            "operation.restore().await",
            "finish_remediation_execution",
        ] {
            assert!(source.contains(required), "missing {required}");
        }
        assert!(!source.contains(&["execute", "Emergency", "Command"].concat()));
        assert!(!source.contains(&["ssh", "_execute", "_command", "_direct"].concat()));
    }

    #[test]
    fn hostile_remote_text_stays_plain_and_filterable() {
        let target = TargetContext::new();
        let current = binding(&target, "host-a");
        let mut model = QuickDetectionModel::default();
        model.activate(Some(current.clone()));
        let lease = lease(&mut model, &current, "scan-a");
        assert!(model.finish_scan(&lease, Some(&current), report(&current, "scan-a")));
        model.set_query("onerror");
        assert_eq!(model.filtered_modules().len(), 1);
        assert_eq!(
            model.filtered_modules()[0].findings[0].title,
            "<img src=x onerror=alert(1)>"
        );
        let source = include_str!("quick_detection.rs").to_lowercase();
        assert!(!source.contains(&["inner", "_html"].concat()));
        assert!(!source.contains(&["web", "view"].concat()));
    }

    #[test]
    fn severity_filter_applies_to_the_native_result_list() {
        let target = TargetContext::new();
        let current = binding(&target, "host-a");
        let mut scan_report = report(&current, "scan-filter");
        scan_report.modules.push(DetectionModuleReport {
            kind: DetectionKind::CpuTest,
            outcome: DetectionOutcome::Passed,
            score: 100,
            findings: Vec::new(),
            raw_text: String::new(),
            raw_text_truncated: false,
            duration_ms: 1,
        });
        let mut model = QuickDetectionModel::default();
        model.activate(Some(current.clone()));
        let scan = lease(&mut model, &current, "scan-filter");
        assert!(model.finish_scan(&scan, Some(&current), scan_report));

        model.filter = ResultFilter::Risk;
        assert_eq!(
            model
                .filtered_modules()
                .into_iter()
                .map(|module| module.kind)
                .collect::<Vec<_>>(),
            vec![DetectionKind::WebshellScan]
        );
        model.filter = ResultFilter::Passed;
        assert_eq!(
            model
                .filtered_modules()
                .into_iter()
                .map(|module| module.kind)
                .collect::<Vec<_>>(),
            vec![DetectionKind::CpuTest]
        );
    }

    #[test]
    fn not_applicable_filter_is_separate_from_errors_and_risks() {
        assert!(ResultFilter::NotApplicable.accepts(DetectionOutcome::NotApplicable));
        assert!(!ResultFilter::Risk.accepts(DetectionOutcome::NotApplicable));
        assert!(ResultFilter::Error.accepts(DetectionOutcome::Cancelled));
        assert!(!ResultFilter::Passed.accepts(DetectionOutcome::Error));
    }

    #[test]
    fn native_catalog_exposes_log_and_performance_without_expanding_first_minute_triage() {
        assert_eq!(DetectionKind::ALL.len(), 13);
        assert_eq!(DetectionKind::LogAnalysis.category().label(), "安全");
        for kind in [
            DetectionKind::CpuTest,
            DetectionKind::MemoryTest,
            DetectionKind::DiskTest,
            DetectionKind::NetworkTest,
        ] {
            assert_eq!(kind.category().label(), "性能");
            assert!(!DetectionKind::COMPETITION_TRIAGE.contains(&kind));
        }
        assert_eq!(DetectionKind::COMPETITION_TRIAGE.len(), 6);
    }

    #[test]
    fn persisted_history_load_requires_the_exact_page_generation_and_target() {
        let target = TargetContext::new();
        let first = binding(&target, "host-a");
        let mut model = QuickDetectionModel::default();
        model.activate(Some(first.clone()));
        let generation = model.activation_generation;
        let stored = report(&first, "stored-a");

        assert!(!model.apply_persisted_history(
            generation.wrapping_add(1),
            &first,
            vec![stored.clone()]
        ));
        assert!(model.history.is_empty());
        assert!(model.apply_persisted_history(generation, &first, vec![stored]));
        assert_eq!(
            model.history.front().map(|entry| entry.id.as_str()),
            Some("stored-a")
        );

        let second = binding(&target, "host-b");
        model.rebind(Some(second));
        assert!(!model.apply_persisted_history(generation, &first, vec![report(&first, "late-a")]));
        assert!(model.history.iter().all(|entry| entry.id != "late-a"));
    }

    #[test]
    fn compliance_view_uses_only_the_current_target_typed_report() {
        let target = TargetContext::new();
        let first = binding(&target, "host-a");
        let mut model = QuickDetectionModel::default();
        model.activate(Some(first.clone()));
        let first_lease = lease(&mut model, &first, "scan-a");
        assert!(model.finish_scan(&first_lease, Some(&first), report(&first, "scan-a")));
        model.detail_mode = DetailMode::Compliance;
        model.compliance_standard = ComplianceStandard::Mlps2;

        let summary =
            generate_compliance_summary(model.compliance_standard, model.current_report.as_ref());
        assert_eq!(summary.target.as_ref(), Some(&first.target));
        assert_eq!(summary.failed, 1);
        assert_eq!(summary.pending, summary.total - 1);
        assert!(!summary.to_markdown().contains("<iframe"));

        let second = binding(&target, "host-b");
        model.rebind(Some(second));
        assert!(model.current_report.is_none());
        let empty =
            generate_compliance_summary(model.compliance_standard, model.current_report.as_ref());
        assert!(empty.target.is_none());
        assert_eq!(empty.pending, empty.total);
    }

    #[test]
    fn native_controls_are_typed_and_every_detail_mode_is_registered() {
        let modes = [
            DetailMode::Findings,
            DetailMode::RawText,
            DetailMode::Compliance,
        ];
        assert_eq!(modes.len(), 3);
        let source = include_str!("quick_detection.rs");
        for required in [
            "set_detail_mode(DetailMode::Findings",
            "set_detail_mode(DetailMode::RawText",
            "set_detail_mode(DetailMode::Compliance",
            ".on_click(cx.listener",
        ] {
            assert!(source.contains(required), "missing {required}");
        }
        assert!(!source.contains(&["data", "-qd-action"].concat()));
        assert!(!source.contains(&["data", "-qd-tab"].concat()));
        assert!(!source.contains(&["on", "click="].concat()));
    }
}
