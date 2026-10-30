//! Incident response engine boundary: scan a bound target for intrusion
//! traces, then plan, confirm, execute and re-verify one fix per issue.
//!
//! The page never names a path, account or process: `scan` mints opaque issue
//! handles, `plan-fix` turns one handle into an immutable core plan, and
//! `execute-fix` starts a background operation whose stage the page follows
//! through `poll-fix`. Backdoor fixes wait out one cron keep-alive period
//! between execution and verification, so the operation outlives the RPC turn
//! and is aborted only when its binding closes.

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use lovelyhawk_core::{
    BackendServices,
    operations::DangerousConfirmation,
    response_engine::{
        FixMode, HardeningStatus, ResponseFixPlan, ResponseIssue, ResponseIssueKind,
        ResponseSeverity, SCAN_STAGE_ACCOUNTS, SCAN_STAGE_COLLECT, SCAN_STAGE_LINKED,
        SCAN_STAGE_PRIVILEGE,
    },
    ssh::BoundSshSession,
    target::TargetGuard,
};
use serde::{Deserialize, Serialize};
use tokio::task::AbortHandle;
use uuid::Uuid;

use crate::ssh_api::SshApi;

const MAX_HANDLE_BYTES: usize = 128;
const MAX_SCANS: usize = 8;
const MAX_PLANS: usize = 16;
const MAX_OPERATIONS: usize = 8;
const MAX_RUNNING_OPERATIONS: usize = 2;
/// A scan's issue handles stay plannable while the operator works the list.
const SCAN_TTL: Duration = Duration::from_secs(15 * 60);
const PLAN_TTL: Duration = Duration::from_secs(5 * 60);
/// A fix takes seconds, but a backdoor verification waits 70 s first.
const RUNNING_TTL: Duration = Duration::from_secs(11 * 60);
const FINISHED_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_RESPONSE_BYTES: usize = 512 * 1024;
const MAX_DETAIL_CHARS: usize = 512;

#[derive(Deserialize)]
#[serde(
    tag = "action",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum ResponseEngineRequest {
    Scan {
        binding_handle: String,
        /// Closed kind selection; None = every detector. Empty or duplicated
        /// lists are rejected so a scan always has a meaningful scope.
        kinds: Option<Vec<ResponseIssueKind>>,
    },
    PollScan {
        binding_handle: String,
        scan_handle: String,
    },
    PlanFix {
        binding_handle: String,
        issue_handle: String,
        mode: Option<FixMode>,
    },
    ConfirmFix {
        binding_handle: String,
        plan_handle: String,
    },
    CancelFix {
        binding_handle: String,
        plan_handle: String,
    },
    ExecuteFix {
        binding_handle: String,
        plan_handle: String,
    },
    PollFix {
        binding_handle: String,
        operation_handle: String,
    },
    HardeningScan {
        binding_handle: String,
    },
    PlanHardening {
        binding_handle: String,
        item_handle: String,
    },
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IssueDto {
    issue_handle: String,
    kind: ResponseIssueKind,
    severity: ResponseSeverity,
    summary: String,
    evidence: Vec<String>,
    fixable: bool,
    fix_summary: Option<String>,
}

/// One hardening finding: `pending` items are plannable through
/// `plan-hardening`, `compliant`/`not-applicable` carry their note.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HardeningItemDto {
    item_handle: String,
    kind: ResponseIssueKind,
    status: &'static str,
    note: Option<String>,
    summary: String,
    evidence: Vec<String>,
    fixable: bool,
    fix_summary: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub(crate) enum ResponseEngineResponse {
    Scan {
        scan_handle: String,
        scanned_at: String,
        truncated: bool,
        gaps: Vec<String>,
        issues: Vec<IssueDto>,
    },
    ScanStarted {
        scan_handle: String,
    },
    ScanStatus {
        scan_handle: String,
        stage: &'static str,
        stage_label: String,
        percent: u32,
        scan: Option<Box<ResponseEngineResponse>>,
        error: Option<String>,
    },
    HardeningScan {
        hardening_handle: String,
        gaps: Vec<String>,
        items: Vec<HardeningItemDto>,
    },
    Plan {
        plan_handle: String,
        summary: String,
        steps: Vec<String>,
        impact: String,
        rollback_note: Option<String>,
        expires_in_seconds: u32,
    },
    Confirmed {
        plan_handle: String,
        confirmed: bool,
        expires_in_seconds: u32,
    },
    Cancelled {
        cancelled: bool,
    },
    Execution {
        operation_handle: String,
    },
    Status {
        operation_handle: String,
        stage: &'static str,
        summary: String,
        verify_passed: Option<bool>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResponseEngineError {
    Invalid,
    Stale,
    Busy,
    Capacity,
    NotConfirmed,
    Core,
}

#[derive(Clone, PartialEq, Eq)]
struct Scope {
    binding_handle: String,
    session_id: String,
    connection_id: String,
    target: TargetGuard,
}

impl Scope {
    fn from_session(binding_handle: &str, session: &BoundSshSession) -> Self {
        Self {
            binding_handle: binding_handle.to_owned(),
            session_id: session.session_id().to_owned(),
            connection_id: session.connection_id().to_owned(),
            target: session.target().clone(),
        }
    }
}

struct ScanRecord {
    scope: Scope,
    expires_at: Instant,
    issues: HashMap<String, ResponseIssue>,
}

/// Hardening handles work like scan handles: only the `Pending` items carry
/// a plannable core issue, the rest are display-only.
struct HardeningScanRecord {
    scope: Scope,
    expires_at: Instant,
    items: HashMap<String, ResponseIssue>,
}

struct PlanRecord {
    scope: Scope,
    plan: ResponseFixPlan,
    confirmed: bool,
    expires_at: Instant,
}

#[derive(Debug)]
enum OperationState {
    Running,
    VerifyPending,
    Completed {
        verify_passed: bool,
        summary: String,
    },
    Failed {
        summary: String,
    },
}

struct OperationRecord {
    scope: Scope,
    state: OperationState,
    abort: Option<AbortHandle>,
    expires_at: Instant,
}

/// One background scan: the stage the target work has really reached, or the
/// finished/failed outcome with its response.
enum ScanOpState {
    Running { stage: &'static str },
    Completed(Box<ResponseEngineResponse>),
    Failed(String),
}

struct ScanOpRecord {
    scope: Scope,
    state: ScanOpState,
    abort: Option<AbortHandle>,
    expires_at: Instant,
}

#[derive(Default)]
struct Registry {
    scans: HashMap<String, ScanRecord>,
    hardening: HashMap<String, HardeningScanRecord>,
    scan_ops: HashMap<String, ScanOpRecord>,
    plans: HashMap<String, PlanRecord>,
    operations: HashMap<String, OperationRecord>,
}

impl Registry {
    fn prune(&mut self, now: Instant) {
        self.scans.retain(|_, scan| scan.expires_at > now);
        self.hardening.retain(|_, scan| scan.expires_at > now);
        self.scan_ops.retain(|_, scan| {
            if scan.expires_at > now {
                return true;
            }
            if let Some(abort) = scan.abort.take() {
                abort.abort();
            }
            false
        });
        self.plans.retain(|_, plan| plan.expires_at > now);
        self.operations.retain(|_, operation| {
            if operation.expires_at > now {
                return true;
            }
            if let Some(abort) = operation.abort.take() {
                abort.abort();
            }
            false
        });
    }

    fn close_binding(&mut self, binding_handle: &str) {
        self.scans
            .retain(|_, scan| scan.scope.binding_handle != binding_handle);
        self.hardening
            .retain(|_, scan| scan.scope.binding_handle != binding_handle);
        self.scan_ops.retain(|_, scan| {
            if scan.scope.binding_handle != binding_handle {
                return true;
            }
            if let Some(abort) = scan.abort.take() {
                abort.abort();
            }
            false
        });
        self.plans
            .retain(|_, plan| plan.scope.binding_handle != binding_handle);
        self.operations.retain(|_, operation| {
            if operation.scope.binding_handle != binding_handle {
                return true;
            }
            if let Some(abort) = operation.abort.take() {
                abort.abort();
            }
            false
        });
    }
}

#[derive(Clone)]
pub(crate) struct ResponseEngineApi {
    services: BackendServices,
    ssh: Arc<SshApi>,
    registry: Arc<Mutex<Registry>>,
}

impl fmt::Debug for ResponseEngineApi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ResponseEngineApi([private state])")
    }
}

impl ResponseEngineApi {
    pub(crate) fn new(services: BackendServices, ssh: Arc<SshApi>) -> Self {
        Self {
            services,
            ssh,
            registry: Arc::new(Mutex::new(Registry::default())),
        }
    }

    pub(crate) fn close_binding(&self, binding_handle: &str) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.close_binding(binding_handle);
        }
    }

    pub(crate) async fn dispatch(
        &self,
        request: ResponseEngineRequest,
    ) -> Result<ResponseEngineResponse, ResponseEngineError> {
        let result = match request {
            ResponseEngineRequest::Scan {
                binding_handle,
                kinds,
            } => {
                if let Some(kinds) = &kinds {
                    let mut seen = std::collections::HashSet::new();
                    if kinds.is_empty()
                        || kinds.len() > 19
                        || !kinds.iter().all(|kind| seen.insert(kind.slug()))
                    {
                        return Err(ResponseEngineError::Invalid);
                    }
                }
                self.scan(&binding_handle, kinds).await
            }
            ResponseEngineRequest::PollScan {
                binding_handle,
                scan_handle,
            } => self.poll_scan(&binding_handle, &scan_handle),
            ResponseEngineRequest::PlanFix {
                binding_handle,
                issue_handle,
                mode,
            } => {
                self.plan_fix(&binding_handle, &issue_handle, mode.unwrap_or_default())
                    .await
            }
            ResponseEngineRequest::ConfirmFix {
                binding_handle,
                plan_handle,
            } => self.confirm_fix(&binding_handle, &plan_handle),
            ResponseEngineRequest::CancelFix {
                binding_handle,
                plan_handle,
            } => self.cancel_fix(&binding_handle, &plan_handle),
            ResponseEngineRequest::ExecuteFix {
                binding_handle,
                plan_handle,
            } => self.execute_fix(&binding_handle, &plan_handle),
            ResponseEngineRequest::PollFix {
                binding_handle,
                operation_handle,
            } => self.poll_fix(&binding_handle, &operation_handle),
            ResponseEngineRequest::HardeningScan { binding_handle } => {
                self.hardening_scan(&binding_handle).await
            }
            ResponseEngineRequest::PlanHardening {
                binding_handle,
                item_handle,
            } => self.plan_hardening(&binding_handle, &item_handle).await,
        }?;
        bounded(&result)?;
        Ok(result)
    }

    /// Starts the scan in the background and returns immediately; the page
    /// follows the real target-side phases through `poll-scan`. One scan at
    /// a time per binding — detectors are read-only, but two concurrent
    /// sweeps would double the load on a slow host.
    async fn scan(
        &self,
        binding: &str,
        kinds: Option<Vec<ResponseIssueKind>>,
    ) -> Result<ResponseEngineResponse, ResponseEngineError> {
        let (session, scope) = self.capture_binding(binding)?;
        let scan_handle = Uuid::new_v4().to_string();
        {
            let mut registry = self.lock_registry()?;
            registry.prune(Instant::now());
            let running = |scan: &&ScanOpRecord| matches!(scan.state, ScanOpState::Running { .. });
            if registry
                .scan_ops
                .values()
                .filter(running)
                .any(|scan| scan.scope.binding_handle == scope.binding_handle)
                || registry.scan_ops.values().filter(running).count() >= MAX_RUNNING_OPERATIONS
            {
                return Err(ResponseEngineError::Busy);
            }
            if registry.scan_ops.len() >= MAX_OPERATIONS {
                let oldest = registry
                    .scan_ops
                    .iter()
                    .filter(|(_, scan)| {
                        matches!(
                            scan.state,
                            ScanOpState::Completed(_) | ScanOpState::Failed(_)
                        )
                    })
                    .min_by_key(|(_, scan)| scan.expires_at)
                    .map(|(handle, _)| handle.clone())
                    .ok_or(ResponseEngineError::Capacity)?;
                registry.scan_ops.remove(&oldest);
            }
            registry.scan_ops.insert(
                scan_handle.clone(),
                ScanOpRecord {
                    scope: scope.clone(),
                    state: ScanOpState::Running {
                        stage: SCAN_STAGE_PRIVILEGE,
                    },
                    abort: None,
                    expires_at: Instant::now() + RUNNING_TTL,
                },
            );
        }

        let api = self.clone();
        let task_scope = scope.clone();
        let task_handle = scan_handle.clone();
        let progress_scope = scope.clone();
        let progress_handle = scan_handle.clone();
        let registry = Arc::clone(&self.registry);
        let progress = move |code: &str| {
            if let Ok(mut ops) = registry.lock() {
                let Some(scan) = ops.scan_ops.get_mut(&progress_handle) else {
                    return;
                };
                if scan.scope == progress_scope
                    && let ScanOpState::Running { stage } = &mut scan.state
                {
                    *stage = stage_code(code);
                }
            }
        };
        let task = tokio::spawn(async move {
            let scan = api
                .services
                .response_engine()
                .scan_with(&session, kinds.as_deref(), Some(&progress))
                .await;
            let response = match scan {
                Ok(scan) => {
                    let mut stored = HashMap::new();
                    let mut issues = Vec::new();
                    for issue in scan.issues {
                        let issue_handle = Uuid::new_v4().to_string();
                        issues.push(IssueDto {
                            issue_handle: issue_handle.clone(),
                            kind: issue.kind,
                            severity: issue.severity,
                            summary: issue.summary.clone(),
                            evidence: issue.evidence.clone(),
                            fixable: issue.fixable,
                            fix_summary: issue.fix_summary.clone(),
                        });
                        stored.insert(issue_handle, issue);
                    }
                    let scanned_at = chrono::Utc::now().to_rfc3339();
                    ResponseEngineResponse::Scan {
                        scan_handle: Uuid::new_v4().to_string(),
                        scanned_at,
                        truncated: scan.truncated,
                        gaps: scan.gaps,
                        issues,
                    }
                    .finish_into_registry(
                        &api,
                        &task_scope,
                        &task_handle,
                        stored,
                    )
                }
                Err(error) => {
                    tracing::warn!(error = %error, "response engine scan failed");
                    Err(ResponseEngineError::Core)
                }
            };
            match response {
                Ok(response) => api.settle_scan_op(
                    &task_scope,
                    &task_handle,
                    ScanOpState::Completed(Box::new(response)),
                ),
                Err(_error) => api.settle_scan_op(
                    &task_scope,
                    &task_handle,
                    ScanOpState::Failed(bounded_detail(
                        "扫描未能完成：目标状态或权限不允许，或连接已变化".to_owned(),
                    )),
                ),
            }
        });
        let attached = self
            .lock_registry()
            .map(
                |mut registry| match registry.scan_ops.get_mut(&scan_handle) {
                    Some(scan)
                        if scan.scope == scope
                            && matches!(scan.state, ScanOpState::Running { .. }) =>
                    {
                        scan.abort = Some(task.abort_handle());
                        true
                    }
                    _ => false,
                },
            )
            .unwrap_or(false);
        if !attached {
            task.abort();
            return Err(ResponseEngineError::Stale);
        }
        Ok(ResponseEngineResponse::ScanStarted {
            scan_handle: scan_handle.clone(),
        })
    }

    fn poll_scan(
        &self,
        binding: &str,
        scan_handle: &str,
    ) -> Result<ResponseEngineResponse, ResponseEngineError> {
        validate_handle(scan_handle)?;
        let (_, scope) = self.capture_binding(binding)?;
        let mut registry = self.lock_registry()?;
        registry.prune(Instant::now());
        let scan = registry
            .scan_ops
            .get(scan_handle)
            .filter(|scan| scan.scope == scope)
            .ok_or(ResponseEngineError::Stale)?;
        match &scan.state {
            ScanOpState::Running { stage } => {
                let (stage_label, percent) = stage_display(stage);
                Ok(ResponseEngineResponse::ScanStatus {
                    scan_handle: scan_handle.to_owned(),
                    stage: "running",
                    stage_label: stage_label.to_owned(),
                    percent,
                    scan: None,
                    error: None,
                })
            }
            ScanOpState::Completed(response) => Ok(ResponseEngineResponse::ScanStatus {
                scan_handle: scan_handle.to_owned(),
                stage: "completed",
                stage_label: "扫描完成".to_owned(),
                percent: 100,
                scan: Some(Box::new((**response).clone())),
                error: None,
            }),
            ScanOpState::Failed(summary) => Ok(ResponseEngineResponse::ScanStatus {
                scan_handle: scan_handle.to_owned(),
                stage: "failed",
                stage_label: "扫描失败".to_owned(),
                percent: 100,
                scan: None,
                error: Some(summary.clone()),
            }),
        }
    }

    /// Move a background scan to a terminal state; a stale handle (binding
    /// closed or record pruned) changes nothing.
    fn settle_scan_op(&self, scope: &Scope, handle: &str, state: ScanOpState) {
        if let Ok(mut registry) = self.registry.lock()
            && let Some(scan) = registry.scan_ops.get_mut(handle)
            && scan.scope == *scope
            && matches!(scan.state, ScanOpState::Running { .. })
        {
            scan.state = state;
            scan.abort = None;
            scan.expires_at = Instant::now() + FINISHED_TTL;
        }
    }

    /// Post-incident hardening sweep: three closed items with a live status;
    /// only pending items mint plannable handles.
    async fn hardening_scan(
        &self,
        binding: &str,
    ) -> Result<ResponseEngineResponse, ResponseEngineError> {
        let (session, scope) = self.capture_binding(binding)?;
        let scan = self
            .services
            .response_engine()
            .hardening_scan(&session)
            .await
            .map_err(|error| {
                tracing::warn!(error = %error, "response engine hardening scan failed");
                ResponseEngineError::Core
            })?;
        self.validate_binding(&scope)?;
        let hardening_handle = Uuid::new_v4().to_string();
        let mut stored = HashMap::new();
        let mut items = Vec::new();
        for item in scan.items {
            let item_handle = Uuid::new_v4().to_string();
            let (status, note) = match &item.status {
                HardeningStatus::Pending => ("pending", None),
                HardeningStatus::Compliant(note) => ("compliant", Some(note.clone())),
                HardeningStatus::NotApplicable(note) => ("not-applicable", Some(note.clone())),
            };
            let fixable = item.fixable && item.issue.is_some();
            items.push(HardeningItemDto {
                item_handle: item_handle.clone(),
                kind: item.kind,
                status,
                note,
                summary: item.summary.clone(),
                evidence: item.evidence.clone(),
                fixable,
                fix_summary: item.fix_summary.clone(),
            });
            if let Some(issue) = item.issue {
                stored.insert(item_handle, issue);
            }
        }
        let response = ResponseEngineResponse::HardeningScan {
            hardening_handle: hardening_handle.clone(),
            gaps: scan.gaps,
            items,
        };
        bounded(&response)?;
        let mut registry = self.lock_registry()?;
        registry.prune(Instant::now());
        registry
            .hardening
            .retain(|_, record| record.scope.binding_handle != scope.binding_handle);
        if registry.hardening.len() >= MAX_SCANS {
            let oldest = registry
                .hardening
                .iter()
                .min_by_key(|(_, record)| record.expires_at)
                .map(|(handle, _)| handle.clone())
                .ok_or(ResponseEngineError::Capacity)?;
            registry.hardening.remove(&oldest);
        }
        registry.hardening.insert(
            hardening_handle,
            HardeningScanRecord {
                scope,
                expires_at: Instant::now() + SCAN_TTL,
                items: stored,
            },
        );
        Ok(response)
    }

    async fn plan_fix(
        &self,
        binding: &str,
        issue_handle: &str,
        mode: FixMode,
    ) -> Result<ResponseEngineResponse, ResponseEngineError> {
        validate_handle(issue_handle)?;
        let (session, scope) = self.capture_binding(binding)?;
        let issue = {
            let mut registry = self.lock_registry()?;
            registry.prune(Instant::now());
            registry
                .scans
                .values()
                .find(|scan| scan.scope == scope)
                .and_then(|scan| scan.issues.get(issue_handle))
                .cloned()
                .ok_or(ResponseEngineError::Stale)?
        };
        if !issue.fixable {
            return Err(ResponseEngineError::Invalid);
        }
        let plan = self
            .services
            .response_engine()
            .plan_fix(&session, &issue, mode)
            .await
            .map_err(|error| {
                tracing::warn!(error = %error, "response engine fix planning failed");
                ResponseEngineError::Core
            })?;
        self.validate_binding(&scope)?;
        let step_labels: Vec<String> = plan.step_labels().into_iter().map(str::to_owned).collect();
        let mut impact = format!(
            "将执行 {} 个修复步骤；删除前证据归档到远端 {}",
            step_labels.len(),
            plan.archive_dir
        );
        if let Some(delay) = plan.cross_period_verify_delay {
            impact.push_str(&format!(
                "；执行后等待 {} 秒跨过一个 cron 保活周期再复验",
                delay.as_secs()
            ));
        }
        let rollback_note = Some(match plan.operation.restore_description {
            Some(ref description) => description.clone(),
            None => "删除账户类修复不提供自动恢复；归档保留在远端，供人工恢复".to_owned(),
        });
        let plan_handle = Uuid::new_v4().to_string();
        let response = ResponseEngineResponse::Plan {
            plan_handle: plan_handle.clone(),
            summary: plan.operation.summary.clone(),
            steps: step_labels,
            impact,
            rollback_note,
            expires_in_seconds: PLAN_TTL.as_secs() as u32,
        };
        bounded(&response)?;
        let mut registry = self.lock_registry()?;
        registry.prune(Instant::now());
        if registry.plans.len() >= MAX_PLANS {
            let oldest = registry
                .plans
                .iter()
                .min_by_key(|(_, record)| record.expires_at)
                .map(|(handle, _)| handle.clone())
                .ok_or(ResponseEngineError::Capacity)?;
            registry.plans.remove(&oldest);
        }
        registry.plans.insert(
            plan_handle,
            PlanRecord {
                scope,
                plan,
                confirmed: false,
                expires_at: Instant::now() + PLAN_TTL,
            },
        );
        Ok(response)
    }

    /// Plans one hardening item from the latest hardening scan of this
    /// binding; the plan then flows through the same confirm/execute/poll
    /// path as an incident fix.
    async fn plan_hardening(
        &self,
        binding: &str,
        item_handle: &str,
    ) -> Result<ResponseEngineResponse, ResponseEngineError> {
        validate_handle(item_handle)?;
        let (session, scope) = self.capture_binding(binding)?;
        let issue = {
            let mut registry = self.lock_registry()?;
            registry.prune(Instant::now());
            registry
                .hardening
                .values()
                .find(|scan| scan.scope == scope)
                .and_then(|scan| scan.items.get(item_handle))
                .cloned()
                .ok_or(ResponseEngineError::Stale)?
        };
        if !issue.fixable {
            return Err(ResponseEngineError::Invalid);
        }
        let plan = self
            .services
            .response_engine()
            .plan_hardening(&session, &issue)
            .await
            .map_err(|error| {
                tracing::warn!(error = %error, "response engine hardening planning failed");
                ResponseEngineError::Core
            })?;
        self.validate_binding(&scope)?;
        let step_labels: Vec<String> = plan.step_labels().into_iter().map(str::to_owned).collect();
        let impact = format!(
            "将执行 {} 个加固步骤；原始权限（如有改动）记录到远端 {}",
            step_labels.len(),
            plan.archive_dir
        );
        let rollback_note = Some(match plan.operation.restore_description {
            Some(ref description) => description.clone(),
            None => "该加固动作不提供自动恢复".to_owned(),
        });
        let plan_handle = Uuid::new_v4().to_string();
        let response = ResponseEngineResponse::Plan {
            plan_handle: plan_handle.clone(),
            summary: plan.operation.summary.clone(),
            steps: step_labels,
            impact,
            rollback_note,
            expires_in_seconds: PLAN_TTL.as_secs() as u32,
        };
        bounded(&response)?;
        let mut registry = self.lock_registry()?;
        registry.prune(Instant::now());
        if registry.plans.len() >= MAX_PLANS {
            let oldest = registry
                .plans
                .iter()
                .min_by_key(|(_, record)| record.expires_at)
                .map(|(handle, _)| handle.clone())
                .ok_or(ResponseEngineError::Capacity)?;
            registry.plans.remove(&oldest);
        }
        registry.plans.insert(
            plan_handle,
            PlanRecord {
                scope,
                plan,
                confirmed: false,
                expires_at: Instant::now() + PLAN_TTL,
            },
        );
        Ok(response)
    }

    fn confirm_fix(
        &self,
        binding: &str,
        plan_handle: &str,
    ) -> Result<ResponseEngineResponse, ResponseEngineError> {
        validate_handle(plan_handle)?;
        let (_, scope) = self.capture_binding(binding)?;
        let mut registry = self.lock_registry()?;
        registry.prune(Instant::now());
        let record = registry
            .plans
            .get_mut(plan_handle)
            .filter(|record| record.scope == scope)
            .ok_or(ResponseEngineError::Stale)?;
        record.confirmed = true;
        Ok(ResponseEngineResponse::Confirmed {
            plan_handle: plan_handle.to_owned(),
            confirmed: true,
            expires_in_seconds: seconds_left(record.expires_at),
        })
    }

    fn cancel_fix(
        &self,
        binding: &str,
        plan_handle: &str,
    ) -> Result<ResponseEngineResponse, ResponseEngineError> {
        validate_handle(plan_handle)?;
        let (_, scope) = self.capture_binding(binding)?;
        let mut registry = self.lock_registry()?;
        let cancelled = registry
            .plans
            .get(plan_handle)
            .is_some_and(|record| record.scope == scope)
            && registry.plans.remove(plan_handle).is_some();
        Ok(ResponseEngineResponse::Cancelled { cancelled })
    }

    /// Starts the fix in the background: execute synchronously inside the
    /// task, wait out the cross-period delay when the plan asks for one, then
    /// verify. The RPC returns as soon as the operation is registered.
    fn execute_fix(
        &self,
        binding: &str,
        plan_handle: &str,
    ) -> Result<ResponseEngineResponse, ResponseEngineError> {
        validate_handle(plan_handle)?;
        let (session, scope) = self.capture_binding(binding)?;
        let operation_handle = Uuid::new_v4().to_string();
        let record = {
            let mut registry = self.lock_registry()?;
            registry.prune(Instant::now());
            let running = |operation: &&OperationRecord| {
                matches!(
                    operation.state,
                    OperationState::Running | OperationState::VerifyPending
                )
            };
            // Fixes on one host are not independent (two edits can share a
            // file), so a binding runs one operation at a time.
            if registry
                .operations
                .values()
                .filter(running)
                .any(|operation| operation.scope.binding_handle == scope.binding_handle)
                || registry.operations.values().filter(running).count() >= MAX_RUNNING_OPERATIONS
            {
                return Err(ResponseEngineError::Busy);
            }
            let record = registry
                .plans
                .get(plan_handle)
                .filter(|record| record.scope == scope)
                .ok_or(ResponseEngineError::Stale)?;
            if !record.confirmed {
                return Err(ResponseEngineError::NotConfirmed);
            }
            let record = registry
                .plans
                .remove(plan_handle)
                .expect("plan checked above");
            if registry.operations.len() >= MAX_OPERATIONS {
                let oldest = registry
                    .operations
                    .iter()
                    .filter(|(_, operation)| {
                        matches!(
                            operation.state,
                            OperationState::Completed { .. } | OperationState::Failed { .. }
                        )
                    })
                    .min_by_key(|(_, operation)| operation.expires_at)
                    .map(|(handle, _)| handle.clone())
                    .ok_or(ResponseEngineError::Capacity)?;
                registry.operations.remove(&oldest);
            }
            registry.operations.insert(
                operation_handle.clone(),
                OperationRecord {
                    scope: scope.clone(),
                    state: OperationState::Running,
                    abort: None,
                    expires_at: Instant::now() + RUNNING_TTL,
                },
            );
            record
        };

        let api = self.clone();
        let task_scope = scope.clone();
        let task_handle = operation_handle.clone();
        let confirmation = DangerousConfirmation::approve(&record.plan.operation);
        let task = tokio::spawn(async move {
            let engine = api.services.response_engine().clone();
            let journal = api.services.operation_journal();
            let executed = engine
                .execute_fix(&session, record.plan, confirmation, journal)
                .await;
            let execution = match executed {
                Ok(execution) => execution,
                Err(error) => {
                    api.finish_operation(
                        &task_scope,
                        &task_handle,
                        OperationState::Failed {
                            summary: bounded_detail(format!("修复执行失败：{error}")),
                        },
                    );
                    return;
                }
            };
            if let Some(delay) = execution.cross_period_verify_delay {
                if !api.settle_operation(
                    &task_scope,
                    &task_handle,
                    OperationState::VerifyPending,
                    RUNNING_TTL,
                ) {
                    return;
                }
                tokio::time::sleep(delay).await;
            }
            if api.validate_binding(&task_scope).is_err() {
                return;
            }
            let outcome = engine.verify_fix(&session, execution, journal).await;
            let state = match outcome {
                Ok(verification) if verification.verification.passed => OperationState::Completed {
                    verify_passed: true,
                    summary: format!("修复完成并复验通过：{}", verification.verification.detail),
                },
                Ok(verification) => OperationState::Completed {
                    verify_passed: false,
                    summary: format!(
                        "修复已执行但复验未通过：{}",
                        verification.verification.detail
                    ),
                },
                Err(error) => OperationState::Failed {
                    summary: bounded_detail(format!("复验未能完成：{error}")),
                },
            };
            api.finish_operation(&task_scope, &task_handle, state);
        });
        let attached = self
            .lock_registry()
            .map(
                |mut registry| match registry.operations.get_mut(&operation_handle) {
                    Some(operation)
                        if operation.scope == scope
                            && matches!(operation.state, OperationState::Running) =>
                    {
                        operation.abort = Some(task.abort_handle());
                        true
                    }
                    _ => false,
                },
            )
            .unwrap_or(false);
        if !attached {
            task.abort();
            return Err(ResponseEngineError::Stale);
        }
        Ok(ResponseEngineResponse::Execution { operation_handle })
    }

    fn poll_fix(
        &self,
        binding: &str,
        operation_handle: &str,
    ) -> Result<ResponseEngineResponse, ResponseEngineError> {
        validate_handle(operation_handle)?;
        let (_, scope) = self.capture_binding(binding)?;
        let mut registry = self.lock_registry()?;
        registry.prune(Instant::now());
        let operation = registry
            .operations
            .get(operation_handle)
            .filter(|operation| operation.scope == scope)
            .ok_or(ResponseEngineError::Stale)?;
        let (stage, summary, verify_passed) = match &operation.state {
            OperationState::Running => ("running", "修复正在执行".to_owned(), None),
            OperationState::VerifyPending => (
                "verify-pending",
                "修复已执行，等待跨过一个 cron 保活周期后复验".to_owned(),
                None,
            ),
            OperationState::Completed {
                verify_passed,
                summary,
            } => ("completed", summary.clone(), Some(*verify_passed)),
            OperationState::Failed { summary } => ("failed", summary.clone(), None),
        };
        Ok(ResponseEngineResponse::Status {
            operation_handle: operation_handle.to_owned(),
            stage,
            summary,
            verify_passed,
        })
    }

    /// A result arriving for an operation that was closed or replaced changes
    /// nothing, mirroring the integrity creation registry.
    fn finish_operation(&self, scope: &Scope, handle: &str, state: OperationState) {
        if let Ok(mut registry) = self.registry.lock()
            && let Some(operation) = registry.operations.get_mut(handle)
            && operation.scope == *scope
            && matches!(
                operation.state,
                OperationState::Running | OperationState::VerifyPending
            )
        {
            operation.state = state;
            operation.abort = None;
            operation.expires_at = Instant::now() + FINISHED_TTL;
        }
    }

    /// Moves an operation to an intermediate stage; false means the operation
    /// is gone (binding closed or record pruned) and the task should stop.
    fn settle_operation(
        &self,
        scope: &Scope,
        handle: &str,
        state: OperationState,
        ttl: Duration,
    ) -> bool {
        let Ok(mut registry) = self.registry.lock() else {
            return false;
        };
        let Some(operation) = registry.operations.get_mut(handle) else {
            return false;
        };
        if operation.scope != *scope || !matches!(operation.state, OperationState::Running) {
            return false;
        }
        operation.state = state;
        operation.expires_at = Instant::now() + ttl;
        true
    }

    fn capture_binding(
        &self,
        binding_handle: &str,
    ) -> Result<(BoundSshSession, Scope), ResponseEngineError> {
        validate_handle(binding_handle)?;
        let session = self
            .ssh
            .binding_session_clone(binding_handle)
            .map_err(|_| ResponseEngineError::Stale)?;
        self.services
            .target()
            .validate(session.target())
            .map_err(|_| ResponseEngineError::Stale)?;
        let scope = Scope::from_session(binding_handle, &session);
        Ok((session, scope))
    }

    fn validate_binding(&self, expected: &Scope) -> Result<(), ResponseEngineError> {
        let (_, current) = self.capture_binding(&expected.binding_handle)?;
        if &current != expected {
            return Err(ResponseEngineError::Stale);
        }
        Ok(())
    }

    fn lock_registry(&self) -> Result<MutexGuard<'_, Registry>, ResponseEngineError> {
        self.registry.lock().map_err(|_| ResponseEngineError::Core)
    }
}

fn bounded(value: &ResponseEngineResponse) -> Result<(), ResponseEngineError> {
    if serde_json::to_vec(value)
        .map_err(|_| ResponseEngineError::Core)?
        .len()
        > MAX_RESPONSE_BYTES
    {
        return Err(ResponseEngineError::Capacity);
    }
    Ok(())
}

fn bounded_detail(text: String) -> String {
    text.chars().take(MAX_DETAIL_CHARS).collect()
}

fn seconds_left(expires: Instant) -> u32 {
    u32::try_from(
        expires
            .saturating_duration_since(Instant::now())
            .as_secs()
            .max(1),
    )
    .unwrap_or(300)
    .min(300)
}

fn validate_handle(value: &str) -> Result<(), ResponseEngineError> {
    if value.is_empty()
        || value.len() > MAX_HANDLE_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(ResponseEngineError::Invalid);
    }
    Ok(())
}

impl ResponseEngineResponse {
    /// Store the completed scan's issue handles so plan-fix can resolve them.
    fn finish_into_registry(
        self,
        api: &ResponseEngineApi,
        scope: &Scope,
        task_handle: &str,
        stored: HashMap<String, ResponseIssue>,
    ) -> Result<Self, ResponseEngineError> {
        let ResponseEngineResponse::Scan { scan_handle, .. } = &self else {
            return Err(ResponseEngineError::Core);
        };
        let scan_handle = scan_handle.clone();
        let response = self;
        let mut registry = api.lock_registry()?;
        registry.prune(Instant::now());
        // A fresh completed scan replaces this binding's previous issue
        // handles; a fix always re-checks fingerprints, but the page must
        // plan from the state it is looking at.
        registry
            .scans
            .retain(|_, record| record.scope.binding_handle != scope.binding_handle);
        if registry.scans.len() >= MAX_SCANS {
            let oldest = registry
                .scans
                .iter()
                .min_by_key(|(_, record)| record.expires_at)
                .map(|(handle, _)| handle.clone())
                .ok_or(ResponseEngineError::Capacity)?;
            registry.scans.remove(&oldest);
        }
        registry.scans.insert(
            scan_handle,
            ScanRecord {
                scope: scope.clone(),
                expires_at: Instant::now() + SCAN_TTL,
                issues: stored,
            },
        );
        let _ = task_handle;
        Ok(response)
    }
}

fn stage_code(code: &str) -> &'static str {
    match code {
        SCAN_STAGE_COLLECT => SCAN_STAGE_COLLECT,
        SCAN_STAGE_LINKED => SCAN_STAGE_LINKED,
        SCAN_STAGE_ACCOUNTS => SCAN_STAGE_ACCOUNTS,
        _ => SCAN_STAGE_PRIVILEGE,
    }
}

fn stage_display(stage: &str) -> (&'static str, u32) {
    match stage {
        SCAN_STAGE_PRIVILEGE => ("正在确认目标与权限…", 15),
        SCAN_STAGE_COLLECT => ("正在采集进程、文件与网络痕迹…", 45),
        SCAN_STAGE_LINKED => ("正在补充采集关联对象指纹…", 75),
        SCAN_STAGE_ACCOUNTS => ("正在核对账户信息…", 90),
        _ => ("正在扫描目标…", 30),
    }
}

#[cfg(test)]
mod tests {
    use lovelyhawk_core::target::TargetIdentity;
    use serde_json::json;

    use super::*;

    fn scope(binding: &str) -> Scope {
        Scope {
            binding_handle: binding.to_owned(),
            session_id: format!("{binding}-session"),
            connection_id: format!("{binding}-connection"),
            target: TargetGuard {
                identity: TargetIdentity::new(format!("{binding}-target")).unwrap(),
                generation: 1,
            },
        }
    }

    #[test]
    fn requests_are_closed_intents_without_paths_commands_or_secrets() {
        let valid = |value: serde_json::Value| {
            serde_json::from_value::<ResponseEngineRequest>(value).is_ok()
        };
        assert!(valid(json!({"action":"scan","bindingHandle":"b"})));
        assert!(valid(
            json!({"action":"plan-fix","bindingHandle":"b","issueHandle":"i"})
        ));
        assert!(valid(
            json!({"action":"plan-fix","bindingHandle":"b","issueHandle":"i","mode":"remove"})
        ));
        assert!(valid(
            json!({"action":"confirm-fix","bindingHandle":"b","planHandle":"p"})
        ));
        assert!(valid(
            json!({"action":"cancel-fix","bindingHandle":"b","planHandle":"p"})
        ));
        assert!(valid(
            json!({"action":"execute-fix","bindingHandle":"b","planHandle":"p"})
        ));
        assert!(valid(
            json!({"action":"poll-fix","bindingHandle":"b","operationHandle":"o"})
        ));
        assert!(valid(
            json!({"action":"hardening-scan","bindingHandle":"b"})
        ));
        assert!(valid(
            json!({"action":"plan-hardening","bindingHandle":"b","itemHandle":"h"})
        ));
        // The mode is the closed core enum.
        assert!(!valid(
            json!({"action":"plan-fix","bindingHandle":"b","issueHandle":"i","mode":"delete"})
        ));
        // No action carries a path, a command, an account name or a password.
        for (action, value) in [
            ("scan", json!({"action":"scan","bindingHandle":"b"})),
            (
                "plan-fix",
                json!({"action":"plan-fix","bindingHandle":"b","issueHandle":"i"}),
            ),
            (
                "confirm-fix",
                json!({"action":"confirm-fix","bindingHandle":"b","planHandle":"p"}),
            ),
            (
                "execute-fix",
                json!({"action":"execute-fix","bindingHandle":"b","planHandle":"p"}),
            ),
            (
                "poll-fix",
                json!({"action":"poll-fix","bindingHandle":"b","operationHandle":"o"}),
            ),
            (
                "hardening-scan",
                json!({"action":"hardening-scan","bindingHandle":"b"}),
            ),
            (
                "plan-hardening",
                json!({"action":"plan-hardening","bindingHandle":"b","itemHandle":"h"}),
            ),
        ] {
            for extra in [
                "path",
                "command",
                "username",
                "password",
                "confirmed",
                "target",
                "issue",
                "__proto__",
            ] {
                let mut forged = value.clone();
                forged[extra] = json!("forged");
                assert!(!valid(forged), "{action}: {extra}");
            }
            // Required fields stay required.
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove("bindingHandle");
            assert!(!valid(missing), "{action}: missing bindingHandle");
        }
        for action in ["fix", "shell", "Scan", "__proto__"] {
            assert!(!valid(json!({"action":action,"bindingHandle":"b"})));
        }
    }

    #[test]
    fn issue_kinds_serialize_kebab_case_onto_the_wire() {
        let kinds = [
            (ResponseIssueKind::HijackedCommand, "hijacked-command"),
            (ResponseIssueKind::UidZeroAccount, "uid-zero-account"),
            (ResponseIssueKind::EmptyPassword, "empty-password"),
            (ResponseIssueKind::SuspiciousAccount, "suspicious-account"),
            (ResponseIssueKind::MaliciousSudoers, "malicious-sudoers"),
            (ResponseIssueKind::CronPersistence, "cron-persistence"),
            (ResponseIssueKind::BackdoorProcess, "backdoor-process"),
            (ResponseIssueKind::LdPreloadHijack, "ld-preload-hijack"),
            (ResponseIssueKind::PathInjection, "path-injection"),
            (ResponseIssueKind::SshKeyBackdoor, "ssh-key-backdoor"),
            (ResponseIssueKind::PamBackdoor, "pam-backdoor"),
            (ResponseIssueKind::BindListener, "bind-listener"),
            (ResponseIssueKind::StashDir, "stash-dir"),
            (ResponseIssueKind::WebSensitiveFile, "web-sensitive-file"),
            (ResponseIssueKind::Webshell, "webshell"),
            (ResponseIssueKind::CommandRecorder, "command-recorder"),
            (
                ResponseIssueKind::HistoryCredentialLeak,
                "history-credential-leak",
            ),
            (ResponseIssueKind::SessionEnvHook, "session-env-hook"),
            (ResponseIssueKind::PreloadResidue, "preload-residue"),
            (
                ResponseIssueKind::HardeningAuthPermissions,
                "hardening-auth-permissions",
            ),
            (
                ResponseIssueKind::HardeningAuditWatch,
                "hardening-audit-watch",
            ),
            (
                ResponseIssueKind::HardeningIntegritySnapshot,
                "hardening-integrity-snapshot",
            ),
        ];
        for (kind, slug) in kinds {
            let dto = IssueDto {
                issue_handle: "i".into(),
                kind,
                severity: ResponseSeverity::Medium,
                summary: "s".into(),
                evidence: vec![],
                fixable: true,
                fix_summary: None,
            };
            assert_eq!(serde_json::to_value(&dto).unwrap()["kind"], json!(slug));
        }
        // The deep-compromise severity rides the same DTO enum.
        let critical = IssueDto {
            issue_handle: "i".into(),
            kind: ResponseIssueKind::LdPreloadHijack,
            severity: ResponseSeverity::Critical,
            summary: "s".into(),
            evidence: vec![],
            fixable: true,
            fix_summary: None,
        };
        assert_eq!(
            serde_json::to_value(&critical).unwrap()["severity"],
            json!("critical")
        );
    }

    #[test]
    fn hardening_items_serialize_status_and_note_onto_the_wire() {
        let dto = HardeningItemDto {
            item_handle: "h".into(),
            kind: ResponseIssueKind::HardeningAuditWatch,
            status: "not-applicable",
            note: Some("目标上没有 auditctl/auditd".into()),
            summary: "s".into(),
            evidence: vec![],
            fixable: false,
            fix_summary: None,
        };
        let value = serde_json::to_value(&dto).unwrap();
        assert_eq!(value["kind"], json!("hardening-audit-watch"));
        assert_eq!(value["status"], json!("not-applicable"));
        assert_eq!(value["itemHandle"], json!("h"));
        assert!(value["note"].is_string());
    }

    #[test]
    fn handles_are_bounded_and_reject_control_and_shell_bytes() {
        for invalid in [
            String::new(),
            "x".repeat(129),
            "a b".into(),
            "a;rm".into(),
            "a\nb".into(),
            "汉".repeat(43),
        ] {
            assert!(matches!(
                validate_handle(&invalid),
                Err(ResponseEngineError::Invalid)
            ));
        }
        assert!(validate_handle(&Uuid::new_v4().to_string()).is_ok());
    }

    #[test]
    fn operation_registry_enforces_scope_ttl_and_binding_cleanup() {
        let now = Instant::now();
        let mut registry = Registry::default();
        let mine = scope("binding-one");
        registry.operations.insert(
            "op-1".to_owned(),
            OperationRecord {
                scope: mine.clone(),
                state: OperationState::Running,
                abort: None,
                expires_at: now + RUNNING_TTL,
            },
        );
        registry.operations.insert(
            "op-2".to_owned(),
            OperationRecord {
                scope: scope("binding-two"),
                state: OperationState::Completed {
                    verify_passed: true,
                    summary: "done".to_owned(),
                },
                abort: None,
                expires_at: now + FINISHED_TTL,
            },
        );
        // Another binding cannot see the operation.
        let other = scope("binding-two");
        assert!(
            registry
                .operations
                .get("op-1")
                .filter(|operation| operation.scope == other)
                .is_none()
        );
        // Closing one binding drops its operations and keeps the other's.
        registry.close_binding("binding-one");
        assert!(!registry.operations.contains_key("op-1"));
        assert!(registry.operations.contains_key("op-2"));
        // Expiry prunes finished records.
        let mut registry = Registry::default();
        registry.operations.insert(
            "op-3".to_owned(),
            OperationRecord {
                scope: scope("binding-three"),
                state: OperationState::Failed {
                    summary: "x".to_owned(),
                },
                abort: None,
                expires_at: now,
            },
        );
        registry.prune(now + Duration::from_secs(1));
        assert!(registry.operations.is_empty());
    }

    #[test]
    fn responses_keep_tagged_kebab_case_and_stay_bounded() {
        let response = ResponseEngineResponse::Status {
            operation_handle: "o".into(),
            stage: "verify-pending",
            summary: "等待复验".into(),
            verify_passed: None,
        };
        assert_eq!(
            serde_json::to_value(&response).unwrap(),
            json!({
                "kind": "status",
                "operationHandle": "o",
                "stage": "verify-pending",
                "summary": "等待复验",
                "verifyPassed": null,
            })
        );
        let scan = ResponseEngineResponse::Scan {
            scan_handle: "s".into(),
            scanned_at: "2026-10-29T00:00:00Z".into(),
            truncated: false,
            gaps: vec![],
            issues: vec![IssueDto {
                issue_handle: "i".into(),
                kind: ResponseIssueKind::CronPersistence,
                severity: ResponseSeverity::High,
                summary: "x".repeat(MAX_RESPONSE_BYTES),
                evidence: vec![],
                fixable: true,
                fix_summary: None,
            }],
        };
        assert!(matches!(bounded(&scan), Err(ResponseEngineError::Capacity)));
        assert_eq!(
            serde_json::to_value(ResponseEngineResponse::Plan {
                plan_handle: "p".into(),
                summary: "s".into(),
                steps: vec!["一步".into()],
                impact: "i".into(),
                rollback_note: None,
                expires_in_seconds: 300,
            })
            .unwrap()["kind"],
            json!("plan")
        );
    }
}
