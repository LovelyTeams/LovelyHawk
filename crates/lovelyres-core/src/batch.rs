//! Target-explicit multi-host command execution with canary gating and portable receipts.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use async_channel::{Receiver, Sender};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::connections::{ConnectionRepository, ConnectionView};
use crate::operations::{
    DangerousConfirmation, ExecutionReceipt, OperationExecutor, OperationPlan, OperationState,
    PlannedOperation, PortableOperationJournal, VerificationResult,
};
use crate::ssh::{BoundSshSession, HostKeyConfirmations, SshCommandOutput, SshService};
use crate::store::StoreFile;
use crate::target::{TargetContext, TargetIdentity};
use crate::{CoreError, CoreResult, PortableStore};

const MAX_TARGETS: usize = 64;
const MAX_TASK_NAME_BYTES: usize = 80;
const MAX_COMMAND_BYTES: usize = 64 * 1024;
const MAX_RESULT_TEXT_BYTES: usize = 256 * 1024;
const MAX_HISTORY: usize = 50;
const MIN_TIMEOUT_SECONDS: u64 = 1;
const MAX_TIMEOUT_SECONDS: u64 = 3_600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BatchStrategy {
    Rolling { stop_on_failure: bool },
    Canary { count: usize },
}

impl BatchStrategy {
    fn validate(self, targets: usize) -> CoreResult<()> {
        if let Self::Canary { count } = self
            && (count == 0 || count > targets)
        {
            return Err(CoreError::validation(
                "batch canary count",
                "must be within the selected target set",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchRequest {
    pub name: String,
    pub command: String,
    pub verify_command: Option<String>,
    pub connection_ids: Vec<String>,
    pub strategy: BatchStrategy,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchTarget {
    pub connection_id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    snapshot_sha256: String,
}

impl BatchTarget {
    pub fn address(&self) -> String {
        format!("{}@{}:{}", self.username, self.host, self.port)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct BatchExecutionPlan {
    task_id: String,
    name: String,
    command: String,
    verify_command: Option<String>,
    targets: Vec<BatchTarget>,
    strategy: BatchStrategy,
    timeout: Duration,
    operation: OperationPlan,
}

impl fmt::Debug for BatchExecutionPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BatchExecutionPlan")
            .field("task_id", &self.task_id)
            .field("name", &self.name)
            .field("command_sha256", &sha256(self.command.as_bytes()))
            .field(
                "verify_command_sha256",
                &self
                    .verify_command
                    .as_ref()
                    .map(|command| sha256(command.as_bytes())),
            )
            .field("targets", &self.targets)
            .field("strategy", &self.strategy)
            .field("timeout", &self.timeout)
            .field("operation", &self.operation)
            .finish()
    }
}

impl BatchExecutionPlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn task_id(&self) -> &str {
        &self.task_id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn targets(&self) -> &[BatchTarget] {
        &self.targets
    }

    pub fn strategy(&self) -> BatchStrategy {
        self.strategy
    }

    pub fn command_preview(&self) -> String {
        bounded_text(&self.command, 512)
    }

    pub fn has_independent_verification(&self) -> bool {
        self.verify_command.is_some()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BatchTargetStatus {
    Success,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchTargetReceipt {
    pub connection_id: String,
    pub server_name: String,
    pub address: String,
    pub target: Option<TargetIdentity>,
    pub connection_snapshot_sha256: String,
    pub status: BatchTargetStatus,
    pub output: String,
    pub error: Option<String>,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub command_dispatched: bool,
    pub verify_output: Option<String>,
    pub verified: Option<bool>,
    pub duration_ms: u64,
}

impl BatchTargetReceipt {
    fn skipped(target: &BatchTarget, reason: impl Into<String>) -> Self {
        Self {
            connection_id: target.connection_id.clone(),
            server_name: target.name.clone(),
            address: target.address(),
            target: Some(
                TargetIdentity::new(target.connection_id.clone()).expect("planned target"),
            ),
            connection_snapshot_sha256: target.snapshot_sha256.clone(),
            status: BatchTargetStatus::Skipped,
            output: String::new(),
            error: Some(reason.into()),
            exit_code: None,
            timed_out: false,
            command_dispatched: false,
            verify_output: None,
            verified: None,
            duration_ms: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BatchTaskStatus {
    Completed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchTaskRecord {
    pub id: String,
    pub operation_id: String,
    pub name: String,
    pub command_preview: String,
    pub command_sha256: String,
    pub verify_command_sha256: Option<String>,
    pub strategy: BatchStrategy,
    pub status: BatchTaskStatus,
    pub results: Vec<BatchTargetReceipt>,
    pub created_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub digest: String,
}

impl BatchTaskRecord {
    pub fn success_count(&self) -> usize {
        self.results
            .iter()
            .filter(|result| result.status == BatchTargetStatus::Success)
            .count()
    }

    pub fn failure_count(&self) -> usize {
        self.results
            .iter()
            .filter(|result| result.status == BatchTargetStatus::Failed)
            .count()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchExecutionOutcome {
    pub task: BatchTaskRecord,
    pub verification: VerificationResult,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchEvent {
    Started {
        task_id: String,
        total: usize,
    },
    TargetStarted {
        task_id: String,
        index: usize,
        total: usize,
        connection_id: String,
        server_name: String,
    },
    TargetFinished {
        task_id: String,
        index: usize,
        total: usize,
        connection_id: String,
        status: BatchTargetStatus,
    },
    Finished {
        task_id: String,
        status: BatchTaskStatus,
    },
}

pub fn batch_event_channel(
    capacity: usize,
) -> CoreResult<(Sender<BatchEvent>, Receiver<BatchEvent>)> {
    if capacity == 0 {
        return Err(CoreError::InvalidChannelCapacity);
    }
    Ok(async_channel::bounded(capacity))
}

#[derive(Debug, Clone, Default)]
pub struct BatchCancellation {
    cancelled: Arc<AtomicBool>,
}

impl BatchCancellation {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct StoredBatchHistory {
    tasks: Vec<BatchTaskRecord>,
}

#[async_trait]
trait BatchTargetRunner: Send + Sync + fmt::Debug {
    async fn execute(
        &self,
        target: &BatchTarget,
        command: &str,
        verify_command: Option<&str>,
        timeout: Duration,
        cancellation: &BatchCancellation,
    ) -> BatchTargetReceipt;
}

#[derive(Debug, Clone)]
struct SshBatchTargetRunner {
    ssh: SshService,
}

#[async_trait]
impl BatchTargetRunner for SshBatchTargetRunner {
    async fn execute(
        &self,
        target: &BatchTarget,
        command: &str,
        verify_command: Option<&str>,
        timeout: Duration,
        cancellation: &BatchCancellation,
    ) -> BatchTargetReceipt {
        let started = Instant::now();
        if cancellation.is_cancelled() {
            return BatchTargetReceipt::skipped(target, "batch cancelled before connection");
        }
        let status = match self
            .ssh
            .connect_if_snapshot(
                &target.connection_id,
                &target.snapshot_sha256,
                HostKeyConfirmations::default(),
            )
            .await
        {
            Ok(status) => status,
            Err(error) => return failed_receipt(target, started, false, error, None),
        };
        let session_id = status.session_id.clone();
        let result = async {
            if cancellation.is_cancelled() {
                return Ok(BatchTargetReceipt::skipped(
                    target,
                    "batch cancelled before command dispatch",
                ));
            }
            let context = TargetContext::new();
            let guard = context.activate(TargetIdentity::new(target.connection_id.clone())?)?;
            let session = self.ssh.bind_session(guard, &session_id).await?;
            execute_bound_target(
                &self.ssh,
                target,
                &session,
                command,
                verify_command,
                timeout,
                started,
            )
            .await
        }
        .await;
        let disconnect = self.ssh.disconnect(&session_id).await;
        match (result, disconnect) {
            (Ok(receipt), Ok(())) => receipt,
            (Ok(mut receipt), Err(error)) => {
                receipt.status = BatchTargetStatus::Failed;
                receipt.error = Some(bounded_text(
                    &format!("SSH session cleanup failed: {error}"),
                    4_096,
                ));
                receipt
            }
            (Err(error), _) => failed_receipt(target, started, true, error, None),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BatchService {
    store: PortableStore,
    connections: ConnectionRepository,
    runner: Arc<dyn BatchTargetRunner>,
    local_target: Arc<TargetContext>,
    journal: PortableOperationJournal,
    history_lock: Arc<Mutex<()>>,
}

impl BatchService {
    pub fn new(
        store: PortableStore,
        connections: ConnectionRepository,
        ssh: SshService,
        journal: PortableOperationJournal,
    ) -> Self {
        Self {
            store,
            connections: connections.clone(),
            runner: Arc::new(SshBatchTargetRunner { ssh }),
            local_target: Arc::new(TargetContext::new()),
            journal,
            history_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn available_targets(&self) -> CoreResult<Vec<ConnectionView>> {
        self.connections.list()
    }

    pub fn plan(&self, request: BatchRequest) -> CoreResult<BatchExecutionPlan> {
        validate_request(&request)?;
        let mut seen = BTreeSet::new();
        let mut targets = Vec::with_capacity(request.connection_ids.len());
        for connection_id in &request.connection_ids {
            if !seen.insert(connection_id.clone()) {
                return Err(CoreError::validation(
                    "batch target set",
                    "contains a duplicate connection id",
                ));
            }
            let connection =
                self.connections
                    .get(connection_id)?
                    .ok_or_else(|| CoreError::NotFound {
                        entity: "SSH connection",
                        id: connection_id.clone(),
                    })?;
            validate_batch_connection(&connection)?;
            targets.push(BatchTarget {
                connection_id: connection.config.id.clone(),
                name: connection.config.name.clone(),
                host: connection.config.host.clone(),
                port: connection.config.port,
                username: connection.config.username.clone(),
                snapshot_sha256: self
                    .connections
                    .execution_snapshot_digest(&connection.config.id)?,
            });
        }
        request.strategy.validate(targets.len())?;
        let task_id = Uuid::new_v4().to_string();
        let guard = self
            .local_target
            .activate(TargetIdentity::new(format!("portable-batch/{task_id}"))?)?;
        let command_digest = sha256(request.command.as_bytes());
        let target_digest =
            sha256(
                &serde_json::to_vec(&targets).map_err(|source| CoreError::Encode {
                    subject: "batch target snapshot",
                    source,
                })?,
            );
        let mut operation = OperationPlan::new(
            guard,
            format!(
                "在 {} 台已固定主机身份的服务器上执行批量任务“{}”；任意命令可能产生不可逆更改。",
                targets.len(),
                request.name
            ),
            true,
            None,
        )?;
        operation
            .metadata
            .insert("task-id".to_owned(), task_id.clone());
        operation
            .metadata
            .insert("command-sha256".to_owned(), command_digest);
        operation
            .metadata
            .insert("targets-sha256".to_owned(), target_digest);
        operation.metadata.insert(
            "independent-verification".to_owned(),
            request.verify_command.is_some().to_string(),
        );
        Ok(BatchExecutionPlan {
            task_id,
            name: request.name,
            command: request.command,
            verify_command: request.verify_command,
            targets,
            strategy: request.strategy,
            timeout: Duration::from_secs(request.timeout_seconds),
            operation,
        })
    }

    pub async fn execute(
        &self,
        plan: BatchExecutionPlan,
        confirmation: DangerousConfirmation,
        cancellation: BatchCancellation,
        events: Option<Sender<BatchEvent>>,
    ) -> CoreResult<BatchExecutionOutcome> {
        validate_plan(&plan)?;
        let task = Arc::new(Mutex::new(None));
        let executor = BatchExecutor {
            runner: self.runner.clone(),
            plan: plan.clone(),
            cancellation,
            events,
            task: task.clone(),
        };
        let mut operation = PlannedOperation::plan(plan.operation.clone());
        operation.confirm(confirmation)?;
        if let Err(error) = operation
            .execute(self.local_target.as_ref(), &executor)
            .await
        {
            if operation.state() == OperationState::StaleAfterExecution {
                operation.journal(&self.journal)?;
            }
            return Err(error);
        }
        let record = task.lock().clone().ok_or_else(|| {
            CoreError::validation("batch execution", "executor did not produce a task receipt")
        })?;
        operation.journal(&self.journal)?;
        let verification = operation
            .verify(self.local_target.as_ref(), &executor, &self.journal)
            .await?;
        self.upsert_history(record.clone())?;
        Ok(BatchExecutionOutcome {
            task: record,
            verification,
        })
    }

    pub fn list_history(&self) -> CoreResult<Vec<BatchTaskRecord>> {
        let _guard = self.history_lock.lock();
        let history = self
            .store
            .read_or_default::<StoredBatchHistory>(StoreFile::Batch)?;
        for task in &history.tasks {
            validate_task_record(task)?;
        }
        Ok(history.tasks)
    }

    fn upsert_history(&self, record: BatchTaskRecord) -> CoreResult<()> {
        validate_task_record(&record)?;
        let _guard = self.history_lock.lock();
        let mut history = self
            .store
            .read_or_default::<StoredBatchHistory>(StoreFile::Batch)?;
        history.tasks.retain(|task| task.id != record.id);
        history.tasks.push(record);
        if history.tasks.len() > MAX_HISTORY {
            let remove = history.tasks.len() - MAX_HISTORY;
            history.tasks.drain(..remove);
        }
        self.store.write(StoreFile::Batch, &history)
    }
}

#[derive(Debug)]
struct BatchExecutor {
    runner: Arc<dyn BatchTargetRunner>,
    plan: BatchExecutionPlan,
    cancellation: BatchCancellation,
    events: Option<Sender<BatchEvent>>,
    task: Arc<Mutex<Option<BatchTaskRecord>>>,
}

#[async_trait]
impl OperationExecutor for BatchExecutor {
    async fn execute(&self, definition: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        if definition != &self.plan.operation {
            return Err(CoreError::validation(
                "batch operation",
                "executor received a different immutable plan",
            ));
        }
        emit(
            &self.events,
            BatchEvent::Started {
                task_id: self.plan.task_id.clone(),
                total: self.plan.targets.len(),
            },
        )
        .await;
        let created_at = Utc::now();
        let mut results = Vec::with_capacity(self.plan.targets.len());
        let mut halt_reason: Option<String> = None;
        for (index, target) in self.plan.targets.iter().enumerate() {
            if self.cancellation.is_cancelled() {
                halt_reason = Some("批量任务已取消".to_owned());
            }
            if let Some(reason) = halt_reason.as_ref() {
                results.push(BatchTargetReceipt::skipped(target, reason.clone()));
                continue;
            }
            emit(
                &self.events,
                BatchEvent::TargetStarted {
                    task_id: self.plan.task_id.clone(),
                    index,
                    total: self.plan.targets.len(),
                    connection_id: target.connection_id.clone(),
                    server_name: target.name.clone(),
                },
            )
            .await;
            let receipt = self
                .runner
                .execute(
                    target,
                    &self.plan.command,
                    self.plan.verify_command.as_deref(),
                    self.plan.timeout,
                    &self.cancellation,
                )
                .await;
            emit(
                &self.events,
                BatchEvent::TargetFinished {
                    task_id: self.plan.task_id.clone(),
                    index,
                    total: self.plan.targets.len(),
                    connection_id: target.connection_id.clone(),
                    status: receipt.status,
                },
            )
            .await;
            results.push(receipt);
            match self.plan.strategy {
                BatchStrategy::Canary { count }
                    if index + 1 == count
                        && results[..count]
                            .iter()
                            .any(|result| result.status != BatchTargetStatus::Success) =>
                {
                    halt_reason = Some("Canary 阶段存在失败，已阻止向剩余服务器发布".to_owned());
                }
                BatchStrategy::Rolling {
                    stop_on_failure: true,
                } if results
                    .last()
                    .is_some_and(|result| result.status != BatchTargetStatus::Success) =>
                {
                    halt_reason = Some("滚动执行遇到失败，已停止剩余服务器".to_owned());
                }
                _ => {}
            }
        }
        let status = if self.cancellation.is_cancelled() {
            BatchTaskStatus::Cancelled
        } else {
            BatchTaskStatus::Completed
        };
        let completed_at = Utc::now();
        let mut record = BatchTaskRecord {
            id: self.plan.task_id.clone(),
            operation_id: self.plan.operation.id.clone(),
            name: self.plan.name.clone(),
            command_preview: bounded_text(&self.plan.command, 512),
            command_sha256: sha256(self.plan.command.as_bytes()),
            verify_command_sha256: self
                .plan
                .verify_command
                .as_ref()
                .map(|command| sha256(command.as_bytes())),
            strategy: self.plan.strategy,
            status,
            results,
            created_at,
            completed_at,
            digest: String::new(),
        };
        record.digest = task_record_digest(&record)?;
        let success = record.success_count();
        let failed = record.failure_count();
        emit(
            &self.events,
            BatchEvent::Finished {
                task_id: self.plan.task_id.clone(),
                status,
            },
        )
        .await;
        *self.task.lock() = Some(record);
        Ok(ExecutionReceipt {
            summary: format!(
                "multi-host batch {} dispatched to {} targets: {success} succeeded, {failed} failed; command sha256 {}",
                self.plan.task_id,
                self.plan.targets.len(),
                sha256(self.plan.command.as_bytes())
            ),
            restore_token: None,
        })
    }

    async fn verify(
        &self,
        _plan: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        let task = self.task.lock().clone().ok_or_else(|| {
            CoreError::validation("batch verification", "missing per-target receipts")
        })?;
        let passed = task.status == BatchTaskStatus::Completed
            && task
                .results
                .iter()
                .all(|result| result.status == BatchTargetStatus::Success);
        Ok(VerificationResult {
            passed,
            detail: format!(
                "batch receipt verified: {} success, {} failed, {} skipped{}",
                task.success_count(),
                task.failure_count(),
                task.results
                    .iter()
                    .filter(|result| result.status == BatchTargetStatus::Skipped)
                    .count(),
                if self.plan.verify_command.is_some() {
                    "; independent verification was required"
                } else {
                    "; only command exit status was available"
                }
            ),
        })
    }

    async fn restore(&self, _plan: &OperationPlan, _receipt: &ExecutionReceipt) -> CoreResult<()> {
        Err(CoreError::Unsupported {
            feature: "automatic rollback of an arbitrary multi-host command",
        })
    }
}

async fn execute_bound_target(
    ssh: &SshService,
    target: &BatchTarget,
    session: &BoundSshSession,
    command: &str,
    verify_command: Option<&str>,
    timeout: Duration,
    started: Instant,
) -> CoreResult<BatchTargetReceipt> {
    let output = ssh
        .execute_bound(session, command.to_owned(), timeout)
        .await?;
    if let Some(error) = command_failure(&output) {
        return Ok(receipt_from_output(target, started, output, error));
    }
    let mut receipt = BatchTargetReceipt {
        connection_id: target.connection_id.clone(),
        server_name: target.name.clone(),
        address: target.address(),
        target: Some(session.target().identity.clone()),
        connection_snapshot_sha256: target.snapshot_sha256.clone(),
        status: BatchTargetStatus::Success,
        output: bounded_text(&output.output, MAX_RESULT_TEXT_BYTES),
        error: None,
        exit_code: output.exit_code,
        timed_out: output.timed_out,
        command_dispatched: true,
        verify_output: None,
        verified: None,
        duration_ms: elapsed_millis(started),
    };
    if let Some(verify_command) = verify_command {
        let verify = match ssh
            .execute_bound(session, verify_command.to_owned(), timeout)
            .await
        {
            Ok(verify) => verify,
            Err(error) => {
                receipt.status = BatchTargetStatus::Failed;
                receipt.error = Some(bounded_text(
                    &format!("执行成功，但独立验证无法取得可信回执：{error}"),
                    4_096,
                ));
                receipt.verified = Some(false);
                receipt.duration_ms = elapsed_millis(started);
                return Ok(receipt);
            }
        };
        receipt.verify_output = Some(bounded_text(&verify.output, MAX_RESULT_TEXT_BYTES));
        if let Some(error) = command_failure(&verify) {
            receipt.status = BatchTargetStatus::Failed;
            receipt.error = Some(bounded_text(
                &format!("执行成功，但独立验证失败：{error}"),
                4_096,
            ));
            receipt.verified = Some(false);
        } else {
            receipt.verified = Some(true);
        }
        receipt.duration_ms = elapsed_millis(started);
    }
    Ok(receipt)
}

fn receipt_from_output(
    target: &BatchTarget,
    started: Instant,
    output: SshCommandOutput,
    error: String,
) -> BatchTargetReceipt {
    BatchTargetReceipt {
        connection_id: target.connection_id.clone(),
        server_name: target.name.clone(),
        address: target.address(),
        target: Some(TargetIdentity::new(target.connection_id.clone()).expect("planned target")),
        connection_snapshot_sha256: target.snapshot_sha256.clone(),
        status: BatchTargetStatus::Failed,
        output: bounded_text(&output.output, MAX_RESULT_TEXT_BYTES),
        error: Some(error),
        exit_code: output.exit_code,
        timed_out: output.timed_out,
        command_dispatched: true,
        verify_output: None,
        verified: None,
        duration_ms: elapsed_millis(started),
    }
}

fn failed_receipt(
    target: &BatchTarget,
    started: Instant,
    dispatched: bool,
    error: impl fmt::Display,
    output: Option<&SshCommandOutput>,
) -> BatchTargetReceipt {
    BatchTargetReceipt {
        connection_id: target.connection_id.clone(),
        server_name: target.name.clone(),
        address: target.address(),
        target: Some(TargetIdentity::new(target.connection_id.clone()).expect("planned target")),
        connection_snapshot_sha256: target.snapshot_sha256.clone(),
        status: BatchTargetStatus::Failed,
        output: output
            .map(|output| bounded_text(&output.output, MAX_RESULT_TEXT_BYTES))
            .unwrap_or_default(),
        error: Some(bounded_text(&error.to_string(), 4_096)),
        exit_code: output.and_then(|output| output.exit_code),
        timed_out: output.is_some_and(|output| output.timed_out),
        command_dispatched: dispatched,
        verify_output: None,
        verified: None,
        duration_ms: elapsed_millis(started),
    }
}

fn command_failure(output: &SshCommandOutput) -> Option<String> {
    if output.timed_out {
        return Some("命令执行超时".to_owned());
    }
    match output.exit_code {
        Some(0) => None,
        Some(code) => Some(format!("命令退出码为 {code}")),
        None => Some("远端未返回可信退出码".to_owned()),
    }
}

fn validate_request(request: &BatchRequest) -> CoreResult<()> {
    validate_text("batch task name", &request.name, MAX_TASK_NAME_BYTES, false)?;
    validate_text("batch command", &request.command, MAX_COMMAND_BYTES, true)?;
    if let Some(command) = &request.verify_command {
        validate_text(
            "batch verification command",
            command,
            MAX_COMMAND_BYTES,
            true,
        )?;
    }
    if request.connection_ids.is_empty() || request.connection_ids.len() > MAX_TARGETS {
        return Err(CoreError::validation(
            "batch target set",
            format!("must contain 1..={MAX_TARGETS} saved connections"),
        ));
    }
    if !(MIN_TIMEOUT_SECONDS..=MAX_TIMEOUT_SECONDS).contains(&request.timeout_seconds) {
        return Err(CoreError::validation(
            "batch timeout",
            format!("must be {MIN_TIMEOUT_SECONDS}..={MAX_TIMEOUT_SECONDS} seconds"),
        ));
    }
    request.strategy.validate(request.connection_ids.len())
}

fn validate_text(
    subject: &'static str,
    value: &str,
    maximum: usize,
    allow_newlines: bool,
) -> CoreResult<()> {
    if value.trim().is_empty()
        || value.len() > maximum
        || value.chars().any(|character| {
            character == '\0'
                || (!allow_newlines && character.is_control())
                || (allow_newlines
                    && character.is_control()
                    && !matches!(character, '\n' | '\r' | '\t'))
        })
    {
        return Err(CoreError::validation(
            subject,
            format!(
                "must be non-empty, bounded to {maximum} bytes, and contain no invalid controls"
            ),
        ));
    }
    Ok(())
}

fn validate_batch_connection(connection: &ConnectionView) -> CoreResult<()> {
    connection.config.validate()?;
    if connection.config.host_key_fingerprint.is_none() {
        return Err(CoreError::validation(
            "batch target",
            format!(
                "connection '{}' has no confirmed host-key fingerprint",
                connection.config.name
            ),
        ));
    }
    if connection
        .config
        .jump_host
        .as_ref()
        .is_some_and(|jump| jump.host_key_fingerprint.is_none())
    {
        return Err(CoreError::validation(
            "batch target",
            format!(
                "connection '{}' has an unconfirmed jump-host fingerprint",
                connection.config.name
            ),
        ));
    }
    Ok(())
}

fn validate_plan(plan: &BatchExecutionPlan) -> CoreResult<()> {
    if Uuid::parse_str(&plan.task_id).is_err()
        || plan.operation.target.identity.as_str() != format!("portable-batch/{}", plan.task_id)
        || plan.operation.metadata.get("task-id") != Some(&plan.task_id)
        || plan.operation.metadata.get("command-sha256") != Some(&sha256(plan.command.as_bytes()))
    {
        return Err(CoreError::validation(
            "batch plan",
            "immutable plan identity or command digest does not match",
        ));
    }
    let targets = serde_json::to_vec(&plan.targets).map_err(|source| CoreError::Encode {
        subject: "batch target snapshot",
        source,
    })?;
    if plan.operation.metadata.get("targets-sha256") != Some(&sha256(&targets)) {
        return Err(CoreError::validation(
            "batch plan",
            "target snapshot digest does not match",
        ));
    }
    Ok(())
}

fn task_record_digest(record: &BatchTaskRecord) -> CoreResult<String> {
    let mut canonical = record.clone();
    canonical.digest.clear();
    let encoded = serde_json::to_vec(&canonical).map_err(|source| CoreError::Encode {
        subject: "batch task receipt",
        source,
    })?;
    Ok(sha256(&encoded))
}

fn validate_task_record(record: &BatchTaskRecord) -> CoreResult<()> {
    if Uuid::parse_str(&record.id).is_err()
        || Uuid::parse_str(&record.operation_id).is_err()
        || record.results.is_empty()
        || record.results.len() > MAX_TARGETS
        || task_record_digest(record)? != record.digest
    {
        return Err(CoreError::validation(
            "batch task receipt",
            "identity, target count, or digest is invalid",
        ));
    }
    validate_sha256("batch command SHA-256", &record.command_sha256)?;
    if let Some(digest) = &record.verify_command_sha256 {
        validate_sha256("batch verification command SHA-256", digest)?;
    }
    for result in &record.results {
        validate_sha256(
            "batch connection snapshot SHA-256",
            &result.connection_snapshot_sha256,
        )?;
    }
    Ok(())
}

fn validate_sha256(subject: &'static str, value: &str) -> CoreResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CoreError::validation(
            subject,
            "must be lowercase SHA-256 hex",
        ));
    }
    Ok(())
}

async fn emit(events: &Option<Sender<BatchEvent>>, event: BatchEvent) {
    if let Some(events) = events {
        let _ = events.send(event).await;
    }
}

fn bounded_text(value: &str, maximum: usize) -> String {
    if value.len() <= maximum {
        return value.to_owned();
    }
    let mut end = maximum;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n…[truncated]", &value[..end])
}

fn elapsed_millis(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, VecDeque};
    use std::fs;
    use std::path::PathBuf;

    use super::*;
    use crate::connections::{ConnectionConfig, ConnectionSecretChanges, SshAuthMethod};
    use crate::crypto::{CryptoVault, SecretValue};

    #[derive(Debug)]
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("lovelyres-batch-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Debug, Default)]
    struct FakeRunner {
        receipts: Mutex<VecDeque<BatchTargetReceipt>>,
        calls: Mutex<Vec<String>>,
        cancel_after_first: Mutex<Option<BatchCancellation>>,
    }

    #[async_trait]
    impl BatchTargetRunner for FakeRunner {
        async fn execute(
            &self,
            target: &BatchTarget,
            _command: &str,
            _verify_command: Option<&str>,
            _timeout: Duration,
            _cancellation: &BatchCancellation,
        ) -> BatchTargetReceipt {
            self.calls.lock().push(target.connection_id.clone());
            let receipt = self
                .receipts
                .lock()
                .pop_front()
                .unwrap_or_else(|| success_receipt(target, None));
            if self.calls.lock().len() == 1
                && let Some(cancellation) = self.cancel_after_first.lock().take()
            {
                cancellation.cancel();
            }
            receipt
        }
    }

    fn fixture(count: usize) -> (TestRoot, BatchService, Arc<FakeRunner>) {
        let root = TestRoot::new();
        let store = PortableStore::prepare(root.0.clone()).unwrap();
        let crypto = Arc::new(CryptoVault::load(&store).unwrap());
        let connections = ConnectionRepository::new(store.clone(), crypto);
        for index in 0..count {
            connections
                .upsert(
                    ConnectionConfig {
                        id: format!("server-{index}"),
                        name: format!("Server {index}"),
                        host: format!("192.0.2.{}", index + 10),
                        port: 22,
                        username: "root".to_owned(),
                        auth_method: SshAuthMethod::Agent,
                        private_key_path: None,
                        certificate_path: None,
                        agent_identity_fingerprint: None,
                        jump_host: None,
                        tags: BTreeSet::new(),
                        notes: None,
                        environment: Some("test".to_owned()),
                        role: None,
                        group: None,
                        host_key_fingerprint: Some(format!("SHA256:server-{index}")),
                    },
                    ConnectionSecretChanges::default(),
                )
                .unwrap();
        }
        let journal = PortableOperationJournal::new(store.clone());
        let runner = Arc::new(FakeRunner::default());
        let service = BatchService {
            store,
            connections,
            runner: runner.clone(),
            local_target: Arc::new(TargetContext::new()),
            journal,
            history_lock: Arc::new(Mutex::new(())),
        };
        (root, service, runner)
    }

    fn request(count: usize, strategy: BatchStrategy) -> BatchRequest {
        BatchRequest {
            name: "Apply security setting".to_owned(),
            command: "apply".to_owned(),
            verify_command: Some("verify".to_owned()),
            connection_ids: (0..count).map(|index| format!("server-{index}")).collect(),
            strategy,
            timeout_seconds: 30,
        }
    }

    fn success_receipt(target: &BatchTarget, verified: Option<bool>) -> BatchTargetReceipt {
        BatchTargetReceipt {
            connection_id: target.connection_id.clone(),
            server_name: target.name.clone(),
            address: target.address(),
            target: Some(TargetIdentity::new(target.connection_id.clone()).unwrap()),
            connection_snapshot_sha256: target.snapshot_sha256.clone(),
            status: BatchTargetStatus::Success,
            output: "ok".to_owned(),
            error: None,
            exit_code: Some(0),
            timed_out: false,
            command_dispatched: true,
            verify_output: verified.map(|_| "verified".to_owned()),
            verified,
            duration_ms: 1,
        }
    }

    fn failed_receipt_for(target: &BatchTarget, verified: Option<bool>) -> BatchTargetReceipt {
        let mut receipt = success_receipt(target, verified);
        receipt.status = BatchTargetStatus::Failed;
        receipt.exit_code = Some(1);
        receipt.error = Some("remote command failed".to_owned());
        receipt
    }

    #[test]
    fn resolved_non_zero_or_missing_exit_status_is_failure() {
        let output = |exit_code, timed_out| SshCommandOutput {
            command: "false".to_owned(),
            output: "permission denied".to_owned(),
            exit_code,
            duration_ms: 1,
            timed_out,
        };
        assert!(command_failure(&output(Some(0), false)).is_none());
        assert!(
            command_failure(&output(Some(1), false))
                .unwrap()
                .contains('1')
        );
        assert!(
            command_failure(&output(None, false))
                .unwrap()
                .contains("可信退出码")
        );
        assert!(
            command_failure(&output(Some(0), true))
                .unwrap()
                .contains("超时")
        );
    }

    #[test]
    fn plan_rejects_duplicate_unpinned_or_changed_target_snapshots() {
        let (_root, service, _) = fixture(2);
        let mut duplicate = request(
            2,
            BatchStrategy::Rolling {
                stop_on_failure: false,
            },
        );
        duplicate.connection_ids[1] = duplicate.connection_ids[0].clone();
        assert!(service.plan(duplicate).is_err());

        let plan = service
            .plan(request(
                2,
                BatchStrategy::Rolling {
                    stop_on_failure: false,
                },
            ))
            .unwrap();
        let mut config = service.connections.get("server-0").unwrap().unwrap().config;
        config.host = "198.51.100.77".to_owned();
        service
            .connections
            .upsert(config, ConnectionSecretChanges::default())
            .unwrap();
        let runner = SshBatchTargetRunner {
            ssh: SshService::new(service.store.clone(), service.connections.clone()).unwrap(),
        };
        let cancellation = BatchCancellation::default();
        let receipt = futures::executor::block_on(runner.execute(
            &plan.targets[0],
            "true",
            None,
            Duration::from_secs(1),
            &cancellation,
        ));
        assert_eq!(receipt.status, BatchTargetStatus::Failed);
        assert!(receipt.error.unwrap().contains("changed after planning"));
    }

    #[test]
    fn credential_rotation_invalidates_a_planned_target_without_exposing_the_secret() {
        let (_root, service, _) = fixture(1);
        let plan = service
            .plan(request(
                1,
                BatchStrategy::Rolling {
                    stop_on_failure: false,
                },
            ))
            .unwrap();
        let config = service.connections.get("server-0").unwrap().unwrap().config;
        service
            .connections
            .upsert(
                config,
                ConnectionSecretChanges {
                    password: crate::connections::SecretChange::Replace(SecretValue::new(
                        "rotated-secret",
                    )),
                    ..ConnectionSecretChanges::default()
                },
            )
            .unwrap();
        let runner = SshBatchTargetRunner {
            ssh: SshService::new(service.store.clone(), service.connections.clone()).unwrap(),
        };
        let receipt = futures::executor::block_on(runner.execute(
            &plan.targets[0],
            "true",
            None,
            Duration::from_secs(1),
            &BatchCancellation::default(),
        ));
        assert_eq!(receipt.status, BatchTargetStatus::Failed);
        let error = receipt.error.unwrap();
        assert!(error.contains("credential changed after planning"));
        assert!(!error.contains("rotated-secret"));
    }

    #[tokio::test]
    async fn wrong_confirmation_has_zero_dispatch_and_exact_plan_is_journaled() {
        let (_root, service, runner) = fixture(1);
        let plan = service
            .plan(request(
                1,
                BatchStrategy::Rolling {
                    stop_on_failure: false,
                },
            ))
            .unwrap();
        let rejected = service
            .execute(
                plan.clone(),
                DangerousConfirmation::reject(plan.definition()),
                BatchCancellation::default(),
                None,
            )
            .await;
        assert!(matches!(
            rejected,
            Err(CoreError::OperationCancelled { .. })
        ));
        assert!(runner.calls.lock().is_empty());

        let outcome = service
            .execute(
                plan.clone(),
                DangerousConfirmation::approve(plan.definition()),
                BatchCancellation::default(),
                None,
            )
            .await
            .unwrap();
        assert!(outcome.verification.passed);
        assert_eq!(service.list_history().unwrap(), vec![outcome.task]);
        assert_eq!(service.journal.entries().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn failed_canary_stops_and_marks_every_remaining_target_skipped() {
        let (_root, service, runner) = fixture(3);
        let plan = service
            .plan(request(3, BatchStrategy::Canary { count: 1 }))
            .unwrap();
        runner
            .receipts
            .lock()
            .push_back(failed_receipt_for(&plan.targets[0], Some(false)));
        let outcome = service
            .execute(
                plan.clone(),
                DangerousConfirmation::approve(plan.definition()),
                BatchCancellation::default(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(runner.calls.lock().as_slice(), &["server-0"]);
        assert_eq!(
            outcome
                .task
                .results
                .iter()
                .map(|result| result.status)
                .collect::<Vec<_>>(),
            vec![
                BatchTargetStatus::Failed,
                BatchTargetStatus::Skipped,
                BatchTargetStatus::Skipped,
            ]
        );
        assert!(
            outcome.task.results[1]
                .error
                .as_deref()
                .unwrap()
                .contains("Canary")
        );
        assert!(!outcome.verification.passed);
    }

    #[tokio::test]
    async fn independent_verification_failure_fails_that_host() {
        let (_root, service, runner) = fixture(1);
        let plan = service
            .plan(request(
                1,
                BatchStrategy::Rolling {
                    stop_on_failure: false,
                },
            ))
            .unwrap();
        runner
            .receipts
            .lock()
            .push_back(failed_receipt_for(&plan.targets[0], Some(false)));
        let outcome = service
            .execute(
                plan.clone(),
                DangerousConfirmation::approve(plan.definition()),
                BatchCancellation::default(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(outcome.task.results[0].status, BatchTargetStatus::Failed);
        assert_eq!(outcome.task.results[0].verified, Some(false));
        assert!(!outcome.verification.passed);
    }

    #[tokio::test]
    async fn cancellation_stops_before_the_next_host_and_preserves_receipts() {
        let (_root, service, runner) = fixture(3);
        let cancellation = BatchCancellation::default();
        *runner.cancel_after_first.lock() = Some(cancellation.clone());
        let plan = service
            .plan(request(
                3,
                BatchStrategy::Rolling {
                    stop_on_failure: false,
                },
            ))
            .unwrap();
        let outcome = service
            .execute(
                plan.clone(),
                DangerousConfirmation::approve(plan.definition()),
                cancellation,
                None,
            )
            .await
            .unwrap();
        assert_eq!(outcome.task.status, BatchTaskStatus::Cancelled);
        assert_eq!(runner.calls.lock().len(), 1);
        assert_eq!(outcome.task.results.len(), 3);
        assert_eq!(outcome.task.results[1].status, BatchTargetStatus::Skipped);
    }

    #[test]
    fn event_channel_is_bounded_and_history_has_a_dedicated_file() {
        assert!(batch_event_channel(0).is_err());
        let (sender, receiver) = batch_event_channel(1).unwrap();
        sender
            .try_send(BatchEvent::Finished {
                task_id: "one".to_owned(),
                status: BatchTaskStatus::Completed,
            })
            .unwrap();
        assert!(
            sender
                .try_send(BatchEvent::Finished {
                    task_id: "two".to_owned(),
                    status: BatchTaskStatus::Completed,
                })
                .is_err()
        );
        drop(receiver);
        assert_eq!(StoreFile::Batch.file_name(), "batch-history.json");
    }
}
