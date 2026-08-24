//! Typed command instrumentation, audit-log analysis, and reversible mutation plans.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, NaiveDateTime, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    CoreError, CoreResult, PortableStore,
    operations::{
        DangerousConfirmation, ExecutionReceipt, OperationExecutor, OperationPlan, OperationState,
        PlannedOperation, PortableOperationJournal, VerificationResult,
    },
    shell_escape::shq,
    ssh::{BoundSshSession, SshCommandOutput, SshService},
    store::StoreFile,
    target::{TargetContext, TargetGuard, TargetIdentity},
};

pub const DEFAULT_AUDIT_COMMANDS: [&str; 17] = [
    "cat",
    "head",
    "tail",
    "more",
    "less",
    "grep",
    "awk",
    "sed",
    "bash",
    "sh",
    "curl",
    "wget",
    "mysql",
    "redis-cli",
    "psql",
    "mongo",
    "find",
];

const LOG_DIR: &str = "/var/log/lovelyres";
const LOG_PATH: &str = "/var/log/lovelyres/command-audit.log";
const MAX_COMMANDS: usize = 32;
const MAX_LOG_ENTRIES: usize = 500;
const MAX_LOG_OUTPUT: usize = 2 * 1024 * 1024;
const MAX_WRAPPER_BYTES: usize = 16 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(30);
const MUTATION_TIMEOUT: Duration = Duration::from_secs(90);
const WRAPPER_MARKER: &str = "LOVELYRES_AUDIT_WRAPPER_V1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditCommandState {
    Original,
    Instrumented,
    Missing,
    ForeignScript,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuditCommandStatus {
    pub name: String,
    pub path: Option<String>,
    pub state: AuditCommandState,
    pub critical: bool,
    pub backup_path: Option<String>,
    pub original_sha256: Option<String>,
    pub wrapper_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditStatusReport {
    pub is_root: bool,
    pub commands: Vec<AuditCommandStatus>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub timestamp: String,
    pub command: String,
    pub args: String,
    pub user: String,
    pub pid: u32,
    pub ppid: u32,
    pub caller: String,
    pub raw: String,
    pub suspicious: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditCommandCount {
    pub command: String,
    pub count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditLogReport {
    pub entries: Vec<AuditLogEntry>,
    pub suspicious_count: usize,
    pub command_counts: Vec<AuditCommandCount>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditCycleCategory {
    FileRead,
    ServiceCheck,
    Network,
    Database,
    Process,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditCycle {
    pub command: String,
    pub args: String,
    pub interval_seconds: Option<u64>,
    pub count: usize,
    pub last_seen: String,
    pub category: AuditCycleCategory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditSuggestionSeverity {
    Critical,
    Warning,
    Info,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditSuggestion {
    pub id: String,
    pub severity: AuditSuggestionSeverity,
    pub title: String,
    pub description: String,
    pub check_command: String,
    pub fix_command: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditAnalysis {
    pub cycles: Vec<AuditCycle>,
    pub suggestions: Vec<AuditSuggestion>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct AuditDeployment {
    target: TargetIdentity,
    name: String,
    path: String,
    backup_path: String,
    original_sha256: String,
    wrapper_sha256: String,
    wrapper_base64: String,
    deployed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct AuditDocument {
    deployments: Vec<AuditDeployment>,
}

#[derive(Clone, Debug)]
struct AuditRepository {
    store: PortableStore,
    transaction: Arc<Mutex<()>>,
}

impl AuditRepository {
    fn new(store: PortableStore) -> Self {
        Self {
            store,
            transaction: Arc::new(Mutex::new(())),
        }
    }

    fn deployment(
        &self,
        target: &TargetIdentity,
        path: &str,
    ) -> CoreResult<Option<AuditDeployment>> {
        let _guard = self.transaction.lock();
        Ok(self
            .store
            .read_or_default::<AuditDocument>(StoreFile::Audit)?
            .deployments
            .into_iter()
            .find(|deployment| &deployment.target == target && deployment.path == path))
    }

    fn apply(&self, effects: &[AuditRegistryEffect]) -> CoreResult<()> {
        if effects
            .iter()
            .all(|effect| matches!(effect, AuditRegistryEffect::None))
        {
            return Ok(());
        }
        let _guard = self.transaction.lock();
        let mut document = self
            .store
            .read_or_default::<AuditDocument>(StoreFile::Audit)?;
        for effect in effects {
            match effect {
                AuditRegistryEffect::Upsert(deployment) => {
                    document.deployments.retain(|item| {
                        item.target != deployment.target || item.path != deployment.path
                    });
                    document.deployments.push(deployment.clone());
                }
                AuditRegistryEffect::Remove { target, path } => {
                    document
                        .deployments
                        .retain(|item| &item.target != target || item.path != *path);
                }
                AuditRegistryEffect::None => {}
            }
        }
        self.store.write(StoreFile::Audit, &document)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AuditRegistryEffect {
    Upsert(AuditDeployment),
    Remove {
        target: TargetIdentity,
        path: String,
    },
    None,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuditMutationStep {
    label: String,
    execute_command: String,
    verify_command: String,
    verify_marker: &'static str,
    rollback_command: Option<String>,
    rollback_marker: Option<&'static str>,
    registry_effect: AuditRegistryEffect,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditMutationPlan {
    operation: OperationPlan,
    steps: Vec<AuditMutationStep>,
    affected_commands: Vec<String>,
}

impl AuditMutationPlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn affected_commands(&self) -> &[String] {
        &self.affected_commands
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditMutationOutcome {
    pub operation_id: String,
    pub verified: bool,
    pub detail: String,
    pub restored_after_failed_verification: bool,
    pub affected_commands: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AuditExecutionToken {
    completed_steps: Vec<usize>,
    failure: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AuditService {
    ssh: SshService,
    target: Arc<TargetContext>,
    repository: AuditRepository,
}

impl AuditService {
    pub fn new(ssh: SshService, target: Arc<TargetContext>, store: PortableStore) -> Self {
        Self {
            ssh,
            target,
            repository: AuditRepository::new(store),
        }
    }

    pub async fn statuses(
        &self,
        session: &BoundSshSession,
        command_names: &[String],
    ) -> CoreResult<AuditStatusReport> {
        let names = normalize_command_names(command_names)?;
        let command = build_status_command(&names);
        let output = self
            .read_command(session, command, "probe audit commands")
            .await?;
        parse_status_report(&names, &output)
    }

    pub async fn read_log(
        &self,
        session: &BoundSshSession,
        limit: usize,
    ) -> CoreResult<AuditLogReport> {
        if !(1..=MAX_LOG_ENTRIES).contains(&limit) {
            return Err(CoreError::validation(
                "audit log limit",
                format!("must be between 1 and {MAX_LOG_ENTRIES}"),
            ));
        }
        let command = format!(
            "if [ -f {log} ] && [ ! -L {log} ]; then tail -n {limit} -- {log}; fi",
            log = shq(LOG_PATH),
        );
        let output = self
            .read_command(session, internal_script(&command), "read command audit log")
            .await?;
        if output.len() > MAX_LOG_OUTPUT {
            return Err(CoreError::validation(
                "command audit log",
                format!("output exceeds {MAX_LOG_OUTPUT} bytes"),
            ));
        }
        Ok(analyze_log(parse_log(&output)?))
    }

    pub fn analyze(&self, entries: &[AuditLogEntry]) -> AuditAnalysis {
        analyze_cycles(entries)
    }

    pub async fn plan_deploy(
        &self,
        session: &BoundSshSession,
        command_name: &str,
    ) -> CoreResult<AuditMutationPlan> {
        self.plan_deploy_many(session, &[command_name.to_owned()])
            .await
    }

    pub async fn plan_deploy_many(
        &self,
        session: &BoundSshSession,
        command_names: &[String],
    ) -> CoreResult<AuditMutationPlan> {
        let report = self.statuses(session, command_names).await?;
        let mut steps = Vec::new();
        let mut affected = Vec::new();
        let mut planned_paths = BTreeSet::new();
        for status in report.commands {
            if status.state != AuditCommandState::Original {
                return Err(CoreError::validation(
                    "audit deployment",
                    format!("{} is not an original executable", status.name),
                ));
            }
            let path = status.path.as_deref().ok_or_else(|| {
                CoreError::validation("audit deployment", "command path is missing")
            })?;
            if planned_paths.insert(path.to_owned()) {
                steps.push(build_deploy_step(
                    session.target(),
                    &status,
                    report.is_root,
                )?);
            }
            affected.push(status.name);
        }
        let critical = affected.iter().any(|name| is_critical_command(name));
        let summary = if affected.len() == 1 {
            format!("部署 {} 命令审计 wrapper", affected[0])
        } else {
            format!(
                "批量部署 {} 个命令审计 wrapper：{}",
                affected.len(),
                affected.join(", ")
            )
        };
        build_mutation_plan(
            session.target().clone(),
            summary,
            if critical {
                "恢复全部原始二进制；其中包含 shell 或基础读取命令"
            } else {
                "恢复全部原始二进制"
            },
            steps,
            affected,
        )
    }

    pub async fn plan_restore(
        &self,
        session: &BoundSshSession,
        command_name: &str,
    ) -> CoreResult<AuditMutationPlan> {
        self.plan_restore_many(session, &[command_name.to_owned()])
            .await
    }

    pub async fn plan_restore_many(
        &self,
        session: &BoundSshSession,
        command_names: &[String],
    ) -> CoreResult<AuditMutationPlan> {
        let report = self.statuses(session, command_names).await?;
        let mut steps = Vec::new();
        let mut affected = Vec::new();
        let mut planned_paths = BTreeSet::new();
        for status in report.commands {
            if status.state != AuditCommandState::Instrumented {
                return Err(CoreError::validation(
                    "audit restore",
                    format!("{} is not a LovelyRes wrapper", status.name),
                ));
            }
            let path = status
                .path
                .as_deref()
                .ok_or_else(|| CoreError::validation("audit restore", "command path is missing"))?;
            if planned_paths.insert(path.to_owned()) {
                let deployment = self
                    .repository
                    .deployment(&session.target().identity, path)?;
                steps.push(build_restore_step(
                    session.target(),
                    &status,
                    report.is_root,
                    deployment.as_ref(),
                )?);
            }
            affected.push(status.name);
        }
        let summary = if affected.len() == 1 {
            format!("恢复 {} 原始系统命令", affected[0])
        } else {
            format!(
                "批量恢复 {} 个原始系统命令：{}",
                affected.len(),
                affected.join(", ")
            )
        };
        build_mutation_plan(
            session.target().clone(),
            summary,
            "重新部署当前 wrapper（仅用于失败补偿）",
            steps,
            affected,
        )
    }

    pub async fn plan_clear_log(&self, session: &BoundSshSession) -> CoreResult<AuditMutationPlan> {
        self.target.validate(session.target())?;
        let is_root = self.probe_is_root(session).await?;
        let backup = format!("{LOG_PATH}.clear-{}", Uuid::new_v4());
        let execute_script = format!(
            "set -eu; [ -d {dir} ] && [ ! -L {dir} ] && [ \"$(stat -c %u -- {dir})\" = 0 ]; if [ -e {log} ]; then [ -f {log} ] && [ ! -L {log} ] && [ \"$(stat -c %u -- {log})\" = 0 ] && [ \"$(stat -c %h -- {log})\" = 1 ]; mv -- {log} {backup}; else install -o 0 -g 0 -m 0600 /dev/null {backup}; fi; install -o 0 -g 0 -m 0666 /dev/null {log}; printf 'CLEAR_OK\\n'",
            dir = shq(LOG_DIR),
            log = shq(LOG_PATH),
            backup = shq(&backup),
        );
        let verify_script = format!(
            "[ -f {log} ] && [ ! -L {log} ] && [ \"$(stat -c %u -- {log})\" = 0 ] && [ \"$(stat -c %h -- {log})\" = 1 ] && [ -f {backup} ] && [ ! -L {backup} ] && [ \"$(stat -c %u -- {backup})\" = 0 ] && [ \"$(stat -c %h -- {backup})\" = 1 ] && printf 'CLEAR_VERIFY_OK\\n'",
            log = shq(LOG_PATH),
            backup = shq(&backup),
        );
        let rollback_command = format!(
            "set -eu; [ -f {log} ] && [ ! -L {log} ] && [ \"$(stat -c %u -- {log})\" = 0 ] && [ \"$(stat -c %h -- {log})\" = 1 ] && [ -f {backup} ] && [ ! -L {backup} ] && [ \"$(stat -c %u -- {backup})\" = 0 ] && [ \"$(stat -c %h -- {backup})\" = 1 ]; cat -- {log} >> {backup}; mv -- {backup} {log}; chmod 0666 {log}; printf 'CLEAR_RESTORE_OK\\n'",
            log = shq(LOG_PATH),
            backup = shq(&backup),
        );
        build_mutation_plan(
            session.target().clone(),
            "清空命令审计日志".to_owned(),
            "恢复清空前日志并保留清空后新增记录",
            vec![AuditMutationStep {
                label: "clear audit log".to_owned(),
                execute_command: privileged_script(is_root, &execute_script),
                verify_command: internal_script(&verify_script),
                verify_marker: "CLEAR_VERIFY_OK",
                rollback_command: Some(privileged_script(is_root, &rollback_command)),
                rollback_marker: Some("CLEAR_RESTORE_OK"),
                registry_effect: AuditRegistryEffect::None,
            }],
            Vec::new(),
        )
    }

    pub async fn execute_mutation(
        &self,
        session: &BoundSshSession,
        plan: AuditMutationPlan,
        confirmation: DangerousConfirmation,
        journal: &PortableOperationJournal,
    ) -> CoreResult<AuditMutationOutcome> {
        self.target.validate(session.target())?;
        if plan.operation.target != *session.target() {
            return Err(CoreError::validation(
                "audit mutation target",
                "plan is not bound to this SSH target epoch",
            ));
        }
        let mut operation = PlannedOperation::plan(plan.operation.clone());
        operation.confirm(confirmation)?;
        let executor = AuditMutationExecutor {
            service: self,
            session,
            plan: &plan,
        };
        if let Err(error) = operation.execute(&self.target, &executor).await {
            if operation.state() == OperationState::StaleAfterExecution {
                operation.journal(journal)?;
            }
            return Err(error);
        }
        operation.journal(journal)?;
        let verification = match operation.verify(&self.target, &executor, journal).await {
            Ok(verification) => verification,
            Err(error) => {
                if operation.state() == OperationState::VerificationFailed {
                    restore_or_combine(&mut operation, &self.target, &executor, journal, &error)
                        .await?;
                }
                return Err(error);
            }
        };
        if !verification.passed {
            operation.restore(&self.target, &executor, journal).await?;
            return Ok(AuditMutationOutcome {
                operation_id: plan.operation.id,
                verified: false,
                detail: verification.detail,
                restored_after_failed_verification: true,
                affected_commands: plan.affected_commands,
            });
        }
        let effects = plan
            .steps
            .iter()
            .map(|step| step.registry_effect.clone())
            .collect::<Vec<_>>();
        if let Err(error) = self.repository.apply(&effects) {
            operation.restore(&self.target, &executor, journal).await?;
            return Err(error);
        }
        Ok(AuditMutationOutcome {
            operation_id: plan.operation.id,
            verified: true,
            detail: verification.detail,
            restored_after_failed_verification: false,
            affected_commands: plan.affected_commands,
        })
    }

    async fn read_command(
        &self,
        session: &BoundSshSession,
        command: String,
        subject: &'static str,
    ) -> CoreResult<String> {
        self.target.validate(session.target())?;
        let output = self
            .ssh
            .execute_bound(session, command, READ_TIMEOUT)
            .await?;
        let output = successful_output(subject, output)?;
        self.target.validate(session.target())?;
        Ok(output)
    }

    async fn mutation_command(
        &self,
        session: &BoundSshSession,
        command: String,
        subject: &'static str,
    ) -> CoreResult<String> {
        self.target.validate(session.target())?;
        let output = self
            .ssh
            .execute_bound(session, command, MUTATION_TIMEOUT)
            .await?;
        successful_output(subject, output)
    }

    async fn probe_is_root(&self, session: &BoundSshSession) -> CoreResult<bool> {
        let output = self
            .read_command(session, "id -u".to_owned(), "probe remote user identity")
            .await?;
        match output.trim() {
            "0" => Ok(true),
            value if value.bytes().all(|byte| byte.is_ascii_digit()) => Ok(false),
            _ => Err(CoreError::validation(
                "remote user identity",
                "id -u returned an invalid value",
            )),
        }
    }
}

#[derive(Debug)]
struct AuditMutationExecutor<'a> {
    service: &'a AuditService,
    session: &'a BoundSshSession,
    plan: &'a AuditMutationPlan,
}

impl AuditMutationExecutor<'_> {
    fn ensure_plan(&self, definition: &OperationPlan) -> CoreResult<()> {
        if definition.id != self.plan.operation.id
            || definition.target != self.plan.operation.target
            || definition.metadata.get("steps_sha256") != Some(&steps_digest(&self.plan.steps))
        {
            return Err(CoreError::validation(
                "audit mutation plan",
                "executor is bound to a different immutable plan",
            ));
        }
        Ok(())
    }

    async fn rollback_steps(&self, completed: &[usize]) -> CoreResult<()> {
        for index in completed.iter().rev() {
            let step = self.plan.steps.get(*index).ok_or_else(|| {
                CoreError::validation("audit rollback", "invalid completed step index")
            })?;
            let Some(command) = step.rollback_command.clone() else {
                continue;
            };
            let output = self
                .service
                .mutation_command(self.session, command, "rollback audit mutation")
                .await?;
            if let Some(marker) = step.rollback_marker
                && !output.lines().any(|line| line == marker)
            {
                return Err(CoreError::validation(
                    "audit rollback verification",
                    format!("{} did not emit {marker}", step.label),
                ));
            }
        }
        Ok(())
    }
}

#[async_trait]
impl OperationExecutor for AuditMutationExecutor<'_> {
    async fn execute(&self, definition: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        self.ensure_plan(definition)?;
        let mut token = AuditExecutionToken {
            completed_steps: Vec::new(),
            failure: None,
        };
        for (index, step) in self.plan.steps.iter().enumerate() {
            match self
                .service
                .mutation_command(
                    self.session,
                    step.execute_command.clone(),
                    "execute audit mutation",
                )
                .await
            {
                Ok(_) => token.completed_steps.push(index),
                Err(error) => {
                    token.failure = Some(format!("{}: {error}", step.label));
                    break;
                }
            }
        }
        let completed = token.completed_steps.len();
        let total = self.plan.steps.len();
        Ok(ExecutionReceipt {
            summary: token
                .failure
                .as_ref()
                .map_or_else(|| format!("completed {completed}/{total} audit mutation steps"), |failure| {
                    format!("completed {completed}/{total} audit mutation steps before failure: {failure}")
                }),
            restore_token: Some(serde_json::to_string(&token).map_err(|source| {
                CoreError::Encode {
                    subject: "audit execution token",
                    source,
                }
            })?),
        })
    }

    async fn verify(
        &self,
        definition: &OperationPlan,
        receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        self.ensure_plan(definition)?;
        let token = execution_token(receipt)?;
        if let Some(failure) = token.failure {
            return Ok(VerificationResult {
                passed: false,
                detail: failure,
            });
        }
        for step in &self.plan.steps {
            let output = self
                .service
                .mutation_command(
                    self.session,
                    step.verify_command.clone(),
                    "verify audit mutation",
                )
                .await?;
            if !output.lines().any(|line| line == step.verify_marker) {
                return Ok(VerificationResult {
                    passed: false,
                    detail: format!("{} did not emit {}", step.label, step.verify_marker),
                });
            }
        }
        Ok(VerificationResult {
            passed: true,
            detail: format!("verified {} audit mutation steps", self.plan.steps.len()),
        })
    }

    async fn restore(
        &self,
        definition: &OperationPlan,
        receipt: &ExecutionReceipt,
    ) -> CoreResult<()> {
        self.ensure_plan(definition)?;
        let token = execution_token(receipt)?;
        self.rollback_steps(&token.completed_steps).await
    }
}

async fn restore_or_combine(
    operation: &mut PlannedOperation,
    target: &TargetContext,
    executor: &dyn OperationExecutor,
    journal: &PortableOperationJournal,
    verification_error: &CoreError,
) -> CoreResult<()> {
    operation
        .restore(target, executor, journal)
        .await
        .map_err(|restore_error| {
            CoreError::validation(
                "audit mutation recovery",
                format!(
                    "verification failed ({verification_error}); automatic restore also failed ({restore_error})"
                ),
            )
        })
}

fn execution_token(receipt: &ExecutionReceipt) -> CoreResult<AuditExecutionToken> {
    let token = receipt.restore_token.as_deref().ok_or_else(|| {
        CoreError::validation("audit execution token", "missing in-memory restore token")
    })?;
    serde_json::from_str(token).map_err(|source| CoreError::Decode {
        subject: "audit execution token",
        source,
    })
}

fn normalize_command_names(names: &[String]) -> CoreResult<Vec<String>> {
    if names.is_empty() || names.len() > MAX_COMMANDS {
        return Err(CoreError::validation(
            "audit command list",
            format!("must contain between 1 and {MAX_COMMANDS} names"),
        ));
    }
    let mut normalized = BTreeSet::new();
    for name in names {
        let name = name.trim();
        validate_command_name(name)?;
        normalized.insert(name.to_owned());
    }
    Ok(normalized.into_iter().collect())
}

fn validate_command_name(name: &str) -> CoreResult<()> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
        || !name
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        return Err(CoreError::validation(
            "audit command name",
            "must start with an ASCII letter/digit and contain only letters, digits, dot, underscore, plus, or hyphen",
        ));
    }
    Ok(())
}

fn validate_absolute_command_path(path: &str) -> CoreResult<()> {
    if path.len() < 2
        || path.len() > 4_096
        || !path.starts_with('/')
        || path.chars().any(char::is_control)
        || path.split('/').any(|component| component == "..")
    {
        return Err(CoreError::validation(
            "audit command path",
            "must be an absolute control-free path without parent traversal",
        ));
    }
    Ok(())
}

fn validate_backup_path(path: &str, command_path: &str) -> CoreResult<()> {
    validate_absolute_command_path(path)?;
    let (directory, base) = command_path.rsplit_once('/').ok_or_else(|| {
        CoreError::validation("audit command path", "command has no parent directory")
    })?;
    let expected_prefix = format!("{directory}/.{base}.lovelyres-orig-");
    let suffix = path.strip_prefix(&expected_prefix).ok_or_else(|| {
        CoreError::validation(
            "audit backup path",
            "backup is not in the command's managed sibling namespace",
        )
    })?;
    if Uuid::parse_str(suffix).is_err() {
        return Err(CoreError::validation(
            "audit backup path",
            "backup suffix must be a UUID",
        ));
    }
    Ok(())
}

fn validate_sha256(value: &str, subject: &'static str) -> CoreResult<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CoreError::validation(subject, "must be a SHA-256 digest"));
    }
    Ok(())
}

fn is_critical_command(name: &str) -> bool {
    matches!(name, "bash" | "sh" | "cat")
}

fn build_status_command(names: &[String]) -> String {
    let worker = format!(
        r#"printf 'LR_AUDIT_STATUS_V1|ROOT|%s\n' "$(id -u 2>/dev/null || printf 1)"
for lr_name do
  lr_raw=$(command -v "$lr_name" 2>/dev/null || true)
  if [ -z "$lr_raw" ]; then
    printf 'LR_AUDIT_CMD|%s|MISSING||||\n' "$(printf %s "$lr_name" | base64 | tr -d '\n')"
    continue
  fi
  lr_path=$(readlink -f -- "$lr_raw" 2>/dev/null || printf %s "$lr_raw")
  lr_name64=$(printf %s "$lr_name" | base64 | tr -d '\n')
  lr_path64=$(printf %s "$lr_path" | base64 | tr -d '\n')
  if [ ! -f "$lr_path" ]; then
    printf 'LR_AUDIT_CMD|%s|MISSING|%s|||\n' "$lr_name64" "$lr_path64"
  elif grep -q '^# {marker}$' "$lr_path" 2>/dev/null; then
    lr_backup=$(sed -n 's/^# LR_ORIGINAL_B64=//p' "$lr_path" | head -n 1)
    lr_original=$(sed -n 's/^# LR_ORIGINAL_SHA256=//p' "$lr_path" | head -n 1)
    lr_wrapper=$(sha256sum -- "$lr_path" 2>/dev/null | awk '{{print $1}}')
    printf 'LR_AUDIT_CMD|%s|INSTRUMENTED|%s|%s|%s|%s\n' "$lr_name64" "$lr_path64" "$lr_backup" "$lr_original" "$lr_wrapper"
  elif file -- "$lr_path" 2>/dev/null | grep -qE 'script|text|ASCII'; then
    printf 'LR_AUDIT_CMD|%s|FOREIGN_SCRIPT|%s|||\n' "$lr_name64" "$lr_path64"
  else
    lr_original=$(sha256sum -- "$lr_path" 2>/dev/null | awk '{{print $1}}')
    printf 'LR_AUDIT_CMD|%s|ORIGINAL|%s||%s|\n' "$lr_name64" "$lr_path64" "$lr_original"
  fi
done"#,
        marker = WRAPPER_MARKER,
    );
    format!(
        "LOVELYRES_AUDIT_INTERNAL=1 /bin/sh -c {} lovelyres-audit-probe {}",
        shq(&worker),
        names
            .iter()
            .map(|name| shq(name))
            .collect::<Vec<_>>()
            .join(" ")
    )
}

fn parse_status_report(expected_names: &[String], output: &str) -> CoreResult<AuditStatusReport> {
    if output.len() > 256 * 1024 {
        return Err(CoreError::validation(
            "audit status",
            "probe output exceeds 256 KiB",
        ));
    }
    let expected = expected_names.iter().cloned().collect::<BTreeSet<_>>();
    let mut is_root = None;
    let mut commands = BTreeMap::new();
    for line in output.lines() {
        if let Some(value) = line.strip_prefix("LR_AUDIT_STATUS_V1|ROOT|") {
            is_root = Some(value.trim() == "0");
            continue;
        }
        let Some(payload) = line.strip_prefix("LR_AUDIT_CMD|") else {
            continue;
        };
        let fields = payload.split('|').collect::<Vec<_>>();
        if fields.len() != 6 {
            return Err(CoreError::validation(
                "audit status",
                "command row has an invalid field count",
            ));
        }
        let name = decode_text(fields[0], 128, "audit command name")?;
        validate_command_name(&name)?;
        if !expected.contains(&name) || commands.contains_key(&name) {
            return Err(CoreError::validation(
                "audit status",
                "probe returned an unexpected or duplicate command",
            ));
        }
        let state = match fields[1] {
            "ORIGINAL" => AuditCommandState::Original,
            "INSTRUMENTED" => AuditCommandState::Instrumented,
            "MISSING" => AuditCommandState::Missing,
            "FOREIGN_SCRIPT" => AuditCommandState::ForeignScript,
            _ => {
                return Err(CoreError::validation(
                    "audit status",
                    "unknown command state",
                ));
            }
        };
        let path = decode_optional_path(fields[2])?;
        let backup_path = if fields[3].is_empty() {
            None
        } else {
            let bytes = STANDARD
                .decode(fields[3])
                .map_err(|_| CoreError::validation("audit backup path", "invalid base64"))?;
            let value = String::from_utf8(bytes)
                .map_err(|_| CoreError::validation("audit backup path", "path is not UTF-8"))?;
            Some(value)
        };
        let original_sha256 = optional_digest(fields[4], "audit original digest")?;
        let wrapper_sha256 = optional_digest(fields[5], "audit wrapper digest")?;
        if (state == AuditCommandState::Original && (path.is_none() || original_sha256.is_none()))
            || (state == AuditCommandState::Instrumented
                && (path.is_none()
                    || backup_path.is_none()
                    || original_sha256.is_none()
                    || wrapper_sha256.is_none()))
        {
            return Err(CoreError::validation(
                "audit status",
                "command state is missing required identity fields",
            ));
        }
        if let (Some(path), Some(backup)) = (&path, &backup_path) {
            validate_backup_path(backup, path)?;
        }
        commands.insert(
            name.clone(),
            AuditCommandStatus {
                critical: is_critical_command(&name),
                name,
                path,
                state,
                backup_path,
                original_sha256,
                wrapper_sha256,
            },
        );
    }
    let is_root = is_root
        .ok_or_else(|| CoreError::validation("audit status", "missing versioned root marker"))?;
    if commands.len() != expected.len() {
        return Err(CoreError::validation(
            "audit status",
            "probe did not return every requested command",
        ));
    }
    Ok(AuditStatusReport {
        is_root,
        commands: expected_names
            .iter()
            .filter_map(|name| commands.remove(name))
            .collect(),
    })
}

fn decode_optional_path(value: &str) -> CoreResult<Option<String>> {
    if value.is_empty() {
        return Ok(None);
    }
    let path = decode_text(value, 4_096, "audit command path")?;
    validate_absolute_command_path(&path)?;
    Ok(Some(path))
}

fn optional_digest(value: &str, subject: &'static str) -> CoreResult<Option<String>> {
    if value.is_empty() {
        return Ok(None);
    }
    validate_sha256(value, subject)?;
    Ok(Some(value.to_ascii_lowercase()))
}

fn build_deploy_step(
    target: &TargetGuard,
    status: &AuditCommandStatus,
    is_root: bool,
) -> CoreResult<AuditMutationStep> {
    let path = status
        .path
        .as_deref()
        .ok_or_else(|| CoreError::validation("audit deployment", "command path is missing"))?;
    let original_sha256 = status
        .original_sha256
        .as_deref()
        .ok_or_else(|| CoreError::validation("audit deployment", "original digest is missing"))?;
    validate_absolute_command_path(path)?;
    validate_sha256(original_sha256, "audit original digest")?;
    let deployment_id = Uuid::new_v4();
    let (directory, base) = path.rsplit_once('/').ok_or_else(|| {
        CoreError::validation("audit command path", "command has no parent directory")
    })?;
    let backup_path = format!("{directory}/.{base}.lovelyres-orig-{deployment_id}");
    let temporary = format!("{directory}/.{base}.lovelyres-tmp-{deployment_id}");
    let wrapper = build_wrapper(
        &status.name,
        path,
        &backup_path,
        original_sha256,
        deployment_id,
    )?;
    if wrapper.len() > MAX_WRAPPER_BYTES {
        return Err(CoreError::validation(
            "audit wrapper",
            "generated wrapper is too large",
        ));
    }
    let wrapper_sha256 = hex_sha256(wrapper.as_bytes());
    let wrapper_base64 = STANDARD.encode(wrapper.as_bytes());
    let deploy_script = deploy_script(
        path,
        &backup_path,
        &temporary,
        original_sha256,
        &wrapper_sha256,
        &wrapper_base64,
    );
    let verify_command =
        verify_deploy_command(path, &backup_path, original_sha256, &wrapper_sha256);
    let rollback_command = restore_script(
        path,
        &backup_path,
        original_sha256,
        &wrapper_sha256,
        "DEPLOY_ROLLBACK_OK",
    );
    Ok(AuditMutationStep {
        label: format!("deploy {}", status.name),
        execute_command: privileged_script(is_root, &deploy_script),
        verify_command,
        verify_marker: "DEPLOY_VERIFY_OK",
        rollback_command: Some(privileged_script(is_root, &rollback_command)),
        rollback_marker: Some("DEPLOY_ROLLBACK_OK"),
        registry_effect: AuditRegistryEffect::Upsert(AuditDeployment {
            target: target.identity.clone(),
            name: status.name.clone(),
            path: path.to_owned(),
            backup_path,
            original_sha256: original_sha256.to_owned(),
            wrapper_sha256,
            wrapper_base64,
            deployed_at: Utc::now(),
        }),
    })
}

fn build_restore_step(
    target: &TargetGuard,
    status: &AuditCommandStatus,
    is_root: bool,
    deployment: Option<&AuditDeployment>,
) -> CoreResult<AuditMutationStep> {
    let path = status
        .path
        .as_deref()
        .ok_or_else(|| CoreError::validation("audit restore", "command path is missing"))?;
    let backup = status
        .backup_path
        .as_deref()
        .ok_or_else(|| CoreError::validation("audit restore", "backup path is missing"))?;
    let original_sha256 = status
        .original_sha256
        .as_deref()
        .ok_or_else(|| CoreError::validation("audit restore", "original digest is missing"))?;
    let wrapper_sha256 = status
        .wrapper_sha256
        .as_deref()
        .ok_or_else(|| CoreError::validation("audit restore", "wrapper digest is missing"))?;
    validate_backup_path(backup, path)?;
    let execute_script =
        restore_script(path, backup, original_sha256, wrapper_sha256, "RESTORE_OK");
    let verify_script = format!(
        "[ -f {path} ] && [ ! -L {path} ] && [ ! -e {backup} ] && [ \"$(sha256sum -- {path} | awk '{{print $1}}')\" = {original} ] && printf 'RESTORE_VERIFY_OK\\n'",
        path = shq(path),
        backup = shq(backup),
        original = shq(original_sha256),
    );
    let (rollback_command, rollback_marker) = if let Some(deployment) = deployment {
        if deployment.path != path
            || deployment.backup_path != backup
            || deployment.original_sha256 != original_sha256
            || deployment.wrapper_sha256 != wrapper_sha256
        {
            return Err(CoreError::validation(
                "audit deployment registry",
                "stored deployment no longer matches the remote wrapper",
            ));
        }
        let (directory, base) = path.rsplit_once('/').ok_or_else(|| {
            CoreError::validation("audit command path", "command has no parent directory")
        })?;
        let temporary = format!("{directory}/.{base}.lovelyres-redo-{}", Uuid::new_v4());
        (
            Some(privileged_script(
                is_root,
                &deploy_script(
                    path,
                    backup,
                    &temporary,
                    original_sha256,
                    wrapper_sha256,
                    &deployment.wrapper_base64,
                ),
            )),
            Some("DEPLOY_OK"),
        )
    } else {
        (None, None)
    };
    Ok(AuditMutationStep {
        label: format!("restore {}", status.name),
        execute_command: privileged_script(is_root, &execute_script),
        verify_command: internal_script(&verify_script),
        verify_marker: "RESTORE_VERIFY_OK",
        rollback_command,
        rollback_marker,
        registry_effect: AuditRegistryEffect::Remove {
            target: target.identity.clone(),
            path: path.to_owned(),
        },
    })
}

fn build_mutation_plan(
    target: TargetGuard,
    summary: String,
    restore_description: &str,
    steps: Vec<AuditMutationStep>,
    affected_commands: Vec<String>,
) -> CoreResult<AuditMutationPlan> {
    if steps.is_empty() || steps.len() > MAX_COMMANDS {
        return Err(CoreError::validation(
            "audit mutation plan",
            "must contain between 1 and 32 steps",
        ));
    }
    let mut operation =
        OperationPlan::new(target, summary, true, Some(restore_description.to_owned()))?;
    operation
        .metadata
        .insert("steps_sha256".to_owned(), steps_digest(&steps));
    operation
        .metadata
        .insert("step_count".to_owned(), steps.len().to_string());
    Ok(AuditMutationPlan {
        operation,
        steps,
        affected_commands,
    })
}

fn steps_digest(steps: &[AuditMutationStep]) -> String {
    let mut hasher = Sha256::new();
    for step in steps {
        for value in [
            step.label.as_str(),
            step.execute_command.as_str(),
            step.verify_command.as_str(),
            step.verify_marker,
            step.rollback_command.as_deref().unwrap_or_default(),
            step.rollback_marker.unwrap_or_default(),
        ] {
            hasher.update(value.len().to_le_bytes());
            hasher.update(value.as_bytes());
        }
    }
    format!("{:x}", hasher.finalize())
}

fn build_wrapper(
    name: &str,
    path: &str,
    backup: &str,
    original_sha256: &str,
    deployment_id: Uuid,
) -> CoreResult<String> {
    validate_command_name(name)?;
    validate_absolute_command_path(path)?;
    validate_backup_path(backup, path)?;
    validate_sha256(original_sha256, "audit original digest")?;
    if matches!(name, "bash" | "sh")
        && (backup.bytes().any(|byte| byte.is_ascii_whitespace()) || backup.len() + 3 > 127)
    {
        return Err(CoreError::validation(
            "audit shell wrapper",
            "shell backup path cannot be represented by the legacy Linux shebang limit",
        ));
    }
    let shebang = if matches!(name, "bash" | "sh") {
        format!("#!{backup}")
    } else {
        "#!/bin/sh".to_owned()
    };
    let backup_base64 = STANDARD.encode(backup.as_bytes());
    Ok(format!(
        r#"{shebang}
# {marker}
# LR_ORIGINAL_B64={backup_base64}
# LR_ORIGINAL_SHA256={original_sha256}
# LR_WRAPPER_ID={deployment_id}
LR_ORIG={original}
LR_LOG={log}
if [ "${{LOVELYRES_AUDIT_SELFTEST:-}}" = 1 ]; then
  printf 'LOVELYRES_AUDIT_WRAPPER_OK\n'
  exit 0
fi
if [ "${{LOVELYRES_AUDIT_INTERNAL:-}}" = 1 ]; then
  if [ -n "${{BASH_VERSION:-}}" ]; then
    exec -a "$0" "$LR_ORIG" "$@"
  else
    exec "$LR_ORIG" "$@"
  fi
fi
lr_b64() {{ printf %s "$1" | base64 | tr -d '\n'; }}
lr_name=${{0##*/}}
lr_args=$(printf '%.2048s' "$*" | base64 | tr -d '\n')
lr_ts=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || printf unknown)
lr_user=$(id -un 2>/dev/null || printf unknown)
lr_caller=$(ps -o comm= "$PPID" 2>/dev/null | head -n 1)
if [ -f "$LR_LOG" ] && [ ! -L "$LR_LOG" ]; then
  printf 'LR_AUDIT_V2|%s|%s|%s|%s|%s|%s|%s\n' "$(lr_b64 "$lr_ts")" "$(lr_b64 "$lr_name")" "$lr_args" "$(lr_b64 "$lr_user")" "$$" "$PPID" "$(lr_b64 "$lr_caller")" >> "$LR_LOG" 2>/dev/null || true
fi
if [ -n "${{BASH_VERSION:-}}" ]; then
  exec -a "$0" "$LR_ORIG" "$@"
else
  exec "$LR_ORIG" "$@"
fi
"#,
        marker = WRAPPER_MARKER,
        original = shq(backup),
        log = shq(LOG_PATH),
    ))
}

fn deploy_script(
    path: &str,
    backup: &str,
    temporary: &str,
    original_sha256: &str,
    wrapper_sha256: &str,
    wrapper_base64: &str,
) -> String {
    format!(
        "set -eu; lr_committed=0; trap '[ \"$lr_committed\" = 1 ] || rm -f -- {backup} {temporary}' 0 1 2 15; [ -f {path} ] && [ ! -L {path} ] && [ ! -u {path} ] && [ ! -g {path} ] && [ ! -e {backup} ] && [ ! -e {temporary} ]; if command -v getcap >/dev/null 2>&1; then [ -z \"$(getcap {path} 2>/dev/null)\" ]; fi; [ \"$(sha256sum -- {path} | awk '{{print $1}}')\" = {original} ]; cp --preserve=all -- {path} {backup}; printf %s {wrapper_b64} | base64 -d > {temporary}; [ \"$(sha256sum -- {temporary} | awk '{{print $1}}')\" = {wrapper} ]; chmod --reference={path} {temporary}; chown --reference={path} {temporary}; touch -r {path} {temporary}; if command -v chcon >/dev/null 2>&1; then chcon --reference={path} {temporary}; fi; if [ -e {log_dir} ]; then [ -d {log_dir} ] && [ ! -L {log_dir} ] && [ \"$(stat -c %u -- {log_dir})\" = 0 ]; else install -d -o 0 -g 0 -m 0755 -- {log_dir}; fi; chmod 0755 -- {log_dir}; if [ -e {log} ]; then [ -f {log} ] && [ ! -L {log} ] && [ \"$(stat -c %u -- {log})\" = 0 ] && [ \"$(stat -c %h -- {log})\" = 1 ]; else install -o 0 -g 0 -m 0666 /dev/null {log}; fi; chmod 0666 -- {log}; mv -- {temporary} {path}; lr_committed=1; trap - 0 1 2 15; printf 'DEPLOY_OK\\n'",
        path = shq(path),
        backup = shq(backup),
        temporary = shq(temporary),
        original = shq(original_sha256),
        wrapper = shq(wrapper_sha256),
        wrapper_b64 = shq(wrapper_base64),
        log_dir = shq(LOG_DIR),
        log = shq(LOG_PATH),
    )
}

fn verify_deploy_command(
    path: &str,
    backup: &str,
    original_sha256: &str,
    wrapper_sha256: &str,
) -> String {
    let script = format!(
        "[ -f {path} ] && [ ! -L {path} ] && [ -f {backup} ] && [ ! -L {backup} ] && [ \"$(sha256sum -- {path} | awk '{{print $1}}')\" = {wrapper} ] && [ \"$(sha256sum -- {backup} | awk '{{print $1}}')\" = {original} ] && [ \"$(LOVELYRES_AUDIT_SELFTEST=1 {path})\" = LOVELYRES_AUDIT_WRAPPER_OK ] && {{ {path} --help </dev/null >/dev/null 2>&1; lr_code=$?; [ \"$lr_code\" -le 2 ]; }} && printf 'DEPLOY_VERIFY_OK\\n'",
        path = shq(path),
        backup = shq(backup),
        original = shq(original_sha256),
        wrapper = shq(wrapper_sha256),
    );
    internal_script(&script)
}

fn restore_script(
    path: &str,
    backup: &str,
    original_sha256: &str,
    wrapper_sha256: &str,
    marker: &str,
) -> String {
    format!(
        "set -eu; [ -f {path} ] && [ ! -L {path} ] && [ -f {backup} ] && [ ! -L {backup} ]; [ \"$(sha256sum -- {path} | awk '{{print $1}}')\" = {wrapper} ]; [ \"$(sha256sum -- {backup} | awk '{{print $1}}')\" = {original} ]; mv -- {backup} {path}; [ \"$(sha256sum -- {path} | awk '{{print $1}}')\" = {original} ]; printf {marker}",
        path = shq(path),
        backup = shq(backup),
        original = shq(original_sha256),
        wrapper = shq(wrapper_sha256),
        marker = shq(&format!("{marker}\n")),
    )
}

fn privileged_script(is_root: bool, script: &str) -> String {
    if is_root {
        internal_script(script)
    } else {
        format!(
            "LOVELYRES_AUDIT_INTERNAL=1 sudo -n LOVELYRES_AUDIT_INTERNAL=1 /bin/sh -c {}",
            shq(script)
        )
    }
}

fn internal_script(script: &str) -> String {
    format!("LOVELYRES_AUDIT_INTERNAL=1 /bin/sh -c {}", shq(script))
}

fn parse_log(output: &str) -> CoreResult<Vec<AuditLogEntry>> {
    let mut entries = Vec::new();
    for line in output.lines() {
        if line.starts_with("LR_AUDIT_V2|") {
            match parse_v2_log_line(line) {
                Ok(Some(entry)) => entries.push(entry),
                Ok(None) => {}
                Err(error) => entries.push(invalid_log_entry(line, error)),
            }
        } else {
            match parse_legacy_log_line(line) {
                Ok(Some(entry)) => entries.push(entry),
                Ok(None) => {}
                Err(error) => entries.push(invalid_log_entry(line, error)),
            }
        }
    }
    if entries.len() > MAX_LOG_ENTRIES {
        entries.drain(..entries.len() - MAX_LOG_ENTRIES);
    }
    Ok(entries)
}

fn invalid_log_entry(line: &str, error: CoreError) -> AuditLogEntry {
    AuditLogEntry {
        timestamp: "unknown".to_owned(),
        command: "invalid-record".to_owned(),
        args: error.to_string(),
        user: "unknown".to_owned(),
        pid: 0,
        ppid: 0,
        caller: "untrusted-log-input".to_owned(),
        raw: line.chars().take(4_096).collect(),
        suspicious: true,
    }
}

fn parse_v2_log_line(line: &str) -> CoreResult<Option<AuditLogEntry>> {
    let Some(payload) = line.strip_prefix("LR_AUDIT_V2|") else {
        return Ok(None);
    };
    let fields = payload.split('|').collect::<Vec<_>>();
    if fields.len() != 7 {
        return Err(CoreError::validation(
            "command audit log",
            "V2 row has an invalid field count",
        ));
    }
    let timestamp = decode_log_text(fields[0], 64, "audit timestamp")?;
    let command = decode_log_text(fields[1], 128, "audit command")?;
    let args = decode_log_text(fields[2], 2_048, "audit arguments")?;
    let user = decode_log_text(fields[3], 128, "audit user")?;
    let pid = parse_pid(fields[4], "audit pid")?;
    let ppid = parse_pid(fields[5], "audit parent pid")?;
    let caller = decode_log_text(fields[6], 256, "audit caller")?;
    let suspicious = is_suspicious(&command, &args);
    Ok(Some(AuditLogEntry {
        timestamp,
        command,
        args,
        user,
        pid,
        ppid,
        caller,
        raw: line.chars().take(4_096).collect(),
        suspicious,
    }))
}

fn decode_log_text(value: &str, maximum: usize, subject: &'static str) -> CoreResult<String> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| CoreError::validation(subject, "invalid base64"))?;
    if bytes.len() > maximum {
        return Err(CoreError::validation(subject, "decoded value is too large"));
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn parse_legacy_log_line(line: &str) -> CoreResult<Option<AuditLogEntry>> {
    let Some(close) = line.find("] CMD=") else {
        return Ok(None);
    };
    if !line.starts_with('[') {
        return Ok(None);
    }
    let timestamp = line[1..close].to_owned();
    let rest = &line[close + "] CMD=".len()..];
    let Some((command, rest)) = rest.split_once(" ARGS=") else {
        return Ok(None);
    };
    let Some((args, rest)) = rest.rsplit_once(" USER=") else {
        return Ok(None);
    };
    let Some((user, rest)) = rest.split_once(" PID=") else {
        return Ok(None);
    };
    let Some((pid, rest)) = rest.split_once(" PPID=") else {
        return Ok(None);
    };
    let Some((ppid, caller)) = rest.split_once(" CALLER=") else {
        return Ok(None);
    };
    let timestamp = bounded_text(timestamp, 64, "audit timestamp")?;
    let command = bounded_text(command.to_owned(), 128, "audit command")?;
    let args = bounded_text(args.to_owned(), 2_048, "audit arguments")?;
    let user = bounded_text(user.to_owned(), 128, "audit user")?;
    let caller = bounded_text(caller.to_owned(), 256, "audit caller")?;
    let pid = parse_pid(pid, "audit pid")?;
    let ppid = parse_pid(ppid, "audit parent pid")?;
    let suspicious = is_suspicious(&command, &args);
    Ok(Some(AuditLogEntry {
        timestamp,
        command,
        args,
        user,
        pid,
        ppid,
        caller,
        raw: line.chars().take(4_096).collect(),
        suspicious,
    }))
}

fn decode_text(value: &str, maximum: usize, subject: &'static str) -> CoreResult<String> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| CoreError::validation(subject, "invalid base64"))?;
    if bytes.len() > maximum {
        return Err(CoreError::validation(
            subject,
            format!("exceeds {maximum} bytes"),
        ));
    }
    let text = String::from_utf8(bytes)
        .map_err(|_| CoreError::validation(subject, "value is not UTF-8"))?;
    bounded_text(text, maximum, subject)
}

fn bounded_text(value: String, maximum: usize, subject: &'static str) -> CoreResult<String> {
    if value.len() > maximum || value.chars().any(|character| character == '\0') {
        return Err(CoreError::validation(
            subject,
            format!("must be at most {maximum} bytes and contain no NUL"),
        ));
    }
    Ok(value)
}

fn parse_pid(value: &str, subject: &'static str) -> CoreResult<u32> {
    value
        .parse::<u32>()
        .map_err(|_| CoreError::validation(subject, "must be an unsigned decimal process id"))
}

fn is_suspicious(command: &str, args: &str) -> bool {
    let value = format!("{command} {args}").to_ascii_lowercase();
    [
        "flag",
        "/etc/passwd",
        "/etc/shadow",
        ".ssh",
        "secret",
        "token",
        "password",
        "key_file",
        "key.file",
    ]
    .iter()
    .any(|needle| value.contains(needle))
}

fn analyze_log(entries: Vec<AuditLogEntry>) -> AuditLogReport {
    let mut counts = BTreeMap::<String, usize>::new();
    let mut suspicious_count = 0;
    for entry in &entries {
        *counts.entry(entry.command.clone()).or_default() += 1;
        suspicious_count += usize::from(entry.suspicious);
    }
    let mut command_counts = counts
        .into_iter()
        .map(|(command, count)| AuditCommandCount { command, count })
        .collect::<Vec<_>>();
    command_counts.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.command.cmp(&right.command))
    });
    command_counts.truncate(8);
    AuditLogReport {
        entries,
        suspicious_count,
        command_counts,
    }
}

fn analyze_cycles(entries: &[AuditLogEntry]) -> AuditAnalysis {
    let mut groups = BTreeMap::<(String, String), Vec<&AuditLogEntry>>::new();
    for entry in entries {
        groups
            .entry((entry.command.clone(), entry.args.clone()))
            .or_default()
            .push(entry);
    }
    let mut cycles = groups
        .into_iter()
        .filter(|(_, group)| group.len() >= 2)
        .map(|((command, args), group)| AuditCycle {
            interval_seconds: detect_period(group.iter().map(|entry| entry.timestamp.as_str())),
            count: group.len(),
            last_seen: group
                .last()
                .map_or_else(String::new, |entry| entry.timestamp.clone()),
            category: classify_command(&command, &args),
            command,
            args,
        })
        .collect::<Vec<_>>();
    cycles.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.command.cmp(&right.command))
            .then_with(|| left.args.cmp(&right.args))
    });
    let suggestions = cycles
        .iter()
        .enumerate()
        .filter_map(|(index, cycle)| cycle_suggestion(index, cycle))
        .collect();
    AuditAnalysis {
        cycles,
        suggestions,
    }
}

fn detect_period<'a>(timestamps: impl Iterator<Item = &'a str>) -> Option<u64> {
    let values = timestamps
        .filter_map(|value| NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S").ok())
        .map(|value| value.and_utc().timestamp())
        .collect::<Vec<_>>();
    if values.len() < 3 {
        return None;
    }
    let intervals = values
        .windows(2)
        .filter_map(|pair| u64::try_from(pair[1] - pair[0]).ok())
        .collect::<Vec<_>>();
    if intervals.len() + 1 != values.len() || intervals.contains(&0) {
        return None;
    }
    let average = intervals.iter().sum::<u64>() as f64 / intervals.len() as f64;
    intervals
        .iter()
        .all(|value| ((*value as f64 - average).abs() / average) < 0.3)
        .then_some(average.round() as u64)
}

fn classify_command(command: &str, args: &str) -> AuditCycleCategory {
    if matches!(command, "cat" | "grep" | "find" | "ls" | "head" | "tail") && args.contains('/') {
        AuditCycleCategory::FileRead
    } else if matches!(command, "systemctl" | "service" | "ss" | "netstat") {
        AuditCycleCategory::ServiceCheck
    } else if matches!(command, "curl" | "wget") {
        AuditCycleCategory::Network
    } else if matches!(command, "mysql" | "redis-cli" | "psql" | "mongo") {
        AuditCycleCategory::Database
    } else {
        AuditCycleCategory::Process
    }
}

fn cycle_suggestion(index: usize, cycle: &AuditCycle) -> Option<AuditSuggestion> {
    validate_command_name(&cycle.command).ok()?;
    let id = format!("audit-fix-{index}");
    match cycle.category {
        AuditCycleCategory::FileRead => {
            let path = cycle
                .args
                .split_whitespace()
                .find(|part| part.starts_with('/'))?;
            validate_absolute_command_path(path).ok()?;
            Some(AuditSuggestion {
                id,
                severity: AuditSuggestionSeverity::Critical,
                title: format!("核实文件 {path}"),
                description: format!(
                    "Check 脚本{}使用 {} 读取此文件",
                    period_text(cycle.interval_seconds),
                    cycle.command
                ),
                check_command: format!("ls -la -- {}", shq(path)),
                fix_command: format!(
                    "ls -la -- {path} && {command} -- {path} | head -5",
                    path = shq(path),
                    command = cycle.command,
                ),
            })
        }
        AuditCycleCategory::Network => {
            let endpoint = cycle
                .args
                .split_whitespace()
                .find(|part| part.starts_with("http://") || part.starts_with("https://"))
                .unwrap_or(cycle.args.as_str());
            Some(AuditSuggestion {
                id,
                severity: AuditSuggestionSeverity::Critical,
                title: format!("核实网络端点 {}", truncate(endpoint, 160)),
                description: format!(
                    "Check 脚本{}访问此端点",
                    period_text(cycle.interval_seconds)
                ),
                check_command: format!("curl -sI -- {} | head -5", shq(endpoint)),
                fix_command: format!("curl -sI -- {} | head -5", shq(endpoint)),
            })
        }
        AuditCycleCategory::ServiceCheck => {
            let service = cycle
                .args
                .split_whitespace()
                .find(|value| is_service_name(value));
            Some(AuditSuggestion {
                id,
                severity: AuditSuggestionSeverity::Warning,
                title: service.map_or_else(
                    || format!("核实服务检查命令 {}", cycle.command),
                    |service| format!("核实服务 {service}"),
                ),
                description: format!("Check 脚本执行 {} {}", cycle.command, cycle.args),
                check_command: service.map_or_else(
                    || format!("{} --help", cycle.command),
                    |service| format!("systemctl status -- {}", shq(service)),
                ),
                fix_command: service.map_or_else(
                    || format!("{} --help", cycle.command),
                    |service| {
                        format!(
                            "systemctl start -- {service} && systemctl status -- {service}",
                            service = shq(service)
                        )
                    },
                ),
            })
        }
        AuditCycleCategory::Database => Some(AuditSuggestion {
            id,
            severity: AuditSuggestionSeverity::Critical,
            title: format!("核实 {} 数据库客户端与服务", cycle.command),
            description: format!("Check 脚本执行 {}", truncate(&cycle.args, 160)),
            check_command: format!("{} --version", cycle.command),
            fix_command: format!("{} --version", cycle.command),
        }),
        AuditCycleCategory::Process if cycle.count >= 3 => Some(AuditSuggestion {
            id,
            severity: AuditSuggestionSeverity::Info,
            title: format!("复核周期命令 {}", cycle.command),
            description: format!(
                "共执行 {} 次{}",
                cycle.count,
                period_text(cycle.interval_seconds)
            ),
            check_command: format!("{} --help", cycle.command),
            fix_command: format!("{} --help", cycle.command),
        }),
        AuditCycleCategory::Process => None,
    }
}

fn period_text(period: Option<u64>) -> String {
    period.map_or_else(String::new, |seconds| format!("约每 {seconds} 秒"))
}

fn is_service_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"@_.:-".contains(&byte))
}

fn truncate(value: &str, maximum: usize) -> String {
    value.chars().take(maximum).collect()
}

fn hex_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn successful_output(subject: &'static str, output: SshCommandOutput) -> CoreResult<String> {
    if output.timed_out {
        return Err(CoreError::ssh(subject, "remote command timed out"));
    }
    if output.exit_code != Some(0) {
        return Err(CoreError::ssh(
            subject,
            format!(
                "remote command exited with {:?}: {}",
                output.exit_code,
                output.output.chars().take(1_024).collect::<String>()
            ),
        ));
    }
    Ok(output.output)
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use super::*;
    use crate::{
        BackendServices,
        ssh::{SshConnectionStatus, TestSessionHarness},
    };

    #[derive(Debug)]
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("lovelyres-audit-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    async fn bound_services(
        root: &TestRoot,
    ) -> (BackendServices, BoundSshSession, Arc<TestSessionHarness>) {
        let services =
            BackendServices::new(PortableStore::prepare(root.0.clone()).unwrap()).unwrap();
        let guard = services
            .activate_target(TargetIdentity::new("connection-a").unwrap())
            .unwrap();
        let status = SshConnectionStatus {
            session_id: "session-a".to_owned(),
            connection_id: "connection-a".to_owned(),
            host: "host-a.test".to_owned(),
            port: 22,
            username: "operator".to_owned(),
            host_key_fingerprint: "SHA256:test".to_owned(),
            connected_at: Utc::now(),
        };
        let session = BoundSshSession::from_status(guard, &status, "test session").unwrap();
        let harness = Arc::new(TestSessionHarness::default());
        services
            .ssh()
            .install_test_session(status, harness.clone())
            .await
            .unwrap();
        (services, session, harness)
    }

    fn status_row(
        name: &str,
        state: &str,
        path: &str,
        backup: &str,
        original: &str,
        wrapper: &str,
    ) -> String {
        format!(
            "LR_AUDIT_CMD|{}|{state}|{}|{}|{original}|{wrapper}",
            STANDARD.encode(name),
            if path.is_empty() {
                String::new()
            } else {
                STANDARD.encode(path)
            },
            if backup.is_empty() {
                String::new()
            } else {
                STANDARD.encode(backup)
            },
        )
    }

    #[test]
    fn command_names_and_paths_fail_closed_before_shell_construction() {
        for invalid in ["", "cat;id", "../cat", "-rf", "a b", "a\nwhoami"] {
            assert!(
                validate_command_name(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
        assert!(validate_command_name("redis-cli").is_ok());
        assert!(validate_absolute_command_path("/usr/local/bin/tool-1").is_ok());
        for invalid in ["relative", "/usr/bin/../tmp/x", "/usr/bin/cat\nrm"] {
            assert!(validate_absolute_command_path(invalid).is_err());
        }
    }

    #[test]
    fn status_parser_requires_every_requested_typed_row() {
        let names = vec!["cat".to_owned(), "missing".to_owned()];
        let output = format!(
            "LR_AUDIT_STATUS_V1|ROOT|0\n{}\n{}\n",
            status_row("cat", "ORIGINAL", "/usr/bin/cat", "", &"a".repeat(64), ""),
            status_row("missing", "MISSING", "", "", "", ""),
        );
        let parsed = parse_status_report(&names, &output).unwrap();
        assert!(parsed.is_root);
        assert_eq!(parsed.commands[0].state, AuditCommandState::Original);
        assert_eq!(parsed.commands[1].state, AuditCommandState::Missing);
        let unexpected = output.replace(&STANDARD.encode("missing"), &STANDARD.encode("other"));
        assert!(parse_status_report(&names, &unexpected).is_err());
    }

    #[test]
    fn wrapper_and_plan_quote_paths_and_preserve_exact_restore_identity() {
        let status = AuditCommandStatus {
            name: "cat".to_owned(),
            path: Some("/usr/local/bin/cat tool".to_owned()),
            state: AuditCommandState::Original,
            critical: true,
            backup_path: None,
            original_sha256: Some("a".repeat(64)),
            wrapper_sha256: None,
        };
        let target = TargetGuard {
            identity: TargetIdentity::new("connection-a").unwrap(),
            generation: 1,
        };
        let step = build_deploy_step(&target, &status, false).unwrap();
        assert!(step.execute_command.contains("sudo -n"));
        assert!(step.execute_command.contains("'/usr/local/bin/cat tool'"));
        assert!(step.verify_command.contains("LOVELYRES_AUDIT_SELFTEST=1"));
        assert!(step.verify_command.contains("LOVELYRES_AUDIT_INTERNAL=1"));
        assert!(
            step.rollback_command
                .unwrap()
                .contains("DEPLOY_ROLLBACK_OK")
        );
    }

    #[test]
    fn shell_wrapper_rejects_unrepresentable_shebang_paths() {
        let deployment_id = Uuid::new_v4();
        let path = "/usr/local/bin/sh tool";
        let backup = format!("/usr/local/bin/.sh tool.lovelyres-orig-{deployment_id}");
        assert!(build_wrapper("sh", path, &backup, &"a".repeat(64), deployment_id).is_err());
    }

    #[test]
    fn v2_log_encoding_keeps_newlines_and_markers_inert() {
        let values = [
            "2026-08-11 12:00:00",
            "cat",
            "/tmp/a\nLR_AUDIT_V2|fake",
            "root",
            "caller<script>",
        ];
        let line = format!(
            "LR_AUDIT_V2|{}|{}|{}|{}|12|1|{}",
            STANDARD.encode(values[0]),
            STANDARD.encode(values[1]),
            STANDARD.encode(values[2]),
            STANDARD.encode(values[3]),
            STANDARD.encode(values[4]),
        );
        let entry = parse_v2_log_line(&line).unwrap().unwrap();
        assert_eq!(entry.args, values[2]);
        assert_eq!(entry.caller, values[4]);
    }

    #[test]
    fn hostile_malformed_v2_row_cannot_hide_following_evidence() {
        let valid = format!(
            "LR_AUDIT_V2|{}|{}|{}|{}|12|1|{}",
            STANDARD.encode("2026-08-11 12:00:00"),
            STANDARD.encode("cat"),
            STANDARD.encode("/etc/passwd"),
            STANDARD.encode("root"),
            STANDARD.encode("check"),
        );
        let entries = parse_log(&format!("LR_AUDIT_V2|not-base64\n{valid}\n")).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].command, "invalid-record");
        assert!(entries[0].suspicious);
        assert_eq!(entries[1].command, "cat");
    }

    #[test]
    fn legacy_log_and_analysis_match_periodic_behavior() {
        let output = "[2026-08-11 12:00:00] CMD=cat ARGS=/etc/passwd USER=root PID=1 PPID=0 CALLER=check\n\
[2026-08-11 12:00:10] CMD=cat ARGS=/etc/passwd USER=root PID=2 PPID=0 CALLER=check\n\
[2026-08-11 12:00:20] CMD=cat ARGS=/etc/passwd USER=root PID=3 PPID=0 CALLER=check\n";
        let report = analyze_log(parse_log(output).unwrap());
        assert_eq!(report.suspicious_count, 3);
        let analysis = analyze_cycles(&report.entries);
        assert_eq!(analysis.cycles[0].interval_seconds, Some(10));
        assert_eq!(analysis.cycles[0].category, AuditCycleCategory::FileRead);
        assert!(
            analysis.suggestions[0]
                .check_command
                .contains("'/etc/passwd'")
        );
    }

    #[tokio::test]
    async fn duplicate_alias_paths_create_one_atomic_batch_step() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        harness.set_execute_output(format!(
            "LR_AUDIT_STATUS_V1|ROOT|0\n{}\n{}\n",
            status_row("bash", "ORIGINAL", "/usr/bin/bash", "", &"a".repeat(64), ""),
            status_row("sh", "ORIGINAL", "/usr/bin/bash", "", &"a".repeat(64), ""),
        ));
        let plan = services
            .audit()
            .plan_deploy_many(&session, &["bash".to_owned(), "sh".to_owned()])
            .await
            .unwrap();
        assert_eq!(plan.steps.len(), 1);
        assert_eq!(plan.affected_commands(), &["bash", "sh"]);
    }

    #[tokio::test]
    async fn deployment_requires_exact_confirmation_then_journals_and_persists_identity() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        let status_output = format!(
            "LR_AUDIT_STATUS_V1|ROOT|0\n{}\n",
            status_row("cat", "ORIGINAL", "/usr/bin/cat", "", &"a".repeat(64), ""),
        );
        harness.set_execute_output(status_output.clone());
        let wrong_plan = services.audit().plan_deploy(&session, "cat").await.unwrap();
        let plan = services.audit().plan_deploy(&session, "cat").await.unwrap();
        let wrong_confirmation = DangerousConfirmation::approve(wrong_plan.definition());
        assert!(
            services
                .audit()
                .execute_mutation(
                    &session,
                    plan,
                    wrong_confirmation,
                    services.operation_journal(),
                )
                .await
                .is_err()
        );
        assert!(services.operation_journal().entries().unwrap().is_empty());

        harness.set_execute_output(status_output);
        let plan = services.audit().plan_deploy(&session, "cat").await.unwrap();
        let deployment = match &plan.steps[0].registry_effect {
            AuditRegistryEffect::Upsert(deployment) => deployment.clone(),
            _ => panic!("deployment plan must upsert its immutable remote identity"),
        };
        let confirmation = DangerousConfirmation::approve(plan.definition());
        harness.set_execute_output("DEPLOY_OK\nDEPLOY_VERIFY_OK\n");
        let outcome = services
            .audit()
            .execute_mutation(&session, plan, confirmation, services.operation_journal())
            .await
            .unwrap();
        assert!(outcome.verified);
        assert_eq!(
            services
                .audit()
                .repository
                .deployment(&session.target().identity, "/usr/bin/cat")
                .unwrap(),
            Some(deployment)
        );
        let journal = services.operation_journal().entries().unwrap();
        assert_eq!(journal.len(), 2);
        assert_eq!(journal[0].phase, crate::operations::JournalPhase::Executed);
        assert_eq!(
            journal[1].phase,
            crate::operations::JournalPhase::VerificationPassed
        );
    }

    #[tokio::test]
    async fn restore_uses_persisted_wrapper_identity_and_removes_registry_entry() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        harness.set_execute_output(format!(
            "LR_AUDIT_STATUS_V1|ROOT|0\n{}\n",
            status_row("cat", "ORIGINAL", "/usr/bin/cat", "", &"a".repeat(64), ""),
        ));
        let deploy = services.audit().plan_deploy(&session, "cat").await.unwrap();
        let deployment = match &deploy.steps[0].registry_effect {
            AuditRegistryEffect::Upsert(deployment) => deployment.clone(),
            _ => panic!("deployment plan must carry a registry upsert"),
        };
        let confirmation = DangerousConfirmation::approve(deploy.definition());
        harness.set_execute_output("DEPLOY_OK\nDEPLOY_VERIFY_OK\n");
        services
            .audit()
            .execute_mutation(&session, deploy, confirmation, services.operation_journal())
            .await
            .unwrap();

        harness.set_execute_output(format!(
            "LR_AUDIT_STATUS_V1|ROOT|0\n{}\n",
            status_row(
                "cat",
                "INSTRUMENTED",
                &deployment.path,
                &deployment.backup_path,
                &deployment.original_sha256,
                &deployment.wrapper_sha256,
            ),
        ));
        let restore = services
            .audit()
            .plan_restore(&session, "cat")
            .await
            .unwrap();
        assert!(restore.steps[0].rollback_command.is_some());
        let confirmation = DangerousConfirmation::approve(restore.definition());
        harness.set_execute_output("RESTORE_OK\nRESTORE_VERIFY_OK\n");
        let outcome = services
            .audit()
            .execute_mutation(
                &session,
                restore,
                confirmation,
                services.operation_journal(),
            )
            .await
            .unwrap();
        assert!(outcome.verified);
        assert!(
            services
                .audit()
                .repository
                .deployment(&session.target().identity, &deployment.path)
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn clear_log_is_root_aware_and_does_not_create_a_deployment_registry() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        harness.set_execute_output("1000\n");
        let plan = services.audit().plan_clear_log(&session).await.unwrap();
        assert!(plan.steps[0].execute_command.contains("sudo -n "));
        assert!(plan.steps[0].execute_command.contains(LOG_DIR));
        let confirmation = DangerousConfirmation::approve(plan.definition());
        harness.set_execute_output("CLEAR_OK\nCLEAR_VERIFY_OK\n");
        let outcome = services
            .audit()
            .execute_mutation(&session, plan, confirmation, services.operation_journal())
            .await
            .unwrap();
        assert!(outcome.verified);
        assert!(!root.0.join("data").join("audit.json").exists());
    }
}
