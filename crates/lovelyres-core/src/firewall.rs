//! Target-bound firewall inspection and reversible response operations.
//!
//! Mutations never accept raw shell or rule syntax. LovelyRes creates one
//! uniquely named chain/table, arms a remote dead-man rollback, verifies that
//! the guarded SSH session is still responsive, and only then allows the UI to
//! explicitly keep the change.

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    CoreError, CoreResult, PortableStore,
    operations::{
        DangerousConfirmation, ExecutionReceipt, OperationExecutor, OperationJournal,
        OperationPlan, OperationState, PlannedOperation, PortableOperationJournal,
        VerificationResult,
    },
    shell_escape::{is_valid_ip_or_cidr, shq},
    ssh::{BoundSshSession, SshCommandOutput, SshService},
    store::StoreFile,
    target::{TargetContext, TargetGuard, TargetIdentity},
};

const FIREWALL_ROOT: &str = "/tmp/.lovelyres_fw";
const DEADMAN_SECONDS: i64 = 60;
const TEMPORARY_BLOCK_SECONDS: i64 = 300;
const READ_TIMEOUT: Duration = Duration::from_secs(30);
const MUTATION_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RULE_BYTES: usize = 2 * 1024 * 1024;
const MAX_RECORDS: usize = 256;
const PROBE_MARKER: &str = "LR_FIREWALL_PROBE_V1";
const APPLY_MARKER: &str = "LR_FIREWALL_APPLY_V1";
const VERIFY_MARKER: &str = "LR_FIREWALL_VERIFY_V1";
const KEEP_MARKER: &str = "LR_FIREWALL_KEEP_V1";
const RESTORE_MARKER: &str = "LR_FIREWALL_RESTORE_V1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FirewallBackend {
    Iptables,
    Nftables,
    Ufw,
    Firewalld,
    Unknown,
}

impl FirewallBackend {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Iptables => "iptables",
            Self::Nftables => "nftables",
            Self::Ufw => "ufw",
            Self::Firewalld => "firewalld",
            Self::Unknown => "未探测到",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FirewallEngine {
    Iptables,
    Nftables,
    Unavailable,
}

impl FirewallEngine {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Iptables => "iptables isolated chain",
            Self::Nftables => "nftables isolated table",
            Self::Unavailable => "仅查看",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallInspection {
    pub target: TargetGuard,
    pub backend: FirewallBackend,
    pub engine: FirewallEngine,
    pub active: bool,
    pub rules: String,
    pub rules_truncated: bool,
    pub rules_sha256: String,
    pub captured_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum FirewallMutationRequest {
    BlockIpv4 { source: String },
    TemporaryBlockIpv4 { source: String },
    AllowTcpPort { port: u16 },
    IsolateInbound,
}

impl FirewallMutationRequest {
    pub fn block_ipv4(source: impl Into<String>) -> CoreResult<Self> {
        let source = normalize_ipv4_or_cidr(&source.into())?;
        Ok(Self::BlockIpv4 { source })
    }

    pub fn temporary_block_ipv4(source: impl Into<String>) -> CoreResult<Self> {
        let source = normalize_ipv4_or_cidr(&source.into())?;
        Ok(Self::TemporaryBlockIpv4 { source })
    }

    pub fn allow_tcp_port(port: u16) -> CoreResult<Self> {
        if port == 0 {
            return Err(CoreError::validation(
                "firewall port",
                "must be in 1..=65535",
            ));
        }
        Ok(Self::AllowTcpPort { port })
    }

    pub const fn isolate_inbound() -> Self {
        Self::IsolateInbound
    }

    pub fn label(&self) -> String {
        match self {
            Self::BlockIpv4 { source } => format!("封禁 IPv4 来源 {source}"),
            Self::TemporaryBlockIpv4 { source } => {
                format!("临时封禁 IPv4 来源 {source}（5 分钟）")
            }
            Self::AllowTcpPort { port } => format!("放行 TCP 端口 {port}"),
            Self::IsolateInbound => "隔离入站流量（保留 SSH、回环及已建立连接）".to_owned(),
        }
    }

    fn validate(&self) -> CoreResult<()> {
        match self {
            Self::BlockIpv4 { source } | Self::TemporaryBlockIpv4 { source } => {
                let normalized = normalize_ipv4_or_cidr(source)?;
                if &normalized != source {
                    return Err(CoreError::validation(
                        "firewall source",
                        "must use the canonical IPv4/CIDR form",
                    ));
                }
            }
            Self::AllowTcpPort { port } if *port == 0 => {
                return Err(CoreError::validation(
                    "firewall port",
                    "must be in 1..=65535",
                ));
            }
            Self::AllowTcpPort { .. } | Self::IsolateInbound => {}
        }
        Ok(())
    }

    const fn deadman_seconds(&self) -> i64 {
        match self {
            Self::TemporaryBlockIpv4 { .. } => TEMPORARY_BLOCK_SECONDS,
            Self::BlockIpv4 { .. } | Self::AllowTcpPort { .. } | Self::IsolateInbound => {
                DEADMAN_SECONDS
            }
        }
    }

    const fn can_keep(&self) -> bool {
        !matches!(self, Self::TemporaryBlockIpv4 { .. })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FirewallChangeState {
    AwaitingKeep,
    Kept,
    Restored,
    AutoRestored,
}

impl FirewallChangeState {
    pub const fn label(self) -> &'static str {
        match self {
            Self::AwaitingKeep => "等待保留确认",
            Self::Kept => "已保留",
            Self::Restored => "已恢复",
            Self::AutoRestored => "已自动恢复",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallChangeRecord {
    pub id: String,
    pub operation_id: String,
    pub last_operation_id: String,
    pub target: TargetIdentity,
    pub backend: FirewallBackend,
    pub engine: FirewallEngine,
    pub request: FirewallMutationRequest,
    pub ssh_port: u16,
    pub remote_root: String,
    pub object_name: String,
    pub preflight_sha256: String,
    pub state: FirewallChangeState,
    pub created_at: DateTime<Utc>,
    pub deadman_deadline: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct FirewallMutationPlan {
    operation: OperationPlan,
    backend: FirewallBackend,
    engine: FirewallEngine,
    request: FirewallMutationRequest,
    ssh_port: u16,
    change_id: String,
    remote_root: String,
    object_name: String,
    preflight_sha256: String,
}

impl FirewallMutationPlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn request(&self) -> &FirewallMutationRequest {
        &self.request
    }

    pub const fn deadman_seconds(&self) -> i64 {
        self.request.deadman_seconds()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallResolution {
    Keep,
    Restore,
}

#[derive(Debug, Clone)]
pub struct FirewallResolutionPlan {
    operation: OperationPlan,
    change: FirewallChangeRecord,
    resolution: FirewallResolution,
}

impl FirewallResolutionPlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub const fn resolution(&self) -> FirewallResolution {
        self.resolution
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallOperationOutcome {
    pub change: FirewallChangeRecord,
    pub verification: VerificationResult,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct StoredFirewall {
    changes: Vec<FirewallChangeRecord>,
}

#[derive(Debug, Clone)]
pub struct FirewallService {
    ssh: SshService,
    target: Arc<TargetContext>,
    store: PortableStore,
    journal: PortableOperationJournal,
    lock: Arc<Mutex<()>>,
}

impl FirewallService {
    pub fn new(
        ssh: SshService,
        target: Arc<TargetContext>,
        store: PortableStore,
        journal: PortableOperationJournal,
    ) -> Self {
        Self {
            ssh,
            target,
            store,
            journal,
            lock: Arc::new(Mutex::new(())),
        }
    }

    pub async fn inspect(&self, session: &BoundSshSession) -> CoreResult<FirewallInspection> {
        self.target.validate(session.target())?;
        let probe = successful_output(
            "probe firewall",
            self.ssh
                .execute_bound(session, probe_command().to_owned(), READ_TIMEOUT)
                .await?,
        )?;
        let (backend, engine, active) = parse_probe(&probe)?;
        self.target.validate(session.target())?;
        let output = successful_output(
            "read firewall rules",
            self.ssh
                .execute_bound(session, rules_command(backend), READ_TIMEOUT)
                .await?,
        )?;
        self.target.validate(session.target())?;
        let (rules, rules_truncated) = truncate_utf8(output, MAX_RULE_BYTES);
        let rules_sha256 = format!("{:x}", Sha256::digest(rules.as_bytes()));
        Ok(FirewallInspection {
            target: session.target().clone(),
            backend,
            engine,
            active,
            rules,
            rules_truncated,
            rules_sha256,
            captured_at: Utc::now(),
        })
    }

    pub async fn plan_mutation(
        &self,
        session: &BoundSshSession,
        request: FirewallMutationRequest,
    ) -> CoreResult<FirewallMutationPlan> {
        request.validate()?;
        let inspection = self.inspect(session).await?;
        if inspection.engine == FirewallEngine::Unavailable {
            return Err(CoreError::Unsupported {
                feature: "firewall mutation without iptables-save/restore or nftables",
            });
        }
        if inspection.engine == FirewallEngine::Nftables
            && matches!(request, FirewallMutationRequest::AllowTcpPort { .. })
        {
            return Err(CoreError::Unsupported {
                feature: "opening a port through an unknown nftables ruleset",
            });
        }
        let ssh_port = self.session_port(session).await?;
        let change_id = Uuid::new_v4().to_string();
        let remote_root = expected_remote_root(&change_id)?;
        let object_name = expected_object_name(inspection.engine, &change_id)?;
        let deadman_seconds = request.deadman_seconds();
        let summary = if request.can_keep() {
            format!(
                "{}；使用 {} 独立对象，{} 秒内未保留将自动恢复",
                request.label(),
                inspection.engine.label(),
                deadman_seconds
            )
        } else {
            format!(
                "{}；使用 {} 独立对象，固定 {} 秒后自动恢复且不可永久保留",
                request.label(),
                inspection.engine.label(),
                deadman_seconds
            )
        };
        let mut operation = OperationPlan::new(
            session.target().clone(),
            summary,
            true,
            Some("删除 LovelyRes 独立链/表并恢复变更前状态".to_owned()),
        )?;
        operation
            .metadata
            .insert("source".to_owned(), "firewall".to_owned());
        operation
            .metadata
            .insert("change_id".to_owned(), change_id.clone());
        operation.metadata.insert(
            "preflight_sha256".to_owned(),
            inspection.rules_sha256.clone(),
        );
        Ok(FirewallMutationPlan {
            operation,
            backend: inspection.backend,
            engine: inspection.engine,
            request,
            ssh_port,
            change_id,
            remote_root,
            object_name,
            preflight_sha256: inspection.rules_sha256,
        })
    }

    pub async fn execute_mutation(
        &self,
        session: &BoundSshSession,
        plan: FirewallMutationPlan,
        confirmation: DangerousConfirmation,
    ) -> CoreResult<FirewallOperationOutcome> {
        validate_mutation_plan(session, &plan)?;
        let executor = MutationExecutor {
            service: self,
            session,
            plan: &plan,
        };
        let verification = run_planned_operation(
            &self.target,
            &self.journal,
            plan.operation.clone(),
            confirmation,
            &executor,
        )
        .await?;
        if !verification.passed {
            return Err(CoreError::validation(
                "firewall verification",
                "the isolated rule object was not readable through the guarded SSH session; it was restored",
            ));
        }
        let change = self.change_by_id(session.target(), &plan.change_id)?;
        Ok(FirewallOperationOutcome {
            change,
            verification,
        })
    }

    pub fn list_changes(&self, target: &TargetGuard) -> CoreResult<Vec<FirewallChangeRecord>> {
        self.target.validate(target)?;
        let _guard = self.lock.lock();
        let mut changes = self
            .store
            .read_or_default::<StoredFirewall>(StoreFile::Firewall)?
            .changes
            .into_iter()
            .filter(|change| change.target == target.identity)
            .collect::<Vec<_>>();
        for change in &changes {
            validate_record(change)?;
        }
        changes.sort_by(|left, right| right.created_at.cmp(&left.created_at));
        Ok(changes)
    }

    /// Restore a single LovelyRes-managed block for an exact IPv4 address.
    /// This never searches or deletes arbitrary host firewall rules. Ambiguous
    /// duplicate blocks must be resolved from the firewall history view.
    pub fn plan_restore_ipv4_block(
        &self,
        session: &BoundSshSession,
        source: impl Into<String>,
    ) -> CoreResult<FirewallResolutionPlan> {
        let source = normalize_ipv4_or_cidr(&source.into())?;
        let matching = self
            .list_changes(session.target())?
            .into_iter()
            .filter(|change| {
                matches!(
                    &change.request,
                    FirewallMutationRequest::BlockIpv4 { source: blocked }
                        | FirewallMutationRequest::TemporaryBlockIpv4 { source: blocked }
                        if blocked == &source
                ) && matches!(
                    change.state,
                    FirewallChangeState::AwaitingKeep | FirewallChangeState::Kept
                )
            })
            .collect::<Vec<_>>();
        let [change] = matching.as_slice() else {
            return Err(CoreError::validation(
                "firewall allow IP",
                match matching.len() {
                    0 => format!(
                        "no active LovelyRes-managed block exists for {source}; arbitrary host rules are never removed"
                    ),
                    count => format!(
                        "{count} active LovelyRes-managed blocks exist for {source}; restore them explicitly from firewall history"
                    ),
                },
            ));
        };
        self.plan_resolution(session, &change.id, FirewallResolution::Restore)
    }

    pub fn plan_resolution(
        &self,
        session: &BoundSshSession,
        change_id: &str,
        resolution: FirewallResolution,
    ) -> CoreResult<FirewallResolutionPlan> {
        self.target.validate(session.target())?;
        let change = self.change_by_id(session.target(), change_id)?;
        validate_record(&change)?;
        if resolution == FirewallResolution::Keep && !change.request.can_keep() {
            return Err(CoreError::validation(
                "firewall resolution",
                "temporary IP blocks cannot be kept beyond their fixed five-minute lifetime",
            ));
        }
        match (resolution, change.state) {
            (FirewallResolution::Keep, FirewallChangeState::AwaitingKeep)
            | (FirewallResolution::Restore, FirewallChangeState::AwaitingKeep)
            | (FirewallResolution::Restore, FirewallChangeState::Kept) => {}
            _ => {
                return Err(CoreError::validation(
                    "firewall resolution",
                    format!(
                        "{} is not valid while the change is {}",
                        resolution.label(),
                        change.state.label()
                    ),
                ));
            }
        }
        let summary = match resolution {
            FirewallResolution::Keep => {
                format!("保留防火墙变更 {} 并取消自动恢复", change.request.label())
            }
            FirewallResolution::Restore => {
                format!("立即恢复防火墙变更 {}", change.request.label())
            }
        };
        let restore_description = (resolution == FirewallResolution::Keep)
            .then(|| "重新删除 LovelyRes 独立链/表".to_owned());
        let mut operation =
            OperationPlan::new(session.target().clone(), summary, true, restore_description)?;
        operation
            .metadata
            .insert("source".to_owned(), "firewall".to_owned());
        operation
            .metadata
            .insert("change_id".to_owned(), change.id.clone());
        Ok(FirewallResolutionPlan {
            operation,
            change,
            resolution,
        })
    }

    pub async fn execute_resolution(
        &self,
        session: &BoundSshSession,
        plan: FirewallResolutionPlan,
        confirmation: DangerousConfirmation,
    ) -> CoreResult<FirewallOperationOutcome> {
        validate_resolution_plan(session, &plan)?;
        let executor = ResolutionExecutor {
            service: self,
            session,
            plan: &plan,
        };
        let verification = run_planned_operation(
            &self.target,
            &self.journal,
            plan.operation.clone(),
            confirmation,
            &executor,
        )
        .await?;
        if !verification.passed {
            return Err(CoreError::validation(
                "firewall resolution verification",
                "remote readback did not match the requested resolution",
            ));
        }
        let change = self.change_by_id(session.target(), &plan.change.id)?;
        Ok(FirewallOperationOutcome {
            change,
            verification,
        })
    }

    pub async fn reconcile(&self, session: &BoundSshSession) -> CoreResult<()> {
        let changes = self.list_changes(session.target())?;
        for change in changes.into_iter().filter(|change| {
            change.state == FirewallChangeState::AwaitingKeep
                && change.deadman_deadline <= Utc::now()
        }) {
            validate_record(&change)?;
            let output = successful_output(
                "reconcile firewall rollback",
                self.ssh
                    .execute_bound(session, reconcile_command(&change), Duration::from_secs(10))
                    .await?,
            )?;
            if output.lines().any(|line| line.trim() == "AUTO_RESTORED=1") {
                self.transition_change(
                    &change.id,
                    &change.target,
                    &[FirewallChangeState::AwaitingKeep],
                    FirewallChangeState::AutoRestored,
                    &change.last_operation_id,
                )?;
            }
        }
        self.target.validate(session.target())
    }

    async fn session_port(&self, session: &BoundSshSession) -> CoreResult<u16> {
        let status = self
            .ssh
            .list_sessions()
            .await?
            .into_iter()
            .find(|status| status.session_id == session.session_id())
            .ok_or_else(|| CoreError::NotFound {
                entity: "SSH session",
                id: session.session_id().to_owned(),
            })?;
        if status.connection_id != session.connection_id() {
            return Err(CoreError::validation(
                "firewall session",
                "SSH session no longer belongs to the guarded target",
            ));
        }
        self.target.validate(session.target())?;
        Ok(status.port)
    }

    fn insert_change(&self, change: FirewallChangeRecord) -> CoreResult<()> {
        validate_record(&change)?;
        let _guard = self.lock.lock();
        let mut stored = self
            .store
            .read_or_default::<StoredFirewall>(StoreFile::Firewall)?;
        if stored.changes.iter().any(|item| item.id == change.id) {
            return Err(CoreError::validation(
                "firewall change",
                "change identity already exists",
            ));
        }
        stored.changes.push(change);
        if stored.changes.len() > MAX_RECORDS {
            stored.changes.sort_by_key(|item| item.created_at);
            stored.changes.drain(..stored.changes.len() - MAX_RECORDS);
        }
        self.store.write(StoreFile::Firewall, &stored)
    }

    fn change_by_id(
        &self,
        target: &TargetGuard,
        change_id: &str,
    ) -> CoreResult<FirewallChangeRecord> {
        validate_uuid("firewall change id", change_id)?;
        let _guard = self.lock.lock();
        self.store
            .read_or_default::<StoredFirewall>(StoreFile::Firewall)?
            .changes
            .into_iter()
            .find(|change| change.id == change_id && change.target == target.identity)
            .ok_or_else(|| CoreError::NotFound {
                entity: "firewall change",
                id: change_id.to_owned(),
            })
    }

    fn transition_change(
        &self,
        change_id: &str,
        target: &TargetIdentity,
        allowed: &[FirewallChangeState],
        next: FirewallChangeState,
        operation_id: &str,
    ) -> CoreResult<FirewallChangeRecord> {
        let _guard = self.lock.lock();
        let mut stored = self
            .store
            .read_or_default::<StoredFirewall>(StoreFile::Firewall)?;
        let change = stored
            .changes
            .iter_mut()
            .find(|change| change.id == change_id && &change.target == target)
            .ok_or_else(|| CoreError::NotFound {
                entity: "firewall change",
                id: change_id.to_owned(),
            })?;
        if !allowed.contains(&change.state) {
            return Err(CoreError::validation(
                "firewall change state",
                format!("cannot transition from {}", change.state.label()),
            ));
        }
        change.state = next;
        change.last_operation_id = operation_id.to_owned();
        change.updated_at = Utc::now();
        let result = change.clone();
        self.store.write(StoreFile::Firewall, &stored)?;
        Ok(result)
    }
}

impl FirewallResolution {
    const fn label(self) -> &'static str {
        match self {
            Self::Keep => "keep",
            Self::Restore => "restore",
        }
    }
}

#[derive(Debug)]
struct MutationExecutor<'a> {
    service: &'a FirewallService,
    session: &'a BoundSshSession,
    plan: &'a FirewallMutationPlan,
}

#[async_trait]
impl OperationExecutor for MutationExecutor<'_> {
    async fn execute(&self, definition: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        ensure_same_plan(definition, &self.plan.operation)?;
        let output = successful_marker(
            "apply firewall mutation",
            self.service
                .ssh
                .execute_bound(self.session, mutation_command(self.plan)?, MUTATION_TIMEOUT)
                .await?,
            APPLY_MARKER,
        )?;
        let now = Utc::now();
        self.service.insert_change(FirewallChangeRecord {
            id: self.plan.change_id.clone(),
            operation_id: self.plan.operation.id.clone(),
            last_operation_id: self.plan.operation.id.clone(),
            target: self.session.target().identity.clone(),
            backend: self.plan.backend,
            engine: self.plan.engine,
            request: self.plan.request.clone(),
            ssh_port: self.plan.ssh_port,
            remote_root: self.plan.remote_root.clone(),
            object_name: self.plan.object_name.clone(),
            preflight_sha256: self.plan.preflight_sha256.clone(),
            state: FirewallChangeState::AwaitingKeep,
            created_at: now,
            deadman_deadline: now + TimeDelta::seconds(self.plan.request.deadman_seconds()),
            updated_at: now,
        })?;
        Ok(ExecutionReceipt {
            summary: format!(
                "{}; remote dead-man rollback armed for {} seconds ({})",
                self.plan.request.label(),
                self.plan.request.deadman_seconds(),
                compact_output(&output)
            ),
            restore_token: Some(self.plan.change_id.clone()),
        })
    }

    async fn verify(
        &self,
        definition: &OperationPlan,
        _: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        ensure_same_plan(definition, &self.plan.operation)?;
        let output = self
            .service
            .ssh
            .execute_bound(
                self.session,
                mutation_verify_command(self.plan)?,
                Duration::from_secs(10),
            )
            .await?;
        let passed = output.exit_code == Some(0)
            && !output.timed_out
            && output
                .output
                .lines()
                .any(|line| line.trim() == VERIFY_MARKER);
        Ok(VerificationResult {
            passed,
            detail: if passed {
                "verified the isolated rule object and guarded SSH command path".to_owned()
            } else {
                "isolated rule object was not readable through the guarded SSH session".to_owned()
            },
        })
    }

    async fn restore(&self, definition: &OperationPlan, _: &ExecutionReceipt) -> CoreResult<()> {
        ensure_same_plan(definition, &self.plan.operation)?;
        successful_marker(
            "restore failed firewall mutation",
            self.service
                .ssh
                .execute_bound(
                    self.session,
                    rollback_command_for_plan(self.plan)?,
                    MUTATION_TIMEOUT,
                )
                .await?,
            RESTORE_MARKER,
        )?;
        self.service.transition_change(
            &self.plan.change_id,
            &self.session.target().identity,
            &[FirewallChangeState::AwaitingKeep],
            FirewallChangeState::Restored,
            &self.plan.operation.id,
        )?;
        Ok(())
    }
}

#[derive(Debug)]
struct ResolutionExecutor<'a> {
    service: &'a FirewallService,
    session: &'a BoundSshSession,
    plan: &'a FirewallResolutionPlan,
}

#[async_trait]
impl OperationExecutor for ResolutionExecutor<'_> {
    async fn execute(&self, definition: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        ensure_same_plan(definition, &self.plan.operation)?;
        let (command, marker, state, allowed) = match self.plan.resolution {
            FirewallResolution::Keep => (
                keep_command(&self.plan.change)?,
                KEEP_MARKER,
                FirewallChangeState::Kept,
                vec![FirewallChangeState::AwaitingKeep],
            ),
            FirewallResolution::Restore => (
                rollback_command(&self.plan.change)?,
                RESTORE_MARKER,
                FirewallChangeState::Restored,
                vec![FirewallChangeState::AwaitingKeep, FirewallChangeState::Kept],
            ),
        };
        successful_marker(
            "resolve firewall mutation",
            self.service
                .ssh
                .execute_bound(self.session, command, MUTATION_TIMEOUT)
                .await?,
            marker,
        )?;
        self.service.transition_change(
            &self.plan.change.id,
            &self.plan.change.target,
            &allowed,
            state,
            &self.plan.operation.id,
        )?;
        Ok(ExecutionReceipt {
            summary: match self.plan.resolution {
                FirewallResolution::Keep => {
                    "cancelled the dead-man rollback and kept the isolated rule object".to_owned()
                }
                FirewallResolution::Restore => {
                    "removed the isolated rule object and cancelled its dead-man process".to_owned()
                }
            },
            restore_token: (self.plan.resolution == FirewallResolution::Keep)
                .then(|| self.plan.change.id.clone()),
        })
    }

    async fn verify(
        &self,
        definition: &OperationPlan,
        _: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        ensure_same_plan(definition, &self.plan.operation)?;
        let output = self
            .service
            .ssh
            .execute_bound(
                self.session,
                resolution_verify_command(&self.plan.change, self.plan.resolution)?,
                Duration::from_secs(10),
            )
            .await?;
        let passed = output.exit_code == Some(0)
            && !output.timed_out
            && output.output.lines().any(|line| {
                line.trim()
                    == match self.plan.resolution {
                        FirewallResolution::Keep => KEEP_MARKER,
                        FirewallResolution::Restore => RESTORE_MARKER,
                    }
            });
        Ok(VerificationResult {
            passed,
            detail: if passed {
                format!(
                    "verified firewall {} resolution",
                    self.plan.resolution.label()
                )
            } else {
                format!(
                    "firewall {} resolution did not match remote readback",
                    self.plan.resolution.label()
                )
            },
        })
    }

    async fn restore(&self, definition: &OperationPlan, _: &ExecutionReceipt) -> CoreResult<()> {
        ensure_same_plan(definition, &self.plan.operation)?;
        if self.plan.resolution != FirewallResolution::Keep {
            return Err(CoreError::Unsupported {
                feature: "reapplying a restored firewall mutation",
            });
        }
        successful_marker(
            "restore kept firewall mutation",
            self.service
                .ssh
                .execute_bound(
                    self.session,
                    rollback_command(&self.plan.change)?,
                    MUTATION_TIMEOUT,
                )
                .await?,
            RESTORE_MARKER,
        )?;
        self.service.transition_change(
            &self.plan.change.id,
            &self.plan.change.target,
            &[FirewallChangeState::Kept],
            FirewallChangeState::Restored,
            &self.plan.operation.id,
        )?;
        Ok(())
    }
}

async fn run_planned_operation(
    target: &TargetContext,
    journal: &dyn OperationJournal,
    definition: OperationPlan,
    confirmation: DangerousConfirmation,
    executor: &dyn OperationExecutor,
) -> CoreResult<VerificationResult> {
    let mut operation = PlannedOperation::plan(definition);
    operation.confirm(confirmation)?;
    let execution = operation.execute(target, executor).await;
    if matches!(
        operation.state(),
        OperationState::Executed | OperationState::StaleAfterExecution
    ) {
        operation.journal(journal)?;
    }
    execution?;
    let verification = operation.verify(target, executor, journal).await;
    match verification {
        Ok(result) if result.passed => Ok(result),
        Ok(result) => {
            operation.restore(target, executor, journal).await?;
            Ok(result)
        }
        Err(error) => {
            if matches!(operation.state(), OperationState::VerificationFailed) {
                let _ = operation.restore(target, executor, journal).await;
            }
            Err(error)
        }
    }
}

fn probe_command() -> &'static str {
    r#"set -u
printf '%s\n' LR_FIREWALL_PROBE_V1
backend=unknown
active=0
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^Status:[[:space:]]*active'; then backend=ufw; active=1
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -qx running; then backend=firewalld; active=1
elif command -v nft >/dev/null 2>&1; then backend=nftables; nft list ruleset 2>/dev/null | grep -q '[^[:space:]]' && active=1 || true
elif command -v iptables >/dev/null 2>&1; then backend=iptables; iptables-save 2>/dev/null | grep -q '^-A ' && active=1 || true
elif command -v ufw >/dev/null 2>&1; then backend=ufw
elif command -v firewall-cmd >/dev/null 2>&1; then backend=firewalld
fi
engine=unavailable
if command -v iptables >/dev/null 2>&1 && command -v iptables-save >/dev/null 2>&1 && command -v iptables-restore >/dev/null 2>&1; then engine=iptables
elif command -v nft >/dev/null 2>&1; then engine=nftables
fi
printf 'BACKEND=%s\nENGINE=%s\nACTIVE=%s\n' "$backend" "$engine" "$active""#
}

fn rules_command(backend: FirewallBackend) -> String {
    let command = match backend {
        FirewallBackend::Ufw => "ufw status numbered 2>&1",
        FirewallBackend::Firewalld => "firewall-cmd --list-all-zones 2>&1",
        FirewallBackend::Nftables => "nft list ruleset 2>&1",
        FirewallBackend::Iptables | FirewallBackend::Unknown => {
            "iptables-save 2>&1 || nft list ruleset 2>&1"
        }
    };
    format!("set -u; ({command}) | head -c {}", MAX_RULE_BYTES + 1)
}

fn parse_probe(output: &str) -> CoreResult<(FirewallBackend, FirewallEngine, bool)> {
    if !output.lines().any(|line| line.trim() == PROBE_MARKER) {
        return Err(CoreError::validation(
            "firewall probe",
            "missing typed probe marker",
        ));
    }
    let values = output
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.trim(), value.trim()))
        .collect::<BTreeMap<_, _>>();
    let backend = match values.get("BACKEND").copied() {
        Some("iptables") => FirewallBackend::Iptables,
        Some("nftables") => FirewallBackend::Nftables,
        Some("ufw") => FirewallBackend::Ufw,
        Some("firewalld") => FirewallBackend::Firewalld,
        Some("unknown") => FirewallBackend::Unknown,
        _ => return Err(CoreError::validation("firewall probe", "invalid backend")),
    };
    let engine = match values.get("ENGINE").copied() {
        Some("iptables") => FirewallEngine::Iptables,
        Some("nftables") => FirewallEngine::Nftables,
        Some("unavailable") => FirewallEngine::Unavailable,
        _ => return Err(CoreError::validation("firewall probe", "invalid engine")),
    };
    let active = match values.get("ACTIVE").copied() {
        Some("1") => true,
        Some("0") => false,
        _ => {
            return Err(CoreError::validation(
                "firewall probe",
                "invalid active state",
            ));
        }
    };
    Ok((backend, engine, active))
}

fn mutation_command(plan: &FirewallMutationPlan) -> CoreResult<String> {
    validate_mutation_identity(plan)?;
    let backup = format!("{}/rules.before", plan.remote_root);
    let armed = format!("{}/armed", plan.remote_root);
    let pid = format!("{}/deadman.pid", plan.remote_root);
    let restored = format!("{}/auto-restored", plan.remote_root);
    let rollback = rollback_script(plan.engine, &plan.object_name);
    let deadman_seconds = plan.request.deadman_seconds();
    let deadman = format!(
        "sleep {deadman_seconds}; if test -f {}; then {rollback}; rm -f -- {}; : > {}; fi",
        shq(&armed),
        shq(&armed),
        shq(&restored)
    );
    let backup_command = match plan.engine {
        FirewallEngine::Iptables => format!("iptables-save > {}", shq(&backup)),
        FirewallEngine::Nftables => format!("nft list ruleset > {}", shq(&backup)),
        FirewallEngine::Unavailable => unreachable!("validated mutation engine"),
    };
    let apply = apply_script(plan.engine, &plan.object_name, &plan.request, plan.ssh_port)?;
    Ok(format!(
        "set -eu; umask 077; mkdir -p -- {root}; {backup}; : > {armed}; ( sh -c {deadman} ) </dev/null >/dev/null 2>&1 & printf '%s\n' \"$!\" > {pid}; {apply}; printf '%s\n' {marker}",
        root = shq(&plan.remote_root),
        backup = backup_command,
        armed = shq(&armed),
        deadman = shq(&deadman),
        pid = shq(&pid),
        apply = apply,
        marker = APPLY_MARKER,
    ))
}

fn apply_script(
    engine: FirewallEngine,
    object: &str,
    request: &FirewallMutationRequest,
    ssh_port: u16,
) -> CoreResult<String> {
    request.validate()?;
    Ok(match engine {
        FirewallEngine::Iptables => {
            let action = match request {
                FirewallMutationRequest::BlockIpv4 { source }
                | FirewallMutationRequest::TemporaryBlockIpv4 { source } => format!(
                    "iptables -A {object} -s {} -j DROP; iptables -A {object} -j RETURN",
                    shq(source)
                ),
                FirewallMutationRequest::AllowTcpPort { port } => format!(
                    "iptables -A {object} -p tcp --dport {port} -j ACCEPT; iptables -A {object} -j RETURN"
                ),
                FirewallMutationRequest::IsolateInbound => {
                    format!("iptables -A {object} -j DROP")
                }
            };
            format!(
                "iptables -N {object}; iptables -A {object} -i lo -j ACCEPT; (iptables -A {object} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || iptables -A {object} -m state --state ESTABLISHED,RELATED -j ACCEPT); iptables -A {object} -p tcp --dport {ssh_port} -j ACCEPT; {action}; iptables -I INPUT 1 -j {object}"
            )
        }
        FirewallEngine::Nftables => {
            let action = match request {
                FirewallMutationRequest::BlockIpv4 { source }
                | FirewallMutationRequest::TemporaryBlockIpv4 { source } => {
                    format!(
                        "nft add rule inet {object} input ip saddr {} drop",
                        shq(source)
                    )
                }
                FirewallMutationRequest::AllowTcpPort { port } => {
                    format!("nft add rule inet {object} input tcp dport {port} accept")
                }
                FirewallMutationRequest::IsolateInbound => {
                    format!("nft add rule inet {object} input drop")
                }
            };
            let chain = format!(
                "add chain inet {object} input {{ type filter hook input priority 300; policy accept; }}"
            );
            format!(
                "nft add table inet {object}; nft {}; nft add rule inet {object} input iifname lo accept; nft add rule inet {object} input ct state established,related accept; nft add rule inet {object} input tcp dport {ssh_port} accept; {action}",
                shq(&chain)
            )
        }
        FirewallEngine::Unavailable => {
            return Err(CoreError::Unsupported {
                feature: "firewall mutation engine",
            });
        }
    })
}

fn mutation_verify_command(plan: &FirewallMutationPlan) -> CoreResult<String> {
    validate_mutation_identity(plan)?;
    let armed = format!("{}/armed", plan.remote_root);
    let check = object_exists_script(plan.engine, &plan.object_name);
    Ok(format!(
        "set -eu; test -f {}; {}; printf '%s\n' {VERIFY_MARKER}",
        shq(&armed),
        check
    ))
}

fn rollback_command_for_plan(plan: &FirewallMutationPlan) -> CoreResult<String> {
    validate_mutation_identity(plan)?;
    rollback_command_parts(
        plan.engine,
        &plan.remote_root,
        &plan.object_name,
        RESTORE_MARKER,
    )
}

fn keep_command(change: &FirewallChangeRecord) -> CoreResult<String> {
    validate_record(change)?;
    let armed = format!("{}/armed", change.remote_root);
    let pid = format!("{}/deadman.pid", change.remote_root);
    let kept = format!("{}/kept", change.remote_root);
    let check = object_exists_script(change.engine, &change.object_name);
    Ok(format!(
        "set -eu; {}; {}; rm -f -- {}; : > {}; {}; printf '%s\n' {KEEP_MARKER}",
        safe_kill_script(&pid),
        check,
        shq(&armed),
        shq(&kept),
        check,
    ))
}

fn rollback_command(change: &FirewallChangeRecord) -> CoreResult<String> {
    validate_record(change)?;
    rollback_command_parts(
        change.engine,
        &change.remote_root,
        &change.object_name,
        RESTORE_MARKER,
    )
}

fn rollback_command_parts(
    engine: FirewallEngine,
    remote_root: &str,
    object: &str,
    marker: &str,
) -> CoreResult<String> {
    let armed = format!("{remote_root}/armed");
    let pid = format!("{remote_root}/deadman.pid");
    let restored = format!("{remote_root}/restored");
    Ok(format!(
        "set -eu; {}; {}; rm -f -- {}; : > {}; printf '%s\n' {marker}",
        safe_kill_script(&pid),
        rollback_script(engine, object),
        shq(&armed),
        shq(&restored),
    ))
}

fn resolution_verify_command(
    change: &FirewallChangeRecord,
    resolution: FirewallResolution,
) -> CoreResult<String> {
    validate_record(change)?;
    let armed = format!("{}/armed", change.remote_root);
    match resolution {
        FirewallResolution::Keep => {
            let kept = format!("{}/kept", change.remote_root);
            Ok(format!(
                "set -eu; test ! -e {}; test -f {}; {}; printf '%s\n' {KEEP_MARKER}",
                shq(&armed),
                shq(&kept),
                object_exists_script(change.engine, &change.object_name)
            ))
        }
        FirewallResolution::Restore => {
            let restored = format!("{}/restored", change.remote_root);
            Ok(format!(
                "set -eu; test ! -e {}; test -f {}; {}; printf '%s\n' {RESTORE_MARKER}",
                shq(&armed),
                shq(&restored),
                object_absent_script(change.engine, &change.object_name)
            ))
        }
    }
}

fn reconcile_command(change: &FirewallChangeRecord) -> String {
    let auto = format!("{}/auto-restored", change.remote_root);
    format!(
        "set -u; if test -f {}; then printf '%s\n' AUTO_RESTORED=1; else printf '%s\n' AUTO_RESTORED=0; fi",
        shq(&auto)
    )
}

fn rollback_script(engine: FirewallEngine, object: &str) -> String {
    match engine {
        FirewallEngine::Iptables => format!(
            "while iptables -D INPUT -j {object} 2>/dev/null; do :; done; iptables -F {object} 2>/dev/null || true; iptables -X {object} 2>/dev/null || true"
        ),
        FirewallEngine::Nftables => {
            format!("nft delete table inet {object} 2>/dev/null || true")
        }
        FirewallEngine::Unavailable => "true".to_owned(),
    }
}

fn object_exists_script(engine: FirewallEngine, object: &str) -> String {
    match engine {
        FirewallEngine::Iptables => format!(
            "iptables -S {object} >/dev/null 2>&1; iptables -C INPUT -j {object} >/dev/null 2>&1"
        ),
        FirewallEngine::Nftables => {
            format!("nft list table inet {object} >/dev/null 2>&1")
        }
        FirewallEngine::Unavailable => "false".to_owned(),
    }
}

fn object_absent_script(engine: FirewallEngine, object: &str) -> String {
    match engine {
        FirewallEngine::Iptables => format!(
            "! iptables -S {object} >/dev/null 2>&1; ! iptables -C INPUT -j {object} >/dev/null 2>&1"
        ),
        FirewallEngine::Nftables => {
            format!("! nft list table inet {object} >/dev/null 2>&1")
        }
        FirewallEngine::Unavailable => "true".to_owned(),
    }
}

fn safe_kill_script(pid_path: &str) -> String {
    format!(
        "if test -f {path}; then lr_pid=$(cat {path} 2>/dev/null || true); case \"$lr_pid\" in ''|*[!0-9]*) : ;; *) kill \"$lr_pid\" 2>/dev/null || true ;; esac; rm -f -- {path}; fi",
        path = shq(pid_path)
    )
}

fn validate_mutation_plan(
    session: &BoundSshSession,
    plan: &FirewallMutationPlan,
) -> CoreResult<()> {
    if session.target() != &plan.operation.target {
        return Err(CoreError::validation(
            "firewall plan",
            "plan belongs to a different target generation",
        ));
    }
    validate_mutation_identity(plan)
}

fn validate_mutation_identity(plan: &FirewallMutationPlan) -> CoreResult<()> {
    plan.request.validate()?;
    validate_uuid("firewall change id", &plan.change_id)?;
    if plan.ssh_port == 0 {
        return Err(CoreError::validation("SSH port", "must be in 1..=65535"));
    }
    if plan.engine == FirewallEngine::Unavailable
        || plan.remote_root != expected_remote_root(&plan.change_id)?
        || plan.object_name != expected_object_name(plan.engine, &plan.change_id)?
    {
        return Err(CoreError::validation(
            "firewall plan identity",
            "remote namespace or isolated object does not match the immutable plan",
        ));
    }
    Ok(())
}

fn validate_resolution_plan(
    session: &BoundSshSession,
    plan: &FirewallResolutionPlan,
) -> CoreResult<()> {
    if session.target() != &plan.operation.target || session.target().identity != plan.change.target
    {
        return Err(CoreError::validation(
            "firewall resolution",
            "resolution belongs to a different target generation",
        ));
    }
    validate_record(&plan.change)
}

fn validate_record(change: &FirewallChangeRecord) -> CoreResult<()> {
    change.request.validate()?;
    validate_uuid("firewall change id", &change.id)?;
    if change.ssh_port == 0
        || change.engine == FirewallEngine::Unavailable
        || change.remote_root != expected_remote_root(&change.id)?
        || change.object_name != expected_object_name(change.engine, &change.id)?
        || change.preflight_sha256.len() != 64
        || !change
            .preflight_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(CoreError::validation(
            "firewall change record",
            "stored namespace or isolated object is invalid",
        ));
    }
    Ok(())
}

fn expected_remote_root(change_id: &str) -> CoreResult<String> {
    let id = validate_uuid("firewall change id", change_id)?;
    Ok(format!("{FIREWALL_ROOT}/{id}"))
}

fn expected_object_name(engine: FirewallEngine, change_id: &str) -> CoreResult<String> {
    let id = validate_uuid("firewall change id", change_id)?
        .simple()
        .to_string();
    Ok(match engine {
        FirewallEngine::Iptables => format!("LR_{}", &id[..16]).to_ascii_uppercase(),
        FirewallEngine::Nftables => format!("lr_{id}"),
        FirewallEngine::Unavailable => {
            return Err(CoreError::Unsupported {
                feature: "firewall mutation object",
            });
        }
    })
}

fn validate_uuid(subject: &'static str, value: &str) -> CoreResult<Uuid> {
    Uuid::parse_str(value).map_err(|_| CoreError::validation(subject, "must be a canonical UUID"))
}

fn normalize_ipv4_or_cidr(value: &str) -> CoreResult<String> {
    let value = value.trim();
    if !is_valid_ip_or_cidr(value) {
        return Err(CoreError::validation(
            "firewall source",
            "must be a valid IPv4 address or CIDR",
        ));
    }
    let (address, prefix) = value
        .split_once('/')
        .map_or((value, None), |(address, prefix)| (address, Some(prefix)));
    let IpAddr::V4(address) = address
        .parse::<IpAddr>()
        .map_err(|_| CoreError::validation("firewall source", "invalid IPv4 address"))?
    else {
        return Err(CoreError::validation(
            "firewall source",
            "IPv6 mutation is not exposed until an ip6tables compatibility matrix is complete",
        ));
    };
    let address: Ipv4Addr = address;
    Ok(prefix.map_or_else(
        || address.to_string(),
        |prefix| format!("{address}/{}", prefix.parse::<u8>().unwrap_or(255)),
    ))
}

fn ensure_same_plan(actual: &OperationPlan, expected: &OperationPlan) -> CoreResult<()> {
    if actual.id != expected.id || actual.target != expected.target {
        return Err(CoreError::validation(
            "firewall operation",
            "executor received a different immutable plan",
        ));
    }
    Ok(())
}

fn successful_output(subject: &'static str, output: SshCommandOutput) -> CoreResult<String> {
    if output.timed_out || output.exit_code != Some(0) {
        return Err(CoreError::ssh(
            subject,
            format!(
                "remote command failed (exit {:?}, timed_out={}): {}",
                output.exit_code,
                output.timed_out,
                compact_output(&output.output)
            ),
        ));
    }
    Ok(output.output)
}

fn successful_marker(
    subject: &'static str,
    output: SshCommandOutput,
    marker: &str,
) -> CoreResult<String> {
    let output = successful_output(subject, output)?;
    if !output.lines().any(|line| line.trim() == marker) {
        return Err(CoreError::validation(subject, "missing completion marker"));
    }
    Ok(output)
}

fn truncate_utf8(mut value: String, maximum: usize) -> (String, bool) {
    if value.len() <= maximum {
        return (value, false);
    }
    let mut end = maximum;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    (value, true)
}

fn compact_output(output: &str) -> String {
    let mut output = output.replace(['\r', '\n'], " ");
    if output.len() > 512 {
        let mut end = 512;
        while !output.is_char_boundary(end) {
            end -= 1;
        }
        output.truncate(end);
        output.push('…');
    }
    output
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, sync::Arc};

    use super::*;
    use crate::{
        BackendServices,
        ssh::{SshConnectionStatus, TestSessionHarness},
        target::TargetIdentity,
    };

    const PROBE: &str = "LR_FIREWALL_PROBE_V1\nBACKEND=firewalld\nENGINE=iptables\nACTIVE=1\n";

    #[derive(Debug)]
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("lovelyres-firewall-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    async fn fixture() -> (
        TestRoot,
        BackendServices,
        BoundSshSession,
        Arc<TestSessionHarness>,
    ) {
        let temp = TestRoot::new();
        let store = PortableStore::prepare(temp.0.clone()).unwrap();
        let services = BackendServices::new(store).unwrap();
        let identity = TargetIdentity::new("firewall-target").unwrap();
        let guard = services.activate_target(identity.clone()).unwrap();
        let status = SshConnectionStatus {
            session_id: "firewall-session".to_owned(),
            connection_id: identity.as_str().to_owned(),
            host: "192.0.2.10".to_owned(),
            port: 2222,
            username: "root".to_owned(),
            host_key_fingerprint: "SHA256:firewall".to_owned(),
            connected_at: Utc::now(),
        };
        let harness = Arc::new(TestSessionHarness::default());
        services
            .ssh()
            .install_test_session(status, harness.clone())
            .await
            .unwrap();
        let session = services
            .ssh()
            .bind_session(guard, "firewall-session")
            .await
            .unwrap();
        (temp, services, session, harness)
    }

    #[test]
    fn probe_parser_is_closed_and_requires_marker() {
        assert_eq!(
            parse_probe(PROBE).unwrap(),
            (FirewallBackend::Firewalld, FirewallEngine::Iptables, true)
        );
        assert!(parse_probe("BACKEND=iptables\nENGINE=iptables\nACTIVE=1").is_err());
        assert!(
            parse_probe("LR_FIREWALL_PROBE_V1\nBACKEND=evil\nENGINE=nftables\nACTIVE=1").is_err()
        );
    }

    #[test]
    fn ipv4_request_rejects_shell_and_ipv6_inputs() {
        assert_eq!(
            FirewallMutationRequest::block_ipv4("192.0.2.4/24").unwrap(),
            FirewallMutationRequest::BlockIpv4 {
                source: "192.0.2.4/24".to_owned()
            }
        );
        for hostile in ["1.2.3.4; id", "$(id)", "2001:db8::1", "10.0.0.0/99"] {
            assert!(FirewallMutationRequest::block_ipv4(hostile).is_err());
        }
        assert!(FirewallMutationRequest::allow_tcp_port(0).is_err());
        let temporary = FirewallMutationRequest::temporary_block_ipv4("192.0.2.9").unwrap();
        assert_eq!(temporary.deadman_seconds(), 300);
        assert!(!temporary.can_keep());
    }

    #[tokio::test]
    async fn inspection_is_target_bound_and_bounded() {
        let (_temp, services, session, harness) = fixture().await;
        harness.set_execute_output(PROBE);
        let inspection = services.firewall().inspect(&session).await.unwrap();
        assert_eq!(inspection.backend, FirewallBackend::Firewalld);
        assert_eq!(inspection.engine, FirewallEngine::Iptables);
        assert!(inspection.active);
        assert!(!inspection.rules_truncated);

        services
            .target()
            .activate(TargetIdentity::new("replacement").unwrap())
            .unwrap();
        assert!(services.firewall().inspect(&session).await.is_err());
    }

    #[tokio::test]
    async fn exact_confirmation_applies_journals_and_arms_deadman() {
        let (_temp, services, session, harness) = fixture().await;
        harness.set_execute_output(PROBE);
        let wrong = services
            .firewall()
            .plan_mutation(
                &session,
                FirewallMutationRequest::block_ipv4("203.0.113.7").unwrap(),
            )
            .await
            .unwrap();
        let plan = services
            .firewall()
            .plan_mutation(
                &session,
                FirewallMutationRequest::block_ipv4("203.0.113.7").unwrap(),
            )
            .await
            .unwrap();
        harness.set_execute_output(format!("{APPLY_MARKER}\n{VERIFY_MARKER}\n"));
        let error = services
            .firewall()
            .execute_mutation(
                &session,
                plan.clone(),
                DangerousConfirmation::approve(wrong.definition()),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("different operation"));
        assert!(
            services
                .firewall()
                .list_changes(session.target())
                .unwrap()
                .is_empty()
        );

        let outcome = services
            .firewall()
            .execute_mutation(
                &session,
                plan.clone(),
                DangerousConfirmation::approve(plan.definition()),
            )
            .await
            .unwrap();
        assert_eq!(outcome.change.state, FirewallChangeState::AwaitingKeep);
        assert_eq!(outcome.change.ssh_port, 2222);
        assert!(outcome.verification.passed);
        let entries = services.operation_journal().entries().unwrap();
        assert!(
            entries
                .iter()
                .any(|entry| entry.operation_id == plan.definition().id)
        );
    }

    #[tokio::test]
    async fn keep_and_restore_are_separate_exact_planned_operations() {
        let (_temp, services, session, harness) = fixture().await;
        harness.set_execute_output(PROBE);
        let mutation = services
            .firewall()
            .plan_mutation(&session, FirewallMutationRequest::isolate_inbound())
            .await
            .unwrap();
        harness.set_execute_output(format!("{APPLY_MARKER}\n{VERIFY_MARKER}\n"));
        let applied = services
            .firewall()
            .execute_mutation(
                &session,
                mutation.clone(),
                DangerousConfirmation::approve(mutation.definition()),
            )
            .await
            .unwrap();

        let keep = services
            .firewall()
            .plan_resolution(&session, &applied.change.id, FirewallResolution::Keep)
            .unwrap();
        harness.set_execute_output(KEEP_MARKER);
        let kept = services
            .firewall()
            .execute_resolution(
                &session,
                keep.clone(),
                DangerousConfirmation::approve(keep.definition()),
            )
            .await
            .unwrap();
        assert_eq!(kept.change.state, FirewallChangeState::Kept);

        let restore = services
            .firewall()
            .plan_resolution(&session, &kept.change.id, FirewallResolution::Restore)
            .unwrap();
        harness.set_execute_output(RESTORE_MARKER);
        let restored = services
            .firewall()
            .execute_resolution(
                &session,
                restore.clone(),
                DangerousConfirmation::approve(restore.definition()),
            )
            .await
            .unwrap();
        assert_eq!(restored.change.state, FirewallChangeState::Restored);
    }

    #[tokio::test]
    async fn temporary_block_is_exactly_five_minutes_and_cannot_be_kept() {
        let (_temp, services, session, harness) = fixture().await;
        harness.set_execute_output(PROBE);
        let mutation = services
            .firewall()
            .plan_mutation(
                &session,
                FirewallMutationRequest::temporary_block_ipv4("203.0.113.19").unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(mutation.deadman_seconds(), 300);
        let command = mutation_command(&mutation).unwrap();
        assert!(command.contains("sleep 300"));
        assert!(!command.contains("sleep 60;"));

        harness.set_execute_output(format!("{APPLY_MARKER}\n{VERIFY_MARKER}\n"));
        let applied = services
            .firewall()
            .execute_mutation(
                &session,
                mutation.clone(),
                DangerousConfirmation::approve(mutation.definition()),
            )
            .await
            .unwrap();
        assert_eq!(
            (applied.change.deadman_deadline - applied.change.created_at).num_seconds(),
            300
        );
        assert!(
            services
                .firewall()
                .plan_resolution(&session, &applied.change.id, FirewallResolution::Keep)
                .is_err()
        );
        assert!(
            services
                .firewall()
                .plan_restore_ipv4_block(&session, "203.0.113.19")
                .is_ok()
        );
    }

    #[tokio::test]
    async fn allow_ip_only_restores_one_managed_exact_block() {
        let (_temp, services, session, harness) = fixture().await;
        assert!(
            services
                .firewall()
                .plan_restore_ipv4_block(&session, "203.0.113.27")
                .is_err()
        );
        harness.set_execute_output(PROBE);
        let mutation = services
            .firewall()
            .plan_mutation(
                &session,
                FirewallMutationRequest::block_ipv4("203.0.113.27").unwrap(),
            )
            .await
            .unwrap();
        harness.set_execute_output(format!("{APPLY_MARKER}\n{VERIFY_MARKER}\n"));
        services
            .firewall()
            .execute_mutation(
                &session,
                mutation.clone(),
                DangerousConfirmation::approve(mutation.definition()),
            )
            .await
            .unwrap();
        let restore = services
            .firewall()
            .plan_restore_ipv4_block(&session, "203.0.113.27")
            .unwrap();
        assert_eq!(restore.resolution(), FirewallResolution::Restore);

        harness.set_execute_output(PROBE);
        let duplicate = services
            .firewall()
            .plan_mutation(
                &session,
                FirewallMutationRequest::block_ipv4("203.0.113.27").unwrap(),
            )
            .await
            .unwrap();
        harness.set_execute_output(format!("{APPLY_MARKER}\n{VERIFY_MARKER}\n"));
        services
            .firewall()
            .execute_mutation(
                &session,
                duplicate.clone(),
                DangerousConfirmation::approve(duplicate.definition()),
            )
            .await
            .unwrap();
        let ambiguous = services
            .firewall()
            .plan_restore_ipv4_block(&session, "203.0.113.27")
            .unwrap_err();
        assert!(ambiguous.to_string().contains("2 active"));
    }

    #[test]
    fn tampered_persisted_identity_cannot_reach_a_shell_builder() {
        let id = Uuid::new_v4().to_string();
        let record = FirewallChangeRecord {
            id: id.clone(),
            operation_id: Uuid::new_v4().to_string(),
            last_operation_id: Uuid::new_v4().to_string(),
            target: TargetIdentity::new("target").unwrap(),
            backend: FirewallBackend::Iptables,
            engine: FirewallEngine::Iptables,
            request: FirewallMutationRequest::IsolateInbound,
            ssh_port: 22,
            remote_root: format!("{FIREWALL_ROOT}/{id}; rm -rf /"),
            object_name: "LR_EVIL;id".to_owned(),
            preflight_sha256: "00".repeat(32),
            state: FirewallChangeState::Kept,
            created_at: Utc::now(),
            deadman_deadline: Utc::now(),
            updated_at: Utc::now(),
        };
        assert!(rollback_command(&record).is_err());
    }

    #[test]
    fn command_builders_only_use_fixed_namespace_and_typed_values() {
        let id = Uuid::new_v4().to_string();
        let plan = FirewallMutationPlan {
            operation: OperationPlan::new(
                TargetGuard {
                    identity: TargetIdentity::new("target").unwrap(),
                    generation: 1,
                },
                "test",
                true,
                Some("restore".to_owned()),
            )
            .unwrap(),
            backend: FirewallBackend::Iptables,
            engine: FirewallEngine::Iptables,
            request: FirewallMutationRequest::block_ipv4("198.51.100.7/32").unwrap(),
            ssh_port: 2222,
            change_id: id.clone(),
            remote_root: expected_remote_root(&id).unwrap(),
            object_name: expected_object_name(FirewallEngine::Iptables, &id).unwrap(),
            preflight_sha256: "00".repeat(32),
        };
        let command = mutation_command(&plan).unwrap();
        assert!(command.contains(FIREWALL_ROOT));
        assert!(command.contains("198.51.100.7/32"));
        assert!(command.contains("--dport 2222"));
        assert!(!command.contains("/etc/"));
        assert!(!command.contains("iptables -P INPUT DROP"));
    }

    #[test]
    fn store_file_is_portable_and_not_an_arbitrary_path() {
        assert_eq!(StoreFile::Firewall.file_name(), "firewall.json");
        let root = PathBuf::from("C:/LovelyRes/data");
        assert_eq!(
            root.join(StoreFile::Firewall.file_name()),
            root.join("firewall.json")
        );
    }
}
