//! Target-bound directory and forensic snapshots.
//!
//! Remote paths and commands in this module are selected from fixed enums. The
//! public API never accepts an arbitrary shell fragment or remote snapshot path.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures::{StreamExt, TryStreamExt, stream};
use parking_lot::Mutex;
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, IgnoredAny, SeqAccess, Visitor},
};
use sha2::{Digest, Sha256};
use tokio::sync::Notify;
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

const SNAPSHOT_DOCUMENT_VERSION: u32 = 1;
const DIRECTORY_SNAPSHOT_LIMIT: usize = 64;
const FORENSIC_SNAPSHOT_LIMIT: usize = 10;
const FORENSIC_CONCURRENCY: usize = 4;
const FORENSIC_TIMEOUT: Duration = Duration::from_secs(30);
const SNAPSHOT_MUTATION_TIMEOUT: Duration = Duration::from_secs(180);
const SNAPSHOT_VERIFY_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_FORENSIC_FIELD_BYTES: usize = 256 * 1024;
const MAX_FORENSIC_TOTAL_BYTES: usize = 2 * 1024 * 1024;
const MAX_SNAPSHOT_DOCUMENT_BYTES: usize = 128 * 1024 * 1024;
const MAX_FORENSIC_DIFF_INPUT_LINES_PER_FIELD: usize = 2_048;
const MAX_FORENSIC_DIFF_INPUT_LINES_TOTAL: usize = 8_192;
const MAX_EVENT_CAPACITY: usize = 256;
const REMOTE_ROOT_PREFIX: &str = "/tmp/.lovelyres_snap";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SnapshotItemKind {
    File,
    Directory,
    Crontab,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SnapshotPreset {
    Etc,
    CurrentCrontab,
    Passwd,
    Shadow,
    AuthorizedKeys,
    WebRoot,
    CronSpool,
    RootHome,
}

impl SnapshotPreset {
    pub const ALL: [Self; 8] = [
        Self::Etc,
        Self::CurrentCrontab,
        Self::Passwd,
        Self::Shadow,
        Self::AuthorizedKeys,
        Self::WebRoot,
        Self::CronSpool,
        Self::RootHome,
    ];

    pub const fn id(self) -> &'static str {
        match self {
            Self::Etc => "etc",
            Self::CurrentCrontab => "current-crontab",
            Self::Passwd => "passwd",
            Self::Shadow => "shadow",
            Self::AuthorizedKeys => "authorized-keys",
            Self::WebRoot => "web-root",
            Self::CronSpool => "cron-spool",
            Self::RootHome => "root-home",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Etc => "/etc 配置目录",
            Self::CurrentCrontab => "当前用户 Crontab",
            Self::Passwd => "/etc/passwd",
            Self::Shadow => "/etc/shadow",
            Self::AuthorizedKeys => "root authorized_keys",
            Self::WebRoot => "/var/www",
            Self::CronSpool => "/var/spool/cron",
            Self::RootHome => "/root",
        }
    }

    pub const fn source(self) -> &'static str {
        match self {
            Self::Etc => "/etc",
            Self::CurrentCrontab => "CRONTAB",
            Self::Passwd => "/etc/passwd",
            Self::Shadow => "/etc/shadow",
            Self::AuthorizedKeys => "/root/.ssh/authorized_keys",
            Self::WebRoot => "/var/www",
            Self::CronSpool => "/var/spool/cron",
            Self::RootHome => "/root",
        }
    }

    pub const fn kind(self) -> SnapshotItemKind {
        match self {
            Self::Etc | Self::WebRoot | Self::CronSpool | Self::RootHome => {
                SnapshotItemKind::Directory
            }
            Self::CurrentCrontab => SnapshotItemKind::Crontab,
            Self::Passwd | Self::Shadow | Self::AuthorizedKeys => SnapshotItemKind::File,
        }
    }

    pub const fn selected_by_default(self) -> bool {
        !matches!(self, Self::CronSpool | Self::RootHome)
    }

    const fn archive_name(self) -> &'static str {
        match self.kind() {
            SnapshotItemKind::Crontab => "current-crontab.txt",
            SnapshotItemKind::File | SnapshotItemKind::Directory => match self {
                Self::Etc => "etc.tar",
                Self::Passwd => "passwd.tar",
                Self::Shadow => "shadow.tar",
                Self::AuthorizedKeys => "authorized-keys.tar",
                Self::WebRoot => "web-root.tar",
                Self::CronSpool => "cron-spool.tar",
                Self::RootHome => "root-home.tar",
                Self::CurrentCrontab => unreachable!(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectorySnapshotItem {
    pub preset: SnapshotPreset,
    pub source: String,
    pub kind: SnapshotItemKind,
    pub archive_path: String,
    pub archive_sha256: String,
    pub content_sha256: String,
    pub bytes: u64,
    pub present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectorySnapshot {
    pub id: String,
    pub target: TargetIdentity,
    pub created_at: DateTime<Utc>,
    pub remote_root: String,
    pub items: Vec<DirectorySnapshotItem>,
    pub record_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectorySnapshotPlan {
    operation: OperationPlan,
    snapshot_id: String,
    remote_root: String,
    presets: Vec<SnapshotPreset>,
}

impl DirectorySnapshotPlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn presets(&self) -> &[SnapshotPreset] {
        &self.presets
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryRestorePlan {
    operation: OperationPlan,
    snapshot: DirectorySnapshot,
    item: DirectorySnapshotItem,
    rollback_root: String,
}

impl DirectoryRestorePlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryDeletePlan {
    operation: OperationPlan,
    snapshot: DirectorySnapshot,
}

impl DirectoryDeletePlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotOperationOutcome {
    pub operation_id: String,
    pub verified: bool,
    pub detail: String,
    pub restored_after_failed_verification: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ForensicCollector {
    Processes,
    NetworkConnections,
    ListeningPorts,
    LoginHistory,
    CronJobs,
    StartupServices,
    AuthorizedKeys,
    Sudoers,
    RunningUsers,
    LoadedModules,
    RecentModifiedFiles,
    EnvVariables,
}

impl ForensicCollector {
    pub const ALL: [Self; 12] = [
        Self::Processes,
        Self::NetworkConnections,
        Self::ListeningPorts,
        Self::LoginHistory,
        Self::CronJobs,
        Self::StartupServices,
        Self::AuthorizedKeys,
        Self::Sudoers,
        Self::RunningUsers,
        Self::LoadedModules,
        Self::RecentModifiedFiles,
        Self::EnvVariables,
    ];

    pub const fn id(self) -> &'static str {
        match self {
            Self::Processes => "processes",
            Self::NetworkConnections => "networkConnections",
            Self::ListeningPorts => "listeningPorts",
            Self::LoginHistory => "loginHistory",
            Self::CronJobs => "cronJobs",
            Self::StartupServices => "startupServices",
            Self::AuthorizedKeys => "authorizedKeys",
            Self::Sudoers => "sudoers",
            Self::RunningUsers => "runningUsers",
            Self::LoadedModules => "loadedModules",
            Self::RecentModifiedFiles => "recentModifiedFiles",
            Self::EnvVariables => "envVariables",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Processes => "进程树",
            Self::NetworkConnections => "网络连接",
            Self::ListeningPorts => "监听端口",
            Self::LoginHistory => "登录历史",
            Self::CronJobs => "计划任务",
            Self::StartupServices => "自启动服务",
            Self::AuthorizedKeys => "授权密钥",
            Self::Sudoers => "Sudoers",
            Self::RunningUsers => "在线用户",
            Self::LoadedModules => "内核模块",
            Self::RecentModifiedFiles => "近期修改文件",
            Self::EnvVariables => "环境变量",
        }
    }

    const fn command(self) -> &'static str {
        match self {
            Self::Processes => "ps auxf 2>/dev/null | head -200",
            Self::NetworkConnections => {
                "(ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null || echo 'ss/netstat not available') | head -100"
            }
            Self::ListeningPorts => {
                "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || echo 'ss/netstat not available'"
            }
            Self::LoginHistory => "last -20 2>/dev/null; echo '---'; w 2>/dev/null",
            Self::CronJobs => {
                "(crontab -l 2>/dev/null; echo '===root==='; sudo -n crontab -l 2>/dev/null || :; echo '===/etc/crontab==='; cat /etc/crontab 2>/dev/null) | head -100"
            }
            Self::StartupServices => {
                "(systemctl list-unit-files --type=service --state=enabled 2>/dev/null || chkconfig --list 2>/dev/null || rc-status -a 2>/dev/null || echo 'service manager not available') | head -50"
            }
            Self::AuthorizedKeys => {
                "find /home /root -name authorized_keys -exec echo '=== {} ===' \\; -exec cat {} \\; 2>/dev/null | head -50"
            }
            Self::Sudoers => {
                "(sudo -n cat /etc/sudoers 2>/dev/null || cat /etc/sudoers 2>/dev/null || echo 'sudoers not readable') | grep -v '^#' | grep -v '^$' | head -30"
            }
            Self::RunningUsers => "who 2>/dev/null; echo '---'; id 2>/dev/null",
            Self::LoadedModules => "lsmod 2>/dev/null | head -50",
            Self::RecentModifiedFiles => {
                "find /etc /usr/bin /usr/sbin -mtime -3 -type f 2>/dev/null | head -50"
            }
            Self::EnvVariables => "env 2>/dev/null | sort | head -60",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForensicTarget {
    pub identity: TargetIdentity,
    pub session_id: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub host_key_fingerprint: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForensicData {
    pub processes: String,
    pub network_connections: String,
    pub listening_ports: String,
    pub login_history: String,
    pub cron_jobs: String,
    pub startup_services: String,
    pub authorized_keys: String,
    pub sudoers: String,
    pub running_users: String,
    pub loaded_modules: String,
    pub recent_modified_files: String,
    pub env_variables: String,
}

impl ForensicData {
    pub fn get(&self, collector: ForensicCollector) -> &str {
        match collector {
            ForensicCollector::Processes => &self.processes,
            ForensicCollector::NetworkConnections => &self.network_connections,
            ForensicCollector::ListeningPorts => &self.listening_ports,
            ForensicCollector::LoginHistory => &self.login_history,
            ForensicCollector::CronJobs => &self.cron_jobs,
            ForensicCollector::StartupServices => &self.startup_services,
            ForensicCollector::AuthorizedKeys => &self.authorized_keys,
            ForensicCollector::Sudoers => &self.sudoers,
            ForensicCollector::RunningUsers => &self.running_users,
            ForensicCollector::LoadedModules => &self.loaded_modules,
            ForensicCollector::RecentModifiedFiles => &self.recent_modified_files,
            ForensicCollector::EnvVariables => &self.env_variables,
        }
    }

    fn set(&mut self, collector: ForensicCollector, value: String) {
        match collector {
            ForensicCollector::Processes => self.processes = value,
            ForensicCollector::NetworkConnections => self.network_connections = value,
            ForensicCollector::ListeningPorts => self.listening_ports = value,
            ForensicCollector::LoginHistory => self.login_history = value,
            ForensicCollector::CronJobs => self.cron_jobs = value,
            ForensicCollector::StartupServices => self.startup_services = value,
            ForensicCollector::AuthorizedKeys => self.authorized_keys = value,
            ForensicCollector::Sudoers => self.sudoers = value,
            ForensicCollector::RunningUsers => self.running_users = value,
            ForensicCollector::LoadedModules => self.loaded_modules = value,
            ForensicCollector::RecentModifiedFiles => self.recent_modified_files = value,
            ForensicCollector::EnvVariables => self.env_variables = value,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForensicCollectionSummary {
    pub total: usize,
    pub completed: usize,
    pub failed: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForensicSnapshot {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub server: String,
    pub target: ForensicTarget,
    pub collection: ForensicCollectionSummary,
    pub data: ForensicData,
    pub sha256: String,
}

#[derive(Debug, Serialize)]
struct ForensicArtifact<'a> {
    schema: &'static str,
    id: &'a str,
    timestamp: DateTime<Utc>,
    server: &'a str,
    target: &'a ForensicTarget,
    collection: &'a ForensicCollectionSummary,
    data: &'a ForensicData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForensicFieldDiff {
    pub collector: ForensicCollector,
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForensicSnapshotDiff {
    pub older_id: String,
    pub newer_id: String,
    pub fields: Vec<ForensicFieldDiff>,
}

#[derive(Clone, Default)]
pub struct ForensicCancellation {
    inner: Arc<ForensicCancellationInner>,
}

#[derive(Debug, Default)]
struct ForensicCancellationInner {
    cancelled: AtomicBool,
    notify: Notify,
}

impl fmt::Debug for ForensicCancellation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ForensicCancellation")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

impl ForensicCancellation {
    pub fn cancel(&self) {
        self.inner.cancelled.store(true, Ordering::Release);
        self.inner.notify.notify_waiters();
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire)
    }

    async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        let notified = self.inner.notify.notified();
        if self.is_cancelled() {
            return;
        }
        notified.await;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForensicCaptureEvent {
    Started {
        capture_id: String,
        total: usize,
    },
    CollectorStarted {
        capture_id: String,
        collector: ForensicCollector,
        ordinal: usize,
        total: usize,
    },
    CollectorFinished {
        capture_id: String,
        collector: ForensicCollector,
        completed: usize,
        total: usize,
        failed: bool,
    },
    Finished {
        capture_id: String,
        failed: usize,
    },
}

#[derive(Debug, Clone)]
pub struct ForensicEventSender {
    sender: async_channel::Sender<ForensicCaptureEvent>,
    dropped: Arc<AtomicUsize>,
}

#[derive(Debug, Clone)]
pub struct ForensicEventReceiver {
    receiver: async_channel::Receiver<ForensicCaptureEvent>,
}

pub fn forensic_event_channel(
    capacity: usize,
) -> CoreResult<(ForensicEventSender, ForensicEventReceiver)> {
    if capacity == 0 || capacity > MAX_EVENT_CAPACITY {
        return Err(CoreError::validation(
            "forensic event capacity",
            format!("must be 1..={MAX_EVENT_CAPACITY}"),
        ));
    }
    let (sender, receiver) = async_channel::bounded(capacity);
    Ok((
        ForensicEventSender {
            sender,
            dropped: Arc::new(AtomicUsize::new(0)),
        },
        ForensicEventReceiver { receiver },
    ))
}

impl ForensicEventSender {
    fn emit(&self, event: ForensicCaptureEvent) {
        if self.sender.try_send(event).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn dropped_count(&self) -> usize {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl ForensicEventReceiver {
    pub async fn recv(&self) -> Option<ForensicCaptureEvent> {
        self.receiver.recv().await.ok()
    }

    pub fn try_recv(&self) -> Option<ForensicCaptureEvent> {
        self.receiver.try_recv().ok()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SnapshotDocument {
    version: u32,
    #[serde(deserialize_with = "deserialize_directory_snapshots")]
    directory_snapshots: Vec<DirectorySnapshot>,
    #[serde(deserialize_with = "deserialize_forensic_snapshots")]
    forensic_snapshots: Vec<ForensicSnapshot>,
}

fn deserialize_directory_snapshots<'de, D>(
    deserializer: D,
) -> Result<Vec<DirectorySnapshot>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_snapshots(
        deserializer,
        DIRECTORY_SNAPSHOT_LIMIT,
        "directory snapshot index",
    )
}

fn deserialize_forensic_snapshots<'de, D>(
    deserializer: D,
) -> Result<Vec<ForensicSnapshot>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_snapshots(
        deserializer,
        FORENSIC_SNAPSHOT_LIMIT,
        "forensic snapshot index",
    )
}

fn deserialize_bounded_snapshots<'de, D, T>(
    deserializer: D,
    maximum: usize,
    subject: &'static str,
) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct BoundedSnapshotVisitor<T> {
        marker: std::marker::PhantomData<T>,
        maximum: usize,
        subject: &'static str,
    }

    impl<'de, T> Visitor<'de> for BoundedSnapshotVisitor<T>
    where
        T: Deserialize<'de>,
    {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "{} with at most {} entries",
                self.subject, self.maximum
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if sequence
                .size_hint()
                .is_some_and(|length| length > self.maximum)
            {
                return Err(de::Error::custom(format!(
                    "{} exceeds its {} entry limit",
                    self.subject, self.maximum
                )));
            }
            let mut values =
                Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(self.maximum));
            while values.len() < self.maximum {
                match sequence.next_element()? {
                    Some(value) => values.push(value),
                    None => return Ok(values),
                }
            }
            if sequence.next_element::<IgnoredAny>()?.is_some() {
                return Err(de::Error::custom(format!(
                    "{} exceeds its {} entry limit",
                    self.subject, self.maximum
                )));
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(BoundedSnapshotVisitor {
        marker: std::marker::PhantomData,
        maximum,
        subject,
    })
}

impl Default for SnapshotDocument {
    fn default() -> Self {
        Self {
            version: SNAPSHOT_DOCUMENT_VERSION,
            directory_snapshots: Vec::new(),
            forensic_snapshots: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SnapshotService {
    ssh: SshService,
    target: Arc<TargetContext>,
    store: PortableStore,
    journal: PortableOperationJournal,
    transaction: Arc<Mutex<()>>,
}

impl SnapshotService {
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
            transaction: Arc::new(Mutex::new(())),
        }
    }

    pub fn plan_directory_snapshot(
        &self,
        session: &BoundSshSession,
        presets: impl IntoIterator<Item = SnapshotPreset>,
    ) -> CoreResult<DirectorySnapshotPlan> {
        self.target.validate(session.target())?;
        let presets = normalize_presets(presets)?;
        let snapshot_id = Uuid::new_v4().to_string();
        let remote_root = format!("{REMOTE_ROOT_PREFIX}/{snapshot_id}");
        validate_remote_root(&snapshot_id, &remote_root)?;
        let mut operation = OperationPlan::new(
            session.target().clone(),
            format!("为可信目标创建 {} 项只读归档快照", presets.len()),
            false,
            Some("删除本次新建的远端归档与便携索引".to_owned()),
        )?;
        operation
            .metadata
            .insert("snapshot-id".to_owned(), snapshot_id.clone());
        operation
            .metadata
            .insert("remote-root".to_owned(), remote_root.clone());
        operation.metadata.insert(
            "presets".to_owned(),
            presets
                .iter()
                .map(|preset| preset.id())
                .collect::<Vec<_>>()
                .join(","),
        );
        Ok(DirectorySnapshotPlan {
            operation,
            snapshot_id,
            remote_root,
            presets,
        })
    }

    pub async fn execute_directory_snapshot(
        &self,
        session: &BoundSshSession,
        plan: DirectorySnapshotPlan,
    ) -> CoreResult<DirectorySnapshot> {
        ensure_target_plan(session, &plan.operation)?;
        let operation_id = plan.operation.id.clone();
        let snapshot_id = plan.snapshot_id.clone();
        let executor = DirectoryCreateExecutor {
            service: self,
            session,
            plan: &plan,
        };
        let mut operation = PlannedOperation::plan(plan.operation.clone());
        if let Err(error) = operation.execute(&self.target, &executor).await {
            if operation.state() == OperationState::StaleAfterExecution {
                operation.journal(&self.journal)?;
            }
            return Err(error);
        }
        operation.journal(&self.journal)?;
        let verification = match operation
            .verify(&self.target, &executor, &self.journal)
            .await
        {
            Ok(verification) => verification,
            Err(error) => {
                operation
                    .restore(&self.target, &executor, &self.journal)
                    .await?;
                return Err(error);
            }
        };
        if !verification.passed {
            operation
                .restore(&self.target, &executor, &self.journal)
                .await?;
            return Err(CoreError::validation(
                "directory snapshot verification",
                verification.detail,
            ));
        }
        self.directory_by_id(session.target(), &snapshot_id)?
            .ok_or(CoreError::NotFound {
                entity: "verified directory snapshot",
                id: operation_id,
            })
    }

    pub fn list_directory(&self, target: &TargetGuard) -> CoreResult<Vec<DirectorySnapshot>> {
        self.target.validate(target)?;
        let mut snapshots = self
            .load_document()?
            .directory_snapshots
            .into_iter()
            .filter(|snapshot| snapshot.target == target.identity)
            .map(validate_directory_snapshot)
            .collect::<CoreResult<Vec<_>>>()?;
        snapshots.sort_by(|left, right| right.created_at.cmp(&left.created_at));
        Ok(snapshots)
    }

    pub fn plan_restore_item(
        &self,
        session: &BoundSshSession,
        snapshot_id: &str,
        preset: SnapshotPreset,
    ) -> CoreResult<DirectoryRestorePlan> {
        self.target.validate(session.target())?;
        let snapshot = self
            .directory_by_id(session.target(), snapshot_id)?
            .ok_or_else(|| CoreError::NotFound {
                entity: "directory snapshot",
                id: snapshot_id.to_owned(),
            })?;
        let item = snapshot
            .items
            .iter()
            .find(|item| item.preset == preset)
            .cloned()
            .ok_or_else(|| CoreError::NotFound {
                entity: "snapshot item",
                id: preset.id().to_owned(),
            })?;
        let rollback_root = format!("{}/restore-{}", snapshot.remote_root, Uuid::new_v4());
        validate_child_path(&snapshot.remote_root, &rollback_root)?;
        let mut operation = OperationPlan::new(
            session.target().clone(),
            format!(
                "用快照 {} 覆盖恢复 {}；执行前会保存当前状态",
                snapshot.id,
                preset.label()
            ),
            true,
            Some(format!(
                "从临时回滚归档恢复 {} 的执行前状态",
                preset.label()
            )),
        )?;
        operation
            .metadata
            .insert("snapshot-id".to_owned(), snapshot.id.clone());
        operation
            .metadata
            .insert("preset".to_owned(), preset.id().to_owned());
        operation
            .metadata
            .insert("record-sha256".to_owned(), snapshot.record_sha256.clone());
        Ok(DirectoryRestorePlan {
            operation,
            snapshot,
            item,
            rollback_root,
        })
    }

    pub async fn execute_restore_item(
        &self,
        session: &BoundSshSession,
        plan: DirectoryRestorePlan,
        confirmation: DangerousConfirmation,
    ) -> CoreResult<SnapshotOperationOutcome> {
        ensure_target_plan(session, &plan.operation)?;
        let operation_id = plan.operation.id.clone();
        let executor = DirectoryRestoreExecutor {
            service: self,
            session,
            plan: &plan,
        };
        let mut operation = PlannedOperation::plan(plan.operation.clone());
        operation.confirm(confirmation)?;
        if let Err(error) = operation.execute(&self.target, &executor).await {
            if operation.state() == OperationState::StaleAfterExecution {
                operation.journal(&self.journal)?;
            }
            return Err(error);
        }
        operation.journal(&self.journal)?;
        let verification = match operation
            .verify(&self.target, &executor, &self.journal)
            .await
        {
            Ok(verification) => verification,
            Err(error) => {
                operation
                    .restore(&self.target, &executor, &self.journal)
                    .await?;
                return Err(error);
            }
        };
        let mut restored = false;
        if !verification.passed {
            operation
                .restore(&self.target, &executor, &self.journal)
                .await?;
            restored = true;
        } else {
            executor.cleanup_rollback().await?;
        }
        Ok(SnapshotOperationOutcome {
            operation_id,
            verified: verification.passed,
            detail: verification.detail,
            restored_after_failed_verification: restored,
        })
    }

    pub fn plan_delete_directory(
        &self,
        session: &BoundSshSession,
        snapshot_id: &str,
    ) -> CoreResult<DirectoryDeletePlan> {
        self.target.validate(session.target())?;
        let snapshot = self
            .directory_by_id(session.target(), snapshot_id)?
            .ok_or_else(|| CoreError::NotFound {
                entity: "directory snapshot",
                id: snapshot_id.to_owned(),
            })?;
        let mut operation = OperationPlan::new(
            session.target().clone(),
            format!("永久删除目录快照 {} 及其远端归档", snapshot.id),
            true,
            None,
        )?;
        operation
            .metadata
            .insert("snapshot-id".to_owned(), snapshot.id.clone());
        operation
            .metadata
            .insert("record-sha256".to_owned(), snapshot.record_sha256.clone());
        Ok(DirectoryDeletePlan {
            operation,
            snapshot,
        })
    }

    pub async fn execute_delete_directory(
        &self,
        session: &BoundSshSession,
        plan: DirectoryDeletePlan,
        confirmation: DangerousConfirmation,
    ) -> CoreResult<SnapshotOperationOutcome> {
        ensure_target_plan(session, &plan.operation)?;
        let operation_id = plan.operation.id.clone();
        let executor = DirectoryDeleteExecutor {
            service: self,
            session,
            plan: &plan,
        };
        let mut operation = PlannedOperation::plan(plan.operation.clone());
        operation.confirm(confirmation)?;
        if let Err(error) = operation.execute(&self.target, &executor).await {
            if operation.state() == OperationState::StaleAfterExecution {
                operation.journal(&self.journal)?;
            }
            return Err(error);
        }
        operation.journal(&self.journal)?;
        let verification = operation
            .verify(&self.target, &executor, &self.journal)
            .await?;
        Ok(SnapshotOperationOutcome {
            operation_id,
            verified: verification.passed,
            detail: verification.detail,
            restored_after_failed_verification: false,
        })
    }

    pub async fn capture_forensic(
        &self,
        session: &BoundSshSession,
        cancellation: ForensicCancellation,
        events: Option<ForensicEventSender>,
    ) -> CoreResult<ForensicSnapshot> {
        self.target.validate(session.target())?;
        let capture_id = format!("snap-{}", Uuid::new_v4());
        if let Some(events) = &events {
            events.emit(ForensicCaptureEvent::Started {
                capture_id: capture_id.clone(),
                total: ForensicCollector::ALL.len(),
            });
        }
        let completed = Arc::new(AtomicUsize::new(0));
        let failed = Arc::new(AtomicUsize::new(0));
        let work = stream::iter(ForensicCollector::ALL.into_iter().enumerate()).map(
            |(index, collector)| {
                let capture_id = capture_id.clone();
                let cancellation = cancellation.clone();
                let events = events.clone();
                let completed = completed.clone();
                let failed = failed.clone();
                async move {
                    self.target.validate(session.target())?;
                    if cancellation.is_cancelled() {
                        return Err(CoreError::OperationCancelled {
                            operation_id: capture_id,
                        });
                    }
                    if let Some(events) = &events {
                        events.emit(ForensicCaptureEvent::CollectorStarted {
                            capture_id: capture_id.clone(),
                            collector,
                            ordinal: index + 1,
                            total: ForensicCollector::ALL.len(),
                        });
                    }
                    let result = tokio::select! {
                        _ = cancellation.cancelled() => {
                            return Err(CoreError::OperationCancelled { operation_id: capture_id });
                        }
                        result = self.ssh.execute_bound(
                            session,
                            collector.command().to_owned(),
                            FORENSIC_TIMEOUT,
                        ) => result,
                    };
                    self.target.validate(session.target())?;
                    let (text, did_fail) = forensic_text(result)?;
                    if did_fail {
                        failed.fetch_add(1, Ordering::AcqRel);
                    }
                    let done = completed.fetch_add(1, Ordering::AcqRel) + 1;
                    if let Some(events) = &events {
                        events.emit(ForensicCaptureEvent::CollectorFinished {
                            capture_id,
                            collector,
                            completed: done,
                            total: ForensicCollector::ALL.len(),
                            failed: did_fail,
                        });
                    }
                    Ok((index, collector, text))
                }
            },
        );
        let mut fields: Vec<(usize, ForensicCollector, String)> = work
            .buffer_unordered(FORENSIC_CONCURRENCY)
            .try_collect()
            .await?;
        self.target.validate(session.target())?;
        if cancellation.is_cancelled() {
            return Err(CoreError::OperationCancelled {
                operation_id: capture_id,
            });
        }
        fields.sort_by_key(|(index, _, _)| *index);
        let mut data = ForensicData::default();
        let total_bytes = fields.iter().map(|(_, _, text)| text.len()).sum::<usize>();
        if total_bytes > MAX_FORENSIC_TOTAL_BYTES {
            return Err(CoreError::validation(
                "forensic snapshot",
                format!("combined output exceeds {MAX_FORENSIC_TOTAL_BYTES} bytes"),
            ));
        }
        for (_, collector, text) in fields {
            data.set(collector, text);
        }
        let status = self
            .ssh
            .list_sessions()
            .await?
            .into_iter()
            .find(|status| {
                status.session_id == session.session_id()
                    && status.connection_id == session.connection_id()
            })
            .ok_or_else(|| CoreError::NotFound {
                entity: "SSH session for forensic snapshot",
                id: session.session_id().to_owned(),
            })?;
        self.target.validate(session.target())?;
        let failed_count = failed.load(Ordering::Acquire);
        let mut snapshot = ForensicSnapshot {
            id: capture_id.clone(),
            timestamp: Utc::now(),
            server: status.host.clone(),
            target: ForensicTarget {
                identity: session.target().identity.clone(),
                session_id: status.session_id,
                host: status.host,
                port: status.port,
                username: status.username,
                host_key_fingerprint: status.host_key_fingerprint,
            },
            collection: ForensicCollectionSummary {
                total: ForensicCollector::ALL.len(),
                completed: completed.load(Ordering::Acquire),
                failed: failed_count,
            },
            data,
            sha256: String::new(),
        };
        snapshot.sha256 = forensic_digest(&snapshot)?;
        self.target.validate(session.target())?;

        self.target
            .apply_if_current(session.target(), || self.insert_forensic(snapshot.clone()))?;
        if let Some(events) = &events {
            events.emit(ForensicCaptureEvent::Finished {
                capture_id,
                failed: failed_count,
            });
        }
        Ok(snapshot)
    }

    pub fn list_forensic(&self, target: &TargetGuard) -> CoreResult<Vec<ForensicSnapshot>> {
        self.target.validate(target)?;
        let mut snapshots = self
            .load_document()?
            .forensic_snapshots
            .into_iter()
            .filter(|snapshot| snapshot.target.identity == target.identity)
            .map(validate_forensic_snapshot)
            .collect::<CoreResult<Vec<_>>>()?;
        snapshots.sort_by(|left, right| right.timestamp.cmp(&left.timestamp));
        Ok(snapshots)
    }

    pub fn export_forensic(&self, target: &TargetGuard, snapshot_id: &str) -> CoreResult<String> {
        self.target.validate(target)?;
        let snapshot = self
            .list_forensic(target)?
            .into_iter()
            .find(|snapshot| snapshot.id == snapshot_id)
            .ok_or_else(|| CoreError::NotFound {
                entity: "forensic snapshot",
                id: snapshot_id.to_owned(),
            })?;
        forensic_artifact(&snapshot)
    }

    pub fn diff_forensic(
        &self,
        target: &TargetGuard,
        older_id: &str,
        newer_id: &str,
    ) -> CoreResult<ForensicSnapshotDiff> {
        if older_id == newer_id {
            return Err(CoreError::validation(
                "forensic snapshot diff",
                "select two different snapshots",
            ));
        }
        let snapshots = self.list_forensic(target)?;
        let older = snapshots
            .iter()
            .find(|snapshot| snapshot.id == older_id)
            .ok_or_else(|| CoreError::NotFound {
                entity: "older forensic snapshot",
                id: older_id.to_owned(),
            })?;
        let newer = snapshots
            .iter()
            .find(|snapshot| snapshot.id == newer_id)
            .ok_or_else(|| CoreError::NotFound {
                entity: "newer forensic snapshot",
                id: newer_id.to_owned(),
            })?;
        let mut input_lines = 0;
        let fields = ForensicCollector::ALL
            .into_iter()
            .map(|collector| {
                diff_field(
                    collector,
                    older.data.get(collector),
                    newer.data.get(collector),
                    &mut input_lines,
                )
            })
            .collect::<CoreResult<Vec<_>>>()?;
        Ok(ForensicSnapshotDiff {
            older_id: older.id.clone(),
            newer_id: newer.id.clone(),
            fields,
        })
    }

    fn load_document(&self) -> CoreResult<SnapshotDocument> {
        let document = self.store.read_or_default_bounded::<SnapshotDocument>(
            StoreFile::Snapshots,
            MAX_SNAPSHOT_DOCUMENT_BYTES,
        )?;
        if document.version != SNAPSHOT_DOCUMENT_VERSION {
            return Err(CoreError::UnsupportedSchema {
                document: "snapshot document",
                expected: SNAPSHOT_DOCUMENT_VERSION,
                actual: document.version,
            });
        }
        if document.directory_snapshots.len() > DIRECTORY_SNAPSHOT_LIMIT
            || document.forensic_snapshots.len() > FORENSIC_SNAPSHOT_LIMIT
        {
            return Err(CoreError::validation(
                "snapshot document",
                "the portable snapshot index exceeds its bounded entry count",
            ));
        }
        Ok(document)
    }

    fn directory_by_id(
        &self,
        target: &TargetGuard,
        snapshot_id: &str,
    ) -> CoreResult<Option<DirectorySnapshot>> {
        self.target.validate(target)?;
        self.load_document()?
            .directory_snapshots
            .into_iter()
            .find(|snapshot| snapshot.id == snapshot_id && snapshot.target == target.identity)
            .map(validate_directory_snapshot)
            .transpose()
    }

    fn insert_directory(&self, snapshot: DirectorySnapshot) -> CoreResult<()> {
        let _guard = self.transaction.lock();
        let mut document = self.load_document()?;
        if document
            .directory_snapshots
            .iter()
            .any(|existing| existing.id == snapshot.id)
        {
            return Err(CoreError::validation(
                "directory snapshot",
                "generated snapshot id already exists",
            ));
        }
        document.directory_snapshots.push(snapshot);
        document
            .directory_snapshots
            .sort_by(|left, right| right.created_at.cmp(&left.created_at));
        document
            .directory_snapshots
            .truncate(DIRECTORY_SNAPSHOT_LIMIT);
        self.store.write(StoreFile::Snapshots, &document)
    }

    fn remove_directory(&self, id: &str, record_sha256: &str) -> CoreResult<()> {
        let _guard = self.transaction.lock();
        let mut document = self.load_document()?;
        let index = document
            .directory_snapshots
            .iter()
            .position(|snapshot| snapshot.id == id && snapshot.record_sha256 == record_sha256)
            .ok_or_else(|| {
                CoreError::validation(
                    "directory snapshot",
                    "snapshot changed or disappeared after planning",
                )
            })?;
        document.directory_snapshots.remove(index);
        self.store.write(StoreFile::Snapshots, &document)
    }

    fn insert_forensic(&self, snapshot: ForensicSnapshot) -> CoreResult<()> {
        let _guard = self.transaction.lock();
        let mut document = self.load_document()?;
        if document
            .forensic_snapshots
            .iter()
            .any(|existing| existing.id == snapshot.id)
        {
            return Err(CoreError::validation(
                "forensic snapshot",
                "generated snapshot id already exists",
            ));
        }
        document.forensic_snapshots.push(snapshot);
        document
            .forensic_snapshots
            .sort_by(|left, right| right.timestamp.cmp(&left.timestamp));
        document
            .forensic_snapshots
            .truncate(FORENSIC_SNAPSHOT_LIMIT);
        self.store.write(StoreFile::Snapshots, &document)
    }
}

#[derive(Debug)]
struct DirectoryCreateExecutor<'a> {
    service: &'a SnapshotService,
    session: &'a BoundSshSession,
    plan: &'a DirectorySnapshotPlan,
}

#[async_trait]
impl OperationExecutor for DirectoryCreateExecutor<'_> {
    async fn execute(&self, plan: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        ensure_same_plan(plan, &self.plan.operation)?;
        let output = self
            .service
            .ssh
            .execute_bound(
                self.session,
                build_directory_create_command(self.plan),
                SNAPSHOT_MUTATION_TIMEOUT,
            )
            .await?;
        let output = successful_output("create directory snapshot", output)?;
        let items = parse_directory_create_output(self.plan, &output)?;
        let mut snapshot = DirectorySnapshot {
            id: self.plan.snapshot_id.clone(),
            target: self.session.target().identity.clone(),
            created_at: Utc::now(),
            remote_root: self.plan.remote_root.clone(),
            items,
            record_sha256: String::new(),
        };
        snapshot.record_sha256 = directory_digest(&snapshot)?;
        if let Err(error) = self
            .service
            .target
            .apply_if_current(self.session.target(), || {
                self.service.insert_directory(snapshot)
            })
        {
            let _ = self
                .service
                .ssh
                .execute_bound(
                    self.session,
                    build_remove_root_command(&self.plan.snapshot_id, &self.plan.remote_root)?,
                    SNAPSHOT_VERIFY_TIMEOUT,
                )
                .await;
            return Err(error);
        }
        Ok(ExecutionReceipt {
            summary: format!(
                "created {} immutable snapshot artifacts",
                self.plan.presets.len()
            ),
            restore_token: Some(self.plan.snapshot_id.clone()),
        })
    }

    async fn verify(
        &self,
        plan: &OperationPlan,
        _: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        ensure_same_plan(plan, &self.plan.operation)?;
        let snapshot = self
            .service
            .directory_by_id(self.session.target(), &self.plan.snapshot_id)?
            .ok_or_else(|| CoreError::NotFound {
                entity: "directory snapshot index",
                id: self.plan.snapshot_id.clone(),
            })?;
        let output = self
            .service
            .ssh
            .execute_bound(
                self.session,
                build_directory_verify_command(&snapshot)?,
                SNAPSHOT_VERIFY_TIMEOUT,
            )
            .await?;
        let passed = !output.timed_out
            && output.exit_code == Some(0)
            && output
                .output
                .lines()
                .any(|line| line.trim() == "LR_SNAPSHOT_VERIFY_V1");
        Ok(VerificationResult {
            passed,
            detail: if passed {
                "verified the portable index and every remote archive SHA-256".to_owned()
            } else {
                "remote archive readback did not match the immutable plan".to_owned()
            },
        })
    }

    async fn restore(&self, plan: &OperationPlan, _: &ExecutionReceipt) -> CoreResult<()> {
        ensure_same_plan(plan, &self.plan.operation)?;
        let output = self
            .service
            .ssh
            .execute_bound(
                self.session,
                build_remove_root_command(&self.plan.snapshot_id, &self.plan.remote_root)?,
                SNAPSHOT_VERIFY_TIMEOUT,
            )
            .await?;
        successful_output("remove failed directory snapshot", output)?;
        if let Some(snapshot) = self
            .service
            .directory_by_id(self.session.target(), &self.plan.snapshot_id)?
        {
            self.service
                .remove_directory(&snapshot.id, &snapshot.record_sha256)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct DirectoryRestoreExecutor<'a> {
    service: &'a SnapshotService,
    session: &'a BoundSshSession,
    plan: &'a DirectoryRestorePlan,
}

impl DirectoryRestoreExecutor<'_> {
    async fn cleanup_rollback(&self) -> CoreResult<()> {
        self.service.target.validate(self.session.target())?;
        let cleanup = format!(
            "set -eu; rm -rf -- {}; printf '%s\\n' LR_SNAPSHOT_ROLLBACK_CLEAN_V1",
            shq(&self.plan.rollback_root)
        );
        let cleanup_output = self
            .service
            .ssh
            .execute_bound(self.session, cleanup, SNAPSHOT_VERIFY_TIMEOUT)
            .await?;
        successful_marker(
            "remove restore rollback artifact",
            cleanup_output,
            "LR_SNAPSHOT_ROLLBACK_CLEAN_V1",
        )?;
        self.service.target.validate(self.session.target())
    }
}

#[async_trait]
impl OperationExecutor for DirectoryRestoreExecutor<'_> {
    async fn execute(&self, plan: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        ensure_same_plan(plan, &self.plan.operation)?;
        ensure_snapshot_unchanged(self.service, self.session.target(), &self.plan.snapshot)?;
        let output = self
            .service
            .ssh
            .execute_bound(
                self.session,
                build_restore_execute_command(self.plan)?,
                SNAPSHOT_MUTATION_TIMEOUT,
            )
            .await?;
        successful_marker("restore snapshot item", output, "LR_SNAPSHOT_RESTORE_V1")?;
        Ok(ExecutionReceipt {
            summary: format!(
                "restored {} after capturing its previous state",
                self.plan.item.preset.label()
            ),
            restore_token: Some(self.plan.rollback_root.clone()),
        })
    }

    async fn verify(
        &self,
        plan: &OperationPlan,
        _: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        ensure_same_plan(plan, &self.plan.operation)?;
        let output = self
            .service
            .ssh
            .execute_bound(
                self.session,
                build_restore_verify_command(self.plan)?,
                SNAPSHOT_VERIFY_TIMEOUT,
            )
            .await?;
        let passed = !output.timed_out
            && output.exit_code == Some(0)
            && output
                .output
                .lines()
                .any(|line| line.trim() == "LR_SNAPSHOT_RESTORE_VERIFY_V1");
        Ok(VerificationResult {
            passed,
            detail: if passed {
                "verified destination state and source archive integrity".to_owned()
            } else {
                "destination readback failed; the previous state must be restored".to_owned()
            },
        })
    }

    async fn restore(&self, plan: &OperationPlan, _: &ExecutionReceipt) -> CoreResult<()> {
        ensure_same_plan(plan, &self.plan.operation)?;
        let output = self
            .service
            .ssh
            .execute_bound(
                self.session,
                build_restore_rollback_command(self.plan)?,
                SNAPSHOT_MUTATION_TIMEOUT,
            )
            .await?;
        successful_marker(
            "restore pre-operation snapshot state",
            output,
            "LR_SNAPSHOT_ROLLBACK_V1",
        )?;
        Ok(())
    }
}

#[derive(Debug)]
struct DirectoryDeleteExecutor<'a> {
    service: &'a SnapshotService,
    session: &'a BoundSshSession,
    plan: &'a DirectoryDeletePlan,
}

#[async_trait]
impl OperationExecutor for DirectoryDeleteExecutor<'_> {
    async fn execute(&self, plan: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        ensure_same_plan(plan, &self.plan.operation)?;
        ensure_snapshot_unchanged(self.service, self.session.target(), &self.plan.snapshot)?;
        let output = self
            .service
            .ssh
            .execute_bound(
                self.session,
                build_remove_root_command(&self.plan.snapshot.id, &self.plan.snapshot.remote_root)?,
                SNAPSHOT_MUTATION_TIMEOUT,
            )
            .await?;
        successful_output("delete directory snapshot", output)?;
        self.service
            .remove_directory(&self.plan.snapshot.id, &self.plan.snapshot.record_sha256)?;
        Ok(ExecutionReceipt {
            summary: "deleted the UUID-owned remote archive and portable index".to_owned(),
            restore_token: None,
        })
    }

    async fn verify(
        &self,
        plan: &OperationPlan,
        _: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        ensure_same_plan(plan, &self.plan.operation)?;
        let local_absent = self
            .service
            .directory_by_id(self.session.target(), &self.plan.snapshot.id)?
            .is_none();
        let command = format!(
            "set -eu; test ! -e {}; printf '%s\\n' LR_SNAPSHOT_DELETE_VERIFY_V1",
            shq(&self.plan.snapshot.remote_root)
        );
        let output = self
            .service
            .ssh
            .execute_bound(self.session, command, SNAPSHOT_VERIFY_TIMEOUT)
            .await?;
        let remote_absent = !output.timed_out
            && output.exit_code == Some(0)
            && output
                .output
                .lines()
                .any(|line| line.trim() == "LR_SNAPSHOT_DELETE_VERIFY_V1");
        Ok(VerificationResult {
            passed: local_absent && remote_absent,
            detail: if local_absent && remote_absent {
                "verified that the local index and remote archive are absent".to_owned()
            } else {
                "snapshot deletion readback failed".to_owned()
            },
        })
    }

    async fn restore(&self, _: &OperationPlan, _: &ExecutionReceipt) -> CoreResult<()> {
        Err(CoreError::Unsupported {
            feature: "restoring a deleted remote snapshot archive",
        })
    }
}

fn normalize_presets(
    presets: impl IntoIterator<Item = SnapshotPreset>,
) -> CoreResult<Vec<SnapshotPreset>> {
    let mut presets = presets.into_iter().collect::<Vec<_>>();
    presets.sort_unstable();
    presets.dedup();
    if presets.is_empty() || presets.len() > SnapshotPreset::ALL.len() {
        return Err(CoreError::validation(
            "snapshot presets",
            format!("select 1..={} fixed presets", SnapshotPreset::ALL.len()),
        ));
    }
    Ok(presets)
}

fn ensure_target_plan(session: &BoundSshSession, plan: &OperationPlan) -> CoreResult<()> {
    if plan.target != *session.target() {
        return Err(CoreError::validation(
            "snapshot operation target",
            "plan is bound to a different SSH target epoch",
        ));
    }
    Ok(())
}

fn ensure_same_plan(actual: &OperationPlan, expected: &OperationPlan) -> CoreResult<()> {
    if actual.id != expected.id || actual.target != expected.target {
        return Err(CoreError::validation(
            "snapshot executor",
            "executor is bound to a different immutable operation plan",
        ));
    }
    Ok(())
}

fn validate_remote_root(snapshot_id: &str, remote_root: &str) -> CoreResult<()> {
    let parsed = Uuid::parse_str(snapshot_id)
        .map_err(|_| CoreError::validation("snapshot id", "must be a canonical UUID"))?;
    if parsed.hyphenated().to_string() != snapshot_id
        || remote_root != format!("{REMOTE_ROOT_PREFIX}/{snapshot_id}")
    {
        return Err(CoreError::validation(
            "remote snapshot root",
            "must be the exact UUID-owned LovelyRes snapshot namespace",
        ));
    }
    Ok(())
}

fn validate_child_path(root: &str, child: &str) -> CoreResult<()> {
    if !child.starts_with(&format!("{root}/"))
        || child.contains("/../")
        || child.contains('\n')
        || child.contains('\r')
    {
        return Err(CoreError::validation(
            "snapshot child path",
            "must remain inside the immutable remote snapshot root",
        ));
    }
    Ok(())
}

fn directory_digest(snapshot: &DirectorySnapshot) -> CoreResult<String> {
    let mut canonical = snapshot.clone();
    canonical.record_sha256.clear();
    let bytes = serde_json::to_vec(&canonical).map_err(|source| CoreError::Encode {
        subject: "directory snapshot digest",
        source,
    })?;
    Ok(hex_digest(&bytes))
}

fn validate_directory_snapshot(snapshot: DirectorySnapshot) -> CoreResult<DirectorySnapshot> {
    validate_remote_root(&snapshot.id, &snapshot.remote_root)?;
    if snapshot.items.is_empty() || snapshot.items.len() > SnapshotPreset::ALL.len() {
        return Err(CoreError::validation(
            "directory snapshot",
            "contains an invalid number of items",
        ));
    }
    let mut presets = BTreeSet::new();
    for item in &snapshot.items {
        if !presets.insert(item.preset)
            || item.source != item.preset.source()
            || item.kind != item.preset.kind()
            || item.archive_path
                != format!("{}/{}", snapshot.remote_root, item.preset.archive_name())
            || !is_sha256(&item.archive_sha256)
            || !is_sha256(&item.content_sha256)
        {
            return Err(CoreError::validation(
                "directory snapshot",
                "stored item violates the fixed preset or digest contract",
            ));
        }
    }
    if directory_digest(&snapshot)? != snapshot.record_sha256 {
        return Err(CoreError::validation(
            "directory snapshot",
            "portable snapshot record SHA-256 does not match its contents",
        ));
    }
    Ok(snapshot)
}

fn ensure_snapshot_unchanged(
    service: &SnapshotService,
    target: &TargetGuard,
    planned: &DirectorySnapshot,
) -> CoreResult<()> {
    let current = service
        .directory_by_id(target, &planned.id)?
        .ok_or_else(|| CoreError::NotFound {
            entity: "planned directory snapshot",
            id: planned.id.clone(),
        })?;
    if current.record_sha256 != planned.record_sha256 {
        return Err(CoreError::validation(
            "directory snapshot plan",
            "snapshot metadata changed after planning",
        ));
    }
    Ok(())
}

fn build_directory_create_command(plan: &DirectorySnapshotPlan) -> String {
    let root = shq(&plan.remote_root);
    let mut command = format!(
        "set -eu; umask 077; test ! -e {root}; mkdir -p -- {root}; trap 'rm -rf -- {root}' HUP INT TERM EXIT; "
    );
    for preset in &plan.presets {
        let archive_path = format!("{}/{}", plan.remote_root, preset.archive_name());
        let archive = shq(&archive_path);
        match preset.kind() {
            SnapshotItemKind::Crontab => command.push_str(&format!(
                "if crontab -l > {archive} 2>/dev/null; then present=1; else : > {archive}; present=0; fi; content=$(sha256sum -- {archive} | awk '{{print $1}}'); bytes=$(wc -c < {archive}); printf 'LR_SNAPSHOT_V1|{}|%s|%s|%s|%s\\n' \"$content\" \"$content\" \"$bytes\" \"$present\"; ",
                preset.id()
            )),
            SnapshotItemKind::File | SnapshotItemKind::Directory => {
                let source = preset.source();
                let (parent, base) = source.rsplit_once('/').unwrap_or(("/", source));
                let parent = if parent.is_empty() { "/" } else { parent };
                let content = if preset.kind() == SnapshotItemKind::File {
                    format!("content=$(sha256sum -- {} | awk '{{print $1}}');", shq(source))
                } else {
                    "content=$archive_sha;".to_owned()
                };
                command.push_str(&format!(
                    "test -e {}; tar -C {} -cpf {archive} -- {}; archive_sha=$(sha256sum -- {archive} | awk '{{print $1}}'); {content} bytes=$(wc -c < {archive}); printf 'LR_SNAPSHOT_V1|{}|%s|%s|%s|1\\n' \"$archive_sha\" \"$content\" \"$bytes\"; ",
                    shq(source),
                    shq(parent),
                    shq(base),
                    preset.id(),
                ));
            }
        }
    }
    command.push_str("trap - HUP INT TERM EXIT; printf '%s\\n' LR_SNAPSHOT_COMPLETE_V1");
    command
}

fn parse_directory_create_output(
    plan: &DirectorySnapshotPlan,
    output: &str,
) -> CoreResult<Vec<DirectorySnapshotItem>> {
    let expected = plan.presets.iter().copied().collect::<BTreeSet<_>>();
    let by_id = SnapshotPreset::ALL
        .into_iter()
        .map(|preset| (preset.id(), preset))
        .collect::<BTreeMap<_, _>>();
    let mut items = Vec::new();
    let mut seen = BTreeSet::new();
    let complete = output
        .lines()
        .any(|line| line.trim() == "LR_SNAPSHOT_COMPLETE_V1");
    for line in output.lines() {
        let Some(payload) = line.trim().strip_prefix("LR_SNAPSHOT_V1|") else {
            continue;
        };
        let fields = payload.split('|').collect::<Vec<_>>();
        if fields.len() != 5 {
            return Err(CoreError::validation(
                "directory snapshot output",
                "malformed item marker",
            ));
        }
        let preset = *by_id.get(fields[0]).ok_or_else(|| {
            CoreError::validation("directory snapshot output", "unknown preset marker")
        })?;
        if !expected.contains(&preset) || !seen.insert(preset) {
            return Err(CoreError::validation(
                "directory snapshot output",
                "unexpected or duplicate preset marker",
            ));
        }
        let archive_sha256 = fields[1].to_ascii_lowercase();
        let content_sha256 = fields[2].to_ascii_lowercase();
        if !is_sha256(&archive_sha256) || !is_sha256(&content_sha256) {
            return Err(CoreError::validation(
                "directory snapshot output",
                "invalid SHA-256 marker",
            ));
        }
        let bytes = fields[3].parse::<u64>().map_err(|_| {
            CoreError::validation("directory snapshot output", "invalid archive size")
        })?;
        let present = match fields[4] {
            "0" => false,
            "1" => true,
            _ => {
                return Err(CoreError::validation(
                    "directory snapshot output",
                    "invalid presence marker",
                ));
            }
        };
        items.push(DirectorySnapshotItem {
            preset,
            source: preset.source().to_owned(),
            kind: preset.kind(),
            archive_path: format!("{}/{}", plan.remote_root, preset.archive_name()),
            archive_sha256,
            content_sha256,
            bytes,
            present,
        });
    }
    if !complete || seen != expected {
        return Err(CoreError::validation(
            "directory snapshot output",
            "remote snapshot did not return every planned item",
        ));
    }
    items.sort_by_key(|item| item.preset);
    Ok(items)
}

fn build_directory_verify_command(snapshot: &DirectorySnapshot) -> CoreResult<String> {
    validate_directory_snapshot(snapshot.clone())?;
    let mut command = format!("set -eu; test -d {}; ", shq(&snapshot.remote_root));
    for item in &snapshot.items {
        command.push_str(&format!(
            "test \"$(sha256sum -- {} | awk '{{print $1}}')\" = {}; ",
            shq(&item.archive_path),
            shq(&item.archive_sha256)
        ));
    }
    command.push_str("printf '%s\\n' LR_SNAPSHOT_VERIFY_V1");
    Ok(command)
}

fn build_remove_root_command(snapshot_id: &str, remote_root: &str) -> CoreResult<String> {
    validate_remote_root(snapshot_id, remote_root)?;
    Ok(format!(
        "set -eu; rm -rf -- {}; test ! -e {}; printf '%s\\n' LR_SNAPSHOT_REMOVE_V1",
        shq(remote_root),
        shq(remote_root)
    ))
}

fn build_restore_execute_command(plan: &DirectoryRestorePlan) -> CoreResult<String> {
    validate_directory_snapshot(plan.snapshot.clone())?;
    validate_child_path(&plan.snapshot.remote_root, &plan.rollback_root)?;
    let rollback = shq(&plan.rollback_root);
    let archive = shq(&plan.item.archive_path);
    let source = plan.item.source.as_str();
    let mut command = format!(
        "set -eu; umask 077; test \"$(sha256sum -- {archive} | awk '{{print $1}}')\" = {}; test ! -e {rollback}; mkdir -p -- {rollback}; ",
        shq(&plan.item.archive_sha256)
    );
    match plan.item.kind {
        SnapshotItemKind::Crontab => {
            command.push_str(&format!(
                "if crontab -l > {rollback}/current 2>/dev/null; then printf present > {rollback}/state; else : > {rollback}/current; printf absent > {rollback}/state; fi; "
            ));
            if plan.item.present {
                command.push_str(&format!("crontab {archive}; "));
            } else {
                command.push_str("crontab -r 2>/dev/null || :; ");
            }
        }
        SnapshotItemKind::File | SnapshotItemKind::Directory => {
            let (parent, base) = source.rsplit_once('/').unwrap_or(("/", source));
            let parent = if parent.is_empty() { "/" } else { parent };
            command.push_str(&format!(
                "if test -e {}; then tar -C {} -cpf {rollback}/current.tar -- {}; printf present > {rollback}/state; else printf absent > {rollback}/state; fi; rm -rf -- {}; tar -C {} -xpf {archive}; ",
                shq(source),
                shq(parent),
                shq(base),
                shq(source),
                shq(parent),
            ));
        }
    }
    command.push_str("printf '%s\\n' LR_SNAPSHOT_RESTORE_V1");
    Ok(command)
}

fn build_restore_verify_command(plan: &DirectoryRestorePlan) -> CoreResult<String> {
    validate_directory_snapshot(plan.snapshot.clone())?;
    let archive_check = format!(
        "test \"$(sha256sum -- {} | awk '{{print $1}}')\" = {}; ",
        shq(&plan.item.archive_path),
        shq(&plan.item.archive_sha256)
    );
    let state_check = match plan.item.kind {
        SnapshotItemKind::Crontab if plan.item.present => format!(
            "tmp=$(mktemp); trap 'rm -f -- \"$tmp\"' EXIT; crontab -l > \"$tmp\" 2>/dev/null; test \"$(sha256sum -- \"$tmp\" | awk '{{print $1}}')\" = {}; ",
            shq(&plan.item.content_sha256)
        ),
        SnapshotItemKind::Crontab => "! crontab -l >/dev/null 2>&1; ".to_owned(),
        SnapshotItemKind::File => format!(
            "test -f {}; test \"$(sha256sum -- {} | awk '{{print $1}}')\" = {}; ",
            shq(&plan.item.source),
            shq(&plan.item.source),
            shq(&plan.item.content_sha256)
        ),
        SnapshotItemKind::Directory => format!("test -d {}; ", shq(&plan.item.source)),
    };
    Ok(format!(
        "set -eu; {archive_check}{state_check}printf '%s\\n' LR_SNAPSHOT_RESTORE_VERIFY_V1"
    ))
}

fn build_restore_rollback_command(plan: &DirectoryRestorePlan) -> CoreResult<String> {
    validate_child_path(&plan.snapshot.remote_root, &plan.rollback_root)?;
    let rollback = shq(&plan.rollback_root);
    let source = plan.item.source.as_str();
    let mut command = format!("set -eu; test -f {rollback}/state; state=$(cat {rollback}/state); ");
    match plan.item.kind {
        SnapshotItemKind::Crontab => command.push_str(&format!(
            "if test \"$state\" = present; then crontab {rollback}/current; else crontab -r 2>/dev/null || :; fi; "
        )),
        SnapshotItemKind::File | SnapshotItemKind::Directory => {
            let (parent, _) = source.rsplit_once('/').unwrap_or(("/", source));
            let parent = if parent.is_empty() { "/" } else { parent };
            command.push_str(&format!(
                "rm -rf -- {}; if test \"$state\" = present; then tar -C {} -xpf {rollback}/current.tar; fi; ",
                shq(source),
                shq(parent)
            ));
        }
    }
    command.push_str(&format!(
        "rm -rf -- {rollback}; printf '%s\\n' LR_SNAPSHOT_ROLLBACK_V1"
    ));
    Ok(command)
}

fn successful_output(subject: &'static str, output: SshCommandOutput) -> CoreResult<String> {
    if output.timed_out {
        return Err(CoreError::validation(subject, "remote command timed out"));
    }
    if output.exit_code != Some(0) {
        return Err(CoreError::validation(
            subject,
            format!("remote command exited with {:?}", output.exit_code),
        ));
    }
    Ok(output.output)
}

fn successful_marker(
    subject: &'static str,
    output: SshCommandOutput,
    marker: &str,
) -> CoreResult<()> {
    let output = successful_output(subject, output)?;
    if !output.lines().any(|line| line.trim() == marker) {
        return Err(CoreError::validation(
            subject,
            "remote success marker is missing",
        ));
    }
    Ok(())
}

fn forensic_text(result: CoreResult<SshCommandOutput>) -> CoreResult<(String, bool)> {
    match result {
        Err(error @ CoreError::TargetChanged { .. }) => Err(error),
        Err(error) => Ok((
            bounded_forensic_text(format!("(failed to collect: {error})"))?,
            true,
        )),
        Ok(output) => {
            let failed = output.timed_out || output.exit_code != Some(0);
            let text = if failed {
                format!(
                    "(collection failed: exit={:?}, timed_out={})\n{}",
                    output.exit_code, output.timed_out, output.output
                )
            } else if output.output.trim().is_empty() {
                "(empty)".to_owned()
            } else {
                output.output.trim().to_owned()
            };
            Ok((bounded_forensic_text(text)?, failed))
        }
    }
}

fn bounded_forensic_text(mut text: String) -> CoreResult<String> {
    if text.len() <= MAX_FORENSIC_FIELD_BYTES {
        return Ok(text);
    }
    const SUFFIX: &str = "\n[truncated by LovelyRes]";
    let mut boundary = MAX_FORENSIC_FIELD_BYTES - SUFFIX.len();
    while !text.is_char_boundary(boundary) {
        boundary -= 1;
    }
    text.truncate(boundary);
    text.push_str(SUFFIX);
    Ok(text)
}

fn forensic_artifact(snapshot: &ForensicSnapshot) -> CoreResult<String> {
    serde_json::to_string_pretty(&ForensicArtifact {
        schema: "lovelyres-forensic-snapshot/v1",
        id: &snapshot.id,
        timestamp: snapshot.timestamp,
        server: &snapshot.server,
        target: &snapshot.target,
        collection: &snapshot.collection,
        data: &snapshot.data,
    })
    .map_err(|source| CoreError::Encode {
        subject: "forensic snapshot artifact",
        source,
    })
}

fn forensic_digest(snapshot: &ForensicSnapshot) -> CoreResult<String> {
    Ok(hex_digest(forensic_artifact(snapshot)?.as_bytes()))
}

fn validate_forensic_snapshot(snapshot: ForensicSnapshot) -> CoreResult<ForensicSnapshot> {
    let valid_id = snapshot
        .id
        .strip_prefix("snap-")
        .and_then(|id| Uuid::parse_str(id).ok())
        .is_some();
    let target_id = snapshot.target.identity.as_str();
    let total_bytes = ForensicCollector::ALL
        .into_iter()
        .map(|collector| snapshot.data.get(collector).len())
        .sum::<usize>();
    let fields_bounded = ForensicCollector::ALL
        .into_iter()
        .all(|collector| snapshot.data.get(collector).len() <= MAX_FORENSIC_FIELD_BYTES);
    if snapshot.collection.total != ForensicCollector::ALL.len()
        || snapshot.collection.completed != ForensicCollector::ALL.len()
        || snapshot.collection.failed > snapshot.collection.total
        || !valid_id
        || target_id.is_empty()
        || target_id.len() > 256
        || target_id.chars().any(char::is_control)
        || !fields_bounded
        || total_bytes > MAX_FORENSIC_TOTAL_BYTES
        || forensic_digest(&snapshot)? != snapshot.sha256
    {
        return Err(CoreError::validation(
            "forensic snapshot",
            "stored artifact metadata or SHA-256 is invalid",
        ));
    }
    Ok(snapshot)
}

fn diff_field(
    collector: ForensicCollector,
    older: &str,
    newer: &str,
    input_lines: &mut usize,
) -> CoreResult<ForensicFieldDiff> {
    let older = line_set(older, input_lines)?;
    let newer = line_set(newer, input_lines)?;
    Ok(ForensicFieldDiff {
        collector,
        added: newer.difference(&older).cloned().collect(),
        removed: older.difference(&newer).cloned().collect(),
    })
}

fn line_set(value: &str, input_lines: &mut usize) -> CoreResult<BTreeSet<String>> {
    let mut field_lines = 0_usize;
    let mut lines = BTreeSet::new();
    for line in value.lines().map(str::trim).filter(|line| !line.is_empty()) {
        field_lines = field_lines.checked_add(1).ok_or_else(|| {
            CoreError::validation("forensic snapshot diff", "input line count overflowed")
        })?;
        *input_lines = input_lines.checked_add(1).ok_or_else(|| {
            CoreError::validation("forensic snapshot diff", "input line count overflowed")
        })?;
        if field_lines > MAX_FORENSIC_DIFF_INPUT_LINES_PER_FIELD
            || *input_lines > MAX_FORENSIC_DIFF_INPUT_LINES_TOTAL
        {
            return Err(CoreError::validation(
                "forensic snapshot diff",
                "input exceeds the bounded line budget",
            ));
        }
        lines.insert(line.to_owned());
    }
    Ok(lines)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn hex_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use super::*;
    use crate::{
        BackendServices,
        operations::JournalPhase,
        ssh::{SshConnectionStatus, TestSessionHarness},
    };

    #[derive(Debug)]
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("lovelyres-snapshot-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    async fn setup() -> (
        TestRoot,
        BackendServices,
        BoundSshSession,
        Arc<TestSessionHarness>,
    ) {
        let root = TestRoot::new();
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
        let session = BoundSshSession::from_status(guard, &status, "snapshot test").unwrap();
        let harness = Arc::new(TestSessionHarness::default());
        services
            .ssh()
            .install_test_session(status, harness.clone())
            .await
            .unwrap();
        (root, services, session, harness)
    }

    fn stored_directory_snapshot(target: TargetIdentity) -> DirectorySnapshot {
        let id = Uuid::new_v4().to_string();
        let remote_root = format!("{REMOTE_ROOT_PREFIX}/{id}");
        let mut snapshot = DirectorySnapshot {
            id,
            target,
            created_at: "2026-08-24T00:00:00Z".parse().unwrap(),
            remote_root: remote_root.clone(),
            items: vec![DirectorySnapshotItem {
                preset: SnapshotPreset::Passwd,
                source: SnapshotPreset::Passwd.source().to_owned(),
                kind: SnapshotPreset::Passwd.kind(),
                archive_path: format!("{remote_root}/{}", SnapshotPreset::Passwd.archive_name()),
                archive_sha256: "a".repeat(64),
                content_sha256: "b".repeat(64),
                bytes: 42,
                present: true,
            }],
            record_sha256: String::new(),
        };
        snapshot.record_sha256 = directory_digest(&snapshot).unwrap();
        snapshot
    }

    fn stored_forensic_snapshot(
        target: &TargetGuard,
        timestamp: &str,
        data: ForensicData,
    ) -> ForensicSnapshot {
        let mut snapshot = ForensicSnapshot {
            id: format!("snap-{}", Uuid::new_v4()),
            timestamp: timestamp.parse().unwrap(),
            server: "host-a.test".to_owned(),
            target: ForensicTarget {
                identity: target.identity.clone(),
                session_id: "session-a".to_owned(),
                host: "host-a.test".to_owned(),
                port: 22,
                username: "operator".to_owned(),
                host_key_fingerprint: "SHA256:test".to_owned(),
            },
            collection: ForensicCollectionSummary {
                total: ForensicCollector::ALL.len(),
                completed: ForensicCollector::ALL.len(),
                failed: 0,
            },
            data,
            sha256: String::new(),
        };
        snapshot.sha256 = forensic_digest(&snapshot).unwrap();
        snapshot
    }

    #[test]
    fn presets_are_fixed_and_remote_namespace_rejects_lookalikes() {
        assert_eq!(SnapshotPreset::ALL.len(), 8);
        let id = Uuid::new_v4().to_string();
        assert!(validate_remote_root(&id, &format!("{REMOTE_ROOT_PREFIX}/{id}")).is_ok());
        assert!(validate_remote_root(&id, &format!("/tmp/.lovelyres_snap_evil/{id}")).is_err());
        assert!(validate_remote_root(&id, &format!("{REMOTE_ROOT_PREFIX}/{id}/../x")).is_err());
        assert!(normalize_presets([]).is_err());
    }

    #[tokio::test]
    async fn directory_snapshot_is_target_bound_hashed_journaled_and_verified() {
        let (_root, services, session, harness) = setup().await;
        let plan = services
            .snapshots()
            .plan_directory_snapshot(&session, [SnapshotPreset::Passwd])
            .unwrap();
        let marker = format!(
            "LR_SNAPSHOT_V1|passwd|{}|{}|42|1\nLR_SNAPSHOT_COMPLETE_V1\nLR_SNAPSHOT_VERIFY_V1",
            "a".repeat(64),
            "b".repeat(64)
        );
        harness.set_execute_output(marker);
        let snapshot = services
            .snapshots()
            .execute_directory_snapshot(&session, plan)
            .await
            .unwrap();
        assert_eq!(snapshot.items.len(), 1);
        assert!(is_sha256(&snapshot.record_sha256));
        assert_eq!(
            services
                .snapshots()
                .list_directory(session.target())
                .unwrap(),
            vec![snapshot]
        );
        let entries = services.operation_journal().entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].phase, JournalPhase::Executed);
        assert_eq!(entries[1].phase, JournalPhase::VerificationPassed);

        let replacement = services
            .activate_target(TargetIdentity::new("connection-b").unwrap())
            .unwrap();
        assert!(
            services
                .snapshots()
                .list_directory(session.target())
                .is_err()
        );
        assert!(
            services
                .snapshots()
                .list_directory(&replacement)
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn directory_snapshot_allows_same_stable_target_after_reconnect() {
        let (_root, services, session, harness) = setup().await;
        let plan = services
            .snapshots()
            .plan_directory_snapshot(&session, [SnapshotPreset::Passwd])
            .unwrap();
        harness.set_execute_output(format!(
            "LR_SNAPSHOT_V1|passwd|{}|{}|42|1\nLR_SNAPSHOT_COMPLETE_V1\nLR_SNAPSHOT_VERIFY_V1",
            "a".repeat(64),
            "b".repeat(64)
        ));
        let snapshot = services
            .snapshots()
            .execute_directory_snapshot(&session, plan)
            .await
            .unwrap();
        let reconnected = services
            .activate_target(TargetIdentity::new("connection-a").unwrap())
            .unwrap();
        assert!(
            services
                .snapshots()
                .list_directory(session.target())
                .is_err()
        );
        assert_eq!(
            services.snapshots().list_directory(&reconnected).unwrap(),
            vec![snapshot]
        );
    }

    #[tokio::test]
    async fn restore_requires_the_exact_plan_then_journals_and_cleans_rollback() {
        let (_root, services, session, harness) = setup().await;
        let create = services
            .snapshots()
            .plan_directory_snapshot(&session, [SnapshotPreset::Passwd])
            .unwrap();
        harness.set_execute_output(format!(
            "LR_SNAPSHOT_V1|passwd|{}|{}|42|1\nLR_SNAPSHOT_COMPLETE_V1\nLR_SNAPSHOT_VERIFY_V1",
            "a".repeat(64),
            "b".repeat(64)
        ));
        let snapshot = services
            .snapshots()
            .execute_directory_snapshot(&session, create)
            .await
            .unwrap();

        let wrong = services
            .snapshots()
            .plan_restore_item(&session, &snapshot.id, SnapshotPreset::Passwd)
            .unwrap();
        let exact = services
            .snapshots()
            .plan_restore_item(&session, &snapshot.id, SnapshotPreset::Passwd)
            .unwrap();
        let before = services.operation_journal().entries().unwrap().len();
        assert!(
            services
                .snapshots()
                .execute_restore_item(
                    &session,
                    exact,
                    DangerousConfirmation::approve(wrong.definition()),
                )
                .await
                .is_err()
        );
        assert_eq!(
            services.operation_journal().entries().unwrap().len(),
            before
        );

        let exact = services
            .snapshots()
            .plan_restore_item(&session, &snapshot.id, SnapshotPreset::Passwd)
            .unwrap();
        let confirmation = DangerousConfirmation::approve(exact.definition());
        harness.set_execute_output(
            "LR_SNAPSHOT_RESTORE_V1\nLR_SNAPSHOT_RESTORE_VERIFY_V1\nLR_SNAPSHOT_ROLLBACK_CLEAN_V1",
        );
        let outcome = services
            .snapshots()
            .execute_restore_item(&session, exact, confirmation)
            .await
            .unwrap();
        assert!(outcome.verified);
        assert!(!outcome.restored_after_failed_verification);
        let entries = services.operation_journal().entries().unwrap();
        assert_eq!(entries[before].phase, JournalPhase::Executed);
        assert_eq!(entries[before + 1].phase, JournalPhase::VerificationPassed);
    }

    #[tokio::test]
    async fn delete_requires_exact_confirmation_and_verifies_both_locations() {
        let (_root, services, session, harness) = setup().await;
        let create = services
            .snapshots()
            .plan_directory_snapshot(&session, [SnapshotPreset::Passwd])
            .unwrap();
        harness.set_execute_output(format!(
            "LR_SNAPSHOT_V1|passwd|{}|{}|42|1\nLR_SNAPSHOT_COMPLETE_V1\nLR_SNAPSHOT_VERIFY_V1",
            "a".repeat(64),
            "b".repeat(64)
        ));
        let snapshot = services
            .snapshots()
            .execute_directory_snapshot(&session, create)
            .await
            .unwrap();
        let wrong = services
            .snapshots()
            .plan_delete_directory(&session, &snapshot.id)
            .unwrap();
        let exact = services
            .snapshots()
            .plan_delete_directory(&session, &snapshot.id)
            .unwrap();
        let before = services.operation_journal().entries().unwrap().len();
        assert!(
            services
                .snapshots()
                .execute_delete_directory(
                    &session,
                    exact,
                    DangerousConfirmation::approve(wrong.definition()),
                )
                .await
                .is_err()
        );
        assert_eq!(
            services.operation_journal().entries().unwrap().len(),
            before
        );
        let exact = services
            .snapshots()
            .plan_delete_directory(&session, &snapshot.id)
            .unwrap();
        let confirmation = DangerousConfirmation::approve(exact.definition());
        harness.set_execute_output("LR_SNAPSHOT_REMOVE_V1\nLR_SNAPSHOT_DELETE_VERIFY_V1");
        let outcome = services
            .snapshots()
            .execute_delete_directory(&session, exact, confirmation)
            .await
            .unwrap();
        assert!(outcome.verified);
        assert!(
            services
                .snapshots()
                .list_directory(session.target())
                .unwrap()
                .is_empty()
        );
        let entries = services.operation_journal().entries().unwrap();
        assert_eq!(entries[before].phase, JournalPhase::Executed);
        assert_eq!(entries[before + 1].phase, JournalPhase::VerificationPassed);
    }

    #[tokio::test]
    async fn forensic_capture_hashes_exact_export_without_case_side_effect() {
        let (_root, services, session, harness) = setup().await;
        harness.set_execute_output("one\ntwo\n");
        let snapshot = services
            .snapshots()
            .capture_forensic(&session, ForensicCancellation::default(), None)
            .await
            .unwrap();
        assert_eq!(snapshot.collection.completed, 12);
        assert_eq!(snapshot.collection.failed, 0);
        let artifact = services
            .snapshots()
            .export_forensic(session.target(), &snapshot.id)
            .unwrap();
        assert_eq!(hex_digest(artifact.as_bytes()), snapshot.sha256);
        assert!(
            services
                .investigation()
                .cases()
                .list_for_target(&session.target().identity)
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn forensic_target_switch_discards_the_entire_capture() {
        let (_root, services, session, _harness) = setup().await;
        let (events, receiver) = forensic_event_channel(32).unwrap();
        let worker_services = services.clone();
        let worker_session = session.clone();
        let task = tokio::spawn(async move {
            worker_services
                .snapshots()
                .capture_forensic(
                    &worker_session,
                    ForensicCancellation::default(),
                    Some(events),
                )
                .await
        });
        let mut started = 0;
        while started < FORENSIC_CONCURRENCY {
            match receiver.recv().await.unwrap() {
                ForensicCaptureEvent::CollectorStarted { .. } => started += 1,
                ForensicCaptureEvent::Started { .. } => {}
                other => panic!("unexpected event before target switch: {other:?}"),
            }
        }
        services
            .activate_target(TargetIdentity::new("connection-b").unwrap())
            .unwrap();
        services
            .ssh()
            .disconnect(session.session_id())
            .await
            .unwrap();
        assert!(matches!(
            task.await.unwrap(),
            Err(CoreError::TargetChanged { .. })
        ));
        assert!(
            services
                .snapshots()
                .list_forensic(&services.target().current_guard().unwrap())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn forensic_diff_uses_trimmed_nonempty_line_sets() {
        let mut input_lines = 0;
        let diff = diff_field(
            ForensicCollector::Processes,
            " a\n b\n",
            " b \n c\n",
            &mut input_lines,
        )
        .unwrap();
        assert_eq!(diff.added, vec!["c"]);
        assert_eq!(diff.removed, vec!["a"]);
        assert_eq!(input_lines, 4);
    }

    #[test]
    fn snapshot_document_encoded_size_is_rejected_before_deserialization() {
        let root = TestRoot::new();
        let store = PortableStore::prepare(root.0.clone()).unwrap();
        let services = BackendServices::new(store.clone()).unwrap();
        let document_path = store.path_for(StoreFile::Snapshots);
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(document_path)
            .unwrap();
        file.set_len((MAX_SNAPSHOT_DOCUMENT_BYTES + 1) as u64)
            .unwrap();
        let error = services.snapshots().load_document().unwrap_err();
        assert!(matches!(error, CoreError::Validation { .. }));
    }

    #[test]
    fn snapshot_document_rejects_more_than_the_bounded_index_counts() {
        let root = TestRoot::new();
        let store = PortableStore::prepare(root.0.clone()).unwrap();
        let services = BackendServices::new(store.clone()).unwrap();
        let target = TargetIdentity::new("connection-a").unwrap();
        let directory = stored_directory_snapshot(target.clone());
        let forensic_target = TargetGuard {
            identity: target,
            generation: 1,
        };
        let forensic = stored_forensic_snapshot(
            &forensic_target,
            "2026-08-24T00:00:00Z",
            ForensicData::default(),
        );

        store
            .write(
                StoreFile::Snapshots,
                &SnapshotDocument {
                    version: SNAPSHOT_DOCUMENT_VERSION,
                    directory_snapshots: vec![directory.clone(); DIRECTORY_SNAPSHOT_LIMIT + 1],
                    forensic_snapshots: Vec::new(),
                },
            )
            .unwrap();
        assert!(matches!(
            services.snapshots().load_document(),
            Err(CoreError::Decode { .. })
        ));

        store
            .write(
                StoreFile::Snapshots,
                &SnapshotDocument {
                    version: SNAPSHOT_DOCUMENT_VERSION,
                    directory_snapshots: Vec::new(),
                    forensic_snapshots: vec![forensic.clone(); FORENSIC_SNAPSHOT_LIMIT + 1],
                },
            )
            .unwrap();
        assert!(matches!(
            services.snapshots().load_document(),
            Err(CoreError::Decode { .. })
        ));

        store
            .write(
                StoreFile::Snapshots,
                &SnapshotDocument {
                    version: SNAPSHOT_DOCUMENT_VERSION,
                    directory_snapshots: vec![directory; DIRECTORY_SNAPSHOT_LIMIT],
                    forensic_snapshots: vec![forensic; FORENSIC_SNAPSHOT_LIMIT],
                },
            )
            .unwrap();
        let maximum = services.snapshots().load_document().unwrap();
        assert_eq!(maximum.directory_snapshots.len(), DIRECTORY_SNAPSHOT_LIMIT);
        assert_eq!(maximum.forensic_snapshots.len(), FORENSIC_SNAPSHOT_LIMIT);
    }

    #[tokio::test]
    async fn forensic_diff_rejects_per_field_and_aggregate_input_line_overflow() {
        let (_root, services, session, _harness) = setup().await;
        let older = stored_forensic_snapshot(
            session.target(),
            "2026-08-23T00:00:00Z",
            ForensicData::default(),
        );
        let per_field_data = ForensicData {
            processes: (0..=MAX_FORENSIC_DIFF_INPUT_LINES_PER_FIELD)
                .map(|index| format!("process-{index}"))
                .collect::<Vec<_>>()
                .join("\n"),
            ..ForensicData::default()
        };
        let per_field =
            stored_forensic_snapshot(session.target(), "2026-08-24T00:00:00Z", per_field_data);
        services
            .snapshots()
            .store
            .write(
                StoreFile::Snapshots,
                &SnapshotDocument {
                    version: SNAPSHOT_DOCUMENT_VERSION,
                    directory_snapshots: Vec::new(),
                    forensic_snapshots: vec![older.clone(), per_field.clone()],
                },
            )
            .unwrap();
        assert!(matches!(
            services
                .snapshots()
                .diff_forensic(session.target(), &older.id, &per_field.id),
            Err(CoreError::Validation { .. })
        ));

        let mut aggregate_data = ForensicData::default();
        for collector in ForensicCollector::ALL {
            aggregate_data.set(
                collector,
                (0..700)
                    .map(|index| format!("{}-{index}", collector.id()))
                    .collect::<Vec<_>>()
                    .join("\n"),
            );
        }
        let aggregate =
            stored_forensic_snapshot(session.target(), "2026-08-25T00:00:00Z", aggregate_data);
        services
            .snapshots()
            .store
            .write(
                StoreFile::Snapshots,
                &SnapshotDocument {
                    version: SNAPSHOT_DOCUMENT_VERSION,
                    directory_snapshots: Vec::new(),
                    forensic_snapshots: vec![older.clone(), aggregate.clone()],
                },
            )
            .unwrap();
        assert!(matches!(
            services
                .snapshots()
                .diff_forensic(session.target(), &older.id, &aggregate.id),
            Err(CoreError::Validation { .. })
        ));
    }

    #[test]
    fn malformed_directory_marker_and_tampered_artifact_are_rejected() {
        let id = Uuid::new_v4().to_string();
        let plan = DirectorySnapshotPlan {
            operation: OperationPlan::new(
                TargetGuard {
                    identity: TargetIdentity::new("target").unwrap(),
                    generation: 1,
                },
                "test",
                false,
                None,
            )
            .unwrap(),
            remote_root: format!("{REMOTE_ROOT_PREFIX}/{id}"),
            snapshot_id: id,
            presets: vec![SnapshotPreset::Passwd],
        };
        assert!(parse_directory_create_output(&plan, "LR_SNAPSHOT_COMPLETE_V1").is_err());
        assert!(
            parse_directory_create_output(
                &plan,
                "LR_SNAPSHOT_V1|passwd|bad|bad|1|1\nLR_SNAPSHOT_COMPLETE_V1"
            )
            .is_err()
        );

        let bounded = bounded_forensic_text("取证".repeat(MAX_FORENSIC_FIELD_BYTES)).unwrap();
        assert!(bounded.len() <= MAX_FORENSIC_FIELD_BYTES);
        assert!(bounded.ends_with("[truncated by LovelyRes]"));
    }
}
