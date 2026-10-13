//! Target-bound Kubernetes inventory and closed, reversible mutations.
//!
//! The service deliberately exposes no generic `kubectl` execution surface.
//! Every dynamic argument is validated as a Kubernetes DNS-1123 name and then
//! shell-quoted. Deployment scaling and node scheduling changes bind the
//! resource UID, resourceVersion, observed state, target epoch, confirmation,
//! journal, verification, and automatic restore into one immutable plan.

use std::{collections::BTreeMap, future::Future, sync::Arc, time::Duration};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    CoreError, CoreResult,
    docker::{
        ContainerFilePath, ContainerFileState, ContainerShell, SHELL_PROBE_SCRIPT,
        container_file_probe_script, parse_container_file_state, parse_shell_probe, sha256_hex,
    },
    events::{TerminalEvent, TerminalEventReceiver, TerminalTransport},
    exec_directory::{ExecDirectoryListing, listing_command, parse_listing},
    operations::{
        DangerousConfirmation, ExecutionReceipt, OperationExecutor, OperationPlan, OperationState,
        PlannedOperation, PortableOperationJournal, VerificationResult,
    },
    sftp::RemotePath,
    shell_escape::shq,
    ssh::{BoundSshSession, PodPtyRequest, SshCommandOutput, SshService, SshTerminalSession},
    target::{TargetContext, TargetGuard},
};

const MAX_ROWS: usize = 1_000;
const MAX_JSON_BYTES: usize = 2_000_000;
const MAX_DETAIL_CHARS: usize = 500_000;
const MAX_LOG_CHARS: usize = 500_000;
const MAX_CELL_CHARS: usize = 4_096;
const MAX_CONTEXT_CHARS: usize = 512;
const MAX_RESOURCE_IDENTITY_BYTES: usize = 512;
const MAX_DEPLOYMENT_REPLICAS: u64 = 10_000;
const DEPLOYMENT_HEALTH_DEADLINE: Duration = Duration::from_secs(45);
const DEPLOYMENT_HEALTH_POLL: Duration = Duration::from_secs(1);
/// Where a pod file waits on the SSH host on its way to a local evidence
/// folder. Only paths of exactly this shape are ever written or removed.
const POD_FILE_STAGE_PREFIX: &str = "/tmp/lovelyhawk-podfile-";
const POD_FILE_STAGE_MARKER: &str = "LOVELYHAWK_PODFILE_V1";
const POD_FILE_STAGE_FAILED: &str = "LOVELYHAWK_PODFILE_FAILED_V1";
/// Exported to the copy's kubectl so a cancel can find and end it.
const POD_FILE_STAGE_ENV: &str = "LOVELYHAWK_PODFILE_STAGE";
/// How long digesting a viewed pod file (at most 1 MiB) may take.
const PROBE_TIMEOUT: Duration = Duration::from_secs(20);
/// How long digesting a pod file kept as evidence (up to 512 MiB) may take.
const EVIDENCE_PROBE_TIMEOUT: Duration = Duration::from_secs(300);

pub const POD_FILE_EVIDENCE_LIMITATIONS: &str = "用 kubectl exec 在所选容器里 cat 文件的原始字节，写入 SSH 主机上的临时文件；复制前后在容器里各算一次长度与 SHA-256，主机副本、两次 SFTP 读取和本地回读都与之一致。这不是原子快照：两次核对之间的变化无法排除，读取可能改变文件的访问时间。记录的是这个容器在这一刻看到的文件，不区分它来自镜像层还是卷，也不代表其他副本里的同名文件。需要 pods/exec 权限，容器里需要 sh、cat 与 sha256sum。";

const AVAILABILITY_COMMAND: &str = r#"if command -v kubectl >/dev/null 2>&1; then
  printf 'installed\ttrue\n'
  context=$(kubectl config current-context 2>/dev/null | tr -d '\r\n\t' | head -c 512 || true)
  printf 'context\t%s\n' "$context"
  namespace=$(kubectl config view --minify -o 'jsonpath={..namespace}' 2>/dev/null | tr -d '\r\n\t' | head -c 128 || true)
  printf 'namespace\t%s\n' "$namespace"
  if kubectl version --request-timeout=5s >/dev/null 2>&1; then
    printf 'api_reachable\ttrue\n'
  else
    printf 'api_reachable\tfalse\n'
  fi
else
  printf 'installed\tfalse\ncontext\t\napi_reachable\tfalse\n'
fi"#;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KubernetesAvailability {
    pub kubectl_installed: bool,
    pub api_reachable: bool,
    pub current_context: String,
    /// The namespace kubectl uses when none is named: the current context's,
    /// or `default` when the context names none. `None` without a context or
    /// when the kubeconfig names something that is not a namespace.
    ///
    /// An account bound to one namespace cannot list namespaces at all, and
    /// this is the one it was given.
    #[serde(default)]
    pub context_namespace: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KubernetesCollection<T> {
    pub items: Vec<T>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KubernetesRowId(String);

impl KubernetesRowId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KubernetesScope {
    AllNamespaces,
    Namespace(String),
    /// Whatever namespace the kubeconfig's current context names, as kubectl
    /// reads it at the time: no `-n` and no `--all-namespaces`. Each row still
    /// carries the namespace the cluster put it in.
    ContextNamespace,
}

impl KubernetesScope {
    pub fn namespace(value: impl Into<String>) -> CoreResult<Self> {
        let value = value.into();
        validate_dns_label("Kubernetes namespace", &value)?;
        Ok(Self::Namespace(value))
    }

    pub fn namespace_name(&self) -> Option<&str> {
        match self {
            Self::AllNamespaces | Self::ContextNamespace => None,
            Self::Namespace(value) => Some(value),
        }
    }

    fn arguments(&self) -> String {
        match self {
            Self::AllNamespaces => "--all-namespaces".to_owned(),
            Self::Namespace(value) => format!("-n {}", shq(value)),
            Self::ContextNamespace => String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KubernetesNamespace {
    pub id: KubernetesRowId,
    pub name: String,
    pub phase: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KubernetesPod {
    pub id: KubernetesRowId,
    pub namespace: String,
    pub name: String,
    pub phase: String,
    pub ready_containers: usize,
    pub total_containers: usize,
    pub restarts: u64,
    pub node: String,
    pub pod_ip: String,
    pub images: Vec<String>,
    pub created_at: String,
    /// The pod's app containers in spec order (init and ephemeral containers
    /// are not places to run a shell or read files).
    pub containers: Vec<KubernetesPodContainer>,
    /// The container kubectl picks when none is named: the one the
    /// `kubectl.kubernetes.io/default-container` annotation names, when that
    /// is one of the pod's containers, else the first.
    pub default_container: Option<String>,
}

/// One app container of a pod, as the list shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KubernetesPodContainer {
    pub name: String,
    pub image: String,
    pub ready: bool,
    pub running: bool,
    pub restarts: u64,
}

impl KubernetesPod {
    /// The named container, when it is one of this pod's app containers.
    pub fn container(&self, name: &str) -> Option<&KubernetesPodContainer> {
        self.containers
            .iter()
            .find(|container| container.name == name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KubernetesDeployment {
    pub id: KubernetesRowId,
    pub namespace: String,
    pub name: String,
    pub desired_replicas: u64,
    pub ready_replicas: u64,
    pub available_replicas: u64,
    pub updated_replicas: u64,
    pub images: Vec<String>,
    pub created_at: String,
}

/// Largest manifest kept; a Node with every image it has pulled is the
/// biggest of the three and stays well under it.
pub const MAX_MANIFEST_BYTES: usize = 1_000_000;
const MANIFEST_MARKER: &str = "LOVELYHAWK_KUBERNETES_MANIFEST_V1";

/// A listed object whose manifest may be read: the row as the list produced
/// it, never a name typed in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KubernetesManifestObject {
    Pod(KubernetesPod),
    Deployment(KubernetesDeployment),
    Node(KubernetesNode),
}

impl KubernetesManifestObject {
    /// Kind, namespace, name and UID as the list recorded them; the UID is
    /// the row id after its fixed prefix.
    fn identity(&self) -> (&'static str, Option<&str>, &str, &str) {
        match self {
            Self::Pod(pod) => (
                "Pod",
                Some(pod.namespace.as_str()),
                pod.name.as_str(),
                pod.id.as_str().strip_prefix("pod:").unwrap_or_default(),
            ),
            Self::Deployment(deployment) => (
                "Deployment",
                Some(deployment.namespace.as_str()),
                deployment.name.as_str(),
                deployment
                    .id
                    .as_str()
                    .strip_prefix("deployment:")
                    .unwrap_or_default(),
            ),
            Self::Node(node) => (
                "Node",
                None,
                node.name.as_str(),
                node.id.as_str().strip_prefix("node:").unwrap_or_default(),
            ),
        }
    }
}

/// One object's manifest, as read, with what is needed to say where it came
/// from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubernetesManifest {
    /// `Pod`, `Deployment` or `Node`.
    pub kind: &'static str,
    pub namespace: Option<String>,
    pub name: String,
    pub uid: String,
    pub resource_version: String,
    /// The kubeconfig context kubectl used; empty when it could not be read.
    pub context: String,
    pub read_at: chrono::DateTime<chrono::Utc>,
    /// Exactly what `kubectl get … -o yaml` printed.
    pub yaml: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KubernetesNode {
    pub id: KubernetesRowId,
    pub name: String,
    pub ready: bool,
    pub unschedulable: bool,
    pub roles: Vec<String>,
    pub kubelet_version: String,
    pub internal_ip: String,
    pub cpu_capacity: String,
    pub memory_capacity: String,
    pub pod_capacity: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KubernetesResourceKind {
    Namespace,
    Pod,
    Deployment,
    Node,
}

impl KubernetesResourceKind {
    const fn command_name(self) -> &'static str {
        match self {
            Self::Namespace => "namespace",
            Self::Pod => "pod",
            Self::Deployment => "deployment",
            Self::Node => "node",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Namespace => "Namespace",
            Self::Pod => "Pod",
            Self::Deployment => "Deployment",
            Self::Node => "Node",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KubernetesDetailRequest {
    pub kind: KubernetesResourceKind,
    name: String,
    namespace: Option<String>,
}

impl KubernetesDetailRequest {
    pub fn namespaced(
        kind: KubernetesResourceKind,
        namespace: impl Into<String>,
        name: impl Into<String>,
    ) -> CoreResult<Self> {
        if !matches!(
            kind,
            KubernetesResourceKind::Pod | KubernetesResourceKind::Deployment
        ) {
            return Err(validation(
                "Kubernetes detail request",
                "only pods and deployments are namespace scoped",
            ));
        }
        let namespace = namespace.into();
        let name = name.into();
        validate_dns_label("Kubernetes namespace", &namespace)?;
        validate_dns_subdomain("Kubernetes resource name", &name)?;
        Ok(Self {
            kind,
            name,
            namespace: Some(namespace),
        })
    }

    pub fn cluster_scoped(
        kind: KubernetesResourceKind,
        name: impl Into<String>,
    ) -> CoreResult<Self> {
        if !matches!(
            kind,
            KubernetesResourceKind::Namespace | KubernetesResourceKind::Node
        ) {
            return Err(validation(
                "Kubernetes detail request",
                "pods and deployments require an explicit namespace",
            ));
        }
        let name = name.into();
        if kind == KubernetesResourceKind::Namespace {
            validate_dns_label("Kubernetes namespace", &name)?;
        } else {
            validate_dns_subdomain("Kubernetes node name", &name)?;
        }
        Ok(Self {
            kind,
            name,
            namespace: None,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    fn command(&self) -> String {
        let namespace = self
            .namespace
            .as_ref()
            .map(|value| format!(" -n {}", shq(value)))
            .unwrap_or_default();
        format!(
            "kubectl describe {} {}{}",
            self.kind.command_name(),
            shq(&self.name),
            namespace
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KubernetesPodLogsRequest {
    namespace: String,
    pod: String,
    container: Option<String>,
    tail_lines: u32,
    since_seconds: Option<u32>,
    previous: bool,
}

impl KubernetesPodLogsRequest {
    pub fn recent(namespace: impl Into<String>, pod: impl Into<String>) -> CoreResult<Self> {
        let namespace = namespace.into();
        let pod = pod.into();
        validate_dns_label("Kubernetes namespace", &namespace)?;
        validate_dns_subdomain("Kubernetes pod name", &pod)?;
        Ok(Self {
            namespace,
            pod,
            container: None,
            tail_lines: 200,
            since_seconds: None,
            previous: false,
        })
    }

    pub fn with_container(mut self, container: impl Into<String>) -> CoreResult<Self> {
        let container = container.into();
        validate_dns_label("Kubernetes container name", &container)?;
        self.container = Some(container);
        Ok(self)
    }

    pub fn with_tail_lines(mut self, tail_lines: u32) -> CoreResult<Self> {
        if !(1..=10_000).contains(&tail_lines) {
            return Err(validation(
                "Kubernetes log line limit",
                "must be between 1 and 10000",
            ));
        }
        self.tail_lines = tail_lines;
        Ok(self)
    }

    pub fn with_since_seconds(mut self, since_seconds: u32) -> CoreResult<Self> {
        if !(1..=604_800).contains(&since_seconds) {
            return Err(validation(
                "Kubernetes log time range",
                "must be between 1 and 604800 seconds",
            ));
        }
        self.since_seconds = Some(since_seconds);
        Ok(self)
    }

    pub fn with_previous(mut self, previous: bool) -> Self {
        self.previous = previous;
        self
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub fn pod(&self) -> &str {
        &self.pod
    }

    fn command(&self) -> String {
        let mut command = format!(
            "kubectl logs {} -n {} --tail={} --limit-bytes={MAX_LOG_CHARS}",
            shq(&self.pod),
            shq(&self.namespace),
            self.tail_lines
        );
        if let Some(container) = &self.container {
            command.push_str(&format!(" -c {}", shq(container)));
        }
        if let Some(since_seconds) = self.since_seconds {
            command.push_str(&format!(" --since={since_seconds}s"));
        }
        if self.previous {
            command.push_str(" --previous");
        }
        command
    }
}

/// One container of one pod, as a place to run a fixed catalogue check.
///
/// Names are validated the same way the log request validates them, so a
/// namespace or pod name that is not a DNS label cannot be built into a
/// command at all. There is no constructor taking a command: the caller
/// chooses a container, never what runs in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubernetesExecTarget {
    namespace: String,
    pod: String,
    /// Absent means the pod's default container, which is what `kubectl exec`
    /// picks when a pod has exactly one.
    container: Option<String>,
}

impl KubernetesExecTarget {
    pub fn new(namespace: impl Into<String>, pod: impl Into<String>) -> CoreResult<Self> {
        let namespace = namespace.into();
        let pod = pod.into();
        validate_dns_label("Kubernetes namespace", &namespace)?;
        validate_dns_subdomain("Kubernetes pod name", &pod)?;
        Ok(Self {
            namespace,
            pod,
            container: None,
        })
    }

    pub fn with_container(mut self, container: impl Into<String>) -> CoreResult<Self> {
        let container = container.into();
        validate_dns_label("Kubernetes container name", &container)?;
        self.container = Some(container);
        Ok(self)
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub fn pod(&self) -> &str {
        &self.pod
    }

    pub fn container(&self) -> Option<&str> {
        self.container.as_deref()
    }

    /// Wraps a command so it runs inside this pod's container.
    ///
    /// `sh -c` and no TTY: this is one non-interactive command, and the
    /// catalogue's commands are POSIX sh already. `--` keeps a command that
    /// begins with a dash from being read as more kubectl flags.
    pub fn exec_command(&self, command: &str) -> String {
        let mut built = format!(
            "kubectl exec {} -n {}",
            shq(&self.pod),
            shq(&self.namespace)
        );
        if let Some(container) = &self.container {
            built.push_str(&format!(" -c {}", shq(container)));
        }
        built.push_str(&format!(" -- sh -c {}", shq(command)));
        built
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KubernetesText {
    pub text: String,
    pub truncated: bool,
}

impl KubernetesText {
    /// Whether the whole body is the kubelet's own refusal rather than
    /// anything the container printed.
    ///
    /// When the container a pod's status still points at has already been
    /// collected — routine in a crash loop, between a restart and the status
    /// catching up — `kubectl logs` exits 0 and prints this one sentence as if
    /// it were the log. Shown as log text it reads as the pod's own output.
    /// Only the exact sentence counts: a log that merely contains it is a log.
    pub fn is_kubelet_log_refusal(&self) -> bool {
        let Some(reference) = self
            .text
            .trim_end_matches('\n')
            .strip_prefix("unable to retrieve container logs for ")
        else {
            return false;
        };
        let Some((runtime, id)) = reference.split_once("://") else {
            return false;
        };
        !runtime.is_empty()
            && runtime
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && (12..=128).contains(&id.len())
            && id.bytes().all(|byte| byte.is_ascii_hexdigit())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KubernetesMutationRequest {
    ScaleDeployment {
        deployment: KubernetesDeployment,
        replicas: u64,
    },
    SetNodeUnschedulable {
        node: KubernetesNode,
        unschedulable: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum KubernetesMutationSnapshot {
    Deployment {
        uid: String,
        resource_version: String,
        generation: Option<u64>,
        replicas: u64,
    },
    Node {
        uid: String,
        resource_version: String,
        unschedulable: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum KubernetesMutationKind {
    ScaleDeployment {
        namespace: String,
        name: String,
        replicas: u64,
    },
    SetNodeUnschedulable {
        name: String,
        unschedulable: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubernetesMutationPlan {
    operation: OperationPlan,
    row_id: KubernetesRowId,
    before: KubernetesMutationSnapshot,
    kind: KubernetesMutationKind,
}

impl KubernetesMutationPlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn row_id(&self) -> &KubernetesRowId {
        &self.row_id
    }

    pub fn label(&self) -> &'static str {
        match self.kind {
            KubernetesMutationKind::ScaleDeployment { .. } => "Deployment 扩缩容",
            KubernetesMutationKind::SetNodeUnschedulable {
                unschedulable: true,
                ..
            } => "Node 停止调度",
            KubernetesMutationKind::SetNodeUnschedulable {
                unschedulable: false,
                ..
            } => "Node 恢复调度",
        }
    }

    pub fn state_change(&self) -> String {
        match &self.kind {
            KubernetesMutationKind::ScaleDeployment { replicas, .. } => format!(
                "副本 {} → {replicas}",
                self.before.replicas().unwrap_or_default()
            ),
            KubernetesMutationKind::SetNodeUnschedulable { unschedulable, .. } => format!(
                "调度状态 {} → {}",
                scheduling_label(self.before.unschedulable().unwrap_or_default()),
                scheduling_label(*unschedulable)
            ),
        }
    }

    fn before(&self) -> &KubernetesMutationSnapshot {
        &self.before
    }

    fn target_matches(&self, snapshot: &KubernetesMutationSnapshot) -> bool {
        match (&self.kind, snapshot) {
            (
                KubernetesMutationKind::ScaleDeployment { replicas, .. },
                KubernetesMutationSnapshot::Deployment {
                    uid,
                    replicas: observed,
                    ..
                },
            ) => self.before.uid() == uid && replicas == observed,
            (
                KubernetesMutationKind::SetNodeUnschedulable { unschedulable, .. },
                KubernetesMutationSnapshot::Node {
                    uid,
                    unschedulable: observed,
                    ..
                },
            ) => self.before.uid() == uid && unschedulable == observed,
            _ => false,
        }
    }
}

impl KubernetesMutationSnapshot {
    fn generation(&self) -> Option<u64> {
        match self {
            Self::Deployment { generation, .. } => *generation,
            Self::Node { .. } => None,
        }
    }

    fn uid(&self) -> &str {
        match self {
            Self::Deployment { uid, .. } | Self::Node { uid, .. } => uid,
        }
    }

    fn resource_version(&self) -> &str {
        match self {
            Self::Deployment {
                resource_version, ..
            }
            | Self::Node {
                resource_version, ..
            } => resource_version,
        }
    }

    fn replicas(&self) -> Option<u64> {
        match self {
            Self::Deployment { replicas, .. } => Some(*replicas),
            Self::Node { .. } => None,
        }
    }

    fn unschedulable(&self) -> Option<bool> {
        match self {
            Self::Deployment { .. } => None,
            Self::Node { unschedulable, .. } => Some(*unschedulable),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubernetesMutationOutcome {
    pub verified: bool,
    pub verification_detail: String,
    pub restored_after_failed_verification: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct KubernetesMutationReceipt {
    schema: String,
    uid: String,
    resource_version: String,
    #[serde(default)]
    generation: Option<u64>,
}

#[async_trait]
trait KubernetesCommandRunner: Send + Sync + std::fmt::Debug {
    async fn run(
        &self,
        session: &BoundSshSession,
        command: String,
        timeout: Duration,
    ) -> CoreResult<SshCommandOutput>;
}

#[derive(Debug)]
struct SshKubernetesCommandRunner {
    ssh: SshService,
}

#[async_trait]
impl KubernetesCommandRunner for SshKubernetesCommandRunner {
    async fn run(
        &self,
        session: &BoundSshSession,
        command: String,
        timeout: Duration,
    ) -> CoreResult<SshCommandOutput> {
        self.ssh.execute_bound(session, command, timeout).await
    }
}

#[derive(Debug, Clone)]
pub struct KubernetesService {
    runner: Arc<dyn KubernetesCommandRunner>,
    // Only for the pod shell, which needs a PTY rather than a command's output.
    ssh: SshService,
    target: Arc<TargetContext>,
    deployment_health_deadline: Duration,
}

impl KubernetesService {
    pub fn new(ssh: SshService, target: Arc<TargetContext>) -> Self {
        Self {
            runner: Arc::new(SshKubernetesCommandRunner { ssh: ssh.clone() }),
            ssh,
            target,
            deployment_health_deadline: DEPLOYMENT_HEALTH_DEADLINE,
        }
    }

    pub async fn availability(
        &self,
        session: &BoundSshSession,
    ) -> CoreResult<KubernetesAvailability> {
        let output = self
            .read_command(
                session,
                AVAILABILITY_COMMAND.to_owned(),
                Duration::from_secs(12),
                "Kubernetes availability",
            )
            .await?;
        parse_availability(&output)
    }

    pub async fn namespaces(
        &self,
        session: &BoundSshSession,
        maximum_rows: usize,
    ) -> CoreResult<KubernetesCollection<KubernetesNamespace>> {
        validate_row_limit(maximum_rows)?;
        let output = self
            .read_command(
                session,
                "kubectl get namespaces -o json".to_owned(),
                Duration::from_secs(20),
                "list Kubernetes namespaces",
            )
            .await?;
        parse_namespaces(&output, maximum_rows)
    }

    pub async fn pods(
        &self,
        session: &BoundSshSession,
        scope: &KubernetesScope,
        maximum_rows: usize,
    ) -> CoreResult<KubernetesCollection<KubernetesPod>> {
        validate_row_limit(maximum_rows)?;
        let command = format!("kubectl get pods {} -o json", scope.arguments());
        let output = self
            .read_command(
                session,
                command,
                Duration::from_secs(25),
                "list Kubernetes pods",
            )
            .await?;
        parse_pods(&output, maximum_rows)
    }

    pub async fn deployments(
        &self,
        session: &BoundSshSession,
        scope: &KubernetesScope,
        maximum_rows: usize,
    ) -> CoreResult<KubernetesCollection<KubernetesDeployment>> {
        validate_row_limit(maximum_rows)?;
        let command = format!("kubectl get deployments {} -o json", scope.arguments());
        let output = self
            .read_command(
                session,
                command,
                Duration::from_secs(25),
                "list Kubernetes deployments",
            )
            .await?;
        parse_deployments(&output, maximum_rows)
    }

    pub async fn nodes(
        &self,
        session: &BoundSshSession,
        maximum_rows: usize,
    ) -> CoreResult<KubernetesCollection<KubernetesNode>> {
        validate_row_limit(maximum_rows)?;
        let output = self
            .read_command(
                session,
                "kubectl get nodes -o json".to_owned(),
                Duration::from_secs(25),
                "list Kubernetes nodes",
            )
            .await?;
        parse_nodes(&output, maximum_rows)
    }

    pub async fn detail(
        &self,
        session: &BoundSshSession,
        request: &KubernetesDetailRequest,
    ) -> CoreResult<KubernetesText> {
        let output = self
            .read_command(
                session,
                request.command(),
                Duration::from_secs(25),
                "describe Kubernetes resource",
            )
            .await?;
        Ok(bounded_multiline(&output, MAX_DETAIL_CHARS))
    }

    pub async fn pod_logs(
        &self,
        session: &BoundSshSession,
        request: &KubernetesPodLogsRequest,
    ) -> CoreResult<KubernetesText> {
        let output = self
            .read_command(
                session,
                request.command(),
                Duration::from_secs(30),
                "read Kubernetes pod logs",
            )
            .await?;
        Ok(bounded_multiline(&output, MAX_LOG_CHARS))
    }

    /// The live manifest of one listed Pod, Deployment or Node, as kubectl
    /// prints it in YAML, for the operator to keep.
    ///
    /// Read-only. The object is the list row's, never a name the caller
    /// chose, and the manifest is refused unless its kind, name, namespace
    /// and UID are still that row's — a pod recreated under the same name is
    /// a different pod. The YAML is returned exactly as kubectl printed it;
    /// kubectl's own stderr is kept out of it, and when the read fails a
    /// second, stderr-only read says whether the cluster refused it.
    pub async fn object_manifest(
        &self,
        session: &BoundSshSession,
        object: &KubernetesManifestObject,
    ) -> CoreResult<KubernetesManifest> {
        let read_at = chrono::Utc::now();
        let output = guarded_result(&self.target, session.target(), || {
            self.runner
                .run(session, manifest_command(object), Duration::from_secs(30))
        })
        .await?;
        let Some((yaml, context)) = parse_manifest_output(&output)? else {
            // kubectl itself failed. Asked again with its stderr, the cluster
            // says whether it refused (permission) or the object is gone.
            self.read_command(
                session,
                format!("{} -o name", object_get(object)),
                Duration::from_secs(20),
                "read Kubernetes manifest",
            )
            .await?;
            return Err(validation(
                "Kubernetes manifest",
                "kubectl 没有读出这个对象",
            ));
        };
        let identity = manifest_identity(&yaml)?;
        let (kind, namespace, name, row_uid) = object.identity();
        if identity.kind != kind
            || identity.name != name
            || identity.namespace.as_deref() != namespace
            || identity.uid != row_uid
        {
            return Err(validation(
                "Kubernetes manifest",
                "这个对象已不是列表里的那一个（可能被删除后重建），请刷新列表后再试",
            ));
        }
        self.target.validate(session.target())?;
        Ok(KubernetesManifest {
            kind,
            namespace: namespace.map(str::to_owned),
            name: name.to_owned(),
            uid: identity.uid,
            resource_version: identity.resource_version,
            context,
            read_at,
            yaml,
        })
    }

    /// Which of bash, ash and sh a pod's container has: the one chosen, or
    /// the pod's default container when none is named.
    ///
    /// Asked through /bin/sh, as for a container; a pod without one (a
    /// distroless image) has no shell to open, and that is the answer. The pod
    /// is checked to be the one listed before anything runs in it.
    pub async fn detect_shell(
        &self,
        session: &BoundSshSession,
        pod: &KubernetesPod,
        container: Option<&str>,
    ) -> CoreResult<ContainerShell> {
        let container = chosen_pod_container(pod, container)?;
        self.ensure_same_running_pod(session, pod, container)
            .await?;
        // kubectl exits 1 alike for an image without /bin/sh and for RBAC
        // refusing exec, so its own words are kept, and its exit status
        // printed after them, to tell the two apart. They are classified
        // here and never shown.
        let output = self
            .read_command(
                session,
                format!(
                    "{} /bin/sh -c {} 2>&1; echo \"{POD_EXEC_STATUS}$?\"",
                    pod_exec(pod, container),
                    shq(SHELL_PROBE_SCRIPT),
                ),
                Duration::from_secs(20),
                "detect Kubernetes pod shell",
            )
            .await?;
        classify_pod_shell_probe(&output)
    }

    /// Open an interactive shell in a pod read from this cluster.
    ///
    /// The pod is re-read first and must still be the same object — same UID,
    /// not being deleted — and running: a pod recreated under the old name is a
    /// different pod, and a shell in it is not what the operator chose. Only
    /// one of the listed pod's containers can be named, never a command;
    /// closing ends what the shell started, in that same container.
    #[allow(clippy::too_many_arguments)]
    pub async fn open_terminal(
        &self,
        session: &BoundSshSession,
        pod: &KubernetesPod,
        container: Option<&str>,
        shell: ContainerShell,
        terminal_id: String,
        columns: u16,
        rows: u16,
    ) -> CoreResult<KubernetesTerminalSession> {
        let container = chosen_pod_container(pod, container)?;
        self.ensure_same_running_pod(session, pod, container)
            .await?;
        self.target.validate(session.target())?;
        let marker = uuid::Uuid::new_v4().simple().to_string();
        let cleanup =
            crate::ssh::pod_session_cleanup_command(&pod.namespace, &pod.name, container, &marker)?;
        let inner = self
            .ssh
            .open_pod_terminal_bound(
                session,
                PodPtyRequest {
                    terminal_id,
                    namespace: pod.namespace.clone(),
                    pod: pod.name.clone(),
                    container: container.map(str::to_owned),
                    shell: shell.pty_shell(),
                    size: (columns, rows),
                    marker,
                },
            )
            .await?;
        let terminal = KubernetesTerminalSession {
            namespace: pod.namespace.clone(),
            pod: pod.name.clone(),
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

    /// One directory inside a pod's container (the chosen one, or the
    /// default), for browsing.
    ///
    /// The same fixed listing script a container uses, through `kubectl exec`,
    /// after checking the pod is still the one listed. Names are data.
    pub async fn list_directory(
        &self,
        session: &BoundSshSession,
        pod: &KubernetesPod,
        container: Option<&str>,
        directory: &RemotePath,
    ) -> CoreResult<ExecDirectoryListing> {
        let container = chosen_pod_container(pod, container)?;
        self.ensure_same_running_pod(session, pod, container)
            .await?;
        let output = match self
            .read_command(
                session,
                // kubectl's own notices ("Defaulted container …") go to
                // stderr, which the transport appends to the output.
                format!(
                    "{} 2>/dev/null",
                    listing_command(&pod_exec(pod, container), directory)
                ),
                Duration::from_secs(30),
                "list pod directory",
            )
            .await
        {
            Ok(output) => output,
            Err(error) => return Err(self.explain_exec_failure(session, pod, error).await),
        };
        self.target.validate(session.target())?;
        parse_listing(directory.clone(), &output)
    }

    /// Why a `kubectl exec` whose stderr was dropped failed, when the reason
    /// is that this account may not exec into the pod at all.
    ///
    /// The listing and the file reads discard kubectl's stderr — its notices
    /// would corrupt their records — and the API server's refusal goes with
    /// it. So, only after a failure, the API server is asked directly with
    /// `kubectl auth can-i` (a self access review any account may make): a
    /// plain "no" is reported as the missing permission, and anything else
    /// keeps the original failure rather than guessing.
    async fn explain_exec_failure(
        &self,
        session: &BoundSshSession,
        pod: &KubernetesPod,
        error: CoreError,
    ) -> CoreError {
        if !matches!(
            &error,
            CoreError::Validation {
                subject: "Kubernetes command",
                ..
            }
        ) {
            return error;
        }
        let command = format!(
            "kubectl auth can-i create {} --subresource=exec -n {} 2>/dev/null",
            shq(&format!("pods/{}", pod.name)),
            shq(&pod.namespace),
        );
        match guarded_result(&self.target, session.target(), || {
            self.runner.run(session, command, Duration::from_secs(15))
        })
        .await
        {
            Ok(answer) if !answer.timed_out && answer.output.trim() == "no" => validation(
                "Kubernetes pod exec",
                "当前账号没有在这个 Pod 里执行命令（pods/exec）的权限",
            ),
            _ => error,
        }
    }

    /// A regular UTF-8 file in a pod's container (the chosen one, or the
    /// default), for reading.
    ///
    /// As for a container: the file's length and SHA-256 are taken before and
    /// after, and the text must match both, so a symlink, a file being written
    /// to, or bytes that are not UTF-8 fail rather than show something else.
    /// There is no write: a pod's filesystem is the image's or a volume's, and
    /// a change belongs in the manifest.
    pub async fn read_file(
        &self,
        session: &BoundSshSession,
        pod: &KubernetesPod,
        container: Option<&str>,
        path: &ContainerFilePath,
    ) -> CoreResult<PodFileContent> {
        let container = chosen_pod_container(pod, container)?;
        self.ensure_same_running_pod(session, pod, container)
            .await?;
        let before = match self
            .probe_pod_file(session, pod, container, path, PROBE_TIMEOUT)
            .await
        {
            Ok(before) => before,
            Err(error) => return Err(self.explain_exec_failure(session, pod, error).await),
        };
        let (sha256, bytes) = match &before {
            ContainerFileState::Missing => {
                return Err(validation("Kubernetes pod file", "这个文件不存在"));
            }
            ContainerFileState::File { sha256, bytes } => (sha256.clone(), *bytes),
        };
        if bytes > MAX_POD_FILE_BYTES as u64 {
            return Err(validation(
                "Kubernetes pod file",
                format!("文件有 {bytes} 字节，超过了查看上限 {MAX_POD_FILE_BYTES} 字节"),
            ));
        }
        let content = self
            .read_command(
                session,
                format!(
                    "{} cat {} 2>/dev/null",
                    pod_exec(pod, container),
                    shq(path.as_str())
                ),
                Duration::from_secs(30),
                "read pod file",
            )
            .await?;
        if content.len() as u64 != bytes || sha256_hex(content.as_bytes()) != sha256 {
            return Err(validation(
                "Kubernetes pod file",
                "读到的内容和文件的长度或摘要对不上：文件可能正在被写入，或不是 UTF-8 文本",
            ));
        }
        let after = self
            .probe_pod_file(session, pod, container, path, PROBE_TIMEOUT)
            .await?;
        self.target.validate(session.target())?;
        if after != before {
            return Err(validation(
                "Kubernetes pod file",
                format!(
                    "读取期间文件变了（{} → {}）",
                    before.summary(),
                    after.summary()
                ),
            ));
        }
        Ok(PodFileContent {
            path: path.clone(),
            text: content,
            bytes,
            sha256,
        })
    }

    /// Copies a regular file of a pod's container (the chosen one, or the
    /// default) to `host_path` on the SSH host, for keeping as evidence.
    ///
    /// The pod is re-read first. The file's length and SHA-256 are taken in
    /// the container before and after the copy and must match each other and
    /// the copy's own; anything else removes the copy and fails. A symlink,
    /// directory or device is refused, as is a file over `maximum_bytes`.
    pub async fn stage_pod_file(
        &self,
        session: &BoundSshSession,
        pod: &KubernetesPod,
        container: Option<&str>,
        path: &ContainerFilePath,
        host_path: &str,
        maximum_bytes: u64,
    ) -> CoreResult<PodFileStage> {
        let id = stage_id(host_path)
            .ok_or_else(|| validation("Kubernetes pod file stage", "not a managed staging path"))?;
        let container = chosen_pod_container(pod, container)?;
        self.ensure_same_running_pod(session, pod, container)
            .await?;
        let before = match self
            .probe_pod_file(session, pod, container, path, EVIDENCE_PROBE_TIMEOUT)
            .await
        {
            Ok(before) => before,
            Err(error) => return Err(self.explain_exec_failure(session, pod, error).await),
        };
        let (sha256, bytes) = match &before {
            ContainerFileState::Missing => {
                return Err(validation("Kubernetes pod file", "这个文件不存在"));
            }
            ContainerFileState::File { sha256, bytes } => (sha256.clone(), *bytes),
        };
        if bytes > maximum_bytes {
            return Err(validation(
                "Kubernetes pod file",
                format!("文件有 {bytes} 字节，超过了留证上限 {maximum_bytes} 字节"),
            ));
        }
        let copied_at = chrono::Utc::now();
        // Two seconds a MiB on top of a minute, within the evidence deadline.
        let timeout = Duration::from_secs(60 + (bytes / (1024 * 1024)) * 2)
            .min(crate::file_evidence::FILE_EVIDENCE_DEADLINE);
        let copied = guarded_result(&self.target, session.target(), || {
            self.runner.run(
                session,
                pod_file_stage_command(pod, container, path, host_path, id),
                timeout,
            )
        })
        .await
        .and_then(|output| parse_pod_file_stage(&output));
        let (copy_bytes, copy_sha256, context) = match copied {
            Ok(copy) => copy,
            Err(error) => {
                let _ = self.remove_pod_file_stage(session, host_path).await;
                return Err(error);
            }
        };
        let after = self
            .probe_pod_file(session, pod, container, path, EVIDENCE_PROBE_TIMEOUT)
            .await;
        let unchanged = after.as_ref().is_ok_and(|after| after == &before)
            && copy_bytes == bytes
            && copy_sha256 == sha256;
        if !unchanged {
            let _ = self.remove_pod_file_stage(session, host_path).await;
            return Err(validation(
                "Kubernetes pod file",
                "复制期间文件变了，或复制出的字节与 Pod 里的不一致",
            ));
        }
        self.target.validate(session.target())?;
        Ok(PodFileStage {
            host_path: host_path.to_owned(),
            bytes,
            sha256,
            pod_uid: pod
                .id
                .as_str()
                .strip_prefix("pod:")
                .unwrap_or_default()
                .to_owned(),
            container: container.map(str::to_owned),
            context,
            copied_at,
        })
    }

    /// Ends a copy still running for `host_path` and removes the file. Only a
    /// managed staging path is touched; Ok means it is gone.
    pub async fn remove_pod_file_stage(
        &self,
        session: &BoundSshSession,
        host_path: &str,
    ) -> CoreResult<()> {
        let id = stage_id(host_path)
            .ok_or_else(|| validation("Kubernetes pod file stage", "not a managed staging path"))?;
        self.read_command(
            session,
            pod_file_stage_cleanup_command(host_path, id),
            Duration::from_secs(20),
            "remove a staged pod file",
        )
        .await
        .map(|_| ())
    }

    /// The length and SHA-256 of a pod file, taken inside its container.
    /// Digesting takes as long as the file is big, so the caller says how
    /// long it may: a viewed file is at most 1 MiB, evidence up to 512 MiB.
    async fn probe_pod_file(
        &self,
        session: &BoundSshSession,
        pod: &KubernetesPod,
        container: Option<&str>,
        path: &ContainerFilePath,
        timeout: Duration,
    ) -> CoreResult<ContainerFileState> {
        let output = guarded_result(&self.target, session.target(), || {
            self.runner.run(
                session,
                format!(
                    "{} sh -c {} 2>/dev/null",
                    pod_exec(pod, container),
                    shq(&container_file_probe_script(path))
                ),
                timeout,
            )
        })
        .await?;
        // The probe exits 42 for anything that is not a plain file under a
        // plain directory: a symlink, a directory, a device.
        if output.exit_code == Some(42) {
            return Err(validation(
                "Kubernetes pod file",
                "这不是普通文件（可能是符号链接、目录或设备），不能在这里查看",
            ));
        }
        parse_container_file_state(&validate_command_output("probe pod file", output)?)
    }

    async fn ensure_same_running_pod(
        &self,
        session: &BoundSshSession,
        pod: &KubernetesPod,
        container: Option<&str>,
    ) -> CoreResult<()> {
        self.target.validate(session.target())?;
        validate_pod_reference(&pod.namespace, &pod.name)?;
        let probe = self
            .read_command(
                session,
                // A pod deleted since the list was read prints nothing rather
                // than failing, so it is reported as gone, not as kubectl
                // being unable to reach the cluster.
                format!(
                    "kubectl get pod {} -n {} -o jsonpath={} --ignore-not-found",
                    shq(&pod.name),
                    shq(&pod.namespace),
                    shq(
                        r#"{.metadata.uid}{"\t"}{.status.phase}{"\t"}{.metadata.deletionTimestamp}{"\t"}{range .status.containerStatuses[*]}{.name}{"="}{.state.running.startedAt}{" "}{end}"#
                    ),
                ),
                Duration::from_secs(20),
                "read Kubernetes pod before opening a shell",
            )
            .await?;
        ensure_pod_open_for_shell(pod, &probe, container)
    }

    pub async fn plan_mutation(
        &self,
        session: &BoundSshSession,
        request: &KubernetesMutationRequest,
    ) -> CoreResult<KubernetesMutationPlan> {
        self.target.validate(session.target())?;
        let (row_id, before, kind, summary, restore_description) = match request {
            KubernetesMutationRequest::ScaleDeployment {
                deployment,
                replicas,
            } => {
                if *replicas > MAX_DEPLOYMENT_REPLICAS {
                    return Err(validation(
                        "Kubernetes deployment replicas",
                        format!("must be between 0 and {MAX_DEPLOYMENT_REPLICAS}"),
                    ));
                }
                validate_dns_label("Kubernetes namespace", &deployment.namespace)?;
                validate_dns_subdomain("Kubernetes deployment name", &deployment.name)?;
                let before = self
                    .probe_deployment(session, &deployment.namespace, &deployment.name)
                    .await?;
                ensure_deployment_row_snapshot(deployment, &before)?;
                let previous = before.replicas().ok_or_else(|| {
                    validation(
                        "Kubernetes deployment plan",
                        "probe returned a non-deployment snapshot",
                    )
                })?;
                if previous == *replicas {
                    return Err(validation(
                        "Kubernetes deployment plan",
                        "requested replica count already matches the observed state",
                    ));
                }
                (
                    deployment.id.clone(),
                    before,
                    KubernetesMutationKind::ScaleDeployment {
                        namespace: deployment.namespace.clone(),
                        name: deployment.name.clone(),
                        replicas: *replicas,
                    },
                    format!(
                        "将 Deployment {}/{} 的副本数从 {previous} 调整为 {replicas}。{}",
                        deployment.namespace,
                        deployment.name,
                        if *replicas == 0 {
                            "最多等待 45 秒核对停止状态；未完成时报告结果，不自动重新启动副本。"
                        } else {
                            "最多等待 45 秒检查副本就绪；未就绪时尝试恢复原副本数。"
                        }
                    ),
                    if *replicas == 0 {
                        "本次停止不会自动重新启动副本；需要恢复运行时，请重新规划并确认".to_owned()
                    } else {
                        "仅在对象与配置未被再次修改时恢复原副本数；恢复配置后仍需检查业务状态"
                            .to_owned()
                    },
                )
            }
            KubernetesMutationRequest::SetNodeUnschedulable {
                node,
                unschedulable,
            } => {
                validate_dns_subdomain("Kubernetes node name", &node.name)?;
                let before = self.probe_node(session, &node.name).await?;
                ensure_node_row_snapshot(node, &before)?;
                let previous = before.unschedulable().ok_or_else(|| {
                    validation("Kubernetes node plan", "probe returned a non-node snapshot")
                })?;
                if previous == *unschedulable {
                    return Err(validation(
                        "Kubernetes node plan",
                        "requested scheduling state already matches the observed state",
                    ));
                }
                (
                    node.id.clone(),
                    before,
                    KubernetesMutationKind::SetNodeUnschedulable {
                        name: node.name.clone(),
                        unschedulable: *unschedulable,
                    },
                    format!(
                        "将 Node {} 的调度状态从“{}”改为“{}”。",
                        node.name,
                        scheduling_label(previous),
                        scheduling_label(*unschedulable)
                    ),
                    "将 Node 调度状态恢复为操作前读回值".to_owned(),
                )
            }
        };
        self.target.validate(session.target())?;
        let mut operation = OperationPlan::new(
            session.target().clone(),
            summary,
            true,
            Some(restore_description),
        )?;
        operation
            .metadata
            .insert("source".to_owned(), "kubernetes".to_owned());
        operation
            .metadata
            .insert("resource-row-id".to_owned(), row_id.as_str().to_owned());
        operation.metadata.insert(
            "resource-version".to_owned(),
            before.resource_version().to_owned(),
        );
        Ok(KubernetesMutationPlan {
            operation,
            row_id,
            before,
            kind,
        })
    }

    pub async fn execute_mutation(
        &self,
        session: &BoundSshSession,
        plan: KubernetesMutationPlan,
        confirmation: DangerousConfirmation,
        journal: &PortableOperationJournal,
    ) -> CoreResult<KubernetesMutationOutcome> {
        if session.target() != &plan.operation.target {
            return Err(validation(
                "Kubernetes mutation",
                "SSH session target does not match the immutable plan",
            ));
        }
        let executor = KubernetesMutationExecutor {
            service: self,
            session,
            plan: &plan,
        };
        let mut operation = PlannedOperation::plan(plan.operation.clone());
        operation.confirm(confirmation)?;
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
                if self.target.validate(session.target()).is_err() {
                    return Err(error);
                }
                VerificationResult {
                    passed: false,
                    detail:
                        "无法读取操作后的资源状态，不能确认本次结果；请检查连接、权限与集群响应"
                            .to_owned(),
                }
            }
        };
        if !verification.passed {
            if matches!(
                plan.kind,
                KubernetesMutationKind::ScaleDeployment { replicas: 0, .. }
            ) {
                return Ok(KubernetesMutationOutcome {
                    verified: false,
                    verification_detail: format!(
                        "{}；未自动启动副本，请刷新检查当前状态",
                        verification.detail
                    ),
                    restored_after_failed_verification: false,
                });
            }
            let restored = operation
                .restore(&self.target, &executor, journal)
                .await
                .is_ok();
            return Ok(KubernetesMutationOutcome {
                verified: false,
                verification_detail: if restored {
                    verification.detail
                } else {
                    format!(
                        "{}；自动恢复未完成，请刷新检查。目标配置再次变化时不会覆盖。",
                        verification.detail
                    )
                },
                restored_after_failed_verification: restored,
            });
        }
        Ok(KubernetesMutationOutcome {
            verified: true,
            verification_detail: verification.detail,
            restored_after_failed_verification: false,
        })
    }

    async fn probe_deployment(
        &self,
        session: &BoundSshSession,
        namespace: &str,
        name: &str,
    ) -> CoreResult<KubernetesMutationSnapshot> {
        self.read_deployment(session, namespace, name)
            .await?
            .snapshot()
    }

    async fn read_deployment(
        &self,
        session: &BoundSshSession,
        namespace: &str,
        name: &str,
    ) -> CoreResult<RawDeployment> {
        let command = format!(
            "kubectl get deployment {} -n {} -o json",
            shq(name),
            shq(namespace)
        );
        let output = self
            .read_command(
                session,
                command,
                Duration::from_secs(20),
                "read Kubernetes deployment snapshot",
            )
            .await?;
        let raw: RawDeployment =
            serde_json::from_str(&output).map_err(|source| CoreError::Decode {
                subject: "Kubernetes deployment snapshot",
                source,
            })?;
        validate_snapshot_metadata("Kubernetes deployment snapshot", &raw.metadata)?;
        if raw.metadata.namespace != namespace || raw.metadata.name != name {
            return Err(validation(
                "Kubernetes deployment snapshot",
                "remote identity does not match the requested namespace and name",
            ));
        }
        Ok(raw)
    }

    async fn probe_node(
        &self,
        session: &BoundSshSession,
        name: &str,
    ) -> CoreResult<KubernetesMutationSnapshot> {
        let output = self
            .read_command(
                session,
                format!("kubectl get node {} -o json", shq(name)),
                Duration::from_secs(20),
                "read Kubernetes node snapshot",
            )
            .await?;
        let raw: RawNode = serde_json::from_str(&output).map_err(|source| CoreError::Decode {
            subject: "Kubernetes node snapshot",
            source,
        })?;
        validate_snapshot_metadata("Kubernetes node snapshot", &raw.metadata)?;
        if raw.metadata.name != name {
            return Err(validation(
                "Kubernetes node snapshot",
                "remote identity does not match the requested node name",
            ));
        }
        Ok(KubernetesMutationSnapshot::Node {
            uid: raw.metadata.uid,
            resource_version: raw.metadata.resource_version,
            unschedulable: raw.spec.unschedulable,
        })
    }

    async fn read_command(
        &self,
        session: &BoundSshSession,
        command: String,
        timeout: Duration,
        subject: &'static str,
    ) -> CoreResult<String> {
        let output = guarded_result(&self.target, session.target(), || {
            self.runner.run(session, command, timeout)
        })
        .await?;
        validate_command_output(subject, output)
    }
}

#[derive(Debug)]
struct KubernetesMutationExecutor<'a> {
    service: &'a KubernetesService,
    session: &'a BoundSshSession,
    plan: &'a KubernetesMutationPlan,
}

impl KubernetesMutationExecutor<'_> {
    async fn verify_deployment(
        &self,
        receipt: &KubernetesMutationReceipt,
        namespace: &str,
        name: &str,
    ) -> CoreResult<VerificationResult> {
        let deadline = tokio::time::Instant::now() + self.service.deployment_health_deadline;
        let mut last_detail = "尚未取得最新就绪状态".to_owned();
        loop {
            self.service.target.validate(self.session.target())?;
            let read = self.service.read_deployment(self.session, namespace, name);
            let raw = match tokio::time::timeout_at(deadline, read).await {
                Ok(result) => result?,
                Err(_) => break,
            };
            let current = raw.snapshot()?;
            if receipt.uid != current.uid() || !self.plan.target_matches(&current) {
                return Ok(VerificationResult {
                    passed: false,
                    detail: "Deployment 对象或副本数已变化，无法确认本次操作结果".to_owned(),
                });
            }
            if receipt.generation.is_none() || receipt.generation != current.generation() {
                return Ok(VerificationResult {
                    passed: false,
                    detail:
                        "Deployment 配置已再次变化或版本信息缺失，不能将当前状态归为本次操作结果"
                            .to_owned(),
                });
            }
            match deployment_health(&raw) {
                DeploymentHealth::Ready => {
                    return Ok(VerificationResult {
                        passed: true,
                        detail: if raw.spec.replicas == Some(0) {
                            "副本数已核对为 0，控制器已处理本次配置；终止中的 Pod 可能仍在退出，这不代表应用可用".to_owned()
                        } else {
                            format!(
                                "副本数已核对为 {}，所有副本已更新、就绪且可用；业务接口仍需另行验证",
                                current.replicas().unwrap_or_default()
                            )
                        },
                    });
                }
                DeploymentHealth::Failed(detail) => {
                    return Ok(VerificationResult {
                        passed: false,
                        detail,
                    });
                }
                DeploymentHealth::Pending(detail) => last_detail = detail,
            }
            if tokio::time::timeout_at(deadline, tokio::time::sleep(DEPLOYMENT_HEALTH_POLL))
                .await
                .is_err()
            {
                break;
            }
        }
        Ok(VerificationResult {
            passed: false,
            detail: format!("就绪检查超时：{last_detail}"),
        })
    }

    fn ensure_plan(&self, operation: &OperationPlan) -> CoreResult<()> {
        if operation != &self.plan.operation {
            return Err(validation(
                "Kubernetes mutation",
                "executor received a different immutable plan",
            ));
        }
        Ok(())
    }

    async fn current_snapshot(&self) -> CoreResult<KubernetesMutationSnapshot> {
        match &self.plan.kind {
            KubernetesMutationKind::ScaleDeployment {
                namespace, name, ..
            } => {
                self.service
                    .probe_deployment(self.session, namespace, name)
                    .await
            }
            KubernetesMutationKind::SetNodeUnschedulable { name, .. } => {
                self.service.probe_node(self.session, name).await
            }
        }
    }

    async fn patch(
        &self,
        current: &KubernetesMutationSnapshot,
        restore: bool,
    ) -> CoreResult<String> {
        let command = mutation_patch_command(self.plan, current, restore)?;
        self.service
            .read_command(
                self.session,
                command,
                Duration::from_secs(30),
                if restore {
                    "restore Kubernetes resource"
                } else {
                    "change Kubernetes resource"
                },
            )
            .await
    }
}

#[async_trait]
impl OperationExecutor for KubernetesMutationExecutor<'_> {
    async fn execute(&self, operation: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        self.ensure_plan(operation)?;
        let current = self.current_snapshot().await?;
        if current != *self.plan.before() {
            return Err(validation(
                "Kubernetes mutation precondition",
                "resource UID, resourceVersion, or reviewed state changed; create a new plan",
            ));
        }
        let output = self.patch(&current, false).await?;
        let patched = parse_mutation_snapshot(self.plan, &output)?;
        if !self.plan.target_matches(&patched) {
            return Err(validation(
                "Kubernetes mutation response",
                "patch response did not contain the exact requested target state",
            ));
        }
        Ok(ExecutionReceipt {
            summary: self.plan.state_change(),
            restore_token: Some(
                serde_json::to_string(&KubernetesMutationReceipt {
                    schema: "kubernetes-mutation/v2".to_owned(),
                    uid: patched.uid().to_owned(),
                    resource_version: patched.resource_version().to_owned(),
                    generation: patched.generation(),
                })
                .map_err(|error| {
                    validation(
                        "Kubernetes mutation receipt",
                        format!("failed to encode opaque revision token: {error}"),
                    )
                })?,
            ),
        })
    }

    async fn verify(
        &self,
        operation: &OperationPlan,
        receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        self.ensure_plan(operation)?;
        let receipt = mutation_receipt(receipt)?;
        if let KubernetesMutationKind::ScaleDeployment {
            namespace, name, ..
        } = &self.plan.kind
        {
            return self.verify_deployment(&receipt, namespace, name).await;
        }
        let current = self.current_snapshot().await?;
        let passed = receipt.uid == current.uid() && self.plan.target_matches(&current);
        Ok(VerificationResult {
            passed,
            detail: if passed {
                format!(
                    "已核对{}；此操作不迁移现有 Pod，也不隔离节点网络",
                    self.plan.state_change()
                )
            } else {
                "核对未通过：资源没有处于确认时计划的状态，或已被换成另一个同名对象。".to_owned()
            },
        })
    }

    async fn restore(
        &self,
        operation: &OperationPlan,
        receipt: &ExecutionReceipt,
    ) -> CoreResult<()> {
        self.ensure_plan(operation)?;
        let receipt = mutation_receipt(receipt)?;
        let current = self.current_snapshot().await?;
        if !self.plan.target_matches(&current)
            || receipt.uid != current.uid()
            || !restore_revision_matches(&receipt, &current)
        {
            return Err(validation(
                "Kubernetes restore precondition",
                "resource revision changed after this operation; refusing to overwrite an independent revision",
            ));
        }
        self.patch(&current, true).await?;
        let restored = self.current_snapshot().await?;
        if !snapshot_state_matches(self.plan.before(), &restored) {
            return Err(validation(
                "Kubernetes restore verification",
                "resource did not return to the exact pre-operation state",
            ));
        }
        Ok(())
    }
}

fn mutation_receipt(receipt: &ExecutionReceipt) -> CoreResult<KubernetesMutationReceipt> {
    let token = receipt.restore_token.as_deref().ok_or_else(|| {
        validation(
            "Kubernetes mutation receipt",
            "receipt is missing its opaque revision token",
        )
    })?;
    let decoded: KubernetesMutationReceipt = serde_json::from_str(token)
        .map_err(|_| validation("Kubernetes mutation receipt", "receipt token is malformed"))?;
    if decoded.schema != "kubernetes-mutation/v1" && decoded.schema != "kubernetes-mutation/v2" {
        return Err(validation(
            "Kubernetes mutation receipt",
            "receipt does not belong to the closed Kubernetes workflow",
        ));
    }
    validate_snapshot_identity(
        "Kubernetes mutation receipt",
        &decoded.uid,
        &decoded.resource_version,
    )?;
    Ok(decoded)
}

fn restore_revision_matches(
    receipt: &KubernetesMutationReceipt,
    current: &KubernetesMutationSnapshot,
) -> bool {
    // Deployment status updates change resourceVersion without changing spec.
    // A matching generation allows those updates; the patch still compares
    // the latest UID/resourceVersion atomically. Legacy receipts and Nodes
    // keep the conservative exact-revision requirement.
    match (
        receipt.schema.as_str(),
        receipt.generation,
        current.generation(),
    ) {
        ("kubernetes-mutation/v2", Some(applied), Some(observed)) if applied > 0 => {
            applied == observed
        }
        _ => receipt.resource_version == current.resource_version(),
    }
}

fn ensure_deployment_row_snapshot(
    deployment: &KubernetesDeployment,
    snapshot: &KubernetesMutationSnapshot,
) -> CoreResult<()> {
    let KubernetesMutationSnapshot::Deployment { uid, replicas, .. } = snapshot else {
        return Err(validation(
            "Kubernetes deployment plan",
            "probe returned a non-deployment snapshot",
        ));
    };
    if deployment.id != KubernetesRowId(format!("deployment:{uid}"))
        || deployment.desired_replicas != *replicas
    {
        return Err(validation(
            "Kubernetes deployment plan",
            "selected row is stale or does not match the probed resource UID",
        ));
    }
    Ok(())
}

fn ensure_node_row_snapshot(
    node: &KubernetesNode,
    snapshot: &KubernetesMutationSnapshot,
) -> CoreResult<()> {
    let KubernetesMutationSnapshot::Node {
        uid, unschedulable, ..
    } = snapshot
    else {
        return Err(validation(
            "Kubernetes node plan",
            "probe returned a non-node snapshot",
        ));
    };
    if node.id != KubernetesRowId(format!("node:{uid}")) || node.unschedulable != *unschedulable {
        return Err(validation(
            "Kubernetes node plan",
            "selected row is stale or does not match the probed resource UID",
        ));
    }
    Ok(())
}

fn validate_snapshot_metadata(subject: &'static str, metadata: &RawMetadata) -> CoreResult<()> {
    validate_snapshot_identity(subject, &metadata.uid, &metadata.resource_version)
}

fn validate_snapshot_identity(
    subject: &'static str,
    uid: &str,
    resource_version: &str,
) -> CoreResult<()> {
    for (field, value) in [("UID", uid), ("resourceVersion", resource_version)] {
        if value.is_empty()
            || value.len() > MAX_RESOURCE_IDENTITY_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(validation(
                subject,
                format!("{field} must be non-empty, bounded, and control-free"),
            ));
        }
    }
    Ok(())
}

fn parse_mutation_snapshot(
    plan: &KubernetesMutationPlan,
    output: &str,
) -> CoreResult<KubernetesMutationSnapshot> {
    match &plan.kind {
        KubernetesMutationKind::ScaleDeployment {
            namespace, name, ..
        } => {
            let raw: RawDeployment =
                serde_json::from_str(output).map_err(|source| CoreError::Decode {
                    subject: "Kubernetes deployment mutation response",
                    source,
                })?;
            validate_snapshot_metadata("Kubernetes deployment mutation response", &raw.metadata)?;
            if raw.metadata.namespace != *namespace || raw.metadata.name != *name {
                return Err(validation(
                    "Kubernetes deployment mutation response",
                    "remote identity does not match the immutable plan",
                ));
            }
            raw.snapshot()
        }
        KubernetesMutationKind::SetNodeUnschedulable { name, .. } => {
            let raw: RawNode =
                serde_json::from_str(output).map_err(|source| CoreError::Decode {
                    subject: "Kubernetes node mutation response",
                    source,
                })?;
            validate_snapshot_metadata("Kubernetes node mutation response", &raw.metadata)?;
            if raw.metadata.name != *name {
                return Err(validation(
                    "Kubernetes node mutation response",
                    "remote identity does not match the immutable plan",
                ));
            }
            Ok(KubernetesMutationSnapshot::Node {
                uid: raw.metadata.uid,
                resource_version: raw.metadata.resource_version,
                unschedulable: raw.spec.unschedulable,
            })
        }
    }
}

fn scheduling_label(unschedulable: bool) -> &'static str {
    if unschedulable {
        "停止调度"
    } else {
        "允许调度"
    }
}

fn snapshot_state_matches(
    expected: &KubernetesMutationSnapshot,
    observed: &KubernetesMutationSnapshot,
) -> bool {
    match (expected, observed) {
        (
            KubernetesMutationSnapshot::Deployment { uid, replicas, .. },
            KubernetesMutationSnapshot::Deployment {
                uid: observed_uid,
                replicas: observed_replicas,
                ..
            },
        ) => uid == observed_uid && replicas == observed_replicas,
        (
            KubernetesMutationSnapshot::Node {
                uid, unschedulable, ..
            },
            KubernetesMutationSnapshot::Node {
                uid: observed_uid,
                unschedulable: observed_unschedulable,
                ..
            },
        ) => uid == observed_uid && unschedulable == observed_unschedulable,
        _ => false,
    }
}

fn mutation_patch_command(
    plan: &KubernetesMutationPlan,
    current: &KubernetesMutationSnapshot,
    restore: bool,
) -> CoreResult<String> {
    if plan.before.uid() != current.uid() {
        return Err(validation(
            "Kubernetes mutation patch",
            "resource UID changed",
        ));
    }
    let resource_version = current.resource_version();
    let (resource, name, namespace, state_patch) = match (&plan.kind, current) {
        (
            KubernetesMutationKind::ScaleDeployment {
                namespace,
                name,
                replicas,
            },
            KubernetesMutationSnapshot::Deployment { .. },
        ) => {
            let target = if restore {
                plan.before.replicas().ok_or_else(|| {
                    validation("Kubernetes mutation patch", "missing deployment state")
                })?
            } else {
                *replicas
            };
            (
                "deployment",
                name.as_str(),
                Some(namespace.as_str()),
                json!({"op": "replace", "path": "/spec/replicas", "value": target}),
            )
        }
        (
            KubernetesMutationKind::SetNodeUnschedulable {
                name,
                unschedulable,
            },
            KubernetesMutationSnapshot::Node { .. },
        ) => {
            let target = if restore {
                plan.before
                    .unschedulable()
                    .ok_or_else(|| validation("Kubernetes mutation patch", "missing node state"))?
            } else {
                *unschedulable
            };
            (
                "node",
                name.as_str(),
                None,
                json!({"op": "add", "path": "/spec/unschedulable", "value": target}),
            )
        }
        _ => {
            return Err(validation(
                "Kubernetes mutation patch",
                "snapshot kind does not match the immutable plan",
            ));
        }
    };
    let patch = json!([
        {"op": "test", "path": "/metadata/uid", "value": current.uid()},
        {"op": "test", "path": "/metadata/resourceVersion", "value": resource_version},
        state_patch,
    ])
    .to_string();
    let namespace = namespace
        .map(|value| format!(" -n {}", shq(value)))
        .unwrap_or_default();
    // `-o json` because the caller parses this output back into a snapshot and
    // checks it reached the exact reviewed state. Without it kubectl prints
    // one line of prose — "deployment.apps/ledger patched" — the parse fails,
    // and the workflow reports a failure for a change that already happened.
    // Telling an operator nothing was done when something was is worse than
    // any error here.
    Ok(format!(
        "kubectl patch {resource} {}{namespace} --type=json -p {} -o json",
        shq(name),
        shq(&patch)
    ))
}

async fn guarded_result<T, F, Fut>(
    target: &TargetContext,
    guard: &TargetGuard,
    operation: F,
) -> CoreResult<T>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = CoreResult<T>>,
{
    target.validate(guard)?;
    let result = operation().await?;
    target.validate(guard)?;
    Ok(result)
}

/// The copy, as one script on the SSH host: the file is created exclusively
/// (no following a planted link), kubectl carries a marker a cancel can find,
/// and the copy's length and digest are printed after a fixed marker.
fn pod_file_stage_command(
    pod: &KubernetesPod,
    container: Option<&str>,
    path: &ContainerFilePath,
    host_path: &str,
    id: &str,
) -> String {
    format!(
        "umask 077; set -C; dest={dest}; \
         if ! {env}={id} {exec} cat -- {path} > \"$dest\" 2>/dev/null; then \
           rm -f -- \"$dest\"; printf '{failed}\\tcopy\\n'; exit 0; fi; \
         if ! command -v sha256sum >/dev/null 2>&1; then \
           rm -f -- \"$dest\"; printf '{failed}\\tsha256sum\\n'; exit 0; fi; \
         bytes=$(wc -c < \"$dest\" | tr -d '[:space:]'); \
         hash=$(sha256sum \"$dest\" | awk '{{print $1}}'); \
         context=$(kubectl config current-context 2>/dev/null | tr -d '\\r\\n\\t' | head -c 512 || true); \
         printf '{marker}\\t%s\\t%s\\t%s\\n' \"$bytes\" \"$hash\" \"$context\"",
        dest = shq(host_path),
        env = POD_FILE_STAGE_ENV,
        id = shq(id),
        exec = pod_exec(pod, container),
        path = shq(path.as_str()),
        failed = POD_FILE_STAGE_FAILED,
        marker = POD_FILE_STAGE_MARKER,
    )
}

/// `kubectl get <kind> <name> [-n <namespace>]` for a listed object; every
/// part is the row's, quoted.
fn object_get(object: &KubernetesManifestObject) -> String {
    match object {
        KubernetesManifestObject::Pod(pod) => format!(
            "kubectl get pod {} -n {}",
            shq(&pod.name),
            shq(&pod.namespace)
        ),
        KubernetesManifestObject::Deployment(deployment) => format!(
            "kubectl get deployment {} -n {}",
            shq(&deployment.name),
            shq(&deployment.namespace)
        ),
        KubernetesManifestObject::Node(node) => format!("kubectl get node {}", shq(&node.name)),
    }
}

/// The manifest, then a marker line with kubectl's exit status and the
/// context it used. stderr goes nowhere: the transport appends it to the
/// output, and a deprecation warning would otherwise end up inside the YAML.
fn manifest_command(object: &KubernetesManifestObject) -> String {
    format!(
        "{get} -o yaml 2>/dev/null; status=$?; \
         context=$(kubectl config current-context 2>/dev/null | tr -d '\\r\\n\\t' | head -c 512 || true); \
         printf '\\n{marker}\\t%s\\t%s\\n' \"$status\" \"$context\"",
        get = object_get(object),
        marker = MANIFEST_MARKER,
    )
}

/// The YAML and the context, from the output of [`manifest_command`]; `None`
/// when kubectl itself failed (the script still ends normally, with kubectl's
/// status in its marker line).
fn parse_manifest_output(output: &SshCommandOutput) -> CoreResult<Option<(String, String)>> {
    if output.timed_out {
        return Err(validation("Kubernetes manifest", "读取超时"));
    }
    let (body, marker) = output
        .output
        .rsplit_once(&format!("\n{MANIFEST_MARKER}\t"))
        .ok_or_else(|| validation("Kubernetes manifest", "读取没有完成"))?;
    let mut fields = marker.trim_end_matches(['\r', '\n']).split('\t');
    if fields.next() != Some("0") {
        return Ok(None);
    }
    let context = bounded_text(fields.next().unwrap_or_default(), MAX_CONTEXT_CHARS);
    if body.len() > MAX_MANIFEST_BYTES {
        return Err(validation(
            "Kubernetes manifest",
            format!("清单超过 {MAX_MANIFEST_BYTES} 字节的上限"),
        ));
    }
    if body.trim().is_empty() {
        return Err(validation(
            "Kubernetes manifest",
            "kubectl 没有读出这个对象",
        ));
    }
    Ok(Some((body.to_owned(), context)))
}

#[derive(Debug, PartialEq, Eq)]
struct ManifestIdentity {
    kind: &'static str,
    name: String,
    namespace: Option<String>,
    uid: String,
    resource_version: String,
}

/// The object's own kind and metadata, read from the top-level `kind:` line
/// and the two-space keys of the top-level `metadata:` block — not from an
/// owner reference or a status entry further in, which carry a `uid:` too.
fn manifest_identity(yaml: &str) -> CoreResult<ManifestIdentity> {
    let mut kind = None;
    let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
    let mut in_metadata = false;
    for line in yaml.lines() {
        if !line.starts_with(' ') && !line.is_empty() {
            in_metadata = line.trim_end() == "metadata:";
            if let Some(value) = line.strip_prefix("kind: ") {
                kind = Some(value.trim());
            }
            continue;
        }
        let Some(rest) = line.strip_prefix("  ").filter(|_| in_metadata) else {
            continue;
        };
        if rest.starts_with([' ', '-']) {
            continue;
        }
        if let Some((key, value)) = rest.split_once(": ")
            && matches!(key, "name" | "namespace" | "uid" | "resourceVersion")
        {
            fields.entry(key).or_insert(value.trim().trim_matches('"'));
        }
    }
    let kind = match kind {
        Some("Pod") => "Pod",
        Some("Deployment") => "Deployment",
        Some("Node") => "Node",
        _ => {
            return Err(validation(
                "Kubernetes manifest",
                "读出的不是所选类型的对象",
            ));
        }
    };
    let text = |key: &str| fields.get(key).map(|value| (*value).to_owned());
    let (Some(name), Some(uid)) = (text("name"), text("uid")) else {
        return Err(validation(
            "Kubernetes manifest",
            "清单里没有对象的名称或 UID",
        ));
    };
    Ok(ManifestIdentity {
        kind,
        name,
        namespace: text("namespace"),
        uid,
        resource_version: text("resourceVersion").unwrap_or_default(),
    })
}

/// Ends any kubectl still copying for this stage (found by the marker in its
/// environment), then removes the file and says whether it is gone.
fn pod_file_stage_cleanup_command(host_path: &str, id: &str) -> String {
    format!(
        "marker={marker}; dest={dest}; \
         for attempt in 1 2 3; do \
           for proc in /proc/[0-9]*; do \
             if tr '\\000' '\\n' < \"$proc/environ\" 2>/dev/null | grep -qxF \"$marker\"; then \
               kill -TERM \"${{proc#/proc/}}\" 2>/dev/null || true; fi; \
           done; \
           rm -f -- \"$dest\"; \
           [ ! -e \"$dest\" ] && [ ! -L \"$dest\" ] && break; \
           sleep 1; \
         done; \
         [ ! -e \"$dest\" ] && [ ! -L \"$dest\" ]",
        marker = shq(&format!("{POD_FILE_STAGE_ENV}={id}")),
        dest = shq(host_path),
    )
}

fn parse_pod_file_stage(output: &SshCommandOutput) -> CoreResult<(u64, String, String)> {
    if output.timed_out || output.exit_code != Some(0) {
        return Err(validation(
            "Kubernetes pod file copy",
            "the copy to the SSH host did not finish",
        ));
    }
    let line = output
        .output
        .lines()
        .rev()
        .find(|line| {
            line.starts_with(POD_FILE_STAGE_MARKER) || line.starts_with(POD_FILE_STAGE_FAILED)
        })
        .ok_or_else(|| validation("Kubernetes pod file copy", "the copy reported nothing"))?;
    let mut fields = line.split('\t');
    if fields.next() != Some(POD_FILE_STAGE_MARKER) {
        return Err(validation(
            "Kubernetes pod file copy",
            format!(
                "the copy to the SSH host failed ({})",
                fields.next().unwrap_or("unknown")
            ),
        ));
    }
    let bytes = fields
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| validation("Kubernetes pod file copy", "the copy's length is missing"))?;
    let sha256 = fields
        .next()
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| validation("Kubernetes pod file copy", "the copy's digest is missing"))?
        .to_ascii_lowercase();
    let context = bounded_text(fields.next().unwrap_or_default(), MAX_CONTEXT_CHARS);
    Ok((bytes, sha256, context))
}

fn validate_command_output(subject: &'static str, output: SshCommandOutput) -> CoreResult<String> {
    if !output.timed_out && output.exit_code != Some(0) && is_api_forbidden(&output.output) {
        return Err(validation(
            "Kubernetes permission",
            format!("{subject} was refused by the API server (Forbidden)"),
        ));
    }
    if output.timed_out || output.exit_code != Some(0) {
        return Err(validation(
            "Kubernetes command",
            format!(
                "{subject} failed (exit={:?}, timed_out={})",
                output.exit_code, output.timed_out
            ),
        ));
    }
    if output.output.len() > MAX_JSON_BYTES {
        return Err(validation(
            "Kubernetes output",
            format!("exceeds the {MAX_JSON_BYTES}-byte boundary"),
        ));
    }
    Ok(output.output)
}

/// The API server's RBAC refusal as kubectl prints it on stderr, which the
/// transport appends to the output — so it is the last line, and a log line
/// that merely reads the same further up does not count. Only the fixed
/// prefix is matched; the rest of the line (the user, the verb, the resource)
/// comes from the cluster and is not passed on.
fn is_api_forbidden(output: &str) -> bool {
    output
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .is_some_and(|line| {
            line.trim_start()
                .starts_with("Error from server (Forbidden):")
        })
}

fn parse_availability(output: &str) -> CoreResult<KubernetesAvailability> {
    let markers: BTreeMap<_, _> = output
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .take(8)
        .collect();
    let installed = markers.get("installed").copied();
    let api_reachable = markers.get("api_reachable").copied();
    if installed.is_none() || api_reachable.is_none() {
        return Err(validation(
            "Kubernetes availability output",
            "missing typed availability markers",
        ));
    }
    Ok(KubernetesAvailability {
        kubectl_installed: installed == Some("true"),
        api_reachable: api_reachable == Some("true"),
        current_context: bounded_text(
            markers.get("context").copied().unwrap_or_default(),
            MAX_CONTEXT_CHARS,
        ),
        context_namespace: context_namespace(
            markers.get("context").copied().unwrap_or_default(),
            markers.get("namespace").copied().unwrap_or_default(),
        ),
    })
}

/// The namespace kubectl falls back to: the context's own, or `default` when
/// a context names none. A value that is not a namespace name is dropped
/// rather than shown or used.
fn context_namespace(context: &str, namespace: &str) -> Option<String> {
    if context.is_empty() {
        return None;
    }
    let namespace = if namespace.is_empty() {
        "default"
    } else {
        namespace
    };
    validate_dns_label("Kubernetes namespace", namespace)
        .ok()
        .map(|()| namespace.to_owned())
}

fn parse_namespaces(
    output: &str,
    maximum_rows: usize,
) -> CoreResult<KubernetesCollection<KubernetesNamespace>> {
    let raw: RawList<RawNamespace> = decode_list(output, "Kubernetes namespace list")?;
    let truncated = raw.items.len() > maximum_rows;
    let items = raw
        .items
        .into_iter()
        .take(maximum_rows)
        .map(|item| KubernetesNamespace {
            id: row_id("namespace", &item.metadata, ""),
            name: bounded_text(&item.metadata.name, MAX_CELL_CHARS),
            phase: bounded_text(&item.status.phase, MAX_CELL_CHARS),
            created_at: bounded_text(&item.metadata.creation_timestamp, MAX_CELL_CHARS),
        })
        .collect();
    Ok(KubernetesCollection { items, truncated })
}

fn parse_pods(
    output: &str,
    maximum_rows: usize,
) -> CoreResult<KubernetesCollection<KubernetesPod>> {
    let raw: RawList<RawPod> = decode_list(output, "Kubernetes pod list")?;
    let truncated = raw.items.len() > maximum_rows;
    let items = raw
        .items
        .into_iter()
        .take(maximum_rows)
        .map(|item| {
            let total_containers = item.spec.containers.len();
            let ready_containers = item
                .status
                .container_statuses
                .iter()
                .filter(|status| status.ready)
                .count();
            let restarts = item
                .status
                .container_statuses
                .iter()
                .map(|status| status.restart_count)
                .sum();
            let waiting_reason = item
                .status
                .container_statuses
                .iter()
                .find_map(|status| status.state.waiting.as_ref())
                .map(|waiting| waiting.reason.as_str())
                .filter(|reason| !reason.is_empty());
            let phase = waiting_reason.unwrap_or(&item.status.phase);
            let containers = item
                .spec
                .containers
                .iter()
                .take(64)
                .filter(|container| {
                    validate_dns_label("Kubernetes container name", &container.name).is_ok()
                })
                .map(|container| {
                    let status = item
                        .status
                        .container_statuses
                        .iter()
                        .find(|status| status.name == container.name);
                    KubernetesPodContainer {
                        name: container.name.clone(),
                        image: bounded_text(&container.image, MAX_CELL_CHARS),
                        ready: status.is_some_and(|status| status.ready),
                        running: status.is_some_and(|status| status.state.running.is_some()),
                        restarts: status.map_or(0, |status| status.restart_count),
                    }
                })
                .collect::<Vec<_>>();
            let default_container = item
                .metadata
                .annotations
                .get("kubectl.kubernetes.io/default-container")
                .filter(|named| containers.iter().any(|container| &container.name == *named))
                .cloned()
                .or_else(|| containers.first().map(|container| container.name.clone()));
            KubernetesPod {
                id: row_id("pod", &item.metadata, &item.metadata.namespace),
                namespace: bounded_text(&item.metadata.namespace, MAX_CELL_CHARS),
                name: bounded_text(&item.metadata.name, MAX_CELL_CHARS),
                phase: bounded_text(phase, MAX_CELL_CHARS),
                ready_containers,
                total_containers,
                restarts,
                node: bounded_text(&item.spec.node_name, MAX_CELL_CHARS),
                pod_ip: bounded_text(&item.status.pod_ip, MAX_CELL_CHARS),
                images: item
                    .spec
                    .containers
                    .into_iter()
                    .take(64)
                    .map(|container| bounded_text(&container.image, MAX_CELL_CHARS))
                    .collect(),
                created_at: bounded_text(&item.metadata.creation_timestamp, MAX_CELL_CHARS),
                containers,
                default_container,
            }
        })
        .collect();
    Ok(KubernetesCollection { items, truncated })
}

fn parse_deployments(
    output: &str,
    maximum_rows: usize,
) -> CoreResult<KubernetesCollection<KubernetesDeployment>> {
    let raw: RawList<RawDeployment> = decode_list(output, "Kubernetes deployment list")?;
    let truncated = raw.items.len() > maximum_rows;
    let items = raw
        .items
        .into_iter()
        .take(maximum_rows)
        .map(|item| KubernetesDeployment {
            id: row_id("deployment", &item.metadata, &item.metadata.namespace),
            namespace: bounded_text(&item.metadata.namespace, MAX_CELL_CHARS),
            name: bounded_text(&item.metadata.name, MAX_CELL_CHARS),
            desired_replicas: item.spec.replicas.unwrap_or(1),
            ready_replicas: item.status.ready_replicas,
            available_replicas: item.status.available_replicas,
            updated_replicas: item.status.updated_replicas,
            images: item
                .spec
                .template
                .spec
                .containers
                .into_iter()
                .take(64)
                .map(|container| bounded_text(&container.image, MAX_CELL_CHARS))
                .collect(),
            created_at: bounded_text(&item.metadata.creation_timestamp, MAX_CELL_CHARS),
        })
        .collect();
    Ok(KubernetesCollection { items, truncated })
}

fn parse_nodes(
    output: &str,
    maximum_rows: usize,
) -> CoreResult<KubernetesCollection<KubernetesNode>> {
    let raw: RawList<RawNode> = decode_list(output, "Kubernetes node list")?;
    let truncated = raw.items.len() > maximum_rows;
    let items = raw
        .items
        .into_iter()
        .take(maximum_rows)
        .map(|item| {
            let ready = item
                .status
                .conditions
                .iter()
                .any(|condition| condition.kind == "Ready" && condition.status == "True");
            let roles = item
                .metadata
                .labels
                .keys()
                .filter_map(|key| key.strip_prefix("node-role.kubernetes.io/"))
                .map(|role| {
                    if role.is_empty() {
                        "worker".to_owned()
                    } else {
                        bounded_text(role, MAX_CELL_CHARS)
                    }
                })
                .take(32)
                .collect();
            let internal_ip = item
                .status
                .addresses
                .iter()
                .find(|address| address.kind == "InternalIP")
                .map(|address| bounded_text(&address.address, MAX_CELL_CHARS))
                .unwrap_or_default();
            KubernetesNode {
                id: row_id("node", &item.metadata, ""),
                name: bounded_text(&item.metadata.name, MAX_CELL_CHARS),
                ready,
                unschedulable: item.spec.unschedulable,
                roles,
                kubelet_version: bounded_text(
                    &item.status.node_info.kubelet_version,
                    MAX_CELL_CHARS,
                ),
                internal_ip,
                cpu_capacity: bounded_text(
                    item.status.capacity.get("cpu").map_or("", String::as_str),
                    MAX_CELL_CHARS,
                ),
                memory_capacity: bounded_text(
                    item.status
                        .capacity
                        .get("memory")
                        .map_or("", String::as_str),
                    MAX_CELL_CHARS,
                ),
                pod_capacity: bounded_text(
                    item.status.capacity.get("pods").map_or("", String::as_str),
                    MAX_CELL_CHARS,
                ),
                created_at: bounded_text(&item.metadata.creation_timestamp, MAX_CELL_CHARS),
            }
        })
        .collect();
    Ok(KubernetesCollection { items, truncated })
}

fn decode_list<T>(output: &str, subject: &'static str) -> CoreResult<RawList<T>>
where
    T: for<'de> Deserialize<'de>,
{
    if output.len() > MAX_JSON_BYTES {
        return Err(validation(
            "Kubernetes output",
            format!("exceeds the {MAX_JSON_BYTES}-byte boundary"),
        ));
    }
    serde_json::from_str(output).map_err(|source| CoreError::Decode { subject, source })
}

fn row_id(kind: &str, metadata: &RawMetadata, namespace: &str) -> KubernetesRowId {
    let value = if metadata.uid.is_empty() {
        format!("{kind}:{namespace}:{}", metadata.name)
    } else {
        format!("{kind}:{}", metadata.uid)
    };
    KubernetesRowId(bounded_text(&value, 1_024))
}

fn bounded_multiline(value: &str, maximum_chars: usize) -> KubernetesText {
    let mut text = String::new();
    let mut truncated = false;
    for (index, character) in value.chars().enumerate() {
        if index >= maximum_chars {
            truncated = true;
            break;
        }
        if character == '\n' || character == '\t' || !character.is_control() {
            text.push(character);
        }
    }
    KubernetesText { text, truncated }
}

fn bounded_text(value: &str, maximum_chars: usize) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(maximum_chars)
        .collect()
}

fn validate_row_limit(maximum_rows: usize) -> CoreResult<()> {
    if !(1..=MAX_ROWS).contains(&maximum_rows) {
        return Err(validation(
            "Kubernetes row limit",
            format!("must be between 1 and {MAX_ROWS}"),
        ));
    }
    Ok(())
}

const POD_EXEC_STATUS: &str = "lovelyhawk-exec-status=";

/// The largest pod file shown: comfortably under the command output bound.
pub const MAX_POD_FILE_BYTES: usize = 1024 * 1024;

/// `kubectl exec` into a pod's chosen container (its default one when
/// none is named), up to and including `--`.
fn pod_exec(pod: &KubernetesPod, container: Option<&str>) -> String {
    let named = container
        .map(|container| format!(" -c {}", shq(container)))
        .unwrap_or_default();
    format!(
        "kubectl exec {} -n {}{named} --",
        shq(&pod.name),
        shq(&pod.namespace)
    )
}

/// The container an operator chose, when it is one of the listed pod's app
/// containers. None means kubectl's own default; any other name is refused
/// before anything runs.
pub fn chosen_pod_container<'a>(
    pod: &KubernetesPod,
    container: Option<&'a str>,
) -> CoreResult<Option<&'a str>> {
    match container {
        None => Ok(None),
        Some(name) => {
            validate_dns_label("Kubernetes container name", name)?;
            if pod.container(name).is_none() {
                return Err(validation(
                    "Kubernetes pod container",
                    "这个 Pod 里没有这个容器",
                ));
            }
            Ok(Some(name))
        }
    }
}

/// A pod file copied onto the SSH host and checked against the file in the
/// pod before and after the copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodFileStage {
    pub host_path: String,
    pub bytes: u64,
    pub sha256: String,
    /// The pod's UID, from the list, re-checked before the copy.
    pub pod_uid: String,
    /// The container the copy came from: the one chosen, or the pod's default.
    pub container: Option<String>,
    /// The kubeconfig context kubectl used, as it printed it (bounded).
    pub context: String,
    pub copied_at: chrono::DateTime<chrono::Utc>,
}

/// The `pod` section of a pod file's evidence manifest: where the bytes came
/// from and how they were checked, readable without this program.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PodFileEvidenceContext {
    pub tool: String,
    pub kube_context: String,
    pub namespace: String,
    pub pod: String,
    pub pod_uid: String,
    pub container: Option<String>,
    pub path: String,
    pub copied_at: chrono::DateTime<chrono::Utc>,
    pub pod_bytes: u64,
    pub pod_sha256: String,
    pub host_temporary_path: String,
    pub host_temporary_removed: bool,
    pub limitations: String,
}

pub fn new_pod_file_stage_path() -> String {
    format!("{POD_FILE_STAGE_PREFIX}{}.bin", uuid::Uuid::new_v4())
}

pub fn is_managed_pod_file_stage_path(path: &str) -> bool {
    stage_id(path).is_some()
}

fn stage_id(path: &str) -> Option<&str> {
    path.strip_prefix(POD_FILE_STAGE_PREFIX)
        .and_then(|rest| rest.strip_suffix(".bin"))
        .filter(|id| {
            uuid::Uuid::parse_str(id).is_ok_and(|uuid| uuid.hyphenated().to_string() == *id)
        })
}

/// A pod file's text with the length and SHA-256 it was checked against.
#[derive(Clone, PartialEq, Eq)]
pub struct PodFileContent {
    pub path: ContainerFilePath,
    pub text: String,
    pub bytes: u64,
    pub sha256: String,
}

impl std::fmt::Debug for PodFileContent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PodFileContent")
            .field("path", &self.path)
            .field("bytes", &self.bytes)
            .field("sha256", &self.sha256)
            .finish_non_exhaustive()
    }
}

/// What the shell probe's run of `kubectl exec` came to.
///
/// Only a clean exit is read for a shell. A failed one is sorted by the words
/// kubectl and the runtime use — the API server's `Forbidden` for RBAC, the
/// runtime's "no such file" naming /bin/sh for a shell-less image — because
/// the operator's next step differs: ask for exec rights, or use another way
/// in. Anything else is reported as kubectl failing, not guessed at.
fn classify_pod_shell_probe(output: &str) -> CoreResult<ContainerShell> {
    let status = output
        .lines()
        .rev()
        .find_map(|line| line.trim().strip_prefix(POD_EXEC_STATUS))
        .and_then(|value| value.parse::<i32>().ok());
    match status {
        Some(0) => parse_shell_probe(output),
        Some(_) => {
            let lowered = output.to_ascii_lowercase();
            if lowered.contains("forbidden") && lowered.contains("pods/exec") {
                Err(validation(
                    "Kubernetes pod exec",
                    "当前账号没有在这个 Pod 里执行命令（pods/exec）的权限",
                ))
            } else if lowered.contains("/bin/sh")
                && (lowered.contains("no such file") || lowered.contains("not found"))
            {
                parse_shell_probe("")
            } else {
                Err(validation(
                    "Kubernetes command",
                    "kubectl exec failed for a reason other than permissions or a missing shell",
                ))
            }
        }
        None => Err(validation(
            "Kubernetes command",
            "the pod shell probe did not report how kubectl exec ended",
        )),
    }
}

fn ensure_pod_open_for_shell(
    pod: &KubernetesPod,
    probe: &str,
    container: Option<&str>,
) -> CoreResult<()> {
    let mut fields = probe.trim_end_matches(['\r', '\n']).split('\t');
    let uid = fields.next().unwrap_or_default();
    let phase = fields.next().unwrap_or_default();
    let deleting = fields.next().unwrap_or_default();
    let statuses = fields.next().unwrap_or_default();
    if uid.is_empty() || pod.id != KubernetesRowId(format!("pod:{uid}")) {
        return Err(validation(
            "Kubernetes pod shell",
            "这个 Pod 已经不是列表里的那一个（被删除或重建过），请刷新后再开终端",
        ));
    }
    if !deleting.is_empty() {
        return Err(validation(
            "Kubernetes pod shell",
            "这个 Pod 正在被删除，不再打开终端",
        ));
    }
    if phase != "Running" {
        return Err(validation(
            "Kubernetes pod shell",
            "只有运行中的 Pod 能打开终端",
        ));
    }
    // A pod runs while one of its containers crashes and restarts: the one
    // chosen must itself be running now.
    if let Some(container) = container {
        let running = statuses.split(' ').any(|entry| {
            entry
                .split_once('=')
                .is_some_and(|(name, started)| name == container && !started.is_empty())
        });
        if !running {
            return Err(validation(
                "Kubernetes pod container",
                "所选的容器现在没有在运行（可能正在重启或已经退出），请刷新后再试",
            ));
        }
    }
    Ok(())
}

/// How long closing a pod shell waits for its leftovers to be ended.
const POD_SESSION_CLEANUP_TIMEOUT: Duration = Duration::from_secs(15);

/// An interactive shell in one pod, bound to the target it was opened on.
pub struct KubernetesTerminalSession {
    namespace: String,
    pod: String,
    shell: ContainerShell,
    guard: TargetGuard,
    target: Arc<TargetContext>,
    inner: SshTerminalSession,
    ssh: SshService,
    session: BoundSshSession,
    cleanup: String,
}

impl std::fmt::Debug for KubernetesTerminalSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KubernetesTerminalSession")
            .field("namespace", &self.namespace)
            .field("pod", &self.pod)
            .field("shell", &self.shell)
            .field("guard", &self.guard)
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

impl KubernetesTerminalSession {
    pub const fn shell(&self) -> ContainerShell {
        self.shell
    }

    pub fn terminal_id(&self) -> &str {
        self.inner.terminal_id()
    }

    pub async fn recv(&self) -> CoreResult<TerminalEvent> {
        self.inner.recv().await
    }
}

#[async_trait]
impl TerminalTransport for KubernetesTerminalSession {
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
        // Best effort and bounded, as for a container: the pod may be gone or
        // the connection lost, and closing still succeeds.
        let _ = self
            .ssh
            .execute_bound(
                &self.session,
                self.cleanup.clone(),
                POD_SESSION_CLEANUP_TIMEOUT,
            )
            .await;
        closed
    }
}

/// A pod named the way a shell command may name it: a DNS-1123 label for the
/// namespace and a DNS-1123 subdomain for the pod, as the API server enforces.
pub(crate) fn validate_pod_reference(namespace: &str, pod: &str) -> CoreResult<()> {
    validate_dns_label("Kubernetes namespace", namespace)?;
    validate_dns_subdomain("Kubernetes pod name", pod)
}

pub(crate) fn validate_container_name(container: &str) -> CoreResult<()> {
    validate_dns_label("Kubernetes container name", container)
}

fn validate_dns_label(subject: &'static str, value: &str) -> CoreResult<()> {
    if value.is_empty() || value.len() > 63 || !is_dns1123(value) {
        return Err(validation(
            subject,
            "must be a lowercase DNS-1123 label of at most 63 bytes",
        ));
    }
    Ok(())
}

fn validate_dns_subdomain(subject: &'static str, value: &str) -> CoreResult<()> {
    if value.is_empty()
        || value.len() > 253
        || value
            .split('.')
            .any(|label| label.is_empty() || label.len() > 63 || !is_dns1123(label))
    {
        return Err(validation(
            subject,
            "must be a lowercase DNS-1123 subdomain of at most 253 bytes",
        ));
    }
    Ok(())
}

fn is_dns1123(value: &str) -> bool {
    let valid = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-';
    value.bytes().all(valid)
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn validation(subject: &'static str, message: impl Into<String>) -> CoreError {
    CoreError::Validation {
        subject,
        message: message.into(),
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(bound(deserialize = "T: Deserialize<'de>"))]
struct RawList<T> {
    #[serde(default)]
    items: Vec<T>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct RawMetadata {
    uid: String,
    resource_version: String,
    generation: Option<u64>,
    name: String,
    namespace: String,
    creation_timestamp: String,
    labels: BTreeMap<String, String>,
    annotations: BTreeMap<String, String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawNamespace {
    metadata: RawMetadata,
    status: RawNamespaceStatus,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawNamespaceStatus {
    phase: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawPod {
    metadata: RawMetadata,
    spec: RawPodSpec,
    status: RawPodStatus,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct RawPodSpec {
    node_name: String,
    containers: Vec<RawContainer>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawContainer {
    name: String,
    image: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct RawPodStatus {
    phase: String,
    /// Not `podIp`. Kubernetes writes `podIP`, with both letters capital, and
    /// camelCase would quietly produce the wrong name and leave every running
    /// pod looking as if it had no address at all.
    #[serde(rename = "podIP")]
    pod_ip: String,
    container_statuses: Vec<RawContainerStatus>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct RawContainerStatus {
    name: String,
    ready: bool,
    restart_count: u64,
    state: RawContainerState,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawContainerState {
    waiting: Option<RawWaitingState>,
    running: Option<serde_json::Value>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawWaitingState {
    reason: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawDeployment {
    metadata: RawMetadata,
    spec: RawDeploymentSpec,
    status: RawDeploymentStatus,
}

impl RawDeployment {
    fn snapshot(&self) -> CoreResult<KubernetesMutationSnapshot> {
        Ok(KubernetesMutationSnapshot::Deployment {
            uid: self.metadata.uid.clone(),
            resource_version: self.metadata.resource_version.clone(),
            generation: self.metadata.generation,
            replicas: self.spec.replicas.ok_or_else(|| {
                validation("Kubernetes deployment snapshot", "replica count is missing")
            })?,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
enum DeploymentHealth {
    Ready,
    Pending(String),
    Failed(String),
}

fn deployment_health(raw: &RawDeployment) -> DeploymentHealth {
    let Some(generation) = raw.metadata.generation.filter(|value| *value > 0) else {
        return DeploymentHealth::Failed("缺少 Deployment 配置版本，无法验证就绪状态".to_owned());
    };
    if raw
        .status
        .observed_generation
        .is_none_or(|observed| observed < generation)
    {
        return DeploymentHealth::Pending("控制器尚未处理本次配置".to_owned());
    }
    let status = &raw.status;
    let Some(desired) = raw.spec.replicas else {
        return DeploymentHealth::Failed("缺少 Deployment 副本数，无法验证就绪状态".to_owned());
    };
    let ready = status.replicas == desired
        && status.updated_replicas == desired
        && status.ready_replicas == desired
        && status.available_replicas == desired;
    // Scaling a failed workload to zero is a valid containment action. Its
    // old rollout failure must not cause the workload to be started again.
    if ready && desired == 0 {
        return DeploymentHealth::Ready;
    }
    if desired == 0 {
        return DeploymentHealth::Pending(format!(
            "停止状态尚未完成，当前副本 {}；不会自动重新启动副本",
            status.replicas
        ));
    }
    if raw.status.conditions.iter().any(|condition| {
        condition.kind == "Progressing"
            && condition.status == "False"
            && condition.reason == "ProgressDeadlineExceeded"
    }) {
        return DeploymentHealth::Failed(
            "Deployment 超过集群设置的进展期限，请检查镜像拉取、资源配额与就绪探针".to_owned(),
        );
    }
    if raw
        .status
        .conditions
        .iter()
        .any(|condition| condition.kind == "ReplicaFailure" && condition.status == "True")
    {
        return DeploymentHealth::Failed(
            "Deployment 副本创建失败，请检查资源配额、权限与调度条件".to_owned(),
        );
    }
    if ready {
        DeploymentHealth::Ready
    } else {
        DeploymentHealth::Pending(format!(
            "期望 {desired}，当前 {}，已更新 {}，就绪 {}，可用 {}",
            status.replicas,
            status.updated_replicas,
            status.ready_replicas,
            status.available_replicas
        ))
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawDeploymentSpec {
    replicas: Option<u64>,
    template: RawPodTemplate,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawPodTemplate {
    spec: RawPodSpec,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct RawDeploymentStatus {
    observed_generation: Option<u64>,
    replicas: u64,
    ready_replicas: u64,
    available_replicas: u64,
    updated_replicas: u64,
    conditions: Vec<RawDeploymentCondition>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawDeploymentCondition {
    #[serde(rename = "type")]
    kind: String,
    status: String,
    reason: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawNode {
    metadata: RawMetadata,
    spec: RawNodeSpec,
    status: RawNodeStatus,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawNodeSpec {
    unschedulable: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct RawNodeStatus {
    conditions: Vec<RawNodeCondition>,
    addresses: Vec<RawNodeAddress>,
    node_info: RawNodeInfo,
    capacity: BTreeMap<String, String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct RawNodeCondition {
    #[serde(rename = "type")]
    kind: String,
    status: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct RawNodeAddress {
    #[serde(rename = "type")]
    kind: String,
    address: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct RawNodeInfo {
    kubelet_version: String,
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use chrono::Utc;
    use uuid::Uuid;

    use crate::{
        BackendServices, PortableStore,
        ssh::{BoundSshSession, SshConnectionStatus, TestSessionHarness},
        target::TargetIdentity,
    };

    use super::*;

    fn identity(value: &str) -> TargetIdentity {
        TargetIdentity::new(value).unwrap()
    }

    #[derive(Debug)]
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("lovelyres-kubernetes-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    async fn test_services() -> (
        TestRoot,
        BackendServices,
        Arc<TestSessionHarness>,
        BoundSshSession,
    ) {
        let root = TestRoot::new();
        let services =
            BackendServices::new(PortableStore::prepare(root.0.clone()).unwrap()).unwrap();
        let guard = services
            .activate_target(TargetIdentity::new("connection-k8s").unwrap())
            .unwrap();
        let status = SshConnectionStatus {
            session_id: "session-k8s".to_owned(),
            connection_id: "connection-k8s".to_owned(),
            host: "k8s.test".to_owned(),
            port: 22,
            username: "operator".to_owned(),
            host_key_fingerprint: "SHA256:k8s".to_owned(),
            connected_at: Utc::now(),
        };
        let session =
            BoundSshSession::from_status(guard, &status, "Kubernetes test session").unwrap();
        let harness = Arc::new(TestSessionHarness::default());
        services
            .ssh()
            .install_test_session(status, harness.clone())
            .await
            .unwrap();
        (root, services, harness, session)
    }

    fn shell_pod(uid: &str) -> KubernetesPod {
        KubernetesPod {
            id: KubernetesRowId(format!("pod:{uid}")),
            namespace: "incident".to_owned(),
            name: "api-7f98d".to_owned(),
            phase: "Running".to_owned(),
            ready_containers: 1,
            total_containers: 1,
            restarts: 0,
            node: "node-a".to_owned(),
            pod_ip: "10.0.0.8".to_owned(),
            images: vec!["api:1".to_owned(), "proxy:1".to_owned()],
            created_at: "now".to_owned(),
            containers: vec![
                KubernetesPodContainer {
                    name: "api".to_owned(),
                    image: "api:1".to_owned(),
                    ready: true,
                    running: true,
                    restarts: 0,
                },
                KubernetesPodContainer {
                    name: "sidecar".to_owned(),
                    image: "proxy:1".to_owned(),
                    ready: true,
                    running: true,
                    restarts: 0,
                },
            ],
            default_container: Some("api".to_owned()),
        }
    }

    fn pod_terminal_id() -> String {
        format!("pod-{}", Uuid::new_v4())
    }

    #[tokio::test]
    async fn a_pod_shell_runs_the_detected_shell_and_ends_what_it_started_on_close() {
        let (_root, services, harness, session) = test_services().await;
        harness.set_execute_outputs([
            "pod-uid-1\tRunning\t",
            "Defaulted container \"api\" out of: api, sidecar\nash\nlovelyhawk-exec-status=0\n",
            "pod-uid-1\tRunning\t",
        ]);
        let pod = shell_pod("pod-uid-1");
        let shell = services
            .kubernetes()
            .detect_shell(&session, &pod, None)
            .await
            .unwrap();
        assert_eq!(shell, ContainerShell::Ash);
        let requested = pod_terminal_id();
        let terminal = services
            .kubernetes()
            .open_terminal(&session, &pod, None, shell, requested.clone(), 120, 40)
            .await
            .unwrap();
        assert_eq!(terminal.terminal_id(), requested);
        assert_eq!(terminal.shell(), ContainerShell::Ash);

        let commands = harness.execute_commands();
        assert!(commands[0].starts_with("kubectl get pod 'api-7f98d' -n 'incident' -o jsonpath="));
        assert!(commands[1].starts_with("kubectl exec 'api-7f98d' -n 'incident' -- /bin/sh -c "));
        // Checked again right before the shell opens, not only before the probe.
        assert!(commands[2].starts_with("kubectl get pod 'api-7f98d' -n 'incident' -o jsonpath="));
        let launches = harness.terminal_launches();
        assert_eq!(launches.len(), 1);
        let prefix =
            "kubectl exec -it 'api-7f98d' -n 'incident' -- /bin/ash -c 'LOVELYHAWK_TERMINAL=";
        let suffix = "; export LOVELYHAWK_TERMINAL; exec /bin/ash'";
        assert!(
            launches[0].starts_with(prefix) && launches[0].ends_with(suffix),
            "{}",
            launches[0]
        );
        let marker = &launches[0][prefix.len()..launches[0].len() - suffix.len()];
        assert!(marker.len() == 32 && marker.bytes().all(|byte| byte.is_ascii_hexdigit()));

        TerminalTransport::close(&terminal).await.unwrap();
        let cleanup = harness
            .execute_commands()
            .into_iter()
            .find(|command| command.contains(marker))
            .expect("a cleanup exec after close");
        assert!(cleanup.starts_with("kubectl exec 'api-7f98d' -n 'incident' -- /bin/sh -c "));
        assert!(cleanup.contains("kill -HUP") && cleanup.contains("kill -KILL"));
    }

    fn pod_manifest(uid: &str, namespace: &str) -> String {
        format!(
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: api-7f98d\n  namespace: {namespace}\n  \
             ownerReferences:\n  - apiVersion: apps/v1\n    kind: ReplicaSet\n    uid: owner-uid\n  \
             resourceVersion: \"4242\"\n  uid: {uid}\nspec:\n  containers:\n  - name: api\n    \
             env:\n    - name: DB_PASSWORD\n      value: hunter2\nstatus:\n  phase: Running\n"
        )
    }

    fn manifest_output(yaml: &str, status: u8) -> String {
        format!("{yaml}\n{MANIFEST_MARKER}\t{status}\tlab-k3s\n")
    }

    /// The manifest is the listed pod's own YAML exactly as kubectl printed
    /// it — every field, the clear-text value an operator may need to see
    /// included — with the identity taken from the pod's own metadata, not
    /// from an owner reference that also says `uid:`.
    #[tokio::test]
    async fn a_manifest_is_the_listed_objects_own_yaml_as_printed() {
        let (_root, services, harness, session) = test_services().await;
        let yaml = pod_manifest("pod-uid-1", "incident");
        harness.set_execute_outputs([manifest_output(&yaml, 0)]);
        let pod = shell_pod("pod-uid-1");
        let manifest = services
            .kubernetes()
            .object_manifest(&session, &KubernetesManifestObject::Pod(pod))
            .await
            .unwrap();
        assert_eq!(manifest.yaml, yaml);
        assert_eq!(manifest.kind, "Pod");
        assert_eq!(manifest.uid, "pod-uid-1");
        assert_eq!(manifest.resource_version, "4242");
        assert_eq!(manifest.context, "lab-k3s");
        assert_eq!(manifest.namespace.as_deref(), Some("incident"));
        let commands = harness.execute_commands();
        assert_eq!(commands.len(), 1);
        // stderr kept out of the YAML; names quoted; no write verb anywhere.
        assert!(
            commands[0].starts_with(
                "kubectl get pod 'api-7f98d' -n 'incident' -o yaml 2>/dev/null; status=$?;"
            ),
            "{}",
            commands[0]
        );

        // A node has no namespace, and none is passed.
        let (_root, services, harness, session) = test_services().await;
        let node_yaml = "apiVersion: v1\nkind: Node\nmetadata:\n  name: worker-1\n  resourceVersion: \"9\"\n  uid: node-uid\nspec: {}\n";
        harness.set_execute_outputs([manifest_output(node_yaml, 0)]);
        let manifest = services
            .kubernetes()
            .object_manifest(&session, &KubernetesManifestObject::Node(node_row(false)))
            .await
            .unwrap();
        assert_eq!((manifest.kind, manifest.namespace), ("Node", None));
        assert!(
            harness.execute_commands()[0]
                .starts_with("kubectl get node 'worker-1' -o yaml 2>/dev/null;")
        );
    }

    /// Recreated under the same name, moved, or a different kind: not the
    /// object the operator picked, so nothing is handed back to keep.
    #[tokio::test]
    async fn a_manifest_that_is_not_the_listed_object_is_refused() {
        for yaml in [
            pod_manifest("pod-uid-2", "incident"),
            pod_manifest("pod-uid-1", "other"),
            pod_manifest("pod-uid-1", "incident").replace("kind: Pod", "kind: Service"),
            // The only uid is an owner reference's.
            pod_manifest("", "incident").replace("  uid: \n", ""),
        ] {
            let (_root, services, harness, session) = test_services().await;
            harness.set_execute_outputs([manifest_output(&yaml, 0)]);
            let refused = services
                .kubernetes()
                .object_manifest(
                    &session,
                    &KubernetesManifestObject::Pod(shell_pod("pod-uid-1")),
                )
                .await;
            assert!(
                matches!(
                    &refused,
                    Err(CoreError::Validation {
                        subject: "Kubernetes manifest",
                        ..
                    })
                ),
                "{refused:?}"
            );
        }
    }

    /// kubectl failing is asked about once more, with its stderr, so a
    /// refusal reads as a permission problem rather than a broken read; and a
    /// manifest past the limit is refused, not cut.
    #[tokio::test]
    async fn a_refused_or_oversized_manifest_says_so() {
        let (_root, services, harness, session) = test_services().await;
        harness.set_execute_outputs([
            manifest_output("", 1),
            "<exit 1>Error from server (Forbidden): pods \"api-7f98d\" is forbidden: User \"x\" cannot get resource".to_owned(),
        ]);
        let refused = services
            .kubernetes()
            .object_manifest(
                &session,
                &KubernetesManifestObject::Deployment(deployment_row(2)),
            )
            .await;
        assert!(
            matches!(
                &refused,
                Err(CoreError::Validation {
                    subject: "Kubernetes permission",
                    ..
                })
            ),
            "{refused:?}"
        );
        let commands = harness.execute_commands();
        assert_eq!(
            commands[1],
            "kubectl get deployment 'api' -n 'incident' -o name"
        );

        let (_root, services, harness, session) = test_services().await;
        let huge = format!(
            "{}{}",
            pod_manifest("pod-uid-1", "incident"),
            "#".repeat(MAX_MANIFEST_BYTES)
        );
        harness.set_execute_outputs([manifest_output(&huge, 0)]);
        let refused = services
            .kubernetes()
            .object_manifest(
                &session,
                &KubernetesManifestObject::Pod(shell_pod("pod-uid-1")),
            )
            .await;
        assert!(
            matches!(&refused, Err(CoreError::Validation { message, .. }) if message.contains("上限")),
            "{refused:?}"
        );
    }

    #[tokio::test]
    async fn a_pod_shell_is_refused_for_a_replaced_deleting_or_stopped_pod() {
        for probe in [
            // Recreated under the same name: a different pod.
            "pod-uid-2\tRunning\t",
            "pod-uid-1\tRunning\t2026-10-11T10:00:00Z",
            "pod-uid-1\tPending\t",
            "pod-uid-1\tSucceeded\t",
            "",
        ] {
            let (_root, services, harness, session) = test_services().await;
            harness.set_execute_outputs([probe, "bash\nlovelyhawk-exec-status=0\n"]);
            let detected = services
                .kubernetes()
                .detect_shell(&session, &shell_pod("pod-uid-1"), None)
                .await;
            assert!(detected.is_err(), "{probe:?}");
            // Nothing ran inside the pod: the probe stopped at the check.
            assert_eq!(harness.execute_commands().len(), 1, "{probe:?}");

            let (_root, services, harness, session) = test_services().await;
            harness.set_execute_outputs([probe]);
            let opened = services
                .kubernetes()
                .open_terminal(
                    &session,
                    &shell_pod("pod-uid-1"),
                    None,
                    ContainerShell::Bash,
                    pod_terminal_id(),
                    80,
                    24,
                )
                .await;
            assert!(opened.is_err(), "{probe:?}");
            assert!(harness.terminal_launches().is_empty(), "{probe:?}");
        }

        // A pod with no shell at all (a distroless image) has nothing to open.
        let (_root, services, harness, session) = test_services().await;
        harness.set_execute_outputs(["pod-uid-1\tRunning\t", ""]);
        assert!(
            services
                .kubernetes()
                .detect_shell(&session, &shell_pod("pod-uid-1"), None)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_pod_directory_is_listed_in_the_same_pod_and_without_kubectl_notices() {
        let (_root, services, harness, session) = test_services().await;
        harness.set_execute_outputs([
            "pod-uid-1\tRunning\t",
            "lovelyhawk-dir=ok/\nd 4096 1 755 conf.d/\nf 12 2 644 hosts/\nlovelyhawk-end/\n",
        ]);
        let listing = services
            .kubernetes()
            .list_directory(
                &session,
                &shell_pod("pod-uid-1"),
                None,
                &RemotePath::new("/etc").unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(listing.entries.len(), 2);
        assert_eq!(listing.entries[0].name, "conf.d");
        let commands = harness.execute_commands();
        assert!(commands[0].starts_with("kubectl get pod 'api-7f98d'"));
        assert!(commands[1].starts_with("kubectl exec 'api-7f98d' -n 'incident' -- /bin/sh -c '"));
        assert!(commands[1].ends_with(" lovelyhawk-list '/etc' 2>/dev/null"));

        // A replaced pod is not listed at all.
        let (_root, services, harness, session) = test_services().await;
        harness.set_execute_outputs(["pod-uid-2\tRunning\t"]);
        assert!(
            services
                .kubernetes()
                .list_directory(
                    &session,
                    &shell_pod("pod-uid-1"),
                    None,
                    &RemotePath::new("/").unwrap()
                )
                .await
                .is_err()
        );
        assert_eq!(harness.execute_commands().len(), 1);
    }

    #[tokio::test]
    async fn a_pod_file_is_shown_only_when_its_text_matches_the_length_and_digest_both_times() {
        let text = "127.0.0.1 localhost\n";
        let marker = format!("file\t{}\t{}\n", sha256_hex(text.as_bytes()), text.len());
        let path = ContainerFilePath::new("/etc/hosts").unwrap();

        let (_root, services, harness, session) = test_services().await;
        harness.set_execute_outputs([
            "pod-uid-1\tRunning\t",
            marker.as_str(),
            text,
            marker.as_str(),
        ]);
        let file = services
            .kubernetes()
            .read_file(&session, &shell_pod("pod-uid-1"), None, &path)
            .await
            .unwrap();
        assert_eq!(file.text, text);
        assert_eq!(file.bytes, text.len() as u64);
        let commands = harness.execute_commands();
        assert!(commands[1].starts_with("kubectl exec 'api-7f98d' -n 'incident' -- sh -c '"));
        assert_eq!(
            commands[2],
            "kubectl exec 'api-7f98d' -n 'incident' -- cat '/etc/hosts' 2>/dev/null"
        );
        // The text never reaches Debug output.
        assert!(!format!("{file:?}").contains("localhost"));

        // Changed between the two looks, or not what the digest said: refused.
        let other = format!("file\t{}\t{}\n", sha256_hex(b"changed"), 7);
        for outputs in [
            vec![
                "pod-uid-1\tRunning\t",
                marker.as_str(),
                text,
                other.as_str(),
            ],
            vec![
                "pod-uid-1\tRunning\t",
                marker.as_str(),
                "tampered text here\n",
                marker.as_str(),
            ],
            vec!["pod-uid-1\tRunning\t", "missing\n"],
        ] {
            let (_root, services, harness, session) = test_services().await;
            harness.set_execute_outputs(outputs.clone());
            assert!(
                services
                    .kubernetes()
                    .read_file(&session, &shell_pod("pod-uid-1"), None, &path)
                    .await
                    .is_err(),
                "{outputs:?}"
            );
        }

        // Too large to show is refused before any text is read.
        let (_root, services, harness, session) = test_services().await;
        let huge = format!("file\t{}\t{}\n", "a".repeat(64), MAX_POD_FILE_BYTES + 1);
        harness.set_execute_outputs(["pod-uid-1\tRunning\t", huge.as_str()]);
        assert!(
            services
                .kubernetes()
                .read_file(&session, &shell_pod("pod-uid-1"), None, &path)
                .await
                .is_err()
        );
        assert_eq!(harness.execute_commands().len(), 2);
    }

    #[test]
    fn a_failed_shell_probe_says_whether_exec_was_refused_or_there_is_no_shell() {
        let subject = |output: &str| match classify_pod_shell_probe(output) {
            Ok(shell) => shell.label(),
            Err(CoreError::Validation { subject, .. }) => subject,
            Err(other) => panic!("{other:?}"),
        };
        assert_eq!(subject("bash\nlovelyhawk-exec-status=0\n"), "bash");
        // Exactly what k3s/containerd printed for coredns, which is distroless.
        assert_eq!(
            subject(
                "error: Internal error occurred: error executing command in container: failed to exec in container: \
                 failed to start exec \"93ee45c5\": OCI runtime exec failed: exec failed: unable to start container \
                 process: exec: \"/bin/sh\": stat /bin/sh: no such file or directory: unknown\n\
                 lovelyhawk-exec-status=1\n"
            ),
            "container shell"
        );
        assert_eq!(
            subject(
                "Error from server (Forbidden): pods \"api\" is forbidden: User \"system:serviceaccount:ops:viewer\" \
                 cannot create resource \"pods/exec\" in API group \"\" in the namespace \"incident\"\n\
                 lovelyhawk-exec-status=1\n"
            ),
            "Kubernetes pod exec"
        );
        // Anything else is kubectl failing, not a guess.
        assert_eq!(
            subject(
                "Unable to connect to the server: dial tcp 10.0.0.1:6443: i/o timeout\nlovelyhawk-exec-status=1\n"
            ),
            "Kubernetes command"
        );
        // A shell name printed by a run that failed is not a shell.
        assert_eq!(
            subject("sh\nlovelyhawk-exec-status=137\n"),
            "Kubernetes command"
        );
        // No status line at all: the probe did not run to the end.
        assert_eq!(subject("bash\n"), "Kubernetes command");
        assert_eq!(subject(""), "Kubernetes command");
    }

    #[test]
    fn an_rbac_refusal_is_named_as_a_permission_only_when_kubectl_ends_with_it() {
        let outcome = |output: &str, exit_code: i32| {
            match validate_command_output(
                "list Kubernetes pods",
                SshCommandOutput {
                    command: String::new(),
                    output: output.to_owned(),
                    exit_code: Some(exit_code),
                    duration_ms: 1,
                    timed_out: false,
                },
            ) {
                Ok(_) => "ok",
                Err(CoreError::Validation { subject, message }) => {
                    // The cluster's own words (user, resource) are not passed on.
                    assert!(!message.contains("viewer"), "{message}");
                    subject
                }
                Err(other) => panic!("{other:?}"),
            }
        };
        // Exactly what k3s printed for a namespace-bound service account.
        let refusal = "Error from server (Forbidden): pods is forbidden: User \
                       \"system:serviceaccount:lh-rbac:viewer\" cannot list resource \"pods\" in API \
                       group \"\" at the cluster scope\n";
        assert_eq!(outcome(refusal, 1), "Kubernetes permission");
        assert_eq!(
            outcome(&format!("Warning: something\n{refusal}\n"), 1),
            "Kubernetes permission"
        );
        // A log line that only reads like one, followed by kubectl's own failure.
        assert_eq!(
            outcome(&format!("{refusal}error: unexpected EOF\n"), 1),
            "Kubernetes command"
        );
        // The same words in output that succeeded are output.
        assert_eq!(outcome(refusal, 0), "ok");
        assert_eq!(
            outcome("Unable to connect to the server: i/o timeout\n", 1),
            "Kubernetes command"
        );
    }

    #[tokio::test]
    async fn a_listing_or_read_that_fails_asks_the_api_server_whether_exec_is_allowed() {
        let running =
            "pod-uid-1\tRunning\t\tapi=2026-10-12T01:00:00Z sidecar=2026-10-12T01:00:01Z ";
        let pod = shell_pod("pod-uid-1");
        let subject = |result: CoreResult<()>| match result {
            Err(CoreError::Validation { subject, .. }) => subject,
            other => panic!("{other:?}"),
        };

        // The listing drops kubectl's stderr; the follow-up question says no.
        let (_root, services, harness, session) = test_services().await;
        harness.set_execute_outputs([running, "<exit 1>", "<exit 1>no\n"]);
        let listed = services
            .kubernetes()
            .list_directory(&session, &pod, None, &RemotePath::new("/tmp").unwrap())
            .await
            .map(|_| ());
        assert_eq!(subject(listed), "Kubernetes pod exec");
        assert_eq!(
            harness.execute_commands()[2],
            "kubectl auth can-i create 'pods/api-7f98d' --subresource=exec -n 'incident' 2>/dev/null"
        );

        // A file read asks the same after its probe fails.
        let (_root, services, harness, session) = test_services().await;
        harness.set_execute_outputs([running, "<exit 1>", "<exit 1>no\n"]);
        let read = services
            .kubernetes()
            .read_file(
                &session,
                &pod,
                Some("sidecar"),
                &ContainerFilePath::new("/etc/hostname").unwrap(),
            )
            .await
            .map(|_| ());
        assert_eq!(subject(read), "Kubernetes pod exec");

        // Exec is allowed, or the answer is not a plain no: the failure is
        // kept as it was, not turned into a permission problem.
        for answer in [
            "yes\n",
            "<exit 1>",
            "<exit 1>error: the server doesn't have a resource\n",
        ] {
            let (_root, services, harness, session) = test_services().await;
            harness.set_execute_outputs([running, "<exit 1>", answer]);
            let listed = services
                .kubernetes()
                .list_directory(&session, &pod, None, &RemotePath::new("/tmp").unwrap())
                .await
                .map(|_| ());
            assert_eq!(subject(listed), "Kubernetes command", "{answer:?}");
        }

        // A refused re-read of the pod itself is a permission problem, and no
        // exec is attempted after it.
        let (_root, services, harness, session) = test_services().await;
        harness.set_execute_outputs([
            "<exit 1>Error from server (Forbidden): pods \"api-7f98d\" is forbidden\n",
        ]);
        let listed = services
            .kubernetes()
            .list_directory(&session, &pod, None, &RemotePath::new("/tmp").unwrap())
            .await
            .map(|_| ());
        assert_eq!(subject(listed), "Kubernetes permission");
        assert_eq!(harness.execute_commands().len(), 1);
    }

    #[test]
    fn only_a_fresh_uuid_under_the_managed_prefix_is_a_staging_path() {
        let path = new_pod_file_stage_path();
        assert!(is_managed_pod_file_stage_path(&path), "{path}");
        assert_ne!(path, new_pod_file_stage_path());
        for forged in [
            "/tmp/lovelyhawk-podfile-123E4567-E89B-12D3-A456-426614174000.bin",
            "/tmp/lovelyhawk-podfile-123e4567e89b12d3a456426614174000.bin",
            "/tmp/lovelyhawk-podfile-123e4567-e89b-12d3-a456-426614174000.pcap",
            "/tmp/lovelyhawk-podfile-../../etc/passwd.bin",
            "/tmp/lovelyhawk-podfile-123e4567-e89b-12d3-a456-426614174000.bin; rm -rf /",
            "/etc/lovelyhawk-podfile-123e4567-e89b-12d3-a456-426614174000.bin",
            "/tmp/lovelyres-pcap-123e4567-e89b-12d3-a456-426614174000.pcap",
        ] {
            assert!(!is_managed_pod_file_stage_path(forged), "{forged}");
        }
    }

    #[tokio::test]
    async fn a_pod_file_is_copied_to_the_host_only_when_both_sides_agree() {
        let running =
            "pod-uid-1\tRunning\t\tapi=2026-10-12T01:00:00Z sidecar=2026-10-12T01:00:01Z ";
        let digest = "ab".repeat(32);
        let probe = format!("file\t{digest}\t3\n");
        let copied = format!("{POD_FILE_STAGE_MARKER}\t3\t{digest}\tviewer@lab\n");
        let pod = shell_pod("pod-uid-1");
        let path = ContainerFilePath::new("/etc/hostname").unwrap();
        let host_path = new_pod_file_stage_path();
        let id = stage_id(&host_path).unwrap().to_owned();

        let (_root, services, harness, session) = test_services().await;
        harness.set_execute_outputs([running, probe.as_str(), copied.as_str(), probe.as_str()]);
        let stage = services
            .kubernetes()
            .stage_pod_file(&session, &pod, Some("sidecar"), &path, &host_path, 1024)
            .await
            .unwrap();
        assert_eq!((stage.bytes, stage.sha256.as_str()), (3, digest.as_str()));
        assert_eq!(stage.pod_uid, "pod-uid-1");
        assert_eq!(stage.container.as_deref(), Some("sidecar"));
        assert_eq!(stage.context, "viewer@lab");
        let commands = harness.execute_commands();
        // Created exclusively, in the chosen container, marked for a cancel.
        assert!(
            commands[2].starts_with("umask 077; set -C; "),
            "{}",
            commands[2]
        );
        assert!(
            commands[2].contains(&format!(
                "{POD_FILE_STAGE_ENV}='{id}' kubectl exec 'api-7f98d' -n 'incident' -c 'sidecar' -- cat -- '/etc/hostname' > \"$dest\""
            )),
            "{}",
            commands[2]
        );
        assert!(commands[2].contains(&format!("dest='{host_path}'")));
        assert_eq!(commands.len(), 4);

        // The file changed while it was copied: refused, and the copy removed.
        let (_root, services, harness, session) = test_services().await;
        let later = format!("file\t{}\t4\n", "cd".repeat(32));
        harness.set_execute_outputs([running, probe.as_str(), copied.as_str(), later.as_str(), ""]);
        let changed = services
            .kubernetes()
            .stage_pod_file(&session, &pod, None, &path, &host_path, 1024)
            .await;
        assert!(
            matches!(&changed, Err(CoreError::Validation { subject: "Kubernetes pod file", message }) if message.contains("变")),
            "{changed:?}"
        );
        let cleanup = harness.execute_commands().last().unwrap().clone();
        assert!(
            cleanup.contains(&format!("'{POD_FILE_STAGE_ENV}={id}'")),
            "{cleanup}"
        );
        assert!(
            cleanup.contains(&format!("dest='{host_path}'")),
            "{cleanup}"
        );

        // A copy whose bytes differ from the pod's is refused the same way.
        let (_root, services, harness, session) = test_services().await;
        let other = format!(
            "{POD_FILE_STAGE_MARKER}\t3\t{}\tviewer@lab\n",
            "ef".repeat(32)
        );
        harness.set_execute_outputs([running, probe.as_str(), other.as_str(), probe.as_str(), ""]);
        assert!(
            services
                .kubernetes()
                .stage_pod_file(&session, &pod, None, &path, &host_path, 1024)
                .await
                .is_err()
        );

        // The copy itself failed: reported, and the leftovers removed.
        let (_root, services, harness, session) = test_services().await;
        let failed = format!("{POD_FILE_STAGE_FAILED}\tcopy\n");
        harness.set_execute_outputs([running, probe.as_str(), failed.as_str(), ""]);
        let refused = services
            .kubernetes()
            .stage_pod_file(&session, &pod, None, &path, &host_path, 1024)
            .await;
        assert!(
            matches!(
                &refused,
                Err(CoreError::Validation {
                    subject: "Kubernetes pod file copy",
                    ..
                })
            ),
            "{refused:?}"
        );
        assert_eq!(harness.execute_commands().len(), 4);

        // Missing or over the limit: nothing is copied at all.
        for (state, limit, wanted) in [
            ("missing\n".to_owned(), 1024, "不存在"),
            (probe.clone(), 2, "上限"),
        ] {
            let (_root, services, harness, session) = test_services().await;
            harness.set_execute_outputs([running, state.as_str()]);
            let result = services
                .kubernetes()
                .stage_pod_file(&session, &pod, None, &path, &host_path, limit)
                .await;
            assert!(
                matches!(&result, Err(CoreError::Validation { message, .. }) if message.contains(wanted)),
                "{result:?}"
            );
            assert_eq!(harness.execute_commands().len(), 2);
        }

        // A path that is not a managed staging path runs nothing.
        let (_root, services, harness, session) = test_services().await;
        for forged in ["/tmp/x.bin", "/etc/passwd"] {
            assert!(
                services
                    .kubernetes()
                    .stage_pod_file(&session, &pod, None, &path, forged, 1024)
                    .await
                    .is_err()
            );
            assert!(
                services
                    .kubernetes()
                    .remove_pod_file_stage(&session, forged)
                    .await
                    .is_err()
            );
        }
        assert!(harness.execute_commands().is_empty());
    }

    #[tokio::test]
    async fn a_pod_shell_names_nothing_that_was_not_a_kubernetes_name() {
        let (_root, services, harness, session) = test_services().await;
        harness.set_execute_outputs(["pod-uid-1\tRunning\t", "bash\nlovelyhawk-exec-status=0\n"]);
        for (namespace, name) in [
            ("incident; id", "api"),
            ("incident", "api$(id)"),
            ("Incident", "api"),
        ] {
            let mut pod = shell_pod("pod-uid-1");
            pod.namespace = namespace.to_owned();
            pod.name = name.to_owned();
            assert!(
                services
                    .kubernetes()
                    .detect_shell(&session, &pod, None)
                    .await
                    .is_err()
            );
            assert!(
                services
                    .kubernetes()
                    .open_terminal(
                        &session,
                        &pod,
                        None,
                        ContainerShell::Sh,
                        pod_terminal_id(),
                        80,
                        24
                    )
                    .await
                    .is_err()
            );
        }
        assert!(harness.execute_commands().is_empty());
        assert!(harness.terminal_launches().is_empty());
        assert!(crate::ssh::pod_session_cleanup_command("incident", "api", None, "short").is_err());
        assert!(
            crate::ssh::pod_session_cleanup_command("incident; id", "api", None, &"a".repeat(32))
                .is_err()
        );
        // A container name is a DNS label like any other name here.
        assert!(
            crate::ssh::pod_session_cleanup_command(
                "incident",
                "api",
                Some("side'car"),
                &"a".repeat(32)
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn a_chosen_container_is_named_in_every_command_and_must_be_one_of_the_pods_running_ones()
    {
        let (_root, services, harness, session) = test_services().await;
        let both = "pod-uid-1\tRunning\t\tapi=2026-10-12T01:00:00Z sidecar=2026-10-12T01:00:01Z ";
        harness.set_execute_outputs([both, "ash\nlovelyhawk-exec-status=0\n", both]);
        let pod = shell_pod("pod-uid-1");
        let shell = services
            .kubernetes()
            .detect_shell(&session, &pod, Some("sidecar"))
            .await
            .unwrap();
        let terminal = services
            .kubernetes()
            .open_terminal(
                &session,
                &pod,
                Some("sidecar"),
                shell,
                pod_terminal_id(),
                80,
                24,
            )
            .await
            .unwrap();
        let commands = harness.execute_commands();
        assert!(
            commands[1]
                .starts_with("kubectl exec 'api-7f98d' -n 'incident' -c 'sidecar' -- /bin/sh -c ")
        );
        let launch = &harness.terminal_launches()[0];
        assert!(
            launch.starts_with(
                "kubectl exec -it 'api-7f98d' -n 'incident' -c 'sidecar' -- /bin/ash -c "
            ),
            "{launch}"
        );
        TerminalTransport::close(&terminal).await.unwrap();
        let cleanup = harness.execute_commands().last().unwrap().clone();
        // Cleanup looks in the container the shell ran in.
        assert!(
            cleanup
                .starts_with("kubectl exec 'api-7f98d' -n 'incident' -c 'sidecar' -- /bin/sh -c "),
            "{cleanup}"
        );

        // Files come from the chosen container too.
        let (_root, services, harness, session) = test_services().await;
        harness.set_execute_outputs([
            both,
            "lovelyhawk-dir=ok/\nf 12 2 644 hosts/\nlovelyhawk-end/\n",
        ]);
        services
            .kubernetes()
            .list_directory(
                &session,
                &pod,
                Some("sidecar"),
                &RemotePath::new("/etc").unwrap(),
            )
            .await
            .unwrap();
        assert!(
            harness.execute_commands()[1]
                .starts_with("kubectl exec 'api-7f98d' -n 'incident' -c 'sidecar' -- ")
        );

        // A name that is not one of this pod's containers runs nothing.
        for name in ["proxy", "Side-Car", "sidecar; id", ""] {
            let (_root, services, harness, session) = test_services().await;
            assert!(
                services
                    .kubernetes()
                    .detect_shell(&session, &pod, Some(name))
                    .await
                    .is_err(),
                "{name:?}"
            );
            assert!(harness.execute_commands().is_empty(), "{name:?}");
        }

        // The pod runs, but the chosen container is restarting: refused after
        // the re-read, before anything runs inside it.
        for statuses in [
            "pod-uid-1\tRunning\t\tapi=2026-10-12T01:00:00Z sidecar= ",
            "pod-uid-1\tRunning\t\tapi=2026-10-12T01:00:00Z ",
        ] {
            let (_root, services, harness, session) = test_services().await;
            harness.set_execute_outputs([statuses]);
            let refused = services
                .kubernetes()
                .detect_shell(&session, &pod, Some("sidecar"))
                .await
                .unwrap_err();
            assert!(
                refused.to_string().contains("所选的容器现在没有在运行"),
                "{refused}"
            );
            assert_eq!(harness.execute_commands().len(), 1, "{statuses:?}");
        }
    }

    #[test]
    fn a_pods_containers_and_its_default_one_are_read_from_the_list() {
        let output = r#"{"items":[{"metadata":{"uid":"u1","name":"web","namespace":"shop",
            "annotations":{"kubectl.kubernetes.io/default-container":"app"}},
          "spec":{"nodeName":"n1","containers":[{"name":"proxy","image":"envoy:1"},{"name":"app","image":"shop:2"}]},
          "status":{"phase":"Running","containerStatuses":[
            {"name":"app","ready":true,"restartCount":0,"state":{"running":{"startedAt":"t"}}},
            {"name":"proxy","ready":false,"restartCount":4,"state":{"waiting":{"reason":"CrashLoopBackOff"}}}]}},
          {"metadata":{"uid":"u2","name":"one","namespace":"shop",
            "annotations":{"kubectl.kubernetes.io/default-container":"gone"}},
          "spec":{"containers":[{"name":"only","image":"x:1"}]},"status":{"phase":"Running"}}]}"#;
        let pods = parse_pods(output, 10).unwrap().items;
        let web = &pods[0];
        assert_eq!(
            web.containers
                .iter()
                .map(|c| (c.name.as_str(), c.ready, c.running, c.restarts))
                .collect::<Vec<_>>(),
            vec![("proxy", false, false, 4), ("app", true, true, 0)]
        );
        // The annotation names the default when it names one of the containers.
        assert_eq!(web.default_container.as_deref(), Some("app"));
        // Otherwise the first container is the default, as for kubectl.
        assert_eq!(pods[1].default_container.as_deref(), Some("only"));
        assert!(web.container("app").is_some() && web.container("sidecar").is_none());
    }

    fn deployment_json(uid: &str, resource_version: &str, replicas: u64) -> String {
        serde_json::json!({
            "metadata": {
                "uid": uid,
                "resourceVersion": resource_version,
                "namespace": "incident",
                "name": "api",
                "generation": 1
            },
            "spec": {"replicas": replicas},
            "status": {"observedGeneration": 1, "replicas": replicas, "updatedReplicas": replicas,
                "readyReplicas": replicas, "availableReplicas": replicas}
        })
        .to_string()
    }

    fn with_generation(document: String, generation: u64) -> String {
        let mut value: serde_json::Value = serde_json::from_str(&document).unwrap();
        value["metadata"]["generation"] = json!(generation);
        value["status"]["observedGeneration"] = json!(generation);
        value.to_string()
    }

    fn with_status(document: String, status: serde_json::Value) -> String {
        let mut value: serde_json::Value = serde_json::from_str(&document).unwrap();
        value["status"] = status;
        value.to_string()
    }

    fn node_json(uid: &str, resource_version: &str, unschedulable: bool) -> String {
        serde_json::json!({
            "metadata": {
                "uid": uid,
                "resourceVersion": resource_version,
                "name": "worker-1"
            },
            "spec": {"unschedulable": unschedulable}
        })
        .to_string()
    }

    fn deployment_row(replicas: u64) -> KubernetesDeployment {
        KubernetesDeployment {
            id: KubernetesRowId("deployment:deployment-uid".to_owned()),
            namespace: "incident".to_owned(),
            name: "api".to_owned(),
            desired_replicas: replicas,
            ready_replicas: replicas,
            available_replicas: replicas,
            updated_replicas: replicas,
            images: vec!["registry/api:1".to_owned()],
            created_at: String::new(),
        }
    }

    fn node_row(unschedulable: bool) -> KubernetesNode {
        KubernetesNode {
            id: KubernetesRowId("node:node-uid".to_owned()),
            name: "worker-1".to_owned(),
            ready: true,
            unschedulable,
            roles: vec!["worker".to_owned()],
            kubelet_version: "v1.34.0".to_owned(),
            internal_ip: "192.0.2.10".to_owned(),
            cpu_capacity: "8".to_owned(),
            memory_capacity: "16Gi".to_owned(),
            pod_capacity: "110".to_owned(),
            created_at: String::new(),
        }
    }

    #[test]
    fn attacker_controlled_names_are_rejected_before_command_construction() {
        for attack in [
            "default;id",
            "prod$(touch /tmp/pwned)",
            "kube-system\n--context=attacker",
            "UPPER",
            "-leading",
            "trailing-",
        ] {
            assert!(KubernetesScope::namespace(attack).is_err());
            assert!(KubernetesPodLogsRequest::recent("default", attack).is_err());
        }
        assert!(
            KubernetesDetailRequest::namespaced(
                KubernetesResourceKind::Pod,
                "default;id",
                "safe-pod",
            )
            .is_err()
        );
    }

    #[test]
    fn typed_detail_and_log_commands_quote_every_dynamic_argument() {
        let detail = KubernetesDetailRequest::namespaced(
            KubernetesResourceKind::Pod,
            "incident-space",
            "api-7f98d",
        )
        .unwrap();
        assert_eq!(
            detail.command(),
            "kubectl describe pod 'api-7f98d' -n 'incident-space'"
        );
        let logs = KubernetesPodLogsRequest::recent("incident-space", "api-7f98d")
            .unwrap()
            .with_container("web")
            .unwrap()
            .with_tail_lines(500)
            .unwrap()
            .with_since_seconds(60)
            .unwrap()
            .with_previous(true);
        let command = logs.command();
        assert!(command.starts_with("kubectl logs 'api-7f98d' -n 'incident-space'"));
        assert!(command.contains(" -c 'web'"));
        assert!(command.contains("--tail=500"));
        assert!(command.contains("--since=60s"));
        assert!(command.ends_with("--previous"));
    }

    #[test]
    fn the_kubelet_refusing_a_log_is_not_taken_for_the_log() {
        let text = |text: &str| KubernetesText {
            text: text.to_owned(),
            truncated: false,
        };
        // Exactly what k3s's kubelet printed, exit 0, for a crash-looping pod
        // whose status still named a container it had already collected.
        let id = "2d9cfaf2d8be65aa74adae85c3b8555b105847ccc24234fbb9d2549fbbd10ef2";
        assert!(
            text(&format!(
                "unable to retrieve container logs for containerd://{id}"
            ))
            .is_kubelet_log_refusal()
        );
        assert!(
            text(&format!(
                "unable to retrieve container logs for cri-o://{id}\n"
            ))
            .is_kubelet_log_refusal()
        );
        assert!(
            text(&format!(
                "unable to retrieve container logs for docker://{}",
                &id[..12]
            ))
            .is_kubelet_log_refusal()
        );

        // A log that says it, among other things, is still a log.
        for log in [
            format!("worker started\nunable to retrieve container logs for containerd://{id}"),
            format!("unable to retrieve container logs for containerd://{id}\nretrying"),
            format!("unable to retrieve container logs for containerd://{id} (see kubelet)"),
            "unable to retrieve container logs for containerd://not-hex-at-all".to_owned(),
            "unable to retrieve container logs for containerd://abc".to_owned(),
            format!("unable to retrieve container logs for Containerd://{id}"),
            format!("unable to retrieve container logs for {id}"),
            String::new(),
            "flapping-worker lab-marker: cannot reach queue, exiting 1".to_owned(),
        ] {
            assert!(!text(&log).is_kubelet_log_refusal(), "{log}");
        }
    }

    #[test]
    fn list_parsing_uses_uid_row_ids_and_enforces_row_and_cell_bounds() {
        let items = (0..1_002)
            .map(|index| {
                serde_json::json!({
                    "metadata": {
                        "uid": format!("uid-{index}"),
                        "name": format!("pod-{index}"),
                        "namespace": "default",
                        "creationTimestamp": "2026-08-11T00:00:00Z"
                    },
                    "spec": {"nodeName": "worker-1", "containers": [{"image": "registry/image:1"}]},
                    "status": {
                        "phase": "Running",
                        "podIP": "10.0.0.2",
                        "containerStatuses": [{"ready": true, "restartCount": 2}]
                    }
                })
            })
            .collect::<Vec<_>>();
        let output = serde_json::json!({"items": items}).to_string();
        let parsed = parse_pods(&output, 1_000).unwrap();
        assert_eq!(parsed.items.len(), 1_000);
        assert!(parsed.truncated);
        assert_eq!(parsed.items[0].id.as_str(), "pod:uid-0");

        let long_image = "x".repeat(MAX_CELL_CHARS + 100);
        let one = serde_json::json!({"items": [{
            "metadata": {"uid": "uid-long", "name": "pod-long", "namespace": "default"},
            "spec": {"containers": [{"image": long_image}]},
            "status": {}
        }]})
        .to_string();
        let bounded = parse_pods(&one, 10).unwrap();
        assert_eq!(bounded.items[0].images[0].chars().count(), MAX_CELL_CHARS);
    }

    /// Every column of a fully populated row, read back one by one.
    ///
    /// The bounds test above parses the same shape and only ever looks at the
    /// row count and the id, so `podIP` deserialised into nothing for as long
    /// as the page has existed and no test noticed: on a real cluster the
    /// address column was blank for every running pod.
    #[test]
    fn a_populated_pod_row_carries_every_column_it_was_given() {
        let output = serde_json::json!({"items": [{
            "metadata": {
                "uid": "uid-1",
                "name": "access-logger",
                "namespace": "frontend",
                "creationTimestamp": "2026-08-27T00:25:52Z"
            },
            "spec": {"nodeName": "worker-1", "containers": [{"image": "alpine:3.20"}]},
            "status": {
                "phase": "Running",
                "podIP": "10.42.0.9",
                "containerStatuses": [{"ready": true, "restartCount": 3}]
            }
        }]})
        .to_string();

        let row = parse_pods(&output, 10).unwrap().items.remove(0);
        assert_eq!(row.name, "access-logger");
        assert_eq!(row.namespace, "frontend");
        assert_eq!(row.node, "worker-1");
        assert_eq!(row.phase, "Running");
        assert_eq!(row.pod_ip, "10.42.0.9");
        assert_eq!(row.images, vec!["alpine:3.20".to_owned()]);
        assert_eq!(row.ready_containers, 1);
        assert_eq!(row.restarts, 3);
        assert_eq!(row.created_at, "2026-08-27T00:25:52Z");
    }

    #[test]
    fn oversized_json_and_text_are_bounded() {
        let oversized = format!(
            "{{\"items\":[],\"padding\":\"{}\"}}",
            "x".repeat(MAX_JSON_BYTES)
        );
        assert!(parse_nodes(&oversized, 10).is_err());

        let text = bounded_multiline(&"x".repeat(MAX_LOG_CHARS + 20), MAX_LOG_CHARS);
        assert_eq!(text.text.chars().count(), MAX_LOG_CHARS);
        assert!(text.truncated);
    }

    #[test]
    fn availability_requires_typed_markers_and_bounds_context() {
        assert!(parse_availability("not kubectl output").is_err());
        let output = format!(
            "installed\ttrue\ncontext\t{}\napi_reachable\ttrue\n",
            "c".repeat(MAX_CONTEXT_CHARS + 10)
        );
        let availability = parse_availability(&output).unwrap();
        assert!(availability.kubectl_installed);
        assert!(availability.api_reachable);
        assert_eq!(
            availability.current_context.chars().count(),
            MAX_CONTEXT_CHARS
        );
    }

    #[test]
    fn the_context_namespace_is_the_one_kubectl_falls_back_to() {
        let read = |context: &str, namespace: &str| {
            parse_availability(&format!(
                "installed\ttrue\ncontext\t{context}\nnamespace\t{namespace}\napi_reachable\ttrue\n"
            ))
            .unwrap()
            .context_namespace
        };
        assert_eq!(read("viewer@lab", "payments").as_deref(), Some("payments"));
        // A context naming no namespace falls back to `default`, as kubectl does.
        assert_eq!(read("admin@lab", "").as_deref(), Some("default"));
        // No context: kubectl has nothing to fall back to.
        assert_eq!(read("", "payments"), None);
        // Not a namespace name: dropped, never shown or passed on.
        for hostile in ["Payments", "a;rm -rf /", "a b", &"n".repeat(64)] {
            assert_eq!(read("viewer@lab", hostile), None, "{hostile}");
        }
        // Output from before the marker existed reads as the fallback.
        let older = parse_availability("installed\ttrue\ncontext\tlab\napi_reachable\ttrue\n");
        assert_eq!(older.unwrap().context_namespace.as_deref(), Some("default"));
        // The context scope adds no namespace argument of its own.
        assert_eq!(KubernetesScope::ContextNamespace.arguments(), "");
    }

    #[tokio::test]
    async fn wrong_target_is_rejected_before_remote_dispatch() {
        let context = TargetContext::new();
        let stale = context.activate(identity("host-a")).unwrap();
        context.activate(identity("host-b")).unwrap();
        let dispatched = Arc::new(AtomicBool::new(false));
        let observed = dispatched.clone();
        let result = guarded_result(&context, &stale, || async move {
            observed.store(true, Ordering::SeqCst);
            Ok(())
        })
        .await;
        assert!(matches!(result, Err(CoreError::TargetChanged { .. })));
        assert!(!dispatched.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn target_change_after_dispatch_rejects_late_result() {
        let context = TargetContext::new();
        let guard = context.activate(identity("host-a")).unwrap();
        let result = guarded_result(&context, &guard, || async {
            context.activate(identity("host-b")).unwrap();
            Ok("late")
        })
        .await;
        assert!(matches!(result, Err(CoreError::TargetChanged { .. })));
    }

    #[tokio::test]
    async fn deployment_scale_requires_exact_confirmation_then_journals_and_verifies() {
        let (_root, services, harness, session) = test_services().await;
        harness.set_execute_outputs([
            deployment_json("deployment-uid", "10", 3),
            deployment_json("deployment-uid", "10", 3),
            deployment_json("deployment-uid", "11", 5),
            deployment_json("deployment-uid", "11", 5),
        ]);
        let plan = services
            .kubernetes()
            .plan_mutation(
                &session,
                &KubernetesMutationRequest::ScaleDeployment {
                    deployment: deployment_row(3),
                    replicas: 5,
                },
            )
            .await
            .unwrap();
        assert_eq!(plan.row_id().as_str(), "deployment:deployment-uid");
        assert_eq!(plan.state_change(), "副本 3 → 5");
        assert_eq!(
            plan.definition().metadata.get("resource-version"),
            Some(&"10".to_owned())
        );
        let outcome = services
            .kubernetes()
            .execute_mutation(
                &session,
                plan.clone(),
                DangerousConfirmation::approve(plan.definition()),
                services.operation_journal(),
            )
            .await
            .unwrap();
        assert!(outcome.verified);
        assert!(!outcome.restored_after_failed_verification);
        let journal = services.operation_journal().entries().unwrap();
        assert_eq!(journal.len(), 2);
        assert!(journal.iter().all(|entry| entry.source == "kubernetes"));
    }

    #[tokio::test]
    async fn wrong_confirmation_and_stale_resource_version_have_zero_side_effects() {
        let (_root, services, harness, session) = test_services().await;
        harness.set_execute_outputs([
            deployment_json("deployment-uid", "10", 3),
            deployment_json("deployment-uid", "10", 3),
        ]);
        let plan = services
            .kubernetes()
            .plan_mutation(
                &session,
                &KubernetesMutationRequest::ScaleDeployment {
                    deployment: deployment_row(3),
                    replicas: 4,
                },
            )
            .await
            .unwrap();
        let error = services
            .kubernetes()
            .execute_mutation(
                &session,
                plan.clone(),
                DangerousConfirmation::reject(plan.definition()),
                services.operation_journal(),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, CoreError::OperationCancelled { .. }));
        assert!(services.operation_journal().entries().unwrap().is_empty());

        harness.set_execute_outputs([
            deployment_json("deployment-uid", "20", 3),
            deployment_json("deployment-uid", "21", 3),
        ]);
        let stale = services
            .kubernetes()
            .plan_mutation(
                &session,
                &KubernetesMutationRequest::ScaleDeployment {
                    deployment: deployment_row(3),
                    replicas: 4,
                },
            )
            .await
            .unwrap();
        let error = services
            .kubernetes()
            .execute_mutation(
                &session,
                stale.clone(),
                DangerousConfirmation::approve(stale.definition()),
                services.operation_journal(),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("resourceVersion"));
        assert!(services.operation_journal().entries().unwrap().is_empty());
    }

    #[tokio::test]
    async fn verification_error_restores_only_the_applied_configuration() {
        let (_root, services, harness, session) = test_services().await;
        harness.set_execute_outputs([
            deployment_json("deployment-uid", "10", 3),
            deployment_json("deployment-uid", "10", 3),
            deployment_json("deployment-uid", "11", 5),
            "not-json".to_owned(),
            deployment_json("deployment-uid", "11", 5),
            deployment_json("deployment-uid", "12", 3),
            deployment_json("deployment-uid", "12", 3),
        ]);
        let plan = services
            .kubernetes()
            .plan_mutation(
                &session,
                &KubernetesMutationRequest::ScaleDeployment {
                    deployment: deployment_row(3),
                    replicas: 5,
                },
            )
            .await
            .unwrap();
        let outcome = services
            .kubernetes()
            .execute_mutation(
                &session,
                plan.clone(),
                DangerousConfirmation::approve(plan.definition()),
                services.operation_journal(),
            )
            .await
            .unwrap();
        assert!(!outcome.verified);
        assert!(outcome.verification_detail.contains("无法读取"));
        assert!(outcome.restored_after_failed_verification);
        let journal = services.operation_journal().entries().unwrap();
        assert_eq!(journal.len(), 3);
        assert_eq!(journal[2].phase, crate::operations::JournalPhase::Restored);

        harness.set_execute_outputs([
            deployment_json("deployment-uid", "20", 3),
            deployment_json("deployment-uid", "20", 3),
            deployment_json("deployment-uid", "21", 5),
            "not-json".to_owned(),
            with_generation(deployment_json("deployment-uid", "22", 5), 2),
        ]);
        let plan = services
            .kubernetes()
            .plan_mutation(
                &session,
                &KubernetesMutationRequest::ScaleDeployment {
                    deployment: deployment_row(3),
                    replicas: 5,
                },
            )
            .await
            .unwrap();
        let outcome = services
            .kubernetes()
            .execute_mutation(
                &session,
                plan.clone(),
                DangerousConfirmation::approve(plan.definition()),
                services.operation_journal(),
            )
            .await
            .unwrap();
        assert!(!outcome.verified);
        assert!(!outcome.restored_after_failed_verification);
        assert!(outcome.verification_detail.contains("自动恢复未完成"));
        let journal = services.operation_journal().entries().unwrap();
        assert_eq!(
            journal
                .iter()
                .filter(|entry| entry.phase == crate::operations::JournalPhase::Restored)
                .count(),
            1
        );
    }

    #[test]
    fn deployment_health_requires_observed_configuration_and_all_replica_counts() {
        let mut raw: RawDeployment =
            serde_json::from_str(&deployment_json("uid", "10", 3)).unwrap();
        assert_eq!(deployment_health(&raw), DeploymentHealth::Ready);
        raw.status.observed_generation = Some(0);
        assert!(matches!(
            deployment_health(&raw),
            DeploymentHealth::Pending(_)
        ));
        raw.status.observed_generation = Some(1);
        for field in [
            "replicas",
            "updatedReplicas",
            "readyReplicas",
            "availableReplicas",
        ] {
            let mut value: serde_json::Value =
                serde_json::from_str(&deployment_json("uid", "10", 3)).unwrap();
            value["status"][field] = json!(2);
            let waiting: RawDeployment = serde_json::from_value(value).unwrap();
            assert!(
                matches!(deployment_health(&waiting), DeploymentHealth::Pending(_)),
                "{field}"
            );
        }
        raw.status.replicas = 4;
        assert!(matches!(
            deployment_health(&raw),
            DeploymentHealth::Pending(_)
        ));
        raw.metadata.generation = None;
        assert!(matches!(
            deployment_health(&raw),
            DeploymentHealth::Failed(_)
        ));
        raw.metadata.generation = Some(1);
        raw.spec.replicas = None;
        assert!(raw.snapshot().is_err());
        assert!(matches!(
            deployment_health(&raw),
            DeploymentHealth::Failed(_)
        ));
    }

    #[test]
    fn failed_rollout_is_reported_but_does_not_undo_containment_at_zero_replicas() {
        let mut raw: RawDeployment =
            serde_json::from_str(&deployment_json("uid", "10", 3)).unwrap();
        raw.status.conditions = vec![RawDeploymentCondition {
            kind: "Progressing".to_owned(),
            status: "False".to_owned(),
            reason: "ProgressDeadlineExceeded".to_owned(),
        }];
        assert!(matches!(
            deployment_health(&raw),
            DeploymentHealth::Failed(_)
        ));
        raw.status.observed_generation = Some(0);
        assert!(matches!(
            deployment_health(&raw),
            DeploymentHealth::Pending(_)
        ));
        raw.status.observed_generation = Some(1);
        raw.spec.replicas = Some(0);
        assert!(matches!(
            deployment_health(&raw),
            DeploymentHealth::Pending(_)
        ));
        raw.status.replicas = 0;
        raw.status.updated_replicas = 0;
        raw.status.ready_replicas = 0;
        raw.status.available_replicas = 0;
        assert_eq!(deployment_health(&raw), DeploymentHealth::Ready);
    }

    #[test]
    fn deployment_restore_accepts_status_revisions_but_rejects_new_configuration_and_legacy_revisions()
     {
        let applied: RawDeployment =
            serde_json::from_str(&deployment_json("uid", "11", 5)).unwrap();
        let mut current = applied.snapshot().unwrap();
        let mut receipt = KubernetesMutationReceipt {
            schema: "kubernetes-mutation/v2".to_owned(),
            uid: "uid".to_owned(),
            resource_version: "10".to_owned(),
            generation: Some(1),
        };
        assert!(restore_revision_matches(&receipt, &current));
        receipt.schema = "kubernetes-mutation/v1".to_owned();
        assert!(!restore_revision_matches(&receipt, &current));
        receipt.schema = "kubernetes-mutation/v2".to_owned();
        if let KubernetesMutationSnapshot::Deployment { generation, .. } = &mut current {
            *generation = Some(2);
        }
        assert!(!restore_revision_matches(&receipt, &current));
        let node = KubernetesMutationSnapshot::Node {
            uid: "uid".to_owned(),
            resource_version: "11".to_owned(),
            unschedulable: true,
        };
        assert!(!restore_revision_matches(&receipt, &node));
    }

    #[tokio::test]
    async fn scaling_waits_for_new_status_and_ignores_status_only_revision_changes() {
        let (_root, services, harness, session) = test_services().await;
        harness.set_execute_outputs([
            deployment_json("deployment-uid", "10", 3),
            deployment_json("deployment-uid", "10", 3),
            with_generation(deployment_json("deployment-uid", "11", 4), 2),
            with_status(with_generation(deployment_json("deployment-uid", "12", 4), 2), json!({
                "observedGeneration": 1, "replicas": 3, "updatedReplicas": 3, "readyReplicas": 3, "availableReplicas": 3,
            })),
            with_generation(deployment_json("deployment-uid", "13", 4), 2),
        ]);
        let plan = services
            .kubernetes()
            .plan_mutation(
                &session,
                &KubernetesMutationRequest::ScaleDeployment {
                    deployment: deployment_row(3),
                    replicas: 4,
                },
            )
            .await
            .unwrap();
        let outcome = services
            .kubernetes()
            .execute_mutation(
                &session,
                plan.clone(),
                DangerousConfirmation::approve(plan.definition()),
                services.operation_journal(),
            )
            .await
            .unwrap();
        assert!(outcome.verified);
        assert!(
            outcome
                .verification_detail
                .contains("所有副本已更新、就绪且可用")
        );
        assert_eq!(harness.execute_commands().len(), 5);
    }

    #[tokio::test]
    async fn readiness_timeout_restores_previous_count_after_controller_status_changes() {
        let (_root, services, harness, session) = test_services().await;
        let mut service = services.kubernetes().clone();
        service.deployment_health_deadline = Duration::from_millis(20);
        harness.set_execute_outputs([
            deployment_json("deployment-uid", "10", 3),
            deployment_json("deployment-uid", "10", 3),
            with_generation(deployment_json("deployment-uid", "11", 4), 2),
            with_status(with_generation(deployment_json("deployment-uid", "12", 4), 2), json!({
                "observedGeneration": 2, "replicas": 4, "updatedReplicas": 4, "readyReplicas": 3, "availableReplicas": 3,
            })),
            with_generation(deployment_json("deployment-uid", "13", 4), 2),
            with_generation(deployment_json("deployment-uid", "14", 3), 3),
            with_generation(deployment_json("deployment-uid", "15", 3), 3),
        ]);
        let plan = service
            .plan_mutation(
                &session,
                &KubernetesMutationRequest::ScaleDeployment {
                    deployment: deployment_row(3),
                    replicas: 4,
                },
            )
            .await
            .unwrap();
        let outcome = service
            .execute_mutation(
                &session,
                plan.clone(),
                DangerousConfirmation::approve(plan.definition()),
                services.operation_journal(),
            )
            .await
            .unwrap();
        assert!(!outcome.verified);
        assert!(outcome.verification_detail.contains("就绪检查超时"));
        assert!(outcome.verification_detail.contains("就绪 3"));
        assert!(outcome.restored_after_failed_verification);
        let journal = services.operation_journal().entries().unwrap();
        assert_eq!(
            journal.last().unwrap().phase,
            crate::operations::JournalPhase::Restored
        );
    }

    #[tokio::test]
    async fn readiness_failure_preserves_a_new_configuration_and_reports_failed_restore() {
        let (_root, services, harness, session) = test_services().await;
        harness.set_execute_outputs([
            deployment_json("deployment-uid", "10", 3),
            deployment_json("deployment-uid", "10", 3),
            with_generation(deployment_json("deployment-uid", "11", 4), 2),
            with_generation(deployment_json("deployment-uid", "12", 4), 3),
            with_generation(deployment_json("deployment-uid", "13", 4), 3),
        ]);
        let plan = services
            .kubernetes()
            .plan_mutation(
                &session,
                &KubernetesMutationRequest::ScaleDeployment {
                    deployment: deployment_row(3),
                    replicas: 4,
                },
            )
            .await
            .unwrap();
        let outcome = services
            .kubernetes()
            .execute_mutation(
                &session,
                plan.clone(),
                DangerousConfirmation::approve(plan.definition()),
                services.operation_journal(),
            )
            .await
            .unwrap();
        assert!(!outcome.verified);
        assert!(!outcome.restored_after_failed_verification);
        assert!(outcome.verification_detail.contains("配置已再次变化"));
        assert!(outcome.verification_detail.contains("自动恢复未完成"));
        assert_eq!(
            harness
                .execute_commands()
                .iter()
                .filter(|command| command.starts_with("kubectl patch"))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn stopping_never_restarts_workload_when_readiness_check_times_out() {
        let (_root, services, harness, session) = test_services().await;
        let mut service = services.kubernetes().clone();
        service.deployment_health_deadline = Duration::from_millis(20);
        harness.set_execute_outputs([
            deployment_json("deployment-uid", "10", 3),
            deployment_json("deployment-uid", "10", 3),
            with_generation(deployment_json("deployment-uid", "11", 0), 2),
            with_status(
                with_generation(deployment_json("deployment-uid", "12", 0), 2),
                json!({
                    "observedGeneration": 1, "replicas": 3, "readyReplicas": 0,
                }),
            ),
        ]);
        let plan = service
            .plan_mutation(
                &session,
                &KubernetesMutationRequest::ScaleDeployment {
                    deployment: deployment_row(3),
                    replicas: 0,
                },
            )
            .await
            .unwrap();
        assert!(plan.definition().summary.contains("不自动重新启动"));
        let outcome = service
            .execute_mutation(
                &session,
                plan.clone(),
                DangerousConfirmation::approve(plan.definition()),
                services.operation_journal(),
            )
            .await
            .unwrap();
        assert!(!outcome.verified);
        assert!(!outcome.restored_after_failed_verification);
        assert!(outcome.verification_detail.contains("未自动启动副本"));
        assert_eq!(
            harness
                .execute_commands()
                .iter()
                .filter(|command| command.starts_with("kubectl patch"))
                .count(),
            1
        );
    }

    #[test]
    fn node_and_deployment_patches_are_closed_uid_and_revision_cas_documents() {
        let target = TargetContext::new();
        let guard = target.activate(identity("host-a")).unwrap();
        let deployment_plan = KubernetesMutationPlan {
            operation: OperationPlan::new(guard.clone(), "scale", true, Some("restore".to_owned()))
                .unwrap(),
            row_id: KubernetesRowId("deployment:deployment-uid".to_owned()),
            before: KubernetesMutationSnapshot::Deployment {
                uid: "deployment-uid".to_owned(),
                resource_version: "10".to_owned(),
                generation: Some(1),
                replicas: 3,
            },
            kind: KubernetesMutationKind::ScaleDeployment {
                namespace: "incident".to_owned(),
                name: "api".to_owned(),
                replicas: 5,
            },
        };
        let deployment_command =
            mutation_patch_command(&deployment_plan, deployment_plan.before(), false).unwrap();
        assert!(deployment_command.starts_with("kubectl patch deployment 'api' -n 'incident'"));
        assert!(deployment_command.contains("metadata/uid"));
        assert!(deployment_command.contains("metadata/resourceVersion"));
        assert!(deployment_command.contains("spec/replicas"));

        let node_plan = KubernetesMutationPlan {
            operation: OperationPlan::new(guard, "cordon", true, Some("restore".to_owned()))
                .unwrap(),
            row_id: KubernetesRowId("node:node-uid".to_owned()),
            before: KubernetesMutationSnapshot::Node {
                uid: "node-uid".to_owned(),
                resource_version: "30".to_owned(),
                unschedulable: false,
            },
            kind: KubernetesMutationKind::SetNodeUnschedulable {
                name: "worker-1".to_owned(),
                unschedulable: true,
            },
        };
        let node_command = mutation_patch_command(&node_plan, node_plan.before(), false).unwrap();
        assert!(node_command.starts_with("kubectl patch node 'worker-1'"));
        assert!(node_command.contains("spec/unschedulable"));
        assert!(!node_command.contains("kubectl exec"));
        assert!(!node_command.contains("kubectl apply"));

        // Both patches have to ask for the object back, because the caller
        // parses the response and refuses to claim success without it. Left
        // off, kubectl prints one line of prose, the parse fails, and the
        // workflow reports a failure for a change that already landed.
        for command in [&deployment_command, &node_command] {
            assert!(
                command.ends_with(" -o json"),
                "patch does not ask for the object back"
            );
            assert!(
                parse_mutation_snapshot(&deployment_plan, "deployment.apps/api patched").is_err()
            );
        }
    }

    #[tokio::test]
    async fn node_plan_rejects_a_row_from_another_uid() {
        let (_root, services, harness, session) = test_services().await;
        harness.set_execute_output(node_json("different-uid", "1", false));
        let error = services
            .kubernetes()
            .plan_mutation(
                &session,
                &KubernetesMutationRequest::SetNodeUnschedulable {
                    node: node_row(false),
                    unschedulable: true,
                },
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("stale"));
        assert!(services.operation_journal().entries().unwrap().is_empty());
    }

    #[test]
    fn legacy_etcd_delete_and_generic_exec_have_no_core_surface() {
        let source = include_str!("kubernetes.rs");
        assert!(!source.contains(&["etcd", "Delete", "Pod"].concat()));
        let public_async_functions = source.lines().filter_map(|line| {
            line.trim_start()
                .strip_prefix("pub async fn ")
                .and_then(|declaration| declaration.split(['(', '<']).next())
        });
        let forbidden = [
            "exec",
            "exec_in_pod",
            "apply",
            "apply_yaml",
            "delete",
            "delete_resource",
            "etcd_delete_pod",
        ];
        for function in public_async_functions {
            assert!(
                !forbidden.contains(&function),
                "unsafe API exposed: {function}"
            );
        }
    }
}
