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
    operations::{
        DangerousConfirmation, ExecutionReceipt, OperationExecutor, OperationPlan, OperationState,
        PlannedOperation, PortableOperationJournal, VerificationResult,
    },
    shell_escape::shq,
    ssh::{BoundSshSession, SshCommandOutput, SshService},
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

const AVAILABILITY_COMMAND: &str = r#"if command -v kubectl >/dev/null 2>&1; then
  printf 'installed\ttrue\n'
  context=$(kubectl config current-context 2>/dev/null | tr -d '\r\n\t' | head -c 512 || true)
  printf 'context\t%s\n' "$context"
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
}

impl KubernetesScope {
    pub fn namespace(value: impl Into<String>) -> CoreResult<Self> {
        let value = value.into();
        validate_dns_label("Kubernetes namespace", &value)?;
        Ok(Self::Namespace(value))
    }

    pub fn namespace_name(&self) -> Option<&str> {
        match self {
            Self::AllNamespaces => None,
            Self::Namespace(value) => Some(value),
        }
    }

    fn arguments(&self) -> String {
        match self {
            Self::AllNamespaces => "--all-namespaces".to_owned(),
            Self::Namespace(value) => format!("-n {}", shq(value)),
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KubernetesText {
    pub text: String,
    pub truncated: bool,
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
    target: Arc<TargetContext>,
}

impl KubernetesService {
    pub fn new(ssh: SshService, target: Arc<TargetContext>) -> Self {
        Self {
            runner: Arc::new(SshKubernetesCommandRunner { ssh }),
            target,
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
                        "将 Deployment {}/{} 的副本数从 {previous} 调整为 {replicas}。",
                        deployment.namespace, deployment.name
                    ),
                    "将 Deployment 副本数恢复为操作前读回值".to_owned(),
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
                return match operation.restore(&self.target, &executor, journal).await {
                    Ok(()) => Err(error),
                    Err(restore_error) => Err(validation(
                        "Kubernetes automatic restore",
                        format!(
                            "verification failed: {error}; automatic restore also failed: {restore_error}"
                        ),
                    )),
                };
            }
        };
        if !verification.passed {
            operation.restore(&self.target, &executor, journal).await?;
            return Ok(KubernetesMutationOutcome {
                verified: false,
                verification_detail: verification.detail,
                restored_after_failed_verification: true,
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
        Ok(KubernetesMutationSnapshot::Deployment {
            uid: raw.metadata.uid,
            resource_version: raw.metadata.resource_version,
            replicas: raw.spec.replicas,
        })
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
                    schema: "kubernetes-mutation/v1".to_owned(),
                    uid: patched.uid().to_owned(),
                    resource_version: patched.resource_version().to_owned(),
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
        let current = self.current_snapshot().await?;
        let passed = receipt.uid == current.uid() && self.plan.target_matches(&current);
        Ok(VerificationResult {
            passed,
            detail: if passed {
                format!("verified {}", self.plan.state_change())
            } else {
                "resource did not reach the exact reviewed target state".to_owned()
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
            || receipt.resource_version != current.resource_version()
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
    if decoded.schema != "kubernetes-mutation/v1" {
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
            Ok(KubernetesMutationSnapshot::Deployment {
                uid: raw.metadata.uid,
                resource_version: raw.metadata.resource_version,
                replicas: raw.spec.replicas,
            })
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
    Ok(format!(
        "kubectl patch {resource} {}{namespace} --type=json -p {}",
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

fn validate_command_output(subject: &'static str, output: SshCommandOutput) -> CoreResult<String> {
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
    })
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
            desired_replicas: item.spec.replicas,
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
    name: String,
    namespace: String,
    creation_timestamp: String,
    labels: BTreeMap<String, String>,
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
    image: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct RawPodStatus {
    phase: String,
    pod_ip: String,
    container_statuses: Vec<RawContainerStatus>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct RawContainerStatus {
    ready: bool,
    restart_count: u64,
    state: RawContainerState,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawContainerState {
    waiting: Option<RawWaitingState>,
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

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawDeploymentSpec {
    replicas: u64,
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
    ready_replicas: u64,
    available_replicas: u64,
    updated_replicas: u64,
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

    fn deployment_json(uid: &str, resource_version: &str, replicas: u64) -> String {
        serde_json::json!({
            "metadata": {
                "uid": uid,
                "resourceVersion": resource_version,
                "namespace": "incident",
                "name": "api"
            },
            "spec": {"replicas": replicas}
        })
        .to_string()
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
    async fn verification_error_restores_only_the_exact_patch_revision() {
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
        let error = services
            .kubernetes()
            .execute_mutation(
                &session,
                plan.clone(),
                DangerousConfirmation::approve(plan.definition()),
                services.operation_journal(),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("decode"));
        let journal = services.operation_journal().entries().unwrap();
        assert_eq!(journal.len(), 3);
        assert_eq!(journal[2].phase, crate::operations::JournalPhase::Restored);

        harness.set_execute_outputs([
            deployment_json("deployment-uid", "20", 3),
            deployment_json("deployment-uid", "20", 3),
            deployment_json("deployment-uid", "21", 5),
            "not-json".to_owned(),
            deployment_json("deployment-uid", "22", 5),
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
        let error = services
            .kubernetes()
            .execute_mutation(
                &session,
                plan.clone(),
                DangerousConfirmation::approve(plan.definition()),
                services.operation_journal(),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("independent revision"));
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
