//! Capability-only desktop boundary for Kubernetes read investigations.
//!
//! All remote commands remain inside `lovelyhawk_core::kubernetes::KubernetesService`.
//! The renderer selects only a closed tab and opaque snapshot/row capabilities;
//! it never supplies a session, target identity, namespace, resource name/UID,
//! command, log arguments, or a mutation request.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use lovelyhawk_core::{
    BackendServices, CoreError,
    kubernetes::{
        KubernetesAvailability, KubernetesCollection, KubernetesDeployment,
        KubernetesDetailRequest, KubernetesManifest, KubernetesManifestObject, KubernetesNamespace,
        KubernetesNode, KubernetesPod, KubernetesPodLogsRequest, KubernetesResourceKind,
        KubernetesScope, KubernetesText,
    },
    ssh::BoundSshSession,
    target::TargetGuard,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ssh_api::SshApi;

const MAX_HANDLE_BYTES: usize = 128;
const MAX_ROWS: usize = 500;
const MAX_IMAGES: usize = 16;
const MAX_ROLES: usize = 16;
const MAX_FIELD_BYTES: usize = 4 * 1024;
const MAX_ROW_BYTES: usize = 48 * 1024;
const MAX_LIST_BYTES: usize = 2 * 1024 * 1024;
const MAX_DETAIL_BYTES: usize = 256 * 1024;
const MAX_LOG_BYTES: usize = 512 * 1024;
const MAX_SNAPSHOTS: usize = 24;
const MAX_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;
const MAX_REGISTRY_BYTES: usize = 32 * 1024 * 1024;
const MAX_GLOBAL_READS: usize = 8;
const MAX_READS_PER_BINDING: usize = 4;
const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;
const SNAPSHOT_TTL: Duration = Duration::from_secs(5 * 60);
const REDACTED_KUBERNETES_TEXT: &str = "[SENSITIVE KUBERNETES TEXT REDACTED]";

#[derive(Clone)]
pub(crate) struct KubernetesReadApi {
    services: BackendServices,
    ssh_api: Arc<SshApi>,
    snapshots: Arc<Mutex<SnapshotRegistry>>,
    concurrency: Arc<Mutex<ConcurrencyState>>,
}

impl fmt::Debug for KubernetesReadApi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (snapshots, snapshot_bytes) = self
            .snapshots
            .lock()
            .map(|registry| (registry.snapshots.len(), registry.total_bytes))
            .unwrap_or_default();
        let active_reads = self
            .concurrency
            .lock()
            .map(|state| state.total)
            .unwrap_or_default();
        formatter
            .debug_struct("KubernetesReadApi")
            .field("snapshot_count", &snapshots)
            .field("snapshot_bytes", &snapshot_bytes)
            .field("active_reads", &active_reads)
            .finish()
    }
}

impl KubernetesReadApi {
    pub(crate) fn new(services: BackendServices, ssh_api: Arc<SshApi>) -> Self {
        Self {
            services,
            ssh_api,
            snapshots: Arc::new(Mutex::new(SnapshotRegistry::default())),
            concurrency: Arc::new(Mutex::new(ConcurrencyState::default())),
        }
    }

    pub(crate) fn close_binding(&self, binding_handle: &str) {
        if let Ok(mut snapshots) = self.snapshots.lock() {
            snapshots.close_binding(binding_handle);
        }
    }

    pub(crate) async fn availability(
        &self,
        binding_handle: &str,
    ) -> Result<KubernetesAvailabilityDto, KubernetesReadApiError> {
        let (session, scope) = self.capture_binding(binding_handle)?;
        let _permit = self.acquire_read(&scope)?;
        let availability = self.services.kubernetes().availability(&session).await?;
        self.validate_binding(&scope)?;
        Ok(project_availability(
            availability,
            &scope.sensitive_literals(),
        ))
    }

    pub(crate) async fn list(
        &self,
        binding_handle: &str,
        input: KubernetesListInput,
    ) -> Result<KubernetesSnapshotDto, KubernetesReadApiError> {
        input.validate()?;
        let (session, scope) = self.capture_binding(binding_handle)?;
        let _permit = self.acquire_read(&scope)?;
        let namespace_scoped = input.namespace_scope.is_some();
        let namespace_capability = match &input.namespace_scope {
            Some(KubernetesNamespaceScopeInput::Listed(capability)) => Some(capability),
            Some(KubernetesNamespaceScopeInput::Context(_)) | None => None,
        };
        let namespace_scope = match (&input.namespace_scope, namespace_capability) {
            (_, Some(capability)) => KubernetesScope::namespace(self.resolve_namespace(
                &scope,
                capability,
                Instant::now(),
            )?)?,
            (Some(KubernetesNamespaceScopeInput::Context(_)), None) => {
                KubernetesScope::ContextNamespace
            }
            _ => KubernetesScope::AllNamespaces,
        };

        let rows = match input.tab {
            KubernetesReadTab::Namespaces => CoreRows::Namespaces(
                self.services
                    .kubernetes()
                    .namespaces(&session, MAX_ROWS)
                    .await?,
            ),
            KubernetesReadTab::Pods => CoreRows::Pods(
                self.services
                    .kubernetes()
                    .pods(&session, &namespace_scope, MAX_ROWS)
                    .await?,
            ),
            KubernetesReadTab::Deployments => CoreRows::Deployments(
                self.services
                    .kubernetes()
                    .deployments(&session, &namespace_scope, MAX_ROWS)
                    .await?,
            ),
            KubernetesReadTab::Nodes => {
                CoreRows::Nodes(self.services.kubernetes().nodes(&session, MAX_ROWS).await?)
            }
        };
        self.validate_binding(&scope)?;
        if let Some(capability) = namespace_capability {
            self.resolve_namespace(&scope, capability, Instant::now())?;
        }

        let mut registry = self.lock_snapshots()?;
        let now = Instant::now();
        registry.prune(now);
        registry.insert(scope, input.tab, namespace_scoped, rows, now)
    }

    pub(crate) async fn detail(
        &self,
        binding_handle: &str,
        snapshot_handle: &str,
        row_handle: &str,
    ) -> Result<KubernetesTextDto, KubernetesReadApiError> {
        validate_handle(snapshot_handle)?;
        validate_handle(row_handle)?;
        let (session, scope) = self.capture_binding(binding_handle)?;
        let _permit = self.acquire_read(&scope)?;
        let row = self.resolve_row(&scope, snapshot_handle, row_handle, Instant::now())?;
        let request = row.detail_request()?;
        let text = self
            .services
            .kubernetes()
            .detail(&session, &request)
            .await?;
        self.validate_binding(&scope)?;
        self.resolve_row(&scope, snapshot_handle, row_handle, Instant::now())?;
        Ok(project_text(
            snapshot_handle,
            row_handle,
            "detail",
            text,
            MAX_DETAIL_BYTES,
            &scope.sensitive_literals(),
        ))
    }

    pub(crate) async fn pod_logs(
        &self,
        binding_handle: &str,
        snapshot_handle: &str,
        row_handle: &str,
        previous: bool,
        container: Option<&str>,
    ) -> Result<KubernetesTextDto, KubernetesReadApiError> {
        validate_handle(snapshot_handle)?;
        validate_handle(row_handle)?;
        let (session, scope) = self.capture_binding(binding_handle)?;
        let _permit = self.acquire_read(&scope)?;
        let row = self.resolve_row(&scope, snapshot_handle, row_handle, Instant::now())?;
        let request = row.pod_logs_request(container)?.with_previous(previous);
        let text = self
            .services
            .kubernetes()
            .pod_logs(&session, &request)
            .await?;
        self.validate_binding(&scope)?;
        let current = self.resolve_row(&scope, snapshot_handle, row_handle, Instant::now())?;
        if !matches!(current, CoreRow::Pod(_)) {
            return Err(KubernetesReadApiError::RowUnavailable);
        }
        if text.is_kubelet_log_refusal() {
            return Err(KubernetesReadApiError::LogsNotReady);
        }
        Ok(project_text(
            snapshot_handle,
            row_handle,
            // Its own kind, so the previous run's logs can never be shown as
            // what the pod is printing now.
            if previous {
                "pod-previous-logs"
            } else {
                "pod-logs"
            },
            text,
            MAX_LOG_BYTES,
            &scope.sensitive_literals(),
        ))
    }

    /// A listed Pod, Deployment or Node's live manifest, prepared for the
    /// host to write to a file the operator chooses.
    ///
    /// For the host only: the contents leave through the host's save dialog,
    /// never back to the page. The object is the row's, and the core refuses
    /// a manifest that is no longer that row's object. The YAML is kept as
    /// kubectl printed it, under a commented header saying where and when it
    /// was read.
    pub(crate) async fn export_manifest(
        &self,
        binding_handle: &str,
        snapshot_handle: &str,
        row_handle: &str,
    ) -> Result<KubernetesManifestExportDto, KubernetesReadApiError> {
        validate_handle(snapshot_handle)?;
        validate_handle(row_handle)?;
        let (session, scope) = self.capture_binding(binding_handle)?;
        let object = match self.resolve_row(&scope, snapshot_handle, row_handle, Instant::now())? {
            CoreRow::Pod(pod) => KubernetesManifestObject::Pod(pod),
            CoreRow::Deployment(deployment) => KubernetesManifestObject::Deployment(deployment),
            CoreRow::Node(node) => KubernetesManifestObject::Node(node),
            CoreRow::Namespace(_) => return Err(KubernetesReadApiError::RowUnavailable),
        };
        let _permit = self.acquire_read(&scope)?;
        let manifest = self
            .services
            .kubernetes()
            .object_manifest(&session, &object)
            .await
            .map_err(|error| match error {
                CoreError::Validation {
                    subject: "Kubernetes manifest",
                    ..
                } => KubernetesReadApiError::ManifestUnavailable,
                other => other.into(),
            })?;
        let source = self
            .services
            .ssh()
            .list_sessions()
            .await
            .ok()
            .and_then(|sessions| {
                sessions.into_iter().find(|status| {
                    status.session_id == session.session_id()
                        && status.connection_id == session.connection_id()
                })
            })
            .map(|status| {
                let host = if status.host.contains(':') {
                    format!("[{}]", status.host)
                } else {
                    status.host
                };
                format!("{}@{}:{}", status.username, host, status.port)
            });
        self.validate_binding(&scope)?;
        Ok(manifest_export(&manifest, source.as_deref()))
    }

    fn capture_binding(
        &self,
        binding_handle: &str,
    ) -> Result<(BoundSshSession, BindingScope), KubernetesReadApiError> {
        validate_handle(binding_handle)?;
        let session = self
            .ssh_api
            .binding_session_clone(binding_handle)
            .map_err(|_| KubernetesReadApiError::BindingUnavailable)?;
        self.services
            .target()
            .validate(session.target())
            .map_err(|_| KubernetesReadApiError::BindingUnavailable)?;
        let scope = BindingScope::from_session(binding_handle, &session);
        Ok((session, scope))
    }

    fn validate_binding(
        &self,
        expected: &BindingScope,
    ) -> Result<BoundSshSession, KubernetesReadApiError> {
        let (session, current) = self.capture_binding(&expected.binding_handle)?;
        if &current != expected {
            return Err(KubernetesReadApiError::BindingUnavailable);
        }
        Ok(session)
    }

    fn resolve_namespace(
        &self,
        scope: &BindingScope,
        capability: &KubernetesNamespaceCapabilityInput,
        now: Instant,
    ) -> Result<String, KubernetesReadApiError> {
        validate_handle(&capability.snapshot_handle)?;
        validate_handle(&capability.row_handle)?;
        self.lock_snapshots()?.resolve_namespace(
            scope,
            &capability.snapshot_handle,
            &capability.row_handle,
            now,
        )
    }

    fn resolve_row(
        &self,
        scope: &BindingScope,
        snapshot_handle: &str,
        row_handle: &str,
        now: Instant,
    ) -> Result<CoreRow, KubernetesReadApiError> {
        self.lock_snapshots()?
            .resolve_row(scope, snapshot_handle, row_handle, now)
    }

    /// Turns a row handle back into the Deployment or Node it was minted for.
    ///
    /// The mutation side needs exactly this and nothing else: it never sees a
    /// namespace, a name or a UID, so it cannot act on a resource the snapshot
    /// did not offer. Scope and expiry are checked here, so a handle from a
    /// previous target, a previous session, or a snapshot that has since aged
    /// out resolves to nothing.
    ///
    /// The row is returned whole because the core's planner re-reads the live
    /// resource and refuses when the UID or resourceVersion moved — it needs
    /// the reading this row was made from to compare against.
    pub(crate) fn resolve_workload_for_mutation(
        &self,
        binding_handle: &str,
        snapshot_handle: &str,
        row_handle: &str,
    ) -> Result<(BoundSshSession, KubernetesWorkloadRow), KubernetesReadApiError> {
        validate_handle(snapshot_handle)?;
        validate_handle(row_handle)?;
        let (session, scope) = self.capture_binding(binding_handle)?;
        let row = self.resolve_row(&scope, snapshot_handle, row_handle, Instant::now())?;
        match row {
            CoreRow::Deployment(deployment) => Ok((
                session,
                KubernetesWorkloadRow::Deployment(Box::new(deployment)),
            )),
            CoreRow::Node(node) => Ok((session, KubernetesWorkloadRow::Node(Box::new(node)))),
            // A namespace or a pod has no mutation in the core at all, so this
            // is "that handle names the wrong kind of thing", not a refusal.
            CoreRow::Namespace(_) | CoreRow::Pod(_) => Err(KubernetesReadApiError::RowUnavailable),
        }
    }

    /// Turns a row handle back into the Pod it was minted for, for a shell.
    ///
    /// Same rules as for a mutation: the scope, the snapshot's expiry and the
    /// row's kind are checked here, so a handle from another target or an
    /// aged-out list resolves to nothing. Core re-reads the pod and refuses
    /// when its UID moved, so the row is returned whole.
    pub(crate) fn resolve_pod_for_terminal(
        &self,
        binding_handle: &str,
        snapshot_handle: &str,
        row_handle: &str,
    ) -> Result<(BoundSshSession, KubernetesPod), KubernetesReadApiError> {
        validate_handle(snapshot_handle)?;
        validate_handle(row_handle)?;
        let (session, scope) = self.capture_binding(binding_handle)?;
        match self.resolve_row(&scope, snapshot_handle, row_handle, Instant::now())? {
            CoreRow::Pod(pod) => Ok((session, pod)),
            _ => Err(KubernetesReadApiError::RowUnavailable),
        }
    }

    fn acquire_read(&self, scope: &BindingScope) -> Result<ReadPermit, KubernetesReadApiError> {
        ReadPermit::acquire(Arc::clone(&self.concurrency), scope.concurrency_key())
    }

    fn lock_snapshots(&self) -> Result<MutexGuard<'_, SnapshotRegistry>, KubernetesReadApiError> {
        self.snapshots
            .lock()
            .map_err(|_| KubernetesReadApiError::RegistryUnavailable)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum KubernetesReadTab {
    Namespaces,
    Pods,
    Deployments,
    Nodes,
}

impl KubernetesReadTab {
    const fn key(self) -> &'static str {
        match self {
            Self::Namespaces => "namespaces",
            Self::Pods => "pods",
            Self::Deployments => "deployments",
            Self::Nodes => "nodes",
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct KubernetesNamespaceCapabilityInput {
    snapshot_handle: String,
    row_handle: String,
}

impl fmt::Debug for KubernetesNamespaceCapabilityInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KubernetesNamespaceCapabilityInput([OPAQUE])")
    }
}

/// The namespace a pod or deployment list reads.
///
/// Either one row of a namespace list this binding read, or the namespace the
/// kubeconfig's current context names — for an account that may not list
/// namespaces at all. Neither way does the page send a namespace name.
#[derive(Clone, Deserialize)]
#[serde(untagged)]
pub(crate) enum KubernetesNamespaceScopeInput {
    Listed(KubernetesNamespaceCapabilityInput),
    Context(KubernetesContextScopeInput),
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct KubernetesContextScopeInput {
    /// Always `true`; there is nothing else to say about this scope.
    context: bool,
}

impl fmt::Debug for KubernetesNamespaceScopeInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Listed(_) => "Listed([OPAQUE])",
            Self::Context(_) => "Context",
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct KubernetesListInput {
    tab: KubernetesReadTab,
    namespace_scope: Option<KubernetesNamespaceScopeInput>,
}

impl fmt::Debug for KubernetesListInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KubernetesListInput")
            .field("tab", &self.tab)
            .field("namespace_scoped", &self.namespace_scope.is_some())
            .finish()
    }
}

impl KubernetesListInput {
    fn validate(&self) -> Result<(), KubernetesReadApiError> {
        if let Some(KubernetesNamespaceScopeInput::Context(input)) = &self.namespace_scope
            && !input.context
        {
            return Err(KubernetesReadApiError::InvalidInput);
        }
        match self.tab {
            KubernetesReadTab::Pods | KubernetesReadTab::Deployments => Ok(()),
            KubernetesReadTab::Namespaces | KubernetesReadTab::Nodes
                if self.namespace_scope.is_none() =>
            {
                Ok(())
            }
            KubernetesReadTab::Namespaces | KubernetesReadTab::Nodes => {
                Err(KubernetesReadApiError::InvalidInput)
            }
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KubernetesAvailabilityDto {
    kubectl_installed: bool,
    api_reachable: bool,
    current_context: String,
    context_truncated: bool,
    /// The namespace kubectl falls back to, already checked to be a
    /// namespace name; an account bound to one namespace reads only this.
    context_namespace: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KubernetesSnapshotDto {
    snapshot_handle: String,
    tab: &'static str,
    namespace_scoped: bool,
    displayed: usize,
    truncated: bool,
    expires_in_seconds: u64,
    rows: Vec<KubernetesRowDto>,
}

/// One app container of a listed pod.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KubernetesPodContainerDto {
    name: String,
    image: String,
    ready: bool,
    running: bool,
    restarts: u64,
}

#[derive(Clone, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
enum KubernetesRowDto {
    Namespace {
        row_handle: String,
        name: String,
        phase: String,
        created_at: String,
        text_truncated: bool,
    },
    Pod {
        row_handle: String,
        namespace: String,
        name: String,
        phase: String,
        ready_containers: u64,
        total_containers: u64,
        restarts: u64,
        node: String,
        pod_ip: String,
        images: Vec<String>,
        created_at: String,
        supports_logs: bool,
        /// The pod's app containers, to choose one for logs, a shell or files.
        containers: Vec<KubernetesPodContainerDto>,
        /// The one used when none is chosen; one of `containers` or none.
        default_container: Option<String>,
        text_truncated: bool,
    },
    Deployment {
        row_handle: String,
        namespace: String,
        name: String,
        desired_replicas: u64,
        ready_replicas: u64,
        available_replicas: u64,
        updated_replicas: u64,
        images: Vec<String>,
        created_at: String,
        text_truncated: bool,
    },
    Node {
        row_handle: String,
        name: String,
        ready: bool,
        unschedulable: bool,
        roles: Vec<String>,
        kubelet_version: String,
        internal_ip: String,
        cpu_capacity: String,
        memory_capacity: String,
        pod_capacity: String,
        created_at: String,
        text_truncated: bool,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KubernetesTextDto {
    snapshot_handle: String,
    row_handle: String,
    content_kind: &'static str,
    text: String,
    truncated: bool,
}

pub(crate) enum KubernetesReadApiError {
    Core(CoreError),
    BindingUnavailable,
    InvalidHandle,
    InvalidInput,
    NamespaceUnavailable,
    SnapshotUnavailable,
    RowUnavailable,
    LogsUnavailable,
    /// The container asked for is not one of the listed pod's containers.
    ContainerUnavailable,
    /// The kubelet answered with its own refusal instead of the log.
    LogsNotReady,
    /// The API server refused this account the read (RBAC Forbidden).
    Forbidden,
    /// The manifest read was not the listed object's (recreated, moved),
    /// was larger than kept, or kubectl did not produce it.
    ManifestUnavailable,
    Capacity,
    ConcurrencyLimit,
    RegistryUnavailable,
}

impl fmt::Debug for KubernetesReadApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core(error) => core_error_kind(error),
            Self::BindingUnavailable => "BindingUnavailable",
            Self::InvalidHandle => "InvalidHandle",
            Self::InvalidInput => "InvalidInput",
            Self::NamespaceUnavailable => "NamespaceUnavailable",
            Self::SnapshotUnavailable => "SnapshotUnavailable",
            Self::RowUnavailable => "RowUnavailable",
            Self::LogsUnavailable => "LogsUnavailable",
            Self::LogsNotReady => "LogsNotReady",
            Self::ContainerUnavailable => "ContainerUnavailable",
            Self::Forbidden => "Forbidden",
            Self::ManifestUnavailable => "ManifestUnavailable",
            Self::Capacity => "Capacity",
            Self::ConcurrencyLimit => "ConcurrencyLimit",
            Self::RegistryUnavailable => "RegistryUnavailable",
        })
    }
}

impl fmt::Display for KubernetesReadApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core(_) => "the Kubernetes read operation failed",
            Self::BindingUnavailable => "the SSH binding is missing or stale",
            Self::InvalidHandle => "the Kubernetes capability is invalid",
            Self::InvalidInput => "the Kubernetes read request is invalid",
            Self::NamespaceUnavailable => "the namespace capability is missing or stale",
            Self::SnapshotUnavailable => "the Kubernetes snapshot is missing or stale",
            Self::RowUnavailable => "the Kubernetes row is missing or stale",
            Self::LogsUnavailable => "pod logs are unavailable for this row",
            Self::LogsNotReady => "the kubelet could not hand over this container log",
            Self::ContainerUnavailable => "the pod has no such container",
            Self::Forbidden => "the API server refused this account the read",
            Self::ManifestUnavailable => "the manifest is not the listed object's or was not read",
            Self::Capacity => "the Kubernetes read registry is full",
            Self::ConcurrencyLimit => "too many Kubernetes reads are active",
            Self::RegistryUnavailable => "the Kubernetes read registry is unavailable",
        })
    }
}

impl std::error::Error for KubernetesReadApiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // Core errors can contain target identity, remote paths, or attacker-controlled stderr.
        // The native tracing owner may classify them, but this public boundary never chains them.
        None
    }
}

impl From<CoreError> for KubernetesReadApiError {
    fn from(error: CoreError) -> Self {
        // A host that went away is not a failure of this feature. One lost
        // connection reported once beats a dozen features each announcing
        // their own breakage.
        if matches!(error, CoreError::SshDisconnected { .. }) {
            return Self::BindingUnavailable;
        }
        // Said apart from a failure: the operator's next step is another
        // namespace or another account, not a retry.
        if matches!(
            error,
            CoreError::Validation {
                subject: "Kubernetes permission",
                ..
            }
        ) {
            return Self::Forbidden;
        }
        Self::Core(error)
    }
}

fn core_error_kind(error: &CoreError) -> &'static str {
    match error {
        CoreError::Io { .. } => "CoreIo([REDACTED])",
        CoreError::PartialCleanup { .. } => "CorePartialCleanup([REDACTED])",
        CoreError::Validation { .. } => "CoreValidation([REDACTED])",
        CoreError::Encode { .. } => "CoreEncode([REDACTED])",
        CoreError::Decode { .. } => "CoreDecode([REDACTED])",
        CoreError::UnsupportedSchema { .. } => "CoreUnsupportedSchema([REDACTED])",
        CoreError::Unsupported { .. } => "CoreUnsupported([REDACTED])",
        CoreError::NoActiveTarget => "CoreNoActiveTarget([REDACTED])",
        CoreError::TargetChanged { .. } => "CoreTargetChanged([REDACTED])",
        CoreError::ConfirmationRequired { .. } => "CoreConfirmationRequired([REDACTED])",
        CoreError::OperationCancelled { .. } => "CoreOperationCancelled([REDACTED])",
        CoreError::InvalidOperationState { .. } => "CoreInvalidOperationState([REDACTED])",
        CoreError::Crypto(_) => "CoreCrypto([REDACTED])",
        CoreError::NotFound { .. } => "CoreNotFound([REDACTED])",
        CoreError::InvalidChannelCapacity => "CoreInvalidChannelCapacity([REDACTED])",
        CoreError::ChannelClosed { .. } => "CoreChannelClosed([REDACTED])",
        CoreError::SshHostKeyConfirmationRequired { .. } => {
            "CoreSshHostKeyConfirmationRequired([REDACTED])"
        }
        CoreError::SshHostKeyChanged { .. } => "CoreSshHostKeyChanged([REDACTED])",
        CoreError::SshDisconnected { .. } => "CoreSshDisconnected([REDACTED])",
        CoreError::SshKeyboardInteractiveRequired { .. } => {
            "CoreSshKeyboardInteractiveRequired([REDACTED])"
        }
        CoreError::Ssh { .. } => "CoreSsh([REDACTED])",
    }
}

#[derive(Clone, Eq, PartialEq)]
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

    fn concurrency_key(&self) -> String {
        format!(
            "{}\0{}\0{}\0{}\0{}",
            self.binding_handle,
            self.session_id,
            self.connection_id,
            self.target.identity.as_str(),
            self.target.generation,
        )
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

#[derive(Default)]
struct ConcurrencyState {
    total: usize,
    per_binding: HashMap<String, usize>,
}

struct ReadPermit {
    state: Arc<Mutex<ConcurrencyState>>,
    key: String,
}

impl ReadPermit {
    fn acquire(
        state: Arc<Mutex<ConcurrencyState>>,
        key: String,
    ) -> Result<Self, KubernetesReadApiError> {
        {
            let mut current = state
                .lock()
                .map_err(|_| KubernetesReadApiError::RegistryUnavailable)?;
            let binding_reads = current.per_binding.get(&key).copied().unwrap_or_default();
            if current.total >= MAX_GLOBAL_READS || binding_reads >= MAX_READS_PER_BINDING {
                return Err(KubernetesReadApiError::ConcurrencyLimit);
            }
            current.total += 1;
            current.per_binding.insert(key.clone(), binding_reads + 1);
        }
        Ok(Self { state, key })
    }
}

impl Drop for ReadPermit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            state.total = state.total.saturating_sub(1);
            if let Some(count) = state.per_binding.get_mut(&self.key) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    state.per_binding.remove(&self.key);
                }
            }
        }
    }
}

#[derive(Default)]
struct SnapshotRegistry {
    snapshots: HashMap<String, SnapshotEntry>,
    total_bytes: usize,
}

impl fmt::Debug for SnapshotRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KubernetesSnapshotRegistry")
            .field("snapshot_count", &self.snapshots.len())
            .field("total_bytes", &self.total_bytes)
            .finish()
    }
}

struct SnapshotEntry {
    scope: BindingScope,
    tab: KubernetesReadTab,
    rows: HashMap<String, CoreRow>,
    bytes: usize,
    expires_at: Instant,
    touched_at: Instant,
}

#[derive(Clone)]
enum CoreRow {
    Namespace(KubernetesNamespace),
    Pod(KubernetesPod),
    Deployment(KubernetesDeployment),
    Node(KubernetesNode),
}

/// The two row kinds the core knows how to change.
///
/// Boxed because a Node row carries its capacities and roles and is much the
/// larger of the two; an unboxed enum would make every caller pay for it.
#[derive(Clone)]
pub(crate) enum KubernetesWorkloadRow {
    Deployment(Box<KubernetesDeployment>),
    Node(Box<KubernetesNode>),
}

impl CoreRow {
    fn id(&self) -> &str {
        match self {
            Self::Namespace(row) => row.id.as_str(),
            Self::Pod(row) => row.id.as_str(),
            Self::Deployment(row) => row.id.as_str(),
            Self::Node(row) => row.id.as_str(),
        }
    }

    fn detail_request(&self) -> Result<KubernetesDetailRequest, KubernetesReadApiError> {
        match self {
            Self::Namespace(row) => Ok(KubernetesDetailRequest::cluster_scoped(
                KubernetesResourceKind::Namespace,
                row.name.clone(),
            )?),
            Self::Pod(row) => Ok(KubernetesDetailRequest::namespaced(
                KubernetesResourceKind::Pod,
                row.namespace.clone(),
                row.name.clone(),
            )?),
            Self::Deployment(row) => Ok(KubernetesDetailRequest::namespaced(
                KubernetesResourceKind::Deployment,
                row.namespace.clone(),
                row.name.clone(),
            )?),
            Self::Node(row) => Ok(KubernetesDetailRequest::cluster_scoped(
                KubernetesResourceKind::Node,
                row.name.clone(),
            )?),
        }
    }

    /// The logs of the listed pod: of the container named, which must be one
    /// of the pod's own, or of its default container.
    fn pod_logs_request(
        &self,
        container: Option<&str>,
    ) -> Result<KubernetesPodLogsRequest, KubernetesReadApiError> {
        match self {
            Self::Pod(row) => {
                let request =
                    KubernetesPodLogsRequest::recent(row.namespace.clone(), row.name.clone())?;
                match container {
                    None => Ok(request),
                    Some(name) if row.container(name).is_some() => {
                        Ok(request.with_container(name)?)
                    }
                    Some(_) => Err(KubernetesReadApiError::ContainerUnavailable),
                }
            }
            _ => Err(KubernetesReadApiError::LogsUnavailable),
        }
    }
}

enum CoreRows {
    Namespaces(KubernetesCollection<KubernetesNamespace>),
    Pods(KubernetesCollection<KubernetesPod>),
    Deployments(KubernetesCollection<KubernetesDeployment>),
    Nodes(KubernetesCollection<KubernetesNode>),
}

impl CoreRows {
    fn into_parts(self) -> (Vec<CoreRow>, bool) {
        match self {
            Self::Namespaces(collection) => (
                collection
                    .items
                    .into_iter()
                    .map(CoreRow::Namespace)
                    .collect(),
                collection.truncated,
            ),
            Self::Pods(collection) => (
                collection.items.into_iter().map(CoreRow::Pod).collect(),
                collection.truncated,
            ),
            Self::Deployments(collection) => (
                collection
                    .items
                    .into_iter()
                    .map(CoreRow::Deployment)
                    .collect(),
                collection.truncated,
            ),
            Self::Nodes(collection) => (
                collection.items.into_iter().map(CoreRow::Node).collect(),
                collection.truncated,
            ),
        }
    }
}

impl SnapshotRegistry {
    fn prune(&mut self, now: Instant) {
        let expired = self
            .snapshots
            .iter()
            .filter_map(|(handle, entry)| (entry.expires_at <= now).then_some(handle.clone()))
            .collect::<Vec<_>>();
        for handle in expired {
            self.remove(&handle);
        }
    }

    fn close_binding(&mut self, binding_handle: &str) {
        let handles = self
            .snapshots
            .iter()
            .filter_map(|(handle, snapshot)| {
                (snapshot.scope.binding_handle == binding_handle).then_some(handle.clone())
            })
            .collect::<Vec<_>>();
        for handle in handles {
            self.remove(&handle);
        }
    }

    fn insert(
        &mut self,
        scope: BindingScope,
        tab: KubernetesReadTab,
        namespace_scoped: bool,
        rows: CoreRows,
        now: Instant,
    ) -> Result<KubernetesSnapshotDto, KubernetesReadApiError> {
        let (source, core_truncated) = rows.into_parts();
        let source_count = source.len();
        let reusable = self.reusable_handles(&scope, tab);
        let sensitive_literals = scope.sensitive_literals();
        let mut seen_ids = HashSet::new();
        let mut stored_rows = HashMap::new();
        let mut projected = Vec::new();
        let mut response_bytes = 0usize;
        let mut storage_bytes = 0usize;
        for row in source.into_iter().take(MAX_ROWS) {
            if !seen_ids.insert(row.id().to_owned()) {
                continue;
            }
            let row_handle = reusable
                .get(row.id())
                .cloned()
                .unwrap_or(self.unique_row_handle()?);
            let dto = project_row(row_handle.clone(), &row, &sensitive_literals)?;
            let dto_bytes = serde_json::to_vec(&dto)
                .map_err(|_| KubernetesReadApiError::Capacity)?
                .len();
            let core_bytes = core_row_bytes(&row)?;
            let next_response_bytes = response_bytes.saturating_add(dto_bytes);
            let next_storage_bytes = storage_bytes.saturating_add(core_bytes);
            if dto_bytes > MAX_ROW_BYTES
                || next_response_bytes > MAX_LIST_BYTES
                || next_storage_bytes > MAX_SNAPSHOT_BYTES
                || next_response_bytes.saturating_add(next_storage_bytes)
                    > MAX_SNAPSHOT_BYTES.saturating_sub(MAX_HANDLE_BYTES)
            {
                break;
            }
            response_bytes = next_response_bytes;
            storage_bytes = next_storage_bytes;
            stored_rows.insert(row_handle, row);
            projected.push(dto);
        }
        let displayed = projected.len();
        let snapshot_handle = unique_handle(&self.snapshots)?;
        let dto = KubernetesSnapshotDto {
            snapshot_handle: snapshot_handle.clone(),
            tab: tab.key(),
            namespace_scoped,
            displayed,
            truncated: core_truncated || displayed < source_count,
            expires_in_seconds: SNAPSHOT_TTL.as_secs(),
            rows: projected,
        };
        let bytes = storage_bytes
            .saturating_add(response_bytes)
            .saturating_add(snapshot_handle.len());
        if bytes > MAX_SNAPSHOT_BYTES {
            return Err(KubernetesReadApiError::Capacity);
        }
        while self.snapshots.len() >= MAX_SNAPSHOTS
            || self.total_bytes.saturating_add(bytes) > MAX_REGISTRY_BYTES
        {
            let Some(oldest) = self
                .snapshots
                .iter()
                .min_by_key(|(_, entry)| entry.touched_at)
                .map(|(handle, _)| handle.clone())
            else {
                break;
            };
            self.remove(&oldest);
        }
        if self.snapshots.len() >= MAX_SNAPSHOTS
            || self.total_bytes.saturating_add(bytes) > MAX_REGISTRY_BYTES
        {
            return Err(KubernetesReadApiError::Capacity);
        }
        self.total_bytes = self.total_bytes.saturating_add(bytes);
        self.snapshots.insert(
            snapshot_handle,
            SnapshotEntry {
                scope,
                tab,
                rows: stored_rows,
                bytes,
                expires_at: now + SNAPSHOT_TTL,
                touched_at: now,
            },
        );
        Ok(dto)
    }

    fn reusable_handles(
        &self,
        scope: &BindingScope,
        tab: KubernetesReadTab,
    ) -> HashMap<String, String> {
        let mut snapshots = self
            .snapshots
            .values()
            .filter(|snapshot| &snapshot.scope == scope && snapshot.tab == tab)
            .collect::<Vec<_>>();
        snapshots.sort_by_key(|snapshot| snapshot.touched_at);
        snapshots
            .into_iter()
            .flat_map(|snapshot| {
                snapshot
                    .rows
                    .iter()
                    .map(|(handle, row)| (row.id().to_owned(), handle.clone()))
            })
            .collect()
    }

    fn unique_row_handle(&self) -> Result<String, KubernetesReadApiError> {
        for _ in 0..8 {
            let handle = Uuid::new_v4().to_string();
            if !self
                .snapshots
                .values()
                .any(|snapshot| snapshot.rows.contains_key(&handle))
            {
                return Ok(handle);
            }
        }
        Err(KubernetesReadApiError::Capacity)
    }

    fn resolve_namespace(
        &mut self,
        scope: &BindingScope,
        snapshot_handle: &str,
        row_handle: &str,
        now: Instant,
    ) -> Result<String, KubernetesReadApiError> {
        let snapshot = self
            .snapshots
            .get_mut(snapshot_handle)
            .filter(|snapshot| {
                &snapshot.scope == scope
                    && snapshot.tab == KubernetesReadTab::Namespaces
                    && snapshot.expires_at > now
            })
            .ok_or(KubernetesReadApiError::NamespaceUnavailable)?;
        let CoreRow::Namespace(row) = snapshot
            .rows
            .get(row_handle)
            .ok_or(KubernetesReadApiError::NamespaceUnavailable)?
        else {
            return Err(KubernetesReadApiError::NamespaceUnavailable);
        };
        snapshot.expires_at = now + SNAPSHOT_TTL;
        snapshot.touched_at = now;
        Ok(row.name.clone())
    }

    fn resolve_row(
        &mut self,
        scope: &BindingScope,
        snapshot_handle: &str,
        row_handle: &str,
        now: Instant,
    ) -> Result<CoreRow, KubernetesReadApiError> {
        let snapshot = self
            .snapshots
            .get_mut(snapshot_handle)
            .filter(|snapshot| &snapshot.scope == scope && snapshot.expires_at > now)
            .ok_or(KubernetesReadApiError::SnapshotUnavailable)?;
        let row = snapshot
            .rows
            .get(row_handle)
            .cloned()
            .ok_or(KubernetesReadApiError::RowUnavailable)?;
        snapshot.expires_at = now + SNAPSHOT_TTL;
        snapshot.touched_at = now;
        Ok(row)
    }

    fn remove(&mut self, handle: &str) {
        if let Some(snapshot) = self.snapshots.remove(handle) {
            self.total_bytes = self.total_bytes.saturating_sub(snapshot.bytes);
        }
    }
}

fn project_availability(
    value: KubernetesAvailability,
    sensitive_literals: &[&str],
) -> KubernetesAvailabilityDto {
    let (current_context, context_truncated, _) =
        project_single_line(&value.current_context, 1024, sensitive_literals);
    KubernetesAvailabilityDto {
        kubectl_installed: value.kubectl_installed,
        api_reachable: value.api_reachable,
        current_context,
        context_truncated,
        // A namespace name carrying an internal handle is dropped, not shown.
        context_namespace: value.context_namespace.filter(|namespace| {
            !sensitive_literals
                .iter()
                .any(|literal| !literal.is_empty() && namespace.contains(literal))
        }),
    }
}

fn project_row(
    row_handle: String,
    row: &CoreRow,
    sensitive_literals: &[&str],
) -> Result<KubernetesRowDto, KubernetesReadApiError> {
    let mut budget = TextBudget::new(MAX_ROW_BYTES);
    Ok(match row {
        CoreRow::Namespace(row) => {
            let (name, name_truncated) =
                budget.take(&row.name, MAX_FIELD_BYTES, sensitive_literals);
            let (phase, phase_truncated) =
                budget.take(&row.phase, MAX_FIELD_BYTES, sensitive_literals);
            let (created_at, created_truncated) =
                budget.take(&row.created_at, MAX_FIELD_BYTES, sensitive_literals);
            KubernetesRowDto::Namespace {
                row_handle,
                name,
                phase,
                created_at,
                text_truncated: name_truncated || phase_truncated || created_truncated,
            }
        }
        CoreRow::Pod(row) => {
            let (namespace, namespace_truncated) =
                budget.take(&row.namespace, MAX_FIELD_BYTES, sensitive_literals);
            let (name, name_truncated) =
                budget.take(&row.name, MAX_FIELD_BYTES, sensitive_literals);
            let (phase, phase_truncated) =
                budget.take(&row.phase, MAX_FIELD_BYTES, sensitive_literals);
            let (node, node_truncated) =
                budget.take(&row.node, MAX_FIELD_BYTES, sensitive_literals);
            let (pod_ip, ip_truncated) =
                budget.take(&row.pod_ip, MAX_FIELD_BYTES, sensitive_literals);
            let (created_at, created_truncated) =
                budget.take(&row.created_at, MAX_FIELD_BYTES, sensitive_literals);
            let (images, images_truncated) =
                budget.take_many(&row.images, MAX_IMAGES, sensitive_literals);
            let (mut ready_containers, mut ready_truncated) = bounded_usize(row.ready_containers);
            let (total_containers, total_truncated) = bounded_usize(row.total_containers);
            if ready_containers > total_containers {
                ready_containers = total_containers;
                ready_truncated = true;
            }
            let (restarts, restarts_truncated) = bounded_u64(row.restarts);
            // Names are DNS labels core already checked; images are text.
            let containers_truncated = row.containers.len() > MAX_IMAGES;
            let mut container_images_truncated = false;
            let containers = row
                .containers
                .iter()
                .take(MAX_IMAGES)
                .map(|container| {
                    let (image, truncated) =
                        budget.take(&container.image, MAX_FIELD_BYTES, sensitive_literals);
                    container_images_truncated |= truncated;
                    let (restarts, _) = bounded_u64(container.restarts);
                    KubernetesPodContainerDto {
                        name: container.name.clone(),
                        image,
                        ready: container.ready,
                        running: container.running,
                        restarts,
                    }
                })
                .collect::<Vec<_>>();
            let default_container = row
                .default_container
                .clone()
                .filter(|name| containers.iter().any(|container| &container.name == name));
            KubernetesRowDto::Pod {
                row_handle,
                namespace,
                name,
                phase,
                ready_containers,
                total_containers,
                restarts,
                node,
                pod_ip,
                images,
                created_at,
                supports_logs: true,
                containers,
                default_container,
                text_truncated: containers_truncated
                    || container_images_truncated
                    || namespace_truncated
                    || name_truncated
                    || phase_truncated
                    || node_truncated
                    || ip_truncated
                    || created_truncated
                    || images_truncated
                    || ready_truncated
                    || total_truncated
                    || restarts_truncated,
            }
        }
        CoreRow::Deployment(row) => {
            let (namespace, namespace_truncated) =
                budget.take(&row.namespace, MAX_FIELD_BYTES, sensitive_literals);
            let (name, name_truncated) =
                budget.take(&row.name, MAX_FIELD_BYTES, sensitive_literals);
            let (created_at, created_truncated) =
                budget.take(&row.created_at, MAX_FIELD_BYTES, sensitive_literals);
            let (images, images_truncated) =
                budget.take_many(&row.images, MAX_IMAGES, sensitive_literals);
            let (desired_replicas, desired_truncated) = bounded_u64(row.desired_replicas);
            let (ready_replicas, ready_truncated) = bounded_u64(row.ready_replicas);
            let (available_replicas, available_truncated) = bounded_u64(row.available_replicas);
            let (updated_replicas, updated_truncated) = bounded_u64(row.updated_replicas);
            KubernetesRowDto::Deployment {
                row_handle,
                namespace,
                name,
                desired_replicas,
                ready_replicas,
                available_replicas,
                updated_replicas,
                images,
                created_at,
                text_truncated: namespace_truncated
                    || name_truncated
                    || created_truncated
                    || images_truncated
                    || desired_truncated
                    || ready_truncated
                    || available_truncated
                    || updated_truncated,
            }
        }
        CoreRow::Node(row) => {
            let (name, name_truncated) =
                budget.take(&row.name, MAX_FIELD_BYTES, sensitive_literals);
            let (kubelet_version, version_truncated) =
                budget.take(&row.kubelet_version, MAX_FIELD_BYTES, sensitive_literals);
            let (internal_ip, ip_truncated) =
                budget.take(&row.internal_ip, MAX_FIELD_BYTES, sensitive_literals);
            let (cpu_capacity, cpu_truncated) =
                budget.take(&row.cpu_capacity, MAX_FIELD_BYTES, sensitive_literals);
            let (memory_capacity, memory_truncated) =
                budget.take(&row.memory_capacity, MAX_FIELD_BYTES, sensitive_literals);
            let (pod_capacity, pod_truncated) =
                budget.take(&row.pod_capacity, MAX_FIELD_BYTES, sensitive_literals);
            let (created_at, created_truncated) =
                budget.take(&row.created_at, MAX_FIELD_BYTES, sensitive_literals);
            let (roles, roles_truncated) =
                budget.take_many(&row.roles, MAX_ROLES, sensitive_literals);
            KubernetesRowDto::Node {
                row_handle,
                name,
                ready: row.ready,
                unschedulable: row.unschedulable,
                roles,
                kubelet_version,
                internal_ip,
                cpu_capacity,
                memory_capacity,
                pod_capacity,
                created_at,
                text_truncated: name_truncated
                    || version_truncated
                    || ip_truncated
                    || cpu_truncated
                    || memory_truncated
                    || pod_truncated
                    || created_truncated
                    || roles_truncated,
            }
        }
    })
}

/// What the host writes: a suggested file name and the manifest under a
/// commented header. Never sent to a page.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KubernetesManifestExportDto {
    suggested_name: String,
    contents: String,
    kind: &'static str,
    name: String,
}

/// The header says where, when and how the manifest was read, and that it is
/// the cluster's own text; YAML comments, so the file still applies and
/// diffs as the manifest it is.
fn manifest_export(
    manifest: &KubernetesManifest,
    source: Option<&str>,
) -> KubernetesManifestExportDto {
    let plain = |value: &str| -> String {
        value
            .chars()
            .filter(|character| !character.is_control())
            .take(512)
            .collect()
    };
    let object = match &manifest.namespace {
        Some(namespace) => format!("{namespace}/{}", manifest.name),
        None => manifest.name.clone(),
    };
    let get = match &manifest.namespace {
        Some(namespace) => format!(
            "kubectl get {} {} -n {namespace} -o yaml",
            manifest.kind.to_ascii_lowercase(),
            manifest.name
        ),
        None => format!(
            "kubectl get {} {} -o yaml",
            manifest.kind.to_ascii_lowercase(),
            manifest.name
        ),
    };
    let header = [
        "# LovelyHawk 导出的 Kubernetes 对象清单（只读导出，没有改动集群）".to_owned(),
        format!(
            "# 来源 SSH 主机：{}",
            source.map(plain).unwrap_or_else(|| "（未读到）".to_owned())
        ),
        format!(
            "# kubeconfig 上下文：{}",
            if manifest.context.is_empty() {
                "（未读到）".to_owned()
            } else {
                plain(&manifest.context)
            }
        ),
        format!("# 对象：{} {object}", manifest.kind),
        format!(
            "# UID：{}  resourceVersion：{}",
            plain(&manifest.uid),
            plain(&manifest.resource_version)
        ),
        // This machine's clock: the cluster's may differ by seconds, and the
        // manifest's own timestamps are the cluster's.
        format!(
            "# 读取时间（本机时钟，UTC）：{}",
            manifest.read_at.format("%Y-%m-%dT%H:%M:%SZ")
        ),
        format!("# 方法：{get}；以下是 kubectl 输出的原文。"),
        "# 原文可能含有环境变量等字段里的明文口令或令牌，请按证据保管。".to_owned(),
    ]
    .join("\n");
    let stamp = manifest.read_at.format("%Y%m%dT%H%M%SZ");
    // Names are DNS names (letters, digits, '-', '.'), but a pod's may run to
    // 253 characters and a file name may not; the stem is cut, the time kept.
    let stem: String = match &manifest.namespace {
        Some(namespace) => format!(
            "{}-{namespace}-{}",
            manifest.kind.to_ascii_lowercase(),
            manifest.name
        ),
        None => format!("{}-{}", manifest.kind.to_ascii_lowercase(), manifest.name),
    }
    .chars()
    .take(180)
    .collect();
    let suggested_name = format!("{}-{stamp}.yaml", stem.trim_end_matches(['.', '-']));
    KubernetesManifestExportDto {
        suggested_name,
        contents: format!("{header}\n{}", manifest.yaml),
        kind: manifest.kind,
        name: object,
    }
}

fn project_text(
    snapshot_handle: &str,
    row_handle: &str,
    content_kind: &'static str,
    text: KubernetesText,
    maximum_bytes: usize,
    sensitive_literals: &[&str],
) -> KubernetesTextDto {
    let (bounded, projected) =
        project_public_multiline(&text.text, maximum_bytes, sensitive_literals);
    KubernetesTextDto {
        snapshot_handle: snapshot_handle.to_owned(),
        row_handle: row_handle.to_owned(),
        content_kind,
        text: bounded,
        truncated: text.truncated || projected,
    }
}

fn core_row_bytes(row: &CoreRow) -> Result<usize, KubernetesReadApiError> {
    let bytes = match row {
        CoreRow::Namespace(row) => serde_json::to_vec(row),
        CoreRow::Pod(row) => serde_json::to_vec(row),
        CoreRow::Deployment(row) => serde_json::to_vec(row),
        CoreRow::Node(row) => serde_json::to_vec(row),
    }
    .map_err(|_| KubernetesReadApiError::Capacity)?
    .len();
    Ok(bytes)
}

struct TextBudget {
    remaining: usize,
}

impl TextBudget {
    const fn new(remaining: usize) -> Self {
        Self { remaining }
    }

    fn take(
        &mut self,
        value: &str,
        field_limit: usize,
        sensitive_literals: &[&str],
    ) -> (String, bool) {
        let limit = self.remaining.min(field_limit);
        let (output, projected, _) = project_single_line(value, limit, sensitive_literals);
        self.remaining = self.remaining.saturating_sub(output.len());
        (output, projected)
    }

    fn take_many(
        &mut self,
        values: &[String],
        maximum_items: usize,
        sensitive_literals: &[&str],
    ) -> (Vec<String>, bool) {
        let mut output = Vec::new();
        let mut truncated = values.len() > maximum_items;
        for value in values.iter().take(maximum_items) {
            if self.remaining == 0 {
                truncated = true;
                break;
            }
            let (value, item_truncated) = self.take(value, MAX_FIELD_BYTES, sensitive_literals);
            output.push(value);
            truncated |= item_truncated;
        }
        (output, truncated)
    }
}

fn project_single_line(
    value: &str,
    maximum_bytes: usize,
    sensitive_literals: &[&str],
) -> (String, bool, bool) {
    if is_sensitive_text(value, sensitive_literals) {
        return if REDACTED_KUBERNETES_TEXT.len() <= maximum_bytes {
            (REDACTED_KUBERNETES_TEXT.to_owned(), true, false)
        } else {
            (String::new(), true, true)
        };
    }
    normalize_bounded_line(value, maximum_bytes, false)
}

fn project_public_multiline(
    value: &str,
    maximum_bytes: usize,
    sensitive_literals: &[&str],
) -> (String, bool) {
    let mut output = String::with_capacity(value.len().min(maximum_bytes));
    let mut projected = false;
    let mut first = true;
    for line in value.split('\n') {
        if !first {
            if output.len() >= maximum_bytes {
                projected = true;
                break;
            }
            output.push('\n');
        }
        first = false;
        let remaining = maximum_bytes.saturating_sub(output.len());
        if is_sensitive_text(line, sensitive_literals) {
            projected = true;
            if REDACTED_KUBERNETES_TEXT.len() > remaining {
                break;
            }
            output.push_str(REDACTED_KUBERNETES_TEXT);
            continue;
        }
        let (line, line_projected, line_truncated) = normalize_bounded_line(line, remaining, true);
        output.push_str(&line);
        projected |= line_projected;
        if line_truncated {
            break;
        }
    }
    (output, projected)
}

fn normalize_bounded_line(
    value: &str,
    maximum_bytes: usize,
    allow_tab: bool,
) -> (String, bool, bool) {
    let mut output = String::with_capacity(value.len().min(maximum_bytes));
    let mut projected = false;
    for character in value.chars() {
        let replacement = if (allow_tab && character == '\t') || !character.is_control() {
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
    value.contains(REDACTED_KUBERNETES_TEXT)
        || sensitive_literals
            .iter()
            .any(|literal| !literal.is_empty() && value.contains(*literal))
}

fn bounded_u64(value: u64) -> (u64, bool) {
    (
        value.min(MAX_SAFE_JSON_INTEGER),
        value > MAX_SAFE_JSON_INTEGER,
    )
}

fn bounded_usize(value: usize) -> (u64, bool) {
    let value = u64::try_from(value).unwrap_or(u64::MAX);
    bounded_u64(value)
}

fn validate_handle(value: &str) -> Result<(), KubernetesReadApiError> {
    if value.is_empty()
        || value.len() > MAX_HANDLE_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(KubernetesReadApiError::InvalidHandle);
    }
    Ok(())
}

fn unique_handle<T>(existing: &HashMap<String, T>) -> Result<String, KubernetesReadApiError> {
    for _ in 0..8 {
        let handle = Uuid::new_v4().to_string();
        if !existing.contains_key(&handle) {
            return Ok(handle);
        }
    }
    Err(KubernetesReadApiError::Capacity)
}

#[cfg(test)]
mod manifest_tests {
    use super::*;
    use chrono::TimeZone;

    fn manifest(namespace: Option<&str>, kind: &'static str, name: &str) -> KubernetesManifest {
        KubernetesManifest {
            kind,
            namespace: namespace.map(str::to_owned),
            name: name.to_owned(),
            uid: "uid-1".to_owned(),
            resource_version: "42".to_owned(),
            context: "lab\u{7}-k3s".to_owned(),
            read_at: chrono::Utc
                .with_ymd_and_hms(2026, 10, 12, 10, 15, 0)
                .unwrap(),
            yaml: format!("apiVersion: v1\nkind: {kind}\nmetadata:\n  name: {name}\n"),
        }
    }

    /// The file says where, when and how it was read, in comments above the
    /// manifest, which is kept byte for byte; the suggested name is plain.
    #[test]
    fn a_manifest_export_says_where_it_came_from_and_keeps_the_yaml() {
        let pod = manifest(Some("incident"), "Pod", "api-7f98d");
        let dto = manifest_export(&pod, Some("root@192.0.2.10:22"));
        assert_eq!(
            dto.suggested_name,
            "pod-incident-api-7f98d-20261012T101500Z.yaml"
        );
        assert!(
            dto.contents.ends_with(&format!("\n{}", pod.yaml)),
            "{}",
            dto.contents
        );
        let header = dto
            .contents
            .lines()
            .take_while(|line| line.starts_with('#'))
            .collect::<Vec<_>>();
        assert_eq!(header.len(), 8, "{header:?}");
        for expected in [
            "# 来源 SSH 主机：root@192.0.2.10:22",
            // A control character the cluster sent is not carried into the file.
            "# kubeconfig 上下文：lab-k3s",
            "# 对象：Pod incident/api-7f98d",
            "# UID：uid-1  resourceVersion：42",
            "# 读取时间（本机时钟，UTC）：2026-10-12T10:15:00Z",
            "# 方法：kubectl get pod api-7f98d -n incident -o yaml；以下是 kubectl 输出的原文。",
        ] {
            assert!(header.contains(&expected), "{expected} not in {header:?}");
        }
        assert!(header.iter().any(|line| line.contains("明文口令")));

        // A name as long as a pod's may be still makes a file name the host
        // takes (its limit is 240 bytes).
        let long = manifest(Some("incident"), "Pod", &"a".repeat(253));
        let name = manifest_export(&long, None).suggested_name;
        assert!(
            name.len() <= 240 && name.ends_with("-20261012T101500Z.yaml"),
            "{name}"
        );

        let node = manifest(None, "Node", "worker-1");
        let dto = manifest_export(&node, None);
        assert_eq!(dto.suggested_name, "node-worker-1-20261012T101500Z.yaml");
        assert!(dto.contents.contains("# 来源 SSH 主机：（未读到）"));
        assert!(dto.contents.contains("kubectl get node worker-1 -o yaml"));
    }
}

#[cfg(test)]
mod tests {
    use lovelyhawk_core::{kubernetes::KubernetesRowId, target::TargetIdentity};

    use super::*;

    fn row_id(value: &str) -> KubernetesRowId {
        serde_json::from_value(serde_json::json!(value)).unwrap()
    }

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

    fn namespace(uid: &str, name: &str) -> KubernetesNamespace {
        KubernetesNamespace {
            id: row_id(&format!("namespace:{uid}")),
            name: name.to_owned(),
            phase: "Active".to_owned(),
            created_at: "2026-08-24T00:00:00Z".to_owned(),
        }
    }

    fn pod(uid: &str, name: &str, image: &str) -> KubernetesPod {
        KubernetesPod {
            id: row_id(&format!("pod:{uid}")),
            namespace: "default".to_owned(),
            name: name.to_owned(),
            phase: "Running".to_owned(),
            ready_containers: 1,
            total_containers: 1,
            restarts: 0,
            node: "worker-1".to_owned(),
            pod_ip: "10.0.0.2".to_owned(),
            images: vec![image.to_owned()],
            created_at: "2026-08-24T00:00:00Z".to_owned(),
            containers: vec![lovelyhawk_core::kubernetes::KubernetesPodContainer {
                name: "app".to_owned(),
                image: image.to_owned(),
                ready: true,
                running: true,
                restarts: 0,
            }],
            default_container: Some("app".to_owned()),
        }
    }

    fn projected_row_handle(row: &KubernetesRowDto) -> &str {
        match row {
            KubernetesRowDto::Namespace { row_handle, .. }
            | KubernetesRowDto::Pod { row_handle, .. }
            | KubernetesRowDto::Deployment { row_handle, .. }
            | KubernetesRowDto::Node { row_handle, .. } => row_handle,
        }
    }

    #[test]
    fn list_input_is_closed_and_namespace_scope_is_opaque() {
        let pods: KubernetesListInput = serde_json::from_value(serde_json::json!({
            "tab": "pods",
            "namespaceScope": {
                "snapshotHandle": "snapshot-opaque",
                "rowHandle": "row-opaque"
            }
        }))
        .unwrap();
        assert!(pods.validate().is_ok());
        let nodes: KubernetesListInput = serde_json::from_value(serde_json::json!({
            "tab": "nodes",
            "namespaceScope": null
        }))
        .unwrap();
        assert!(nodes.validate().is_ok());
        let scoped_nodes: KubernetesListInput = serde_json::from_value(serde_json::json!({
            "tab": "nodes",
            "namespaceScope": {
                "snapshotHandle": "snapshot-opaque",
                "rowHandle": "row-opaque"
            }
        }))
        .unwrap();
        assert!(scoped_nodes.validate().is_err());
        assert!(
            serde_json::from_value::<KubernetesListInput>(serde_json::json!({
                "tab": "pods",
                "namespace": "attacker",
                "namespaceScope": null
            }))
            .is_err()
        );

        // The kubeconfig's own namespace: named by nothing but `context: true`.
        let context = |tab: &str, scope: serde_json::Value| {
            serde_json::from_value::<KubernetesListInput>(serde_json::json!({
                "tab": tab,
                "namespaceScope": scope
            }))
        };
        let in_context = context("pods", serde_json::json!({ "context": true })).unwrap();
        assert!(in_context.validate().is_ok());
        assert!(matches!(
            in_context.namespace_scope,
            Some(KubernetesNamespaceScopeInput::Context(_))
        ));
        assert!(
            context("deployments", serde_json::json!({ "context": true }))
                .unwrap()
                .validate()
                .is_ok()
        );
        assert!(
            context("pods", serde_json::json!({ "context": false }))
                .unwrap()
                .validate()
                .is_err()
        );
        assert!(
            context("nodes", serde_json::json!({ "context": true }))
                .unwrap()
                .validate()
                .is_err()
        );
        for forged in [
            serde_json::json!({ "context": true, "namespace": "kube-system" }),
            serde_json::json!({ "context": true, "snapshotHandle": "s", "rowHandle": "r" }),
            serde_json::json!({ "context": "true" }),
            serde_json::json!({ "namespace": "kube-system" }),
            serde_json::json!({}),
        ] {
            assert!(context("pods", forged.clone()).is_err(), "{forged}");
        }
    }

    #[test]
    fn snapshot_handles_are_stable_for_uid_target_scoped_and_expiring() {
        let now = Instant::now();
        let current = scope("cluster-one", 1);
        let stale = scope("cluster-one", 2);
        let mut registry = SnapshotRegistry::default();
        let first = registry
            .insert(
                current.clone(),
                KubernetesReadTab::Pods,
                false,
                CoreRows::Pods(KubernetesCollection {
                    items: vec![pod("uid-a", "api", "registry/api:1")],
                    truncated: false,
                }),
                now,
            )
            .unwrap();
        let first_row = match &first.rows[0] {
            KubernetesRowDto::Pod { row_handle, .. } => row_handle.clone(),
            _ => panic!("expected pod"),
        };
        let second = registry
            .insert(
                current.clone(),
                KubernetesReadTab::Pods,
                false,
                CoreRows::Pods(KubernetesCollection {
                    items: vec![pod("uid-a", "api-renamed-display", "registry/api:2")],
                    truncated: false,
                }),
                now,
            )
            .unwrap();
        let second_row = match &second.rows[0] {
            KubernetesRowDto::Pod { row_handle, .. } => row_handle.clone(),
            _ => panic!("expected pod"),
        };
        assert_eq!(first_row, second_row);
        assert!(
            registry
                .resolve_row(&stale, &second.snapshot_handle, &second_row, now)
                .is_err()
        );
        assert!(
            registry
                .resolve_row(
                    &current,
                    &second.snapshot_handle,
                    &second_row,
                    now + SNAPSHOT_TTL + Duration::from_secs(1),
                )
                .is_err()
        );
    }

    #[test]
    fn close_binding_invalidates_only_its_snapshots_and_late_capabilities() {
        let now = Instant::now();
        let closed = scope("cluster-one", 1);
        let kept = scope("cluster-two", 1);
        let mut registry = SnapshotRegistry::default();
        let closed_snapshot = registry
            .insert(
                closed.clone(),
                KubernetesReadTab::Pods,
                false,
                CoreRows::Pods(KubernetesCollection {
                    items: vec![pod("closed", "closed", "closed:1")],
                    truncated: false,
                }),
                now,
            )
            .unwrap();
        let kept_snapshot = registry
            .insert(
                kept.clone(),
                KubernetesReadTab::Pods,
                false,
                CoreRows::Pods(KubernetesCollection {
                    items: vec![pod("kept", "kept", "kept:1")],
                    truncated: false,
                }),
                now,
            )
            .unwrap();
        let closed_row = projected_row_handle(&closed_snapshot.rows[0]).to_owned();
        let kept_row = projected_row_handle(&kept_snapshot.rows[0]).to_owned();
        let bytes_before = registry.total_bytes;

        registry.close_binding(&closed.binding_handle);

        assert!(registry.total_bytes < bytes_before);
        assert!(
            registry
                .resolve_row(&closed, &closed_snapshot.snapshot_handle, &closed_row, now,)
                .is_err()
        );
        assert!(
            registry
                .resolve_row(&kept, &kept_snapshot.snapshot_handle, &kept_row, now)
                .is_ok()
        );

        let reopened = registry
            .insert(
                scope("cluster-one", 2),
                KubernetesReadTab::Pods,
                false,
                CoreRows::Pods(KubernetesCollection {
                    items: vec![pod("reopened", "reopened", "reopened:1")],
                    truncated: false,
                }),
                now,
            )
            .unwrap();
        assert_eq!(reopened.displayed, 1);
    }

    #[test]
    fn namespace_capability_never_accepts_a_pod_or_another_target() {
        let now = Instant::now();
        let current = scope("cluster-one", 1);
        let other = scope("cluster-two", 1);
        let mut registry = SnapshotRegistry::default();
        let namespaces = registry
            .insert(
                current.clone(),
                KubernetesReadTab::Namespaces,
                false,
                CoreRows::Namespaces(KubernetesCollection {
                    items: vec![namespace("uid-default", "default")],
                    truncated: false,
                }),
                now,
            )
            .unwrap();
        let namespace_row = match &namespaces.rows[0] {
            KubernetesRowDto::Namespace { row_handle, .. } => row_handle.clone(),
            _ => panic!("expected namespace"),
        };
        assert_eq!(
            registry
                .resolve_namespace(&current, &namespaces.snapshot_handle, &namespace_row, now,)
                .unwrap(),
            "default"
        );
        assert!(
            registry
                .resolve_namespace(&other, &namespaces.snapshot_handle, &namespace_row, now)
                .is_err()
        );
    }

    #[test]
    fn hostile_row_text_is_bounded_plain_data_and_uid_never_serializes() {
        let hostile = "</code><img src=x onerror=steal()><script>bad()</script>";
        let current = scope("secret-cluster", 9);
        let mut registry = SnapshotRegistry::default();
        let snapshot = registry
            .insert(
                current.clone(),
                KubernetesReadTab::Pods,
                false,
                CoreRows::Pods(KubernetesCollection {
                    items: vec![pod("secret-resource-uid", "api", hostile)],
                    truncated: false,
                }),
                Instant::now(),
            )
            .unwrap();
        let encoded = serde_json::to_string(&snapshot).unwrap();
        assert!(encoded.contains(hostile));
        for forbidden in [
            "secret-resource-uid",
            "secret-cluster",
            "sessionId",
            "targetGuard",
            "generation",
            "identity",
            "resourceUid",
            "command",
        ] {
            assert!(!encoded.contains(forbidden), "leaked {forbidden}");
        }
        assert!(!format!("{current:?}").contains("secret-cluster"));
    }

    #[test]
    fn controls_and_unsafe_json_numbers_are_sanitized_or_bounded() {
        let mut hostile_pod = pod("uid-hostile", "api\0name", "image\u{7f}");
        hostile_pod.ready_containers = usize::MAX;
        hostile_pod.total_containers = 0;
        hostile_pod.restarts = u64::MAX;
        let projected =
            project_row("row-opaque".to_owned(), &CoreRow::Pod(hostile_pod), &[]).unwrap();
        let KubernetesRowDto::Pod {
            name,
            images,
            ready_containers,
            total_containers,
            restarts,
            text_truncated,
            ..
        } = projected
        else {
            panic!("expected pod");
        };
        assert!(!name.contains('\0'));
        assert!(!images[0].contains('\u{7f}'));
        assert_eq!(ready_containers, total_containers);
        assert!(restarts <= MAX_SAFE_JSON_INTEGER);
        assert!(text_truncated);

        let text = project_text(
            "snapshot",
            "row",
            "pod-logs",
            KubernetesText {
                text: "line\nkept\0replaced".to_owned(),
                truncated: false,
            },
            MAX_LOG_BYTES,
            &[],
        );
        assert!(text.text.contains('\n'));
        assert!(!text.text.contains('\0'));
        assert!(text.truncated);
    }

    #[test]
    fn public_text_scrubs_binding_literals_and_marker_injection_only() {
        let hostile = "</pre><script>plain-hostile-text()</script>";
        let sensitive_literals = [
            "binding-internal-secret",
            "session-internal-secret",
            "connection-internal-secret",
            "target-internal-secret",
        ];
        let projected = project_text(
            "snapshot",
            "row",
            "pod-logs",
            KubernetesText {
                text: format!(
                    "{hostile}\npassword=credential-secret\n{{\"clientSecret\":\"json-secret\"}}\ncontains {}\ncontains {}\n{} suffix\nsafe final line",
                    sensitive_literals[0], sensitive_literals[1], REDACTED_KUBERNETES_TEXT,
                ),
                truncated: false,
            },
            MAX_LOG_BYTES,
            &sensitive_literals,
        );
        assert!(projected.text.contains(hostile));
        assert!(projected.truncated);
        // Pod output is shown as the pod wrote it; only our own handles and an
        // injected marker are scrubbed.
        assert!(projected.text.contains("credential-secret"));
        assert!(projected.text.contains("json-secret"));
        for forbidden in ["binding-internal-secret", "session-internal-secret"] {
            assert!(!projected.text.contains(forbidden));
        }

        let detail = project_text(
            "snapshot",
            "row",
            "detail",
            KubernetesText {
                text: "Authorization: Bearer detail-secret".to_owned(),
                truncated: false,
            },
            MAX_DETAIL_BYTES,
            &sensitive_literals,
        );
        // An Authorization header in a resource detail is the finding.
        assert_eq!(detail.text, "Authorization: Bearer detail-secret");
        assert!(!detail.truncated);

        let availability = project_availability(
            KubernetesAvailability {
                kubectl_installed: true,
                api_reachable: true,
                current_context: "target-internal-secret".to_owned(),
                context_namespace: Some("target-internal-secret".to_owned()),
            },
            &sensitive_literals,
        );
        assert_eq!(availability.current_context, REDACTED_KUBERNETES_TEXT);
        assert!(availability.context_truncated);
        assert_eq!(availability.context_namespace, None);
        let ordinary = project_availability(
            KubernetesAvailability {
                kubectl_installed: true,
                api_reachable: true,
                current_context: "viewer@lab".to_owned(),
                context_namespace: Some("payments".to_owned()),
            },
            &sensitive_literals,
        );
        assert_eq!(ordinary.context_namespace.as_deref(), Some("payments"));

        let mut secret_row = pod("uid-secret", "api", "token=image-secret");
        secret_row.node = "connection-internal-secret".to_owned();
        let row = project_row(
            "row-opaque".to_owned(),
            &CoreRow::Pod(secret_row),
            &sensitive_literals,
        )
        .unwrap();
        let KubernetesRowDto::Pod {
            images,
            node,
            text_truncated,
            ..
        } = row
        else {
            panic!("expected pod");
        };
        assert_eq!(images, vec!["token=image-secret".to_owned()]);
        assert_eq!(node, REDACTED_KUBERNETES_TEXT);
        assert!(text_truncated);
    }

    #[test]
    fn duplicate_ids_are_not_projected_as_ambiguous_row_capabilities() {
        let mut registry = SnapshotRegistry::default();
        let snapshot = registry
            .insert(
                scope("cluster-one", 1),
                KubernetesReadTab::Pods,
                false,
                CoreRows::Pods(KubernetesCollection {
                    items: vec![
                        pod("same-uid", "first", "first:1"),
                        pod("same-uid", "second", "second:1"),
                    ],
                    truncated: false,
                }),
                Instant::now(),
            )
            .unwrap();
        assert_eq!(snapshot.displayed, 1);
        assert!(snapshot.truncated);
    }

    #[test]
    fn registry_evicts_oldest_snapshots_at_the_hard_cap() {
        let now = Instant::now();
        let current = scope("cluster-one", 1);
        let mut registry = SnapshotRegistry::default();
        let mut first_handle = String::new();
        for index in 0..=MAX_SNAPSHOTS {
            let snapshot = registry
                .insert(
                    current.clone(),
                    KubernetesReadTab::Pods,
                    false,
                    CoreRows::Pods(KubernetesCollection {
                        items: vec![pod(
                            &format!("uid-{index}"),
                            &format!("pod-{index}"),
                            "image:1",
                        )],
                        truncated: false,
                    }),
                    now + Duration::from_millis(index as u64),
                )
                .unwrap();
            if index == 0 {
                first_handle = snapshot.snapshot_handle;
            }
        }
        assert_eq!(registry.snapshots.len(), MAX_SNAPSHOTS);
        assert!(!registry.snapshots.contains_key(&first_handle));
        assert!(registry.total_bytes <= MAX_REGISTRY_BYTES);
    }

    #[test]
    fn oversized_core_rows_fail_closed_inside_snapshot_and_registry_byte_caps() {
        let mut registry = SnapshotRegistry::default();
        let snapshot = registry
            .insert(
                scope("cluster-one", 1),
                KubernetesReadTab::Pods,
                false,
                CoreRows::Pods(KubernetesCollection {
                    items: vec![pod(
                        "oversized",
                        "oversized",
                        &"x".repeat(MAX_SNAPSHOT_BYTES + 1),
                    )],
                    truncated: false,
                }),
                Instant::now(),
            )
            .unwrap();
        assert_eq!(snapshot.displayed, 0);
        assert!(snapshot.truncated);
        assert!(registry.total_bytes <= MAX_REGISTRY_BYTES);
        assert!(
            registry
                .snapshots
                .get(&snapshot.snapshot_handle)
                .is_some_and(|entry| entry.bytes <= MAX_SNAPSHOT_BYTES)
        );
    }

    #[test]
    fn core_errors_have_fixed_redacted_debug_and_no_public_source_chain() {
        let error = KubernetesReadApiError::from(CoreError::Ssh {
            operation: "read",
            message: "secret target stderr".to_owned(),
        });
        let debug = format!("{error:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("secret"));
        assert_eq!(error.to_string(), "the Kubernetes read operation failed");
        assert!(std::error::Error::source(&error).is_none());
    }

    #[test]
    fn detail_and_logs_have_independent_utf8_byte_bounds() {
        let text = KubernetesText {
            text: "界".repeat(MAX_LOG_BYTES),
            truncated: false,
        };
        let detail = project_text(
            "snapshot",
            "row",
            "detail",
            text.clone(),
            MAX_DETAIL_BYTES,
            &[],
        );
        let logs = project_text("snapshot", "row", "pod-logs", text, MAX_LOG_BYTES, &[]);
        assert!(detail.text.len() <= MAX_DETAIL_BYTES);
        assert!(logs.text.len() <= MAX_LOG_BYTES);
        assert!(detail.truncated);
        assert!(logs.truncated);
    }

    #[test]
    fn concurrency_is_bounded_per_binding_and_released_on_drop() {
        let state = Arc::new(Mutex::new(ConcurrencyState::default()));
        let permits = (0..MAX_READS_PER_BINDING)
            .map(|_| ReadPermit::acquire(Arc::clone(&state), "binding-one".to_owned()).unwrap())
            .collect::<Vec<_>>();
        assert!(ReadPermit::acquire(Arc::clone(&state), "binding-one".to_owned()).is_err());
        drop(permits);
        assert!(ReadPermit::acquire(state, "binding-one".to_owned()).is_ok());
    }

    #[test]
    fn concurrency_is_globally_bounded_across_distinct_bindings() {
        let state = Arc::new(Mutex::new(ConcurrencyState::default()));
        let permits = (0..MAX_GLOBAL_READS)
            .map(|index| {
                ReadPermit::acquire(Arc::clone(&state), format!("binding-{index}")).unwrap()
            })
            .collect::<Vec<_>>();
        assert!(ReadPermit::acquire(Arc::clone(&state), "overflow".to_owned()).is_err());
        drop(permits);
        assert!(ReadPermit::acquire(state, "after-drop".to_owned()).is_ok());
    }

    #[test]
    fn non_pod_rows_cannot_create_log_requests() {
        let row = CoreRow::Namespace(namespace("uid-default", "default"));
        assert!(matches!(
            row.pod_logs_request(None),
            Err(KubernetesReadApiError::LogsUnavailable)
        ));
    }

    #[test]
    fn pod_logs_name_only_one_of_the_listed_pods_containers() {
        let row = CoreRow::Pod(pod("uid-api", "api", "registry.example/api:1"));
        assert!(row.pod_logs_request(None).is_ok());
        assert!(row.pod_logs_request(Some("app")).is_ok());
        for other in ["sidecar", "App", "app; id", ""] {
            assert!(
                matches!(
                    row.pod_logs_request(Some(other)),
                    Err(KubernetesReadApiError::ContainerUnavailable)
                ),
                "{other:?}"
            );
        }
    }
}
