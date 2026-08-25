//! Bounded, read-only Electron boundary for Docker investigation.
//!
//! Renderer follow-up requests use opaque snapshot and resource handles. Only
//! core's closed DockerService methods can reach SSH; this module never accepts
//! a runtime command, resource identity, remote path, or target guard.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use lovelyres_core::{
    BackendServices, CoreError,
    docker::{
        ContainerIdentity, ContainerImage, ContainerInspection, ContainerLogsRequest,
        ContainerRuntime, ContainerStats, ContainerSummary, DockerCollection, DockerComposeProject,
        DockerNetwork, DockerNetworkInspection, DockerSecurityAudit, DockerSecurityCategory,
        DockerSecurityFinding, DockerSecuritySeverity, DockerVolume, DockerVolumeInspection,
    },
    ssh::BoundSshSession,
    target::TargetGuard,
};
use serde::Serialize;
use uuid::Uuid;

use crate::ssh_api::SshApi;

const MAX_HANDLE_BYTES: usize = 128;
const MAX_SNAPSHOTS: usize = 8;
const MAX_ACTIVE_REFRESHES: usize = 2;
const MAX_ACTIVE_READS: usize = 8;
const MAX_ACTIVE_READS_PER_BINDING: usize = 4;
const MAX_ACTIVE_PER_SNAPSHOT: usize = 3;
const MAX_CONTAINERS: usize = 500;
const MAX_STATS: usize = 500;
const MAX_IMAGES: usize = 500;
const MAX_NETWORKS: usize = 256;
const MAX_VOLUMES: usize = 256;
const MAX_COMPOSE_PROJECTS: usize = 256;
const MAX_INSPECTION_FIELDS: usize = 64;
const MAX_INSPECTION_MOUNTS: usize = 128;
const MAX_INSPECTION_NETWORKS: usize = 128;
const MAX_NETWORK_IPAM: usize = 128;
const MAX_NETWORK_ATTACHMENTS: usize = 256;
const MAX_METADATA_ENTRIES: usize = 128;
const MAX_SECURITY_FINDINGS: usize = 500;
const MAX_SECURITY_CONTAINERS: usize = 1_000;
const MAX_LOG_TAIL: usize = 1_000;
const MAX_LOG_BYTES: usize = 256 * 1024;
const MAX_SNAPSHOT_BYTES: usize = 2 * 1024 * 1024;
const MAX_COLLECTION_TEXT_BYTES: usize = 1024 * 1024;
const MAX_INSPECTION_TEXT_BYTES: usize = 512 * 1024;
const MAX_AUDIT_TEXT_BYTES: usize = 1024 * 1024;
const MIN_ITEM_TEXT_BYTES: usize = 128;
const MAX_PUBLIC_U64: u64 = 9_007_199_254_740_991;
const SNAPSHOT_TTL: Duration = Duration::from_secs(5 * 60);
const REDACTED_DOCKER_TEXT: &str = "[SENSITIVE DOCKER TEXT REDACTED]";

#[derive(Clone)]
pub(crate) struct DockerReadApi {
    services: BackendServices,
    ssh_api: Arc<SshApi>,
    registry: Arc<Mutex<SnapshotRegistry>>,
}

impl fmt::Debug for DockerReadApi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (snapshots, bytes, active_reads, refreshes) = self
            .registry
            .lock()
            .map(|registry| {
                (
                    registry.snapshots.len(),
                    registry.total_bytes(),
                    registry
                        .snapshots
                        .values()
                        .map(|snapshot| snapshot.active_reads)
                        .sum::<usize>(),
                    registry.active_refreshes,
                )
            })
            .unwrap_or_default();
        formatter
            .debug_struct("DockerReadApi")
            .field("snapshot_count", &snapshots)
            .field("snapshot_bytes", &bytes)
            .field("active_reads", &active_reads)
            .field("active_refreshes", &refreshes)
            .finish()
    }
}

impl DockerReadApi {
    pub(crate) fn new(services: BackendServices, ssh_api: Arc<SshApi>) -> Self {
        Self {
            services,
            ssh_api,
            registry: Arc::new(Mutex::new(SnapshotRegistry::default())),
        }
    }

    pub(crate) fn close_binding(&self, binding_handle: &str) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.close_binding(binding_handle);
        }
    }

    pub(crate) async fn refresh_containers(
        &self,
        binding_handle: &str,
    ) -> Result<DockerContainerSnapshotDto, DockerReadApiError> {
        let (session, scope) = self.capture_binding(binding_handle)?;
        let permit = self.begin_refresh(&scope)?;
        let collection = self
            .services
            .docker()
            .list(&session, ContainerRuntime::Docker)
            .await?;
        self.validate_binding(&scope)?;
        let (snapshot, dto) = build_container_snapshot(scope.clone(), collection)?;
        let mut registry = self.lock_registry()?;
        registry.prune(Instant::now());
        registry.insert_refreshed(&scope, permit.token, snapshot)?;
        Ok(dto)
    }

    pub(crate) async fn collection(
        &self,
        binding_handle: &str,
        snapshot_handle: &str,
        kind: &str,
    ) -> Result<DockerReadCollectionDto, DockerReadApiError> {
        validate_handle(snapshot_handle)?;
        let kind = CollectionKind::parse(kind)?;
        let (session, scope) = self.capture_binding(binding_handle)?;
        let (access, _permit) =
            self.begin_collection_snapshot_read(&scope, snapshot_handle, kind)?;
        let response = match kind {
            CollectionKind::Stats => {
                let collection = self
                    .services
                    .docker()
                    .stats(&session, ContainerRuntime::Docker)
                    .await?;
                self.validate_binding(&scope)?;
                let registry = self.lock_registry()?;
                let snapshot = registry.verify(&access)?;
                DockerReadCollectionDto::Stats(project_stats(
                    snapshot_handle,
                    collection,
                    &snapshot.container_index,
                )?)
            }
            CollectionKind::Images => {
                let collection = self
                    .services
                    .docker()
                    .images(&session, ContainerRuntime::Docker)
                    .await?;
                self.validate_binding(&scope)?;
                self.verify_access(&access)?;
                DockerReadCollectionDto::Images(project_images(snapshot_handle, collection))
            }
            CollectionKind::Networks => {
                let collection = self
                    .services
                    .docker()
                    .networks(&session, ContainerRuntime::Docker)
                    .await?;
                self.validate_binding(&scope)?;
                let mut registry = self.lock_registry()?;
                DockerReadCollectionDto::Networks(registry.replace_networks(
                    &access,
                    snapshot_handle,
                    collection,
                )?)
            }
            CollectionKind::Volumes => {
                let collection = self
                    .services
                    .docker()
                    .volumes(&session, ContainerRuntime::Docker)
                    .await?;
                self.validate_binding(&scope)?;
                let mut registry = self.lock_registry()?;
                DockerReadCollectionDto::Volumes(registry.replace_volumes(
                    &access,
                    snapshot_handle,
                    collection,
                )?)
            }
            CollectionKind::ComposeProjects => {
                let collection = self
                    .services
                    .docker()
                    .compose_projects(&session, ContainerRuntime::Docker)
                    .await?;
                self.validate_binding(&scope)?;
                self.verify_access(&access)?;
                DockerReadCollectionDto::ComposeProjects(project_compose_projects(
                    snapshot_handle,
                    collection,
                )?)
            }
        };
        Ok(response)
    }

    pub(crate) async fn inspect(
        &self,
        binding_handle: &str,
        snapshot_handle: &str,
        resource_kind: &str,
        resource_handle: &str,
    ) -> Result<DockerReadInspectionDto, DockerReadApiError> {
        validate_handle(snapshot_handle)?;
        validate_handle(resource_handle)?;
        let kind = ResourceKind::parse(resource_kind)?;
        let (session, scope) = self.capture_binding(binding_handle)?;
        let (access, resource, _permit) =
            self.begin_resource_read(&scope, snapshot_handle, kind, resource_handle)?;
        let response = match resource {
            StoredResource::Container(identity) => {
                let inspection = self.services.docker().inspect(&session, &identity).await?;
                self.validate_binding(&scope)?;
                if inspection.identity != identity {
                    return Err(DockerReadApiError::SnapshotStale);
                }
                self.verify_resource(&access, kind, resource_handle, &identity.stable_key())?;
                DockerReadInspectionDto::Container(project_container_inspection(
                    snapshot_handle,
                    resource_handle,
                    inspection,
                    &scope.sensitive_literals(),
                ))
            }
            StoredResource::Network(network) => {
                let expected = network.stable_key();
                let inspection = self
                    .services
                    .docker()
                    .inspect_network(&session, &network)
                    .await?;
                self.validate_binding(&scope)?;
                if inspection.network.stable_key() != expected {
                    return Err(DockerReadApiError::SnapshotStale);
                }
                self.verify_resource(&access, kind, resource_handle, &expected)?;
                DockerReadInspectionDto::Network(project_network_inspection(
                    snapshot_handle,
                    resource_handle,
                    inspection,
                    &scope.sensitive_literals(),
                ))
            }
            StoredResource::Volume(volume) => {
                let expected = volume.stable_key();
                let inspection = self
                    .services
                    .docker()
                    .inspect_volume(&session, &volume)
                    .await?;
                self.validate_binding(&scope)?;
                if inspection.volume.stable_key() != expected {
                    return Err(DockerReadApiError::SnapshotStale);
                }
                self.verify_resource(&access, kind, resource_handle, &expected)?;
                DockerReadInspectionDto::Volume(project_volume_inspection(
                    snapshot_handle,
                    resource_handle,
                    inspection,
                    &scope.sensitive_literals(),
                ))
            }
        };
        Ok(response)
    }

    pub(crate) async fn security_audit(
        &self,
        binding_handle: &str,
        snapshot_handle: &str,
    ) -> Result<DockerSecurityAuditDto, DockerReadApiError> {
        validate_handle(snapshot_handle)?;
        let (session, scope) = self.capture_binding(binding_handle)?;
        let (access, _permit) = self.begin_snapshot_read(&scope, snapshot_handle)?;
        let audit = self
            .services
            .docker()
            .security_audit(&session, ContainerRuntime::Docker)
            .await?;
        self.validate_binding(&scope)?;
        self.verify_access(&access)?;
        project_security_audit(snapshot_handle, audit)
    }

    pub(crate) async fn logs(
        &self,
        binding_handle: &str,
        snapshot_handle: &str,
        container_handle: &str,
        tail: usize,
    ) -> Result<DockerLogsDto, DockerReadApiError> {
        validate_handle(snapshot_handle)?;
        validate_handle(container_handle)?;
        if tail == 0 || tail > MAX_LOG_TAIL {
            return Err(DockerReadApiError::InvalidBounds);
        }
        let (session, scope) = self.capture_binding(binding_handle)?;
        let (access, resource, _permit) = self.begin_resource_read(
            &scope,
            snapshot_handle,
            ResourceKind::Container,
            container_handle,
        )?;
        let StoredResource::Container(identity) = resource else {
            return Err(DockerReadApiError::InvalidResource);
        };
        let request = ContainerLogsRequest {
            container: identity.clone(),
            tail,
            since: None,
            timestamps: true,
            stdout: true,
            stderr: true,
        };
        let logs = self.services.docker().logs(&session, &request).await?;
        self.validate_binding(&scope)?;
        if logs.identity != identity {
            return Err(DockerReadApiError::SnapshotStale);
        }
        self.verify_resource(
            &access,
            ResourceKind::Container,
            container_handle,
            &identity.stable_key(),
        )?;
        let (text, text_truncated) =
            project_public_multiline(&logs.text, MAX_LOG_BYTES, &scope.sensitive_literals());
        Ok(DockerLogsDto {
            snapshot_handle: snapshot_handle.to_owned(),
            container_handle: container_handle.to_owned(),
            tail,
            text,
            truncated: logs.truncated || text_truncated,
        })
    }

    fn capture_binding(
        &self,
        binding_handle: &str,
    ) -> Result<(BoundSshSession, BindingScope), DockerReadApiError> {
        validate_handle(binding_handle)?;
        let session = self
            .ssh_api
            .binding_session_clone(binding_handle)
            .map_err(|_| DockerReadApiError::BindingUnavailable)?;
        self.services
            .target()
            .validate(session.target())
            .map_err(|_| DockerReadApiError::BindingUnavailable)?;
        Ok((
            session.clone(),
            BindingScope::from_session(binding_handle, &session),
        ))
    }

    fn validate_binding(
        &self,
        expected: &BindingScope,
    ) -> Result<BoundSshSession, DockerReadApiError> {
        let (session, current) = self.capture_binding(&expected.binding_handle)?;
        if &current != expected {
            return Err(DockerReadApiError::BindingUnavailable);
        }
        Ok(session)
    }

    fn begin_refresh(&self, scope: &BindingScope) -> Result<RefreshPermit, DockerReadApiError> {
        let mut registry = self.lock_registry()?;
        registry.prune(Instant::now());
        let token = registry.begin_refresh(scope)?;
        Ok(RefreshPermit {
            registry: Arc::clone(&self.registry),
            binding_handle: scope.binding_handle.clone(),
            token,
        })
    }

    fn begin_snapshot_read(
        &self,
        scope: &BindingScope,
        snapshot_handle: &str,
    ) -> Result<(SnapshotAccess, SnapshotPermit), DockerReadApiError> {
        let mut registry = self.lock_registry()?;
        registry.prune(Instant::now());
        let access = registry.begin_read(scope, snapshot_handle)?;
        let permit = SnapshotPermit {
            registry: Arc::clone(&self.registry),
            snapshot_handle: snapshot_handle.to_owned(),
            token: access.token,
        };
        Ok((access, permit))
    }

    fn begin_collection_snapshot_read(
        &self,
        scope: &BindingScope,
        snapshot_handle: &str,
        kind: CollectionKind,
    ) -> Result<(SnapshotAccess, SnapshotPermit), DockerReadApiError> {
        let mut registry = self.lock_registry()?;
        registry.prune(Instant::now());
        let access = registry.begin_collection_read(scope, snapshot_handle, kind)?;
        let permit = SnapshotPermit {
            registry: Arc::clone(&self.registry),
            snapshot_handle: snapshot_handle.to_owned(),
            token: access.token,
        };
        Ok((access, permit))
    }

    fn begin_resource_read(
        &self,
        scope: &BindingScope,
        snapshot_handle: &str,
        kind: ResourceKind,
        resource_handle: &str,
    ) -> Result<(SnapshotAccess, StoredResource, SnapshotPermit), DockerReadApiError> {
        let (access, permit) = self.begin_snapshot_read(scope, snapshot_handle)?;
        let resource = {
            let registry = self.lock_registry()?;
            registry.resource(&access, kind, resource_handle)?
        };
        Ok((access, resource, permit))
    }

    fn verify_access(&self, access: &SnapshotAccess) -> Result<(), DockerReadApiError> {
        self.lock_registry()?.verify(access).map(|_| ())
    }

    fn verify_resource(
        &self,
        access: &SnapshotAccess,
        kind: ResourceKind,
        resource_handle: &str,
        expected_key: &str,
    ) -> Result<(), DockerReadApiError> {
        let registry = self.lock_registry()?;
        let resource = registry.resource(access, kind, resource_handle)?;
        if resource.stable_key() != expected_key {
            return Err(DockerReadApiError::SnapshotStale);
        }
        Ok(())
    }

    fn lock_registry(&self) -> Result<MutexGuard<'_, SnapshotRegistry>, DockerReadApiError> {
        self.registry
            .lock()
            .map_err(|_| DockerReadApiError::RegistryUnavailable)
    }
}

pub(crate) enum DockerReadApiError {
    Core,
    BindingUnavailable,
    InvalidHandle,
    InvalidKind,
    InvalidBounds,
    InvalidSnapshot,
    InvalidResource,
    SnapshotStale,
    Capacity,
    RegistryUnavailable,
}

impl fmt::Debug for DockerReadApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core => "Core([REDACTED])",
            Self::BindingUnavailable => "BindingUnavailable",
            Self::InvalidHandle => "InvalidHandle",
            Self::InvalidKind => "InvalidKind",
            Self::InvalidBounds => "InvalidBounds",
            Self::InvalidSnapshot => "InvalidSnapshot",
            Self::InvalidResource => "InvalidResource",
            Self::SnapshotStale => "SnapshotStale",
            Self::Capacity => "Capacity",
            Self::RegistryUnavailable => "RegistryUnavailable",
        })
    }
}

impl fmt::Display for DockerReadApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core => "the Docker read operation failed",
            Self::BindingUnavailable => "the SSH binding is missing or stale",
            Self::InvalidHandle => "the Docker read handle is invalid",
            Self::InvalidKind => "the Docker read kind is invalid",
            Self::InvalidBounds => "the Docker read bounds are invalid",
            Self::InvalidSnapshot => "the Docker snapshot is missing or stale",
            Self::InvalidResource => "the Docker resource is missing or stale",
            Self::SnapshotStale => "the Docker result no longer matches its snapshot",
            Self::Capacity => "the Docker read registry is full",
            Self::RegistryUnavailable => "the Docker read registry is unavailable",
        })
    }
}

impl std::error::Error for DockerReadApiError {}

impl From<CoreError> for DockerReadApiError {
    fn from(_: CoreError) -> Self {
        Self::Core
    }
}

#[derive(Clone, PartialEq, Eq)]
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum CollectionKind {
    Stats,
    Images,
    Networks,
    Volumes,
    ComposeProjects,
}

impl CollectionKind {
    fn parse(value: &str) -> Result<Self, DockerReadApiError> {
        match value {
            "stats" => Ok(Self::Stats),
            "images" => Ok(Self::Images),
            "networks" => Ok(Self::Networks),
            "volumes" => Ok(Self::Volumes),
            "compose-projects" => Ok(Self::ComposeProjects),
            _ => Err(DockerReadApiError::InvalidKind),
        }
    }
}

#[derive(Clone, Copy)]
enum ResourceKind {
    Container,
    Network,
    Volume,
}

impl ResourceKind {
    fn parse(value: &str) -> Result<Self, DockerReadApiError> {
        match value {
            "container" => Ok(Self::Container),
            "network" => Ok(Self::Network),
            "volume" => Ok(Self::Volume),
            _ => Err(DockerReadApiError::InvalidKind),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DockerContainerSnapshotDto {
    snapshot_handle: String,
    expires_in_seconds: u64,
    containers: Vec<DockerContainerDto>,
    truncated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DockerContainerDto {
    container_handle: String,
    name: String,
    image: String,
    state: String,
    status: String,
    ports: String,
    created_at: String,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub(crate) enum DockerReadCollectionDto {
    Stats(DockerStatsCollectionDto),
    Images(DockerImagesCollectionDto),
    Networks(DockerNetworksCollectionDto),
    Volumes(DockerVolumesCollectionDto),
    ComposeProjects(DockerComposeCollectionDto),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DockerStatsCollectionDto {
    snapshot_handle: String,
    items: Vec<DockerStatsDto>,
    truncated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DockerStatsDto {
    container_handle: String,
    name: String,
    cpu_percent: String,
    memory_usage: String,
    memory_percent: String,
    network_io: String,
    block_io: String,
    pids: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DockerImagesCollectionDto {
    snapshot_handle: String,
    items: Vec<DockerImageDto>,
    truncated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DockerImageDto {
    repository: String,
    tag: String,
    digest: String,
    created_at: String,
    size: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DockerNetworksCollectionDto {
    snapshot_handle: String,
    items: Vec<DockerNetworkDto>,
    truncated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DockerNetworkDto {
    network_handle: String,
    name: String,
    driver: String,
    scope: String,
    internal: bool,
    ipv6: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DockerVolumesCollectionDto {
    snapshot_handle: String,
    items: Vec<DockerVolumeDto>,
    truncated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DockerVolumeDto {
    volume_handle: String,
    name: String,
    driver: String,
    mountpoint: String,
    scope: String,
    labels: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DockerComposeCollectionDto {
    snapshot_handle: String,
    items: Vec<DockerComposeProjectDto>,
    truncated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DockerComposeProjectDto {
    name: String,
    status: String,
    config_files: String,
    services: u64,
    running: u64,
    stopped: u64,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub(crate) enum DockerReadInspectionDto {
    Container(DockerContainerInspectionDto),
    Network(DockerNetworkInspectionDto),
    Volume(DockerVolumeInspectionDto),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DockerContainerInspectionDto {
    snapshot_handle: String,
    resource_handle: String,
    name: String,
    fields: Vec<DockerFieldDto>,
    mounts: Vec<DockerMountDto>,
    networks: Vec<DockerContainerNetworkDto>,
    truncated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DockerFieldDto {
    label: String,
    value: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DockerMountDto {
    kind: String,
    source: String,
    destination: String,
    mode: String,
    read_write: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DockerContainerNetworkDto {
    name: String,
    mac_address: String,
    ipv4_address: String,
    ipv6_address: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DockerNetworkInspectionDto {
    snapshot_handle: String,
    resource_handle: String,
    name: String,
    driver: String,
    scope: String,
    internal: bool,
    ipv6: bool,
    attachable: bool,
    ingress: bool,
    ipam_driver: String,
    ipam: Vec<DockerIpamDto>,
    attachments: Vec<DockerAttachmentDto>,
    options: Vec<DockerMetadataDto>,
    labels: Vec<DockerMetadataDto>,
    truncated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DockerIpamDto {
    subnet: String,
    gateway: String,
    ip_range: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DockerAttachmentDto {
    name: String,
    mac_address: String,
    ipv4_address: String,
    ipv6_address: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DockerMetadataDto {
    key: String,
    value: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DockerVolumeInspectionDto {
    snapshot_handle: String,
    resource_handle: String,
    name: String,
    driver: String,
    mountpoint: String,
    scope: String,
    created_at: String,
    options: Vec<DockerMetadataDto>,
    labels: Vec<DockerMetadataDto>,
    truncated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DockerSecurityAuditDto {
    snapshot_handle: String,
    containers_scanned: usize,
    findings: Vec<DockerSecurityFindingDto>,
    summary: DockerSecuritySummaryDto,
    truncated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DockerSecurityFindingDto {
    severity: &'static str,
    severity_label: &'static str,
    category: &'static str,
    category_label: &'static str,
    container_name: String,
    description: String,
    recommendation: String,
    text_truncated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DockerSecuritySummaryDto {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
    total: usize,
    score: u8,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DockerLogsDto {
    snapshot_handle: String,
    container_handle: String,
    tail: usize,
    text: String,
    truncated: bool,
}

#[derive(Default)]
struct SnapshotRegistry {
    snapshots: HashMap<String, SnapshotEntry>,
    active_refreshes: usize,
    refreshing_bindings: HashMap<String, Uuid>,
}

impl fmt::Debug for SnapshotRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DockerSnapshotRegistry")
            .field("snapshot_count", &self.snapshots.len())
            .field("snapshot_bytes", &self.total_bytes())
            .field("active_refreshes", &self.active_refreshes)
            .finish()
    }
}

struct SnapshotEntry {
    handle: String,
    token: Uuid,
    scope: BindingScope,
    expires_at: Instant,
    active_reads: usize,
    stored_bytes: usize,
    containers: HashMap<String, ContainerIdentity>,
    container_index: HashMap<String, String>,
    networks: HashMap<String, DockerNetwork>,
    volumes: HashMap<String, DockerVolume>,
    network_revision: u64,
    volume_revision: u64,
}

#[derive(Clone)]
struct SnapshotAccess {
    handle: String,
    token: Uuid,
    scope: BindingScope,
    collection_revision: Option<(CollectionKind, u64)>,
}

impl SnapshotAccess {
    fn matches(&self, snapshot: &SnapshotEntry, now: Instant) -> bool {
        if snapshot.token != self.token
            || snapshot.scope != self.scope
            || snapshot.expires_at <= now
        {
            return false;
        }
        match self.collection_revision {
            Some((CollectionKind::Networks, revision)) => snapshot.network_revision == revision,
            Some((CollectionKind::Volumes, revision)) => snapshot.volume_revision == revision,
            Some(_) | None => true,
        }
    }
}

#[derive(Clone)]
enum StoredResource {
    Container(ContainerIdentity),
    Network(DockerNetwork),
    Volume(DockerVolume),
}

impl StoredResource {
    fn stable_key(&self) -> String {
        match self {
            Self::Container(value) => value.stable_key(),
            Self::Network(value) => value.stable_key(),
            Self::Volume(value) => value.stable_key(),
        }
    }
}

impl SnapshotRegistry {
    fn prune(&mut self, now: Instant) {
        self.snapshots
            .retain(|_, snapshot| snapshot.expires_at > now || snapshot.active_reads > 0);
    }

    fn total_bytes(&self) -> usize {
        self.snapshots
            .values()
            .map(|snapshot| snapshot.stored_bytes)
            .sum()
    }

    fn active_reads(&self) -> usize {
        self.snapshots
            .values()
            .map(|snapshot| snapshot.active_reads)
            .sum()
    }

    fn active_reads_for_binding(&self, binding_handle: &str) -> usize {
        self.snapshots
            .values()
            .filter(|snapshot| snapshot.scope.binding_handle == binding_handle)
            .map(|snapshot| snapshot.active_reads)
            .sum()
    }

    fn close_binding(&mut self, binding_handle: &str) {
        self.snapshots
            .retain(|_, snapshot| snapshot.scope.binding_handle != binding_handle);
        if self.refreshing_bindings.remove(binding_handle).is_some() {
            self.active_refreshes = self.active_refreshes.saturating_sub(1);
        }
    }

    fn begin_refresh(&mut self, scope: &BindingScope) -> Result<Uuid, DockerReadApiError> {
        if self.active_refreshes >= MAX_ACTIVE_REFRESHES
            || self.refreshing_bindings.contains_key(&scope.binding_handle)
        {
            return Err(DockerReadApiError::Capacity);
        }
        let token = Uuid::new_v4();
        self.active_refreshes += 1;
        self.refreshing_bindings
            .insert(scope.binding_handle.clone(), token);
        Ok(token)
    }

    fn release_refresh(&mut self, binding_handle: &str, token: Uuid) {
        if self
            .refreshing_bindings
            .get(binding_handle)
            .is_some_and(|current| *current == token)
        {
            self.refreshing_bindings.remove(binding_handle);
            self.active_refreshes = self.active_refreshes.saturating_sub(1);
        }
    }

    fn insert_refreshed(
        &mut self,
        scope: &BindingScope,
        token: Uuid,
        snapshot: SnapshotEntry,
    ) -> Result<(), DockerReadApiError> {
        if snapshot.scope != *scope
            || self
                .refreshing_bindings
                .get(&scope.binding_handle)
                .is_none_or(|current| *current != token)
        {
            return Err(DockerReadApiError::SnapshotStale);
        }
        self.insert(snapshot)
    }

    fn insert(&mut self, snapshot: SnapshotEntry) -> Result<(), DockerReadApiError> {
        if self.snapshots.contains_key(&snapshot.handle) {
            return Err(DockerReadApiError::Capacity);
        }
        self.snapshots
            .retain(|_, existing| existing.scope != snapshot.scope);
        if self.snapshots.len() >= MAX_SNAPSHOTS
            || snapshot.stored_bytes > MAX_SNAPSHOT_BYTES
            || self.total_bytes().saturating_add(snapshot.stored_bytes)
                > MAX_SNAPSHOTS * MAX_SNAPSHOT_BYTES
        {
            return Err(DockerReadApiError::Capacity);
        }
        self.snapshots.insert(snapshot.handle.clone(), snapshot);
        Ok(())
    }

    fn begin_read(
        &mut self,
        scope: &BindingScope,
        handle: &str,
    ) -> Result<SnapshotAccess, DockerReadApiError> {
        let snapshot = self
            .snapshots
            .get(handle)
            .filter(|snapshot| &snapshot.scope == scope && snapshot.expires_at > Instant::now())
            .ok_or(DockerReadApiError::InvalidSnapshot)?;
        if self.active_reads() >= MAX_ACTIVE_READS
            || self.active_reads_for_binding(&scope.binding_handle) >= MAX_ACTIVE_READS_PER_BINDING
            || snapshot.active_reads >= MAX_ACTIVE_PER_SNAPSHOT
        {
            return Err(DockerReadApiError::Capacity);
        }
        let snapshot = self
            .snapshots
            .get_mut(handle)
            .filter(|snapshot| &snapshot.scope == scope && snapshot.expires_at > Instant::now())
            .ok_or(DockerReadApiError::InvalidSnapshot)?;
        snapshot.active_reads += 1;
        Ok(SnapshotAccess {
            handle: handle.to_owned(),
            token: snapshot.token,
            scope: scope.clone(),
            collection_revision: None,
        })
    }

    fn begin_collection_read(
        &mut self,
        scope: &BindingScope,
        handle: &str,
        kind: CollectionKind,
    ) -> Result<SnapshotAccess, DockerReadApiError> {
        let snapshot = self
            .snapshots
            .get(handle)
            .filter(|snapshot| &snapshot.scope == scope && snapshot.expires_at > Instant::now())
            .ok_or(DockerReadApiError::InvalidSnapshot)?;
        if self.active_reads() >= MAX_ACTIVE_READS
            || self.active_reads_for_binding(&scope.binding_handle) >= MAX_ACTIVE_READS_PER_BINDING
            || snapshot.active_reads >= MAX_ACTIVE_PER_SNAPSHOT
        {
            return Err(DockerReadApiError::Capacity);
        }
        let snapshot = self
            .snapshots
            .get_mut(handle)
            .filter(|snapshot| &snapshot.scope == scope && snapshot.expires_at > Instant::now())
            .ok_or(DockerReadApiError::InvalidSnapshot)?;
        let collection_revision = match kind {
            CollectionKind::Networks => {
                snapshot.network_revision = snapshot
                    .network_revision
                    .checked_add(1)
                    .ok_or(DockerReadApiError::Capacity)?;
                Some((kind, snapshot.network_revision))
            }
            CollectionKind::Volumes => {
                snapshot.volume_revision = snapshot
                    .volume_revision
                    .checked_add(1)
                    .ok_or(DockerReadApiError::Capacity)?;
                Some((kind, snapshot.volume_revision))
            }
            _ => None,
        };
        snapshot.active_reads += 1;
        Ok(SnapshotAccess {
            handle: handle.to_owned(),
            token: snapshot.token,
            scope: scope.clone(),
            collection_revision,
        })
    }

    fn release_read(&mut self, handle: &str, token: Uuid) {
        if let Some(snapshot) = self
            .snapshots
            .get_mut(handle)
            .filter(|snapshot| snapshot.token == token)
        {
            snapshot.active_reads = snapshot.active_reads.saturating_sub(1);
        }
    }

    fn verify(&self, access: &SnapshotAccess) -> Result<&SnapshotEntry, DockerReadApiError> {
        self.snapshots
            .get(&access.handle)
            .filter(|snapshot| access.matches(snapshot, Instant::now()))
            .ok_or(DockerReadApiError::SnapshotStale)
    }

    fn resource(
        &self,
        access: &SnapshotAccess,
        kind: ResourceKind,
        resource_handle: &str,
    ) -> Result<StoredResource, DockerReadApiError> {
        let snapshot = self.verify(access)?;
        match kind {
            ResourceKind::Container => snapshot
                .containers
                .get(resource_handle)
                .cloned()
                .map(StoredResource::Container),
            ResourceKind::Network => snapshot
                .networks
                .get(resource_handle)
                .cloned()
                .map(StoredResource::Network),
            ResourceKind::Volume => snapshot
                .volumes
                .get(resource_handle)
                .cloned()
                .map(StoredResource::Volume),
        }
        .ok_or(DockerReadApiError::InvalidResource)
    }

    fn replace_networks(
        &mut self,
        access: &SnapshotAccess,
        snapshot_handle: &str,
        collection: DockerCollection<DockerNetwork>,
    ) -> Result<DockerNetworksCollectionDto, DockerReadApiError> {
        let snapshot = self
            .snapshots
            .get_mut(&access.handle)
            .filter(|snapshot| access.matches(snapshot, Instant::now()))
            .ok_or(DockerReadApiError::SnapshotStale)?;
        let old_bytes = snapshot
            .networks
            .iter()
            .map(|(handle, network)| {
                handle
                    .len()
                    .saturating_add(estimated_network_bytes(network))
            })
            .sum::<usize>();
        let (networks, items, projected_truncated, bytes) = project_networks(collection)?;
        let candidate = snapshot
            .stored_bytes
            .saturating_sub(old_bytes)
            .saturating_add(bytes);
        if candidate > MAX_SNAPSHOT_BYTES {
            return Err(DockerReadApiError::Capacity);
        }
        snapshot.networks = networks;
        snapshot.stored_bytes = candidate;
        Ok(DockerNetworksCollectionDto {
            snapshot_handle: snapshot_handle.to_owned(),
            items,
            truncated: projected_truncated,
        })
    }

    fn replace_volumes(
        &mut self,
        access: &SnapshotAccess,
        snapshot_handle: &str,
        collection: DockerCollection<DockerVolume>,
    ) -> Result<DockerVolumesCollectionDto, DockerReadApiError> {
        let snapshot = self
            .snapshots
            .get_mut(&access.handle)
            .filter(|snapshot| access.matches(snapshot, Instant::now()))
            .ok_or(DockerReadApiError::SnapshotStale)?;
        let old_bytes = snapshot
            .volumes
            .iter()
            .map(|(handle, volume)| handle.len().saturating_add(estimated_volume_bytes(volume)))
            .sum::<usize>();
        let (volumes, items, projected_truncated, bytes) = project_volumes(collection)?;
        let candidate = snapshot
            .stored_bytes
            .saturating_sub(old_bytes)
            .saturating_add(bytes);
        if candidate > MAX_SNAPSHOT_BYTES {
            return Err(DockerReadApiError::Capacity);
        }
        snapshot.volumes = volumes;
        snapshot.stored_bytes = candidate;
        Ok(DockerVolumesCollectionDto {
            snapshot_handle: snapshot_handle.to_owned(),
            items,
            truncated: projected_truncated,
        })
    }
}

struct RefreshPermit {
    registry: Arc<Mutex<SnapshotRegistry>>,
    binding_handle: String,
    token: Uuid,
}

impl Drop for RefreshPermit {
    fn drop(&mut self) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.release_refresh(&self.binding_handle, self.token);
        }
    }
}

struct SnapshotPermit {
    registry: Arc<Mutex<SnapshotRegistry>>,
    snapshot_handle: String,
    token: Uuid,
}

impl Drop for SnapshotPermit {
    fn drop(&mut self) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.release_read(&self.snapshot_handle, self.token);
        }
    }
}

fn build_container_snapshot(
    scope: BindingScope,
    collection: DockerCollection<ContainerSummary>,
) -> Result<(SnapshotEntry, DockerContainerSnapshotDto), DockerReadApiError> {
    let snapshot_handle = unique_handle()?;
    let mut budget = TextBudget::new(MAX_COLLECTION_TEXT_BYTES);
    let mut containers = HashMap::new();
    let mut container_index = HashMap::new();
    let mut items = Vec::new();
    let source_len = collection.items.len();
    let mut stored_bytes = 0_usize;
    for container in collection.items.into_iter().take(MAX_CONTAINERS) {
        if budget.remaining() < MIN_ITEM_TEXT_BYTES {
            break;
        }
        if container.identity.runtime() != ContainerRuntime::Docker {
            return Err(DockerReadApiError::SnapshotStale);
        }
        let handle = unique_map_handle(&containers)?;
        let key = container.identity.stable_key();
        if container_index.contains_key(&key) {
            return Err(DockerReadApiError::SnapshotStale);
        }
        let dto = DockerContainerDto {
            container_handle: handle.clone(),
            name: budget.take(&container.name, 512).0,
            image: budget.take(&container.image, 2 * 1024).0,
            state: budget.take(&container.state, 128).0,
            status: budget.take(&container.status, 1024).0,
            ports: budget.take(&container.ports, 4 * 1024).0,
            created_at: budget.take(&container.created_at, 1024).0,
        };
        stored_bytes = stored_bytes
            .saturating_add(handle.len())
            .saturating_add(key.len())
            .saturating_add(container.identity.id().len())
            .saturating_add(128);
        container_index.insert(key, handle.clone());
        containers.insert(handle, container.identity);
        items.push(dto);
    }
    if stored_bytes > MAX_SNAPSHOT_BYTES {
        return Err(DockerReadApiError::Capacity);
    }
    let truncated = collection.truncated || items.len() < source_len || budget.projected();
    let snapshot = SnapshotEntry {
        handle: snapshot_handle.clone(),
        token: Uuid::new_v4(),
        scope,
        expires_at: Instant::now() + SNAPSHOT_TTL,
        active_reads: 0,
        stored_bytes,
        containers,
        container_index,
        networks: HashMap::new(),
        volumes: HashMap::new(),
        network_revision: 0,
        volume_revision: 0,
    };
    let dto = DockerContainerSnapshotDto {
        snapshot_handle,
        expires_in_seconds: SNAPSHOT_TTL.as_secs(),
        containers: items,
        truncated,
    };
    Ok((snapshot, dto))
}

fn project_stats(
    snapshot_handle: &str,
    collection: DockerCollection<ContainerStats>,
    container_index: &HashMap<String, String>,
) -> Result<DockerStatsCollectionDto, DockerReadApiError> {
    let mut budget = TextBudget::new(MAX_COLLECTION_TEXT_BYTES);
    let source_len = collection.items.len();
    let mut items = Vec::new();
    let mut seen = HashSet::new();
    for stats in collection.items.into_iter().take(MAX_STATS) {
        if budget.remaining() < MIN_ITEM_TEXT_BYTES {
            break;
        }
        let handle = container_index
            .get(&stats.identity.stable_key())
            .cloned()
            .ok_or(DockerReadApiError::SnapshotStale)?;
        if !seen.insert(handle.clone()) || stats.pids.is_some_and(|pids| pids > MAX_PUBLIC_U64) {
            return Err(DockerReadApiError::SnapshotStale);
        }
        items.push(DockerStatsDto {
            container_handle: handle,
            name: budget.take(&stats.name, 512).0,
            cpu_percent: budget.take(&stats.cpu_percent, 128).0,
            memory_usage: budget.take(&stats.memory_usage, 256).0,
            memory_percent: budget.take(&stats.memory_percent, 128).0,
            network_io: budget.take(&stats.network_io, 256).0,
            block_io: budget.take(&stats.block_io, 256).0,
            pids: stats.pids,
        });
    }
    Ok(DockerStatsCollectionDto {
        snapshot_handle: snapshot_handle.to_owned(),
        truncated: collection.truncated || items.len() < source_len || budget.projected(),
        items,
    })
}

fn project_images(
    snapshot_handle: &str,
    collection: DockerCollection<ContainerImage>,
) -> DockerImagesCollectionDto {
    let mut budget = TextBudget::new(MAX_COLLECTION_TEXT_BYTES);
    let source_len = collection.items.len();
    let mut items = Vec::new();
    for image in collection.items.into_iter().take(MAX_IMAGES) {
        if budget.remaining() < MIN_ITEM_TEXT_BYTES {
            break;
        }
        items.push(DockerImageDto {
            repository: budget.take(&image.repository, 2 * 1024).0,
            tag: budget.take(&image.tag, 1024).0,
            digest: budget.take(&image.digest, 512).0,
            created_at: budget.take(&image.created_at, 1024).0,
            size: budget.take(&image.size, 256).0,
        });
    }
    DockerImagesCollectionDto {
        snapshot_handle: snapshot_handle.to_owned(),
        truncated: collection.truncated || items.len() < source_len || budget.projected(),
        items,
    }
}

type ProjectedNetworks = (
    HashMap<String, DockerNetwork>,
    Vec<DockerNetworkDto>,
    bool,
    usize,
);

fn project_networks(
    collection: DockerCollection<DockerNetwork>,
) -> Result<ProjectedNetworks, DockerReadApiError> {
    let mut budget = TextBudget::new(MAX_COLLECTION_TEXT_BYTES);
    let source_len = collection.items.len();
    let mut stored = HashMap::new();
    let mut stable_keys = HashSet::new();
    let mut items = Vec::new();
    let mut bytes = 0_usize;
    for network in collection.items.into_iter().take(MAX_NETWORKS) {
        if budget.remaining() < MIN_ITEM_TEXT_BYTES {
            break;
        }
        if network.runtime != ContainerRuntime::Docker || !stable_keys.insert(network.stable_key())
        {
            return Err(DockerReadApiError::SnapshotStale);
        }
        let handle = unique_map_handle(&stored)?;
        bytes = bytes
            .saturating_add(handle.len())
            .saturating_add(estimated_network_bytes(&network));
        items.push(DockerNetworkDto {
            network_handle: handle.clone(),
            name: budget.take(&network.name, 512).0,
            driver: budget.take(&network.driver, 256).0,
            scope: budget.take(&network.scope, 256).0,
            internal: network.internal,
            ipv6: network.ipv6,
        });
        stored.insert(handle, network);
    }
    let truncated = collection.truncated || items.len() < source_len || budget.projected();
    Ok((stored, items, truncated, bytes))
}

type ProjectedVolumes = (
    HashMap<String, DockerVolume>,
    Vec<DockerVolumeDto>,
    bool,
    usize,
);

fn project_volumes(
    collection: DockerCollection<DockerVolume>,
) -> Result<ProjectedVolumes, DockerReadApiError> {
    let mut budget = TextBudget::new(MAX_COLLECTION_TEXT_BYTES);
    let source_len = collection.items.len();
    let mut stored = HashMap::new();
    let mut stable_keys = HashSet::new();
    let mut items = Vec::new();
    let mut bytes = 0_usize;
    for volume in collection.items.into_iter().take(MAX_VOLUMES) {
        if budget.remaining() < MIN_ITEM_TEXT_BYTES {
            break;
        }
        if volume.runtime != ContainerRuntime::Docker || !stable_keys.insert(volume.stable_key()) {
            return Err(DockerReadApiError::SnapshotStale);
        }
        let handle = unique_map_handle(&stored)?;
        bytes = bytes
            .saturating_add(handle.len())
            .saturating_add(estimated_volume_bytes(&volume));
        items.push(DockerVolumeDto {
            volume_handle: handle.clone(),
            name: budget.take(&volume.name, 512).0,
            driver: budget.take(&volume.driver, 256).0,
            mountpoint: budget.take(&volume.mountpoint, 4 * 1024).0,
            scope: budget.take(&volume.scope, 256).0,
            labels: budget.take(&volume.labels, 4 * 1024).0,
        });
        stored.insert(handle, volume);
    }
    let truncated = collection.truncated || items.len() < source_len || budget.projected();
    Ok((stored, items, truncated, bytes))
}

fn project_compose_projects(
    snapshot_handle: &str,
    collection: DockerCollection<DockerComposeProject>,
) -> Result<DockerComposeCollectionDto, DockerReadApiError> {
    let mut budget = TextBudget::new(MAX_COLLECTION_TEXT_BYTES);
    let source_len = collection.items.len();
    let mut items = Vec::new();
    for project in collection.items.into_iter().take(MAX_COMPOSE_PROJECTS) {
        if budget.remaining() < MIN_ITEM_TEXT_BYTES {
            break;
        }
        if project.runtime != ContainerRuntime::Docker
            || project.services > MAX_PUBLIC_U64
            || project.running > MAX_PUBLIC_U64
            || project.stopped > MAX_PUBLIC_U64
            || project.running > project.services
            || project.stopped > project.services
        {
            return Err(DockerReadApiError::SnapshotStale);
        }
        items.push(DockerComposeProjectDto {
            name: budget.take(&project.name, 512).0,
            status: budget.take(&project.status, 512).0,
            config_files: budget.take(&project.config_files, 4 * 1024).0,
            services: project.services,
            running: project.running,
            stopped: project.stopped,
        });
    }
    Ok(DockerComposeCollectionDto {
        snapshot_handle: snapshot_handle.to_owned(),
        truncated: collection.truncated || items.len() < source_len || budget.projected(),
        items,
    })
}

fn project_container_inspection(
    snapshot_handle: &str,
    resource_handle: &str,
    inspection: ContainerInspection,
    sensitive_literals: &[&str],
) -> DockerContainerInspectionDto {
    let mut budget = TextBudget::new(MAX_INSPECTION_TEXT_BYTES);
    let fields_len = inspection.fields.len();
    let mounts_len = inspection.mounts.len();
    let networks_len = inspection.networks.len();
    let (name, mut projected) = budget.take_public(&inspection.name, 512, sensitive_literals);
    let mut fields = Vec::new();
    for field in inspection.fields.into_iter().take(MAX_INSPECTION_FIELDS) {
        if budget.remaining() < MIN_ITEM_TEXT_BYTES {
            break;
        }
        let sensitive_key = is_sensitive_key(&field.label);
        let (label, label_projected) = budget.take_public(&field.label, 256, sensitive_literals);
        let (value, value_projected) = if sensitive_key {
            budget.take_redacted(4 * 1024)
        } else {
            budget.take_public(&field.value, 4 * 1024, sensitive_literals)
        };
        projected |= label_projected || value_projected;
        fields.push(DockerFieldDto { label, value });
    }
    let mut mounts = Vec::new();
    for mount in inspection.mounts.into_iter().take(MAX_INSPECTION_MOUNTS) {
        if budget.remaining() < MIN_ITEM_TEXT_BYTES {
            break;
        }
        let (kind, kind_projected) = budget.take_public(&mount.kind, 128, sensitive_literals);
        let (source, source_projected) =
            budget.take_public(&mount.source, 4 * 1024, sensitive_literals);
        let (destination, destination_projected) =
            budget.take_public(&mount.destination, 4 * 1024, sensitive_literals);
        let (mode, mode_projected) = budget.take_public(&mount.mode, 512, sensitive_literals);
        projected |= kind_projected || source_projected || destination_projected || mode_projected;
        mounts.push(DockerMountDto {
            kind,
            source,
            destination,
            mode,
            read_write: mount.read_write,
        });
    }
    let mut networks = Vec::new();
    for network in inspection
        .networks
        .into_iter()
        .take(MAX_INSPECTION_NETWORKS)
    {
        if budget.remaining() < MIN_ITEM_TEXT_BYTES {
            break;
        }
        let (name, name_projected) = budget.take_public(&network.name, 512, sensitive_literals);
        let (mac_address, mac_projected) =
            budget.take_public(&network.mac_address, 256, sensitive_literals);
        let (ipv4_address, ipv4_projected) =
            budget.take_public(&network.ipv4_address, 256, sensitive_literals);
        let (ipv6_address, ipv6_projected) =
            budget.take_public(&network.ipv6_address, 256, sensitive_literals);
        projected |= name_projected || mac_projected || ipv4_projected || ipv6_projected;
        networks.push(DockerContainerNetworkDto {
            name,
            mac_address,
            ipv4_address,
            ipv6_address,
        });
    }
    let truncated = projected
        || budget.projected()
        || fields.len() < fields_len
        || mounts.len() < mounts_len
        || networks.len() < networks_len;
    DockerContainerInspectionDto {
        snapshot_handle: snapshot_handle.to_owned(),
        resource_handle: resource_handle.to_owned(),
        name,
        fields,
        mounts,
        networks,
        truncated,
    }
}

fn project_network_inspection(
    snapshot_handle: &str,
    resource_handle: &str,
    inspection: DockerNetworkInspection,
    sensitive_literals: &[&str],
) -> DockerNetworkInspectionDto {
    let mut budget = TextBudget::new(MAX_INSPECTION_TEXT_BYTES);
    let ipam_len = inspection.ipam.len();
    let attachments_len = inspection.attachments.len();
    let options_len = inspection.options.len();
    let labels_len = inspection.labels.len();
    let mut projected = false;
    let mut ipam = Vec::new();
    for value in inspection.ipam.into_iter().take(MAX_NETWORK_IPAM) {
        if budget.remaining() < MIN_ITEM_TEXT_BYTES {
            break;
        }
        let (subnet, subnet_projected) = budget.take_public(&value.subnet, 512, sensitive_literals);
        let (gateway, gateway_projected) =
            budget.take_public(&value.gateway, 512, sensitive_literals);
        let (ip_range, range_projected) =
            budget.take_public(&value.ip_range, 512, sensitive_literals);
        projected |= subnet_projected || gateway_projected || range_projected;
        ipam.push(DockerIpamDto {
            subnet,
            gateway,
            ip_range,
        });
    }
    let mut attachments = Vec::new();
    for value in inspection
        .attachments
        .into_iter()
        .take(MAX_NETWORK_ATTACHMENTS)
    {
        if budget.remaining() < MIN_ITEM_TEXT_BYTES {
            break;
        }
        let (name, name_projected) = budget.take_public(&value.name, 512, sensitive_literals);
        let (mac_address, mac_projected) =
            budget.take_public(&value.mac_address, 256, sensitive_literals);
        let (ipv4_address, ipv4_projected) =
            budget.take_public(&value.ipv4_address, 512, sensitive_literals);
        let (ipv6_address, ipv6_projected) =
            budget.take_public(&value.ipv6_address, 512, sensitive_literals);
        projected |= name_projected || mac_projected || ipv4_projected || ipv6_projected;
        attachments.push(DockerAttachmentDto {
            name,
            mac_address,
            ipv4_address,
            ipv6_address,
        });
    }
    let (options, options_projected) =
        project_metadata(inspection.options, &mut budget, sensitive_literals);
    let (labels, labels_projected) =
        project_metadata(inspection.labels, &mut budget, sensitive_literals);
    projected |= options_projected || labels_projected;
    let (name, name_projected) =
        budget.take_public(&inspection.network.name, 512, sensitive_literals);
    let (driver, driver_projected) =
        budget.take_public(&inspection.network.driver, 256, sensitive_literals);
    let (scope, scope_projected) =
        budget.take_public(&inspection.network.scope, 256, sensitive_literals);
    let (ipam_driver, ipam_driver_projected) =
        budget.take_public(&inspection.ipam_driver, 256, sensitive_literals);
    projected |= name_projected || driver_projected || scope_projected || ipam_driver_projected;
    let truncated = projected
        || budget.projected()
        || ipam.len() < ipam_len
        || attachments.len() < attachments_len
        || options.len() < options_len
        || labels.len() < labels_len;
    DockerNetworkInspectionDto {
        snapshot_handle: snapshot_handle.to_owned(),
        resource_handle: resource_handle.to_owned(),
        name,
        driver,
        scope,
        internal: inspection.network.internal,
        ipv6: inspection.network.ipv6,
        attachable: inspection.attachable,
        ingress: inspection.ingress,
        ipam_driver,
        ipam,
        attachments,
        truncated,
        options,
        labels,
    }
}

fn project_volume_inspection(
    snapshot_handle: &str,
    resource_handle: &str,
    inspection: DockerVolumeInspection,
    sensitive_literals: &[&str],
) -> DockerVolumeInspectionDto {
    let mut budget = TextBudget::new(MAX_INSPECTION_TEXT_BYTES);
    let options_len = inspection.options.len();
    let labels_len = inspection.labels.len();
    let (options, options_projected) =
        project_metadata(inspection.options, &mut budget, sensitive_literals);
    let (labels, labels_projected) =
        project_metadata(inspection.labels, &mut budget, sensitive_literals);
    let (name, name_projected) =
        budget.take_public(&inspection.volume.name, 512, sensitive_literals);
    let (driver, driver_projected) =
        budget.take_public(&inspection.volume.driver, 256, sensitive_literals);
    let (mountpoint, mountpoint_projected) =
        budget.take_public(&inspection.volume.mountpoint, 4 * 1024, sensitive_literals);
    let (scope, scope_projected) =
        budget.take_public(&inspection.volume.scope, 256, sensitive_literals);
    let (created_at, created_projected) =
        budget.take_public(&inspection.created_at, 512, sensitive_literals);
    DockerVolumeInspectionDto {
        snapshot_handle: snapshot_handle.to_owned(),
        resource_handle: resource_handle.to_owned(),
        name,
        driver,
        mountpoint,
        scope,
        created_at,
        truncated: budget.projected()
            || options_projected
            || labels_projected
            || name_projected
            || driver_projected
            || mountpoint_projected
            || scope_projected
            || created_projected
            || options.len() < options_len
            || labels.len() < labels_len,
        options,
        labels,
    }
}

fn project_metadata(
    metadata: BTreeMap<String, String>,
    budget: &mut TextBudget,
    sensitive_literals: &[&str],
) -> (Vec<DockerMetadataDto>, bool) {
    let mut items = Vec::new();
    let mut projected = false;
    for (key, value) in metadata.into_iter().take(MAX_METADATA_ENTRIES) {
        if budget.remaining() < MIN_ITEM_TEXT_BYTES {
            break;
        }
        let sensitive_key = is_sensitive_key(&key);
        let (key, key_projected) = budget.take_public(&key, 512, sensitive_literals);
        let (value, value_projected) = if sensitive_key {
            budget.take_redacted(2 * 1024)
        } else {
            budget.take_public(&value, 2 * 1024, sensitive_literals)
        };
        projected |= key_projected || value_projected;
        items.push(DockerMetadataDto { key, value });
    }
    (items, projected)
}

fn project_security_audit(
    snapshot_handle: &str,
    audit: DockerSecurityAudit,
) -> Result<DockerSecurityAuditDto, DockerReadApiError> {
    let total = audit
        .summary
        .critical
        .checked_add(audit.summary.high)
        .and_then(|count| count.checked_add(audit.summary.medium))
        .and_then(|count| count.checked_add(audit.summary.low))
        .and_then(|count| count.checked_add(audit.summary.info))
        .ok_or(DockerReadApiError::InvalidBounds)?;
    let mut finding_counts = [0_usize; 5];
    for finding in &audit.findings {
        let index = match finding.severity {
            DockerSecuritySeverity::Critical => 0,
            DockerSecuritySeverity::High => 1,
            DockerSecuritySeverity::Medium => 2,
            DockerSecuritySeverity::Low => 3,
            DockerSecuritySeverity::Info => 4,
        };
        finding_counts[index] = finding_counts[index]
            .checked_add(1)
            .ok_or(DockerReadApiError::InvalidBounds)?;
    }
    if audit.runtime != ContainerRuntime::Docker
        || audit.containers_scanned > MAX_SECURITY_CONTAINERS
        || audit.summary.total > 10_000
        || total != audit.summary.total
        || audit.summary.score > 100
        || audit.findings.len() > 10_000
        || finding_counts[0] > audit.summary.critical
        || finding_counts[1] > audit.summary.high
        || finding_counts[2] > audit.summary.medium
        || finding_counts[3] > audit.summary.low
        || finding_counts[4] > audit.summary.info
        || audit
            .findings
            .iter()
            .any(|finding| finding.container.runtime() != ContainerRuntime::Docker)
    {
        return Err(DockerReadApiError::SnapshotStale);
    }
    let mut budget = TextBudget::new(MAX_AUDIT_TEXT_BYTES);
    let source_len = audit.findings.len();
    let mut findings = Vec::new();
    for finding in audit.findings.into_iter().take(MAX_SECURITY_FINDINGS) {
        if budget.remaining() < MIN_ITEM_TEXT_BYTES {
            break;
        }
        findings.push(project_security_finding(finding, &mut budget));
    }
    Ok(DockerSecurityAuditDto {
        snapshot_handle: snapshot_handle.to_owned(),
        containers_scanned: audit.containers_scanned,
        summary: DockerSecuritySummaryDto {
            critical: audit.summary.critical,
            high: audit.summary.high,
            medium: audit.summary.medium,
            low: audit.summary.low,
            info: audit.summary.info,
            total: audit.summary.total,
            score: audit.summary.score,
        },
        truncated: audit.truncated || findings.len() < source_len,
        findings,
    })
}

fn project_security_finding(
    finding: DockerSecurityFinding,
    budget: &mut TextBudget,
) -> DockerSecurityFindingDto {
    let (container_name, name_truncated) = budget.take(&finding.container_name, 512);
    let (description, description_truncated) = budget.take(&finding.description, 4 * 1024);
    let (recommendation, recommendation_truncated) = budget.take(&finding.remediation, 4 * 1024);
    DockerSecurityFindingDto {
        severity: security_severity_key(finding.severity),
        severity_label: finding.severity.label(),
        category: security_category_key(finding.category),
        category_label: finding.category.label(),
        container_name,
        description,
        recommendation,
        text_truncated: name_truncated || description_truncated || recommendation_truncated,
    }
}

struct TextBudget {
    remaining: usize,
    projected: bool,
}

impl TextBudget {
    const fn new(remaining: usize) -> Self {
        Self {
            remaining,
            projected: false,
        }
    }

    const fn remaining(&self) -> usize {
        self.remaining
    }

    const fn projected(&self) -> bool {
        self.projected
    }

    fn take(&mut self, value: &str, maximum_bytes: usize) -> (String, bool) {
        let limit = maximum_bytes.min(self.remaining);
        let (output, truncated) = project_single_line(value, limit, &[]);
        self.remaining = self.remaining.saturating_sub(output.len());
        self.projected |= truncated;
        (output, truncated)
    }

    fn take_public(
        &mut self,
        value: &str,
        maximum_bytes: usize,
        sensitive_literals: &[&str],
    ) -> (String, bool) {
        let limit = maximum_bytes.min(self.remaining);
        let (output, projected) = project_single_line(value, limit, sensitive_literals);
        self.remaining = self.remaining.saturating_sub(output.len());
        self.projected |= projected;
        (output, projected)
    }

    fn take_redacted(&mut self, maximum_bytes: usize) -> (String, bool) {
        let limit = maximum_bytes.min(self.remaining);
        if REDACTED_DOCKER_TEXT.len() > limit {
            self.projected = true;
            return (String::new(), true);
        }
        self.remaining = self.remaining.saturating_sub(REDACTED_DOCKER_TEXT.len());
        self.projected = true;
        (REDACTED_DOCKER_TEXT.to_owned(), true)
    }
}

fn project_single_line(
    value: &str,
    maximum_bytes: usize,
    sensitive_literals: &[&str],
) -> (String, bool) {
    if is_sensitive_text(value, sensitive_literals) {
        return if REDACTED_DOCKER_TEXT.len() <= maximum_bytes {
            (REDACTED_DOCKER_TEXT.to_owned(), true)
        } else {
            (String::new(), true)
        };
    }
    let (output, projected, _) = normalize_bounded_line(value, maximum_bytes, false);
    (output, projected)
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
            if REDACTED_DOCKER_TEXT.len() > remaining {
                break;
            }
            output.push_str(REDACTED_DOCKER_TEXT);
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
    value.contains(REDACTED_DOCKER_TEXT)
        || contains_sensitive_material(value)
        || sensitive_literals
            .iter()
            .any(|literal| !literal.is_empty() && value.contains(*literal))
}

fn is_sensitive_key(value: &str) -> bool {
    const KEY_MARKERS: &[&str] = &[
        "password",
        "passwd",
        "passphrase",
        "secret",
        "token",
        "authorization",
        "api_key",
        "api-key",
        "apikey",
        "private_key",
        "private-key",
        "access_key",
        "access-key",
        "client_secret",
        "client-secret",
        "credential",
        "cookie",
        "session_id",
        "session-id",
        "fingerprint",
    ];
    KEY_MARKERS
        .iter()
        .any(|marker| contains_ascii_case_insensitive(value, marker))
}

fn contains_sensitive_material(value: &str) -> bool {
    const MARKERS: &[&str] = &[
        "password=",
        "password:",
        "password\"",
        "password'",
        "password_",
        "_password",
        "--password",
        "passwd=",
        "passphrase=",
        "passphrase:",
        "passphrase\"",
        "passphrase'",
        "secret=",
        "secret:",
        "secret\"",
        "secret'",
        "secret_",
        "_secret",
        "--secret",
        "token=",
        "token:",
        "token\"",
        "token'",
        "token_",
        "_token",
        "--token",
        "authorization=",
        "authorization:",
        "authorization\"",
        "authorization'",
        "api_key=",
        "api_key:",
        "api-key:",
        "apikey=",
        "apikey:",
        "apikey\"",
        "apikey'",
        "private_key=",
        "private-key",
        "access_key",
        "access-key",
        "client_secret",
        "client-secret",
        "private key-----",
        "credential=",
        "credential:",
        "credential\"",
        "credential'",
        "cookie:",
        "set-cookie:",
        "session_id=",
        "session_id:",
        "session-id:",
        "sessionid\"",
        "sessionid'",
        "fingerprint=",
        "bearer ",
    ];
    MARKERS
        .iter()
        .any(|marker| contains_ascii_case_insensitive(value, marker))
        || contains_uri_userinfo(value)
}

fn contains_ascii_case_insensitive(value: &str, marker: &str) -> bool {
    value
        .as_bytes()
        .windows(marker.len())
        .any(|candidate| candidate.eq_ignore_ascii_case(marker.as_bytes()))
}

fn contains_uri_userinfo(value: &str) -> bool {
    let mut remaining = value;
    while let Some(marker) = remaining.find("://") {
        remaining = &remaining[marker + 3..];
        let authority = remaining
            .split(|character: char| {
                character == '/'
                    || character == '?'
                    || character == '#'
                    || character.is_ascii_whitespace()
            })
            .next()
            .unwrap_or_default();
        if authority.contains('@') {
            return true;
        }
    }
    false
}

fn estimated_network_bytes(value: &DockerNetwork) -> usize {
    128_usize
        .saturating_add(value.id.len())
        .saturating_add(value.name.len())
        .saturating_add(value.driver.len())
        .saturating_add(value.scope.len())
}

fn estimated_volume_bytes(value: &DockerVolume) -> usize {
    128_usize
        .saturating_add(value.name.len())
        .saturating_add(value.driver.len())
        .saturating_add(value.mountpoint.len())
        .saturating_add(value.scope.len())
        .saturating_add(value.labels.len())
}

fn validate_handle(value: &str) -> Result<(), DockerReadApiError> {
    if value.is_empty()
        || value.len() > MAX_HANDLE_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(DockerReadApiError::InvalidHandle);
    }
    Ok(())
}

fn unique_handle() -> Result<String, DockerReadApiError> {
    let handle = Uuid::new_v4().to_string();
    validate_handle(&handle)?;
    Ok(handle)
}

fn unique_map_handle<T>(existing: &HashMap<String, T>) -> Result<String, DockerReadApiError> {
    for _ in 0..8 {
        let handle = unique_handle()?;
        if !existing.contains_key(&handle) {
            return Ok(handle);
        }
    }
    Err(DockerReadApiError::Capacity)
}

const fn security_severity_key(severity: DockerSecuritySeverity) -> &'static str {
    match severity {
        DockerSecuritySeverity::Critical => "critical",
        DockerSecuritySeverity::High => "high",
        DockerSecuritySeverity::Medium => "medium",
        DockerSecuritySeverity::Low => "low",
        DockerSecuritySeverity::Info => "info",
    }
}

const fn security_category_key(category: DockerSecurityCategory) -> &'static str {
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

#[cfg(test)]
mod tests {
    use lovelyres_core::docker::{
        ContainerInspectionField, ContainerMount, ContainerNetwork, DockerSecuritySummary,
    };
    use lovelyres_core::target::TargetIdentity;

    use super::*;

    const CONTAINER_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const NETWORK_ID: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

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

    fn container(name: &str) -> ContainerSummary {
        ContainerSummary {
            identity: ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_ID).unwrap(),
            name: name.to_owned(),
            image: "example:1".to_owned(),
            state: "running".to_owned(),
            status: "Up".to_owned(),
            ports: "127.0.0.1:80->80/tcp".to_owned(),
            created_at: "now".to_owned(),
            command: "must-not-cross-boundary".to_owned(),
        }
    }

    fn network(name: &str) -> DockerNetwork {
        DockerNetwork {
            runtime: ContainerRuntime::Docker,
            id: NETWORK_ID.to_owned(),
            name: name.to_owned(),
            driver: "bridge".to_owned(),
            scope: "local".to_owned(),
            internal: false,
            ipv6: false,
        }
    }

    fn snapshot(now: Instant, scope: BindingScope) -> SnapshotEntry {
        let (mut snapshot, _) = build_container_snapshot(
            scope,
            DockerCollection {
                items: vec![container("alpha")],
                truncated: false,
            },
        )
        .unwrap();
        snapshot.expires_at = now + SNAPSHOT_TTL;
        snapshot
    }

    #[test]
    fn container_snapshot_uses_opaque_handles_and_omits_identity_and_command() {
        let hostile = "</script><img src=x onerror=steal()>";
        let (_, dto) = build_container_snapshot(
            scope("server-one", 1),
            DockerCollection {
                items: vec![container(hostile)],
                truncated: false,
            },
        )
        .unwrap();
        let json = serde_json::to_string(&dto).unwrap();
        assert!(json.contains(hostile));
        assert!(!json.contains(CONTAINER_ID));
        assert!(!json.contains("must-not-cross-boundary"));
        assert!(!json.contains("session-one"));
        assert!(!json.contains("generation"));
    }

    #[test]
    fn collection_redaction_uses_the_fixed_marker_and_sets_projection_flags() {
        let (_, containers) = build_container_snapshot(
            scope("server-one", 1),
            DockerCollection {
                items: vec![container("PASSWORD=container-secret")],
                truncated: false,
            },
        )
        .unwrap();
        assert_eq!(containers.containers[0].name, REDACTED_DOCKER_TEXT);
        assert!(containers.truncated);

        let images = project_images(
            "snapshot",
            DockerCollection {
                items: vec![ContainerImage {
                    id: "must-not-cross".to_owned(),
                    repository: "https://user:pass@registry.example/image".to_owned(),
                    tag: "latest".to_owned(),
                    digest: "sha256:safe".to_owned(),
                    created_at: "now".to_owned(),
                    size: "1MiB".to_owned(),
                }],
                truncated: false,
            },
        );
        assert_eq!(images.items[0].repository, REDACTED_DOCKER_TEXT);
        assert!(images.truncated);

        let (_, volumes, volume_truncated, _) = project_volumes(DockerCollection {
            items: vec![DockerVolume {
                runtime: ContainerRuntime::Docker,
                name: "volume-one".to_owned(),
                driver: "local".to_owned(),
                mountpoint: "/safe".to_owned(),
                scope: "local".to_owned(),
                labels: "token=volume-secret".to_owned(),
            }],
            truncated: false,
        })
        .unwrap();
        assert_eq!(volumes[0].labels, REDACTED_DOCKER_TEXT);
        assert!(volume_truncated);

        let compose = project_compose_projects(
            "snapshot",
            DockerCollection {
                items: vec![DockerComposeProject {
                    runtime: ContainerRuntime::Docker,
                    name: "project-one".to_owned(),
                    status: "secret=compose-secret".to_owned(),
                    config_files: "/safe/compose.yml".to_owned(),
                    services: 1,
                    running: 1,
                    stopped: 0,
                }],
                truncated: false,
            },
        )
        .unwrap();
        assert_eq!(compose.items[0].status, REDACTED_DOCKER_TEXT);
        assert!(compose.truncated);
    }

    #[test]
    fn snapshot_registry_is_target_scoped_ttl_bounded_and_limits_concurrency() {
        let now = Instant::now();
        let first = scope("server-one", 1);
        let second = scope("server-two", 1);
        let entry = snapshot(now, first.clone());
        let handle = entry.handle.clone();
        let token = entry.token;
        let mut registry = SnapshotRegistry::default();
        registry.insert(entry).unwrap();
        assert!(matches!(
            registry.begin_read(&second, &handle),
            Err(DockerReadApiError::InvalidSnapshot)
        ));
        let switched_generation = scope("server-one", 2);
        assert!(matches!(
            registry.begin_read(&switched_generation, &handle),
            Err(DockerReadApiError::InvalidSnapshot)
        ));
        for _ in 0..MAX_ACTIVE_PER_SNAPSHOT {
            registry.begin_read(&first, &handle).unwrap();
        }
        assert!(matches!(
            registry.begin_read(&first, &handle),
            Err(DockerReadApiError::Capacity)
        ));
        for _ in 0..MAX_ACTIVE_PER_SNAPSHOT {
            registry.release_read(&handle, token);
        }
        let inflight = registry.begin_read(&first, &handle).unwrap();
        registry.snapshots.get_mut(&handle).unwrap().expires_at = now;
        assert!(matches!(
            registry.verify(&inflight),
            Err(DockerReadApiError::SnapshotStale)
        ));
        registry.release_read(&handle, token);
        registry.prune(now);
        assert!(!registry.snapshots.contains_key(&handle));
    }

    #[test]
    fn close_binding_reclaims_snapshots_resources_reads_and_refresh_without_cross_talk() {
        let now = Instant::now();
        let closed = scope("closed", 1);
        let closed_new_generation = scope("closed", 2);
        let open = scope("open", 1);
        let closed_entry = snapshot(now, closed.clone());
        let closed_handle = closed_entry.handle.clone();
        let closed_token = closed_entry.token;
        let closed_resource = closed_entry.containers.keys().next().unwrap().clone();
        let closed_new_entry = snapshot(now, closed_new_generation);
        let closed_new_handle = closed_new_entry.handle.clone();
        let open_entry = snapshot(now, open.clone());
        let open_handle = open_entry.handle.clone();
        let open_token = open_entry.token;
        let open_resource = open_entry.containers.keys().next().unwrap().clone();
        let open_bytes = open_entry.stored_bytes;

        let mut registry = SnapshotRegistry::default();
        registry.insert(closed_entry).unwrap();
        registry.insert(closed_new_entry).unwrap();
        registry.insert(open_entry).unwrap();
        let closed_access = registry.begin_read(&closed, &closed_handle).unwrap();
        let open_access = registry.begin_read(&open, &open_handle).unwrap();
        let closed_refresh = registry.begin_refresh(&closed).unwrap();
        let open_refresh = registry.begin_refresh(&open).unwrap();
        assert!(registry.total_bytes() > open_bytes);
        assert_eq!(registry.active_reads(), 2);
        assert_eq!(registry.active_refreshes, 2);

        registry.close_binding(&closed.binding_handle);
        assert!(!registry.snapshots.contains_key(&closed_handle));
        assert!(!registry.snapshots.contains_key(&closed_new_handle));
        assert!(registry.snapshots.contains_key(&open_handle));
        assert_eq!(registry.total_bytes(), open_bytes);
        assert_eq!(registry.active_reads(), 1);
        assert_eq!(registry.active_refreshes, 1);
        assert!(
            !registry
                .refreshing_bindings
                .contains_key(&closed.binding_handle)
        );
        assert_eq!(
            registry.refreshing_bindings.get(&open.binding_handle),
            Some(&open_refresh)
        );
        assert!(matches!(
            registry.verify(&closed_access),
            Err(DockerReadApiError::SnapshotStale)
        ));
        assert!(matches!(
            registry.resource(&closed_access, ResourceKind::Container, &closed_resource),
            Err(DockerReadApiError::SnapshotStale)
        ));
        assert!(registry.verify(&open_access).is_ok());
        assert!(
            registry
                .resource(&open_access, ResourceKind::Container, &open_resource)
                .is_ok()
        );

        registry.release_read(&closed_handle, closed_token);
        registry.release_refresh(&closed.binding_handle, closed_refresh);
        assert_eq!(registry.active_reads(), 1);
        assert_eq!(registry.active_refreshes, 1);
        registry.release_read(&open_handle, open_token);
        registry.release_refresh(&open.binding_handle, open_refresh);
        assert_eq!(registry.active_reads(), 0);
        assert_eq!(registry.active_refreshes, 0);
    }

    #[test]
    fn close_after_validation_blocks_late_refresh_and_old_permit_cannot_release_reuse() {
        let now = Instant::now();
        let current = scope("server-one", 1);
        let mut registry = SnapshotRegistry::default();
        let old_refresh = registry.begin_refresh(&current).unwrap();
        let old_snapshot = snapshot(now, current.clone());

        registry.close_binding(&current.binding_handle);
        let new_refresh = registry.begin_refresh(&current).unwrap();
        assert_ne!(old_refresh, new_refresh);
        assert!(matches!(
            registry.insert_refreshed(&current, old_refresh, old_snapshot),
            Err(DockerReadApiError::SnapshotStale)
        ));
        registry.release_refresh(&current.binding_handle, old_refresh);
        assert_eq!(registry.active_refreshes, 1);
        assert_eq!(
            registry.refreshing_bindings.get(&current.binding_handle),
            Some(&new_refresh)
        );

        let new_snapshot = snapshot(now, current.clone());
        let new_handle = new_snapshot.handle.clone();
        registry
            .insert_refreshed(&current, new_refresh, new_snapshot)
            .unwrap();
        assert!(registry.snapshots.contains_key(&new_handle));
        registry.release_refresh(&current.binding_handle, new_refresh);
        assert_eq!(registry.active_refreshes, 0);
    }

    #[test]
    fn registry_bounds_snapshot_refresh_binding_and_global_read_capacity() {
        let now = Instant::now();
        let mut snapshots = SnapshotRegistry::default();
        for index in 0..MAX_SNAPSHOTS {
            snapshots
                .insert(snapshot(now, scope(&format!("capacity-{index}"), 1)))
                .unwrap();
        }
        assert!(matches!(
            snapshots.insert(snapshot(now, scope("capacity-overflow", 1))),
            Err(DockerReadApiError::Capacity)
        ));
        assert!(snapshots.total_bytes() <= MAX_SNAPSHOTS * MAX_SNAPSHOT_BYTES);

        let first = scope("refresh-one", 1);
        let second = scope("refresh-two", 1);
        let third = scope("refresh-three", 1);
        let mut refreshes = SnapshotRegistry::default();
        let first_token = refreshes.begin_refresh(&first).unwrap();
        assert!(matches!(
            refreshes.begin_refresh(&first),
            Err(DockerReadApiError::Capacity)
        ));
        let second_token = refreshes.begin_refresh(&second).unwrap();
        assert!(matches!(
            refreshes.begin_refresh(&third),
            Err(DockerReadApiError::Capacity)
        ));
        refreshes.release_refresh(&first.binding_handle, first_token);
        let third_token = refreshes.begin_refresh(&third).unwrap();
        refreshes.release_refresh(&second.binding_handle, second_token);
        refreshes.release_refresh(&third.binding_handle, third_token);
        assert_eq!(refreshes.active_refreshes, 0);

        let first_generation = scope("same-binding", 1);
        let second_generation = scope("same-binding", 2);
        let first_entry = snapshot(now, first_generation.clone());
        let first_handle = first_entry.handle.clone();
        let second_entry = snapshot(now, second_generation.clone());
        let second_handle = second_entry.handle.clone();
        let mut per_binding = SnapshotRegistry::default();
        per_binding.insert(first_entry).unwrap();
        per_binding.insert(second_entry).unwrap();
        for _ in 0..MAX_ACTIVE_PER_SNAPSHOT {
            per_binding
                .begin_read(&first_generation, &first_handle)
                .unwrap();
        }
        per_binding
            .begin_read(&second_generation, &second_handle)
            .unwrap();
        assert_eq!(
            per_binding.active_reads_for_binding(&first_generation.binding_handle),
            MAX_ACTIVE_READS_PER_BINDING
        );
        assert!(matches!(
            per_binding.begin_read(&second_generation, &second_handle),
            Err(DockerReadApiError::Capacity)
        ));

        let mut global = SnapshotRegistry::default();
        let scopes = [
            scope("global-one", 1),
            scope("global-two", 1),
            scope("global-three", 1),
        ];
        let mut handles = Vec::new();
        for current in &scopes {
            let entry = snapshot(now, current.clone());
            handles.push(entry.handle.clone());
            global.insert(entry).unwrap();
        }
        for _ in 0..MAX_ACTIVE_PER_SNAPSHOT {
            global.begin_read(&scopes[0], &handles[0]).unwrap();
            global.begin_read(&scopes[1], &handles[1]).unwrap();
        }
        for _ in 0..2 {
            global.begin_read(&scopes[2], &handles[2]).unwrap();
        }
        assert_eq!(global.active_reads(), MAX_ACTIVE_READS);
        assert!(matches!(
            global.begin_read(&scopes[2], &handles[2]),
            Err(DockerReadApiError::Capacity)
        ));
    }

    #[test]
    fn replacing_resources_invalidates_old_opaque_handles_and_obeys_snapshot_budget() {
        let now = Instant::now();
        let current = scope("server-one", 1);
        let entry = snapshot(now, current.clone());
        let handle = entry.handle.clone();
        let mut registry = SnapshotRegistry::default();
        registry.insert(entry).unwrap();
        let access = registry.begin_read(&current, &handle).unwrap();
        let first = registry
            .replace_networks(
                &access,
                &handle,
                DockerCollection {
                    items: vec![network("network-one")],
                    truncated: false,
                },
            )
            .unwrap();
        let old_handle = first.items[0].network_handle.clone();
        let first_bytes = registry.snapshots[&handle].stored_bytes;
        assert!(
            registry
                .resource(&access, ResourceKind::Network, &old_handle)
                .is_ok()
        );
        registry
            .replace_networks(
                &access,
                &handle,
                DockerCollection {
                    items: vec![network("network-one")],
                    truncated: false,
                },
            )
            .unwrap();
        assert_eq!(registry.snapshots[&handle].stored_bytes, first_bytes);
        assert!(matches!(
            registry.resource(&access, ResourceKind::Network, &old_handle),
            Err(DockerReadApiError::InvalidResource)
        ));
        assert!(registry.snapshots[&handle].stored_bytes <= MAX_SNAPSHOT_BYTES);
    }

    #[test]
    fn late_resource_collection_revision_cannot_overwrite_newer_handles() {
        let now = Instant::now();
        let current = scope("server-one", 1);
        let entry = snapshot(now, current.clone());
        let handle = entry.handle.clone();
        let mut registry = SnapshotRegistry::default();
        registry.insert(entry).unwrap();
        let older = registry
            .begin_collection_read(&current, &handle, CollectionKind::Networks)
            .unwrap();
        let newer = registry
            .begin_collection_read(&current, &handle, CollectionKind::Networks)
            .unwrap();
        let current_dto = registry
            .replace_networks(
                &newer,
                &handle,
                DockerCollection {
                    items: vec![network("newer")],
                    truncated: false,
                },
            )
            .unwrap();
        let current_resource_handle = current_dto.items[0].network_handle.clone();
        assert!(matches!(
            registry.replace_networks(
                &older,
                &handle,
                DockerCollection {
                    items: vec![network("older")],
                    truncated: false,
                },
            ),
            Err(DockerReadApiError::SnapshotStale)
        ));
        assert!(
            registry
                .resource(&newer, ResourceKind::Network, &current_resource_handle)
                .is_ok()
        );
    }

    #[test]
    fn stats_must_match_container_snapshot_and_logs_are_utf8_byte_bounded() {
        let current = scope("server-one", 1);
        let (snapshot, _) = build_container_snapshot(
            current,
            DockerCollection {
                items: vec![container("alpha")],
                truncated: false,
            },
        )
        .unwrap();
        let stats = ContainerStats {
            identity: ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_ID).unwrap(),
            name: "alpha".to_owned(),
            cpu_percent: "1%".to_owned(),
            memory_usage: "1MiB / 2MiB".to_owned(),
            memory_percent: "50%".to_owned(),
            network_io: "1kB / 2kB".to_owned(),
            block_io: "0B / 0B".to_owned(),
            pids: Some(2),
        };
        assert!(
            project_stats(
                &snapshot.handle,
                DockerCollection {
                    items: vec![stats],
                    truncated: false,
                },
                &snapshot.container_index,
            )
            .is_ok()
        );
        let unknown = ContainerStats {
            identity: ContainerIdentity::new(
                ContainerRuntime::Docker,
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            )
            .unwrap(),
            name: String::new(),
            cpu_percent: String::new(),
            memory_usage: String::new(),
            memory_percent: String::new(),
            network_io: String::new(),
            block_io: String::new(),
            pids: None,
        };
        assert!(matches!(
            project_stats(
                &snapshot.handle,
                DockerCollection {
                    items: vec![unknown],
                    truncated: false,
                },
                &snapshot.container_index,
            ),
            Err(DockerReadApiError::SnapshotStale)
        ));
        let (text, truncated) =
            project_public_multiline(&"界".repeat(MAX_LOG_BYTES), MAX_LOG_BYTES, &[]);
        assert!(truncated);
        assert!(text.len() <= MAX_LOG_BYTES);
        assert!(text.is_char_boundary(text.len()));
    }

    #[test]
    fn inspection_and_security_projection_preserve_hostile_plain_text_without_ids() {
        let hostile = "</pre><script>steal()</script>";
        let inspection = ContainerInspection {
            identity: ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_ID).unwrap(),
            name: hostile.to_owned(),
            fields: vec![ContainerInspectionField {
                label: "field".to_owned(),
                value: hostile.to_owned(),
            }],
            mounts: vec![ContainerMount {
                kind: "bind".to_owned(),
                source: hostile.to_owned(),
                destination: "/safe-display".to_owned(),
                mode: "ro".to_owned(),
                read_write: false,
            }],
            networks: vec![ContainerNetwork {
                name: hostile.to_owned(),
                network_id: NETWORK_ID.to_owned(),
                endpoint_id: NETWORK_ID.to_owned(),
                mac_address: "00:00:00:00:00:00".to_owned(),
                ipv4_address: "127.0.0.1".to_owned(),
                ipv6_address: String::new(),
            }],
        };
        let dto = project_container_inspection("snapshot", "resource", inspection, &[]);
        let json = serde_json::to_string(&dto).unwrap();
        assert!(json.contains(hostile));
        assert!(!json.contains(CONTAINER_ID));
        assert!(!json.contains(NETWORK_ID));

        let audit = DockerSecurityAudit {
            runtime: ContainerRuntime::Docker,
            containers_scanned: 1,
            findings: vec![DockerSecurityFinding {
                id: format!("secret-{CONTAINER_ID}"),
                severity: DockerSecuritySeverity::Critical,
                category: DockerSecurityCategory::Privileged,
                container: ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_ID).unwrap(),
                container_name: hostile.to_owned(),
                description: hostile.to_owned(),
                remediation: hostile.to_owned(),
            }],
            summary: DockerSecuritySummary {
                critical: 1,
                high: 0,
                medium: 0,
                low: 0,
                info: 0,
                total: 1,
                score: 85,
            },
            truncated: false,
        };
        let json =
            serde_json::to_string(&project_security_audit("snapshot", audit).unwrap()).unwrap();
        assert!(json.contains(hostile));
        assert!(!json.contains(CONTAINER_ID));
    }

    #[test]
    fn inspection_fields_metadata_mounts_and_logs_redact_secrets_and_scope_literals() {
        let mut current = scope("connection-one", 7);
        current.target.identity = TargetIdentity::new("target-one").unwrap();
        let sensitive_literals = current.sensitive_literals();
        let hostile = "</pre><script>plain-data()</script>";
        let raw_secret = "raw-docker-secret-must-not-cross";
        let multi_uri = "https://safe.example/x https://user:pass@secret.example/y";

        let inspection = ContainerInspection {
            identity: ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_ID).unwrap(),
            name: "safe-container".to_owned(),
            fields: vec![
                ContainerInspectionField {
                    label: "Environment".to_owned(),
                    value: format!("SAFE=1\nPASSWORD={raw_secret}"),
                },
                ContainerInspectionField {
                    label: "client_secret".to_owned(),
                    value: raw_secret.to_owned(),
                },
                ContainerInspectionField {
                    label: "binding".to_owned(),
                    value: format!("scope={}", sensitive_literals[0]),
                },
                ContainerInspectionField {
                    label: "session".to_owned(),
                    value: format!("scope={}", sensitive_literals[1]),
                },
                ContainerInspectionField {
                    label: "connection".to_owned(),
                    value: format!("scope={}", sensitive_literals[2]),
                },
                ContainerInspectionField {
                    label: "target".to_owned(),
                    value: format!("scope={}", sensitive_literals[3]),
                },
                ContainerInspectionField {
                    label: "marker".to_owned(),
                    value: REDACTED_DOCKER_TEXT.to_owned(),
                },
                ContainerInspectionField {
                    label: "plain".to_owned(),
                    value: format!("{hostile}\u{0}"),
                },
            ],
            mounts: vec![
                ContainerMount {
                    kind: "bind".to_owned(),
                    source: multi_uri.to_owned(),
                    destination: "/safe-display".to_owned(),
                    mode: "ro".to_owned(),
                    read_write: false,
                },
                ContainerMount {
                    kind: "bind".to_owned(),
                    source: hostile.to_owned(),
                    destination: "/plain-display".to_owned(),
                    mode: "ro".to_owned(),
                    read_write: false,
                },
            ],
            networks: Vec::new(),
        };
        let dto =
            project_container_inspection("snapshot", "resource", inspection, &sensitive_literals);
        assert!(dto.truncated);
        for field in dto.fields.iter().take(7) {
            assert!(
                field.label == REDACTED_DOCKER_TEXT || field.value == REDACTED_DOCKER_TEXT,
                "sensitive inspection field was not redacted"
            );
        }
        assert_eq!(dto.mounts[0].source, REDACTED_DOCKER_TEXT);
        assert_eq!(dto.mounts[1].source, hostile);
        assert!(dto.fields[7].value.contains(hostile));
        assert!(!dto.fields[7].value.contains('\0'));
        let json = serde_json::to_string(&dto).unwrap();
        assert!(!json.contains(raw_secret));
        assert!(!json.contains("user:pass@secret.example"));
        for literal in sensitive_literals {
            assert!(!json.contains(literal));
        }

        let mut network_options = BTreeMap::new();
        network_options.insert("client_secret".to_owned(), raw_secret.to_owned());
        network_options.insert("remote".to_owned(), multi_uri.to_owned());
        let mut network_labels = BTreeMap::new();
        network_labels.insert("binding".to_owned(), current.binding_handle.clone());
        network_labels.insert("plain".to_owned(), hostile.to_owned());
        let network = project_network_inspection(
            "snapshot",
            "resource",
            DockerNetworkInspection {
                network: network("network-one"),
                attachable: false,
                ingress: false,
                ipam_driver: "default".to_owned(),
                ipam: Vec::new(),
                attachments: Vec::new(),
                options: network_options,
                labels: network_labels,
            },
            &current.sensitive_literals(),
        );
        assert!(network.truncated);
        assert!(
            network
                .options
                .iter()
                .all(|item| item.key == REDACTED_DOCKER_TEXT || item.value == REDACTED_DOCKER_TEXT)
        );
        assert!(
            network
                .labels
                .iter()
                .any(|item| item.value == REDACTED_DOCKER_TEXT)
        );
        assert!(network.labels.iter().any(|item| item.value == hostile));

        let mut volume_options = BTreeMap::new();
        volume_options.insert("password".to_owned(), raw_secret.to_owned());
        let mut volume_labels = BTreeMap::new();
        volume_labels.insert("marker".to_owned(), REDACTED_DOCKER_TEXT.to_owned());
        let volume = project_volume_inspection(
            "snapshot",
            "resource",
            DockerVolumeInspection {
                volume: DockerVolume {
                    runtime: ContainerRuntime::Docker,
                    name: "volume-one".to_owned(),
                    driver: "local".to_owned(),
                    mountpoint: current.target.identity.as_str().to_owned(),
                    scope: "local".to_owned(),
                    labels: String::new(),
                },
                created_at: "now".to_owned(),
                options: volume_options,
                labels: volume_labels,
            },
            &current.sensitive_literals(),
        );
        assert!(volume.truncated);
        assert_eq!(volume.mountpoint, REDACTED_DOCKER_TEXT);
        assert_eq!(volume.options[0].value, REDACTED_DOCKER_TEXT);
        assert_eq!(volume.labels[0].value, REDACTED_DOCKER_TEXT);

        let logs = format!(
            "{hostile}\nAuthorization: Bearer {raw_secret}\n{}\n{}\n{}\n{}\n{multi_uri}\n{}\nplain\u{0}line",
            current.binding_handle,
            current.session_id,
            current.connection_id,
            current.target.identity.as_str(),
            REDACTED_DOCKER_TEXT,
        );
        let (text, projected) =
            project_public_multiline(&logs, MAX_LOG_BYTES, &current.sensitive_literals());
        let dto = DockerLogsDto {
            snapshot_handle: "snapshot".to_owned(),
            container_handle: "container".to_owned(),
            tail: 100,
            text,
            truncated: projected,
        };
        assert!(dto.truncated);
        assert!(dto.text.contains(hostile));
        assert!(dto.text.contains(REDACTED_DOCKER_TEXT));
        assert!(dto.text.contains('\u{fffd}'));
        assert!(!dto.text.contains(raw_secret));
        assert!(!dto.text.contains("user:pass@secret.example"));
        assert!(dto.text.len() <= MAX_LOG_BYTES);
        for literal in current.sensitive_literals() {
            assert!(!dto.text.contains(literal));
        }
        assert!(contains_uri_userinfo(multi_uri));
        assert!(!contains_uri_userinfo(
            "https://safe.example/x ssh://host.example/y"
        ));
    }

    #[test]
    fn tagged_response_shape_matches_the_strict_renderer_contract() {
        let collection = DockerReadCollectionDto::Stats(DockerStatsCollectionDto {
            snapshot_handle: "snapshot-1".to_owned(),
            items: Vec::new(),
            truncated: false,
        });
        let value = serde_json::to_value(collection).unwrap();
        assert_eq!(value["kind"], "stats");
        assert_eq!(value["snapshotHandle"], "snapshot-1");
        assert_eq!(value["items"], serde_json::json!([]));
        assert_eq!(value["truncated"], false);
        assert_eq!(value.as_object().unwrap().len(), 4);

        let inspection = DockerReadInspectionDto::Container(DockerContainerInspectionDto {
            snapshot_handle: "snapshot-1".to_owned(),
            resource_handle: "container-1".to_owned(),
            name: String::new(),
            fields: Vec::new(),
            mounts: Vec::new(),
            networks: Vec::new(),
            truncated: false,
        });
        let value = serde_json::to_value(inspection).unwrap();
        assert_eq!(value["kind"], "container");
        assert_eq!(value["snapshotHandle"], "snapshot-1");
        assert_eq!(value["resourceHandle"], "container-1");
        assert_eq!(value.as_object().unwrap().len(), 8);
    }

    #[test]
    fn source_has_only_read_service_calls_and_no_mutation_file_terminal_or_generic_execution() {
        let source = include_str!("docker_read_api.rs");
        for required in [
            ".list(&session",
            ".stats(&session",
            ".images(&session",
            ".networks(&session",
            ".volumes(&session",
            ".compose_projects(&session",
            ".inspect(&session",
            ".inspect_network(&session",
            ".inspect_volume(&session",
            ".security_audit(&session",
            ".logs(&session",
        ] {
            assert!(source.contains(required), "missing read call: {required}");
        }
        for forbidden in [
            ["plan_", "action"].concat(),
            ["execute_", "action"].concat(),
            ["resource_", "mutation"].concat(),
            ["compose_", "action"].concat(),
            ["read_", "file"].concat(),
            ["write_", "file"].concat(),
            ["file_", "copy"].concat(),
            ["open_", "terminal"].concat(),
            ["shell", ".execute"].concat(),
            ["execute", "_bound"].concat(),
        ] {
            assert!(
                !source.contains(&forbidden),
                "unexpected surface: {forbidden}"
            );
        }
    }
}
