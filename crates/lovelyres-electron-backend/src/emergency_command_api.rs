//! Bounded Electron boundary for the closed emergency-command catalog.
//!
//! The renderer receives only binding-scoped opaque handles and safe catalog
//! metadata. Core catalog ids, system-family selection, and fixed shell text
//! remain sidecar-owned.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use lovelyres_core::{
    BackendServices, CoreError,
    command_workbench::{
        CommandCatalogEntry, CommandCategory, CommandExecutionReceipt, CommandResultKind,
        SystemFamily,
    },
    docker::{ContainerIdentity, ContainerSummary},
    kubernetes::{KubernetesExecTarget, KubernetesPod, KubernetesScope},
    ssh::BoundSshSession,
    target::TargetGuard,
};
use serde::Serialize;
use tokio::time::timeout;
use uuid::Uuid;

use crate::{
    emergency_path_api::{EmergencyPathApi, EmergencyPathDto, PathScope},
    ssh_api::SshApi,
};

const MAX_HANDLE_BYTES: usize = 128;
const MAX_CATALOG_COMMANDS: usize = 256;
/// A ceiling on how many containers one catalogue offers. A machine with more
/// than this is a container host, and the Docker pane is where it is read.
const MAX_CATALOG_CONTAINERS: usize = 64;
const MAX_TITLE_BYTES: usize = 128;
const MAX_DESCRIPTION_BYTES: usize = 512;
const MAX_REASON_BYTES: usize = 512;
const MAX_TIMEOUT_SECONDS: u64 = 60;
const MAX_CATALOGS: usize = 8;
const MAX_CATALOG_BYTES: usize = 256 * 1024;
const MAX_REGISTRY_BYTES: usize = 2 * 1024 * 1024;
const MAX_ACTIVE_LOADS: usize = 2;
const MAX_ACTIVE_RUNS: usize = 4;
const MAX_CORE_OUTPUT_BYTES: usize = 2 * 1024 * 1024;
const MAX_OUTPUT_LINES: usize = 2_000;
const MAX_OUTPUT_LINE_BYTES: usize = 4 * 1024;
const MAX_OUTPUT_BYTES: usize = 256 * 1024;
const MAX_CATALOG_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_RUN_RESPONSE_BYTES: usize = 384 * 1024;
const MAX_RECEIPT_DURATION_MS: u64 = 60_000;
const CATALOG_TTL: Duration = Duration::from_secs(5 * 60);
const DETECTION_DEADLINE: Duration = Duration::from_secs(15);
// The backstop must sit above the largest catalog timeout, otherwise a heavy
// scan is cut off here and reported as a boundary failure instead of the
// honest timeout receipt the core produces.
const EXECUTION_DEADLINE: Duration = Duration::from_secs(75);
const _: () = assert!(MAX_TIMEOUT_SECONDS < EXECUTION_DEADLINE.as_secs());
// Output crosses the boundary verbatim. The tool runs against targets the
// operator already owns, and blanking lines that merely look credential-like
// destroys the very evidence the run was started for.

#[derive(Clone)]
pub(crate) struct EmergencyCommandApi {
    services: BackendServices,
    ssh_api: Arc<SshApi>,
    paths: EmergencyPathApi,
    registry: Arc<Mutex<EmergencyRegistry>>,
}

impl fmt::Debug for EmergencyCommandApi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (catalogs, bytes, loads, runs) = self
            .registry
            .lock()
            .map(|registry| {
                (
                    registry.catalogs.len(),
                    registry.total_bytes(),
                    registry.active_load_bindings.len(),
                    registry.active_runs.len(),
                )
            })
            .unwrap_or_default();
        formatter
            .debug_struct("EmergencyCommandApi")
            .field("catalog_count", &catalogs)
            .field("registry_bytes", &bytes)
            .field("active_loads", &loads)
            .field("active_runs", &runs)
            .finish()
    }
}

impl EmergencyCommandApi {
    pub(crate) fn new(services: BackendServices, ssh_api: Arc<SshApi>) -> Self {
        Self {
            paths: EmergencyPathApi::new(services.clone(), Arc::clone(&ssh_api)),
            services,
            ssh_api,
            registry: Arc::new(Mutex::new(EmergencyRegistry::default())),
        }
    }

    /// The surface that acts on a path one of these runs printed.
    pub(crate) fn paths(&self) -> &EmergencyPathApi {
        &self.paths
    }

    pub(crate) fn close_binding(&self, binding_handle: &str) {
        self.paths.close_binding(binding_handle);
        if let Ok(mut registry) = self.registry.lock() {
            registry.close_binding(binding_handle);
        }
    }

    pub(crate) async fn load_catalog(
        &self,
        binding_handle: &str,
    ) -> Result<EmergencyCommandCatalogDto, EmergencyCommandApiError> {
        let (session, scope) = self.capture_binding(binding_handle)?;
        let _permit = self.begin_load(&scope)?;
        let entries = self.services.commands().catalog();
        // A host under investigation is often a host under load, and the one
        // that will not answer a probe in time is the one an operator most
        // needs a catalogue for. Fall back to the portable command set rather
        // than handing back an empty page.
        let family = match timeout(
            DETECTION_DEADLINE,
            self.services.commands().detect_system(&session),
        )
        .await
        {
            Ok(Ok(family)) => family,
            Ok(Err(error)) => {
                tracing::warn!(
                    operation = "detect target system family",
                    error = %error,
                    "falling back to the portable command set"
                );
                SystemFamily::Other
            }
            Err(_) => {
                tracing::warn!(
                    operation = "detect target system family",
                    "probe exceeded its deadline; falling back to the portable command set"
                );
                SystemFamily::Other
            }
        };
        self.validate_binding(&scope)?;

        // Containers are an offer, never a requirement. A target with no
        // runtime, or one whose runtime will not answer, still gets its
        // catalogue — it simply has nothing to point it at.
        let containers = match timeout(
            DETECTION_DEADLINE,
            self.list_containers_for_catalog(&session),
        )
        .await
        {
            Ok(Ok(containers)) => containers,
            Ok(Err(error)) => {
                tracing::info!(
                    operation = "list containers for the command workbench",
                    error = %error,
                    "no containers will be offered"
                );
                Vec::new()
            }
            Err(_) => {
                tracing::info!(
                    operation = "list containers for the command workbench",
                    "probe exceeded its deadline; no containers will be offered"
                );
                Vec::new()
            }
        };
        // Pods, on the same terms: an offer when the target is a Kubernetes
        // client, and silence when it is not.
        let pods = match timeout(DETECTION_DEADLINE, self.list_pods_for_catalog(&session)).await {
            Ok(Ok(pods)) => pods,
            Ok(Err(error)) => {
                tracing::info!(
                    operation = "list pods for the command workbench",
                    error = %error,
                    "no pods will be offered"
                );
                Vec::new()
            }
            Err(_) => {
                tracing::info!(
                    operation = "list pods for the command workbench",
                    "probe exceeded its deadline; no pods will be offered"
                );
                Vec::new()
            }
        };
        self.validate_binding(&scope)?;

        let now = Instant::now();
        let (catalog, dto) = build_catalog(scope.clone(), family, entries, containers, pods, now)?;
        ensure_serialized_bound(&dto, MAX_CATALOG_RESPONSE_BYTES)?;
        let snapshot_handle = catalog.snapshot_handle.clone();
        let token = catalog.token;
        let mut registry = self.lock_registry()?;
        registry.prune(now);
        registry.replace(catalog)?;
        drop(registry);

        self.validate_binding(&scope)?;
        self.verify_catalog(&scope, &snapshot_handle, token)?;
        Ok(dto)
    }

    pub(crate) async fn run_command(
        &self,
        binding_handle: &str,
        snapshot_handle: &str,
        command_handle: &str,
        container_handle: Option<&str>,
    ) -> Result<EmergencyCommandResultDto, EmergencyCommandApiError> {
        validate_handle(snapshot_handle)?;
        validate_handle(command_handle)?;
        if let Some(handle) = container_handle {
            validate_handle(handle)?;
        }
        let (session, scope) = self.capture_binding(binding_handle)?;
        let (access, command, family, _permit) =
            self.begin_run(&scope, snapshot_handle, command_handle)?;
        // Resolved from the same snapshot the command came from, so a handle
        // from a refreshed catalogue or another target names nothing.
        let container = match container_handle {
            None => None,
            Some(handle) => Some(self.resolve_container(snapshot_handle, handle)?),
        };
        let receipt = match &container {
            None => timeout(
                EXECUTION_DEADLINE,
                self.services
                    .commands()
                    .execute(&session, &command.raw_id, family),
            )
            .await
            .map_err(|_| EmergencyCommandApiError::Deadline)??,
            Some(place) => {
                // The place's own family, never the target's. An Alpine
                // container on an Ubuntu host — or a distroless pod on any
                // node — is ordinary, and the Debian form of a command on a
                // busybox userland prints nothing and exits zero, which reads
                // as a clean container.
                let inner = self
                    .container_family(&session, snapshot_handle, container_handle.unwrap(), place)
                    .await?;
                self.validate_binding(&scope)?;
                let run = async {
                    match place {
                        ExecPlace::Container(identity) => {
                            self.services
                                .commands()
                                .execute_in_container(&session, &command.raw_id, inner, identity)
                                .await
                        }
                        ExecPlace::Pod(pod) => {
                            self.services
                                .commands()
                                .execute_in_pod(&session, &command.raw_id, inner, pod)
                                .await
                        }
                    }
                };
                timeout(EXECUTION_DEADLINE, run)
                    .await
                    .map_err(|_| EmergencyCommandApiError::Deadline)??
            }
        };

        self.validate_binding(&scope)?;
        self.verify_run(&access, &command)?;
        validate_receipt(&command, &receipt)?;
        let (mut dto, clipped_lines) = project_receipt(&access, &command, receipt)?;
        // Read from what the window will display, so a line the operator
        // clicks is the line the path was taken from.
        dto.paths = self
            .paths
            .offer(&scope.to_path_scope(), &dto.output, &clipped_lines);
        ensure_serialized_bound(&dto, MAX_RUN_RESPONSE_BYTES)?;
        self.validate_binding(&scope)?;
        self.verify_run(&access, &command)?;
        Ok(dto)
    }

    /// The running pods this target can reach, or none at all.
    ///
    /// Availability is checked first so a machine without kubectl, or with one
    /// that cannot reach an API server, costs a single fast probe instead of a
    /// listing that will time out.
    async fn list_pods_for_catalog(
        &self,
        session: &BoundSshSession,
    ) -> Result<Vec<KubernetesPod>, CoreError> {
        let availability = self.services.kubernetes().availability(session).await?;
        if !availability.kubectl_installed || !availability.api_reachable {
            return Ok(Vec::new());
        }
        Ok(self
            .services
            .kubernetes()
            .pods(
                session,
                &KubernetesScope::AllNamespaces,
                MAX_CATALOG_CONTAINERS,
            )
            .await?
            .items)
    }

    /// Turns a container handle back into an identity, under this snapshot.
    fn resolve_container(
        &self,
        snapshot_handle: &str,
        container_handle: &str,
    ) -> Result<ExecPlace, EmergencyCommandApiError> {
        let registry = self.lock_registry()?;
        registry
            .catalogs
            .get(snapshot_handle)
            .and_then(|catalog| {
                catalog
                    .containers
                    .iter()
                    .find(|container| container.container_handle == container_handle)
            })
            .map(|container| match &container.place {
                ExecPlace::Container(identity) => ExecPlace::Container(identity.clone()),
                ExecPlace::Pod(pod) => ExecPlace::Pod(pod.clone()),
            })
            .ok_or(EmergencyCommandApiError::CatalogStale)
    }

    /// Which family the container is, detected once and then remembered.
    ///
    /// Detecting per command would put a round trip in front of every check on
    /// a container, and the answer cannot change while it is running.
    async fn container_family(
        &self,
        session: &BoundSshSession,
        snapshot_handle: &str,
        container_handle: &str,
        place: &ExecPlace,
    ) -> Result<SystemFamily, EmergencyCommandApiError> {
        if let Some(known) = self.cached_container_family(snapshot_handle, container_handle)? {
            return Ok(known);
        }
        let probe = async {
            match place {
                ExecPlace::Container(identity) => {
                    self.services
                        .commands()
                        .detect_container_system(session, identity)
                        .await
                }
                ExecPlace::Pod(pod) => {
                    self.services
                        .commands()
                        .detect_pod_system(session, pod)
                        .await
                }
            }
        };
        let detected = match timeout(DETECTION_DEADLINE, probe).await {
            Ok(Ok(family)) => family,
            // Same rule the host detection follows: a probe that will not
            // answer falls back to the portable command set rather than
            // refusing to run anything.
            _ => SystemFamily::Other,
        };
        // Best effort: a catalogue that expired while the probe ran simply
        // does not get the answer cached, and the next run asks again.
        if let Ok(mut registry) = self.registry.lock()
            && let Some(catalog) = registry.catalogs.get_mut(snapshot_handle)
            && let Some(container) = catalog
                .containers
                .iter_mut()
                .find(|container| container.container_handle == container_handle)
        {
            container.family = Some(detected);
        }
        Ok(detected)
    }

    fn cached_container_family(
        &self,
        snapshot_handle: &str,
        container_handle: &str,
    ) -> Result<Option<SystemFamily>, EmergencyCommandApiError> {
        let registry = self.lock_registry()?;
        Ok(registry
            .catalogs
            .get(snapshot_handle)
            .and_then(|catalog| {
                catalog
                    .containers
                    .iter()
                    .find(|container| container.container_handle == container_handle)
            })
            .and_then(|container| container.family))
    }

    /// The running containers on this target, or none at all.
    ///
    /// The runtime is detected rather than assumed: most RHEL-family and
    /// domestic distributions ship Podman and no `docker`, and assuming
    /// otherwise reports an empty machine on every one of them.
    async fn list_containers_for_catalog(
        &self,
        session: &BoundSshSession,
    ) -> Result<Vec<ContainerSummary>, CoreError> {
        let probe = self.services.docker().detect_runtime(session).await?;
        let Some(runtime) = probe.usable else {
            return Ok(Vec::new());
        };
        Ok(self.services.docker().list(session, runtime).await?.items)
    }

    fn capture_binding(
        &self,
        binding_handle: &str,
    ) -> Result<(BoundSshSession, BindingScope), EmergencyCommandApiError> {
        validate_handle(binding_handle)?;
        let session = self
            .ssh_api
            .binding_session_clone(binding_handle)
            .map_err(|_| EmergencyCommandApiError::BindingUnavailable)?;
        self.services
            .target()
            .validate(session.target())
            .map_err(|_| EmergencyCommandApiError::BindingUnavailable)?;
        let scope = BindingScope::from_session(binding_handle, &session);
        Ok((session, scope))
    }

    fn validate_binding(&self, expected: &BindingScope) -> Result<(), EmergencyCommandApiError> {
        let (_, current) = self.capture_binding(&expected.binding_handle)?;
        if &current != expected {
            return Err(EmergencyCommandApiError::BindingUnavailable);
        }
        Ok(())
    }

    fn begin_load(&self, scope: &BindingScope) -> Result<LoadPermit, EmergencyCommandApiError> {
        let mut registry = self.lock_registry()?;
        registry.prune(Instant::now());
        registry.begin_load(scope)?;
        Ok(LoadPermit {
            registry: Arc::clone(&self.registry),
            binding_handle: scope.binding_handle.clone(),
        })
    }

    fn begin_run(
        &self,
        scope: &BindingScope,
        snapshot_handle: &str,
        command_handle: &str,
    ) -> Result<(RunAccess, StoredCommand, SystemFamily, RunPermit), EmergencyCommandApiError> {
        let mut registry = self.lock_registry()?;
        registry.prune(Instant::now());
        let (access, command, family) =
            registry.begin_run(scope, snapshot_handle, command_handle)?;
        let permit = RunPermit {
            registry: Arc::clone(&self.registry),
            run_token: access.run_token,
        };
        Ok((access, command, family, permit))
    }

    fn verify_catalog(
        &self,
        scope: &BindingScope,
        snapshot_handle: &str,
        token: Uuid,
    ) -> Result<(), EmergencyCommandApiError> {
        self.lock_registry()?
            .verify_catalog(scope, snapshot_handle, token)
    }

    fn verify_run(
        &self,
        access: &RunAccess,
        command: &StoredCommand,
    ) -> Result<(), EmergencyCommandApiError> {
        self.lock_registry()?.verify_run(access, command)
    }

    fn lock_registry(&self) -> Result<MutexGuard<'_, EmergencyRegistry>, EmergencyCommandApiError> {
        self.registry
            .lock()
            .map_err(|_| EmergencyCommandApiError::RegistryUnavailable)
    }
}

pub(crate) enum EmergencyCommandApiError {
    Core,
    BindingUnavailable,
    InvalidHandle,
    InvalidCatalog,
    CatalogStale,
    Busy,
    Capacity,
    Deadline,
    InvalidReceipt,
    RegistryUnavailable,
}

impl fmt::Debug for EmergencyCommandApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core => "Core([REDACTED])",
            Self::BindingUnavailable => "BindingUnavailable",
            Self::InvalidHandle => "InvalidHandle",
            Self::InvalidCatalog => "InvalidCatalog",
            Self::CatalogStale => "CatalogStale",
            Self::Busy => "Busy",
            Self::Capacity => "Capacity",
            Self::Deadline => "Deadline",
            Self::InvalidReceipt => "InvalidReceipt",
            Self::RegistryUnavailable => "RegistryUnavailable",
        })
    }
}

impl fmt::Display for EmergencyCommandApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core => "the emergency command operation failed",
            Self::BindingUnavailable => "the SSH binding is missing or stale",
            Self::InvalidHandle => "the emergency command capability is invalid",
            Self::InvalidCatalog => "the emergency command catalog is invalid",
            Self::CatalogStale => "the emergency command catalog is missing or stale",
            Self::Busy => "the emergency command boundary is busy",
            Self::Capacity => "the emergency command boundary reached its capacity",
            Self::Deadline => "the emergency command operation exceeded its deadline",
            Self::InvalidReceipt => "the emergency command result was rejected",
            Self::RegistryUnavailable => "the emergency command registry is unavailable",
        })
    }
}

impl std::error::Error for EmergencyCommandApiError {}

impl From<CoreError> for EmergencyCommandApiError {
    fn from(error: CoreError) -> Self {
        // The renderer only ever sees a fixed message, so without this the
        // reason a page failed is lost before anyone can read it.
        tracing::warn!(operation = "EmergencyCommand", error = %error, "core operation failed");
        // A host that went away is not a failure of this feature. One lost
        // connection reported once beats a dozen features each announcing
        // their own breakage.
        if matches!(error, CoreError::SshDisconnected { .. }) {
            return Self::BindingUnavailable;
        }
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

    fn to_path_scope(&self) -> PathScope {
        PathScope {
            binding_handle: self.binding_handle.clone(),
            session_id: self.session_id.clone(),
            connection_id: self.connection_id.clone(),
            target: self.target.clone(),
        }
    }

    fn estimated_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(self.binding_handle.len())
            .saturating_add(self.session_id.len())
            .saturating_add(self.connection_id.len())
            .saturating_add(self.target.identity.as_str().len())
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum EmergencyCommandCategory {
    Permissions,
    Accounts,
    Network,
    Processes,
    Persistence,
    Logs,
    Files,
    Containers,
    System,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum EmergencyCommandResultKind {
    Success,
    Empty,
    NonZero,
    Timeout,
    MissingCommand,
    PermissionDenied,
    UnknownExit,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EmergencyCommandCatalogDto {
    pub(crate) snapshot_handle: String,
    pub(crate) expires_in_seconds: u64,
    pub(crate) commands: Vec<EmergencyCommandCatalogItemDto>,
    /// The containers on this target a command may be pointed at.
    ///
    /// Empty when there is no container runtime, which is the ordinary case.
    pub(crate) containers: Vec<EmergencyCommandContainerDto>,
}

/// One container the toolbar can offer.
///
/// Name and image so a person can pick the right one; a handle so the run can
/// name it. No container id: the same rule the Docker pane follows.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EmergencyCommandContainerDto {
    pub(crate) container_handle: String,
    /// `container` or `pod`. Carried rather than guessed from the name: the
    /// pane says which one it is offering, and a pod named like a container
    /// must not read as one.
    pub(crate) kind: &'static str,
    pub(crate) name: String,
    pub(crate) image: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EmergencyCommandCatalogItemDto {
    pub(crate) command_handle: String,
    pub(crate) category: EmergencyCommandCategory,
    pub(crate) title: String,
    pub(crate) description: String,
    pub(crate) timeout_seconds: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EmergencyCommandResultDto {
    pub(crate) snapshot_handle: String,
    pub(crate) command_handle: String,
    pub(crate) result_kind: EmergencyCommandResultKind,
    pub(crate) exit_code: Option<i32>,
    pub(crate) output: String,
    pub(crate) observed_line_count: u32,
    pub(crate) displayed_line_count: u32,
    pub(crate) finding_lines: Vec<u32>,
    pub(crate) finding_reason: Option<String>,
    pub(crate) truncated: bool,
    /// One entry per displayed line that named a file, so the window can offer
    /// an action on the line the operator points at.
    pub(crate) paths: Vec<EmergencyPathDto>,
}

#[derive(Clone, PartialEq, Eq)]
struct StoredCommand {
    command_handle: String,
    raw_id: String,
    category: EmergencyCommandCategory,
    title: String,
    description: String,
    timeout_seconds: u64,
}

impl StoredCommand {
    fn estimated_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(self.command_handle.len())
            .saturating_add(self.raw_id.len())
            .saturating_add(self.title.len())
            .saturating_add(self.description.len())
    }

    fn dto(&self) -> EmergencyCommandCatalogItemDto {
        EmergencyCommandCatalogItemDto {
            command_handle: self.command_handle.clone(),
            category: self.category,
            title: self.title.clone(),
            description: self.description.clone(),
            timeout_seconds: self.timeout_seconds,
        }
    }
}

/// Where a check can run, when that is not the target itself.
///
/// One handle space for both kinds, so the pane offers one list and the run
/// call takes one handle. Which kind a handle is was decided when the
/// catalogue was built and cannot be changed by the caller.
enum ExecPlace {
    Container(ContainerIdentity),
    Pod(KubernetesExecTarget),
}

/// A place the catalog can be pointed at, and what was learned about it.
///
/// The family is filled in on the first run against this place and kept for
/// the rest of the snapshot: it costs a round trip, it does not change while
/// the container is running, and detecting it per command would make every
/// check pay for it again.
struct StoredContainer {
    container_handle: String,
    place: ExecPlace,
    name: String,
    image: String,
    family: Option<SystemFamily>,
}

impl StoredContainer {
    fn estimated_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(self.container_handle.len())
            .saturating_add(match &self.place {
                ExecPlace::Container(identity) => identity.id().len(),
                ExecPlace::Pod(pod) => pod.namespace().len() + pod.pod().len(),
            })
            .saturating_add(self.name.len())
            .saturating_add(self.image.len())
    }
}

struct CatalogSnapshot {
    snapshot_handle: String,
    token: Uuid,
    scope: BindingScope,
    family: SystemFamily,
    commands: Vec<StoredCommand>,
    /// Empty when the target has no container runtime, which is the ordinary
    /// case and not an error.
    containers: Vec<StoredContainer>,
    stored_bytes: usize,
    created_at: Instant,
    expires_at: Instant,
}

#[derive(Clone, PartialEq, Eq)]
struct RunAccess {
    snapshot_handle: String,
    snapshot_token: Uuid,
    command_handle: String,
    run_token: Uuid,
    scope: BindingScope,
}

struct ActiveRun {
    snapshot_handle: String,
    snapshot_token: Uuid,
    binding_handle: String,
}

#[derive(Default)]
struct EmergencyRegistry {
    catalogs: HashMap<String, CatalogSnapshot>,
    active_load_bindings: HashSet<String>,
    active_runs: HashMap<Uuid, ActiveRun>,
}

impl EmergencyRegistry {
    fn total_bytes(&self) -> usize {
        self.catalogs
            .values()
            .map(|catalog| catalog.stored_bytes)
            .fold(0usize, usize::saturating_add)
    }

    fn close_binding(&mut self, binding_handle: &str) {
        self.catalogs
            .retain(|_, catalog| catalog.scope.binding_handle != binding_handle);
        self.active_load_bindings.remove(binding_handle);
        self.active_runs
            .retain(|_, run| run.binding_handle != binding_handle);
    }

    fn begin_load(&mut self, scope: &BindingScope) -> Result<(), EmergencyCommandApiError> {
        if self.active_load_bindings.len() >= MAX_ACTIVE_LOADS
            || self.active_load_bindings.contains(&scope.binding_handle)
            || self
                .active_runs
                .values()
                .any(|run| run.binding_handle == scope.binding_handle)
        {
            return Err(EmergencyCommandApiError::Busy);
        }
        self.active_load_bindings
            .insert(scope.binding_handle.clone());
        Ok(())
    }

    fn finish_load(&mut self, binding_handle: &str) {
        self.active_load_bindings.remove(binding_handle);
    }

    fn replace(&mut self, catalog: CatalogSnapshot) -> Result<(), EmergencyCommandApiError> {
        if catalog.commands.len() > MAX_CATALOG_COMMANDS
            || catalog.stored_bytes > MAX_CATALOG_BYTES
            || catalog.stored_bytes > MAX_REGISTRY_BYTES
        {
            return Err(EmergencyCommandApiError::Capacity);
        }
        let binding_handle = catalog.scope.binding_handle.clone();
        self.catalogs
            .retain(|_, stored| stored.scope.binding_handle != binding_handle);
        while self.catalogs.len() >= MAX_CATALOGS
            || self.total_bytes().saturating_add(catalog.stored_bytes) > MAX_REGISTRY_BYTES
        {
            let Some(handle) = self
                .catalogs
                .iter()
                .filter(|(handle, stored)| !self.is_catalog_active(handle, stored.token))
                .min_by_key(|(_, stored)| stored.created_at)
                .map(|(handle, _)| handle.clone())
            else {
                return Err(EmergencyCommandApiError::Capacity);
            };
            self.catalogs.remove(&handle);
        }
        self.catalogs
            .insert(catalog.snapshot_handle.clone(), catalog);
        Ok(())
    }

    fn begin_run(
        &mut self,
        scope: &BindingScope,
        snapshot_handle: &str,
        command_handle: &str,
    ) -> Result<(RunAccess, StoredCommand, SystemFamily), EmergencyCommandApiError> {
        if self.active_runs.len() >= MAX_ACTIVE_RUNS
            || self.active_load_bindings.contains(&scope.binding_handle)
            || self
                .active_runs
                .values()
                .any(|run| run.binding_handle == scope.binding_handle)
        {
            return Err(EmergencyCommandApiError::Busy);
        }
        let catalog = self
            .catalogs
            .get_mut(snapshot_handle)
            .ok_or(EmergencyCommandApiError::CatalogStale)?;
        let now = Instant::now();
        if &catalog.scope != scope || catalog.expires_at <= now {
            return Err(EmergencyCommandApiError::CatalogStale);
        }
        // The window slides while the catalogue is in use. A sweep of a slow
        // host outlasts a fixed five minutes and every command after that
        // point failed, which in the window is a category run stopping
        // half-way through. An idle catalogue still expires on time, and the
        // target-change check below is what actually guards the binding.
        catalog.expires_at = now + CATALOG_TTL;
        let catalog = &*catalog;
        let command = catalog
            .commands
            .iter()
            .find(|command| command.command_handle == command_handle)
            .cloned()
            .ok_or(EmergencyCommandApiError::CatalogStale)?;
        let run_token = Uuid::new_v4();
        let access = RunAccess {
            snapshot_handle: snapshot_handle.to_owned(),
            snapshot_token: catalog.token,
            command_handle: command_handle.to_owned(),
            run_token,
            scope: scope.clone(),
        };
        self.active_runs.insert(
            run_token,
            ActiveRun {
                snapshot_handle: snapshot_handle.to_owned(),
                snapshot_token: catalog.token,
                binding_handle: scope.binding_handle.clone(),
            },
        );
        Ok((access, command, catalog.family))
    }

    fn verify_catalog(
        &self,
        scope: &BindingScope,
        snapshot_handle: &str,
        token: Uuid,
    ) -> Result<(), EmergencyCommandApiError> {
        let catalog = self
            .catalogs
            .get(snapshot_handle)
            .ok_or(EmergencyCommandApiError::CatalogStale)?;
        if catalog.token != token || &catalog.scope != scope || catalog.expires_at <= Instant::now()
        {
            return Err(EmergencyCommandApiError::CatalogStale);
        }
        Ok(())
    }

    fn verify_run(
        &self,
        access: &RunAccess,
        expected_command: &StoredCommand,
    ) -> Result<(), EmergencyCommandApiError> {
        let active = self
            .active_runs
            .get(&access.run_token)
            .ok_or(EmergencyCommandApiError::CatalogStale)?;
        let catalog = self
            .catalogs
            .get(&access.snapshot_handle)
            .ok_or(EmergencyCommandApiError::CatalogStale)?;
        if active.snapshot_handle != access.snapshot_handle
            || active.snapshot_token != access.snapshot_token
            || active.binding_handle != access.scope.binding_handle
            || catalog.token != access.snapshot_token
            || catalog.scope != access.scope
            || catalog.expires_at <= Instant::now()
            || catalog
                .commands
                .iter()
                .find(|command| command.command_handle == access.command_handle)
                != Some(expected_command)
        {
            return Err(EmergencyCommandApiError::CatalogStale);
        }
        Ok(())
    }

    fn finish_run(&mut self, run_token: Uuid) {
        self.active_runs.remove(&run_token);
    }

    fn prune(&mut self, now: Instant) {
        self.catalogs.retain(|_, catalog| catalog.expires_at > now);
    }

    fn is_catalog_active(&self, snapshot_handle: &str, snapshot_token: Uuid) -> bool {
        self.active_runs.values().any(|run| {
            run.snapshot_handle == snapshot_handle && run.snapshot_token == snapshot_token
        })
    }
}

struct LoadPermit {
    registry: Arc<Mutex<EmergencyRegistry>>,
    binding_handle: String,
}

impl Drop for LoadPermit {
    fn drop(&mut self) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.finish_load(&self.binding_handle);
        }
    }
}

struct RunPermit {
    registry: Arc<Mutex<EmergencyRegistry>>,
    run_token: Uuid,
}

impl Drop for RunPermit {
    fn drop(&mut self) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.finish_run(self.run_token);
        }
    }
}

fn build_catalog(
    scope: BindingScope,
    family: SystemFamily,
    entries: Vec<CommandCatalogEntry>,
    containers: Vec<ContainerSummary>,
    pods: Vec<KubernetesPod>,
    now: Instant,
) -> Result<(CatalogSnapshot, EmergencyCommandCatalogDto), EmergencyCommandApiError> {
    if entries.len() > MAX_CATALOG_COMMANDS {
        return Err(EmergencyCommandApiError::Capacity);
    }
    let mut raw_ids = HashSet::with_capacity(entries.len());
    let mut commands = Vec::with_capacity(entries.len());
    for entry in entries {
        if !valid_raw_id(entry.id)
            || !raw_ids.insert(entry.id)
            || !valid_catalog_text(entry.title, MAX_TITLE_BYTES, false)
            || !valid_catalog_text(entry.description, MAX_DESCRIPTION_BYTES, false)
            || !(1..=MAX_TIMEOUT_SECONDS).contains(&entry.timeout_seconds)
        {
            return Err(EmergencyCommandApiError::InvalidCatalog);
        }
        commands.push(StoredCommand {
            command_handle: Uuid::new_v4().to_string(),
            raw_id: entry.id.to_owned(),
            category: category(entry.category),
            title: entry.title.to_owned(),
            description: entry.description.to_owned(),
            timeout_seconds: entry.timeout_seconds,
        });
    }
    // Only containers that are running: a stopped one has no process namespace
    // to enter, so offering it would produce a refusal per command rather than
    // an answer.
    let mut stored_containers = containers
        .into_iter()
        .filter(ContainerSummary::is_running)
        .map(|container| StoredContainer {
            container_handle: Uuid::new_v4().to_string(),
            name: bounded_text(&container.name, MAX_TITLE_BYTES),
            image: bounded_text(&container.image, MAX_TITLE_BYTES),
            place: ExecPlace::Container(container.identity),
            family: None,
        })
        .collect::<Vec<_>>();
    // Pods join the same list. Only running ones, for the same reason: a pod
    // that is not running has no container to enter.
    stored_containers.extend(pods.into_iter().filter_map(|pod| {
        if !pod.phase.eq_ignore_ascii_case("running") {
            return None;
        }
        let target = KubernetesExecTarget::new(&pod.namespace, &pod.name).ok()?;
        Some(StoredContainer {
            container_handle: Uuid::new_v4().to_string(),
            name: bounded_text(&format!("{}/{}", pod.namespace, pod.name), MAX_TITLE_BYTES),
            image: bounded_text(
                pod.images.first().map(String::as_str).unwrap_or_default(),
                MAX_TITLE_BYTES,
            ),
            place: ExecPlace::Pod(target),
            family: None,
        })
    }));
    stored_containers.truncate(MAX_CATALOG_CONTAINERS);
    let snapshot_handle = Uuid::new_v4().to_string();
    let stored_bytes = stored_containers.iter().fold(0usize, |total, container| {
        total.saturating_add(container.estimated_bytes())
    });
    let stored_bytes = commands.iter().fold(
        stored_bytes
            .saturating_add(scope.estimated_bytes())
            .saturating_add(snapshot_handle.len())
            .saturating_add(std::mem::size_of::<CatalogSnapshot>()),
        |total, command| total.saturating_add(command.estimated_bytes()),
    );
    if stored_bytes > MAX_CATALOG_BYTES {
        return Err(EmergencyCommandApiError::Capacity);
    }
    let dto = EmergencyCommandCatalogDto {
        snapshot_handle: snapshot_handle.clone(),
        expires_in_seconds: CATALOG_TTL.as_secs(),
        commands: commands.iter().map(StoredCommand::dto).collect(),
        containers: stored_containers
            .iter()
            .map(|container| EmergencyCommandContainerDto {
                container_handle: container.container_handle.clone(),
                kind: match container.place {
                    ExecPlace::Container(_) => "container",
                    ExecPlace::Pod(_) => "pod",
                },
                name: container.name.clone(),
                image: container.image.clone(),
            })
            .collect(),
    };
    let catalog = CatalogSnapshot {
        snapshot_handle,
        token: Uuid::new_v4(),
        scope,
        family,
        commands,
        containers: stored_containers,
        stored_bytes,
        created_at: now,
        expires_at: now + CATALOG_TTL,
    };
    Ok((catalog, dto))
}

fn validate_receipt(
    command: &StoredCommand,
    receipt: &CommandExecutionReceipt,
) -> Result<(), EmergencyCommandApiError> {
    if receipt.command_id != command.raw_id
        || receipt.title != command.title
        || receipt.output.len() > MAX_CORE_OUTPUT_BYTES
        || receipt.duration_ms > MAX_RECEIPT_DURATION_MS
        || receipt.finding_lines.len() > MAX_OUTPUT_LINES
        || !receipt
            .finding_lines
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || receipt.finding_lines.last().is_some_and(|last| {
            usize::try_from(*last).unwrap_or(usize::MAX) >= receipt.output.lines().count()
        })
        || receipt
            .finding_reason
            .as_deref()
            .is_some_and(|reason| !valid_catalog_text(reason, MAX_REASON_BYTES, false))
    {
        return Err(EmergencyCommandApiError::InvalidReceipt);
    }
    let valid = match receipt.kind {
        CommandResultKind::Success => {
            receipt.success
                && !receipt.timed_out
                && receipt.exit_code == Some(0)
                && !receipt.output.trim().is_empty()
        }
        CommandResultKind::Empty => {
            receipt.success
                && !receipt.timed_out
                && receipt.exit_code == Some(0)
                && receipt.output.trim().is_empty()
        }
        CommandResultKind::NonZero => {
            !receipt.success
                && !receipt.timed_out
                && receipt.exit_code.is_some_and(|code| code != 0)
        }
        CommandResultKind::Timeout => !receipt.success && receipt.timed_out,
        CommandResultKind::MissingCommand | CommandResultKind::PermissionDenied => {
            !receipt.success && !receipt.timed_out
        }
        CommandResultKind::UnknownExit => {
            !receipt.success && !receipt.timed_out && receipt.exit_code.is_none()
        }
    };
    if !valid {
        return Err(EmergencyCommandApiError::InvalidReceipt);
    }
    Ok(())
}

fn project_receipt(
    access: &RunAccess,
    command: &StoredCommand,
    receipt: CommandExecutionReceipt,
) -> Result<(EmergencyCommandResultDto, Vec<u32>), EmergencyCommandApiError> {
    let projected = project_output(&receipt.output, &receipt.finding_lines)?;
    let clipped_lines = projected.clipped_lines;
    Ok((
        EmergencyCommandResultDto {
            snapshot_handle: access.snapshot_handle.clone(),
            command_handle: command.command_handle.clone(),
            result_kind: result_kind(receipt.kind),
            exit_code: receipt.exit_code,
            output: projected.output,
            observed_line_count: projected.observed_line_count,
            displayed_line_count: projected.displayed_line_count,
            finding_lines: projected.finding_lines,
            finding_reason: receipt.finding_reason,
            truncated: receipt.truncated || projected.truncated,
            paths: Vec::new(),
        },
        clipped_lines,
    ))
}

struct ProjectedOutput {
    output: String,
    observed_line_count: u32,
    displayed_line_count: u32,
    finding_lines: Vec<u32>,
    /// Displayed lines that lost their tail to the per-line ceiling. What is
    /// left of such a line is a fragment, and a path read out of a fragment
    /// would name the wrong file.
    clipped_lines: Vec<u32>,
    truncated: bool,
}

fn project_output(
    source: &str,
    findings: &[u32],
) -> Result<ProjectedOutput, EmergencyCommandApiError> {
    if source.len() > MAX_CORE_OUTPUT_BYTES {
        return Err(EmergencyCommandApiError::InvalidReceipt);
    }
    let observed = source.lines().count();
    let observed_line_count =
        u32::try_from(observed).map_err(|_| EmergencyCommandApiError::InvalidReceipt)?;
    let mut lines = Vec::with_capacity(observed.min(MAX_OUTPUT_LINES));
    let mut finding_lines = Vec::new();
    let mut clipped_lines = Vec::new();
    let mut bytes = 0usize;
    let mut truncated = false;
    for (index, line) in source.lines().enumerate() {
        if lines.len() >= MAX_OUTPUT_LINES {
            truncated = true;
            break;
        }
        // Only control characters and the per-line byte ceiling are applied;
        // nothing is substituted for what the target actually printed.
        let (projected, line_truncated) = normalize_plain_line(line, MAX_OUTPUT_LINE_BYTES);
        let separator = usize::from(!lines.is_empty());
        if bytes
            .saturating_add(separator)
            .saturating_add(projected.len())
            > MAX_OUTPUT_BYTES
        {
            truncated = true;
            break;
        }
        bytes = bytes
            .saturating_add(separator)
            .saturating_add(projected.len());
        truncated |= line_truncated;
        if line_truncated && let Ok(displayed) = u32::try_from(lines.len()) {
            clipped_lines.push(displayed);
        }
        // Marks follow the line to its displayed position, and a redacted line
        // keeps none of them because its content is gone.
        if u32::try_from(index).is_ok_and(|index| findings.binary_search(&index).is_ok())
            && let Ok(displayed) = u32::try_from(lines.len())
        {
            finding_lines.push(displayed);
        }
        lines.push(projected);
    }
    truncated |= observed > lines.len();
    Ok(ProjectedOutput {
        output: lines.join("\n"),
        observed_line_count,
        displayed_line_count: u32::try_from(lines.len())
            .map_err(|_| EmergencyCommandApiError::InvalidReceipt)?,
        finding_lines,
        clipped_lines,
        truncated,
    })
}

fn normalize_plain_line(value: &str, maximum_bytes: usize) -> (String, bool) {
    let mut output = String::with_capacity(value.len().min(maximum_bytes));
    let mut truncated = false;
    for character in value.chars() {
        let replacement = if character == '\t' || !character.is_control() {
            character
        } else {
            '\u{fffd}'
        };
        if output.len().saturating_add(replacement.len_utf8()) > maximum_bytes {
            truncated = true;
            break;
        }
        output.push(replacement);
    }
    (output, truncated)
}

fn valid_raw_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// A container's own name and image, cut to fit and stripped of anything that
/// would not draw as one line.
///
/// These come from the target, so they are shown as they are — only control
/// characters and the size ceiling are applied, the same rule the rest of this
/// tool follows for text a machine under investigation produced.
fn bounded_text(value: &str, maximum_bytes: usize) -> String {
    let cleaned = value
        .chars()
        .filter(|character| !character.is_control())
        .collect::<String>();
    let mut end = cleaned.len().min(maximum_bytes);
    while end > 0 && !cleaned.is_char_boundary(end) {
        end -= 1;
    }
    cleaned[..end].to_owned()
}

fn valid_catalog_text(value: &str, maximum_bytes: usize, allow_empty: bool) -> bool {
    value.len() <= maximum_bytes
        && (allow_empty || !value.is_empty())
        && !value.chars().any(char::is_control)
}

fn validate_handle(value: &str) -> Result<(), EmergencyCommandApiError> {
    if value.is_empty()
        || value.len() > MAX_HANDLE_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(EmergencyCommandApiError::InvalidHandle);
    }
    Ok(())
}

fn ensure_serialized_bound<T: Serialize>(
    value: &T,
    maximum_bytes: usize,
) -> Result<(), EmergencyCommandApiError> {
    let bytes = serde_json::to_vec(value).map_err(|_| EmergencyCommandApiError::InvalidReceipt)?;
    if bytes.len() > maximum_bytes {
        return Err(EmergencyCommandApiError::Capacity);
    }
    Ok(())
}

const fn category(value: CommandCategory) -> EmergencyCommandCategory {
    match value {
        CommandCategory::Permissions => EmergencyCommandCategory::Permissions,
        CommandCategory::Accounts => EmergencyCommandCategory::Accounts,
        CommandCategory::Network => EmergencyCommandCategory::Network,
        CommandCategory::Processes => EmergencyCommandCategory::Processes,
        CommandCategory::Persistence => EmergencyCommandCategory::Persistence,
        CommandCategory::Logs => EmergencyCommandCategory::Logs,
        CommandCategory::Files => EmergencyCommandCategory::Files,
        CommandCategory::Containers => EmergencyCommandCategory::Containers,
        CommandCategory::System => EmergencyCommandCategory::System,
    }
}

const fn result_kind(value: CommandResultKind) -> EmergencyCommandResultKind {
    match value {
        CommandResultKind::Success => EmergencyCommandResultKind::Success,
        CommandResultKind::Empty => EmergencyCommandResultKind::Empty,
        CommandResultKind::NonZero => EmergencyCommandResultKind::NonZero,
        CommandResultKind::Timeout => EmergencyCommandResultKind::Timeout,
        CommandResultKind::MissingCommand => EmergencyCommandResultKind::MissingCommand,
        CommandResultKind::PermissionDenied => EmergencyCommandResultKind::PermissionDenied,
        CommandResultKind::UnknownExit => EmergencyCommandResultKind::UnknownExit,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use lovelyres_core::{
        command_workbench::{CommandCatalogEntry, CommandCategory, CommandExecutionReceipt},
        target::{TargetContext, TargetIdentity},
    };

    use super::*;

    fn scope(binding: &str, identity: &str, generation: usize) -> BindingScope {
        let target = TargetContext::new();
        let mut guard = target
            .activate(TargetIdentity::new(identity).unwrap())
            .unwrap();
        for _ in 0..generation {
            guard = target
                .activate(TargetIdentity::new(identity).unwrap())
                .unwrap();
        }
        BindingScope {
            binding_handle: binding.to_owned(),
            session_id: format!("session-{identity}"),
            connection_id: identity.to_owned(),
            target: guard,
        }
    }

    fn entry(id: &'static str, category: CommandCategory) -> CommandCatalogEntry {
        CommandCatalogEntry {
            id,
            category,
            title: "安全目录标题",
            description: "固定只读调查用途",
            command_preview: "shell text must remain core-owned",
            timeout_seconds: 30,
        }
    }

    fn receipt(command: &StoredCommand, output: String) -> CommandExecutionReceipt {
        CommandExecutionReceipt {
            command_id: command.raw_id.clone(),
            title: command.title.clone(),
            finding_lines: Vec::new(),
            finding_reason: None,
            output,
            exit_code: Some(0),
            duration_ms: 5,
            timed_out: false,
            kind: CommandResultKind::Success,
            success: true,
            message: "fixed core message".to_owned(),
            truncated: false,
            history_id: Some("history-private".to_owned()),
            history_warning: Some("private storage detail".to_owned()),
        }
    }

    /// The shipped catalog grew well past the original slice; every bound it
    /// crosses has to hold for the real entries, not just for fixtures.
    /// A sweep of a slow host outlasts a fixed five minutes, and every command
    /// after that point failed — in the window, a category run stopping
    /// half-way through with nothing said about why.
    #[test]
    fn the_catalogue_window_slides_while_it_is_in_use() {
        let source = include_str!("emergency_command_api.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains("catalog.expires_at = now + CATALOG_TTL;"));
        // Renewal happens after the staleness check, never instead of it.
        let check = production
            .find("if &catalog.scope != scope || catalog.expires_at <= now {")
            .unwrap();
        let renew = production
            .find("catalog.expires_at = now + CATALOG_TTL;")
            .unwrap();
        assert!(check < renew);
        // The binding is still validated on every run; the window is not what
        // protects against the target changing underneath.
        assert!(production.contains("self.validate_binding(&scope)"));
    }

    /// A host under investigation is often a host under load. Losing the whole
    /// catalogue because the one-line os-release probe was slow leaves the
    /// operator with nothing exactly when they need something.
    #[test]
    fn a_slow_probe_falls_back_to_the_portable_catalogue() {
        let source = include_str!("emergency_command_api.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains("Ok(Err(error)) => {"));
        assert!(production.contains("Err(_) => {"));
        // Three fallbacks, all landing on the portable set rather than an
        // error: the host probe's two arms, and the container probe, which is
        // asked the same question inside a container and can be just as slow.
        assert_eq!(production.matches("SystemFamily::Other").count(), 3);
        assert!(production.contains("falling back to the portable command set"));
        // A target with no container runtime, or one whose runtime will not
        // answer, still gets its catalogue — it just has nothing to point it at.
        assert!(production.contains("no containers will be offered"));
        // Every family, including the portable one, still builds a catalogue
        // that fits the boundary.
        let entries = lovelyres_core::command_workbench::shipped_catalog();
        let (_, dto) = build_catalog(
            scope("binding", "identity", 0),
            SystemFamily::Other,
            entries,
            Vec::new(),
            Vec::new(),
            Instant::now(),
        )
        .unwrap();
        assert!(dto.commands.len() >= 140);
    }

    #[test]
    fn shipped_catalog_fits_every_boundary_limit() {
        for family in [
            SystemFamily::Debian,
            SystemFamily::RedHat,
            SystemFamily::Alpine,
            SystemFamily::Other,
        ] {
            let entries = lovelyres_core::command_workbench::shipped_catalog();
            assert!(entries.len() >= 140, "{} entries", entries.len());
            let (stored, dto) = build_catalog(
                scope("binding", "identity", 0),
                family,
                entries,
                Vec::new(),
                Vec::new(),
                Instant::now(),
            )
            .expect("the shipped catalog must cross the boundary");
            assert!(stored.stored_bytes <= MAX_CATALOG_BYTES);
            assert!(stored.stored_bytes <= MAX_REGISTRY_BYTES / MAX_CATALOGS);
            let encoded = serde_json::to_string(&dto).unwrap();
            assert!(
                encoded.len() <= MAX_CATALOG_RESPONSE_BYTES,
                "{} bytes",
                encoded.len()
            );
            for command in &stored.commands {
                // The core has to be able to finish and report on its own.
                assert!(
                    Duration::from_secs(command.timeout_seconds) < EXECUTION_DEADLINE,
                    "{} would be cut off by the run deadline",
                    command.raw_id
                );
            }
        }
    }

    #[test]
    fn catalog_maps_raw_ids_and_family_to_opaque_scoped_handles() {
        let private_scope = scope("binding-secret", "target-secret", 0);
        let (stored, dto) = build_catalog(
            private_scope,
            SystemFamily::Debian,
            vec![
                entry("network-listen", CommandCategory::Network),
                entry("system-kernel", CommandCategory::System),
            ],
            Vec::new(),
            Vec::new(),
            Instant::now(),
        )
        .unwrap();
        assert_eq!(dto.expires_in_seconds, 300);
        assert_eq!(dto.commands.len(), 2);
        assert_eq!(stored.commands[0].raw_id, "network-listen");
        assert_eq!(stored.family, SystemFamily::Debian);
        assert_ne!(dto.commands[0].command_handle, "network-listen");
        assert_eq!(
            dto.commands
                .iter()
                .map(|command| command.command_handle.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            2
        );
        let encoded = serde_json::to_string(&dto).unwrap();
        for forbidden in [
            "network-listen",
            "system-kernel",
            "shell text must remain core-owned",
            "Debian",
            "debian",
            "binding-secret",
            "target-secret",
            "session-",
            "generation",
            "family",
            "commandPreview",
        ] {
            assert!(!encoded.contains(forbidden), "encoded {forbidden}");
        }
        assert!(encoded.contains("安全目录标题"));
        assert!(encoded.len() <= MAX_CATALOG_RESPONSE_BYTES);
    }

    #[test]
    fn registry_is_ttl_refresh_memory_and_concurrency_bounded() {
        let now = Instant::now();
        let first_scope = scope("binding-one", "target-one", 0);
        let (first, _) = build_catalog(
            first_scope.clone(),
            SystemFamily::Other,
            vec![entry("network-listen", CommandCategory::Network)],
            Vec::new(),
            Vec::new(),
            now,
        )
        .unwrap();
        let first_handle = first.snapshot_handle.clone();
        let first_token = first.token;
        let command_handle = first.commands[0].command_handle.clone();
        let mut registry = EmergencyRegistry::default();
        registry.begin_load(&first_scope).unwrap();
        assert!(matches!(
            registry.begin_load(&first_scope),
            Err(EmergencyCommandApiError::Busy)
        ));
        registry.finish_load(&first_scope.binding_handle);
        registry.replace(first).unwrap();
        let (access, command, _) = registry
            .begin_run(&first_scope, &first_handle, &command_handle)
            .unwrap();
        assert!(matches!(
            registry.begin_run(&first_scope, &first_handle, &command_handle),
            Err(EmergencyCommandApiError::Busy)
        ));
        registry.verify_run(&access, &command).unwrap();

        let (refresh, _) = build_catalog(
            first_scope.clone(),
            SystemFamily::Other,
            vec![entry("network-listen", CommandCategory::Network)],
            Vec::new(),
            Vec::new(),
            now + Duration::from_millis(1),
        )
        .unwrap();
        registry.replace(refresh).unwrap();
        assert!(matches!(
            registry.verify_run(&access, &command),
            Err(EmergencyCommandApiError::CatalogStale)
        ));
        registry.finish_run(access.run_token);
        assert!(!registry.catalogs.contains_key(&first_handle));
        assert_ne!(
            registry.catalogs.values().next().unwrap().token,
            first_token
        );

        registry.catalogs.clear();
        for index in 0..MAX_CATALOGS + 1 {
            let binding = format!("binding-{index}");
            let identity = format!("target-{index}");
            let (catalog, _) = build_catalog(
                scope(&binding, &identity, 0),
                SystemFamily::Other,
                vec![entry("network-listen", CommandCategory::Network)],
                Vec::new(),
                Vec::new(),
                now + Duration::from_millis(index as u64),
            )
            .unwrap();
            registry.replace(catalog).unwrap();
        }
        assert_eq!(registry.catalogs.len(), MAX_CATALOGS);
        assert!(registry.total_bytes() <= MAX_REGISTRY_BYTES);
        for catalog in registry.catalogs.values_mut() {
            catalog.expires_at = now;
        }
        registry.prune(now);
        assert!(registry.catalogs.is_empty());
    }

    #[test]
    fn concurrency_is_bounded_globally_and_per_binding() {
        let load_scopes = (0..MAX_ACTIVE_LOADS + 1)
            .map(|index| scope(&format!("load-{index}"), &format!("target-load-{index}"), 0))
            .collect::<Vec<_>>();
        let mut registry = EmergencyRegistry::default();
        for load_scope in load_scopes.iter().take(MAX_ACTIVE_LOADS) {
            registry.begin_load(load_scope).unwrap();
        }
        assert!(matches!(
            registry.begin_load(&load_scopes[MAX_ACTIVE_LOADS]),
            Err(EmergencyCommandApiError::Busy)
        ));
        assert!(matches!(
            registry.begin_load(&load_scopes[0]),
            Err(EmergencyCommandApiError::Busy)
        ));
        for load_scope in &load_scopes {
            registry.finish_load(&load_scope.binding_handle);
        }

        let now = Instant::now();
        let mut runs = Vec::new();
        for index in 0..MAX_ACTIVE_RUNS + 1 {
            let run_scope = scope(&format!("run-{index}"), &format!("target-run-{index}"), 0);
            let (catalog, _) = build_catalog(
                run_scope.clone(),
                SystemFamily::Other,
                vec![entry("network-listen", CommandCategory::Network)],
                Vec::new(),
                Vec::new(),
                now,
            )
            .unwrap();
            let snapshot_handle = catalog.snapshot_handle.clone();
            let command_handle = catalog.commands[0].command_handle.clone();
            registry.replace(catalog).unwrap();
            runs.push((run_scope, snapshot_handle, command_handle));
        }
        let active = runs
            .iter()
            .take(MAX_ACTIVE_RUNS)
            .map(|(run_scope, snapshot_handle, command_handle)| {
                registry
                    .begin_run(run_scope, snapshot_handle, command_handle)
                    .unwrap()
                    .0
            })
            .collect::<Vec<_>>();
        let (extra_scope, extra_snapshot, extra_command) = &runs[MAX_ACTIVE_RUNS];
        assert!(matches!(
            registry.begin_run(extra_scope, extra_snapshot, extra_command),
            Err(EmergencyCommandApiError::Busy)
        ));
        let (first_scope, first_snapshot, first_command) = &runs[0];
        assert!(matches!(
            registry.begin_run(first_scope, first_snapshot, first_command),
            Err(EmergencyCommandApiError::Busy)
        ));
        for access in active {
            registry.finish_run(access.run_token);
        }
    }

    #[test]
    fn close_binding_removes_only_its_catalogs_loads_and_active_runs() {
        let now = Instant::now();
        let closed = scope("binding-closed", "target-closed", 0);
        let mut stale = closed.clone();
        stale.session_id = "session-closed-stale".to_owned();
        stale.target.generation += 1;
        let kept = scope("binding-kept", "target-kept", 0);
        let (closed_catalog, _) = build_catalog(
            closed.clone(),
            SystemFamily::Other,
            vec![entry("network-listen", CommandCategory::Network)],
            Vec::new(),
            Vec::new(),
            now,
        )
        .unwrap();
        let closed_handle = closed_catalog.snapshot_handle.clone();
        let closed_token = closed_catalog.token;
        let closed_command_handle = closed_catalog.commands[0].command_handle.clone();
        let (stale_catalog, _) = build_catalog(
            stale,
            SystemFamily::Other,
            vec![entry("system-kernel", CommandCategory::System)],
            Vec::new(),
            Vec::new(),
            now,
        )
        .unwrap();
        let stale_handle = stale_catalog.snapshot_handle.clone();
        let (kept_catalog, _) = build_catalog(
            kept.clone(),
            SystemFamily::Other,
            vec![entry("network-listen", CommandCategory::Network)],
            Vec::new(),
            Vec::new(),
            now,
        )
        .unwrap();
        let kept_handle = kept_catalog.snapshot_handle.clone();
        let kept_bytes = kept_catalog.stored_bytes;

        let mut registry = EmergencyRegistry::default();
        registry.replace(closed_catalog).unwrap();
        registry
            .catalogs
            .insert(stale_handle.clone(), stale_catalog);
        registry.replace(kept_catalog).unwrap();
        let (late_access, late_command, _) = registry
            .begin_run(&closed, &closed_handle, &closed_command_handle)
            .unwrap();
        registry.begin_load(&kept).unwrap();

        registry.close_binding(&closed.binding_handle);

        assert!(!registry.catalogs.contains_key(&closed_handle));
        assert!(!registry.catalogs.contains_key(&stale_handle));
        assert!(registry.catalogs.contains_key(&kept_handle));
        assert_eq!(registry.total_bytes(), kept_bytes);
        assert!(!registry.active_runs.contains_key(&late_access.run_token));
        assert!(registry.active_load_bindings.contains(&kept.binding_handle));
        assert!(matches!(
            registry.verify_catalog(&closed, &closed_handle, closed_token),
            Err(EmergencyCommandApiError::CatalogStale)
        ));
        assert!(matches!(
            registry.verify_run(&late_access, &late_command),
            Err(EmergencyCommandApiError::CatalogStale)
        ));

        registry.finish_load(&kept.binding_handle);
        registry.begin_load(&closed).unwrap();
        registry.close_binding(&closed.binding_handle);
        assert!(
            !registry
                .active_load_bindings
                .contains(&closed.binding_handle)
        );
    }

    #[test]
    fn exact_scope_generation_and_command_membership_fail_closed() {
        let now = Instant::now();
        let original = scope("binding-one", "target-one", 0);
        let (catalog, _) = build_catalog(
            original.clone(),
            SystemFamily::RedHat,
            vec![entry("network-listen", CommandCategory::Network)],
            Vec::new(),
            Vec::new(),
            now,
        )
        .unwrap();
        let snapshot_handle = catalog.snapshot_handle.clone();
        let command_handle = catalog.commands[0].command_handle.clone();
        let mut registry = EmergencyRegistry::default();
        registry.replace(catalog).unwrap();
        let mut changed_binding = original.clone();
        changed_binding.binding_handle = "binding-reused".to_owned();
        let mut changed_session = original.clone();
        changed_session.session_id = "session-reused".to_owned();
        let mut changed_connection = original.clone();
        changed_connection.connection_id = "connection-reused".to_owned();
        let mut changed_identity = original.clone();
        changed_identity.target.identity = TargetIdentity::new("target-two").unwrap();
        let changed_generation = scope("binding-one", "target-one", 1);
        for changed in [
            changed_binding,
            changed_session,
            changed_connection,
            changed_identity,
            changed_generation,
        ] {
            assert!(matches!(
                registry.begin_run(&changed, &snapshot_handle, &command_handle),
                Err(EmergencyCommandApiError::CatalogStale)
            ));
        }
        assert!(matches!(
            registry.begin_run(&original, &snapshot_handle, "unknown-command-handle"),
            Err(EmergencyCommandApiError::CatalogStale)
        ));
        assert!(matches!(
            registry.begin_run(&original, "unknown-snapshot", &command_handle),
            Err(EmergencyCommandApiError::CatalogStale)
        ));
    }

    #[test]
    fn output_crosses_verbatim_within_line_byte_and_control_bounds() {
        let private_scope = scope("binding-private", "target-private", 0);
        let (catalog, _) = build_catalog(
            private_scope.clone(),
            SystemFamily::Alpine,
            vec![entry("network-listen", CommandCategory::Network)],
            Vec::new(),
            Vec::new(),
            Instant::now(),
        )
        .unwrap();
        let command = catalog.commands[0].clone();
        let access = RunAccess {
            snapshot_handle: catalog.snapshot_handle,
            snapshot_token: catalog.token,
            command_handle: command.command_handle.clone(),
            run_token: Uuid::new_v4(),
            scope: private_scope,
        };
        let hostile = [
            "</pre><script>steal()</script><img src=x onerror=steal()>",
            "root:$6$salt$hash:19000:0:99999:7:::",
            "Failed password for invalid user admin from 10.0.0.9",
            "plain\u{0007}control",
            &"x".repeat(MAX_OUTPUT_LINE_BYTES + 20),
        ]
        .join("\n");
        let (dto, clipped) =
            project_receipt(&access, &command, receipt(&command, hostile)).unwrap();
        // Markup is inert text, never markup; the rest reaches the operator
        // exactly as the target printed it.
        assert!(dto.output.contains("</pre><script>steal()</script>"));
        assert!(dto.output.contains("root:$6$salt$hash:19000:0:99999:7:::"));
        assert!(
            dto.output
                .contains("Failed password for invalid user admin")
        );
        // Only control characters are normalised, because they break rendering.
        assert!(dto.output.contains("plain\u{fffd}control"));
        assert!(dto.truncated);
        assert!(dto.displayed_line_count <= MAX_OUTPUT_LINES as u32);
        assert!(dto.output.len() <= MAX_OUTPUT_BYTES);
        assert!(
            dto.output
                .lines()
                .all(|line| line.len() <= MAX_OUTPUT_LINE_BYTES)
        );
        // A line that lost its tail is named, so no action is offered on the
        // fragment that is left of it.
        assert_eq!(clipped, vec![4]);
        let encoded = serde_json::to_string(&dto).unwrap();
        for forbidden in [
            "network-listen",
            "history-private",
            "private storage detail",
            "target-private",
        ] {
            assert!(!encoded.contains(forbidden), "encoded {forbidden}");
        }
        assert!(encoded.len() <= MAX_RUN_RESPONSE_BYTES);
    }

    #[test]
    fn abnormal_marks_follow_their_line_through_truncation() {
        let source = [
            "/usr/bin/passwd",
            "/usr/bin/find",
            "/tmp/.hidden/bash",
            "/home/ctf/rootshell",
        ]
        .join("\n");
        let projected = project_output(&source, &[1, 2, 3]).unwrap();
        assert_eq!(projected.finding_lines, vec![1, 2, 3]);

        // Marks past the display cap are dropped with their lines.
        let long = (0..MAX_OUTPUT_LINES + 10)
            .map(|index| format!("/tmp/planted-{index}"))
            .collect::<Vec<_>>()
            .join("\n");
        let marks = (0..MAX_OUTPUT_LINES as u32 + 10).collect::<Vec<_>>();
        let projected = project_output(&long, &marks).unwrap();
        assert_eq!(projected.finding_lines.len(), MAX_OUTPUT_LINES);
        assert_eq!(
            projected.finding_lines.last().copied(),
            Some(MAX_OUTPUT_LINES as u32 - 1)
        );

        // A receipt whose marks are unordered or point past the output is a
        // broken receipt, not a display problem.
        let command = StoredCommand {
            command_handle: "opaque-command".to_owned(),
            raw_id: "perm-suid".to_owned(),
            category: EmergencyCommandCategory::Permissions,
            title: "SUID 可执行".to_owned(),
            description: "只读".to_owned(),
            timeout_seconds: 30,
        };
        let base = receipt(&command, "/tmp/one\n/tmp/two".to_owned());
        for broken in [vec![1, 1], vec![1, 0], vec![2]] {
            let mut invalid = base.clone();
            invalid.finding_lines = broken.clone();
            assert!(
                validate_receipt(&command, &invalid).is_err(),
                "{broken:?} must be refused"
            );
        }
        let mut valid = base.clone();
        valid.finding_lines = vec![0, 1];
        assert!(validate_receipt(&command, &valid).is_ok());
    }

    #[test]
    fn many_short_lines_and_serialized_escaping_stay_bounded() {
        let output = (0..MAX_OUTPUT_LINES + 200)
            .map(|index| format!("<line-{index}>\\\""))
            .collect::<Vec<_>>()
            .join("\n");
        let projected = project_output(&output, &[]).unwrap();
        assert_eq!(projected.displayed_line_count, MAX_OUTPUT_LINES as u32);
        assert!(projected.truncated);
        assert!(projected.output.len() <= MAX_OUTPUT_BYTES);
        let command = StoredCommand {
            command_handle: "opaque-command".to_owned(),
            raw_id: "network-listen".to_owned(),
            category: EmergencyCommandCategory::Network,
            title: "监听端口".to_owned(),
            description: "只读".to_owned(),
            timeout_seconds: 30,
        };
        let access = RunAccess {
            snapshot_handle: "opaque-snapshot".to_owned(),
            snapshot_token: Uuid::new_v4(),
            command_handle: command.command_handle.clone(),
            run_token: Uuid::new_v4(),
            scope: scope("binding-one", "target-one", 0),
        };
        let dto = project_receipt(&access, &command, receipt(&command, output)).unwrap();
        ensure_serialized_bound(&dto, MAX_RUN_RESPONSE_BYTES).unwrap();
    }

    #[test]
    fn catalog_and_receipt_validation_reject_ambiguous_core_data() {
        assert!(matches!(
            build_catalog(
                scope("binding-one", "target-one", 0),
                SystemFamily::Other,
                vec![entry("network-listen", CommandCategory::Network); MAX_CATALOG_COMMANDS + 1],
                Vec::new(),
                Vec::new(),
                Instant::now(),
            ),
            Err(EmergencyCommandApiError::Capacity)
        ));
        assert!(
            build_catalog(
                scope("binding-one", "target-one", 0),
                SystemFamily::Other,
                vec![
                    entry("network-listen", CommandCategory::Network),
                    entry("network-listen", CommandCategory::Network),
                ],
                Vec::new(),
                Vec::new(),
                Instant::now(),
            )
            .is_err()
        );
        assert!(
            build_catalog(
                scope("binding-one", "target-one", 0),
                SystemFamily::Other,
                vec![entry("network-listen;id", CommandCategory::Network)],
                Vec::new(),
                Vec::new(),
                Instant::now(),
            )
            .is_err()
        );
        let mut oversized_title = entry("network-listen", CommandCategory::Network);
        oversized_title.title = Box::leak("x".repeat(MAX_TITLE_BYTES + 1).into_boxed_str());
        assert!(matches!(
            build_catalog(
                scope("binding-one", "target-one", 0),
                SystemFamily::Other,
                vec![oversized_title],
                Vec::new(),
                Vec::new(),
                Instant::now(),
            ),
            Err(EmergencyCommandApiError::InvalidCatalog)
        ));
        let mut oversized_description = entry("network-listen", CommandCategory::Network);
        oversized_description.description =
            Box::leak("x".repeat(MAX_DESCRIPTION_BYTES + 1).into_boxed_str());
        assert!(matches!(
            build_catalog(
                scope("binding-one", "target-one", 0),
                SystemFamily::Other,
                vec![oversized_description],
                Vec::new(),
                Vec::new(),
                Instant::now(),
            ),
            Err(EmergencyCommandApiError::InvalidCatalog)
        ));

        let (mut oversized_catalog, _) = build_catalog(
            scope("binding-one", "target-one", 0),
            SystemFamily::Other,
            vec![entry("network-listen", CommandCategory::Network)],
            Vec::new(),
            Vec::new(),
            Instant::now(),
        )
        .unwrap();
        oversized_catalog.stored_bytes = MAX_CATALOG_BYTES + 1;
        assert!(matches!(
            EmergencyRegistry::default().replace(oversized_catalog),
            Err(EmergencyCommandApiError::Capacity)
        ));

        let (_, catalog_dto) = build_catalog(
            scope("binding-one", "target-one", 0),
            SystemFamily::Other,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Instant::now(),
        )
        .unwrap();
        assert!(catalog_dto.commands.is_empty());

        let command = StoredCommand {
            command_handle: "opaque-command".to_owned(),
            raw_id: "network-listen".to_owned(),
            category: EmergencyCommandCategory::Network,
            title: "监听端口".to_owned(),
            description: "只读".to_owned(),
            timeout_seconds: 30,
        };
        let mut invalid = receipt(&command, "plain".to_owned());
        invalid.command_id = "different-private-id".to_owned();
        assert!(matches!(
            validate_receipt(&command, &invalid),
            Err(EmergencyCommandApiError::InvalidReceipt)
        ));
        invalid.command_id = command.raw_id.clone();
        invalid.success = false;
        assert!(validate_receipt(&command, &invalid).is_err());
    }

    #[test]
    fn handles_and_public_errors_are_fixed_and_redacted() {
        for invalid in [
            "",
            "space value",
            "slash/value",
            "control\n",
            &"x".repeat(129),
        ] {
            assert!(validate_handle(invalid).is_err());
        }
        assert!(validate_handle("opaque-123-ABC").is_ok());
        let error = EmergencyCommandApiError::Core;
        assert_eq!(error.to_string(), "the emergency command operation failed");
        assert!(!format!("{error:?}").contains("secret"));
    }

    #[test]
    fn production_source_calls_only_the_closed_core_methods() {
        let source = include_str!("emergency_command_api.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains("commands().catalog()"));
        assert!(production.contains("commands().detect_system(&session)"));
        assert!(production.contains(".execute(&session, &command.raw_id, family)"));
        // Running a check inside a container adds two, and only two: ask the
        // container which family it is, and run one catalogue command in it.
        // Neither takes a command string from anywhere but the catalogue.
        assert!(production.contains("detect_container_system(session, identity)"));
        assert!(production.contains("execute_in_container("));
        // And two more for a pod, which is the same two questions asked
        // through kubectl instead of through the container runtime.
        assert!(production.contains("detect_pod_system(session, pod)"));
        assert!(production.contains("execute_in_pod("));
        // Listing what may be pointed at is a read, and it detects the runtime
        // rather than assuming Docker.
        assert!(production.contains("docker().detect_runtime(session)"));
        assert!(production.contains("docker().list(session, runtime)"));
        // Kubernetes is checked before it is listed, so a machine without
        // kubectl costs one fast probe rather than a listing that times out.
        assert!(production.contains("kubernetes().availability(session)"));
        assert!(production.contains("kubernetes()"));
        // Still no way to run a command of the caller's choosing anywhere.
        for forbidden in [
            ["kubectl_", "exec"].concat(),
            ["run_", "in_pod_command"].concat(),
        ] {
            assert!(
                !production.contains(&forbidden),
                "production contains {forbidden}"
            );
        }
        for forbidden in [
            ["execute_", "bound"].concat(),
            ["execute_", "raw"].concat(),
            ["custom_", "command"].concat(),
            ["command_", "preview"].concat(),
            ["open_", "terminal"].concat(),
            ["open_", "file"].concat(),
            ["export_", "command"].concat(),
            ["mutation_", "plan"].concat(),
            "DangerousConfirmation".to_owned(),
        ] {
            assert!(
                !production.contains(&forbidden),
                "production contains {forbidden}"
            );
        }
    }
}
