//! Java hot update for the desktop: find the JVMs on the bound host, open one of
//! the JARs they run, and replace a single class inside it through an immutable
//! plan, an explicit confirmation, a verified write and a restorable record.
//!
//! The page never names a path, a process or a command. A JAR is reached only by
//! a handle this module made for an absolute `.jar` path it read on a JVM's own
//! command line; a class entry must be one the inspection of that JAR listed;
//! the replacement class is a file the host's open dialog picked, copied into
//! core's staging area before the page hears about it. Everything is bound to
//! the binding it was made for and expires.

use std::{
    collections::{BTreeSet, HashMap},
    fmt,
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use lovelyhawk_core::{
    BackendServices, CoreError,
    java::{
        JarEntryPath, JavaJarUpdatePlan, JavaRestorePlan, JavaTool, JavaUpdateRecord,
        JavaUpdateState, StagedClassArtifact,
    },
    operations::DangerousConfirmation,
    sftp::RemotePath,
    ssh::BoundSshSession,
    target::TargetGuard,
};
use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use uuid::Uuid;

use crate::ssh_api::SshApi;

const SNAPSHOT_TTL: Duration = Duration::from_secs(10 * 60);
const PLAN_TTL: Duration = Duration::from_secs(10 * 60);
const SCAN_DEADLINE: Duration = Duration::from_secs(150);
const INSPECT_DEADLINE: Duration = Duration::from_secs(150);
const PLAN_DEADLINE: Duration = Duration::from_secs(150);
const EXECUTE_DEADLINE: Duration = Duration::from_secs(300);
const MAX_HANDLE_BYTES: usize = 128;
const MAX_JARS: usize = 512;
const MAX_TYPED_JARS: usize = 16;
const MAX_STAGED: usize = 4;
const MAX_PLANS: usize = 4;
const MAX_COMMAND_BYTES: usize = 512;
const MAX_NAME_CHARS: usize = 255;
const MAX_DETAIL_BYTES: usize = 2 * 1024;
const MAX_HISTORY_ROWS: usize = 64;

/// One request from the page. Tagged by action so the page has one method,
/// and each action carries exactly the handles it needs.
#[derive(Deserialize)]
#[serde(
    tag = "action",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum JavaHotUpdateRequest {
    Scan {
        binding_handle: String,
    },
    Inspect {
        binding_handle: String,
        snapshot_handle: String,
        jar_handle: String,
    },
    /// A JAR the scan did not find (an application server may have closed
    /// it), typed by the operator as an absolute path ending in `.jar`. It is
    /// only read here; core again refuses a symlink or anything not a file.
    InspectPath {
        binding_handle: String,
        snapshot_handle: String,
        path: String,
    },
    Plan {
        binding_handle: String,
        snapshot_handle: String,
        jar_handle: String,
        entry: String,
        staged_handle: String,
    },
    History {
        binding_handle: String,
    },
    PlanRestore {
        binding_handle: String,
        record_id: String,
    },
    Confirm {
        binding_handle: String,
        plan_handle: String,
    },
    Execute {
        binding_handle: String,
        plan_handle: String,
    },
    Cancel {
        binding_handle: String,
        plan_handle: String,
    },
    DiscardStaged {
        binding_handle: String,
        staged_handle: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum JavaHotUpdateError {
    Invalid,
    BindingUnavailable,
    Stale,
    Capacity,
    NotConfirmed,
    ToolMissing,
    /// The login has no home folder of its own to keep the original JAR in.
    NoBackupFolder,
    Deadline,
    Core,
}

impl fmt::Display for JavaHotUpdateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Invalid => "the Java hot update request is invalid",
            Self::BindingUnavailable => "the SSH binding is missing or stale",
            Self::Stale => "the JVM list, JAR, staged class or plan is no longer current",
            Self::Capacity => "too many Java hot update items are pending",
            Self::NotConfirmed => "the plan has not been confirmed",
            Self::ToolMissing => "the target has no jar tool",
            Self::NoBackupFolder => "the login has no home folder to keep the original JAR in",
            Self::Deadline => "the Java operation did not finish in time",
            Self::Core => "the Java operation failed",
        })
    }
}

impl std::error::Error for JavaHotUpdateError {}

#[derive(Clone, PartialEq, Eq)]
struct Scope {
    binding_handle: String,
    session_id: String,
    connection_id: String,
    target: TargetGuard,
}

impl Scope {
    fn from_session(binding_handle: &str, session: &BoundSshSession) -> Self {
        Self {
            binding_handle: binding_handle.to_owned(),
            session_id: session.session_id().to_owned(),
            connection_id: session.connection_id().to_owned(),
            target: session.target().clone(),
        }
    }
}

struct Snapshot {
    scope: Scope,
    jars: HashMap<String, RemotePath>,
    /// Class entries an inspection listed, per JAR handle: a plan may only
    /// name one of these. The JAR's own hash is read again by the plan.
    inspected: HashMap<String, BTreeSet<String>>,
    /// Whether the scan found the `jar` tool: a JRE without it can run Java
    /// but cannot list or rebuild an archive.
    jar_tool: bool,
    expires_at: Instant,
}

impl Snapshot {
    fn jar(&self, jar_handle: &str) -> Result<RemotePath, JavaHotUpdateError> {
        let path = self
            .jars
            .get(jar_handle)
            .cloned()
            .ok_or(JavaHotUpdateError::Stale)?;
        if !self.jar_tool {
            return Err(JavaHotUpdateError::ToolMissing);
        }
        Ok(path)
    }
}

struct Staged {
    scope: Scope,
    artifact: StagedClassArtifact,
    expires_at: Instant,
}

enum PlanKind {
    Update(Box<JavaJarUpdatePlan>),
    Restore(Box<JavaRestorePlan>),
}

struct StoredPlan {
    scope: Scope,
    kind: PlanKind,
    dto: JavaPlanDto,
    confirmed: bool,
    expires_at: Instant,
}

#[derive(Default)]
struct Registry {
    snapshots: HashMap<String, Snapshot>,
    staged: HashMap<String, Staged>,
    plans: HashMap<String, StoredPlan>,
}

impl Registry {
    fn prune(&mut self, now: Instant) {
        self.snapshots
            .retain(|_, snapshot| snapshot.expires_at > now);
        self.staged.retain(|_, staged| staged.expires_at > now);
        self.plans.retain(|_, plan| plan.expires_at > now);
    }

    fn close_binding(&mut self, binding_handle: &str) {
        self.snapshots
            .retain(|_, snapshot| snapshot.scope.binding_handle != binding_handle);
        self.staged
            .retain(|_, staged| staged.scope.binding_handle != binding_handle);
        self.plans
            .retain(|_, plan| plan.scope.binding_handle != binding_handle);
    }

    fn snapshot(
        &mut self,
        scope: &Scope,
        handle: &str,
    ) -> Result<&mut Snapshot, JavaHotUpdateError> {
        self.snapshots
            .get_mut(handle)
            .filter(|snapshot| &snapshot.scope == scope)
            .ok_or(JavaHotUpdateError::Stale)
    }
}

#[derive(Clone)]
pub(crate) struct JavaHotUpdateApi {
    services: BackendServices,
    ssh_api: Arc<SshApi>,
    registry: Arc<Mutex<Registry>>,
}

impl fmt::Debug for JavaHotUpdateApi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (snapshots, staged, plans) = self
            .registry
            .lock()
            .map(|registry| {
                (
                    registry.snapshots.len(),
                    registry.staged.len(),
                    registry.plans.len(),
                )
            })
            .unwrap_or_default();
        formatter
            .debug_struct("JavaHotUpdateApi")
            .field("snapshots", &snapshots)
            .field("staged", &staged)
            .field("plans", &plans)
            .finish()
    }
}

// ---------------------------------------------------------------- DTOs

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct JavaScanDto {
    snapshot_handle: String,
    version: Option<String>,
    tools: Vec<JavaToolDto>,
    processes: Vec<JavaProcessDto>,
    jars: Vec<JavaJarOfferDto>,
    /// More JARs were found than are offered.
    jars_truncated: bool,
    expires_in_seconds: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct JavaToolDto {
    tool: &'static str,
    available: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct JavaProcessDto {
    pid: u32,
    user: String,
    cpu_percent: f32,
    memory_percent: f32,
    elapsed_seconds: u64,
    /// The command line as `ps` showed it, cut at 512 bytes by the collector.
    command: String,
    command_truncated: bool,
    /// Whether this login could read the process's open files.
    open_files_readable: bool,
    /// Some open JARs are not listed (too many, or unusable names).
    open_jars_incomplete: bool,
    jar_handles: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct JavaJarOfferDto {
    jar_handle: String,
    path: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct JavaJarDto {
    jar_handle: String,
    path: String,
    size_bytes: u64,
    sha256: String,
    class_count: usize,
    classes: Vec<String>,
    truncated: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct JavaStagedClassDto {
    staged_handle: String,
    name: String,
    size_bytes: u64,
    sha256: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct JavaPlanDto {
    plan_handle: String,
    operation: &'static str,
    summary: String,
    jar_path: String,
    entry: String,
    /// The class file going in (update), or the class the record had put in (restore).
    class_sha256: String,
    restore_description: Option<String>,
    confirmed: bool,
    expires_in_seconds: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct JavaReceiptDto {
    plan_handle: String,
    operation: &'static str,
    verified: bool,
    record_id: Option<String>,
    jar_path: String,
    entry: String,
    jar_sha256: Option<String>,
    detail: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct JavaRecordDto {
    record_id: String,
    jar_path: String,
    entry: String,
    state: &'static str,
    before_jar_sha256: String,
    applied_jar_sha256: String,
    class_sha256: String,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct JavaHistoryDto {
    records: Vec<JavaRecordDto>,
    truncated: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct JavaCancelledDto {
    cancelled: bool,
}

/// One response per request kind, tagged so the page checks it against the
/// request it sent.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub(crate) enum JavaHotUpdateResponse {
    Scan(JavaScanDto),
    Jar(JavaJarDto),
    Plan(JavaPlanDto),
    Receipt(JavaReceiptDto),
    History(JavaHistoryDto),
    Cancelled(JavaCancelledDto),
}

impl JavaHotUpdateApi {
    pub(crate) fn new(services: BackendServices, ssh_api: Arc<SshApi>) -> Self {
        Self {
            services,
            ssh_api,
            registry: Arc::new(Mutex::new(Registry::default())),
        }
    }

    pub(crate) fn close_binding(&self, binding_handle: &str) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.close_binding(binding_handle);
        }
    }

    pub(crate) async fn dispatch(
        &self,
        request: JavaHotUpdateRequest,
    ) -> Result<JavaHotUpdateResponse, JavaHotUpdateError> {
        match request {
            JavaHotUpdateRequest::Scan { binding_handle } => self
                .scan(&binding_handle)
                .await
                .map(JavaHotUpdateResponse::Scan),
            JavaHotUpdateRequest::Inspect {
                binding_handle,
                snapshot_handle,
                jar_handle,
            } => self
                .inspect(&binding_handle, &snapshot_handle, &jar_handle)
                .await
                .map(JavaHotUpdateResponse::Jar),
            JavaHotUpdateRequest::InspectPath {
                binding_handle,
                snapshot_handle,
                path,
            } => self
                .inspect_path(&binding_handle, &snapshot_handle, &path)
                .await
                .map(JavaHotUpdateResponse::Jar),
            JavaHotUpdateRequest::Plan {
                binding_handle,
                snapshot_handle,
                jar_handle,
                entry,
                staged_handle,
            } => self
                .plan_update(
                    &binding_handle,
                    &snapshot_handle,
                    &jar_handle,
                    &entry,
                    &staged_handle,
                )
                .await
                .map(JavaHotUpdateResponse::Plan),
            JavaHotUpdateRequest::History { binding_handle } => self
                .history(&binding_handle)
                .map(JavaHotUpdateResponse::History),
            JavaHotUpdateRequest::PlanRestore {
                binding_handle,
                record_id,
            } => self
                .plan_restore(&binding_handle, &record_id)
                .map(JavaHotUpdateResponse::Plan),
            JavaHotUpdateRequest::Confirm {
                binding_handle,
                plan_handle,
            } => self
                .confirm(&binding_handle, &plan_handle)
                .map(JavaHotUpdateResponse::Plan),
            JavaHotUpdateRequest::Execute {
                binding_handle,
                plan_handle,
            } => self
                .execute(&binding_handle, &plan_handle)
                .await
                .map(JavaHotUpdateResponse::Receipt),
            JavaHotUpdateRequest::Cancel {
                binding_handle,
                plan_handle,
            } => self
                .cancel(&binding_handle, &plan_handle)
                .map(JavaHotUpdateResponse::Cancelled),
            JavaHotUpdateRequest::DiscardStaged {
                binding_handle,
                staged_handle,
            } => self
                .discard_staged(&binding_handle, &staged_handle)
                .map(JavaHotUpdateResponse::Cancelled),
        }
    }

    /// Lists the JVMs on the host and the JAR files their command lines name
    /// or they hold open.
    async fn scan(&self, binding_handle: &str) -> Result<JavaScanDto, JavaHotUpdateError> {
        let (session, scope) = self.capture_binding(binding_handle)?;
        let environment = timeout(
            SCAN_DEADLINE,
            self.services.java().scan_environment(&session),
        )
        .await
        .map_err(|_| JavaHotUpdateError::Deadline)?
        .map_err(|_| JavaHotUpdateError::Core)?;
        self.validate_binding(&scope)?;

        let mut jars: HashMap<String, RemotePath> = HashMap::new();
        let mut handle_by_path: HashMap<String, String> = HashMap::new();
        let mut processes = Vec::with_capacity(environment.processes.len());
        let mut jars_truncated = false;
        for process in environment.processes {
            let truncated = process.command.len() >= MAX_COMMAND_BYTES;
            let mut jar_handles = Vec::new();
            let named = jar_paths(&process.command, truncated);
            let open = process
                .open_jars
                .iter()
                .flatten()
                .map(|path| path.as_str().to_owned());
            for path in named.into_iter().chain(open) {
                if let Some(handle) = handle_by_path.get(&path) {
                    if !jar_handles.contains(handle) {
                        jar_handles.push(handle.clone());
                    }
                    continue;
                }
                if jars.len() >= MAX_JARS {
                    jars_truncated = true;
                    continue;
                }
                let Ok(remote) = RemotePath::new(path.clone()) else {
                    continue;
                };
                let handle = Uuid::new_v4().to_string();
                handle_by_path.insert(path, handle.clone());
                jars.insert(handle.clone(), remote);
                jar_handles.push(handle);
            }
            processes.push(JavaProcessDto {
                pid: process.pid,
                user: process.user,
                cpu_percent: process.cpu_percent,
                memory_percent: process.memory_percent,
                elapsed_seconds: process.elapsed_seconds,
                command: process.command,
                command_truncated: truncated,
                open_files_readable: process.open_jars.is_some(),
                open_jars_incomplete: process.open_jars_incomplete,
                jar_handles,
            });
        }
        let mut offers: Vec<JavaJarOfferDto> = jars
            .iter()
            .map(|(handle, path)| JavaJarOfferDto {
                jar_handle: handle.clone(),
                path: path.as_str().to_owned(),
            })
            .collect();
        offers.sort_by(|left, right| left.path.cmp(&right.path));
        let tools: Vec<JavaToolDto> = JavaTool::ALL
            .into_iter()
            .map(|tool| JavaToolDto {
                tool: tool.command(),
                available: environment.tools.get(&tool).copied().unwrap_or(false),
            })
            .collect();
        let jar_tool = environment
            .tools
            .get(&JavaTool::Jar)
            .copied()
            .unwrap_or(false);

        let snapshot_handle = Uuid::new_v4().to_string();
        let now = Instant::now();
        let mut registry = self.lock_registry()?;
        registry.prune(now);
        // One JVM list per connection: a fresh scan replaces the last one.
        registry
            .snapshots
            .retain(|_, snapshot| snapshot.scope.binding_handle != scope.binding_handle);
        registry.snapshots.insert(
            snapshot_handle.clone(),
            Snapshot {
                scope,
                jars,
                inspected: HashMap::new(),
                jar_tool,
                expires_at: now + SNAPSHOT_TTL,
            },
        );
        Ok(JavaScanDto {
            snapshot_handle,
            version: environment.version,
            tools,
            processes,
            jars: offers,
            jars_truncated,
            expires_in_seconds: SNAPSHOT_TTL.as_secs(),
        })
    }

    /// Lists the classes in one offered JAR, with its size and hash.
    async fn inspect(
        &self,
        binding_handle: &str,
        snapshot_handle: &str,
        jar_handle: &str,
    ) -> Result<JavaJarDto, JavaHotUpdateError> {
        validate_handle(snapshot_handle)?;
        validate_handle(jar_handle)?;
        let (session, scope) = self.capture_binding(binding_handle)?;
        let jar_path = {
            let mut registry = self.lock_registry()?;
            registry.prune(Instant::now());
            registry
                .snapshot(&scope, snapshot_handle)?
                .jar(jar_handle)?
        };
        let inspection = timeout(
            INSPECT_DEADLINE,
            self.services.java().inspect_jar(&session, jar_path.clone()),
        )
        .await
        .map_err(|_| JavaHotUpdateError::Deadline)?
        .map_err(|_| JavaHotUpdateError::Core)?;
        self.validate_binding(&scope)?;
        let classes: Vec<String> = inspection
            .class_entries
            .iter()
            .map(|entry| entry.as_str().to_owned())
            .collect();
        {
            let mut registry = self.lock_registry()?;
            let snapshot = registry.snapshot(&scope, snapshot_handle)?;
            snapshot
                .inspected
                .insert(jar_handle.to_owned(), classes.iter().cloned().collect());
        }
        Ok(JavaJarDto {
            jar_handle: jar_handle.to_owned(),
            path: jar_path.as_str().to_owned(),
            size_bytes: inspection.size,
            sha256: inspection.sha256,
            class_count: inspection.class_count,
            classes,
            truncated: inspection.truncated,
        })
    }

    /// Offers a typed JAR path in the snapshot (once per path) and reads it
    /// the same way as a found one; planning then uses the returned handle.
    async fn inspect_path(
        &self,
        binding_handle: &str,
        snapshot_handle: &str,
        path: &str,
    ) -> Result<JavaJarDto, JavaHotUpdateError> {
        validate_handle(snapshot_handle)?;
        let path = typed_jar_path(path)?;
        let (_, scope) = self.capture_binding(binding_handle)?;
        let jar_handle = {
            let mut registry = self.lock_registry()?;
            registry.prune(Instant::now());
            let snapshot = registry.snapshot(&scope, snapshot_handle)?;
            match snapshot
                .jars
                .iter()
                .find(|(_, offered)| **offered == path)
                .map(|(handle, _)| handle.clone())
            {
                Some(handle) => handle,
                None => {
                    if snapshot.jars.len() >= MAX_JARS + MAX_TYPED_JARS {
                        return Err(JavaHotUpdateError::Capacity);
                    }
                    let handle = Uuid::new_v4().to_string();
                    snapshot.jars.insert(handle.clone(), path);
                    handle
                }
            }
        };
        self.inspect(binding_handle, snapshot_handle, &jar_handle)
            .await
    }

    /// Copies a class file the host's open dialog picked into core's staging
    /// area. Called by the host only: the page never holds a local path.
    pub(crate) fn stage_class(
        &self,
        binding_handle: &str,
        local_path: &Path,
        name: &str,
    ) -> Result<JavaStagedClassDto, JavaHotUpdateError> {
        let (_, scope) = self.capture_binding(binding_handle)?;
        let name = name.trim();
        if name.is_empty()
            || name.chars().count() > MAX_NAME_CHARS
            || name.chars().any(char::is_control)
            || !name.to_ascii_lowercase().ends_with(".class")
        {
            return Err(JavaHotUpdateError::Invalid);
        }
        let paths = self
            .services
            .path_guard([])
            .map_err(|_| JavaHotUpdateError::Core)?;
        let artifact = self
            .services
            .java()
            .stage_class_file(&paths, local_path)
            .map_err(|_| JavaHotUpdateError::Invalid)?;
        let dto = JavaStagedClassDto {
            staged_handle: Uuid::new_v4().to_string(),
            name: name.to_owned(),
            size_bytes: artifact.bytes(),
            sha256: artifact.sha256().to_owned(),
        };
        let now = Instant::now();
        let mut registry = self.lock_registry()?;
        registry.prune(now);
        let mine = registry
            .staged
            .values()
            .filter(|staged| staged.scope.binding_handle == scope.binding_handle)
            .count();
        if mine >= MAX_STAGED {
            return Err(JavaHotUpdateError::Capacity);
        }
        registry.staged.insert(
            dto.staged_handle.clone(),
            Staged {
                scope,
                artifact,
                expires_at: now + PLAN_TTL,
            },
        );
        Ok(dto)
    }

    /// Builds the replacement plan: the core reads the JAR and the entry as they
    /// are now and keeps their hashes as the precondition the write checks.
    async fn plan_update(
        &self,
        binding_handle: &str,
        snapshot_handle: &str,
        jar_handle: &str,
        entry: &str,
        staged_handle: &str,
    ) -> Result<JavaPlanDto, JavaHotUpdateError> {
        validate_handle(snapshot_handle)?;
        validate_handle(jar_handle)?;
        validate_handle(staged_handle)?;
        let entry_path = JarEntryPath::new(entry).map_err(|_| JavaHotUpdateError::Invalid)?;
        let (session, scope) = self.capture_binding(binding_handle)?;
        let (jar_path, staged) = {
            let now = Instant::now();
            let mut registry = self.lock_registry()?;
            registry.prune(now);
            let mine = registry
                .plans
                .values()
                .filter(|plan| plan.scope.binding_handle == scope.binding_handle)
                .count();
            if mine >= MAX_PLANS {
                return Err(JavaHotUpdateError::Capacity);
            }
            let snapshot = registry.snapshot(&scope, snapshot_handle)?;
            let jar_path = snapshot.jar(jar_handle)?;
            // Only a class the inspection of this JAR actually listed.
            if !snapshot
                .inspected
                .get(jar_handle)
                .is_some_and(|classes| classes.contains(entry_path.as_str()))
            {
                return Err(JavaHotUpdateError::Stale);
            }
            let staged = registry
                .staged
                .remove(staged_handle)
                .filter(|staged| staged.scope == scope)
                .ok_or(JavaHotUpdateError::Stale)?;
            (jar_path, staged)
        };
        let paths = self
            .services
            .path_guard([])
            .map_err(|_| JavaHotUpdateError::Core)?;
        let plan = timeout(
            PLAN_DEADLINE,
            self.services.java().plan_jar_update(
                &session,
                &paths,
                jar_path,
                entry_path,
                staged.artifact,
            ),
        )
        .await
        .map_err(|_| JavaHotUpdateError::Deadline)?
        .map_err(|error| match error {
            // An ordinary login keeps the original JAR in its own home; one
            // without a home of its own gets no plan, and is told why.
            CoreError::Validation {
                subject: "Java backup folder",
                ..
            } => JavaHotUpdateError::NoBackupFolder,
            _ => JavaHotUpdateError::Core,
        })?;
        self.validate_binding(&scope)?;
        let dto = JavaPlanDto {
            plan_handle: Uuid::new_v4().to_string(),
            operation: "update",
            summary: bounded(&plan.definition().summary),
            jar_path: plan.jar_path().as_str().to_owned(),
            entry: plan.entry_path().as_str().to_owned(),
            class_sha256: plan.source_sha256().to_owned(),
            restore_description: plan
                .definition()
                .restore_description
                .as_deref()
                .map(bounded),
            confirmed: false,
            expires_in_seconds: PLAN_TTL.as_secs(),
        };
        self.store_plan(scope, PlanKind::Update(Box::new(plan)), dto)
    }

    fn history(&self, binding_handle: &str) -> Result<JavaHistoryDto, JavaHotUpdateError> {
        let (session, scope) = self.capture_binding(binding_handle)?;
        let records = self
            .services
            .java()
            .list_history(session.target())
            .map_err(|_| JavaHotUpdateError::Core)?;
        self.validate_binding(&scope)?;
        let truncated = records.len() > MAX_HISTORY_ROWS;
        Ok(JavaHistoryDto {
            records: records
                .into_iter()
                .take(MAX_HISTORY_ROWS)
                .map(record_dto)
                .collect(),
            truncated,
        })
    }

    fn plan_restore(
        &self,
        binding_handle: &str,
        record_id: &str,
    ) -> Result<JavaPlanDto, JavaHotUpdateError> {
        validate_handle(record_id)?;
        let (session, scope) = self.capture_binding(binding_handle)?;
        let plan = self
            .services
            .java()
            .plan_restore(&session, record_id)
            .map_err(|_| JavaHotUpdateError::Stale)?;
        let record = plan.record();
        let dto = JavaPlanDto {
            plan_handle: Uuid::new_v4().to_string(),
            operation: "restore",
            summary: bounded(&plan.definition().summary),
            jar_path: record.jar_path.as_str().to_owned(),
            entry: record.entry_path.as_str().to_owned(),
            class_sha256: record.source_sha256.clone(),
            restore_description: plan
                .definition()
                .restore_description
                .as_deref()
                .map(bounded),
            confirmed: false,
            expires_in_seconds: PLAN_TTL.as_secs(),
        };
        self.store_plan(scope, PlanKind::Restore(Box::new(plan)), dto)
    }

    fn store_plan(
        &self,
        scope: Scope,
        kind: PlanKind,
        dto: JavaPlanDto,
    ) -> Result<JavaPlanDto, JavaHotUpdateError> {
        let now = Instant::now();
        let mut registry = self.lock_registry()?;
        registry.prune(now);
        let mine = registry
            .plans
            .values()
            .filter(|plan| plan.scope.binding_handle == scope.binding_handle)
            .count();
        if mine >= MAX_PLANS {
            return Err(JavaHotUpdateError::Capacity);
        }
        registry.plans.insert(
            dto.plan_handle.clone(),
            StoredPlan {
                scope,
                kind,
                dto: dto.clone(),
                confirmed: false,
                expires_at: now + PLAN_TTL,
            },
        );
        Ok(dto)
    }

    /// Records the operator's approval; nothing runs until this happened.
    fn confirm(
        &self,
        binding_handle: &str,
        plan_handle: &str,
    ) -> Result<JavaPlanDto, JavaHotUpdateError> {
        validate_handle(plan_handle)?;
        let (_, scope) = self.capture_binding(binding_handle)?;
        let now = Instant::now();
        let mut registry = self.lock_registry()?;
        registry.prune(now);
        let plan = registry
            .plans
            .get_mut(plan_handle)
            .filter(|plan| plan.scope == scope)
            .ok_or(JavaHotUpdateError::Stale)?;
        plan.confirmed = true;
        plan.dto.confirmed = true;
        plan.dto.expires_in_seconds = plan.expires_at.saturating_duration_since(now).as_secs();
        Ok(plan.dto.clone())
    }

    /// Runs a confirmed plan once. The plan leaves the registry before the
    /// await, so it can never run twice.
    async fn execute(
        &self,
        binding_handle: &str,
        plan_handle: &str,
    ) -> Result<JavaReceiptDto, JavaHotUpdateError> {
        validate_handle(plan_handle)?;
        let (session, scope) = self.capture_binding(binding_handle)?;
        let stored = {
            let now = Instant::now();
            let mut registry = self.lock_registry()?;
            registry.prune(now);
            let plan = registry
                .plans
                .get(plan_handle)
                .filter(|plan| plan.scope == scope)
                .ok_or(JavaHotUpdateError::Stale)?;
            if !plan.confirmed {
                return Err(JavaHotUpdateError::NotConfirmed);
            }
            registry
                .plans
                .remove(plan_handle)
                .ok_or(JavaHotUpdateError::Stale)?
        };
        let dto = stored.dto;
        let java = self.services.java();
        let outcome = match stored.kind {
            PlanKind::Update(plan) => {
                let confirmation = DangerousConfirmation::approve(plan.definition());
                timeout(
                    EXECUTE_DEADLINE,
                    java.execute_jar_update(&session, *plan, confirmation),
                )
                .await
            }
            PlanKind::Restore(plan) => {
                let confirmation = DangerousConfirmation::approve(plan.definition());
                timeout(
                    EXECUTE_DEADLINE,
                    java.execute_restore(&session, *plan, confirmation),
                )
                .await
            }
        };
        self.validate_binding(&scope)?;
        let operation = dto.operation;
        Ok(match outcome {
            Err(_) => JavaReceiptDto {
                plan_handle: dto.plan_handle,
                operation,
                verified: false,
                record_id: None,
                jar_path: dto.jar_path,
                entry: dto.entry,
                jar_sha256: None,
                detail: "操作没有在时限内结束，不确定 JAR 现在是什么内容。请重新打开这个 JAR 核对。"
                    .to_owned(),
            },
            Ok(Err(CoreError::Validation {
                subject: "Java JAR owner",
                ..
            })) => JavaReceiptDto {
                plan_handle: dto.plan_handle,
                operation,
                verified: false,
                record_id: None,
                jar_path: dto.jar_path,
                entry: dto.entry,
                jar_sha256: None,
                detail: "这个 JAR 属于其他账号，当前登录账号不能把新文件的属主和权限改回原样，所以没有换入，JAR 没有任何改动。需要替换时请用 root 或这个文件所属的账号登录。"
                    .to_owned(),
            },
            Ok(Err(_)) => JavaReceiptDto {
                plan_handle: dto.plan_handle,
                operation,
                verified: false,
                record_id: None,
                jar_path: dto.jar_path,
                entry: dto.entry,
                jar_sha256: None,
                detail: if operation == "update" {
                    "替换没有完成或没有通过核对。条件安全时已放回原 JAR；请重新打开这个 JAR 核对当前内容。"
                } else {
                    "恢复没有完成或没有通过核对。请重新打开这个 JAR 核对当前内容，再决定下一步。"
                }
                .to_owned(),
            },
            Ok(Ok(result)) => JavaReceiptDto {
                plan_handle: dto.plan_handle,
                operation,
                verified: result.verification.passed,
                jar_sha256: Some(match result.record.state {
                    JavaUpdateState::Applied => result.record.applied_jar_sha256.clone(),
                    JavaUpdateState::Restored => result.record.before_jar_sha256.clone(),
                }),
                record_id: Some(result.record.id),
                jar_path: dto.jar_path,
                entry: dto.entry,
                detail: bounded(&result.verification.detail),
            },
        })
    }

    fn cancel(
        &self,
        binding_handle: &str,
        plan_handle: &str,
    ) -> Result<JavaCancelledDto, JavaHotUpdateError> {
        validate_handle(plan_handle)?;
        let (_, scope) = self.capture_binding(binding_handle)?;
        let mut registry = self.lock_registry()?;
        let removed = registry
            .plans
            .get(plan_handle)
            .is_some_and(|plan| plan.scope == scope);
        if removed {
            registry.plans.remove(plan_handle);
        }
        Ok(JavaCancelledDto { cancelled: removed })
    }

    fn discard_staged(
        &self,
        binding_handle: &str,
        staged_handle: &str,
    ) -> Result<JavaCancelledDto, JavaHotUpdateError> {
        validate_handle(staged_handle)?;
        let (_, scope) = self.capture_binding(binding_handle)?;
        let mut registry = self.lock_registry()?;
        let removed = registry
            .staged
            .get(staged_handle)
            .is_some_and(|staged| staged.scope == scope);
        if removed {
            // Dropping the artifact removes its staged file.
            registry.staged.remove(staged_handle);
        }
        Ok(JavaCancelledDto { cancelled: removed })
    }

    fn capture_binding(
        &self,
        binding_handle: &str,
    ) -> Result<(BoundSshSession, Scope), JavaHotUpdateError> {
        validate_handle(binding_handle)?;
        let session = self
            .ssh_api
            .binding_session_clone(binding_handle)
            .map_err(|_| JavaHotUpdateError::BindingUnavailable)?;
        self.services
            .target()
            .validate(session.target())
            .map_err(|_| JavaHotUpdateError::BindingUnavailable)?;
        let scope = Scope::from_session(binding_handle, &session);
        Ok((session, scope))
    }

    fn validate_binding(&self, expected: &Scope) -> Result<(), JavaHotUpdateError> {
        let (_, current) = self.capture_binding(&expected.binding_handle)?;
        if &current != expected {
            return Err(JavaHotUpdateError::BindingUnavailable);
        }
        Ok(())
    }

    fn lock_registry(&self) -> Result<MutexGuard<'_, Registry>, JavaHotUpdateError> {
        self.registry.lock().map_err(|_| JavaHotUpdateError::Core)
    }
}

fn record_dto(record: JavaUpdateRecord) -> JavaRecordDto {
    JavaRecordDto {
        record_id: record.id,
        jar_path: record.jar_path.as_str().to_owned(),
        entry: record.entry_path.as_str().to_owned(),
        state: match record.state {
            JavaUpdateState::Applied => "applied",
            JavaUpdateState::Restored => "restored",
        },
        before_jar_sha256: record.before_jar_sha256,
        applied_jar_sha256: record.applied_jar_sha256,
        class_sha256: record.source_sha256,
        created_at: record.created_at.to_rfc3339(),
        updated_at: record.updated_at.to_rfc3339(),
    }
}

/// The absolute `.jar` paths a JVM's command line names: after `-jar`, inside
/// `-cp`/`-classpath`/`--class-path`, and in `-javaagent:`. When the collector
/// cut the line short, its last token may be a fragment and is left out.
fn jar_paths(command: &str, truncated: bool) -> Vec<String> {
    let mut tokens: Vec<&str> = command.split_whitespace().collect();
    if truncated {
        tokens.pop();
    }
    let mut found = Vec::new();
    let mut push = |candidate: &str| {
        let candidate = candidate.trim_matches(|c| c == '"' || c == '\'');
        if candidate.starts_with('/')
            && candidate.to_ascii_lowercase().ends_with(".jar")
            && !candidate.contains("..")
            && !candidate.chars().any(char::is_control)
            && !found.iter().any(|known: &String| known == candidate)
        {
            found.push(candidate.to_owned());
        }
    };
    let mut index = 0;
    while index < tokens.len() {
        let token = tokens[index];
        match token {
            "-jar" | "-cp" | "-classpath" | "--class-path" => {
                if let Some(next) = tokens.get(index + 1) {
                    for part in next.split(':') {
                        push(part);
                    }
                    index += 1;
                }
            }
            _ => {
                if let Some(rest) = token.strip_prefix("--class-path=") {
                    for part in rest.split(':') {
                        push(part);
                    }
                } else if let Some(rest) = token.strip_prefix("-javaagent:") {
                    push(rest.split('=').next().unwrap_or_default());
                }
            }
        }
        index += 1;
    }
    found
}

/// A JAR path the operator typed: absolute, plain components, a `.jar` name.
/// Anything else is refused here rather than corrected.
fn typed_jar_path(value: &str) -> Result<RemotePath, JavaHotUpdateError> {
    let path = RemotePath::new(value.to_owned()).map_err(|_| JavaHotUpdateError::Invalid)?;
    let name = path.file_name().map_err(|_| JavaHotUpdateError::Invalid)?;
    if name.len() <= 4 || !name.to_ascii_lowercase().ends_with(".jar") || value.trim() != value {
        return Err(JavaHotUpdateError::Invalid);
    }
    Ok(path)
}

fn bounded(value: &str) -> String {
    let mut text: String = value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    if text.len() > MAX_DETAIL_BYTES {
        let mut end = MAX_DETAIL_BYTES;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    text
}

fn validate_handle(value: &str) -> Result<(), JavaHotUpdateError> {
    if value.is_empty()
        || value.len() > MAX_HANDLE_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(JavaHotUpdateError::Invalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jars_are_read_only_from_the_places_a_command_line_names_them() {
        let command = "/opt/java/bin/java -Xmx1g -javaagent:/opt/agent/probe.jar=mode \
            -cp /usr/local/tomcat/bin/bootstrap.jar:/usr/local/tomcat/bin/tomcat-juli.jar:lib/rel.jar \
            -Dcatalina.base=/x.jar org.apache.catalina.startup.Bootstrap start";
        assert_eq!(
            jar_paths(command, false),
            [
                "/opt/agent/probe.jar",
                "/usr/local/tomcat/bin/bootstrap.jar",
                "/usr/local/tomcat/bin/tomcat-juli.jar",
            ]
        );
        assert_eq!(
            jar_paths("java -jar /srv/app/app.jar --server.port=8080", false),
            ["/srv/app/app.jar"]
        );
        assert_eq!(
            jar_paths("java --class-path=/a/one.jar:/a/two.jar Main", false),
            ["/a/one.jar", "/a/two.jar"]
        );
        // Relative, traversing and non-JAR entries are never offered.
        assert!(jar_paths("java -cp lib/x.jar:/a/../b.jar:/a/b.zip Main", false).is_empty());
        // A cut-off last token may be a fragment of a longer path.
        assert!(jar_paths("java -jar /srv/app/application.jar", true).is_empty());
        assert_eq!(
            jar_paths("java -jar /srv/app/app.jar /srv/app/applic", true),
            ["/srv/app/app.jar"]
        );
    }

    #[test]
    fn requests_take_handles_a_class_entry_or_one_checked_jar_path() {
        let parse =
            |value: serde_json::Value| serde_json::from_value::<JavaHotUpdateRequest>(value);
        assert!(parse(serde_json::json!({ "action": "scan", "bindingHandle": "b" })).is_ok());
        assert!(
            parse(serde_json::json!({
                "action": "plan", "bindingHandle": "b", "snapshotHandle": "s",
                "jarHandle": "j", "entry": "com/x/A.class", "stagedHandle": "c"
            }))
            .is_ok()
        );
        // The one action that takes a path takes only that path, never with a handle.
        assert!(
            parse(serde_json::json!({
                "action": "inspect-path", "bindingHandle": "b", "snapshotHandle": "s",
                "path": "/srv/tomcat/webapps/shop/WEB-INF/lib/shop.jar"
            }))
            .is_ok()
        );
        for forged in [
            serde_json::json!({ "action": "inspect-path", "bindingHandle": "b", "snapshotHandle": "s", "path": "/a.jar", "jarHandle": "j" }),
            serde_json::json!({ "action": "inspect-path", "bindingHandle": "b", "path": "/a.jar" }),
            serde_json::json!({ "action": "inspect", "bindingHandle": "b", "snapshotHandle": "s", "jarHandle": "j", "path": "/etc/passwd" }),
            serde_json::json!({ "action": "scan", "bindingHandle": "b", "command": "id" }),
            serde_json::json!({ "action": "plan", "bindingHandle": "b", "snapshotHandle": "s", "jarHandle": "j", "entry": "A.class", "stagedHandle": "c", "localPath": "C:\\x.class" }),
            serde_json::json!({ "action": "stage", "bindingHandle": "b" }),
            serde_json::json!({ "action": "execute", "bindingHandle": "b" }),
        ] {
            assert!(parse(forged.clone()).is_err(), "{forged}");
        }
    }

    #[test]
    fn a_typed_jar_path_is_taken_only_as_written() {
        for good in [
            "/srv/tomcat/webapps/shop/WEB-INF/lib/shop-core.jar",
            "/opt/app/App.JAR",
            "/opt/my app/lib.jar",
        ] {
            assert_eq!(typed_jar_path(good).unwrap().as_str(), good);
        }
        for bad in [
            "",
            "lib/shop.jar",
            "/etc/passwd",
            "/opt/app/../../etc/shadow.jar",
            "/opt/app/./a.jar",
            "/opt//a.jar",
            "/opt/a.jar/",
            "/opt/.jar",
            " /opt/a.jar",
            "/opt/a.jar ",
            "/opt/a.jar\n",
            "/opt/a\\b.jar",
            "/opt/a.zip",
        ] {
            assert_eq!(
                typed_jar_path(bad).err(),
                Some(JavaHotUpdateError::Invalid),
                "{bad:?}"
            );
        }
        assert!(typed_jar_path(&format!("/{}.jar", "a".repeat(4_096))).is_err());
    }

    #[test]
    fn handles_and_details_are_bounded() {
        assert!(validate_handle("2f1c-ab").is_ok());
        for bad in ["", "a/b", "a b", &"x".repeat(MAX_HANDLE_BYTES + 1)] {
            assert_eq!(validate_handle(bad), Err(JavaHotUpdateError::Invalid));
        }
        let long = format!("line\nbreak{}", "长".repeat(2_000));
        let shown = bounded(&long);
        assert!(shown.len() <= MAX_DETAIL_BYTES && !shown.contains('\n'));
    }
}
