//! Acting on a container the Docker pane already listed.
//!
//! The renderer never sends a container id. It sends the opaque handle its own
//! snapshot minted, and the read side turns that back into an identity under
//! the same scope, token and expiry rules the read paths use. A forged handle
//! names nothing, and a handle from a refreshed snapshot or a switched target
//! names nothing either.
//!
//! Every action goes through the core's plan, confirm, execute, journal,
//! verify and restore pipeline, so it is described before it runs, runs at
//! most once, and is put back when verification fails. This module adds only
//! what the core deliberately leaves out: a handle for a plan that has not
//! been approved yet, a lifetime for it, and the rule that approval and
//! execution are two separate calls.

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use lovelyhawk_core::{
    BackendServices, CoreError,
    docker::{
        ContainerAction, ContainerActionRequest, ContainerFilePath, DockerActionPlan,
        DockerFileContent, DockerFileCopyPlan, DockerFileCopyRequest, DockerFileWritePlan,
        DockerFileWriteRequest, MAX_CONTAINER_FILE_BYTES,
    },
    operations::DangerousConfirmation,
    sftp::RemotePath,
    target::TargetGuard,
};
use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use uuid::Uuid;

use crate::{docker_read_api::DockerReadApi, ssh_api::SshApi};

const MAX_HANDLE_BYTES: usize = 128;
/// One pane drives one dialog, but a second window on the same target is
/// legitimate, so this is a ceiling rather than a count of one.
const MAX_PLANS: usize = 16;
const MAX_PLAN_TEXT_BYTES: usize = 512;

/// Long enough to read what the plan says and decide; short enough that an
/// abandoned dialog cannot be executed from later.
const PLAN_TTL: Duration = Duration::from_secs(5 * 60);
const PLAN_DEADLINE: Duration = Duration::from_secs(45);
/// Execution covers the mutation, the journal write, the verification read and
/// a restore if verification failed, so it is given more room than a plan.
const EXECUTE_DEADLINE: Duration = Duration::from_secs(120);
/// An opened file stays editable for as long as an operator reasonably works
/// on one; its content is held here, never handed back by a handle.
const OPENED_FILE_TTL: Duration = Duration::from_secs(30 * 60);
const MAX_OPENED_FILES: usize = 8;
const MAX_PATH_BYTES: usize = 4_096;
const FILE_DEADLINE: Duration = Duration::from_secs(60);

pub(crate) struct DockerWriteApi {
    services: BackendServices,
    ssh_api: Arc<SshApi>,
    read: Arc<DockerReadApi>,
    registry: Arc<Mutex<PlanRegistry>>,
}

impl fmt::Debug for DockerWriteApi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (plans, confirmed) = self
            .registry
            .lock()
            .map(|registry| {
                (
                    registry.plans.len(),
                    registry
                        .plans
                        .values()
                        .filter(|plan| plan.confirmed)
                        .count(),
                )
            })
            .unwrap_or_default();
        formatter
            .debug_struct("DockerWriteApi")
            .field("plan_count", &plans)
            .field("confirmed_count", &confirmed)
            .finish()
    }
}

/// What the operator may do to a container the pane listed.
///
/// A closed set, parsed from a fixed string. The renderer cannot describe an
/// action that is not one of these, and cannot reach the runtime's own verbs.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum DockerWriteAction {
    Start,
    Stop,
    Restart,
    Pause,
    Unpause,
    Kill,
    Remove,
}

impl DockerWriteAction {
    const fn core(self) -> ContainerAction {
        match self {
            Self::Start => ContainerAction::Start,
            Self::Stop => ContainerAction::Stop,
            Self::Restart => ContainerAction::Restart,
            Self::Pause => ContainerAction::Pause,
            Self::Unpause => ContainerAction::Unpause,
            Self::Kill => ContainerAction::Kill,
            Self::Remove => ContainerAction::Remove,
        }
    }
}

/// Which way a file is copied. Host paths are paths on the connected machine,
/// never on the operator's own computer.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum DockerFileCopyDirection {
    ContainerToHost,
    HostToContainer,
    InContainer,
}

/// What a stored plan will do once approved.
enum StoredOperation {
    Action {
        action: DockerWriteAction,
        plan: Box<DockerActionPlan>,
    },
    FileWrite(Box<DockerFileWritePlan>),
    FileCopy(Box<DockerFileCopyPlan>),
}

impl StoredOperation {
    fn id(&self) -> &'static str {
        match self {
            Self::Action { action, .. } => action.core().id(),
            Self::FileWrite(_) => "write-file",
            Self::FileCopy(_) => "copy-file",
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Action { action, .. } => action.core().label(),
            Self::FileWrite(_) => "写入文件",
            Self::FileCopy(_) => "复制文件",
        }
    }

    fn before_state(&self) -> String {
        match self {
            Self::Action { plan, .. } => plan.before_state().to_owned(),
            Self::FileWrite(plan) => plan.before_description(),
            Self::FileCopy(plan) => plan.target_before_description(),
        }
    }

    fn definition(&self) -> &lovelyhawk_core::operations::OperationPlan {
        match self {
            Self::Action { plan, .. } => plan.definition(),
            Self::FileWrite(plan) => plan.definition(),
            Self::FileCopy(plan) => plan.definition(),
        }
    }
}

/// A file read from a container, kept here so a later write is checked
/// against exactly what the operator saw.
struct OpenedFile {
    scope: WriteScope,
    container_handle: String,
    container_name: String,
    content: DockerFileContent,
    expires_at: Instant,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DockerFileDto {
    pub(crate) file_handle: String,
    pub(crate) container_handle: String,
    pub(crate) container_name: String,
    pub(crate) path: String,
    pub(crate) text: String,
    pub(crate) bytes: usize,
}

impl fmt::Debug for DockerFileDto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DockerFileDto")
            .field("path", &self.path)
            .field("bytes", &self.bytes)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DockerActionPlanDto {
    pub(crate) plan_handle: String,
    pub(crate) container_handle: String,
    /// The container's name as the pane showed it, so the dialog can say what
    /// it is about to act on. Display only; nothing resolves through it.
    pub(crate) container_name: String,
    pub(crate) action: String,
    pub(crate) action_label: String,
    /// What the host says the container is doing right now, read again at
    /// planning time rather than taken from the row.
    pub(crate) before_state: String,
    pub(crate) summary: String,
    pub(crate) dangerous: bool,
    pub(crate) restore_description: Option<String>,
    pub(crate) confirmed: bool,
    pub(crate) expires_in_seconds: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DockerActionReceiptDto {
    pub(crate) plan_handle: String,
    pub(crate) container_name: String,
    pub(crate) action_label: String,
    /// Whether the host, read back afterwards, is in the state the plan said
    /// it would be. A command that returned zero is not the same thing.
    pub(crate) verified: bool,
    pub(crate) detail: String,
    pub(crate) restored: bool,
}

#[derive(Clone, PartialEq, Eq)]
struct WriteScope {
    binding_handle: String,
    session_id: String,
    connection_id: String,
    target: TargetGuard,
}

struct StoredPlan {
    plan_handle: String,
    container_handle: String,
    container_name: String,
    operation: StoredOperation,
    scope: WriteScope,
    /// Set by `confirm` and never unset. `execute` refuses without it, and the
    /// plan leaves the registry as it is taken, so approval covers one run.
    confirmed: bool,
    expires_at: Instant,
}

#[derive(Default)]
struct PlanRegistry {
    plans: HashMap<String, StoredPlan>,
    files: HashMap<String, OpenedFile>,
}

impl PlanRegistry {
    fn prune(&mut self, now: Instant) {
        self.plans.retain(|_, plan| plan.expires_at > now);
        self.files.retain(|_, file| file.expires_at > now);
    }

    fn close_binding(&mut self, binding_handle: &str) {
        self.plans
            .retain(|_, plan| plan.scope.binding_handle != binding_handle);
        self.files
            .retain(|_, file| file.scope.binding_handle != binding_handle);
    }

    /// Keeps the newest opened files; an editor left open longest goes first.
    fn store_file(&mut self, handle: String, file: OpenedFile) {
        if self.files.len() >= MAX_OPENED_FILES
            && let Some(oldest) = self
                .files
                .iter()
                .min_by_key(|(_, file)| file.expires_at)
                .map(|(handle, _)| handle.clone())
        {
            self.files.remove(&oldest);
        }
        self.files.insert(handle, file);
    }

    fn file(
        &self,
        scope: &WriteScope,
        file_handle: &str,
        now: Instant,
    ) -> Result<&OpenedFile, DockerWriteApiError> {
        let file = self
            .files
            .get(file_handle)
            .ok_or(DockerWriteApiError::PlanStale)?;
        if &file.scope != scope || file.expires_at <= now {
            return Err(DockerWriteApiError::PlanStale);
        }
        Ok(file)
    }

    fn store(&mut self, plan: StoredPlan) -> Result<(), DockerWriteApiError> {
        // A pane drives one dialog at a time, so an older plan of the same
        // binding is one the operator already walked away from. Dropping it
        // here also stops an abandoned dialog holding a slot for five minutes.
        self.plans
            .retain(|_, stored| stored.scope.binding_handle != plan.scope.binding_handle);
        if self.plans.len() >= MAX_PLANS {
            return Err(DockerWriteApiError::Capacity);
        }
        self.plans.insert(plan.plan_handle.clone(), plan);
        Ok(())
    }

    fn plan_mut(
        &mut self,
        scope: &WriteScope,
        plan_handle: &str,
        now: Instant,
    ) -> Result<&mut StoredPlan, DockerWriteApiError> {
        let plan = self
            .plans
            .get_mut(plan_handle)
            .ok_or(DockerWriteApiError::PlanStale)?;
        if &plan.scope != scope || plan.expires_at <= now {
            return Err(DockerWriteApiError::PlanStale);
        }
        Ok(plan)
    }

    /// Takes an approved plan out, so it can never run twice.
    fn take_confirmed(
        &mut self,
        scope: &WriteScope,
        plan_handle: &str,
        now: Instant,
    ) -> Result<StoredPlan, DockerWriteApiError> {
        if !self.plan_mut(scope, plan_handle, now)?.confirmed {
            return Err(DockerWriteApiError::PlanNotConfirmed);
        }
        self.plans
            .remove(plan_handle)
            .ok_or(DockerWriteApiError::PlanStale)
    }

    fn remove(&mut self, scope: &WriteScope, plan_handle: &str) {
        if self
            .plans
            .get(plan_handle)
            .is_some_and(|plan| &plan.scope == scope)
        {
            self.plans.remove(plan_handle);
        }
    }
}

pub(crate) enum DockerWriteApiError {
    Core,
    BindingUnavailable,
    InvalidHandle,
    /// The container handle names nothing in a live snapshot of this scope.
    InvalidContainer,
    /// The action is not one this container can take from the state it is in,
    /// or the plan expired, or it belongs to someone else.
    PlanStale,
    PlanNotConfirmed,
    Capacity,
    Deadline,
    RegistryUnavailable,
    /// The path is not an absolute path to a file.
    FilePathInvalid,
    FileMissing,
    FileTooLarge,
    /// Not plain UTF-8 text, or its bytes did not match what the container
    /// reported for it.
    FileNotText,
    /// The file changed while it was read, or after it was opened.
    FileChanged,
    /// The container could not describe the file (no sha256sum, no
    /// permission, or not a regular file).
    FileUnreadable,
}

impl fmt::Debug for DockerWriteApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core => "Core([REDACTED])",
            Self::BindingUnavailable => "BindingUnavailable",
            Self::InvalidHandle => "InvalidHandle",
            Self::InvalidContainer => "InvalidContainer",
            Self::PlanStale => "PlanStale",
            Self::PlanNotConfirmed => "PlanNotConfirmed",
            Self::Capacity => "Capacity",
            Self::Deadline => "Deadline",
            Self::RegistryUnavailable => "RegistryUnavailable",
            Self::FilePathInvalid => "FilePathInvalid",
            Self::FileMissing => "FileMissing",
            Self::FileTooLarge => "FileTooLarge",
            Self::FileNotText => "FileNotText",
            Self::FileChanged => "FileChanged",
            Self::FileUnreadable => "FileUnreadable",
        })
    }
}

impl DockerWriteApi {
    pub(crate) fn new(
        services: BackendServices,
        ssh_api: Arc<SshApi>,
        read: Arc<DockerReadApi>,
    ) -> Self {
        Self {
            services,
            ssh_api,
            read,
            registry: Arc::new(Mutex::new(PlanRegistry::default())),
        }
    }

    pub(crate) fn close_binding(&self, binding_handle: &str) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.close_binding(binding_handle);
        }
    }

    /// Describes what an action would do, without doing any of it.
    ///
    /// The container's current state is read from the host here rather than
    /// taken from the row the operator clicked: the row may be minutes old,
    /// and the precondition the core checks has to be checked against now.
    pub(crate) async fn plan(
        &self,
        binding_handle: &str,
        snapshot_handle: &str,
        container_handle: &str,
        container_name: &str,
        action: DockerWriteAction,
    ) -> Result<DockerActionPlanDto, DockerWriteApiError> {
        let scope = self.capture_binding(binding_handle)?;
        let (session, identity) = self
            .read
            .resolve_container_for_mutation(binding_handle, snapshot_handle, container_handle)
            .map_err(|_| DockerWriteApiError::InvalidContainer)?;

        let request = ContainerActionRequest {
            container: identity,
            action: action.core(),
        };
        let plan = timeout(
            PLAN_DEADLINE,
            self.services.docker().plan_action(&session, &request),
        )
        .await
        .map_err(|_| DockerWriteApiError::Deadline)?
        .map_err(|_| DockerWriteApiError::Core)?;
        self.validate_binding(&scope)?;

        self.store_plan(
            scope,
            container_handle,
            container_name,
            StoredOperation::Action {
                action,
                plan: Box::new(plan),
            },
        )
    }

    /// Reads one text file from a container the pane listed. The content is
    /// kept here with the revision it was read at; the page gets the text and
    /// a handle, and a write is later checked against that exact revision.
    pub(crate) async fn read_file(
        &self,
        binding_handle: &str,
        snapshot_handle: &str,
        container_handle: &str,
        container_name: &str,
        path: &str,
    ) -> Result<DockerFileDto, DockerWriteApiError> {
        let scope = self.capture_binding(binding_handle)?;
        let path = container_file_path(path)?;
        let (session, identity) = self
            .read
            .resolve_container_for_mutation(binding_handle, snapshot_handle, container_handle)
            .map_err(|_| DockerWriteApiError::InvalidContainer)?;
        let content = timeout(
            FILE_DEADLINE,
            self.services.docker().read_file(&session, &identity, &path),
        )
        .await
        .map_err(|_| DockerWriteApiError::Deadline)?
        .map_err(|error| file_refusal(&error))?;
        self.validate_binding(&scope)?;

        let now = Instant::now();
        let file_handle = Uuid::new_v4().to_string();
        let dto = DockerFileDto {
            file_handle: file_handle.clone(),
            container_handle: container_handle.to_owned(),
            container_name: bounded_text(container_name),
            path: content.path().as_str().to_owned(),
            text: content.content().to_owned(),
            bytes: content.content_bytes(),
        };
        let mut registry = self.lock_registry()?;
        registry.prune(now);
        registry.store_file(
            file_handle,
            OpenedFile {
                scope,
                container_handle: container_handle.to_owned(),
                container_name: bounded_text(container_name),
                content,
                expires_at: now + OPENED_FILE_TTL,
            },
        );
        Ok(dto)
    }

    /// Plans writing new text over a file opened with `read_file`. Planning
    /// re-reads the file and refuses if it is no longer what was opened.
    pub(crate) async fn plan_file_write(
        &self,
        binding_handle: &str,
        file_handle: &str,
        text: String,
    ) -> Result<DockerActionPlanDto, DockerWriteApiError> {
        validate_handle(file_handle)?;
        if text.len() > MAX_CONTAINER_FILE_BYTES {
            return Err(DockerWriteApiError::FileTooLarge);
        }
        let scope = self.capture_binding(binding_handle)?;
        let (request, container_handle, container_name) = {
            let now = Instant::now();
            let mut registry = self.lock_registry()?;
            registry.prune(now);
            let opened = registry.file(&scope, file_handle, now)?;
            (
                DockerFileWriteRequest::replace(&opened.content, text)
                    .map_err(|error| file_refusal(&error))?,
                opened.container_handle.clone(),
                opened.container_name.clone(),
            )
        };
        let session = self
            .ssh_api
            .binding_session_clone(&scope.binding_handle)
            .map_err(|_| DockerWriteApiError::BindingUnavailable)?;
        let plan = timeout(
            PLAN_DEADLINE,
            self.services.docker().plan_file_write(&session, request),
        )
        .await
        .map_err(|_| DockerWriteApiError::Deadline)?
        .map_err(|error| file_refusal(&error))?;
        self.validate_binding(&scope)?;
        self.store_plan(
            scope,
            &container_handle,
            &container_name,
            StoredOperation::FileWrite(Box::new(plan)),
        )
    }

    /// Plans copying one file between a container and its host, or within the
    /// container. Both paths are on the connected machine.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn plan_file_copy(
        &self,
        binding_handle: &str,
        snapshot_handle: &str,
        container_handle: &str,
        container_name: &str,
        direction: DockerFileCopyDirection,
        source: &str,
        target: &str,
    ) -> Result<DockerActionPlanDto, DockerWriteApiError> {
        let scope = self.capture_binding(binding_handle)?;
        let (session, container) = self
            .read
            .resolve_container_for_mutation(binding_handle, snapshot_handle, container_handle)
            .map_err(|_| DockerWriteApiError::InvalidContainer)?;
        let request = match direction {
            DockerFileCopyDirection::ContainerToHost => DockerFileCopyRequest::ContainerToHost {
                container,
                source: container_file_path(source)?,
                target: host_file_path(target)?,
            },
            DockerFileCopyDirection::HostToContainer => DockerFileCopyRequest::HostToContainer {
                container,
                source: host_file_path(source)?,
                target: container_file_path(target)?,
            },
            DockerFileCopyDirection::InContainer => DockerFileCopyRequest::InContainer {
                container,
                source: container_file_path(source)?,
                target: container_file_path(target)?,
            },
        };
        let plan = timeout(
            PLAN_DEADLINE,
            self.services.docker().plan_file_copy(&session, request),
        )
        .await
        .map_err(|_| DockerWriteApiError::Deadline)?
        .map_err(|error| file_refusal(&error))?;
        self.validate_binding(&scope)?;
        self.store_plan(
            scope,
            container_handle,
            container_name,
            StoredOperation::FileCopy(Box::new(plan)),
        )
    }

    fn store_plan(
        &self,
        scope: WriteScope,
        container_handle: &str,
        container_name: &str,
        operation: StoredOperation,
    ) -> Result<DockerActionPlanDto, DockerWriteApiError> {
        let now = Instant::now();
        let stored = StoredPlan {
            plan_handle: Uuid::new_v4().to_string(),
            container_handle: container_handle.to_owned(),
            container_name: bounded_text(container_name),
            operation,
            scope,
            confirmed: false,
            expires_at: now + PLAN_TTL,
        };
        let dto = plan_dto(&stored, now)?;
        let mut registry = self.lock_registry()?;
        registry.prune(now);
        registry.store(stored)?;
        Ok(dto)
    }

    /// Records the operator's approval; nothing runs until this happened.
    pub(crate) fn confirm(
        &self,
        binding_handle: &str,
        plan_handle: &str,
    ) -> Result<DockerActionPlanDto, DockerWriteApiError> {
        validate_handle(plan_handle)?;
        let scope = self.capture_binding(binding_handle)?;
        let now = Instant::now();
        let mut registry = self.lock_registry()?;
        registry.prune(now);
        let plan = registry.plan_mut(&scope, plan_handle, now)?;
        plan.confirmed = true;
        plan_dto(plan, now)
    }

    /// Runs the approved plan once, verifies it, and puts it back on failure.
    pub(crate) async fn execute(
        &self,
        binding_handle: &str,
        plan_handle: &str,
    ) -> Result<DockerActionReceiptDto, DockerWriteApiError> {
        validate_handle(plan_handle)?;
        let scope = self.capture_binding(binding_handle)?;
        // The plan leaves the registry before the await, so the lock is never
        // held across it and the plan can never run twice.
        let stored = {
            let now = Instant::now();
            let mut registry = self.lock_registry()?;
            registry.prune(now);
            registry.take_confirmed(&scope, plan_handle, now)?
        };
        let session = self
            .ssh_api
            .binding_session_clone(&scope.binding_handle)
            .map_err(|_| DockerWriteApiError::BindingUnavailable)?;

        let action_label = stored.operation.label().to_owned();
        let confirmation = DangerousConfirmation::approve(stored.operation.definition());
        let journal = self.services.operation_journal();
        let docker = self.services.docker();
        // Every kind ends in the same three facts: verified, what the check
        // read back, and whether a failed check was put back.
        let outcome = timeout(EXECUTE_DEADLINE, async {
            match stored.operation {
                StoredOperation::Action { plan, .. } => docker
                    .execute_action(&session, *plan, confirmation, journal)
                    .await
                    .map(|result| {
                        (
                            result.verified,
                            result.verification_detail,
                            result.restored_after_failed_verification,
                        )
                    }),
                StoredOperation::FileWrite(plan) => docker
                    .execute_file_write(&session, *plan, confirmation, journal)
                    .await
                    .map(|result| {
                        (
                            result.verified,
                            result.verification_detail,
                            result.restored_after_failed_verification,
                        )
                    }),
                StoredOperation::FileCopy(plan) => docker
                    .execute_file_copy(&session, *plan, confirmation, journal)
                    .await
                    .map(|result| {
                        (
                            result.verified,
                            result.verification_detail,
                            result.restored_after_failed_verification,
                        )
                    }),
            }
        })
        .await;
        self.validate_binding(&scope)?;

        match outcome {
            Err(_) => Err(DockerWriteApiError::Deadline),
            // The core restores on failed verification itself and journals
            // whatever it got to, so a failure here is reported rather than
            // retried: retrying a half-applied destructive action is worse
            // than telling the operator to look.
            Ok(Err(_)) => Ok(DockerActionReceiptDto {
                plan_handle: stored.plan_handle,
                container_name: stored.container_name,
                action_label,
                verified: false,
                detail: "操作没有完成，主机上的状态请再确认一次。".to_owned(),
                restored: false,
            }),
            Ok(Ok((verified, detail, restored))) => Ok(DockerActionReceiptDto {
                plan_handle: stored.plan_handle,
                container_name: stored.container_name,
                action_label,
                verified,
                detail: bounded_text(&detail),
                restored,
            }),
        }
    }

    /// Drops a plan the operator decided against.
    pub(crate) fn cancel(
        &self,
        binding_handle: &str,
        plan_handle: &str,
    ) -> Result<(), DockerWriteApiError> {
        validate_handle(plan_handle)?;
        let scope = self.capture_binding(binding_handle)?;
        self.lock_registry()?.remove(&scope, plan_handle);
        Ok(())
    }

    fn capture_binding(&self, binding_handle: &str) -> Result<WriteScope, DockerWriteApiError> {
        validate_handle(binding_handle)?;
        let session = self
            .ssh_api
            .binding_session_clone(binding_handle)
            .map_err(|_| DockerWriteApiError::BindingUnavailable)?;
        self.services
            .target()
            .validate(session.target())
            .map_err(|_| DockerWriteApiError::BindingUnavailable)?;
        Ok(WriteScope {
            binding_handle: binding_handle.to_owned(),
            session_id: session.session_id().to_owned(),
            connection_id: session.connection_id().to_owned(),
            target: session.target().clone(),
        })
    }

    fn validate_binding(&self, expected: &WriteScope) -> Result<(), DockerWriteApiError> {
        let current = self.capture_binding(&expected.binding_handle)?;
        if &current != expected {
            return Err(DockerWriteApiError::BindingUnavailable);
        }
        Ok(())
    }

    fn lock_registry(&self) -> Result<MutexGuard<'_, PlanRegistry>, DockerWriteApiError> {
        self.registry
            .lock()
            .map_err(|_| DockerWriteApiError::RegistryUnavailable)
    }
}

fn plan_dto(stored: &StoredPlan, now: Instant) -> Result<DockerActionPlanDto, DockerWriteApiError> {
    let definition = stored.operation.definition();
    let remaining = stored.expires_at.saturating_duration_since(now).as_secs();
    Ok(DockerActionPlanDto {
        plan_handle: stored.plan_handle.clone(),
        container_handle: stored.container_handle.clone(),
        container_name: stored.container_name.clone(),
        action: stored.operation.id().to_owned(),
        action_label: stored.operation.label().to_owned(),
        before_state: bounded_text(&stored.operation.before_state()),
        summary: bounded_text(&definition.summary),
        dangerous: definition.dangerous,
        restore_description: definition.restore_description.as_deref().map(bounded_text),
        confirmed: stored.confirmed,
        expires_in_seconds: u32::try_from(remaining.max(1))
            .map_err(|_| DockerWriteApiError::Core)?,
    })
}

/// Keeps host text printable and bounded. Nothing is judged by its shape: a
/// state or a verification detail is evidence, and hiding part of it because
/// it looked like something would hide the part worth reading.
fn bounded_text(value: &str) -> String {
    let mut text = String::with_capacity(value.len().min(MAX_PLAN_TEXT_BYTES));
    for character in value.chars() {
        let drawable = if character.is_control() {
            char::REPLACEMENT_CHARACTER
        } else {
            character
        };
        if text.len().saturating_add(drawable.len_utf8()) > MAX_PLAN_TEXT_BYTES {
            break;
        }
        text.push(drawable);
    }
    text
}

fn validate_handle(handle: &str) -> Result<(), DockerWriteApiError> {
    if handle.is_empty() || handle.len() > MAX_HANDLE_BYTES {
        return Err(DockerWriteApiError::InvalidHandle);
    }
    Ok(())
}

fn container_file_path(path: &str) -> Result<ContainerFilePath, DockerWriteApiError> {
    if path.len() > MAX_PATH_BYTES {
        return Err(DockerWriteApiError::FilePathInvalid);
    }
    ContainerFilePath::new(path).map_err(|_| DockerWriteApiError::FilePathInvalid)
}

fn host_file_path(path: &str) -> Result<RemotePath, DockerWriteApiError> {
    if path.len() > MAX_PATH_BYTES {
        return Err(DockerWriteApiError::FilePathInvalid);
    }
    let path = RemotePath::new(path).map_err(|_| DockerWriteApiError::FilePathInvalid)?;
    path.file_name()
        .map_err(|_| DockerWriteApiError::FilePathInvalid)?;
    Ok(path)
}

/// Names the reason a file could not be read, written or copied, from the
/// core's own refusal. Anything not recognised stays the generic failure
/// rather than being described wrongly.
fn file_refusal(error: &CoreError) -> DockerWriteApiError {
    let evidence = error.to_string();
    let has = |needle: &str| evidence.contains(needle);
    if has("file does not exist") {
        DockerWriteApiError::FileMissing
    } else if has("must be at most") {
        DockerWriteApiError::FileTooLarge
    } else if has("does not match the remote length and SHA-256") {
        DockerWriteApiError::FileNotText
    } else if has("changed during read") || has("loaded file changed") {
        DockerWriteApiError::FileChanged
    } else if has("file-state marker") || has("file marker") {
        DockerWriteApiError::FileUnreadable
    } else if has("file path") || has("root is not a file") || has("must be different") {
        DockerWriteApiError::FilePathInvalid
    } else {
        DockerWriteApiError::Core
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invalid(subject: &'static str, message: &str) -> CoreError {
        CoreError::Validation {
            subject,
            message: message.to_owned(),
        }
    }

    #[test]
    fn container_and_host_paths_must_name_a_file_and_stay_bounded() {
        assert!(container_file_path("/etc/nginx/nginx.conf").is_ok());
        assert!(host_file_path("/tmp/copy.conf").is_ok());
        for bad in ["", "relative/path", "/", &"/a".repeat(3_000)] {
            assert!(matches!(
                container_file_path(bad),
                Err(DockerWriteApiError::FilePathInvalid)
            ));
            assert!(matches!(
                host_file_path(bad),
                Err(DockerWriteApiError::FilePathInvalid)
            ));
        }
    }

    #[test]
    fn a_file_refusal_is_named_only_when_the_core_said_which() {
        let named = [
            (
                invalid("container file read", "file does not exist"),
                "FileMissing",
            ),
            (
                invalid("Docker file copy source", "source file does not exist"),
                "FileMissing",
            ),
            (
                invalid("container file content", "must be at most 2097152 bytes"),
                "FileTooLarge",
            ),
            (
                invalid(
                    "container file read",
                    "downloaded text does not match the remote length and SHA-256 marker",
                ),
                "FileNotText",
            ),
            (
                invalid(
                    "Docker file write precondition",
                    "loaded file changed from file:1:a to file:2:b; reload before saving",
                ),
                "FileChanged",
            ),
            (
                invalid(
                    "container file state",
                    "runtime returned an unknown file-state marker",
                ),
                "FileUnreadable",
            ),
            (
                invalid("Docker file copy", "source and target must be different"),
                "FilePathInvalid",
            ),
        ];
        for (error, expected) in named {
            assert_eq!(format!("{:?}", file_refusal(&error)), expected, "{error}");
        }
        assert_eq!(
            format!("{:?}", file_refusal(&invalid("x", "something new"))),
            "Core([REDACTED])"
        );
    }
}
