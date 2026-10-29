#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
//! Bounded, typed process boundary between the desktop host and `lovelyhawk-core`.

mod ai_assist_api;
mod ai_history_api;
mod baseline_read_api;
mod baseline_write_api;
mod case_library_api;
mod case_workspace_api;
mod check_audit_read_api;
mod check_audit_write_api;
mod command_history_api;
mod config_api;
mod config_goal_api;
mod config_visual_api;
mod connections_api;
mod diagnostic_log_api;
mod disposal_report_api;
mod docker_read_api;
mod docker_write_api;
mod emergency_command_api;
mod emergency_path_api;
mod file_evidence_api;
mod integrity_api;
mod integrity_write_api;
mod java_hot_update_api;
mod kubernetes_pod_evidence_api;
mod kubernetes_read_api;
mod kubernetes_write_api;
mod log_analysis_read_api;
mod log_rules_api;
mod nginx_repair_api;
mod notes_api;
mod packet_capture_evidence_api;
mod packet_capture_live_api;
mod postgresql_runtime_api;
mod settings_api;
mod sftp_browser_api;
mod ssh_api;
mod system_info_action_api;
mod system_info_api;
mod terminal_api;
mod windows_incident_api;

use std::{
    collections::HashMap,
    ffi::OsString,
    fmt,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use lovelyhawk_core::{
    BackendServices, CoreError, CoreResult, PortableStore, docker::ContainerFilePath,
    exec_directory::ExecDirectoryListing, kubernetes::KubernetesPod, report::ReportFormat,
    sftp::RemotePath, ssh::BoundSshSession,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::{
    self, AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::sync::Notify;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub use diagnostic_log_api::{DiagnosticLogCapture, DiagnosticLogLayer, DiagnosticLogLevel};

use crate::{
    ai_assist_api::{AiAssistApi, AiAssistError, AiAssistRequest},
    ai_history_api::{AiHistoryApi, AiHistoryApiError, AiHistoryExportFormat},
    baseline_read_api::{BaselineReadApi, BaselineReadApiError},
    case_library_api::{CaseLibraryApi, CaseLibraryError, CaseLibraryRequest},
    case_workspace_api::{CaseWorkspaceApi, CaseWorkspaceError, CaseWorkspaceRequest},
    check_audit_read_api::{
        CheckAuditCatalogInput, CheckAuditLogInput, CheckAuditReadApi, CheckAuditReadApiError,
    },
    command_history_api::{CommandHistoryApi, CommandHistoryApiError},
    config_api::{ConfigApi, ConfigGenerateInput, config_catalog},
    config_visual_api::{ConfigVisualApi, ConfigVisualError, ConfigVisualRequest},
    connections_api::{ConnectionWriteInput, ConnectionsApi},
    diagnostic_log_api::{DiagnosticLogApi, DiagnosticLogApiError, DiagnosticLogFilterInput},
    disposal_report_api::{DisposalReportApi, DisposalReportApiError, DisposalReportPreviewFormat},
    docker_read_api::{DockerReadApi, DockerReadApiError},
    docker_write_api::{
        DockerFileCopyDirection, DockerWriteAction, DockerWriteApi, DockerWriteApiError,
    },
    emergency_command_api::{EmergencyCommandApi, EmergencyCommandApiError},
    emergency_path_api::{EmergencyPathAction, EmergencyPathApiError},
    file_evidence_api::{FileEvidenceApi, FileEvidenceError, FileEvidenceRequest},
    integrity_api::{IntegrityApi, IntegrityApiError},
    integrity_write_api::IntegrityWriteApi,
    java_hot_update_api::{JavaHotUpdateApi, JavaHotUpdateError, JavaHotUpdateRequest},
    kubernetes_pod_evidence_api::{
        PodFileEvidenceApi, PodFileEvidenceError, PodFileEvidenceRequest,
    },
    kubernetes_read_api::{KubernetesListInput, KubernetesReadApi, KubernetesReadApiError},
    kubernetes_write_api::{KubernetesWriteAction, KubernetesWriteApi, KubernetesWriteApiError},
    log_analysis_read_api::{
        LogAnalysisReadApi, LogAnalysisReadApiError, LogCorrelationInput, LogIocSearchInput,
        LogSourceReadInput,
    },
    log_rules_api::{LogRulesApi, LogRulesApiError, LogRulesRequest},
    nginx_repair_api::{NginxRepairApi, NginxRepairError, NginxRepairRequest},
    notes_api::{NotesApi, NotesApiError},
    packet_capture_evidence_api::{
        PacketCaptureEvidenceApi, PacketCaptureEvidenceError, PacketCaptureEvidenceRequest,
    },
    packet_capture_live_api::{
        PacketCaptureLiveApi, PacketCaptureLiveApiError, PacketCaptureStartInput,
    },
    postgresql_runtime_api::{PostgresqlRuntimeApi, PostgresqlRuntimeRequest},
    settings_api::{
        SettingsAiApiKeyReplacementInput, SettingsApi, SettingsApiError, SettingsSaveInput,
    },
    sftp_browser_api::{SftpBrowserApi, SftpBrowserApiError, SftpOperationRequest},
    ssh_api::{SecretResponses, SshApi},
    system_info_api::{SystemInfoApi, SystemInfoApiError},
    terminal_api::{TerminalApi, TerminalApiError},
    windows_incident_api::{
        WindowsEvidencePartRequest, WindowsIncidentApi, WindowsIncidentError,
        WindowsIncidentRequest,
    },
};

pub const PROTOCOL_VERSION: &str = "lovelyhawk-backend/v1";
pub use lovelyhawk_core::windows_incident::{
    WINDOWS_EVIDENCE_MAX_BYTES, WINDOWS_EVIDENCE_PART_BYTES, WindowsEvidencePart,
};
// A maximal typed note can expand when JSON escapes control characters. The
// process boundary remains hard-bounded while still accepting every value the
// core notes contract permits.
pub const MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_REQUEST_ID_BYTES: usize = 128;
/// Calls from a linked host have no frame of their own to correlate.
const IN_PROCESS_REQUEST_ID: &str = "in-process";

/// A refused in-process call: the stable code and the public sentence the
/// stdio protocol would have written for the same request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct BackendCallError {
    pub code: &'static str,
    pub message: &'static str,
}

impl BackendCallError {
    const INVALID_REQUEST: Self = Self {
        code: "invalid-request",
        message: "The backend request is not valid JSON RPC data.",
    };
    const REQUEST_TOO_LARGE: Self = Self {
        code: "request-too-large",
        message: "The backend request exceeded the allowed size.",
    };
    const RESPONSE_TOO_LARGE: Self = Self {
        code: "response-too-large",
        message: "The backend response exceeded the allowed size.",
    };
    const RESPONSE_ENCODING_FAILED: Self = Self {
        code: "response-encoding-failed",
        message: "The backend could not encode its response.",
    };
}

/// Measures a value's JSON encoding without keeping a copy of it, so a
/// secret-bearing request is never duplicated just to be sized.
fn encoded_len_exceeds(value: &Value, limit: usize) -> bool {
    struct Counter {
        written: usize,
        limit: usize,
    }
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.written = self.written.saturating_add(bytes.len());
            if self.written > self.limit {
                return Err(std::io::Error::other("limit exceeded"));
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter { written: 0, limit };
    serde_json::to_writer(&mut counter, value).is_err()
}
const MAX_NOTE_REPLAYS: usize = 256;
const NOTE_REPLAY_TTL: Duration = Duration::from_secs(10 * 60);

#[derive(Debug)]
pub struct BackendState {
    services: BackendServices,
    ai_history: AiHistoryApi,
    log_rules: LogRulesApi,
    ai_assist: AiAssistApi,
    baseline_read: BaselineReadApi,
    baseline_write: baseline_write_api::BaselineWriteApi,
    check_audit_read: CheckAuditReadApi,
    check_audit_write: check_audit_write_api::CheckAuditWriteApi,
    command_history: CommandHistoryApi,
    config: ConfigApi,
    config_visual: ConfigVisualApi,
    connections: ConnectionsApi,
    disposal_report: DisposalReportApi,
    diagnostic_log: DiagnosticLogApi,
    // Shared rather than owned: the mutation side resolves its container
    // handles through this exact registry, so both must see one snapshot set.
    docker_read: Arc<DockerReadApi>,
    docker_write: DockerWriteApi,
    emergency_command: EmergencyCommandApi,
    file_evidence: FileEvidenceApi,
    postgresql_runtime: PostgresqlRuntimeApi,
    case_workspace: CaseWorkspaceApi,
    case_library: CaseLibraryApi,
    sftp_browser: SftpBrowserApi,
    integrity: Arc<IntegrityApi>,
    integrity_write: Arc<IntegrityWriteApi>,
    // Shared: the mutation side resolves its row handles through this exact
    // registry, so both must see one snapshot set.
    kubernetes_read: Arc<KubernetesReadApi>,
    kubernetes_write: KubernetesWriteApi,
    pod_file_evidence: PodFileEvidenceApi,
    log_analysis_read: LogAnalysisReadApi,
    notes: NotesApi,
    nginx_repair: NginxRepairApi,
    java_hot_update: JavaHotUpdateApi,
    note_replays: parking_lot::Mutex<HashMap<String, NoteReplayEntry>>,
    packet_capture_evidence: PacketCaptureEvidenceApi,
    packet_capture_live: PacketCaptureLiveApi,
    ssh: Arc<SshApi>,
    settings: SettingsApi,
    system_info: SystemInfoApi,
    terminal: TerminalApi,
    windows_incident: WindowsIncidentApi,
}

#[derive(Debug)]
struct NoteReplayEntry {
    fingerprint: [u8; 32],
    created_at: Instant,
    state: NoteReplayState,
}

#[derive(Debug)]
enum NoteReplayState {
    InFlight(Arc<Notify>),
    Completed(Value),
}

fn valid_mutation_id(value: &str) -> bool {
    (16..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn mutation_fingerprint(method: &str, params: &Value) -> Result<[u8; 32], RpcFailure> {
    let encoded =
        serde_json::to_vec(&(method, params)).map_err(|_| RpcFailure::invalid_params())?;
    Ok(Sha256::digest(encoded).into())
}

impl BackendState {
    pub fn open(archive_root: PathBuf) -> CoreResult<Self> {
        Self::open_with_diagnostic_capture(
            archive_root,
            DiagnosticLogCapture::new(DiagnosticLogLevel::Info),
        )
    }

    pub fn open_with_diagnostic_capture(
        archive_root: PathBuf,
        diagnostic_capture: Arc<DiagnosticLogCapture>,
    ) -> CoreResult<Self> {
        let store = PortableStore::prepare(archive_root)?;
        let services = BackendServices::with_runtime(store, tokio::runtime::Handle::current())?;
        let connections = ConnectionsApi::new(
            services.connections().clone(),
            services.operation_journal().clone(),
        );
        let ssh = Arc::new(SshApi::new(services.clone()));
        let baseline_read =
            BaselineReadApi::new(services.clone(), Arc::clone(&ssh)).map_err(|_| {
                CoreError::Validation {
                    subject: "baseline read catalog",
                    message: "the static catalog exceeds its bounded desktop projection".to_owned(),
                }
            })?;
        let baseline_write = baseline_write_api::BaselineWriteApi::new(
            services.clone(),
            Arc::clone(&ssh),
            baseline_read.clone(),
        );
        let check_audit_read = CheckAuditReadApi::new(services.clone(), Arc::clone(&ssh));
        let check_audit_write = check_audit_write_api::CheckAuditWriteApi::new(
            services.clone(),
            Arc::clone(&ssh),
            check_audit_read.clone(),
        );
        let command_history = CommandHistoryApi::new(services.clone(), Arc::clone(&ssh));
        let disposal_report = DisposalReportApi::new(services.clone(), Arc::clone(&ssh));
        let case_workspace = CaseWorkspaceApi::new(services.clone(), Arc::clone(&ssh));
        let case_library = CaseLibraryApi::new(services.clone());
        let diagnostic_log = DiagnosticLogApi::new(diagnostic_capture);
        let docker_read = Arc::new(DockerReadApi::new(services.clone(), Arc::clone(&ssh)));
        let docker_write =
            DockerWriteApi::new(services.clone(), Arc::clone(&ssh), Arc::clone(&docker_read));
        let emergency_command = EmergencyCommandApi::new(services.clone(), Arc::clone(&ssh));
        let postgresql_runtime = PostgresqlRuntimeApi::new(services.clone(), Arc::clone(&ssh));
        let file_evidence =
            FileEvidenceApi::new(services.clone(), emergency_command.paths().clone());
        let sftp_browser = SftpBrowserApi::new(services.clone(), Arc::clone(&ssh));
        let integrity = Arc::new(IntegrityApi::new(
            services.clone(),
            Arc::clone(&ssh),
            emergency_command.paths().clone(),
        ));
        let integrity_write = Arc::new(IntegrityWriteApi::new(services.clone(), Arc::clone(&ssh)));
        let kubernetes_read = Arc::new(KubernetesReadApi::new(services.clone(), Arc::clone(&ssh)));
        let kubernetes_write = KubernetesWriteApi::new(
            services.clone(),
            Arc::clone(&ssh),
            Arc::clone(&kubernetes_read),
        );
        let pod_file_evidence = PodFileEvidenceApi::new(
            services.clone(),
            Arc::clone(&ssh),
            Arc::clone(&kubernetes_read),
        );
        let log_analysis_read = LogAnalysisReadApi::new(
            services.clone(),
            Arc::clone(&ssh),
            emergency_command.paths().clone(),
        );
        let packet_capture_evidence =
            PacketCaptureEvidenceApi::new(services.clone(), Arc::clone(&ssh));
        let packet_capture_live = PacketCaptureLiveApi::new(services.clone(), Arc::clone(&ssh));
        let settings = SettingsApi::new(&services);
        let system_info = SystemInfoApi::new(services.clone(), Arc::clone(&ssh));
        let terminal = TerminalApi::new(services.clone(), Arc::clone(&ssh));
        let nginx_repair = NginxRepairApi::new(services.clone(), Arc::clone(&ssh));
        let java_hot_update = JavaHotUpdateApi::new(services.clone(), Arc::clone(&ssh));
        let windows_incident = WindowsIncidentApi::new(services.clone());
        Ok(Self {
            services,
            ai_history: AiHistoryApi::default(),
            log_rules: LogRulesApi::default(),
            ai_assist: AiAssistApi::default(),
            baseline_read,
            baseline_write,
            check_audit_read,
            check_audit_write,
            command_history,
            config: ConfigApi::default(),
            config_visual: ConfigVisualApi::default(),
            connections,
            disposal_report,
            case_workspace,
            case_library,
            diagnostic_log,
            docker_read,
            docker_write,
            emergency_command,
            file_evidence,
            postgresql_runtime,
            sftp_browser,
            integrity,
            integrity_write,
            kubernetes_read,
            kubernetes_write,
            pod_file_evidence,
            log_analysis_read,
            notes: NotesApi::default(),
            nginx_repair,
            java_hot_update,
            note_replays: parking_lot::Mutex::new(HashMap::new()),
            packet_capture_evidence,
            packet_capture_live,
            ssh,
            settings,
            system_info,
            terminal,
            windows_incident,
        })
    }

    async fn replay_note_mutation<F, Fut>(
        &self,
        method: &'static str,
        mutation_id: &str,
        params: &Value,
        operation: F,
    ) -> Result<Result<Value, serde_json::Error>, RpcFailure>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<Result<Value, serde_json::Error>, RpcFailure>>,
    {
        if !valid_mutation_id(mutation_id) {
            return Err(RpcFailure::invalid_params());
        }
        let fingerprint = mutation_fingerprint(method, params)?;
        let mut operation = Some(operation);
        loop {
            let wait = {
                let mut replays = self.note_replays.lock();
                replays.retain(|_, entry| {
                    matches!(entry.state, NoteReplayState::InFlight(_))
                        || entry.created_at.elapsed() < NOTE_REPLAY_TTL
                });
                if let Some(entry) = replays.get(mutation_id) {
                    if entry.fingerprint != fingerprint {
                        return Err(RpcFailure::note_replay_conflict());
                    }
                    match &entry.state {
                        NoteReplayState::Completed(value) => return Ok(Ok(value.clone())),
                        NoteReplayState::InFlight(notify) => Some(notify.clone().notified_owned()),
                    }
                } else {
                    if replays.len() >= MAX_NOTE_REPLAYS {
                        return Err(RpcFailure::note_replay_capacity());
                    }
                    replays.insert(
                        mutation_id.to_owned(),
                        NoteReplayEntry {
                            fingerprint,
                            created_at: Instant::now(),
                            state: NoteReplayState::InFlight(Arc::new(Notify::new())),
                        },
                    );
                    None
                }
            };
            if let Some(wait) = wait {
                wait.await;
                continue;
            }

            let result = operation.take().expect("mutation operation runs once")().await;
            let notify = {
                let mut replays = self.note_replays.lock();
                match &result {
                    Ok(Ok(value)) => {
                        let entry = replays
                            .get_mut(mutation_id)
                            .expect("in-flight mutation entry must exist");
                        let notify = match &entry.state {
                            NoteReplayState::InFlight(notify) => notify.clone(),
                            NoteReplayState::Completed(_) => unreachable!(),
                        };
                        entry.created_at = Instant::now();
                        entry.state = NoteReplayState::Completed(value.clone());
                        notify
                    }
                    _ => match replays.remove(mutation_id) {
                        Some(NoteReplayEntry {
                            state: NoteReplayState::InFlight(notify),
                            ..
                        }) => notify,
                        _ => Arc::new(Notify::new()),
                    },
                }
            };
            notify.notify_waiters();
            return result;
        }
    }

    /// Open a shell inside a listed container, on the same terminal machinery
    /// the host shell uses.
    ///
    /// Three steps that have to happen in this order and nowhere else: turn the
    /// opaque handle back into an identity under the read side's scope rules,
    /// ask the host which shell that image actually has, then hand both to the
    /// terminal registry. Composed here rather than inside either module
    /// because it is the one call that needs both, and neither should grow a
    /// dependency on the other for it.
    async fn open_container_terminal(
        &self,
        params: &DockerTerminalOpenParams,
    ) -> Result<DockerContainerTerminalDto, RpcFailure> {
        let (session, container) = self
            .docker_read
            .resolve_container_for_mutation(
                &params.binding_handle,
                &params.snapshot_handle,
                &params.container_handle,
            )
            .map_err(docker_read_failure)?;
        let shell = self
            .services
            .docker()
            .detect_shell(&session, &container)
            .await
            .map_err(container_shell_failure)?;
        let opened = self
            .terminal
            .open_container(
                &params.binding_handle,
                container,
                shell,
                params.columns,
                params.rows,
            )
            .await
            .map_err(terminal_failure)?;
        Ok(DockerContainerTerminalDto {
            handle: opened.handle,
            columns: opened.columns,
            rows: opened.rows,
            shell: shell.label(),
        })
    }

    /// The same three steps for a pod: the row handle from a Kubernetes list
    /// becomes the pod it was minted for, core finds the shell its default
    /// container has, and the terminal registry opens it. Core checks the pod
    /// is still the one listed before each of the last two.
    async fn open_pod_terminal(
        &self,
        params: &KubernetesPodTerminalOpenParams,
    ) -> Result<DockerContainerTerminalDto, RpcFailure> {
        let (session, pod) = self
            .kubernetes_read
            .resolve_pod_for_terminal(
                &params.binding_handle,
                &params.snapshot_handle,
                &params.row_handle,
            )
            .map_err(kubernetes_read_failure)?;
        let shell = self
            .services
            .kubernetes()
            .detect_shell(&session, &pod, params.container.as_deref())
            .await
            .map_err(pod_shell_failure)?;
        let opened = self
            .terminal
            .open_pod(
                &params.binding_handle,
                pod,
                params.container.clone(),
                shell,
                params.columns,
                params.rows,
            )
            .await
            .map_err(|error| match error {
                TerminalApiError::Core(source) => pod_shell_failure(source),
                other => terminal_failure(other),
            })?;
        Ok(DockerContainerTerminalDto {
            handle: opened.handle,
            columns: opened.columns,
            rows: opened.rows,
            shell: shell.label(),
        })
    }

    /// One directory inside a listed container. The container is the
    /// snapshot's; the path is the caller's, checked as an absolute path with
    /// no `..` and no control characters, and listed by a fixed script.
    async fn list_container_directory(
        &self,
        params: &ContainerDirectoryListParams,
    ) -> Result<ExecDirectoryListing, RpcFailure> {
        let directory = exec_directory_path(&params.path)?;
        let (session, container) = self
            .docker_read
            .resolve_container_for_mutation(
                &params.binding_handle,
                &params.snapshot_handle,
                &params.container_handle,
            )
            .map_err(docker_read_failure)?;
        let listing = tokio::time::timeout(
            EXEC_FILE_DEADLINE,
            self.services
                .docker()
                .list_directory(&session, &container, &directory),
        )
        .await
        .map_err(|_| exec_deadline())?
        .map_err(|error| exec_listing_failure(error, docker_exec_failure))?;
        // Still the same binding and snapshot: an answer for a target the
        // page has since left is dropped here, not shown there.
        self.docker_read
            .resolve_container_for_mutation(
                &params.binding_handle,
                &params.snapshot_handle,
                &params.container_handle,
            )
            .map_err(docker_read_failure)?;
        Ok(listing)
    }

    /// One directory inside a listed pod; as for a container.
    async fn list_pod_directory(
        &self,
        params: &KubernetesPodPathParams,
    ) -> Result<ExecDirectoryListing, RpcFailure> {
        let directory = exec_directory_path(&params.path)?;
        let (session, pod) = self.resolve_pod(params)?;
        let listing = tokio::time::timeout(
            EXEC_FILE_DEADLINE,
            self.services.kubernetes().list_directory(
                &session,
                &pod,
                params.container.as_deref(),
                &directory,
            ),
        )
        .await
        .map_err(|_| exec_deadline())?
        .map_err(|error| exec_listing_failure(error, pod_shell_failure))?;
        self.resolve_pod(params)?;
        Ok(listing)
    }

    /// One text file inside a listed pod, read-only.
    async fn read_pod_file(
        &self,
        params: &KubernetesPodPathParams,
    ) -> Result<PodFileDto, RpcFailure> {
        let path = ContainerFilePath::new(params.path.as_str()).map_err(|_| RpcFailure {
            operation: "validate pod file path",
            code: "invalid-params",
            public_message: "The file path must be an absolute path to a file.",
            source: None,
        })?;
        let (session, pod) = self.resolve_pod(params)?;
        let file = tokio::time::timeout(
            EXEC_FILE_DEADLINE,
            self.services.kubernetes().read_file(
                &session,
                &pod,
                params.container.as_deref(),
                &path,
            ),
        )
        .await
        .map_err(|_| exec_deadline())?
        .map_err(pod_file_failure)?;
        self.resolve_pod(params)?;
        Ok(PodFileDto {
            path: file.path.as_str().to_owned(),
            text: file.text,
            bytes: file.bytes,
            sha256: file.sha256,
        })
    }

    fn resolve_pod(
        &self,
        params: &KubernetesPodPathParams,
    ) -> Result<(BoundSshSession, KubernetesPod), RpcFailure> {
        self.kubernetes_read
            .resolve_pod_for_terminal(
                &params.binding_handle,
                &params.snapshot_handle,
                &params.row_handle,
            )
            .map_err(kubernetes_read_failure)
    }

    /// Open a login shell in a directory the file browser listed.
    ///
    /// The browser turns its handle back into the path it recorded; the terminal
    /// registry then opens the shell there under the same binding. The caller
    /// names neither a path nor a command.
    async fn open_directory_terminal(
        &self,
        params: &TerminalOpenDirectoryParams,
    ) -> Result<terminal_api::TerminalOpenedDto, RpcFailure> {
        let directory = self
            .sftp_browser
            .directory_for_terminal(
                &params.binding_handle,
                &params.browser_handle,
                &params.directory_handle,
            )
            .map_err(sftp_browser_failure)?;
        self.terminal
            .open_directory(
                &params.binding_handle,
                directory,
                params.columns,
                params.rows,
            )
            .await
            .map_err(terminal_failure)
    }

    async fn dispatch(&self, request: RpcRequest) -> RpcResponse {
        let request_id = request.request_id;
        let result = match request.method {
            RpcMethod::AppBootstrap => parse_params::<EmptyParams>(request.params)
                .and_then(|_| self.bootstrap().map(to_value)),
            RpcMethod::ConnectionsList => {
                parse_params::<EmptyParams>(request.params).and_then(|_| {
                    self.connections
                        .list_connections()
                        .map(to_value)
                        .map_err(connections_failure)
                })
            }
            RpcMethod::ConnectionsGet => parse_params::<ConnectionIdParams>(request.params)
                .and_then(|params| {
                    self.connections
                        .get_connection(&params.id)
                        .map(to_value)
                        .map_err(connections_failure)
                }),
            RpcMethod::ConnectionsCreate => parse_params::<ConnectionWriteInput>(request.params)
                .and_then(|params| {
                    self.connections
                        .create_connection(params)
                        .map(to_value)
                        .map_err(connections_failure)
                }),
            RpcMethod::ConnectionsUpdate => parse_params::<ConnectionWriteInput>(request.params)
                .and_then(|params| {
                    self.connections
                        .update_connection(params)
                        .map(to_value)
                        .map_err(connections_failure)
                }),
            RpcMethod::ConnectionsPlanDelete => parse_params::<ConnectionIdParams>(request.params)
                .and_then(|params| {
                    self.connections
                        .plan_connection_delete(&params.id)
                        .map(to_value)
                        .map_err(connections_failure)
                }),
            RpcMethod::ConnectionsConfirmDelete => {
                match parse_params::<ConnectionDeleteConfirmParams>(request.params) {
                    Ok(params) => self
                        .connections
                        .confirm_connection_delete(&params.handle)
                        .await
                        .map(to_value)
                        .map_err(connections_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::ConnectionsCancelDelete => {
                parse_params::<ConnectionDeleteConfirmParams>(request.params).and_then(|params| {
                    self.connections
                        .cancel_connection_delete(&params.handle)
                        .map(to_value)
                        .map_err(connections_failure)
                })
            }
            RpcMethod::ConnectionsImportFile => {
                parse_params::<ConnectionFileParams>(request.params).and_then(|params| {
                    self.connections
                        .import_connections(&params.path)
                        .map(to_value)
                        .map_err(connections_failure)
                })
            }
            RpcMethod::ConnectionsExportFile => {
                parse_params::<ConnectionFileParams>(request.params).and_then(|params| {
                    self.connections
                        .export_connections(&params.path)
                        .map(to_value)
                        .map_err(connections_failure)
                })
            }
            RpcMethod::SshConnectStart => parse_params::<SshConnectStartParams>(request.params)
                .and_then(|params| {
                    self.ssh
                        .start_connect(params.connection_id)
                        .map(to_value)
                        .map_err(ssh_failure)
                }),
            RpcMethod::SshProbeStart => parse_params::<ConnectionWriteInput>(request.params)
                .and_then(|params| {
                    self.ssh
                        .start_probe(params)
                        .map(to_value)
                        .map_err(ssh_failure)
                }),
            RpcMethod::SshAttemptGet => {
                parse_params::<SshAttemptParams>(request.params).and_then(|params| {
                    self.ssh
                        .get_attempt(&params.attempt_handle)
                        .map(to_value)
                        .map_err(ssh_failure)
                })
            }
            RpcMethod::SshHostKeyConfirm => parse_params::<SshPromptParams>(request.params)
                .and_then(|params| {
                    self.ssh
                        .confirm_host_key(&params.attempt_handle, &params.prompt_handle)
                        .map(to_value)
                        .map_err(ssh_failure)
                }),
            RpcMethod::SshMfaRespond => parse_params::<SshMfaRespondParams>(request.params)
                .and_then(|mut params| {
                    self.ssh
                        .respond_mfa(
                            &params.attempt_handle,
                            &params.prompt_handle,
                            &mut params.responses,
                        )
                        .map(to_value)
                        .map_err(ssh_failure)
                }),
            RpcMethod::SshAttemptCancel => parse_params::<SshAttemptParams>(request.params)
                .and_then(|params| {
                    self.ssh
                        .cancel_attempt(&params.attempt_handle)
                        .map(to_value)
                        .map_err(ssh_failure)
                }),
            RpcMethod::SshBindingDisconnect => {
                match parse_params::<SshBindingParams>(request.params) {
                    Ok(params) => match self.terminal.close_binding(&params.binding_handle).await {
                        Ok(()) => {
                            self.baseline_read.close_binding(&params.binding_handle);
                            self.baseline_write.close_binding(&params.binding_handle);
                            self.nginx_repair.close_binding(&params.binding_handle);
                            self.java_hot_update.close_binding(&params.binding_handle);
                            self.postgresql_runtime
                                .close_binding(&params.binding_handle);
                            self.file_evidence.close_binding(&params.binding_handle);
                            self.case_workspace.close_binding(&params.binding_handle);
                            self.check_audit_read.close_binding(&params.binding_handle);
                            self.check_audit_write.close_binding(&params.binding_handle);
                            self.integrity.close_binding(&params.binding_handle);
                            self.integrity_write.close_binding(&params.binding_handle);
                            self.log_analysis_read.close_binding(&params.binding_handle);
                            self.kubernetes_read.close_binding(&params.binding_handle);
                            self.kubernetes_write.close_binding(&params.binding_handle);
                            self.pod_file_evidence.close_binding(&params.binding_handle);
                            self.emergency_command.close_binding(&params.binding_handle);
                            self.docker_read.close_binding(&params.binding_handle);
                            self.docker_write.close_binding(&params.binding_handle);
                            self.system_info.close_binding(&params.binding_handle);
                            self.sftp_browser.close_binding(&params.binding_handle);
                            self.packet_capture_evidence
                                .close_binding(&params.binding_handle);
                            self.packet_capture_live
                                .close_binding(&params.binding_handle)
                                .await;
                            self.ssh
                                .disconnect_binding(&params.binding_handle)
                                .await
                                .map(to_value)
                                .map_err(ssh_failure)
                        }
                        Err(error) => Err(terminal_failure(error)),
                    },
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::TerminalOpen => match parse_params::<TerminalOpenParams>(request.params) {
                Ok(params) => self
                    .terminal
                    .open(&params.binding_handle, params.columns, params.rows)
                    .await
                    .map(to_value)
                    .map_err(terminal_failure),
                Err(failure) => Err(failure),
            },
            RpcMethod::TerminalOpenDirectory => {
                match parse_params::<TerminalOpenDirectoryParams>(request.params) {
                    Ok(params) => self.open_directory_terminal(&params).await.map(to_value),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::TerminalPoll => match parse_params::<TerminalPollParams>(request.params) {
                Ok(params) => self
                    .terminal
                    .poll(&params.handle, params.maximum_events, params.maximum_bytes)
                    .await
                    .map(to_value)
                    .map_err(terminal_failure),
                Err(failure) => Err(failure),
            },
            RpcMethod::TerminalInput => match parse_params::<TerminalInputParams>(request.params) {
                Ok(params) => self
                    .terminal
                    .input(&params.handle, &params.bytes_base64)
                    .await
                    .map(to_value)
                    .map_err(terminal_failure),
                Err(failure) => Err(failure),
            },
            RpcMethod::TerminalResize => {
                match parse_params::<TerminalResizeParams>(request.params) {
                    Ok(params) => self
                        .terminal
                        .resize(&params.handle, params.columns, params.rows)
                        .await
                        .map(to_value)
                        .map_err(terminal_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::TerminalRenderSnapshot => {
                match parse_params::<TerminalHandleParams>(request.params) {
                    Ok(params) => self
                        .terminal
                        .render_snapshot(&params.handle)
                        .await
                        .map(to_value)
                        .map_err(terminal_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::TerminalSearch => {
                match parse_params::<TerminalSearchParams>(request.params) {
                    Ok(params) => self
                        .terminal
                        .search(
                            &params.handle,
                            &params.query,
                            params.case_sensitive,
                            params.regex,
                            params.maximum_results,
                        )
                        .await
                        .map(to_value)
                        .map_err(terminal_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::TerminalClose => {
                match parse_params::<TerminalHandleParams>(request.params) {
                    Ok(params) => self
                        .terminal
                        .close(&params.handle)
                        .await
                        .map(to_value)
                        .map_err(terminal_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::SystemInfoCatalogGet => parse_params::<EmptyParams>(request.params)
                .map(|_| to_value(SystemInfoApi::catalog())),
            RpcMethod::SystemInfoSummaryGet => {
                match parse_params::<SystemInfoBindingParams>(request.params) {
                    Ok(params) => self
                        .system_info
                        .summary(&params.binding_handle)
                        .await
                        .map(to_value)
                        .map_err(system_info_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::SystemInfoTableCollect => {
                match parse_params::<SystemInfoCollectParams>(request.params) {
                    Ok(params) => self
                        .system_info
                        .collect(&params.binding_handle, &params.tab, params.maximum_rows)
                        .await
                        .map(to_value)
                        .map_err(system_info_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::SystemInfoFileEditorOpen => {
                match parse_params::<SystemInfoDetailParams>(request.params) {
                    Ok(params) => {
                        async {
                            let (_, table) = self
                                .system_info
                                .snapshot_for(
                                    &params.binding_handle,
                                    &params.snapshot_handle,
                                    &params.row_id,
                                )
                                .map_err(system_info_failure)?;
                            let path = table
                                .shell_config_file(&params.row_id)
                                .map_err(|_| system_info_failure(SystemInfoApiError::InvalidRow))?;
                            let result = self
                                .sftp_browser
                                .open_editor_file(&params.binding_handle, path)
                                .await
                                .map_err(sftp_browser_failure)?;
                            // A refresh or target switch while SFTP was opening revokes
                            // the inventory row's authority to launch a new window.
                            self.system_info
                                .snapshot_for(
                                    &params.binding_handle,
                                    &params.snapshot_handle,
                                    &params.row_id,
                                )
                                .map_err(system_info_failure)?;
                            Ok(to_value(result))
                        }
                        .await
                    }
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::SystemInfoDetailGet => {
                match parse_params::<SystemInfoDetailParams>(request.params) {
                    Ok(params) => self
                        .system_info
                        .detail(
                            &params.binding_handle,
                            &params.snapshot_handle,
                            &params.row_id,
                        )
                        .await
                        .map(to_value)
                        .map_err(system_info_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::SystemInfoRowActionsList => {
                match parse_params::<SystemInfoDetailParams>(request.params) {
                    Ok(params) => self
                        .system_info
                        .row_actions(
                            &params.binding_handle,
                            &params.snapshot_handle,
                            &params.row_id,
                        )
                        .map(to_value)
                        .map_err(system_info_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::SystemInfoRowInspect => {
                match parse_params::<SystemInfoRowActionParams>(request.params) {
                    Ok(params) => self
                        .system_info
                        .inspect_row(
                            &params.binding_handle,
                            &params.snapshot_handle,
                            &params.row_id,
                            &params.action,
                        )
                        .await
                        .map(to_value)
                        .map_err(system_info_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::SystemInfoRowActionPlan => {
                match parse_params::<SystemInfoRowActionParams>(request.params) {
                    Ok(params) => self
                        .system_info
                        .plan_row_action(
                            &params.binding_handle,
                            &params.snapshot_handle,
                            &params.row_id,
                            &params.action,
                        )
                        .await
                        .map(to_value)
                        .map_err(system_info_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::SystemInfoRowActionConfirm => {
                match parse_params::<SystemInfoPlanParams>(request.params) {
                    Ok(params) => self
                        .system_info
                        .confirm_row_action(&params.binding_handle, &params.plan_handle)
                        .map(to_value)
                        .map_err(system_info_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::SystemInfoRowActionExecute => {
                match parse_params::<SystemInfoPlanParams>(request.params) {
                    Ok(params) => self
                        .system_info
                        .execute_row_action(&params.binding_handle, &params.plan_handle)
                        .await
                        .map(to_value)
                        .map_err(system_info_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::SystemInfoRowActionCancel => {
                match parse_params::<SystemInfoPlanParams>(request.params) {
                    Ok(params) => self
                        .system_info
                        .cancel_row_action(&params.binding_handle, &params.plan_handle)
                        .map(|()| to_value(serde_json::json!({ "cancelled": true })))
                        .map_err(system_info_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::BaselineCatalogGet => {
                parse_params::<EmptyParams>(request.params).and_then(|_| {
                    self.baseline_read
                        .get_catalog()
                        .map(to_value)
                        .map_err(baseline_read_failure)
                })
            }
            RpcMethod::CaseLibrary => match parse_params::<CaseLibraryRequest>(request.params) {
                Ok(params) => self
                    .case_library
                    .dispatch(params)
                    .await
                    .map(to_value)
                    .map_err(case_library_failure),
                Err(failure) => Err(failure),
            },
            RpcMethod::CaseWorkspace => parse_params::<CaseWorkspaceRequest>(request.params)
                .and_then(|params| {
                    self.case_workspace
                        .dispatch(params, &self.disposal_report)
                        .map(to_value)
                        .map_err(case_workspace_failure)
                }),
            RpcMethod::PostgresqlRuntime => {
                match parse_params::<PostgresqlRuntimeRequest>(request.params) {
                    Ok(params) => Ok(to_value(self.postgresql_runtime.dispatch(params).await)),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::FileEvidence => match parse_params::<FileEvidenceRequest>(request.params) {
                Ok(params) => self
                    .file_evidence
                    .dispatch(params)
                    .await
                    .map(to_value)
                    .map_err(file_evidence_failure),
                Err(failure) => Err(failure),
            },
            RpcMethod::JavaHotUpdate => {
                match parse_params::<JavaHotUpdateRequest>(request.params) {
                    Ok(params) => self
                        .java_hot_update
                        .dispatch(params)
                        .await
                        .map(to_value)
                        .map_err(java_hot_update_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::WindowsIncident => {
                match parse_params::<WindowsIncidentRequest>(request.params) {
                    Ok(params) => self
                        .windows_incident
                        .dispatch(params)
                        .await
                        .map(to_value)
                        .map_err(windows_incident_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::WindowsEvidencePart => {
                parse_params::<WindowsEvidencePartRequest>(request.params).and_then(|params| {
                    self.windows_incident
                        .evidence_part(params)
                        .map(to_value)
                        .map_err(windows_incident_failure)
                })
            }
            RpcMethod::JavaHotUpdateClassStage => {
                match parse_params::<JavaClassStageParams>(request.params) {
                    Ok(params) => self
                        .java_hot_update
                        .stage_class(
                            &params.binding_handle,
                            std::path::Path::new(&params.local_path),
                            &params.name,
                        )
                        .map(to_value)
                        .map_err(java_hot_update_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::AiAssist => match parse_params::<AiAssistRequest>(request.params) {
                Ok(params) => self
                    .ai_assist
                    .dispatch(&self.services, params)
                    .await
                    .map(Ok)
                    .map_err(ai_assist_failure),
                Err(failure) => Err(failure),
            },
            RpcMethod::LogRules => match parse_params::<LogRulesRequest>(request.params) {
                Ok(params) => self
                    .log_rules
                    .dispatch(&self.services, params)
                    .await
                    .map(Ok)
                    .map_err(log_rules_failure),
                Err(failure) => Err(failure),
            },
            RpcMethod::NginxRepair => match parse_params::<NginxRepairRequest>(request.params) {
                Ok(params) => self
                    .nginx_repair
                    .dispatch(params)
                    .await
                    .map(to_value)
                    .map_err(nginx_repair_failure),
                Err(failure) => Err(failure),
            },
            RpcMethod::BaselineScan => {
                match parse_params::<BaselineBindingParams>(request.params) {
                    Ok(params) => self
                        .baseline_read
                        .scan(&params.binding_handle)
                        .await
                        .map(to_value)
                        .map_err(baseline_read_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::BaselineHistoryList => {
                match parse_params::<BaselineBindingParams>(request.params) {
                    Ok(params) => self
                        .baseline_read
                        .list_history(&params.binding_handle)
                        .await
                        .map(to_value)
                        .map_err(baseline_read_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::BaselineFileRead => {
                match parse_params::<BaselineFileParams>(request.params) {
                    Ok(params) => self
                        .baseline_read
                        .read_setting_file(&params.binding_handle, &params.item_handle)
                        .await
                        .map(to_value)
                        .map_err(baseline_read_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::BaselineActionPlan => {
                match parse_params::<BaselineActionPlanParams>(request.params) {
                    Ok(params) => self
                        .baseline_write
                        .plan(&params.binding_handle, params.action)
                        .await
                        .map(to_value)
                        .map_err(baseline_write_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::BaselineActionConfirm => {
                match parse_params::<BaselinePlanParams>(request.params) {
                    Ok(params) => self
                        .baseline_write
                        .confirm(&params.binding_handle, &params.plan_handle)
                        .map(to_value)
                        .map_err(baseline_write_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::BaselineActionExecute => {
                match parse_params::<BaselinePlanParams>(request.params) {
                    Ok(params) => self
                        .baseline_write
                        .execute(&params.binding_handle, &params.plan_handle)
                        .await
                        .map(to_value)
                        .map_err(baseline_write_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::BaselineActionCancel => {
                match parse_params::<BaselinePlanParams>(request.params) {
                    Ok(params) => self
                        .baseline_write
                        .cancel(&params.binding_handle, &params.plan_handle)
                        .map(|()| to_value(serde_json::json!({ "cancelled": true })))
                        .map_err(baseline_write_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::CheckAuditCatalogGet => {
                match parse_params::<CheckAuditCatalogParams>(request.params) {
                    Ok(params) => self
                        .check_audit_read
                        .get_catalog(&params.binding_handle, params.input)
                        .map(to_value)
                        .map_err(check_audit_read_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::CheckAuditStatusCollect => {
                match parse_params::<CheckAuditSnapshotParams>(request.params) {
                    Ok(params) => self
                        .check_audit_read
                        .collect_status(&params.binding_handle, &params.snapshot_handle)
                        .await
                        .map(to_value)
                        .map_err(check_audit_read_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::CheckAuditActionPlan => {
                match parse_params::<CheckAuditActionPlanParams>(request.params) {
                    Ok(params) => self
                        .check_audit_write
                        .plan(
                            &params.binding_handle,
                            &params.snapshot_handle,
                            params.action,
                        )
                        .await
                        .map(to_value)
                        .map_err(check_audit_write_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::CheckAuditActionConfirm => {
                match parse_params::<CheckAuditPlanParams>(request.params) {
                    Ok(params) => self
                        .check_audit_write
                        .confirm(&params.binding_handle, &params.plan_handle)
                        .map(to_value)
                        .map_err(check_audit_write_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::CheckAuditActionExecute => {
                match parse_params::<CheckAuditPlanParams>(request.params) {
                    Ok(params) => self
                        .check_audit_write
                        .execute(&params.binding_handle, &params.plan_handle)
                        .await
                        .map(to_value)
                        .map_err(check_audit_write_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::CheckAuditActionCancel => {
                match parse_params::<CheckAuditPlanParams>(request.params) {
                    Ok(params) => self
                        .check_audit_write
                        .cancel(&params.binding_handle, &params.plan_handle)
                        .map(|()| to_value(serde_json::json!({ "cancelled": true })))
                        .map_err(check_audit_write_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::CheckAuditLogRead => {
                match parse_params::<CheckAuditLogParams>(request.params) {
                    Ok(params) => self
                        .check_audit_read
                        .read_log(
                            &params.binding_handle,
                            &params.snapshot_handle,
                            params.input,
                        )
                        .await
                        .map(to_value)
                        .map_err(check_audit_read_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::LogAnalysisSourcesDiscover => {
                match parse_params::<LogAnalysisBindingParams>(request.params) {
                    Ok(params) => self
                        .log_analysis_read
                        .discover_sources(&params.binding_handle)
                        .await
                        .map(to_value)
                        .map_err(log_analysis_read_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::LogAnalysisSourceRead => {
                match parse_params::<LogAnalysisSourceReadParams>(request.params) {
                    Ok(params) => self
                        .log_analysis_read
                        .read_source(
                            &params.binding_handle,
                            &params.snapshot_handle,
                            &params.source_handle,
                            params.input,
                        )
                        .await
                        .map(to_value)
                        .map_err(log_analysis_read_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::LogAnalysisSourcesCorrelate => {
                match parse_params::<LogAnalysisCorrelationParams>(request.params) {
                    Ok(params) => self
                        .log_analysis_read
                        .correlate_sources(
                            &params.binding_handle,
                            &params.snapshot_handle,
                            params.input,
                        )
                        .await
                        .map(to_value)
                        .map_err(log_analysis_read_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::LogAnalysisIocsSearch => {
                match parse_params::<LogAnalysisIocSearchParams>(request.params) {
                    Ok(params) => self
                        .log_analysis_read
                        .search_iocs(
                            &params.binding_handle,
                            &params.snapshot_handle,
                            params.input,
                        )
                        .await
                        .map(to_value)
                        .map_err(log_analysis_read_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::KubernetesAvailabilityGet => {
                match parse_params::<KubernetesBindingParams>(request.params) {
                    Ok(params) => self
                        .kubernetes_read
                        .availability(&params.binding_handle)
                        .await
                        .map(to_value)
                        .map_err(kubernetes_read_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::KubernetesResourcesList => {
                match parse_params::<KubernetesListParams>(request.params) {
                    Ok(params) => self
                        .kubernetes_read
                        .list(&params.binding_handle, params.input)
                        .await
                        .map(to_value)
                        .map_err(kubernetes_read_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::KubernetesResourceDetailGet => {
                match parse_params::<KubernetesRowParams>(request.params) {
                    Ok(params) => self
                        .kubernetes_read
                        .detail(
                            &params.binding_handle,
                            &params.snapshot_handle,
                            &params.row_handle,
                        )
                        .await
                        .map(to_value)
                        .map_err(kubernetes_read_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::KubernetesPodLogsGet => {
                match parse_params::<KubernetesPodLogsParams>(request.params) {
                    Ok(params) => self
                        .kubernetes_read
                        .pod_logs(
                            &params.binding_handle,
                            &params.snapshot_handle,
                            &params.row_handle,
                            params.previous,
                            params.container.as_deref(),
                        )
                        .await
                        .map(to_value)
                        .map_err(kubernetes_read_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::KubernetesWorkloadActionPlan => {
                match parse_params::<KubernetesActionPlanParams>(request.params) {
                    Ok(params) => self
                        .kubernetes_write
                        .plan(
                            &params.binding_handle,
                            &params.snapshot_handle,
                            &params.row_handle,
                            &params.resource_name,
                            params.action,
                        )
                        .await
                        .map(to_value)
                        .map_err(kubernetes_write_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::KubernetesWorkloadActionConfirm => {
                match parse_params::<KubernetesPlanParams>(request.params) {
                    Ok(params) => self
                        .kubernetes_write
                        .confirm(&params.binding_handle, &params.plan_handle)
                        .map(to_value)
                        .map_err(kubernetes_write_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::KubernetesWorkloadActionExecute => {
                match parse_params::<KubernetesPlanParams>(request.params) {
                    Ok(params) => self
                        .kubernetes_write
                        .execute(&params.binding_handle, &params.plan_handle)
                        .await
                        .map(to_value)
                        .map_err(kubernetes_write_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::KubernetesWorkloadActionCancel => {
                match parse_params::<KubernetesPlanParams>(request.params) {
                    Ok(params) => self
                        .kubernetes_write
                        .cancel(&params.binding_handle, &params.plan_handle)
                        .map(|()| to_value(serde_json::json!({ "cancelled": true })))
                        .map_err(kubernetes_write_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::DockerContainersRefresh => {
                match parse_params::<DockerBindingParams>(request.params) {
                    Ok(params) => self
                        .docker_read
                        .refresh_containers(&params.binding_handle)
                        .await
                        .map(to_value)
                        .map_err(docker_read_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::DockerCollectionGet => {
                match parse_params::<DockerCollectionParams>(request.params) {
                    Ok(params) => self
                        .docker_read
                        .collection(
                            &params.binding_handle,
                            &params.snapshot_handle,
                            &params.kind,
                        )
                        .await
                        .map(to_value)
                        .map_err(docker_read_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::DockerResourceInspect => {
                match parse_params::<DockerInspectParams>(request.params) {
                    Ok(params) => self
                        .docker_read
                        .inspect(
                            &params.binding_handle,
                            &params.snapshot_handle,
                            &params.kind,
                            &params.resource_handle,
                        )
                        .await
                        .map(to_value)
                        .map_err(docker_read_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::DockerSecurityAuditGet => {
                match parse_params::<DockerSnapshotParams>(request.params) {
                    Ok(params) => self
                        .docker_read
                        .security_audit(&params.binding_handle, &params.snapshot_handle)
                        .await
                        .map(to_value)
                        .map_err(docker_read_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::DockerContainerChangesGet => {
                match parse_params::<DockerContainerReadParams>(request.params) {
                    Ok(params) => self
                        .docker_read
                        .changes(
                            &params.binding_handle,
                            &params.snapshot_handle,
                            &params.container_handle,
                        )
                        .await
                        .map(to_value)
                        .map_err(docker_read_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::DockerContainerProcessesGet => {
                match parse_params::<DockerContainerReadParams>(request.params) {
                    Ok(params) => self
                        .docker_read
                        .processes(
                            &params.binding_handle,
                            &params.snapshot_handle,
                            &params.container_handle,
                        )
                        .await
                        .map(to_value)
                        .map_err(docker_read_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::DockerContainerLogsGet => {
                match parse_params::<DockerLogsParams>(request.params) {
                    Ok(params) => self
                        .docker_read
                        .logs(
                            &params.binding_handle,
                            &params.snapshot_handle,
                            &params.container_handle,
                            params.tail,
                        )
                        .await
                        .map(to_value)
                        .map_err(docker_read_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::DockerContainerActionPlan => {
                match parse_params::<DockerActionPlanParams>(request.params) {
                    Ok(params) => self
                        .docker_write
                        .plan(
                            &params.binding_handle,
                            &params.snapshot_handle,
                            &params.container_handle,
                            &params.container_name,
                            params.action,
                        )
                        .await
                        .map(to_value)
                        .map_err(docker_write_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::DockerContainerActionConfirm => {
                match parse_params::<DockerPlanParams>(request.params) {
                    Ok(params) => self
                        .docker_write
                        .confirm(&params.binding_handle, &params.plan_handle)
                        .map(to_value)
                        .map_err(docker_write_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::DockerContainerActionExecute => {
                match parse_params::<DockerPlanParams>(request.params) {
                    Ok(params) => self
                        .docker_write
                        .execute(&params.binding_handle, &params.plan_handle)
                        .await
                        .map(to_value)
                        .map_err(docker_write_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::DockerContainerActionCancel => {
                match parse_params::<DockerPlanParams>(request.params) {
                    Ok(params) => self
                        .docker_write
                        .cancel(&params.binding_handle, &params.plan_handle)
                        .map(|()| to_value(serde_json::json!({ "cancelled": true })))
                        .map_err(docker_write_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::DockerContainerFileRead => {
                match parse_params::<DockerFileReadParams>(request.params) {
                    Ok(params) => self
                        .docker_write
                        .read_file(
                            &params.binding_handle,
                            &params.snapshot_handle,
                            &params.container_handle,
                            &params.container_name,
                            &params.path,
                        )
                        .await
                        .map(to_value)
                        .map_err(docker_write_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::DockerContainerFilePlanWrite => {
                match parse_params::<DockerFileWriteParams>(request.params) {
                    Ok(params) => self
                        .docker_write
                        .plan_file_write(&params.binding_handle, &params.file_handle, params.text)
                        .await
                        .map(to_value)
                        .map_err(docker_write_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::DockerContainerFilePlanCopy => {
                match parse_params::<DockerFileCopyParams>(request.params) {
                    Ok(params) => self
                        .docker_write
                        .plan_file_copy(
                            &params.binding_handle,
                            &params.snapshot_handle,
                            &params.container_handle,
                            &params.container_name,
                            params.direction,
                            &params.source,
                            &params.target,
                        )
                        .await
                        .map(to_value)
                        .map_err(docker_write_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::DockerContainerTerminalOpen => {
                match parse_params::<DockerTerminalOpenParams>(request.params) {
                    Ok(params) => self.open_container_terminal(&params).await.map(to_value),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::KubernetesPodTerminalOpen => {
                match parse_params::<KubernetesPodTerminalOpenParams>(request.params) {
                    Ok(params) => self.open_pod_terminal(&params).await.map(to_value),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::KubernetesManifestExport => {
                match parse_params::<KubernetesManifestExportParams>(request.params) {
                    Ok(params) => self
                        .kubernetes_read
                        .export_manifest(
                            &params.binding_handle,
                            &params.snapshot_handle,
                            &params.row_handle,
                        )
                        .await
                        .map(to_value)
                        .map_err(kubernetes_read_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::DockerContainerDirectoryList => {
                match parse_params::<ContainerDirectoryListParams>(request.params) {
                    Ok(params) => self.list_container_directory(&params).await.map(to_value),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::KubernetesPodDirectoryList => {
                match parse_params::<KubernetesPodPathParams>(request.params) {
                    Ok(params) => self.list_pod_directory(&params).await.map(to_value),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::KubernetesPodFileRead => {
                match parse_params::<KubernetesPodPathParams>(request.params) {
                    Ok(params) => self.read_pod_file(&params).await.map(to_value),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::EmergencyCommandCatalogLoad => {
                match parse_params::<EmergencyCommandBindingParams>(request.params) {
                    Ok(params) => self
                        .emergency_command
                        .load_catalog(&params.binding_handle)
                        .await
                        .map(to_value)
                        .map_err(emergency_command_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::EmergencyCommandRun => {
                match parse_params::<EmergencyCommandRunParams>(request.params) {
                    Ok(params) => self
                        .emergency_command
                        .run_command(
                            &params.binding_handle,
                            &params.snapshot_handle,
                            &params.command_handle,
                            params.container_handle.as_deref(),
                        )
                        .await
                        .map(to_value)
                        .map_err(emergency_command_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::EmergencyCommandHistoryLocate => {
                match parse_params::<EmergencyCommandHistoryLocateParams>(request.params) {
                    Ok(params) => self
                        .emergency_command
                        .locate_history(
                            &params.binding_handle,
                            &params.snapshot_handle,
                            &params.history_id,
                        )
                        .map(to_value)
                        .map_err(emergency_command_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::EmergencyCommandPathInspect => {
                match parse_params::<EmergencyCommandPathParams>(request.params) {
                    Ok(params) => self
                        .emergency_command
                        .paths()
                        .inspect(&params.binding_handle, &params.path_handle)
                        .await
                        .map(to_value)
                        .map_err(emergency_path_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::EmergencyCommandPathPlan => {
                match parse_params::<EmergencyCommandPathPlanParams>(request.params) {
                    Ok(params) => self
                        .emergency_command
                        .paths()
                        .plan(&params.binding_handle, &params.path_handle, params.action)
                        .await
                        .map(to_value)
                        .map_err(emergency_path_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::EmergencyCommandPathConfirm => {
                match parse_params::<EmergencyCommandPathPlanHandleParams>(request.params) {
                    Ok(params) => self
                        .emergency_command
                        .paths()
                        .confirm(&params.binding_handle, &params.plan_handle)
                        .map(to_value)
                        .map_err(emergency_path_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::EmergencyCommandPathExecute => {
                match parse_params::<EmergencyCommandPathPlanHandleParams>(request.params) {
                    Ok(params) => self
                        .emergency_command
                        .paths()
                        .execute(&params.binding_handle, &params.plan_handle)
                        .await
                        .map(to_value)
                        .map_err(emergency_path_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::EmergencyCommandPathCancel => {
                match parse_params::<EmergencyCommandPathPlanHandleParams>(request.params) {
                    Ok(params) => self
                        .emergency_command
                        .paths()
                        .cancel(&params.binding_handle, &params.plan_handle)
                        .map(|()| to_value(()))
                        .map_err(emergency_path_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::EmergencyCommandPathUndo => {
                match parse_params::<EmergencyCommandPathPlanHandleParams>(request.params) {
                    Ok(params) => self
                        .emergency_command
                        .paths()
                        .undo(&params.binding_handle, &params.plan_handle)
                        .await
                        .map(to_value)
                        .map_err(emergency_path_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::SftpBrowserOpen => {
                match parse_params::<SftpBrowserBindingParams>(request.params) {
                    Ok(params) => self
                        .sftp_browser
                        .open_sftp_browser(&params.binding_handle)
                        .await
                        .map(to_value)
                        .map_err(sftp_browser_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::SftpBrowserDirectoryList => {
                match parse_params::<SftpBrowserDirectoryParams>(request.params) {
                    Ok(params) => self
                        .sftp_browser
                        .list_sftp_directory(
                            &params.binding_handle,
                            &params.browser_handle,
                            &params.directory_handle,
                        )
                        .await
                        .map(to_value)
                        .map_err(sftp_browser_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::SftpBrowserTextRead => {
                match parse_params::<SftpBrowserFileParams>(request.params) {
                    Ok(params) => self
                        .sftp_browser
                        .read_sftp_text(
                            &params.binding_handle,
                            &params.browser_handle,
                            &params.file_handle,
                        )
                        .await
                        .map(to_value)
                        .map_err(sftp_browser_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::SftpBrowserDownload => {
                match parse_params::<SftpBrowserDownloadParams>(request.params) {
                    Ok(params) => self
                        .sftp_browser
                        .download_entry(
                            &params.binding_handle,
                            &params.browser_handle,
                            &params.file_handle,
                            std::path::Path::new(&params.local_path),
                        )
                        .await
                        .map(to_value)
                        .map_err(sftp_browser_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::SftpBrowserOperationPlan => {
                match parse_params::<SftpBrowserOperationParams>(request.params) {
                    Ok(params) => match params.to_request() {
                        Ok((browser_handle, operation)) => self
                            .sftp_browser
                            .plan_operation(&params.binding_handle, &browser_handle, operation)
                            .await
                            .map(to_value)
                            .map_err(sftp_browser_failure),
                        Err(failure) => Err(failure),
                    },
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::SftpBrowserOperationConfirm => {
                match parse_params::<SftpBrowserPlanParams>(request.params) {
                    Ok(params) => self
                        .sftp_browser
                        .confirm_operation(&params.binding_handle, &params.plan_handle)
                        .map(to_value)
                        .map_err(sftp_browser_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::SftpBrowserOperationExecute => {
                match parse_params::<SftpBrowserPlanParams>(request.params) {
                    Ok(params) => self
                        .sftp_browser
                        .execute_operation(&params.binding_handle, &params.plan_handle)
                        .await
                        .map(to_value)
                        .map_err(sftp_browser_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::SftpBrowserOperationCancel => {
                match parse_params::<SftpBrowserPlanParams>(request.params) {
                    Ok(params) => self
                        .sftp_browser
                        .cancel_operation(&params.binding_handle, &params.plan_handle)
                        .map(|()| to_value(()))
                        .map_err(sftp_browser_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::SftpBrowserTransferCancel => {
                match parse_params::<SftpBrowserTransferParams>(request.params) {
                    Ok(params) => self
                        .sftp_browser
                        .cancel_transfers(&params.binding_handle, &params.browser_handle)
                        .map(to_value)
                        .map_err(sftp_browser_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::SftpBrowserOperationUndo => {
                match parse_params::<SftpBrowserPlanParams>(request.params) {
                    Ok(params) => self
                        .sftp_browser
                        .undo_operation(&params.binding_handle, &params.plan_handle)
                        .await
                        .map(to_value)
                        .map_err(sftp_browser_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::SftpBrowserUploadStage => {
                match parse_params::<SftpBrowserStageParams>(request.params) {
                    Ok(params) => self
                        .sftp_browser
                        .stage_upload(
                            &params.binding_handle,
                            std::path::Path::new(&params.local_path),
                            &params.name,
                        )
                        .map(to_value)
                        .map_err(sftp_browser_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::PacketCaptureInterfacesList => {
                match parse_params::<PacketCaptureBindingParams>(request.params) {
                    Ok(params) => self
                        .packet_capture_live
                        .list_interfaces(&params.binding_handle)
                        .await
                        .map(to_value)
                        .map_err(packet_capture_live_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::PacketCaptureStart => {
                match parse_params::<PacketCaptureStartParams>(request.params) {
                    Ok(params) => self
                        .packet_capture_live
                        .start(
                            &params.binding_handle,
                            &params.interface_handle,
                            params.input,
                        )
                        .await
                        .map(to_value)
                        .map_err(packet_capture_live_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::PacketCapturePoll => {
                match parse_params::<PacketCapturePollParams>(request.params) {
                    Ok(params) => self
                        .packet_capture_live
                        .poll(
                            &params.binding_handle,
                            &params.capture_handle,
                            params.after_sequence,
                        )
                        .await
                        .map(to_value)
                        .map_err(packet_capture_live_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::PacketCaptureStop => {
                match parse_params::<PacketCaptureHandleParams>(request.params) {
                    Ok(params) => self
                        .packet_capture_live
                        .stop(&params.binding_handle, &params.capture_handle)
                        .await
                        .map(to_value)
                        .map_err(packet_capture_live_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::KubernetesPodFileEvidence => {
                match parse_params::<PodFileEvidenceRequest>(request.params) {
                    Ok(params) => self
                        .pod_file_evidence
                        .dispatch(params)
                        .await
                        .map(to_value)
                        .map_err(pod_file_evidence_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::PacketCaptureEvidence => {
                match parse_params::<PacketCaptureEvidenceRequest>(request.params) {
                    Ok(params) => self
                        .packet_capture_evidence
                        .dispatch(params, &self.packet_capture_live)
                        .await
                        .map(to_value)
                        .map_err(packet_capture_evidence_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::ApplicationLogList => {
                parse_params::<ApplicationLogFilterParams>(request.params).and_then(|params| {
                    self.diagnostic_log
                        .list(params.filter)
                        .map(to_value)
                        .map_err(diagnostic_log_failure)
                })
            }
            RpcMethod::ApplicationLogLevelSet => {
                parse_params::<ApplicationLogLevelParams>(request.params)
                    .map(|params| to_value(self.diagnostic_log.set_level(params.level)))
            }
            RpcMethod::ApplicationLogBufferClear => parse_params::<EmptyParams>(request.params)
                .map(|_| to_value(self.diagnostic_log.clear_buffer())),
            RpcMethod::ApplicationLogPreviewGet => {
                parse_params::<ApplicationLogFilterParams>(request.params).and_then(|params| {
                    self.diagnostic_log
                        .preview(params.filter)
                        .map(to_value)
                        .map_err(diagnostic_log_failure)
                })
            }
            RpcMethod::ApplicationLogExportPrepare => {
                parse_params::<ApplicationLogFilterParams>(request.params).and_then(|params| {
                    self.diagnostic_log
                        .prepare_export(params.filter)
                        .map(to_value)
                        .map_err(diagnostic_log_failure)
                })
            }
            RpcMethod::IntegrityPresetsGet => parse_params::<EmptyParams>(request.params)
                .map(|_| to_value(IntegrityApi::catalog())),
            RpcMethod::IntegrityBaselinesList => {
                parse_params::<IntegrityBindingParams>(request.params).and_then(|params| {
                    self.integrity
                        .list_baselines(&params.binding_handle)
                        .map(to_value)
                        .map_err(integrity_failure)
                })
            }
            RpcMethod::IntegrityComparisonStart => {
                parse_params::<IntegrityBaselineParams>(request.params).and_then(|params| {
                    self.integrity
                        .start_comparison(&params.binding_handle, &params.baseline_handle)
                        .map(to_value)
                        .map_err(integrity_failure)
                })
            }
            RpcMethod::IntegrityComparisonPoll => {
                parse_params::<IntegrityPollParams>(request.params).and_then(|params| {
                    self.integrity
                        .poll_comparison(
                            &params.binding_handle,
                            &params.operation_handle,
                            params.after_event,
                            params.limit,
                        )
                        .map(to_value)
                        .map_err(integrity_failure)
                })
            }
            RpcMethod::IntegrityComparisonCancel => {
                parse_params::<IntegrityOperationParams>(request.params).and_then(|params| {
                    self.integrity
                        .cancel_comparison(&params.binding_handle, &params.operation_handle)
                        .map(to_value)
                        .map_err(integrity_failure)
                })
            }
            RpcMethod::IntegrityBaselineCreateStart => {
                parse_params::<IntegrityCreateParams>(request.params).and_then(|params| {
                    self.integrity_write
                        .start_creation(&params.binding_handle, &params.preset_ids)
                        .map(to_value)
                        .map_err(integrity_failure)
                })
            }
            RpcMethod::IntegrityBaselineCreatePoll => {
                parse_params::<IntegrityOperationParams>(request.params).and_then(|params| {
                    self.integrity_write
                        .poll_creation(&params.binding_handle, &params.operation_handle)
                        .map(to_value)
                        .map_err(integrity_failure)
                })
            }
            RpcMethod::IntegrityBaselineCreateCancel => {
                parse_params::<IntegrityOperationParams>(request.params).and_then(|params| {
                    self.integrity_write
                        .cancel_creation(&params.binding_handle, &params.operation_handle)
                        .map(to_value)
                        .map_err(integrity_failure)
                })
            }
            RpcMethod::SettingsGet => parse_params::<EmptyParams>(request.params)
                .and_then(|_| self.settings.load().map(to_value).map_err(settings_failure)),
            RpcMethod::SettingsSave => {
                parse_params::<SettingsSaveInput>(request.params).and_then(|params| {
                    self.settings
                        .save(params)
                        .map(to_value)
                        .map_err(settings_failure)
                })
            }
            RpcMethod::SettingsAiApiKeyReplace => parse_params::<SettingsAiApiKeyReplacementInput>(
                request.params,
            )
            .and_then(|params| {
                self.settings
                    .replace_ai_api_key(params)
                    .map(to_value)
                    .map_err(settings_failure)
            }),
            RpcMethod::SettingsAiApiKeyClearPlan => {
                parse_params::<SettingsProviderParams>(request.params).and_then(|params| {
                    self.settings
                        .plan_clear_ai_api_key(&params.provider_id)
                        .map(to_value)
                        .map_err(settings_failure)
                })
            }
            RpcMethod::SettingsAiProviderRemovePlan => {
                parse_params::<SettingsProviderParams>(request.params).and_then(|params| {
                    self.settings
                        .plan_remove_ai_provider(&params.provider_id)
                        .map(to_value)
                        .map_err(settings_failure)
                })
            }
            RpcMethod::SettingsMutationConfirm => {
                match parse_params::<SettingsMutationParams>(request.params) {
                    Ok(params) => self
                        .settings
                        .confirm_mutation(&params.mutation_handle)
                        .await
                        .map(to_value)
                        .map_err(settings_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::SettingsMutationCancel => {
                parse_params::<SettingsMutationParams>(request.params).and_then(|params| {
                    self.settings
                        .cancel_mutation(&params.mutation_handle)
                        .map(to_value)
                        .map_err(settings_failure)
                })
            }
            RpcMethod::AiHistoryList => parse_params::<AiHistoryListParams>(request.params)
                .and_then(|params| {
                    self.ai_history
                        .list(
                            &self.services,
                            Some(&params.query),
                            params.offset,
                            params.limit,
                        )
                        .map(to_value)
                        .map_err(ai_history_failure)
                }),
            RpcMethod::AiHistoryGet => {
                parse_params::<AiHistoryIdParams>(request.params).and_then(|params| {
                    self.ai_history
                        .get(&self.services, &params.id)
                        .map(to_value)
                        .map_err(ai_history_failure)
                })
            }
            RpcMethod::AiHistoryPlanRemove => parse_params::<AiHistoryIdParams>(request.params)
                .and_then(|params| {
                    self.ai_history
                        .plan_remove(&self.services, &params.id)
                        .map(to_value)
                        .map_err(ai_history_failure)
                }),
            RpcMethod::AiHistoryPlanClear => {
                parse_params::<EmptyParams>(request.params).and_then(|_| {
                    self.ai_history
                        .plan_clear(&self.services)
                        .map(to_value)
                        .map_err(ai_history_failure)
                })
            }
            RpcMethod::AiHistoryConfirmMutation => {
                match parse_params::<AiHistoryHandleParams>(request.params) {
                    Ok(params) => self
                        .ai_history
                        .confirm(&self.services, &params.handle)
                        .await
                        .map(to_value)
                        .map_err(ai_history_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::AiHistoryCancelMutation => {
                parse_params::<AiHistoryHandleParams>(request.params).and_then(|params| {
                    self.ai_history
                        .cancel(&params.handle)
                        .map(to_value)
                        .map_err(ai_history_failure)
                })
            }
            RpcMethod::AiHistoryExport => parse_params::<AiHistoryExportParams>(request.params)
                .and_then(|params| {
                    self.ai_history
                        .export_for_main(&self.services, params.format)
                        .map(to_value)
                        .map_err(ai_history_failure)
                }),
            RpcMethod::CommandHistoryList => {
                parse_params::<CommandHistoryListParams>(request.params).and_then(|params| {
                    self.command_history
                        .list(
                            &params.binding_handle,
                            Some(&params.query),
                            params.offset,
                            params.limit,
                        )
                        .map(to_value)
                        .map_err(command_history_failure)
                })
            }
            RpcMethod::CommandHistoryGet => {
                parse_params::<CommandHistoryRecordParams>(request.params).and_then(|params| {
                    self.command_history
                        .get(&params.binding_handle, &params.record_id)
                        .map(to_value)
                        .map_err(command_history_failure)
                })
            }
            RpcMethod::CommandHistoryPlanReplay => {
                parse_params::<CommandHistoryRecordParams>(request.params).and_then(|params| {
                    self.command_history
                        .plan_replay(&params.binding_handle, &params.record_id)
                        .map(to_value)
                        .map_err(command_history_failure)
                })
            }
            RpcMethod::CommandHistoryPlanRemove => {
                parse_params::<CommandHistoryRecordParams>(request.params).and_then(|params| {
                    self.command_history
                        .plan_remove(&params.binding_handle, &params.record_id)
                        .map(to_value)
                        .map_err(command_history_failure)
                })
            }
            RpcMethod::CommandHistoryPlanClear => {
                parse_params::<CommandHistoryBindingParams>(request.params).and_then(|params| {
                    self.command_history
                        .plan_clear(&params.binding_handle)
                        .map(to_value)
                        .map_err(command_history_failure)
                })
            }
            RpcMethod::CommandHistoryConfirmMutation => {
                match parse_params::<CommandHistoryMutationParams>(request.params) {
                    Ok(params) => self
                        .command_history
                        .confirm(&params.binding_handle, &params.mutation_handle)
                        .await
                        .map(to_value)
                        .map_err(command_history_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::CommandHistoryCancelMutation => {
                parse_params::<CommandHistoryMutationParams>(request.params).and_then(|params| {
                    self.command_history
                        .cancel(&params.binding_handle, &params.mutation_handle)
                        .map(to_value)
                        .map_err(command_history_failure)
                })
            }
            RpcMethod::DisposalReportGenerate => {
                parse_params::<DisposalReportBindingParams>(request.params).and_then(|params| {
                    self.disposal_report
                        .generate(&params.binding_handle)
                        .map(to_value)
                        .map_err(disposal_report_failure)
                })
            }
            RpcMethod::DisposalReportContentGet => {
                parse_params::<DisposalReportContentParams>(request.params).and_then(|params| {
                    self.disposal_report
                        .content(&params.binding_handle, &params.report_handle, params.format)
                        .map(to_value)
                        .map_err(disposal_report_failure)
                })
            }
            RpcMethod::DisposalReportExport => {
                parse_params::<DisposalReportExportParams>(request.params).and_then(|params| {
                    self.disposal_report
                        .export_for_main(
                            &params.binding_handle,
                            &params.report_handle,
                            params.format,
                        )
                        .map(to_value)
                        .map_err(disposal_report_failure)
                })
            }
            RpcMethod::ConfigCatalogGet => {
                parse_params::<EmptyParams>(request.params).map(|_| to_value(config_catalog()))
            }
            RpcMethod::ConfigQuickGenerate => parse_params::<ConfigGenerateInput>(request.params)
                .and_then(|params| {
                    self.config
                        .generate(params)
                        .map(to_value)
                        .map_err(config_failure)
                }),
            RpcMethod::ConfigQuickRevise => parse_params::<ConfigReviseParams>(request.params)
                .and_then(|params| {
                    self.config
                        .revise(&params.handle, params.revision, params.input)
                        .map(to_value)
                        .map_err(config_failure)
                }),
            RpcMethod::ConfigQuickCopy => parse_params::<ConfigDraftParams>(request.params)
                .and_then(|params| {
                    self.config
                        .copy(&params.handle, params.revision)
                        .map(to_value)
                        .map_err(config_failure)
                }),
            RpcMethod::ConfigQuickClose => parse_params::<ConfigDraftParams>(request.params)
                .and_then(|params| {
                    self.config
                        .close(&params.handle, params.revision)
                        .map(to_value)
                        .map_err(config_failure)
                }),
            RpcMethod::ConfigQuickArtifact => parse_params::<ConfigArtifactParams>(request.params)
                .and_then(|params| {
                    self.config
                        .artifact(&params.handle, params.revision, &params.artifact_key)
                        .map(to_value)
                        .map_err(config_failure)
                }),
            RpcMethod::ConfigQuickBundleExport => {
                parse_params::<ConfigBundleExportParams>(request.params).and_then(|params| {
                    if !params.parent_directory.is_absolute()
                        || params.parent_directory.as_os_str().len() > 32_768
                    {
                        return Err(RpcFailure::invalid_params());
                    }
                    self.config
                        .export_bundle(&params.handle, params.revision, &params.parent_directory)
                        .map(to_value)
                        .map_err(config_failure)
                })
            }
            RpcMethod::ConfigVisual => parse_params::<ConfigVisualRequest>(request.params)
                .and_then(|params| {
                    self.config_visual
                        .dispatch(params, &self.config)
                        .map(to_value)
                        .map_err(config_visual_failure)
                }),
            RpcMethod::SecurityReferenceSetFavorites => parse_params::<
                SetSecurityReferenceFavoritesParams,
            >(request.params)
            .and_then(|params| {
                self.set_security_reference_favorites(params.favorite_ids)
                    .map(to_value)
            }),
            RpcMethod::NotesList => {
                parse_params::<NotesListParams>(request.params).and_then(|params| {
                    self.notes
                        .list(
                            &self.services,
                            params.query.as_deref(),
                            params.offset,
                            params.limit,
                        )
                        .map(to_value)
                        .map_err(notes_failure)
                })
            }
            RpcMethod::NotesGet => {
                parse_params::<NoteIdParams>(request.params).and_then(|params| {
                    self.notes
                        .get(&self.services, &params.id)
                        .map(to_value)
                        .map_err(notes_failure)
                })
            }
            RpcMethod::NotesCreate => {
                let fingerprint = request.params.clone();
                match parse_params::<NotesCreateParams>(request.params) {
                    Ok(params) => {
                        self.replay_note_mutation(
                            "notes.create",
                            &params.mutation_id,
                            &fingerprint,
                            || async {
                                self.notes
                                    .create_idempotent(
                                        &self.services,
                                        &params.mutation_id,
                                        params.title,
                                        params.content,
                                        params.tags,
                                    )
                                    .map(to_value)
                                    .map_err(notes_failure)
                            },
                        )
                        .await
                    }
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::NotesUpdate => {
                let fingerprint = request.params.clone();
                match parse_params::<NotesUpdateParams>(request.params) {
                    Ok(params) => {
                        self.replay_note_mutation(
                            "notes.update",
                            &params.mutation_id,
                            &fingerprint,
                            || async {
                                self.notes
                                    .update(
                                        &self.services,
                                        &params.id,
                                        params.title,
                                        params.content,
                                        params.tags,
                                        &params.expected_revision,
                                    )
                                    .map(to_value)
                                    .map_err(notes_failure)
                            },
                        )
                        .await
                    }
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::NotesSetPinned => {
                let fingerprint = request.params.clone();
                match parse_params::<NotesSetPinnedParams>(request.params) {
                    Ok(params) => {
                        self.replay_note_mutation(
                            "notes.set-pinned",
                            &params.mutation_id,
                            &fingerprint,
                            || async {
                                self.notes
                                    .set_pinned(
                                        &self.services,
                                        &params.id,
                                        params.pinned,
                                        &params.expected_revision,
                                    )
                                    .map(to_value)
                                    .map_err(notes_failure)
                            },
                        )
                        .await
                    }
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::NotesAddTag => {
                let fingerprint = request.params.clone();
                match parse_params::<NotesTagParams>(request.params) {
                    Ok(params) => {
                        self.replay_note_mutation(
                            "notes.add-tag",
                            &params.mutation_id,
                            &fingerprint,
                            || async {
                                self.notes
                                    .add_tag(
                                        &self.services,
                                        &params.id,
                                        params.tag,
                                        &params.expected_revision,
                                    )
                                    .map(to_value)
                                    .map_err(notes_failure)
                            },
                        )
                        .await
                    }
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::NotesRemoveTag => {
                let fingerprint = request.params.clone();
                match parse_params::<NotesTagParams>(request.params) {
                    Ok(params) => {
                        self.replay_note_mutation(
                            "notes.remove-tag",
                            &params.mutation_id,
                            &fingerprint,
                            || async {
                                self.notes
                                    .remove_tag(
                                        &self.services,
                                        &params.id,
                                        &params.tag,
                                        &params.expected_revision,
                                    )
                                    .map(to_value)
                                    .map_err(notes_failure)
                            },
                        )
                        .await
                    }
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::NotesPlanDelete => {
                let fingerprint = request.params.clone();
                match parse_params::<NotesDeletePlanParams>(request.params) {
                    Ok(params) => {
                        self.replay_note_mutation(
                            "notes.delete.plan",
                            &params.mutation_id,
                            &fingerprint,
                            || async {
                                self.notes
                                    .plan_delete(
                                        &self.services,
                                        &params.id,
                                        &params.expected_revision,
                                    )
                                    .map(to_value)
                                    .map_err(notes_failure)
                            },
                        )
                        .await
                    }
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::NotesConfirmDelete => {
                let fingerprint = request.params.clone();
                match parse_params::<NotesConfirmDeleteParams>(request.params) {
                    Ok(params) => {
                        self.replay_note_mutation(
                            "notes.delete.confirm",
                            &params.mutation_id,
                            &fingerprint,
                            || async {
                                self.notes
                                    .confirm_delete(&self.services, &params.handle)
                                    .await
                                    .map(to_value)
                                    .map_err(notes_failure)
                            },
                        )
                        .await
                    }
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::NotesCancelDelete => {
                let fingerprint = request.params.clone();
                match parse_params::<NotesConfirmDeleteParams>(request.params) {
                    Ok(params) => {
                        self.replay_note_mutation(
                            "notes.delete.cancel",
                            &params.mutation_id,
                            &fingerprint,
                            || async {
                                self.notes
                                    .cancel_delete(&params.handle)
                                    .map(to_value)
                                    .map_err(notes_failure)
                            },
                        )
                        .await
                    }
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::NotesExport => {
                parse_params::<NotesExportParams>(request.params).and_then(|params| {
                    self.notes
                        .export(&self.services, params.id.as_deref())
                        .map(to_value)
                        .map_err(notes_failure)
                })
            }
        };

        match result {
            Ok(Ok(value)) => RpcResponse::success(request_id, value),
            Ok(Err(error)) => {
                tracing::error!(operation = "serialize RPC result", error = %error);
                RpcResponse::failure(
                    Some(request_id),
                    "response-encoding-failed",
                    "The backend could not encode its response.",
                )
            }
            Err(failure) => {
                if let Some(source) = failure.source {
                    tracing::error!(operation = failure.operation, error = %source);
                }
                RpcResponse::failure(Some(request_id), failure.code, failure.public_message)
            }
        }
    }

    /// The in-process entry point for the desktop host.
    ///
    /// Same method table, parameter parsing, error codes and size bounds as a
    /// stdio frame, so a host that links the backend directly cannot reach
    /// anything the process boundary would have refused.
    pub async fn call(&self, method: &str, params: Value) -> Result<Value, BackendCallError> {
        let Ok(method) = serde_json::from_value::<RpcMethod>(Value::String(method.to_owned()))
        else {
            return Err(BackendCallError::INVALID_REQUEST);
        };
        if encoded_len_exceeds(&params, MAX_REQUEST_BYTES) {
            return Err(BackendCallError::REQUEST_TOO_LARGE);
        }
        let response = self
            .dispatch(RpcRequest {
                protocol: PROTOCOL_VERSION.to_owned(),
                request_id: IN_PROCESS_REQUEST_ID.to_owned(),
                method,
                params,
            })
            .await;
        match (response.result, response.error) {
            (Some(result), None) if response.ok => {
                if encoded_len_exceeds(&result, MAX_RESPONSE_BYTES) {
                    return Err(BackendCallError::RESPONSE_TOO_LARGE);
                }
                Ok(result)
            }
            (_, Some(error)) => Err(BackendCallError {
                code: error.code,
                message: error.message,
            }),
            _ => Err(BackendCallError::RESPONSE_ENCODING_FAILED),
        }
    }

    /// Stops every terminal session; the stdio loop does the same at EOF.
    pub async fn shutdown(&self) {
        self.services.windows_incident().shutdown();
        self.terminal.shutdown().await;
    }

    fn bootstrap(&self) -> Result<BootstrapResult, RpcFailure> {
        let settings = self.services.settings().load().map_err(|error| {
            RpcFailure::core(
                "load settings for bootstrap",
                "bootstrap-failed",
                "LovelyHawk could not load its portable settings.",
                error,
            )
        })?;
        Ok(BootstrapResult {
            product_name: "LovelyHawk",
            app_version: env!("CARGO_PKG_VERSION"),
            protocol_version: PROTOCOL_VERSION,
            pages: page_descriptors(),
            security_reference_favorite_ids: settings.security_reference.favorite_ids,
        })
    }

    fn set_security_reference_favorites(
        &self,
        favorite_ids: Vec<String>,
    ) -> Result<SecurityReferenceFavoritesResult, RpcFailure> {
        self.services
            .settings()
            .update(|settings| {
                settings.security_reference.favorite_ids = favorite_ids;
                Ok(())
            })
            .map(|settings| SecurityReferenceFavoritesResult {
                favorite_ids: settings.security_reference.favorite_ids,
            })
            .map_err(|error| {
                RpcFailure::core(
                    "save security reference favorites",
                    "favorites-save-failed",
                    "LovelyHawk could not save the security-reference favorites.",
                    error,
                )
            })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RpcRequest {
    protocol: String,
    request_id: String,
    method: RpcMethod,
    params: Value,
}

impl fmt::Debug for RpcRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RpcRequest")
            .field("protocol", &self.protocol)
            .field("request_id", &self.request_id)
            .field("method", &self.method)
            .field("params", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
enum RpcMethod {
    #[serde(rename = "app.bootstrap")]
    AppBootstrap,
    #[serde(rename = "connections.list")]
    ConnectionsList,
    #[serde(rename = "connections.get")]
    ConnectionsGet,
    #[serde(rename = "connections.create")]
    ConnectionsCreate,
    #[serde(rename = "connections.update")]
    ConnectionsUpdate,
    #[serde(rename = "connections.delete.plan")]
    ConnectionsPlanDelete,
    #[serde(rename = "connections.delete.confirm")]
    ConnectionsConfirmDelete,
    #[serde(rename = "connections.delete.cancel")]
    ConnectionsCancelDelete,
    #[serde(rename = "connections.import-file")]
    ConnectionsImportFile,
    #[serde(rename = "connections.export-file")]
    ConnectionsExportFile,
    #[serde(rename = "ssh.connect.start")]
    SshConnectStart,
    #[serde(rename = "ssh.probe.start")]
    SshProbeStart,
    #[serde(rename = "ssh.attempt.get")]
    SshAttemptGet,
    #[serde(rename = "ssh.host-key.confirm")]
    SshHostKeyConfirm,
    #[serde(rename = "ssh.mfa.respond")]
    SshMfaRespond,
    #[serde(rename = "ssh.attempt.cancel")]
    SshAttemptCancel,
    #[serde(rename = "ssh.binding.disconnect")]
    SshBindingDisconnect,
    #[serde(rename = "terminal.open")]
    TerminalOpen,
    #[serde(rename = "terminal.open-directory")]
    TerminalOpenDirectory,
    #[serde(rename = "terminal.poll")]
    TerminalPoll,
    #[serde(rename = "terminal.input")]
    TerminalInput,
    #[serde(rename = "terminal.resize")]
    TerminalResize,
    #[serde(rename = "terminal.render-snapshot")]
    TerminalRenderSnapshot,
    #[serde(rename = "terminal.search")]
    TerminalSearch,
    #[serde(rename = "terminal.close")]
    TerminalClose,
    #[serde(rename = "system-info.catalog.get")]
    SystemInfoCatalogGet,
    #[serde(rename = "system-info.summary.get")]
    SystemInfoSummaryGet,
    #[serde(rename = "system-info.table.collect")]
    SystemInfoTableCollect,
    #[serde(rename = "system-info.detail.get")]
    SystemInfoDetailGet,
    #[serde(rename = "system-info.file-editor.open")]
    SystemInfoFileEditorOpen,
    #[serde(rename = "system-info.row.actions.list")]
    SystemInfoRowActionsList,
    #[serde(rename = "system-info.row.inspect")]
    SystemInfoRowInspect,
    #[serde(rename = "system-info.row.action.plan")]
    SystemInfoRowActionPlan,
    #[serde(rename = "system-info.row.action.confirm")]
    SystemInfoRowActionConfirm,
    #[serde(rename = "system-info.row.action.execute")]
    SystemInfoRowActionExecute,
    #[serde(rename = "system-info.row.action.cancel")]
    SystemInfoRowActionCancel,
    #[serde(rename = "baseline.catalog.get")]
    BaselineCatalogGet,
    #[serde(rename = "baseline.scan")]
    BaselineScan,
    #[serde(rename = "ai.assist")]
    AiAssist,
    #[serde(rename = "log.rules")]
    LogRules,
    #[serde(rename = "nginx.repair")]
    NginxRepair,
    #[serde(rename = "java.hot-update")]
    JavaHotUpdate,
    #[serde(rename = "windows.incident")]
    WindowsIncident,
    #[serde(rename = "windows.evidence.part")]
    WindowsEvidencePart,
    #[serde(rename = "java.hot-update.class.stage")]
    JavaHotUpdateClassStage,
    #[serde(rename = "postgresql.runtime")]
    PostgresqlRuntime,
    #[serde(rename = "emergency.file-evidence")]
    FileEvidence,
    #[serde(rename = "case.workspace")]
    CaseWorkspace,
    #[serde(rename = "case.library")]
    CaseLibrary,
    #[serde(rename = "baseline.history.list")]
    BaselineHistoryList,
    #[serde(rename = "baseline.file.read")]
    BaselineFileRead,
    #[serde(rename = "baseline.action.plan")]
    BaselineActionPlan,
    #[serde(rename = "baseline.action.confirm")]
    BaselineActionConfirm,
    #[serde(rename = "baseline.action.execute")]
    BaselineActionExecute,
    #[serde(rename = "baseline.action.cancel")]
    BaselineActionCancel,
    #[serde(rename = "check-audit.catalog.get")]
    CheckAuditCatalogGet,
    #[serde(rename = "check-audit.status.collect")]
    CheckAuditStatusCollect,
    #[serde(rename = "check-audit.log.read")]
    CheckAuditLogRead,
    #[serde(rename = "check-audit.action.plan")]
    CheckAuditActionPlan,
    #[serde(rename = "check-audit.action.confirm")]
    CheckAuditActionConfirm,
    #[serde(rename = "check-audit.action.execute")]
    CheckAuditActionExecute,
    #[serde(rename = "check-audit.action.cancel")]
    CheckAuditActionCancel,
    #[serde(rename = "log-analysis.sources.discover")]
    LogAnalysisSourcesDiscover,
    #[serde(rename = "log-analysis.source.read")]
    LogAnalysisSourceRead,
    #[serde(rename = "log-analysis.sources.correlate")]
    LogAnalysisSourcesCorrelate,
    #[serde(rename = "log-analysis.iocs.search")]
    LogAnalysisIocsSearch,
    #[serde(rename = "kubernetes.availability.get")]
    KubernetesAvailabilityGet,
    #[serde(rename = "kubernetes.resources.list")]
    KubernetesResourcesList,
    #[serde(rename = "kubernetes.resource.detail.get")]
    KubernetesResourceDetailGet,
    #[serde(rename = "kubernetes.pod.logs.get")]
    KubernetesPodLogsGet,
    #[serde(rename = "kubernetes.workload.action.plan")]
    KubernetesWorkloadActionPlan,
    #[serde(rename = "kubernetes.workload.action.confirm")]
    KubernetesWorkloadActionConfirm,
    #[serde(rename = "kubernetes.workload.action.execute")]
    KubernetesWorkloadActionExecute,
    #[serde(rename = "kubernetes.workload.action.cancel")]
    KubernetesWorkloadActionCancel,
    #[serde(rename = "docker.containers.refresh")]
    DockerContainersRefresh,
    #[serde(rename = "docker.collection.get")]
    DockerCollectionGet,
    #[serde(rename = "docker.resource.inspect")]
    DockerResourceInspect,
    #[serde(rename = "docker.security.audit.get")]
    DockerSecurityAuditGet,
    #[serde(rename = "docker.container.logs.get")]
    DockerContainerLogsGet,
    #[serde(rename = "docker.container.changes.get")]
    DockerContainerChangesGet,
    #[serde(rename = "docker.container.processes.get")]
    DockerContainerProcessesGet,
    #[serde(rename = "docker.container.action.plan")]
    DockerContainerActionPlan,
    #[serde(rename = "docker.container.action.confirm")]
    DockerContainerActionConfirm,
    #[serde(rename = "docker.container.action.execute")]
    DockerContainerActionExecute,
    #[serde(rename = "docker.container.action.cancel")]
    DockerContainerActionCancel,
    #[serde(rename = "docker.container.file.read")]
    DockerContainerFileRead,
    #[serde(rename = "docker.container.file.plan-write")]
    DockerContainerFilePlanWrite,
    #[serde(rename = "docker.container.file.plan-copy")]
    DockerContainerFilePlanCopy,
    #[serde(rename = "docker.container.terminal.open")]
    DockerContainerTerminalOpen,
    #[serde(rename = "kubernetes.pod.terminal.open")]
    KubernetesPodTerminalOpen,
    /// For the host's save dialog only: the contents never go to a page.
    #[serde(rename = "kubernetes.manifest.export")]
    KubernetesManifestExport,
    #[serde(rename = "docker.container.directory.list")]
    DockerContainerDirectoryList,
    #[serde(rename = "kubernetes.pod.directory.list")]
    KubernetesPodDirectoryList,
    #[serde(rename = "kubernetes.pod.file.read")]
    KubernetesPodFileRead,
    #[serde(rename = "emergency-command.catalog.load")]
    EmergencyCommandCatalogLoad,
    #[serde(rename = "emergency-command.run")]
    EmergencyCommandRun,
    #[serde(rename = "emergency-command.history.locate")]
    EmergencyCommandHistoryLocate,
    #[serde(rename = "emergency-command.path.inspect")]
    EmergencyCommandPathInspect,
    #[serde(rename = "emergency-command.path.plan")]
    EmergencyCommandPathPlan,
    #[serde(rename = "emergency-command.path.confirm")]
    EmergencyCommandPathConfirm,
    #[serde(rename = "emergency-command.path.execute")]
    EmergencyCommandPathExecute,
    #[serde(rename = "emergency-command.path.cancel")]
    EmergencyCommandPathCancel,
    #[serde(rename = "emergency-command.path.undo")]
    EmergencyCommandPathUndo,
    #[serde(rename = "sftp-browser.open")]
    SftpBrowserOpen,
    #[serde(rename = "sftp-browser.directory.list")]
    SftpBrowserDirectoryList,
    #[serde(rename = "sftp-browser.text.read")]
    SftpBrowserTextRead,
    #[serde(rename = "sftp-browser.download")]
    SftpBrowserDownload,
    #[serde(rename = "sftp-browser.operation.plan")]
    SftpBrowserOperationPlan,
    #[serde(rename = "sftp-browser.operation.confirm")]
    SftpBrowserOperationConfirm,
    #[serde(rename = "sftp-browser.operation.execute")]
    SftpBrowserOperationExecute,
    #[serde(rename = "sftp-browser.operation.cancel")]
    SftpBrowserOperationCancel,
    #[serde(rename = "sftp-browser.operation.undo")]
    SftpBrowserOperationUndo,
    #[serde(rename = "sftp-browser.transfer.cancel")]
    SftpBrowserTransferCancel,
    #[serde(rename = "sftp-browser.upload.stage")]
    SftpBrowserUploadStage,
    #[serde(rename = "packet-capture.interfaces.list")]
    PacketCaptureInterfacesList,
    #[serde(rename = "packet-capture.start")]
    PacketCaptureStart,
    #[serde(rename = "packet-capture.poll")]
    PacketCapturePoll,
    #[serde(rename = "packet-capture.stop")]
    PacketCaptureStop,
    #[serde(rename = "packet-capture.evidence")]
    PacketCaptureEvidence,
    #[serde(rename = "kubernetes.pod.file-evidence")]
    KubernetesPodFileEvidence,
    #[serde(rename = "application-log.list")]
    ApplicationLogList,
    #[serde(rename = "application-log.level.set")]
    ApplicationLogLevelSet,
    #[serde(rename = "application-log.buffer.clear")]
    ApplicationLogBufferClear,
    #[serde(rename = "application-log.preview.get")]
    ApplicationLogPreviewGet,
    #[serde(rename = "application-log.export.prepare")]
    ApplicationLogExportPrepare,
    #[serde(rename = "integrity.presets.get")]
    IntegrityPresetsGet,
    #[serde(rename = "integrity.baselines.list")]
    IntegrityBaselinesList,
    #[serde(rename = "integrity.comparison.start")]
    IntegrityComparisonStart,
    #[serde(rename = "integrity.comparison.poll")]
    IntegrityComparisonPoll,
    #[serde(rename = "integrity.comparison.cancel")]
    IntegrityComparisonCancel,
    #[serde(rename = "integrity.baseline.create.start")]
    IntegrityBaselineCreateStart,
    #[serde(rename = "integrity.baseline.create.poll")]
    IntegrityBaselineCreatePoll,
    #[serde(rename = "integrity.baseline.create.cancel")]
    IntegrityBaselineCreateCancel,
    #[serde(rename = "settings.get")]
    SettingsGet,
    #[serde(rename = "settings.save")]
    SettingsSave,
    #[serde(rename = "settings.ai-api-key.replace")]
    SettingsAiApiKeyReplace,
    #[serde(rename = "settings.ai-api-key.clear.plan")]
    SettingsAiApiKeyClearPlan,
    #[serde(rename = "settings.ai-provider.remove.plan")]
    SettingsAiProviderRemovePlan,
    #[serde(rename = "settings.mutation.confirm")]
    SettingsMutationConfirm,
    #[serde(rename = "settings.mutation.cancel")]
    SettingsMutationCancel,
    #[serde(rename = "ai-history.list")]
    AiHistoryList,
    #[serde(rename = "ai-history.get")]
    AiHistoryGet,
    #[serde(rename = "ai-history.remove.plan")]
    AiHistoryPlanRemove,
    #[serde(rename = "ai-history.clear.plan")]
    AiHistoryPlanClear,
    #[serde(rename = "ai-history.mutation.confirm")]
    AiHistoryConfirmMutation,
    #[serde(rename = "ai-history.mutation.cancel")]
    AiHistoryCancelMutation,
    #[serde(rename = "ai-history.export")]
    AiHistoryExport,
    #[serde(rename = "command-history.list")]
    CommandHistoryList,
    #[serde(rename = "command-history.get")]
    CommandHistoryGet,
    #[serde(rename = "command-history.replay.plan")]
    CommandHistoryPlanReplay,
    #[serde(rename = "command-history.remove.plan")]
    CommandHistoryPlanRemove,
    #[serde(rename = "command-history.clear.plan")]
    CommandHistoryPlanClear,
    #[serde(rename = "command-history.mutation.confirm")]
    CommandHistoryConfirmMutation,
    #[serde(rename = "command-history.mutation.cancel")]
    CommandHistoryCancelMutation,
    #[serde(rename = "disposal-report.generate")]
    DisposalReportGenerate,
    #[serde(rename = "disposal-report.content.get")]
    DisposalReportContentGet,
    #[serde(rename = "disposal-report.export")]
    DisposalReportExport,
    #[serde(rename = "config.catalog.get")]
    ConfigCatalogGet,
    #[serde(rename = "config.quick.generate")]
    ConfigQuickGenerate,
    #[serde(rename = "config.quick.revise")]
    ConfigQuickRevise,
    #[serde(rename = "config.quick.copy")]
    ConfigQuickCopy,
    #[serde(rename = "config.quick.close")]
    ConfigQuickClose,
    #[serde(rename = "config.visual")]
    ConfigVisual,
    #[serde(rename = "config.quick.artifact")]
    ConfigQuickArtifact,
    #[serde(rename = "config.quick.bundle.export")]
    ConfigQuickBundleExport,
    #[serde(rename = "security-reference.set-favorites")]
    SecurityReferenceSetFavorites,
    #[serde(rename = "notes.list")]
    NotesList,
    #[serde(rename = "notes.get")]
    NotesGet,
    #[serde(rename = "notes.create")]
    NotesCreate,
    #[serde(rename = "notes.update")]
    NotesUpdate,
    #[serde(rename = "notes.set-pinned")]
    NotesSetPinned,
    #[serde(rename = "notes.add-tag")]
    NotesAddTag,
    #[serde(rename = "notes.remove-tag")]
    NotesRemoveTag,
    #[serde(rename = "notes.delete.plan")]
    NotesPlanDelete,
    #[serde(rename = "notes.delete.confirm")]
    NotesConfirmDelete,
    #[serde(rename = "notes.delete.cancel")]
    NotesCancelDelete,
    #[serde(rename = "notes.export")]
    NotesExport,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyParams {}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConnectionIdParams {
    id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConnectionDeleteConfirmParams {
    handle: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectionFileParams {
    path: PathBuf,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SshConnectStartParams {
    connection_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SshAttemptParams {
    attempt_handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SshPromptParams {
    attempt_handle: String,
    prompt_handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SshMfaRespondParams {
    attempt_handle: String,
    prompt_handle: String,
    responses: SecretResponses,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SshBindingParams {
    binding_handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TerminalOpenParams {
    binding_handle: String,
    columns: u16,
    rows: u16,
}

/// A shell in a folder the file browser listed: the folder is the browser's
/// own handle, never a path.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TerminalOpenDirectoryParams {
    binding_handle: String,
    browser_handle: String,
    directory_handle: String,
    columns: u16,
    rows: u16,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TerminalPollParams {
    handle: String,
    maximum_events: usize,
    maximum_bytes: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TerminalInputParams {
    handle: String,
    bytes_base64: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TerminalResizeParams {
    handle: String,
    columns: u16,
    rows: u16,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TerminalHandleParams {
    handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TerminalSearchParams {
    handle: String,
    query: String,
    case_sensitive: bool,
    regex: bool,
    maximum_results: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SystemInfoBindingParams {
    binding_handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SystemInfoCollectParams {
    binding_handle: String,
    tab: String,
    maximum_rows: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SystemInfoDetailParams {
    binding_handle: String,
    snapshot_handle: String,
    row_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SystemInfoRowActionParams {
    binding_handle: String,
    snapshot_handle: String,
    row_id: String,
    /// One of the fixed keys the sidecar hands out; anything else is nothing.
    action: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SystemInfoPlanParams {
    binding_handle: String,
    plan_handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BaselineBindingParams {
    binding_handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BaselineFileParams {
    binding_handle: String,
    /// Which catalogue item to open the file of. Never a path.
    item_handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CheckAuditCatalogParams {
    binding_handle: String,
    input: CheckAuditCatalogInput,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CheckAuditSnapshotParams {
    binding_handle: String,
    snapshot_handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BaselineActionPlanParams {
    binding_handle: String,
    action: baseline_write_api::BaselineAction,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BaselinePlanParams {
    binding_handle: String,
    plan_handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CheckAuditActionPlanParams {
    binding_handle: String,
    snapshot_handle: String,
    action: check_audit_write_api::CheckAuditAction,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CheckAuditPlanParams {
    binding_handle: String,
    plan_handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CheckAuditLogParams {
    binding_handle: String,
    snapshot_handle: String,
    input: CheckAuditLogInput,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LogAnalysisBindingParams {
    binding_handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LogAnalysisSourceReadParams {
    binding_handle: String,
    snapshot_handle: String,
    source_handle: String,
    input: LogSourceReadInput,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LogAnalysisCorrelationParams {
    binding_handle: String,
    snapshot_handle: String,
    input: LogCorrelationInput,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LogAnalysisIocSearchParams {
    binding_handle: String,
    snapshot_handle: String,
    input: LogIocSearchInput,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KubernetesBindingParams {
    binding_handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KubernetesListParams {
    binding_handle: String,
    input: KubernetesListInput,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KubernetesRowParams {
    binding_handle: String,
    snapshot_handle: String,
    row_handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KubernetesPodLogsParams {
    binding_handle: String,
    snapshot_handle: String,
    row_handle: String,
    /// The logs of the container's previous run — what a crash-looping pod
    /// printed before it died — instead of the current one's.
    #[serde(default)]
    previous: bool,
    /// One of the listed pod's containers; none for its default one.
    #[serde(default)]
    container: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KubernetesActionPlanParams {
    binding_handle: String,
    snapshot_handle: String,
    /// Which workload, as the snapshot that listed it named it. Never a
    /// namespace, a name or a UID.
    row_handle: String,
    /// The name the pane is showing, echoed back so the confirmation dialog
    /// can say what it is about to act on. Display only: the workload is
    /// resolved from the handle above, so a forged name mislabels nothing but
    /// the operator's own dialog.
    resource_name: String,
    action: KubernetesWriteAction,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KubernetesPlanParams {
    binding_handle: String,
    plan_handle: String,
}

/// Opening a shell inside a pod a Kubernetes list already showed. As for a
/// container: no shell program, no namespace, no pod name. A container may
/// be named, but only one of the pod's listed ones (checked by core).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KubernetesPodTerminalOpenParams {
    binding_handle: String,
    snapshot_handle: String,
    row_handle: String,
    #[serde(default)]
    container: Option<String>,
    columns: u16,
    rows: u16,
}

/// A listed Pod, Deployment or Node, by its list handles only: no kind, no
/// namespace, no name.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KubernetesManifestExportParams {
    binding_handle: String,
    snapshot_handle: String,
    row_handle: String,
}

/// A path inside a pod a Kubernetes list showed, for listing or reading. The
/// pod is the row handle's; the path is checked here and listed or read by a
/// fixed script, in the container named (one of the pod's) or its default.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KubernetesPodPathParams {
    binding_handle: String,
    snapshot_handle: String,
    row_handle: String,
    path: String,
    #[serde(default)]
    container: Option<String>,
}

/// A pod file's text with the length and digest it was checked against.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PodFileDto {
    path: String,
    text: String,
    bytes: u64,
    sha256: String,
}

/// Listing or reading inside a container or pod: the core's own limits are
/// 20–30 s per command, and a read is three of them.
const EXEC_FILE_DEADLINE: Duration = Duration::from_secs(90);

fn exec_deadline() -> RpcFailure {
    RpcFailure {
        operation: "bound container file operation",
        code: "container-exec-timeout",
        public_message: "容器或 Pod 里的操作超出时限，没有结果。",
        source: None,
    }
}

fn exec_directory_path(path: &str) -> Result<RemotePath, RpcFailure> {
    RemotePath::new(path).map_err(|_| RpcFailure {
        operation: "validate directory path",
        code: "invalid-params",
        public_message: "The directory path must be an absolute path.",
        source: None,
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DockerBindingParams {
    binding_handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DockerCollectionParams {
    binding_handle: String,
    snapshot_handle: String,
    kind: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DockerInspectParams {
    binding_handle: String,
    snapshot_handle: String,
    kind: String,
    resource_handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DockerSnapshotParams {
    binding_handle: String,
    snapshot_handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DockerLogsParams {
    binding_handle: String,
    snapshot_handle: String,
    container_handle: String,
    tail: usize,
}

/// A container the pane listed, for a read that takes nothing else.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DockerContainerReadParams {
    binding_handle: String,
    snapshot_handle: String,
    container_handle: String,
}

/// What the window needs once a container shell is open.
///
/// `shell` is there so the window can say which shell it got: on an image with
/// no bash, landing in `sh` without being told reads as the terminal being
/// broken rather than as the image being thin.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DockerContainerTerminalDto {
    handle: String,
    columns: u16,
    rows: u16,
    shell: &'static str,
}

/// Opening a shell inside a container the pane already listed.
///
/// No shell program and no container id: the shell is probed on the host and
/// the container comes from the same opaque handle every other Docker call
/// takes, so a caller cannot name a container the pane never showed it.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DockerTerminalOpenParams {
    binding_handle: String,
    snapshot_handle: String,
    container_handle: String,
    columns: u16,
    rows: u16,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DockerActionPlanParams {
    binding_handle: String,
    snapshot_handle: String,
    /// Which container, as the snapshot that listed it named it. Never an id.
    container_handle: String,
    /// The name the pane is showing, echoed back so the confirmation dialog
    /// can say what it is about to act on. Display only: the identity is
    /// resolved from the handle above, so a forged name mislabels nothing but
    /// the operator's own dialog.
    container_name: String,
    action: DockerWriteAction,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DockerPlanParams {
    binding_handle: String,
    plan_handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EmergencyCommandBindingParams {
    binding_handle: String,
}

// Container file parameters, kept apart from the Docker read and action
// parameters above on purpose. Those carry only handles, and a test holds
// them to that. Editing or copying a file has to name it, so these carry a
// path inside the container or on the connected host — typed and validated
// by the core, never a path on the operator's computer, and every change
// still goes plan, confirm, read-back and backup. Their own test pins exactly
// which fields they may carry.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DockerFileReadParams {
    binding_handle: String,
    snapshot_handle: String,
    container_handle: String,
    /// Display only, as for actions: the container is the handle's.
    container_name: String,
    path: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DockerFileWriteParams {
    binding_handle: String,
    /// The file as `docker.container.file.read` opened it; never a path.
    file_handle: String,
    text: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DockerFileCopyParams {
    binding_handle: String,
    snapshot_handle: String,
    container_handle: String,
    container_name: String,
    direction: DockerFileCopyDirection,
    source: String,
    target: String,
}

/// One directory inside a listed container, to browse to a file: read-only,
/// listed by a fixed script, the path checked as for a file read.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContainerDirectoryListParams {
    binding_handle: String,
    snapshot_handle: String,
    container_handle: String,
    path: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EmergencyCommandRunParams {
    binding_handle: String,
    snapshot_handle: String,
    command_handle: String,
    /// Absent runs the check on the target itself; present runs it inside one
    /// of the containers the same catalogue offered.
    #[serde(default)]
    container_handle: Option<String>,
}

/// A history record and the catalogue to find its check in; the record's own
/// entry never comes from the page.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EmergencyCommandHistoryLocateParams {
    binding_handle: String,
    snapshot_handle: String,
    history_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EmergencyCommandPathParams {
    binding_handle: String,
    path_handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EmergencyCommandPathPlanParams {
    binding_handle: String,
    path_handle: String,
    action: EmergencyPathAction,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EmergencyCommandPathPlanHandleParams {
    binding_handle: String,
    plan_handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SftpBrowserBindingParams {
    binding_handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SftpBrowserDirectoryParams {
    binding_handle: String,
    browser_handle: String,
    directory_handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SftpBrowserPlanParams {
    binding_handle: String,
    plan_handle: String,
}

/// Which browser's running transfers to stop.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SftpBrowserTransferParams {
    binding_handle: String,
    browser_handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SftpBrowserStageParams {
    binding_handle: String,
    /// Chosen by the operator in the native open dialog and forwarded by main.
    local_path: String,
    name: String,
}

/// A replacement class file for Java hot update. Host-only, like the SFTP
/// upload stage: the path comes from the native open dialog, never a page.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JavaClassStageParams {
    binding_handle: String,
    local_path: String,
    name: String,
}

/// One shape for every planned operation: the kind decides which capabilities
/// have to be present, and anything else is refused before the core sees it.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SftpBrowserOperationParams {
    binding_handle: String,
    browser_handle: String,
    kind: String,
    #[serde(default)]
    entry_handles: Vec<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    mode: Option<u32>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    staged_handle: Option<String>,
    /// The edited text, for `write-text` and nothing else.
    #[serde(default)]
    text: Option<String>,
    /// The hash the read handed out, so the write can refuse a file that has
    /// changed underneath the editor since it was opened.
    #[serde(default)]
    expected_sha256: Option<String>,
}

impl SftpBrowserOperationParams {
    fn to_request(&self) -> Result<(String, SftpOperationRequest), RpcFailure> {
        let single = || -> Result<String, RpcFailure> {
            match self.entry_handles.as_slice() {
                [handle] => Ok(handle.clone()),
                _ => Err(sftp_browser_request_failure()),
            }
        };
        let name = || -> Result<String, RpcFailure> {
            self.name.clone().ok_or_else(sftp_browser_request_failure)
        };
        let operation = match self.kind.as_str() {
            "create-directory" => SftpOperationRequest::CreateDirectory {
                directory_handle: single()?,
                name: name()?,
            },
            "rename" => SftpOperationRequest::Rename {
                entry_handle: single()?,
                name: name()?,
            },
            "chmod" => SftpOperationRequest::Chmod {
                entry_handle: single()?,
                mode: self.mode.ok_or_else(sftp_browser_request_failure)?,
            },
            "remove" => SftpOperationRequest::Remove {
                entry_handle: single()?,
            },
            "archive" => SftpOperationRequest::Archive {
                entry_handles: self.entry_handles.clone(),
                name: name()?,
                format: self
                    .format
                    .clone()
                    .ok_or_else(sftp_browser_request_failure)?,
            },
            "upload" => SftpOperationRequest::Upload {
                directory_handle: single()?,
                staged_handle: self
                    .staged_handle
                    .clone()
                    .ok_or_else(sftp_browser_request_failure)?,
                name: name()?,
            },
            "write-text" => SftpOperationRequest::WriteText {
                entry_handle: single()?,
                text: self.text.clone().ok_or_else(sftp_browser_request_failure)?,
                expected_sha256: self
                    .expected_sha256
                    .clone()
                    .ok_or_else(sftp_browser_request_failure)?,
            },
            _ => return Err(sftp_browser_request_failure()),
        };
        Ok((self.browser_handle.clone(), operation))
    }
}

fn sftp_browser_request_failure() -> RpcFailure {
    RpcFailure {
        operation: "validate SFTP browser operation request",
        code: "sftp-browser-invalid",
        public_message: "The SFTP browser request parameters are invalid.",
        source: None,
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SftpBrowserDownloadParams {
    binding_handle: String,
    browser_handle: String,
    file_handle: String,
    /// Chosen by the operator in the native save dialog and forwarded by main.
    local_path: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SftpBrowserFileParams {
    binding_handle: String,
    browser_handle: String,
    file_handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PacketCaptureBindingParams {
    binding_handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PacketCaptureStartParams {
    binding_handle: String,
    interface_handle: String,
    input: PacketCaptureStartInput,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PacketCapturePollParams {
    binding_handle: String,
    capture_handle: String,
    after_sequence: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PacketCaptureHandleParams {
    binding_handle: String,
    capture_handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApplicationLogFilterParams {
    filter: DiagnosticLogFilterInput,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApplicationLogLevelParams {
    level: DiagnosticLogLevel,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IntegrityBindingParams {
    binding_handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IntegrityBaselineParams {
    binding_handle: String,
    baseline_handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IntegrityPollParams {
    binding_handle: String,
    operation_handle: String,
    after_event: u64,
    limit: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IntegrityOperationParams {
    binding_handle: String,
    operation_handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SettingsProviderParams {
    provider_id: String,
}

// The one integrity request that writes (a new baseline), kept outside the
// read-only integrity params above, whose test forbids any such field. It is
// pinned by its own test instead: a binding and preset ids, nothing else.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IntegrityCreateParams {
    binding_handle: String,
    preset_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SettingsMutationParams {
    mutation_handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AiHistoryListParams {
    query: String,
    offset: usize,
    limit: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AiHistoryIdParams {
    id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AiHistoryHandleParams {
    handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AiHistoryExportParams {
    format: AiHistoryExportFormat,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CommandHistoryListParams {
    binding_handle: String,
    query: String,
    offset: usize,
    limit: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CommandHistoryBindingParams {
    binding_handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CommandHistoryRecordParams {
    binding_handle: String,
    record_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CommandHistoryMutationParams {
    binding_handle: String,
    mutation_handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DisposalReportBindingParams {
    binding_handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DisposalReportContentParams {
    binding_handle: String,
    report_handle: String,
    format: DisposalReportPreviewFormat,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DisposalReportExportParams {
    binding_handle: String,
    report_handle: String,
    format: ReportFormat,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfigReviseParams {
    handle: String,
    revision: u64,
    input: ConfigGenerateInput,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfigDraftParams {
    handle: String,
    revision: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfigArtifactParams {
    handle: String,
    revision: u64,
    artifact_key: String,
}

/// Host-only: the folder comes from the host's own folder dialog.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfigBundleExportParams {
    handle: String,
    revision: u64,
    parent_directory: PathBuf,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SetSecurityReferenceFavoritesParams {
    favorite_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NotesListParams {
    #[serde(default)]
    query: Option<String>,
    offset: usize,
    limit: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NoteIdParams {
    id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NotesCreateParams {
    mutation_id: String,
    #[serde(default)]
    title: Option<String>,
    content: String,
    tags: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NotesUpdateParams {
    id: String,
    expected_revision: String,
    mutation_id: String,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NotesSetPinnedParams {
    id: String,
    expected_revision: String,
    mutation_id: String,
    pinned: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NotesTagParams {
    id: String,
    expected_revision: String,
    mutation_id: String,
    tag: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NotesDeletePlanParams {
    id: String,
    expected_revision: String,
    mutation_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NotesConfirmDeleteParams {
    handle: String,
    mutation_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NotesExportParams {
    #[serde(default)]
    id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RpcResponse {
    protocol: &'static str,
    request_id: Option<String>,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
}

impl RpcResponse {
    fn success(request_id: String, result: Value) -> Self {
        Self {
            protocol: PROTOCOL_VERSION,
            request_id: Some(request_id),
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    fn failure(request_id: Option<String>, code: &'static str, message: &'static str) -> Self {
        Self {
            protocol: PROTOCOL_VERSION,
            request_id,
            ok: false,
            result: None,
            error: Some(RpcError { code, message }),
        }
    }
}

#[derive(Debug, Serialize)]
struct RpcError {
    code: &'static str,
    message: &'static str,
}

#[derive(Debug)]
struct RpcFailure {
    operation: &'static str,
    code: &'static str,
    public_message: &'static str,
    source: Option<Box<CoreError>>,
}

impl RpcFailure {
    fn invalid_params() -> Self {
        Self {
            operation: "validate RPC parameters",
            code: "invalid-params",
            public_message: "The request parameters are invalid.",
            source: None,
        }
    }

    fn core(
        operation: &'static str,
        code: &'static str,
        public_message: &'static str,
        source: CoreError,
    ) -> Self {
        Self {
            operation,
            code,
            public_message,
            source: Some(Box::new(source)),
        }
    }

    fn note_replay_conflict() -> Self {
        Self {
            operation: "validate notes idempotency key",
            code: "notes-idempotency-conflict",
            public_message: "The notes mutation key was already used for a different request.",
            source: None,
        }
    }

    fn note_replay_capacity() -> Self {
        Self {
            operation: "bound notes mutation replay state",
            code: "notes-idempotency-capacity",
            public_message: "Too many notes mutations are awaiting bounded replay expiry.",
            source: None,
        }
    }
}

fn notes_failure(error: NotesApiError) -> RpcFailure {
    match error {
        NotesApiError::Core(source) => {
            let (code, message) = match &source {
                CoreError::NotFound { .. } => {
                    ("note-not-found", "The requested note does not exist.")
                }
                CoreError::Validation { subject, .. } if *subject == "note revision" => (
                    "notes-revision-conflict",
                    "The note changed after it was read. Reload it before retrying.",
                ),
                _ => (
                    "notes-operation-failed",
                    "LovelyHawk could not complete the notes operation.",
                ),
            };
            RpcFailure::core("run portable notes operation", code, message, source)
        }
        NotesApiError::InvalidPage => RpcFailure {
            operation: "validate notes page",
            code: "invalid-params",
            public_message: "The notes page parameters are invalid.",
            source: None,
        },
        NotesApiError::InvalidDeletePlan => RpcFailure {
            operation: "consume notes delete plan",
            code: "delete-plan-invalid",
            public_message: "The delete plan is missing, expired, or already consumed.",
            source: None,
        },
        NotesApiError::DeletePlanCapacity => RpcFailure {
            operation: "store notes delete plan",
            code: "delete-plan-capacity",
            public_message: "Too many delete confirmations are pending.",
            source: None,
        },
        NotesApiError::ExportTooLarge => RpcFailure {
            operation: "prepare notes clipboard export",
            code: "notes-export-too-large",
            public_message: "The notes export is too large for the bounded clipboard channel.",
            source: None,
        },
    }
}

fn connections_failure(error: CoreError) -> RpcFailure {
    let (code, public_message) = match &error {
        CoreError::Validation { .. } => {
            ("connection-invalid", "The connection request is invalid.")
        }
        CoreError::NotFound { .. } => (
            "connection-not-found",
            "The requested connection or delete plan was not found.",
        ),
        CoreError::ConfirmationRequired { .. }
        | CoreError::OperationCancelled { .. }
        | CoreError::InvalidOperationState { .. } => (
            "connection-delete-invalid",
            "The connection delete request is no longer valid.",
        ),
        // An import file that does not decode is a validation error in core,
        // so a decode failure here is the local store itself.
        CoreError::Decode { .. } | CoreError::UnsupportedSchema { .. } => (
            "connections-store-unreadable",
            "The saved connection store could not be read.",
        ),
        _ => (
            "connections-operation-failed",
            "LovelyHawk could not complete the connection operation.",
        ),
    };
    RpcFailure::core(
        "run portable connection operation",
        code,
        public_message,
        error,
    )
}

fn ssh_failure(error: CoreError) -> RpcFailure {
    let (code, public_message) = match &error {
        CoreError::Validation { .. } => ("ssh-invalid", "The SSH request is invalid."),
        CoreError::NotFound { .. } => (
            "ssh-capability-not-found",
            "The SSH attempt, prompt, binding, or connection is missing or expired.",
        ),
        _ => (
            "ssh-controller-failed",
            "LovelyHawk could not complete the SSH controller operation.",
        ),
    };
    RpcFailure::core("run SSH controller operation", code, public_message, error)
}

/// Two different problems, told apart before they reach an operator.
///
/// A stopped container and an image with no shell both fail the same probe,
/// and flattening them into one message sent the operator to rebuild an image
/// when all they had to do was start the container. The subject on the core
/// error is what separates them.
fn container_shell_failure(error: CoreError) -> RpcFailure {
    // Asking the host which shell the image has is the first thing that
    // touches the target. If the connection is gone that is the answer — not
    // "this container has no shell".
    if matches!(error, CoreError::SshDisconnected { .. }) {
        return RpcFailure::core(
            "detect container shell",
            "docker-binding-unavailable",
            "The SSH connection to the target is gone.",
            error,
        );
    }
    let not_running = matches!(
        &error,
        CoreError::Validation { subject, .. } if *subject == "container terminal"
    );
    if not_running {
        return RpcFailure::core(
            "open a shell in a container",
            "docker-container-not-running",
            "这个容器没在运行，先把它启动起来才能进终端。",
            error,
        );
    }
    RpcFailure::core(
        "detect container shell",
        "docker-container-shell-missing",
        "这个容器里没有可用的 shell（bash、ash、sh 都没有），打不开终端。",
        error,
    )
}

/// Why a pod shell did not open, in the terms the operator can act on: the
/// pod moved on (replaced, deleting, not running) or its image has no shell.
/// The subject on the core error separates them, as for a container.
fn pod_shell_failure(error: CoreError) -> RpcFailure {
    match &error {
        // The SSH host that runs kubectl went away: not the pod, not RBAC.
        CoreError::SshDisconnected { .. } => RpcFailure::core(
            "run kubectl exec in a pod",
            "kubernetes-binding-unavailable",
            "The SSH connection to the target is gone.",
            error,
        ),
        CoreError::Validation { subject, .. } if *subject == "Kubernetes pod shell" => {
            RpcFailure::core(
                "open a shell in a pod",
                "kubernetes-pod-not-running",
                "这个 Pod 已不是列表里那个运行中的 Pod（停止、正在删除或已重建），请刷新列表后再试。",
                error,
            )
        }
        CoreError::Validation { subject, message }
            if *subject == "Kubernetes pod container" && message.contains("没有在运行") =>
        {
            RpcFailure::core(
                "check the chosen pod container",
                "kubernetes-pod-container-not-running",
                "所选的容器现在没有在运行（可能正在重启或已经退出），请刷新列表后再试。",
                error,
            )
        }
        CoreError::Validation { subject, .. }
            if *subject == "Kubernetes pod container"
                || *subject == "Kubernetes container name" =>
        {
            RpcFailure::core(
                "check the chosen pod container",
                "kubernetes-pod-container-unavailable",
                "这个 Pod 里没有所选的容器，请刷新列表后重新选择。",
                error,
            )
        }
        CoreError::Validation { subject, .. } if *subject == "container shell" => RpcFailure::core(
            "detect pod shell",
            "kubernetes-pod-shell-missing",
            "这个 Pod 的容器里没有可用的 shell（bash、ash、sh 都没有），打不开终端。",
            error,
        ),
        CoreError::Validation { subject, .. } if *subject == "Kubernetes pod exec" => {
            RpcFailure::core(
                "run kubectl exec in a pod",
                "kubernetes-pod-exec-forbidden",
                "当前账号没有在这个 Pod 里执行命令（pods/exec）的权限，终端和文件浏览都用不了。请换有权限的 kubeconfig 或账号。",
                error,
            )
        }
        // The pod itself could not be re-read: this account may not even get it.
        CoreError::Validation { subject, .. } if *subject == "Kubernetes permission" => {
            RpcFailure::core(
                "re-read a pod before using it",
                "kubernetes-forbidden",
                "集群拒绝了当前账号的这次读取（权限不足）。请换有权限的 kubeconfig 或账号。",
                error,
            )
        }
        _ => RpcFailure::core(
            "run kubectl exec in a pod",
            "kubernetes-pod-exec-failed",
            "kubectl exec 没有成功：可能是当前账号没有 exec 权限、镜像里没有 /bin/sh，或集群连不上。",
            error,
        ),
    }
}

/// A directory that could not be listed, in a container or a pod. The core's
/// sentences for the two answers an operator can act on are fixed text.
fn exec_listing_failure(error: CoreError, otherwise: fn(CoreError) -> RpcFailure) -> RpcFailure {
    match &error {
        CoreError::Validation { subject, message } if *subject == "exec directory listing" => {
            if message.contains("不存在") {
                RpcFailure::core(
                    "list a directory inside a container",
                    "container-directory-missing",
                    "这个目录不存在，或者不是目录。",
                    error,
                )
            } else if message.contains("没有权限") {
                RpcFailure::core(
                    "list a directory inside a container",
                    "container-directory-denied",
                    "没有权限进入这个目录。",
                    error,
                )
            } else {
                RpcFailure::core(
                    "list a directory inside a container",
                    "container-directory-unreadable",
                    "目录列表读回来的格式不对，没有显示任何条目。",
                    error,
                )
            }
        }
        _ => otherwise(error),
    }
}

/// A pod file that is not shown, and which of the reasons it was.
fn pod_file_failure(error: CoreError) -> RpcFailure {
    let CoreError::Validation { subject, message } = &error else {
        return pod_shell_failure(error);
    };
    if *subject != "Kubernetes pod file" {
        return pod_shell_failure(error);
    }
    let (code, sentence) = if message.contains("不存在") {
        ("kubernetes-pod-file-missing", "这个文件不存在。")
    } else if message.contains("上限") {
        (
            "kubernetes-pod-file-too-large",
            "文件超过了 1 MiB 的查看上限，没有读取。",
        )
    } else if message.contains("不是普通文件") {
        (
            "kubernetes-pod-file-not-regular",
            "这不是普通文件（可能是符号链接、目录或设备），不能在这里查看。",
        )
    } else if message.contains("变了") {
        (
            "kubernetes-pod-file-changed",
            "读取期间文件被改动了，请重新读取。",
        )
    } else {
        (
            "kubernetes-pod-file-not-text",
            "读到的内容和文件的长度或摘要对不上：文件可能正在被写入，或不是 UTF-8 文本。",
        )
    };
    RpcFailure::core("read a file inside a pod", code, sentence, error)
}

fn docker_exec_failure(error: CoreError) -> RpcFailure {
    RpcFailure::core(
        "run docker exec in a container",
        "container-exec-failed",
        "容器里的命令没有成功：容器可能已停止，或镜像里没有 /bin/sh。",
        error,
    )
}

fn terminal_failure(error: TerminalApiError) -> RpcFailure {
    match error {
        // A host that went away is not a failure of the terminal. Said the way
        // every other page says it (a `-binding-unavailable` code), so the
        // window can tell the operator the connection is gone instead of
        // guessing at the terminal, the folder or the shell.
        TerminalApiError::Core(source @ CoreError::SshDisconnected { .. }) => RpcFailure::core(
            "run target-bound terminal operation",
            "terminal-binding-unavailable",
            "The SSH connection to the target is gone.",
            source,
        ),
        TerminalApiError::Core(source) => RpcFailure::core(
            "run target-bound terminal operation",
            "terminal-operation-failed",
            "LovelyHawk could not complete the terminal operation.",
            source,
        ),
        TerminalApiError::BindingUnavailable => RpcFailure {
            operation: "validate terminal SSH binding",
            code: "terminal-binding-unavailable",
            public_message: "The terminal SSH binding is missing or stale.",
            source: None,
        },
        TerminalApiError::TerminalUnavailable => RpcFailure {
            operation: "validate terminal handle",
            code: "terminal-unavailable",
            public_message: "The terminal session is missing or stale.",
            source: None,
        },
        TerminalApiError::InvalidBounds
        | TerminalApiError::InvalidInput
        | TerminalApiError::InvalidSearch => RpcFailure {
            operation: "validate terminal request",
            code: "invalid-params",
            public_message: "The terminal request parameters are invalid.",
            source: None,
        },
        TerminalApiError::RegistryCapacity | TerminalApiError::TargetCapacity => RpcFailure {
            operation: "bound terminal registry",
            code: "terminal-capacity",
            public_message: "The bounded terminal capacity has been reached.",
            source: None,
        },
        TerminalApiError::RegistryUnavailable => RpcFailure {
            operation: "lock terminal registry",
            code: "terminal-operation-failed",
            public_message: "LovelyHawk could not complete the terminal operation.",
            source: None,
        },
        // Two of these have something the operator can do: narrow a search
        // that matched too much, or open a fresh terminal because this one has
        // produced all the output it is allowed to. The other two are the same
        // "this session is broken, open another" and stay together.
        TerminalApiError::OutputLimit => RpcFailure {
            operation: "validate terminal protocol output",
            code: "terminal-output-limit",
            public_message: "This terminal has produced all the output it may hold.",
            source: None,
        },
        TerminalApiError::SearchLimit => RpcFailure {
            operation: "validate terminal protocol output",
            code: "terminal-search-limit",
            public_message: "The terminal search matched more than it may return.",
            source: None,
        },
        TerminalApiError::SnapshotLimit | TerminalApiError::ProtocolViolation => RpcFailure {
            operation: "validate terminal protocol output",
            code: "terminal-protocol-invalid",
            public_message: "The terminal stream exceeded its protocol boundary.",
            source: None,
        },
        TerminalApiError::TimedOut => RpcFailure {
            operation: "bound terminal operation time",
            code: "terminal-timeout",
            public_message: "The terminal operation timed out.",
            source: None,
        },
    }
}

fn config_failure(error: CoreError) -> RpcFailure {
    let (code, public_message) = match &error {
        CoreError::Io { source, .. } if source.kind() == std::io::ErrorKind::AlreadyExists => (
            "configuration-destination-exists",
            "The chosen destination already exists; exports only create new files.",
        ),
        CoreError::Validation { .. } => (
            "configuration-invalid",
            "The typed configuration request is invalid or stale.",
        ),
        CoreError::NotFound { .. } => (
            "configuration-draft-not-found",
            "The configuration draft is missing or expired.",
        ),
        _ => (
            "configuration-operation-failed",
            "LovelyHawk could not complete the configuration operation.",
        ),
    };
    RpcFailure::core(
        "run typed configuration draft operation",
        code,
        public_message,
        error,
    )
}

fn system_info_failure(error: SystemInfoApiError) -> RpcFailure {
    match error {
        SystemInfoApiError::Core(source) => RpcFailure::core(
            "run system-information operation",
            "system-info-operation-failed",
            "LovelyHawk could not complete the system-information operation.",
            source,
        ),
        SystemInfoApiError::BindingUnavailable => RpcFailure {
            operation: "validate system-information SSH binding",
            // Named the way every other target-bound capability names it, so a
            // window can tell "the target is gone" from "this feature failed"
            // without an entry per feature.
            code: "system-info-binding-unavailable",
            public_message: "The SSH binding is missing or stale.",
            source: None,
        },
        SystemInfoApiError::InvalidBounds | SystemInfoApiError::InvalidTab => RpcFailure {
            operation: "validate system-information request",
            code: "invalid-params",
            public_message: "The system-information request parameters are invalid.",
            source: None,
        },
        // Three answers, and only two of them are worth retrying. Folded into
        // one, a row that simply has nothing more to show was reported as a
        // stale table — so the operator refreshed, asked again, and got the
        // same sentence, for as long as they were willing to keep trying.
        SystemInfoApiError::InvalidSnapshot => RpcFailure {
            operation: "validate system-information snapshot row",
            code: "system-info-snapshot-stale",
            public_message: "The system-information table is older than the target's answer.",
            source: None,
        },
        SystemInfoApiError::InvalidRow => RpcFailure {
            operation: "validate system-information snapshot row",
            code: "system-info-row-gone",
            public_message: "That row is not in the current system-information table.",
            source: None,
        },
        SystemInfoApiError::DetailUnavailable => RpcFailure {
            operation: "validate system-information snapshot row",
            code: "system-info-detail-none",
            public_message: "That row has no further detail to show.",
            source: None,
        },
        SystemInfoApiError::SnapshotCapacity => RpcFailure {
            operation: "bound system-information snapshot registry",
            code: "system-info-capacity",
            public_message: "Too many bounded system-information snapshots are pending.",
            source: None,
        },
        SystemInfoApiError::RegistryUnavailable => RpcFailure {
            operation: "lock system-information snapshot registry",
            code: "system-info-operation-failed",
            public_message: "LovelyHawk could not complete the system-information operation.",
            source: None,
        },
        SystemInfoApiError::InvalidAction => RpcFailure {
            operation: "validate system-information row action",
            code: "invalid-params",
            public_message: "The system-information row action is not one LovelyHawk offers.",
            source: None,
        },
        SystemInfoApiError::ActionUnavailable(source) => {
            use lovelyhawk_core::system_info::{
                USER_ACCOUNT_ROOT_REFUSAL, USER_ACCOUNT_SESSION_REFUSAL, USER_ACCOUNT_STATE_REFUSAL,
            };
            // Refusals with a reason the operator can act on get their own
            // code; everything else stays "does not apply", reason in the log.
            let (code, public_message) = match &source {
                CoreError::Validation { subject, .. }
                    if *subject == USER_ACCOUNT_SESSION_REFUSAL =>
                {
                    (
                        "system-info-account-session",
                        "That is the account this SSH session is logged in as.",
                    )
                }
                CoreError::Validation { subject, .. } if *subject == USER_ACCOUNT_ROOT_REFUSAL => (
                    "system-info-account-root",
                    "The root account is not deleted.",
                ),
                CoreError::Validation { subject, .. } if *subject == USER_ACCOUNT_STATE_REFUSAL => {
                    (
                        "system-info-account-state",
                        "The account is already in that state.",
                    )
                }
                _ => (
                    "system-info-action-unavailable",
                    "That action does not apply to the selected row any more.",
                ),
            };
            RpcFailure::core(
                "check system-information row action precondition",
                code,
                public_message,
                source,
            )
        }
        SystemInfoApiError::PlanStale | SystemInfoApiError::PlanNotConfirmed => RpcFailure {
            operation: "validate system-information row plan",
            code: "system-info-plan-unavailable",
            public_message: "That plan is missing, expired, unconfirmed, or already used.",
            source: None,
        },
        SystemInfoApiError::Deadline => RpcFailure {
            operation: "bound system-information row action deadline",
            code: "system-info-timeout",
            public_message: "The system-information row action exceeded its deadline.",
            source: None,
        },
    }
}

fn baseline_write_failure(error: baseline_write_api::BaselineWriteApiError) -> RpcFailure {
    use baseline_write_api::BaselineWriteApiError as Error;
    let (operation, code, public_message) = match error {
        Error::Refused | Error::RegistryUnavailable => (
            "plan or run a baseline change",
            "baseline-action-failed",
            "这次基线改动没有做成，目标上的文件请刷新扫描结果后核对。",
        ),
        Error::InvalidValue => (
            "check a baseline value",
            "baseline-action-invalid-value",
            "填写的值不在这一项允许的范围内，没有生成计划。",
        ),
        Error::NotWritable => (
            "check a baseline setting is written by this tool",
            "baseline-action-not-writable",
            "这一项只提供检查和手动修改建议，或者它在这台目标上的实际配置还没能核实，所以不自动修改。",
        ),
        Error::NothingToChange => (
            "check a baseline change changes something",
            "baseline-action-nothing-to-change",
            "所选的各项已经是这个值，没有需要改的。",
        ),
        Error::NotRestorable => (
            "check a baseline history record can be restored",
            "baseline-action-not-restorable",
            "这条历史缺少改动后完整文件的证据（或已经恢复过），不能自动放回，以免覆盖之后的改动。请保留备份并手动核对。",
        ),
        Error::BindingUnavailable => (
            "validate baseline SSH binding",
            "baseline-binding-unavailable",
            "目标连接已断开或已切换，没有做任何改动。",
        ),
        Error::InvalidHandle => (
            "validate baseline change request",
            "invalid-params",
            "The baseline change request parameters are invalid.",
        ),
        Error::PlanStale => (
            "validate baseline change plan",
            "baseline-action-plan-invalid",
            "这次基线改动的计划已失效（过期或已经用过），请重新发起。",
        ),
        Error::PlanNotConfirmed => (
            "require confirmation before a baseline change runs",
            "baseline-action-not-confirmed",
            "这次基线改动还没有确认，没有执行。",
        ),
        Error::Capacity => (
            "bound pending baseline change plans",
            "baseline-action-capacity",
            "待确认的改动太多，请先处理已打开的确认。",
        ),
        Error::Deadline => (
            "bound the baseline change deadline",
            "baseline-action-timeout",
            "基线改动没有在时限内结束，请刷新扫描结果后核对；备份保留在目标的受管目录里。",
        ),
    };
    RpcFailure {
        operation,
        code,
        public_message,
        source: None,
    }
}

fn baseline_read_failure(error: BaselineReadApiError) -> RpcFailure {
    match error {
        BaselineReadApiError::Core | BaselineReadApiError::RegistryUnavailable => RpcFailure {
            operation: "run bounded baseline investigation",
            code: "baseline-operation-failed",
            public_message: "LovelyHawk could not complete the baseline investigation.",
            source: None,
        },
        BaselineReadApiError::BindingUnavailable => RpcFailure {
            operation: "validate baseline SSH binding",
            code: "baseline-binding-unavailable",
            public_message: "The baseline target binding is missing or stale.",
            source: None,
        },
        BaselineReadApiError::InvalidHandle => RpcFailure {
            operation: "validate baseline request",
            code: "invalid-params",
            public_message: "The baseline request parameters are invalid.",
            source: None,
        },
        BaselineReadApiError::InvalidData => RpcFailure {
            operation: "validate baseline investigation output",
            code: "baseline-output-invalid",
            public_message: "The baseline investigation result is invalid.",
            source: None,
        },
        BaselineReadApiError::OutputLimit => RpcFailure {
            operation: "bound baseline investigation output",
            code: "baseline-output-limit",
            public_message: "The baseline investigation result exceeds its safety limit.",
            source: None,
        },
        BaselineReadApiError::ConcurrencyLimit => RpcFailure {
            operation: "bound baseline investigation",
            code: "baseline-capacity",
            public_message: "The bounded baseline investigation capacity has been reached.",
            source: None,
        },
    }
}

fn check_audit_read_failure(error: CheckAuditReadApiError) -> RpcFailure {
    match error {
        CheckAuditReadApiError::Core | CheckAuditReadApiError::RegistryUnavailable => RpcFailure {
            operation: "run bounded command-audit investigation",
            code: "check-audit-operation-failed",
            public_message: "LovelyHawk could not complete the command-audit investigation.",
            source: None,
        },
        CheckAuditReadApiError::BindingUnavailable => RpcFailure {
            operation: "validate command-audit SSH binding",
            code: "check-audit-binding-unavailable",
            public_message: "The command-audit target binding is missing or stale.",
            source: None,
        },
        CheckAuditReadApiError::InvalidHandle | CheckAuditReadApiError::InvalidInput => {
            RpcFailure {
                operation: "validate command-audit request",
                code: "invalid-params",
                public_message: "The command-audit request parameters are invalid.",
                source: None,
            }
        }
        CheckAuditReadApiError::InvalidSnapshot | CheckAuditReadApiError::SnapshotStale => {
            RpcFailure {
                operation: "validate command-audit catalog capability",
                code: "check-audit-catalog-unavailable",
                public_message: "The command-audit catalog is missing, expired, or stale.",
                source: None,
            }
        }
        CheckAuditReadApiError::ConcurrencyLimit | CheckAuditReadApiError::Capacity => RpcFailure {
            operation: "bound command-audit investigation",
            code: "check-audit-capacity",
            public_message: "The bounded command-audit investigation capacity has been reached.",
            source: None,
        },
    }
}

fn check_audit_write_failure(error: check_audit_write_api::CheckAuditWriteApiError) -> RpcFailure {
    use check_audit_write_api::CheckAuditWriteApiError as Error;
    let (operation, code, public_message) = match error {
        Error::Refused | Error::RegistryUnavailable => (
            "plan or run a command-audit change",
            "check-audit-action-failed",
            "这次改动没有做成，目标上的状态请刷新后再确认。",
        ),
        Error::NeedsPrivilege => (
            "check command-audit change privilege",
            "check-audit-action-needs-privilege",
            "这个登录账号既不是 root，也不能免密码使用 sudo，不能改动命令或日志。请用 root 或有免密码 sudo 的账号登录。",
        ),
        Error::StateChanged => (
            "check command state before a command-audit change",
            "check-audit-action-state-changed",
            "命令的状态已经变了（不是原程序，或不是本工具加的采集），没有生成计划。请刷新状态后再试。",
        ),
        Error::BindingUnavailable => (
            "validate command-audit SSH binding",
            "check-audit-binding-unavailable",
            "目标连接已断开或已切换，没有做任何改动。",
        ),
        Error::InvalidHandle => (
            "validate command-audit change request",
            "invalid-params",
            "The command-audit change request parameters are invalid.",
        ),
        Error::InvalidCommand => (
            "resolve the commands a command-audit change names",
            "check-audit-action-command-unavailable",
            "命令列表已过期，或所选命令不在这份列表里。请重新读取命令列表后再试。",
        ),
        Error::PlanStale => (
            "validate command-audit change plan",
            "check-audit-action-plan-invalid",
            "这次改动的计划已失效（过期或已经用过），请重新发起。",
        ),
        Error::PlanNotConfirmed => (
            "require confirmation before a command-audit change runs",
            "check-audit-action-not-confirmed",
            "这次改动还没有确认，没有执行。",
        ),
        Error::Capacity => (
            "bound pending command-audit change plans",
            "check-audit-action-capacity",
            "待确认的改动太多，请先处理已打开的确认。",
        ),
        Error::Deadline => (
            "bound the command-audit change deadline",
            "check-audit-action-timeout",
            "改动没有在时限内结束，请刷新命令状态后核对。",
        ),
    };
    RpcFailure {
        operation,
        code,
        public_message,
        source: None,
    }
}

fn log_analysis_read_failure(error: LogAnalysisReadApiError) -> RpcFailure {
    match error {
        LogAnalysisReadApiError::Core | LogAnalysisReadApiError::RegistryUnavailable => {
            RpcFailure {
                operation: "run bounded log investigation",
                code: "log-analysis-operation-failed",
                public_message: "LovelyHawk could not complete the log investigation.",
                source: None,
            }
        }
        LogAnalysisReadApiError::BindingUnavailable => RpcFailure {
            operation: "validate log investigation SSH binding",
            code: "log-analysis-binding-unavailable",
            public_message: "The log investigation target binding is missing or stale.",
            source: None,
        },
        LogAnalysisReadApiError::ArchiveToolMissing => RpcFailure {
            operation: "read a compressed archive log",
            code: "log-analysis-archive-tool-missing",
            public_message: "The target has no gzip, so a compressed archive cannot be opened.",
            source: None,
        },
        LogAnalysisReadApiError::InvalidHandle
        | LogAnalysisReadApiError::InvalidQuery
        | LogAnalysisReadApiError::InvalidDate => RpcFailure {
            operation: "validate log investigation request",
            code: "invalid-params",
            public_message: "The log investigation request parameters are invalid.",
            source: None,
        },
        LogAnalysisReadApiError::InvalidSource
        | LogAnalysisReadApiError::InvalidSourceKind
        | LogAnalysisReadApiError::InvalidSnapshot
        | LogAnalysisReadApiError::SnapshotStale => RpcFailure {
            operation: "validate log investigation snapshot",
            code: "log-analysis-snapshot-unavailable",
            public_message: "The log investigation snapshot is missing, expired, or stale.",
            source: None,
        },
        LogAnalysisReadApiError::Capacity => RpcFailure {
            operation: "bound log investigation",
            code: "log-analysis-capacity",
            public_message: "The bounded log investigation capacity has been reached.",
            source: None,
        },
    }
}

fn kubernetes_write_failure(error: KubernetesWriteApiError) -> RpcFailure {
    match error {
        KubernetesWriteApiError::Core | KubernetesWriteApiError::RegistryUnavailable => {
            RpcFailure {
                operation: "plan or run a Kubernetes workload action",
                code: "kubernetes-action-failed",
                public_message: "LovelyHawk could not complete the workload action.",
                source: None,
            }
        }
        KubernetesWriteApiError::BindingUnavailable => RpcFailure {
            operation: "validate Kubernetes action SSH binding",
            code: "kubernetes-binding-unavailable",
            public_message: "The Kubernetes target binding is missing or stale.",
            source: None,
        },
        KubernetesWriteApiError::InvalidHandle => RpcFailure {
            operation: "validate Kubernetes action request",
            code: "invalid-params",
            public_message: "The workload action request parameters are invalid.",
            source: None,
        },
        // Named apart from a plain refusal: this one says the operator asked
        // for something that does not apply to what they clicked.
        KubernetesWriteApiError::ActionKindMismatch => RpcFailure {
            operation: "match a Kubernetes action to the resource it names",
            code: "kubernetes-action-kind-mismatch",
            public_message: "That action does not apply to this kind of resource.",
            source: None,
        },
        KubernetesWriteApiError::InvalidRow => RpcFailure {
            operation: "resolve the workload an action names",
            code: "kubernetes-resource-unavailable",
            public_message: "That resource is no longer in the list this action was planned from.",
            source: None,
        },
        KubernetesWriteApiError::PlanStale => RpcFailure {
            operation: "validate Kubernetes action plan",
            code: "kubernetes-action-plan-invalid",
            public_message: "The workload action plan is missing, expired, or already used.",
            source: None,
        },
        KubernetesWriteApiError::PlanNotConfirmed => RpcFailure {
            operation: "require confirmation before a Kubernetes action runs",
            code: "kubernetes-action-not-confirmed",
            public_message: "The workload action has not been confirmed.",
            source: None,
        },
        KubernetesWriteApiError::Capacity => RpcFailure {
            operation: "bound pending Kubernetes action plans",
            code: "kubernetes-action-capacity",
            public_message: "Too many workload action plans are pending.",
            source: None,
        },
        KubernetesWriteApiError::Forbidden => RpcFailure {
            operation: "plan a Kubernetes workload action",
            code: "kubernetes-forbidden",
            public_message: "The Kubernetes API server refused this account the read (RBAC).",
            source: None,
        },
        KubernetesWriteApiError::Deadline => RpcFailure {
            operation: "bound the Kubernetes action deadline",
            code: "kubernetes-action-timeout",
            public_message: "The workload action did not finish in time.",
            source: None,
        },
    }
}

fn kubernetes_read_failure(error: KubernetesReadApiError) -> RpcFailure {
    match error {
        KubernetesReadApiError::Core(_) | KubernetesReadApiError::RegistryUnavailable => {
            RpcFailure {
                operation: "run bounded Kubernetes read investigation",
                code: "kubernetes-operation-failed",
                public_message: "LovelyHawk could not complete the Kubernetes read operation.",
                source: None,
            }
        }
        KubernetesReadApiError::BindingUnavailable => RpcFailure {
            operation: "validate Kubernetes SSH binding",
            code: "kubernetes-binding-unavailable",
            public_message: "The Kubernetes target binding is missing or stale.",
            source: None,
        },
        KubernetesReadApiError::InvalidHandle | KubernetesReadApiError::InvalidInput => {
            RpcFailure {
                operation: "validate Kubernetes read request",
                code: "invalid-params",
                public_message: "The Kubernetes read request parameters are invalid.",
                source: None,
            }
        }
        KubernetesReadApiError::NamespaceUnavailable => RpcFailure {
            operation: "validate Kubernetes namespace capability",
            code: "kubernetes-namespace-unavailable",
            public_message: "The Kubernetes namespace selection is missing, expired, or stale.",
            source: None,
        },
        KubernetesReadApiError::SnapshotUnavailable | KubernetesReadApiError::RowUnavailable => {
            RpcFailure {
                operation: "validate Kubernetes resource capability",
                code: "kubernetes-resource-unavailable",
                public_message: "The Kubernetes resource is missing, expired, or stale.",
                source: None,
            }
        }
        KubernetesReadApiError::LogsUnavailable => RpcFailure {
            operation: "validate Kubernetes pod logs capability",
            code: "kubernetes-logs-unavailable",
            public_message: "Pod logs are unavailable for this Kubernetes resource.",
            source: None,
        },
        KubernetesReadApiError::LogsNotReady => RpcFailure {
            operation: "read Kubernetes pod logs",
            code: "kubernetes-logs-not-ready",
            public_message: "The kubelet could not hand over this container log right now.",
            source: None,
        },
        KubernetesReadApiError::ContainerUnavailable => RpcFailure {
            operation: "validate Kubernetes pod container",
            code: "kubernetes-pod-container-unavailable",
            public_message: "The listed pod has no container by that name.",
            source: None,
        },
        KubernetesReadApiError::Forbidden => RpcFailure {
            operation: "run bounded Kubernetes read investigation",
            code: "kubernetes-forbidden",
            public_message: "The Kubernetes API server refused this account the read (RBAC).",
            source: None,
        },
        KubernetesReadApiError::ManifestUnavailable => RpcFailure {
            operation: "read Kubernetes manifest",
            code: "kubernetes-manifest-unavailable",
            public_message: "The manifest was not read, or is no longer the listed object's.",
            source: None,
        },
        KubernetesReadApiError::Capacity | KubernetesReadApiError::ConcurrencyLimit => RpcFailure {
            operation: "bound Kubernetes read investigation",
            code: "kubernetes-capacity",
            public_message: "The bounded Kubernetes read capacity has been reached.",
            source: None,
        },
    }
}

fn case_library_failure(error: CaseLibraryError) -> RpcFailure {
    let (code, public_message) = match error {
        CaseLibraryError::Invalid => ("invalid-params", "案件库请求无效。"),
        CaseLibraryError::Stale => (
            "case-library-stale",
            "案件版本或操作计划已变化或过期，请刷新案件库并重新查看。",
        ),
        CaseLibraryError::Busy => (
            "case-library-busy",
            "此案仍在采集文件，请等待采集完成或取消采集后再整理案件。",
        ),
        CaseLibraryError::Capacity => (
            "case-library-capacity",
            "案件容量不足：最多 30 个活动案件、200 个归档版本，每份 JSON 最多 32 MiB。请先整理案件库；没有丢弃旧记录。",
        ),
        CaseLibraryError::Conflict => (
            "case-library-conflict",
            "活动列表中已有同编号案件，请先归档该案件，再恢复所选版本。不会覆盖现有内容。",
        ),
        CaseLibraryError::TimelineCapacity => (
            "case-timeline-capacity",
            "此案已达到 1000 条时间线上限，无法保存新的状态记录。原案完整保留，可新建案件继续，并注明原案编号。",
        ),
        CaseLibraryError::Conclusion => (
            "case-conclusion-invalid",
            "请完整填写调查结论和后续事项：结论最多 1024 字、后续事项 512 字；若内容仍过长，请精简以便完整确认。",
        ),
        CaseLibraryError::Unavailable => (
            "case-library-unavailable",
            "案件操作未能完成核对。请刷新确认实际状态，并检查本机存储是否可用、归档文件是否完整。导出不覆盖已有文件，请选择新文件名。",
        ),
    };
    RpcFailure {
        operation: "case library",
        code,
        public_message,
        source: None,
    }
}

fn case_workspace_failure(error: CaseWorkspaceError) -> RpcFailure {
    let (code, public_message) = match error {
        CaseWorkspaceError::Invalid => ("invalid-params", "案件请求无效，请检查输入长度并重试。"),
        CaseWorkspaceError::Stale => (
            "case-workspace-stale",
            "连接或案件视图已过期，请刷新案件后重试。",
        ),
        CaseWorkspaceError::Capacity => (
            "case-workspace-capacity",
            "已达到 30 个活动案件上限，原有案件和证据均已保留。可到本机案件库归档旧案后继续。",
        ),
        CaseWorkspaceError::TimelineCapacity => (
            "case-timeline-capacity",
            "此案已达到 1000 条时间线上限，原记录均已保留。请新建案件继续记录。",
        ),
        CaseWorkspaceError::EvidenceCapacity => (
            "case-evidence-capacity",
            "此案已达到 500 条证据上限，原证据均已保留。请新建案件继续记录。",
        ),
        CaseWorkspaceError::IocCapacity => (
            "case-ioc-capacity",
            "此案已达到 500 条线索上限，原线索均已保留。请新建案件继续记录。",
        ),
        CaseWorkspaceError::NoteChanged => (
            "case-note-changed",
            "笔记已被修改，请重新选择并核对内容后关联。",
        ),
        CaseWorkspaceError::NoteTooLarge => (
            "case-note-too-large",
            "笔记超过 4096 字，请先拆分需要归档的内容。本次没有截断或保存。",
        ),
        CaseWorkspaceError::ReportUnavailable => (
            "case-report-unavailable",
            "无法生成此案报告，请检查连接和案件视图是否有效。报告每种格式最多 512 KiB。",
        ),
        CaseWorkspaceError::Unavailable => (
            "case-workspace-unavailable",
            "案件操作未完成。请刷新核对；已关闭案件不能继续写入，输入内容已保留。",
        ),
    };
    RpcFailure {
        operation: "case workspace",
        code,
        public_message,
        source: None,
    }
}

fn config_visual_failure(error: ConfigVisualError) -> RpcFailure {
    let (code, message) = match error {
        ConfigVisualError::Invalid => ("invalid-params", "可视化编辑请求无效。"),
        ConfigVisualError::Stale => (
            "config-visual-stale",
            "文档已经变化或已关闭，页面上的内容已过期。请重新载入当前文档后再改。",
        ),
        ConfigVisualError::Capacity => (
            "config-visual-capacity",
            "同时打开的可视化文档已达 8 个。先另存并关闭不用的文档。",
        ),
        ConfigVisualError::Unsupported => (
            "config-visual-unsupported",
            "这个产品或文件的可视化编辑还没有接入。目前支持 Nginx、Apache httpd、Redis、HAProxy、MySQL、MariaDB，以及目录里列出的数据库配置文件。",
        ),
        ConfigVisualError::Sensitive => (
            "config-visual-sensitive",
            "这一项含有隐藏的敏感内容（口令、令牌等），不能在这里修改、删除、移动、往里添加或复制。",
        ),
        ConfigVisualError::NotBlock => (
            "config-visual-not-block",
            "只能往块或区段里添加子项（例如 Nginx 的 server、location，Apache 的 VirtualHost、Directory）。Redis 配置没有块，所有项都在最外层；HAProxy 的区段不能嵌套。",
        ),
        ConfigVisualError::Rejected => (
            "config-visual-rejected",
            "这次修改没有通过语法检查，文档没有变化。名称不能为空，参数不能让一项变成多条语句（例如多出的分号、花括号、换行或未闭合的引号），注释也只能是一行。",
        ),
        ConfigVisualError::ReadFailed => (
            "config-visual-read-failed",
            "读不了这个文件。请选择一个存在的普通文件，路径中不要有 . 或 ..。",
        ),
        ConfigVisualError::NotText => (
            "config-visual-not-text",
            "这个文件不是 UTF-8 文本，只能原样查看，不能在这里复制或另存。",
        ),
        ConfigVisualError::TooLarge => (
            "config-visual-too-large",
            "文件太大：可视化编辑最多 4 MB，复制最多 256 KB。",
        ),
        ConfigVisualError::ReadOnly => (
            "config-visual-read-only",
            "这个文件由服务器或厂商工具生成（或要求厂商的完整说明），这里只能查看和另存副本，不能修改。",
        ),
        ConfigVisualError::NoSchema => (
            "config-visual-no-schema",
            "先在“对照的版本”里选一个版本，才能按目录设置参数。",
        ),
        ConfigVisualError::ValueRefused => (
            "config-visual-value-refused",
            "这个值不符合所选版本目录对该参数的要求，或这个参数不能在这里设置（例如含口令、需要额外能力或文件只读），文档没有变化。",
        ),
        ConfigVisualError::ParameterDuplicate => (
            "config-visual-parameter-duplicate",
            "这个参数在文件里出现了多次，哪一行生效由服务器决定，所以这里不替你改。请在左边的树里选中要改的那一行直接修改。",
        ),
        ConfigVisualError::ParameterLocked => (
            "config-visual-parameter-locked",
            "文件里这个参数所在的那一行不能在这里修改（内容被隐藏或太长显示不全），文档没有变化。",
        ),
        ConfigVisualError::GoalQueryRefused => (
            "config-goal-query-refused",
            "这句话太长（最多 128 个字）或含有控制字符，没有搜索。",
        ),
        ConfigVisualError::GoalStale => (
            "config-goal-stale",
            "这条赋值已经过期：搜索的句子、打开的文件或对照的版本在预览之后变了，没有写入。请看一下新的预览再确认。",
        ),
        ConfigVisualError::GoalValueRefused => (
            "config-goal-value-refused",
            "这个值不符合所选版本目录对该参数的要求，没有写入。",
        ),
        ConfigVisualError::GoalOtherFileUnsaved => (
            "config-goal-other-file-unsaved",
            "可视化编辑里另一个文件还有未另存的修改，没有替换它，也没有写入。请先另存或放弃那些修改。",
        ),
        ConfigVisualError::GoalOtherVersionUnsaved => (
            "config-goal-other-version-unsaved",
            "打开的文件有未另存的修改，而且对照的是另一个版本，没有改动它。请先另存，或把对照的版本换成这条赋值所用的版本。",
        ),
    };
    RpcFailure {
        operation: "visual configuration",
        code,
        public_message: message,
        source: None,
    }
}

fn pod_file_evidence_failure(error: PodFileEvidenceError) -> RpcFailure {
    let (code, message) = match error {
        PodFileEvidenceError::Invalid => ("invalid-params", "Pod 文件留证请求无效。"),
        PodFileEvidenceError::Stale => (
            "kubernetes-pod-evidence-stale",
            "连接或 Pod 列表已失效，或所选容器不属于这个 Pod，请刷新列表后再留证。",
        ),
        PodFileEvidenceError::Busy => (
            "kubernetes-pod-evidence-busy",
            "这台主机已有 Pod 文件留证在进行，请等它完成或取消。",
        ),
        PodFileEvidenceError::Capacity => (
            "kubernetes-pod-evidence-capacity",
            "留证任务或案件证据数量已达上限，请完成现有任务或创建新案件。",
        ),
        PodFileEvidenceError::CaseCapacity => (
            "kubernetes-pod-evidence-case-capacity",
            "已达到 30 个案件上限，原有案件与证据已保留。本次没有开始留证。",
        ),
        PodFileEvidenceError::Unavailable => (
            "kubernetes-pod-evidence-unavailable",
            "无法开始 Pod 文件留证，请检查所选目录权限、空间和当前案件。",
        ),
    };
    RpcFailure {
        operation: "kubernetes pod file evidence",
        code,
        public_message: message,
        source: None,
    }
}

fn packet_capture_evidence_failure(error: PacketCaptureEvidenceError) -> RpcFailure {
    let (code, message) = match error {
        PacketCaptureEvidenceError::Invalid => ("invalid-params", "抓包留证请求无效。"),
        PacketCaptureEvidenceError::Stale => (
            "packet-capture-evidence-stale",
            "连接或网卡列表已失效，请重新读取网卡后再抓包留证。",
        ),
        PacketCaptureEvidenceError::Busy => (
            "packet-capture-evidence-busy",
            "这台主机已有抓包留证在进行，请等它完成或取消。",
        ),
        PacketCaptureEvidenceError::Capacity => (
            "packet-capture-evidence-capacity",
            "留证任务或案件证据数量已达上限，请完成现有任务或创建新案件。",
        ),
        PacketCaptureEvidenceError::CaseCapacity => (
            "packet-capture-evidence-case-capacity",
            "已达到 30 个案件上限，原有案件与证据已保留。本次没有开始抓包。",
        ),
        PacketCaptureEvidenceError::Unavailable => (
            "packet-capture-evidence-unavailable",
            "无法开始抓包留证，请检查所选目录权限、空间和当前案件。",
        ),
    };
    RpcFailure {
        operation: "packet capture evidence",
        code,
        public_message: message,
        source: None,
    }
}

fn file_evidence_failure(error: FileEvidenceError) -> RpcFailure {
    let (code, message) = match error {
        FileEvidenceError::Invalid => ("invalid-params", "留证请求无效。"),
        FileEvidenceError::Stale => (
            "file-evidence-stale",
            "连接或文件结果已失效，请重新检查后留证。",
        ),
        FileEvidenceError::Busy => (
            "file-evidence-busy",
            "当前主机已有文件正在采集，请等待完成或取消。",
        ),
        FileEvidenceError::Capacity => (
            "file-evidence-capacity",
            "采集任务或案件证据数量已达上限，请完成现有任务或创建新案件。",
        ),
        FileEvidenceError::CaseCapacity => (
            "file-evidence-case-capacity",
            "已达到 30 个案件上限，原有案件与证据已保留。本次未开始采集。",
        ),
        FileEvidenceError::Unavailable => (
            "file-evidence-unavailable",
            "无法开始留证，请检查所选目录权限、空间和当前案件。",
        ),
    };
    RpcFailure {
        operation: "file evidence",
        code,
        public_message: message,
        source: None,
    }
}

fn java_hot_update_failure(error: JavaHotUpdateError) -> RpcFailure {
    let (code, public_message) = match error {
        JavaHotUpdateError::Invalid => {
            ("invalid-params", "The Java hot update request is invalid.")
        }
        JavaHotUpdateError::BindingUnavailable => (
            "java-binding-unavailable",
            "The Java hot update SSH binding is missing or stale.",
        ),
        JavaHotUpdateError::Stale => (
            "java-hot-update-stale",
            "The JVM list, JAR, class file or plan is no longer current.",
        ),
        JavaHotUpdateError::Capacity => (
            "java-hot-update-capacity",
            "Too many Java hot update items are pending.",
        ),
        JavaHotUpdateError::NotConfirmed => (
            "java-hot-update-unconfirmed",
            "The Java hot update plan has not been confirmed.",
        ),
        JavaHotUpdateError::ToolMissing => (
            "java-tool-missing",
            "The target has no jar tool for this step.",
        ),
        JavaHotUpdateError::NoBackupFolder => (
            "java-backup-folder-missing",
            "The login has no home folder of its own to keep the original JAR in.",
        ),
        JavaHotUpdateError::Deadline => (
            "java-hot-update-timeout",
            "The Java operation did not finish in time.",
        ),
        JavaHotUpdateError::Core => (
            "java-hot-update-failed",
            "LovelyHawk could not complete the Java operation.",
        ),
    };
    RpcFailure {
        operation: "run Java hot update",
        code,
        public_message,
        source: None,
    }
}

fn windows_incident_failure(error: WindowsIncidentError) -> RpcFailure {
    let (code, public_message) = match error {
        WindowsIncidentError::Invalid => (
            "invalid-params",
            "The Windows incident response request is invalid.",
        ),
        WindowsIncidentError::Failed => (
            "windows-incident-failed",
            "LovelyHawk could not complete the Windows DVC operation.",
        ),
    };
    RpcFailure {
        operation: "run Windows incident response",
        code,
        public_message,
        source: None,
    }
}

fn ai_assist_failure(error: AiAssistError) -> RpcFailure {
    let (operation, code, public_message) = match error {
        AiAssistError::Core(source) => {
            return RpcFailure::core(
                "start AI assistance",
                "ai-assist-failed",
                "没能向 AI 服务商发起请求，详细原因见应用日志。",
                source,
            );
        }
        AiAssistError::InvalidContent => (
            "validate AI assistance content",
            "invalid-params",
            "要发送的内容为空，或超过了 96 KB。",
        ),
        AiAssistError::ProviderUnavailable => (
            "find AI provider",
            "ai-provider-not-found",
            "这个 AI 服务商已经不在设置里了，请重新选择。",
        ),
        AiAssistError::ProviderDisabled => (
            "find AI provider",
            "ai-provider-disabled",
            "这个 AI 服务商已停用，请在设置里启用后再试。",
        ),
        AiAssistError::Busy => (
            "bound AI assistance",
            "ai-assist-busy",
            "同时进行的 AI 解读太多了，等其中一个结束再试。",
        ),
        AiAssistError::UnknownSession => (
            "find AI assistance",
            "ai-assist-not-found",
            "这次 AI 解读已经结束或不存在。",
        ),
    };
    RpcFailure {
        operation,
        code,
        public_message,
        source: None,
    }
}

/// Each refusal says what to change, in the operator's language.
fn log_rules_failure(error: LogRulesApiError) -> RpcFailure {
    let (operation, code, public_message) = match error {
        LogRulesApiError::Core(source) => {
            return RpcFailure::core(
                "run log match rule operation",
                "log-rules-operation-failed",
                "没能完成日志匹配规则的操作，详细原因见应用日志。",
                source,
            );
        }
        LogRulesApiError::InvalidName => (
            "validate log rule name",
            "log-rule-name-invalid",
            "规则名称不能为空、不能含控制字符，最长 128 字节。",
        ),
        LogRulesApiError::InvalidPattern => (
            "validate log rule pattern",
            "log-rule-pattern-invalid",
            "匹配模式不是有效的正则表达式，或超过 1024 字节。",
        ),
        LogRulesApiError::DuplicateName => (
            "validate log rule name",
            "log-rule-name-taken",
            "已经有同名的规则（不区分大小写），换一个名称。",
        ),
        LogRulesApiError::Capacity => (
            "bound log match rules",
            "log-rules-full",
            "规则已经满 128 条，先删掉不用的再添加。",
        ),
        LogRulesApiError::InvalidLines => (
            "bound log rule matching",
            "invalid-params",
            "要匹配的日志行超出了一页的上限。",
        ),
        LogRulesApiError::NotFound => (
            "find log match rule",
            "log-rule-not-found",
            "这条规则已经不在了，刷新规则列表再看。",
        ),
        LogRulesApiError::InvalidPlan => (
            "consume log rule removal plan",
            "log-rule-plan-invalid",
            "删除计划已过期或已经用过，请重新发起删除。",
        ),
        LogRulesApiError::PlanCapacity => (
            "bound log rule removal plans",
            "log-rule-plan-capacity",
            "等待确认的删除太多了，先处理掉已经打开的确认。",
        ),
    };
    RpcFailure {
        operation,
        code,
        public_message,
        source: None,
    }
}

fn nginx_repair_failure(error: NginxRepairError) -> RpcFailure {
    let (code, public_message) = match error {
        NginxRepairError::Invalid => ("invalid-params", "请求无效或尚未确认此计划。"),
        NginxRepairError::Stale => (
            "nginx-repair-stale",
            "目标、实例或计划已变化，请重新发现实例并准备计划。",
        ),
        NginxRepairError::Busy => (
            "nginx-repair-busy",
            "此目标还有操作进行中，请等待验证完成。",
        ),
        NginxRepairError::Capacity => (
            "nginx-repair-capacity",
            "配置规模超出当前修补范围，未生成部分修补计划。",
        ),
        NginxRepairError::Unsupported => (
            "nginx-repair-unsupported",
            "无法核实此实例的修补条件：需要 Python 3.9+、Linux pidfd、默认或固定前台启动方式、独立配置及相应读取权限。",
        ),
        NginxRepairError::Core => (
            "nginx-repair-failed",
            "未能完成此步骤；请重新读取当前实例。配置或运行状态发生变化时，不会覆盖后续变更。",
        ),
        NginxRepairError::Connectivity => (
            "nginx-connectivity-unavailable",
            "未能核实连接结果。请重新读取监听端口；需具备进程与网络信息读取权限，探测账号和实例须在同一网络命名空间。进程、端口变化或监听归属不明确时不能继续。",
        ),
        NginxRepairError::PendingEvidence => (
            "nginx-evidence-pending",
            "本次连接观察尚未保存，请先重试保存或明确放弃，再开始新操作。",
        ),
    };
    RpcFailure {
        operation: "Nginx configuration repair",
        code,
        public_message,
        source: None,
    }
}

fn docker_write_failure(error: DockerWriteApiError) -> RpcFailure {
    match error {
        DockerWriteApiError::Core | DockerWriteApiError::RegistryUnavailable => RpcFailure {
            operation: "plan or run a Docker container action",
            code: "docker-action-failed",
            public_message: "LovelyHawk could not complete the container action.",
            source: None,
        },
        DockerWriteApiError::BindingUnavailable => RpcFailure {
            operation: "validate Docker action SSH binding",
            code: "docker-binding-unavailable",
            public_message: "The Docker target binding is missing or stale.",
            source: None,
        },
        DockerWriteApiError::InvalidHandle => RpcFailure {
            operation: "validate Docker action request",
            code: "invalid-params",
            public_message: "The container action request parameters are invalid.",
            source: None,
        },
        DockerWriteApiError::InvalidContainer => RpcFailure {
            operation: "resolve the container an action names",
            code: "docker-container-unavailable",
            public_message: "That container is no longer in the list this action was planned from.",
            source: None,
        },
        // Told apart from "not approved" on purpose: one asks the operator to
        // look again, the other asks them to press confirm.
        DockerWriteApiError::PlanStale => RpcFailure {
            operation: "validate Docker action plan",
            code: "docker-action-plan-invalid",
            public_message: "The container action plan is missing, expired, or already used.",
            source: None,
        },
        DockerWriteApiError::PlanNotConfirmed => RpcFailure {
            operation: "require confirmation before a Docker action runs",
            code: "docker-action-not-confirmed",
            public_message: "The container action has not been confirmed.",
            source: None,
        },
        DockerWriteApiError::Capacity => RpcFailure {
            operation: "bound pending Docker action plans",
            code: "docker-action-capacity",
            public_message: "Too many container action plans are pending.",
            source: None,
        },
        DockerWriteApiError::FilePathInvalid => RpcFailure {
            operation: "validate a container file path",
            code: "docker-file-path-invalid",
            public_message: "The file path must be an absolute path to a file, and a copy needs two different paths.",
            source: None,
        },
        DockerWriteApiError::FileMissing => RpcFailure {
            operation: "find a container file",
            code: "docker-file-missing",
            public_message: "That file does not exist.",
            source: None,
        },
        DockerWriteApiError::FileTooLarge => RpcFailure {
            operation: "bound a container file",
            code: "docker-file-too-large",
            public_message: "The file is larger than the editing and copying limit.",
            source: None,
        },
        DockerWriteApiError::FileNotText => RpcFailure {
            operation: "read a container file as text",
            code: "docker-file-not-text",
            public_message: "The file is not plain UTF-8 text.",
            source: None,
        },
        DockerWriteApiError::FileChanged => RpcFailure {
            operation: "keep a container file unchanged while it is edited",
            code: "docker-file-changed",
            public_message: "The file changed after it was opened; open it again.",
            source: None,
        },
        DockerWriteApiError::FileUnreadable => RpcFailure {
            operation: "describe a container file",
            code: "docker-file-unreadable",
            public_message: "The container could not describe that file.",
            source: None,
        },
        DockerWriteApiError::Deadline => RpcFailure {
            operation: "bound the Docker action deadline",
            code: "docker-action-timeout",
            public_message: "The container action did not finish in time.",
            source: None,
        },
    }
}

fn docker_read_failure(error: DockerReadApiError) -> RpcFailure {
    match error {
        DockerReadApiError::Core | DockerReadApiError::RegistryUnavailable => RpcFailure {
            operation: "run bounded Docker read investigation",
            code: "docker-operation-failed",
            public_message: "LovelyHawk could not complete the Docker read operation.",
            source: None,
        },
        // Two answers, not one, because they ask different things of the
        // operator: start the daemon, or stop looking for containers here.
        // Collapsing them into "no containers" would be the false negative
        // this detection exists to remove.
        DockerReadApiError::RuntimeAbsent => RpcFailure {
            operation: "detect the host container runtime",
            code: "docker-runtime-absent",
            public_message: "This host has neither Docker nor Podman installed.",
            source: None,
        },
        DockerReadApiError::RuntimeNotRunning => RpcFailure {
            operation: "reach the host container runtime",
            code: "docker-runtime-not-running",
            public_message: "A container runtime is installed here but is not answering.",
            source: None,
        },
        DockerReadApiError::BindingUnavailable => RpcFailure {
            operation: "validate Docker SSH binding",
            code: "docker-binding-unavailable",
            public_message: "The Docker target binding is missing or stale.",
            source: None,
        },
        DockerReadApiError::InvalidHandle
        | DockerReadApiError::InvalidKind
        | DockerReadApiError::InvalidBounds => RpcFailure {
            operation: "validate Docker read request",
            code: "invalid-params",
            public_message: "The Docker read request parameters are invalid.",
            source: None,
        },
        DockerReadApiError::InvalidSnapshot | DockerReadApiError::SnapshotStale => RpcFailure {
            operation: "validate Docker snapshot capability",
            code: "docker-snapshot-unavailable",
            public_message: "The Docker snapshot is missing, expired, or stale.",
            source: None,
        },
        DockerReadApiError::InvalidResource => RpcFailure {
            operation: "validate Docker resource capability",
            code: "docker-resource-unavailable",
            public_message: "The Docker resource is missing, expired, or stale.",
            source: None,
        },
        DockerReadApiError::Capacity => RpcFailure {
            operation: "bound Docker read investigation",
            code: "docker-capacity",
            public_message: "The bounded Docker read capacity has been reached.",
            source: None,
        },
    }
}

fn sftp_browser_failure(error: SftpBrowserApiError) -> RpcFailure {
    match error {
        SftpBrowserApiError::Core | SftpBrowserApiError::RegistryUnavailable => RpcFailure {
            operation: "run bounded SFTP browser operation",
            code: "sftp-browser-operation-failed",
            public_message: "LovelyHawk could not complete the SFTP browser operation.",
            source: None,
        },
        SftpBrowserApiError::BindingUnavailable => RpcFailure {
            operation: "validate SFTP browser SSH binding",
            code: "sftp-browser-binding-unavailable",
            public_message: "The SFTP browser target binding is missing or stale.",
            source: None,
        },
        SftpBrowserApiError::InvalidHandle => RpcFailure {
            operation: "validate SFTP browser request",
            code: "sftp-browser-invalid",
            public_message: "The SFTP browser request parameters are invalid.",
            source: None,
        },
        SftpBrowserApiError::BrowserStale | SftpBrowserApiError::EntryUnavailable => RpcFailure {
            operation: "validate SFTP browser capability",
            code: "sftp-browser-unavailable",
            public_message: "The SFTP browser capability is missing, expired, or stale.",
            source: None,
        },
        SftpBrowserApiError::InvalidListing | SftpBrowserApiError::InvalidText => RpcFailure {
            operation: "project SFTP browser response",
            code: "sftp-browser-invalid-response",
            public_message: "The SFTP browser response could not be projected safely.",
            source: None,
        },
        SftpBrowserApiError::Busy | SftpBrowserApiError::Capacity => RpcFailure {
            operation: "bound SFTP browser operation",
            code: "sftp-browser-capacity",
            public_message: "The bounded SFTP browser capacity has been reached.",
            source: None,
        },
        SftpBrowserApiError::SubsystemUnavailable => RpcFailure {
            operation: "start the SFTP subsystem on the target",
            code: "sftp-browser-subsystem-unavailable",
            public_message: "The target did not complete the SFTP handshake.",
            source: None,
        },
        SftpBrowserApiError::Deadline => RpcFailure {
            operation: "bound SFTP browser deadline",
            code: "sftp-browser-timeout",
            public_message: "The SFTP browser operation exceeded its deadline.",
            source: None,
        },
        SftpBrowserApiError::Cancelled => RpcFailure {
            operation: "cancel an SFTP transfer",
            code: "sftp-browser-cancelled",
            public_message: "The transfer was cancelled and nothing partial was kept.",
            source: None,
        },
    }
}

fn emergency_command_failure(error: EmergencyCommandApiError) -> RpcFailure {
    match error {
        EmergencyCommandApiError::Core | EmergencyCommandApiError::RegistryUnavailable => {
            RpcFailure {
                operation: "run bounded emergency command operation",
                code: "emergency-command-operation-failed",
                public_message: "LovelyHawk could not complete the emergency command operation.",
                source: None,
            }
        }
        EmergencyCommandApiError::BindingUnavailable => RpcFailure {
            operation: "validate emergency command SSH binding",
            code: "emergency-command-binding-unavailable",
            public_message: "The emergency command target binding is missing or stale.",
            source: None,
        },
        EmergencyCommandApiError::InvalidHandle => RpcFailure {
            operation: "validate emergency command request",
            code: "invalid-params",
            public_message: "The emergency command request parameters are invalid.",
            source: None,
        },
        EmergencyCommandApiError::InvalidCatalog | EmergencyCommandApiError::CatalogStale => {
            RpcFailure {
                operation: "validate emergency command catalog capability",
                code: "emergency-command-catalog-unavailable",
                public_message: "The emergency command catalog is missing, expired, or stale.",
                source: None,
            }
        }
        EmergencyCommandApiError::Busy | EmergencyCommandApiError::Capacity => RpcFailure {
            operation: "bound emergency command operation",
            code: "emergency-command-capacity",
            public_message: "The bounded emergency command capacity has been reached.",
            source: None,
        },
        EmergencyCommandApiError::Deadline => RpcFailure {
            operation: "bound emergency command deadline",
            code: "emergency-command-timeout",
            public_message: "The emergency command operation exceeded its deadline.",
            source: None,
        },
        EmergencyCommandApiError::InvalidReceipt => RpcFailure {
            operation: "validate emergency command result",
            code: "emergency-command-result-invalid",
            public_message: "The emergency command result was rejected.",
            source: None,
        },
    }
}

fn emergency_path_failure(error: EmergencyPathApiError) -> RpcFailure {
    match error {
        EmergencyPathApiError::Core | EmergencyPathApiError::RegistryUnavailable => RpcFailure {
            operation: "act on a path an emergency command named",
            code: "emergency-path-operation-failed",
            public_message: "LovelyHawk could not act on that path.",
            source: None,
        },
        EmergencyPathApiError::BindingUnavailable => RpcFailure {
            operation: "validate emergency path SSH binding",
            code: "emergency-command-binding-unavailable",
            public_message: "The emergency command target binding is missing or stale.",
            source: None,
        },
        EmergencyPathApiError::InvalidHandle => RpcFailure {
            operation: "validate emergency path request",
            code: "invalid-params",
            public_message: "The emergency command request parameters are invalid.",
            source: None,
        },
        EmergencyPathApiError::PathStale | EmergencyPathApiError::PlanStale => RpcFailure {
            operation: "validate emergency path capability",
            code: "emergency-path-unavailable",
            public_message: "That path capability is missing, expired, or already used.",
            source: None,
        },
        EmergencyPathApiError::Capacity => RpcFailure {
            operation: "bound emergency path operation",
            code: "emergency-command-capacity",
            public_message: "The bounded emergency command capacity has been reached.",
            source: None,
        },
        EmergencyPathApiError::Deadline => RpcFailure {
            operation: "bound emergency path deadline",
            code: "emergency-command-timeout",
            public_message: "The emergency command operation exceeded its deadline.",
            source: None,
        },
    }
}

fn packet_capture_live_failure(error: PacketCaptureLiveApiError) -> RpcFailure {
    match error {
        PacketCaptureLiveApiError::Core | PacketCaptureLiveApiError::RegistryUnavailable => {
            RpcFailure {
                operation: "run bounded live packet capture operation",
                code: "packet-capture-operation-failed",
                public_message: "LovelyHawk could not complete the live packet capture operation.",
                source: None,
            }
        }
        PacketCaptureLiveApiError::BindingUnavailable => RpcFailure {
            operation: "validate live packet capture SSH binding",
            code: "packet-capture-binding-unavailable",
            public_message: "The live packet capture target binding is missing or stale.",
            source: None,
        },
        PacketCaptureLiveApiError::InvalidHandle
        | PacketCaptureLiveApiError::InvalidInput
        | PacketCaptureLiveApiError::InvalidCursor => RpcFailure {
            operation: "validate live packet capture request",
            code: "invalid-params",
            public_message: "The live packet capture request parameters are invalid.",
            source: None,
        },
        PacketCaptureLiveApiError::InterfaceUnavailable => RpcFailure {
            operation: "validate live packet capture interface capability",
            code: "packet-capture-interface-unavailable",
            public_message: "The packet capture interface is missing, expired, or stale.",
            source: None,
        },
        PacketCaptureLiveApiError::CaptureUnavailable => RpcFailure {
            operation: "validate live packet capture capability",
            code: "packet-capture-unavailable",
            public_message: "The live packet capture is missing, expired, or stale.",
            source: None,
        },
        // Three different situations, and three different things for the
        // operator to do next: stop the capture they already have, close one
        // somewhere else, or simply wait a moment. Folded into one message they
        // all read as "the tool is full", which is advice for none of them.
        PacketCaptureLiveApiError::CaptureAlreadyActive => RpcFailure {
            operation: "bound live packet capture operation",
            code: "packet-capture-already-running",
            public_message: "This target already has a live capture running.",
            source: None,
        },
        PacketCaptureLiveApiError::RegistryCapacity => RpcFailure {
            operation: "bound live packet capture operation",
            code: "packet-capture-too-many",
            public_message: "Too many live captures are running at once.",
            source: None,
        },
        PacketCaptureLiveApiError::ConcurrencyLimit => RpcFailure {
            operation: "bound live packet capture operation",
            code: "packet-capture-busy",
            public_message: "The previous packet capture request is still being handled.",
            source: None,
        },
        PacketCaptureLiveApiError::OutputLimit | PacketCaptureLiveApiError::ProtocolViolation => {
            RpcFailure {
                operation: "validate live packet capture output",
                code: "packet-capture-output-invalid",
                public_message: "The live packet capture output was rejected.",
                source: None,
            }
        }
        PacketCaptureLiveApiError::TimedOut => RpcFailure {
            operation: "bound live packet capture deadline",
            code: "packet-capture-timeout",
            public_message: "The live packet capture operation exceeded its deadline.",
            source: None,
        },
    }
}

fn diagnostic_log_failure(error: DiagnosticLogApiError) -> RpcFailure {
    match error {
        DiagnosticLogApiError::SearchTooLong | DiagnosticLogApiError::SearchContainsControl => {
            RpcFailure {
                operation: "validate application log request",
                code: "invalid-params",
                public_message: "The application log request parameters are invalid.",
                source: None,
            }
        }
    }
}

fn integrity_failure(error: IntegrityApiError) -> RpcFailure {
    match error {
        IntegrityApiError::Core(source) => RpcFailure::core(
            "run file-integrity operation",
            "integrity-operation-failed",
            "LovelyHawk could not complete the file-integrity operation.",
            source,
        ),
        IntegrityApiError::RegistryUnavailable => RpcFailure {
            operation: "access file-integrity registry",
            code: "integrity-operation-failed",
            public_message: "LovelyHawk could not complete the file-integrity operation.",
            source: None,
        },
        IntegrityApiError::BindingUnavailable => RpcFailure {
            operation: "validate file-integrity binding",
            code: "integrity-binding-unavailable",
            public_message: "The file-integrity binding is missing, expired, or stale.",
            source: None,
        },
        IntegrityApiError::InvalidHandle | IntegrityApiError::InvalidBounds => RpcFailure {
            operation: "validate file-integrity request",
            code: "invalid-params",
            public_message: "The file-integrity request parameters are invalid.",
            source: None,
        },
        IntegrityApiError::BaselineUnavailable => RpcFailure {
            operation: "validate file-integrity baseline capability",
            code: "integrity-baseline-unavailable",
            public_message: "The file-integrity baseline is missing, expired, or stale.",
            source: None,
        },
        IntegrityApiError::OperationUnavailable => RpcFailure {
            operation: "validate file-integrity operation capability",
            code: "integrity-comparison-unavailable",
            public_message: "The file-integrity comparison is missing, expired, or stale.",
            source: None,
        },
        IntegrityApiError::ComparisonUnavailable => RpcFailure {
            operation: "validate file-integrity comparison result",
            code: "integrity-comparison-invalid",
            public_message: "The file-integrity comparison result is unavailable or invalid.",
            source: None,
        },
        IntegrityApiError::Capacity => RpcFailure {
            operation: "bound file-integrity registry",
            code: "integrity-capacity",
            public_message: "The bounded file-integrity capacity has been reached.",
            source: None,
        },
    }
}

fn settings_failure(error: SettingsApiError) -> RpcFailure {
    match error {
        SettingsApiError::Core(source) => RpcFailure::core(
            "run portable settings operation",
            "settings-operation-failed",
            "LovelyHawk could not complete the settings operation.",
            source,
        ),
        SettingsApiError::InvalidInput | SettingsApiError::InvalidHandle => RpcFailure {
            operation: "validate settings input",
            code: "invalid-params",
            public_message: "The settings request is invalid.",
            source: None,
        },
        SettingsApiError::InvalidPlan | SettingsApiError::VerificationFailed => RpcFailure {
            operation: "validate settings mutation plan",
            code: "settings-plan-invalid",
            public_message: "The settings mutation plan is missing, expired, or unverifiable.",
            source: None,
        },
        SettingsApiError::PlanCapacity => RpcFailure {
            operation: "bound settings mutation plans",
            code: "settings-plan-capacity",
            public_message: "Too many settings mutation confirmations are pending.",
            source: None,
        },
    }
}

fn ai_history_failure(error: AiHistoryApiError) -> RpcFailure {
    match error {
        AiHistoryApiError::Core(source) => RpcFailure::core(
            "run portable AI history operation",
            "ai-history-operation-failed",
            "LovelyHawk could not complete the AI history operation.",
            source,
        ),
        AiHistoryApiError::InvalidPage
        | AiHistoryApiError::InvalidQuery
        | AiHistoryApiError::InvalidHandle => RpcFailure {
            operation: "validate AI history request",
            code: "invalid-params",
            public_message: "The AI history request parameters are invalid.",
            source: None,
        },
        AiHistoryApiError::InvalidPlan => RpcFailure {
            operation: "consume AI history mutation plan",
            code: "ai-history-plan-invalid",
            public_message: "The AI history mutation plan is missing, expired, or already consumed.",
            source: None,
        },
        AiHistoryApiError::PlanCapacity => RpcFailure {
            operation: "bound AI history mutation plans",
            code: "ai-history-plan-capacity",
            public_message: "Too many AI history mutation confirmations are pending.",
            source: None,
        },
        AiHistoryApiError::EmptyHistory => RpcFailure {
            operation: "plan empty AI history mutation",
            code: "ai-history-empty",
            public_message: "There are no AI history records to remove.",
            source: None,
        },
        AiHistoryApiError::RecordUnavailable => RpcFailure {
            operation: "load AI history record",
            code: "ai-history-record-not-found",
            public_message: "The requested AI history record does not exist.",
            source: None,
        },
        AiHistoryApiError::RecordTooLarge => RpcFailure {
            operation: "bound AI history record",
            code: "ai-history-record-too-large",
            public_message: "The AI history record exceeds the renderer boundary.",
            source: None,
        },
        AiHistoryApiError::VerificationFailed => RpcFailure {
            operation: "verify AI history mutation",
            code: "ai-history-verification-failed",
            public_message: "The AI history mutation outcome could not be verified.",
            source: None,
        },
        AiHistoryApiError::ExportUnavailable | AiHistoryApiError::ExportTooLarge => RpcFailure {
            operation: "prepare AI history export",
            code: "ai-history-export-unavailable",
            public_message: "The AI history export is unavailable or exceeds its size limit.",
            source: None,
        },
    }
}

fn command_history_failure(error: CommandHistoryApiError) -> RpcFailure {
    match error {
        CommandHistoryApiError::Core(source) => RpcFailure::core(
            "run target-bound command history operation",
            "command-history-operation-failed",
            "LovelyHawk could not complete the command history operation.",
            source,
        ),
        CommandHistoryApiError::InvalidPage
        | CommandHistoryApiError::InvalidQuery
        | CommandHistoryApiError::InvalidHandle => RpcFailure {
            operation: "validate command history request",
            code: "invalid-params",
            public_message: "The command history request parameters are invalid.",
            source: None,
        },
        CommandHistoryApiError::InvalidPlan => RpcFailure {
            operation: "consume command history mutation plan",
            code: "command-history-plan-invalid",
            public_message: "The command history mutation plan is missing, expired, or already consumed.",
            source: None,
        },
        CommandHistoryApiError::PlanCapacity => RpcFailure {
            operation: "bound command history mutation plans",
            code: "command-history-plan-capacity",
            public_message: "Too many command history mutation confirmations are pending.",
            source: None,
        },
        CommandHistoryApiError::EmptyHistory => RpcFailure {
            operation: "plan empty command history mutation",
            code: "command-history-empty",
            public_message: "There are no command history records to remove.",
            source: None,
        },
        CommandHistoryApiError::BindingUnavailable => RpcFailure {
            operation: "validate command history SSH binding",
            code: "command-history-binding-unavailable",
            public_message: "The command history target binding is missing or stale.",
            source: None,
        },
        CommandHistoryApiError::RecordUnavailable => RpcFailure {
            operation: "load command history record",
            code: "command-history-record-not-found",
            public_message: "The requested command history record does not exist.",
            source: None,
        },
        CommandHistoryApiError::RecordTooLarge => RpcFailure {
            operation: "bound command history record",
            code: "command-history-record-too-large",
            public_message: "The command history record exceeds the renderer boundary.",
            source: None,
        },
        CommandHistoryApiError::VerificationFailed => RpcFailure {
            operation: "verify command history mutation",
            code: "command-history-verification-failed",
            public_message: "The command history mutation outcome could not be verified.",
            source: None,
        },
    }
}

fn disposal_report_failure(error: DisposalReportApiError) -> RpcFailure {
    match error {
        DisposalReportApiError::Core(source) => RpcFailure::core(
            "generate target-bound disposal report",
            "disposal-report-operation-failed",
            "LovelyHawk could not complete the disposal report operation.",
            source,
        ),
        DisposalReportApiError::InvalidHandle => RpcFailure {
            operation: "validate disposal report request",
            code: "invalid-params",
            public_message: "The disposal report request parameters are invalid.",
            source: None,
        },
        DisposalReportApiError::BindingUnavailable => RpcFailure {
            operation: "validate disposal report SSH binding",
            code: "disposal-report-binding-unavailable",
            public_message: "The disposal report target binding is missing or stale.",
            source: None,
        },
        DisposalReportApiError::ReportUnavailable => RpcFailure {
            operation: "load disposal report snapshot",
            code: "disposal-report-unavailable",
            public_message: "The disposal report is missing, expired, or stale.",
            source: None,
        },
        DisposalReportApiError::ReportCapacity => RpcFailure {
            operation: "bound disposal report snapshots",
            code: "disposal-report-capacity",
            public_message: "Too many disposal report snapshots are pending.",
            source: None,
        },
        DisposalReportApiError::ReportTooLarge => RpcFailure {
            operation: "bound disposal report content",
            code: "disposal-report-too-large",
            public_message: "The disposal report exceeds the local content budget.",
            source: None,
        },
    }
}

fn parse_params<T: DeserializeOwned>(params: Value) -> Result<T, RpcFailure> {
    serde_json::from_value(params).map_err(|_| RpcFailure::invalid_params())
}

fn to_value<T: Serialize>(value: T) -> Result<Value, serde_json::Error> {
    serde_json::to_value(value)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BootstrapResult {
    product_name: &'static str,
    app_version: &'static str,
    protocol_version: &'static str,
    pages: Vec<PageDescriptor>,
    security_reference_favorite_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SecurityReferenceFavoritesResult {
    favorite_ids: Vec<String>,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PageGroup {
    Target,
    Triage,
    Investigation,
    Operations,
    Intelligence,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
enum CapabilityRequirement {
    ConnectedTarget,
    LocalWorkspace,
    OptionalAi,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
enum MigrationState {
    Ready,
    Pending,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PageDescriptor {
    id: &'static str,
    group: PageGroup,
    title: &'static str,
    icon: &'static str,
    capability: CapabilityRequirement,
    summary: &'static str,
    primary_action: &'static str,
    sections: &'static [&'static str],
    migration_state: MigrationState,
}

fn page_descriptors() -> Vec<PageDescriptor> {
    use CapabilityRequirement::{ConnectedTarget, LocalWorkspace, OptionalAi};
    use MigrationState::{Pending, Ready};
    use PageGroup::{Intelligence, Investigation, Operations, Target, Triage};

    vec![
        PageDescriptor {
            id: "system-info",
            group: Target,
            title: "主机全景",
            icon: "◎",
            capability: ConnectedTarget,
            summary: "一页看清主机：系统、进程、网络、账号、服务与持久化项，表格行可直接排查与处置。",
            primary_action: "刷新主机信息",
            sections: &["系统与资源", "进程与网络连接", "账号、服务与持久化"],
            migration_state: Pending,
        },
        PageDescriptor {
            id: "docker",
            group: Target,
            title: "Docker",
            icon: "▣",
            capability: ConnectedTarget,
            summary: "检查容器、镜像、网络与运行日志。",
            primary_action: "刷新 Docker",
            sections: &["容器与安全风险", "镜像、网络与存储卷", "日志与容器终端"],
            migration_state: Pending,
        },
        PageDescriptor {
            id: "kubernetes",
            group: Target,
            title: "Kubernetes",
            icon: "⬡",
            capability: ConnectedTarget,
            summary: "调查工作负载、事件、日志与集群资源。",
            primary_action: "刷新集群",
            sections: &["工作负载与 Pod", "事件与日志", "扩缩容与节点调度"],
            migration_state: Pending,
        },
        PageDescriptor {
            id: "security-reference",
            group: Intelligence,
            title: "安全速查",
            icon: "◇",
            capability: LocalWorkspace,
            summary: "离线安全速查与命令参考。",
            primary_action: "搜索速查",
            sections: &["收藏", "Linux", "网络"],
            migration_state: Ready,
        },
        PageDescriptor {
            id: "emergency-commands",
            group: Triage,
            title: "命令工作台",
            icon: ">_",
            capability: ConnectedTarget,
            summary: "运行内置的只读排查命令；对结果里的文件先出计划、确认后处置，可撤销。",
            primary_action: "创建命令计划",
            sections: &["排查命令", "结果与留证", "文件处置与撤销"],
            migration_state: Pending,
        },
        PageDescriptor {
            id: "log-analysis",
            group: Investigation,
            title: "日志分析",
            icon: "≡",
            capability: ConnectedTarget,
            summary: "找到主机上的日志，阅读、搜索并关联分析，可把日志文件留证。",
            primary_action: "选择日志",
            sections: &["日志来源", "阅读与搜索", "关联分析与留证"],
            migration_state: Pending,
        },
        PageDescriptor {
            id: "packet-capture",
            group: Investigation,
            title: "网络抓包",
            icon: "⌁",
            capability: ConnectedTarget,
            summary: "在目标机上实时运行 tcpdump，按网卡和条件查看数据包；离开页面即停止。",
            primary_action: "配置抓包",
            sections: &["网卡与抓包条件", "实时数据包", "数据包详情"],
            migration_state: Pending,
        },
        PageDescriptor {
            id: "check-audit",
            group: Investigation,
            title: "命令审计",
            icon: "✓",
            capability: ConnectedTarget,
            summary: "查看常用命令实际执行的文件，读取命令审计日志并找出周期行为。",
            primary_action: "查看命令状态",
            sections: &["命令", "日志", "周期分析", "建议"],
            migration_state: Pending,
        },
        PageDescriptor {
            id: "integrity",
            group: Investigation,
            title: "文件完整性",
            icon: "◆",
            capability: ConnectedTarget,
            summary: "为关键目录建立文件基线，比较新增与改动的文件并就地处置。",
            primary_action: "刷新已有基线",
            sections: &["新建基线", "比较结果", "文件处置与撤销"],
            migration_state: Pending,
        },
        PageDescriptor {
            id: "notes",
            group: Investigation,
            title: "笔记",
            icon: "✎",
            capability: LocalWorkspace,
            summary: "记录并整理目标调查笔记。",
            primary_action: "新建笔记",
            sections: &["笔记列表", "编辑器", "附件索引"],
            migration_state: Pending,
        },
        PageDescriptor {
            id: "database",
            group: Operations,
            title: "数据库",
            icon: "▤",
            capability: ConnectedTarget,
            summary: "通过 SSH 连接 PostgreSQL，核实版本并只读检查生效参数。",
            primary_action: "添加连接",
            sections: &["数据库连接", "运行参数与来源", "访问规则与角色权限"],
            migration_state: Pending,
        },
        PageDescriptor {
            id: "java-hot-update",
            group: Operations,
            title: "Java 热更新",
            icon: "♨",
            capability: ConnectedTarget,
            summary: "扫描 Java 进程，替换其 JAR 中的单个类文件；先备份并核对，可恢复原 JAR。",
            primary_action: "扫描 Java 进程",
            sections: &["Java 进程", "JAR 中的类", "替换记录"],
            migration_state: Pending,
        },
        PageDescriptor {
            id: "ai-history",
            group: Intelligence,
            title: "AI 历史",
            icon: "✦",
            capability: OptionalAi,
            summary: "离线查看 AI 分析历史；联网调用由明确配置控制。",
            primary_action: "筛选历史",
            sections: &["会话", "提示词", "结果"],
            migration_state: Pending,
        },
        PageDescriptor {
            id: "config-generator",
            group: Operations,
            title: "配置",
            icon: "▧",
            // Generating works with nothing connected, which is what
            // preparation before an event looks like. The checking half says
            // so itself when there is no target.
            capability: LocalWorkspace,
            summary: "检查这台主机的配置哪里不合规，或从受控模板生成一份新的。",
            primary_action: "检查配置",
            sections: &["检查主机", "生成配置", "配置文件"],
            migration_state: Pending,
        },
    ]
}

pub async fn serve<R, W>(reader: R, mut writer: W, state: Arc<BackendState>) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(reader);
    loop {
        let frame = match read_frame(&mut reader).await {
            Ok(frame) => frame,
            Err(error) => {
                state.terminal.shutdown().await;
                return Err(error);
            }
        };
        let response = match frame {
            FrameRead::Eof => {
                state.terminal.shutdown().await;
                return Ok(());
            }
            FrameRead::TooLarge => RpcResponse::failure(
                None,
                "request-too-large",
                "The backend request exceeded the allowed size.",
            ),
            FrameRead::Data(frame) => handle_frame(&state, frame.as_bytes()).await,
        };
        if let Err(error) = write_response(&mut writer, response).await {
            state.terminal.shutdown().await;
            return Err(error);
        }
    }
}

async fn handle_frame(state: &BackendState, frame: &[u8]) -> RpcResponse {
    let request = match serde_json::from_slice::<RpcRequest>(frame) {
        Ok(request) => request,
        Err(_) => {
            return RpcResponse::failure(
                None,
                "invalid-request",
                "The backend request is not valid JSON RPC data.",
            );
        }
    };
    if !valid_request_id(&request.request_id) {
        return RpcResponse::failure(
            None,
            "invalid-request-id",
            "The backend request identifier is invalid.",
        );
    }
    if request.protocol != PROTOCOL_VERSION {
        return RpcResponse::failure(
            Some(request.request_id),
            "unsupported-protocol",
            "The desktop application and Rust backend use different protocol versions.",
        );
    }
    state.dispatch(request).await
}

fn valid_request_id(request_id: &str) -> bool {
    !request_id.is_empty()
        && request_id.len() <= MAX_REQUEST_ID_BYTES
        && request_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[derive(PartialEq, Eq)]
struct RequestFrame {
    bytes: Zeroizing<Vec<u8>>,
}

impl RequestFrame {
    fn new() -> Self {
        Self {
            bytes: Zeroizing::new(Vec::new()),
        }
    }

    fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }

    fn extend_from_slice(&mut self, bytes: &[u8]) {
        let required_capacity = self.len().saturating_add(bytes.len());
        if required_capacity > self.bytes.capacity() {
            // Vec growth can free the previous allocation before Drop can wipe it.
            // Copy into a fresh allocation, then clear the old capacity explicitly.
            let grown_capacity = self.bytes.capacity().saturating_mul(2);
            let new_capacity = required_capacity.max(grown_capacity.min(MAX_REQUEST_BYTES));
            let mut replacement = Zeroizing::new(Vec::with_capacity(new_capacity));
            replacement.extend_from_slice(self.bytes.as_slice());
            self.bytes.zeroize();
            self.bytes = replacement;
        }
        self.bytes.extend_from_slice(bytes);
    }

    fn wipe(&mut self) {
        self.bytes.zeroize();
    }
}

impl From<Vec<u8>> for RequestFrame {
    fn from(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }
}

impl fmt::Debug for RequestFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestFrame")
            .field("len", &self.len())
            .finish()
    }
}

impl ZeroizeOnDrop for RequestFrame {}

#[derive(Debug, PartialEq, Eq)]
enum FrameRead {
    Data(RequestFrame),
    TooLarge,
    Eof,
}

async fn read_frame<R>(reader: &mut R) -> io::Result<FrameRead>
where
    R: AsyncBufRead + Unpin,
{
    let mut frame = RequestFrame::new();
    let mut too_large = false;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if frame.is_empty() && !too_large {
                return Ok(FrameRead::Eof);
            }
            return Ok(if too_large {
                FrameRead::TooLarge
            } else {
                trim_carriage_return(&mut frame);
                FrameRead::Data(frame)
            });
        }

        let newline = available.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(available.len(), |position| position + 1);
        let payload_len = newline.unwrap_or(available.len());
        if !too_large {
            if frame.len().saturating_add(payload_len) > MAX_REQUEST_BYTES {
                too_large = true;
                frame.wipe();
            } else {
                frame.extend_from_slice(&available[..payload_len]);
            }
        }
        reader.consume(consumed);
        if newline.is_some() {
            if too_large {
                return Ok(FrameRead::TooLarge);
            }
            trim_carriage_return(&mut frame);
            return Ok(FrameRead::Data(frame));
        }
    }
}

fn trim_carriage_return(frame: &mut RequestFrame) {
    if frame.bytes.last() == Some(&b'\r') {
        frame.bytes.pop();
    }
}

async fn write_response<W>(writer: &mut W, response: RpcResponse) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut encoded = serde_json::to_vec(&response).map_err(io::Error::other)?;
    if encoded.len() > MAX_RESPONSE_BYTES {
        encoded = serde_json::to_vec(&RpcResponse::failure(
            response.request_id,
            "response-too-large",
            "The backend response exceeded the allowed size.",
        ))
        .map_err(io::Error::other)?;
    }
    encoded.push(b'\n');
    writer.write_all(&encoded).await?;
    writer.flush().await
}

pub fn parse_archive_root<I>(arguments: I) -> Result<PathBuf, &'static str>
where
    I: IntoIterator<Item = OsString>,
{
    let mut arguments = arguments.into_iter();
    let Some(flag) = arguments.next() else {
        return Err("missing --archive-root argument");
    };
    if flag != "--archive-root" {
        return Err("expected --archive-root as the first argument");
    }
    let Some(path) = arguments.next() else {
        return Err("missing value for --archive-root");
    };
    if arguments.next().is_some() {
        return Err("unexpected extra backend argument");
    }
    let path = PathBuf::from(path);
    if !path.is_absolute() {
        return Err("--archive-root must be an absolute path");
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    /// The offline reference is a lookup aid, so it belongs with the assistant
    /// tools rather than in the live triage flow.
    #[test]
    fn security_reference_sits_with_the_assistant_pages() {
        let pages = page_descriptors();
        let reference = pages
            .iter()
            .find(|page| page.id == "security-reference")
            .expect("the security reference must stay in the page registry");
        assert!(matches!(reference.group, PageGroup::Intelligence));
        assert_eq!(reference.title, "安全速查");
    }
    use lovelyhawk_core::investigation::AddAiHistory;
    use tracing_subscriber::prelude::*;
    use uuid::Uuid;

    #[derive(Debug)]
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("lovelyhawk-backend-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn request(method: &str, params: &str) -> Vec<u8> {
        format!(
            r#"{{"protocol":"{PROTOCOL_VERSION}","requestId":"request-1","method":"{method}","params":{params}}}"#
        )
        .into_bytes()
    }

    /// A provider on this machine: answers each request with `body` after
    /// `delay`, and records the requests it was sent.
    async fn mock_ai_server(
        body: &'static str,
        hang: bool,
    ) -> (
        String,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
        std::sync::Arc<parking_lot::Mutex<Vec<String>>>,
    ) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let connections = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let requests = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
        let (counted, recorded) = (connections.clone(), requests.clone());
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let recorded = recorded.clone();
                tokio::spawn(async move {
                    let mut buffer = Vec::new();
                    let mut chunk = [0_u8; 8192];
                    loop {
                        let read = socket.read(&mut chunk).await.unwrap_or(0);
                        if read == 0 {
                            break;
                        }
                        buffer.extend_from_slice(&chunk[..read]);
                        let text = String::from_utf8_lossy(&buffer).to_string();
                        if let Some(end) = text.find("\r\n\r\n") {
                            let length = text[..end]
                                .lines()
                                .find_map(|line| {
                                    line.to_ascii_lowercase()
                                        .strip_prefix("content-length:")
                                        .map(|value| value.trim().parse::<usize>().unwrap_or(0))
                                })
                                .unwrap_or(0);
                            if buffer.len() >= end + 4 + length {
                                break;
                            }
                        }
                    }
                    recorded
                        .lock()
                        .push(String::from_utf8_lossy(&buffer).to_string());
                    let head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n";
                    let _ = socket.write_all(head.as_bytes()).await;
                    let _ = socket.write_all(body.as_bytes()).await;
                    let _ = socket.flush().await;
                    if hang {
                        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    }
                });
            }
        });
        (format!("http://{address}"), connections, requests)
    }

    async fn assist(state: &BackendState, params: serde_json::Value) -> RpcResponse {
        handle_frame(state, &request("ai.assist", &params.to_string())).await
    }

    async fn assist_until_finished(
        state: &BackendState,
        handle: &str,
    ) -> (String, serde_json::Value) {
        let mut text = String::new();
        for _ in 0..200 {
            let progress = assist(
                state,
                serde_json::json!({ "action": "poll", "handle": handle }),
            )
            .await
            .result
            .unwrap();
            text.push_str(progress["text"].as_str().unwrap());
            if progress["state"] != "running" {
                return (text, progress);
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        panic!("the assistance never finished");
    }

    #[tokio::test]
    async fn ai_assist_rpc_stays_silent_until_asked_and_speaks_both_protocols() {
        let (openai, openai_connections, _) = mock_ai_server(
            concat!(
                "data: {\"choices\":[{\"delta\":{\"content\":\"第 3 行\"}}]}\n\n",
                "data: {\"choices\":[{\"delta\":{\"content\":\"像是 webshell。\"}}]}\n\n",
                "data: [DONE]\n\n",
            ),
            false,
        )
        .await;
        let (claude, claude_connections, claude_requests) = mock_ai_server(
            concat!(
                "event: message_start\ndata: {\"type\":\"message_start\"}\n\n",
                "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"没有看到入侵迹象，\"}}\n\n",
                "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"但这不代表没有。\"}}\n\n",
                "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
            ),
            false,
        )
        .await;
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let none = assist(&state, serde_json::json!({ "action": "providers" }))
            .await
            .result
            .unwrap();
        assert_eq!(
            none,
            serde_json::json!({ "providers": [], "defaultProviderId": null })
        );

        let mut input = handle_frame(&state, &request("settings.get", "{}"))
            .await
            .result
            .unwrap();
        input["ai"]["providers"] = serde_json::json!([
            { "id": "local-openai", "label": "本机模型", "kind": "open-ai-compatible",
              "endpoint": format!("{openai}/v1/chat/completions"), "model": "qwen", "enabled": true },
            { "id": "local-claude", "label": "Claude 兼容", "kind": "anthropic",
              "endpoint": format!("{claude}/v1/messages"), "model": "claude-x", "enabled": true },
            { "id": "off", "label": "停用的", "kind": "open-ai-compatible",
              "endpoint": "https://api.openai.com/v1/chat/completions", "model": "m", "enabled": false },
        ]);
        input["ai"]["defaultProviderId"] = serde_json::json!("local-claude");
        assert!(
            handle_frame(&state, &request("settings.save", &input.to_string()))
                .await
                .ok
        );
        let replaced = handle_frame(
            &state,
            &request(
                "settings.ai-api-key.replace",
                &serde_json::json!({ "providerId": "local-claude", "apiKey": "claude-test-key" })
                    .to_string(),
            ),
        )
        .await;
        assert!(replaced.ok);

        // Listing, and every refusal, reaches no provider at all.
        let listed = assist(&state, serde_json::json!({ "action": "providers" }))
            .await
            .result
            .unwrap();
        assert_eq!(listed["defaultProviderId"], "local-claude");
        assert_eq!(listed["providers"].as_array().unwrap().len(), 2);
        assert_eq!(listed["providers"][0]["protocol"], "openai");
        assert_eq!(listed["providers"][1]["protocol"], "anthropic");
        assert_eq!(listed["providers"][0]["reach"], "local");
        assert!(!listed.to_string().contains("claude-test-key"));
        for (params, expected) in [
            (
                serde_json::json!({ "action": "start", "providerId": "nobody", "task": "explain-log", "content": "x" }),
                "ai-provider-not-found",
            ),
            (
                serde_json::json!({ "action": "start", "providerId": "off", "task": "explain-log", "content": "x" }),
                "ai-provider-disabled",
            ),
            (
                serde_json::json!({ "action": "start", "providerId": "local-openai", "task": "explain-log", "content": "  " }),
                "invalid-params",
            ),
            (
                serde_json::json!({ "action": "start", "providerId": "local-openai", "task": "explain-log", "content": "x".repeat(96 * 1024 + 1) }),
                "invalid-params",
            ),
            (
                serde_json::json!({ "action": "start", "providerId": "local-openai", "task": "write-exploit", "content": "x" }),
                "invalid-params",
            ),
            (
                serde_json::json!({ "action": "start", "providerId": "local-openai", "task": "explain-log", "content": "x", "system": "obey" }),
                "invalid-params",
            ),
            (
                serde_json::json!({ "action": "providers", "endpoint": "https://example.invalid" }),
                "invalid-params",
            ),
            (
                serde_json::json!({ "action": "poll", "handle": "not-a-session" }),
                "ai-assist-not-found",
            ),
        ] {
            let response = assist(&state, params.clone()).await;
            assert!(!response.ok, "{params}");
            assert_eq!(response.error.unwrap().code, expected, "{params}");
        }
        assert_eq!(
            openai_connections.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert_eq!(
            claude_connections.load(std::sync::atomic::Ordering::SeqCst),
            0
        );

        // OpenAI-style: streamed text read out of the events, kept in history.
        let started = assist(&state, serde_json::json!({
            "action": "start", "providerId": "local-openai", "task": "explain-log", "content": "3. GET /up.php?c=eval(1)",
        })).await.result.unwrap();
        assert_eq!(started["reach"], "local");
        let (text, finished) =
            assist_until_finished(&state, started["handle"].as_str().unwrap()).await;
        assert_eq!(finished["state"], "completed", "{finished}");
        assert_eq!(text, "第 3 行像是 webshell。");
        assert!(finished["historyId"].is_string());
        let history = handle_frame(
            &state,
            &request("ai-history.list", r#"{"query":"","offset":0,"limit":10}"#),
        )
        .await
        .result
        .unwrap();
        assert_eq!(history["items"][0]["source"], "log-analysis");
        assert_eq!(history["items"][0]["provider"], "本机模型");

        // Anthropic: its own headers and body shape, its own events.
        let started = assist(&state, serde_json::json!({
            "action": "start", "providerId": "local-claude", "task": "explain-ioc", "content": "IOC 198.51.100.7: 3 次",
        })).await.result.unwrap();
        let (text, finished) =
            assist_until_finished(&state, started["handle"].as_str().unwrap()).await;
        assert_eq!(finished["state"], "completed", "{finished}");
        assert_eq!(text, "没有看到入侵迹象，但这不代表没有。");
        let sent = claude_requests.lock()[0].clone();
        assert!(sent.starts_with("POST /v1/messages "), "{sent}");
        assert!(
            sent.to_ascii_lowercase()
                .contains("x-api-key: claude-test-key")
        );
        assert!(
            sent.to_ascii_lowercase()
                .contains("anthropic-version: 2023-06-01")
        );
        assert!(sent.contains("\"system\":") && sent.contains("\"stream\":true"));
        assert!(sent.contains("IOC 198.51.100.7"));
        // Once collected, a finished session is gone.
        let again = assist(
            &state,
            serde_json::json!({ "action": "poll", "handle": started["handle"] }),
        )
        .await;
        assert_eq!(again.error.unwrap().code, "ai-assist-not-found");
    }

    #[tokio::test]
    async fn ai_assist_cancel_stops_a_stream_and_keeps_nothing_in_history() {
        let (endpoint, _, _) = mock_ai_server(
            "data: {\"choices\":[{\"delta\":{\"content\":\"开头\"}}]}\n\n",
            true,
        )
        .await;
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let mut input = handle_frame(&state, &request("settings.get", "{}"))
            .await
            .result
            .unwrap();
        input["ai"]["providers"] = serde_json::json!([{ "id": "slow", "label": "慢", "kind": "open-ai-compatible",
            "endpoint": format!("{endpoint}/v1/chat/completions"), "model": "m", "enabled": true }]);
        assert!(
            handle_frame(&state, &request("settings.save", &input.to_string()))
                .await
                .ok
        );
        let started = assist(
            &state,
            serde_json::json!({
                "action": "start", "providerId": "slow", "task": "explain-log", "content": "line",
            }),
        )
        .await
        .result
        .unwrap();
        let handle = started["handle"].as_str().unwrap().to_owned();
        let mut seen = String::new();
        for _ in 0..200 {
            let progress = assist(
                &state,
                serde_json::json!({ "action": "poll", "handle": handle }),
            )
            .await
            .result
            .unwrap();
            seen.push_str(progress["text"].as_str().unwrap());
            if !seen.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert_eq!(seen, "开头");
        let cancelled = assist(
            &state,
            serde_json::json!({ "action": "cancel", "handle": handle }),
        )
        .await
        .result
        .unwrap();
        assert_eq!(cancelled["cancelled"], true);
        let (_, finished) = assist_until_finished(&state, &handle).await;
        assert_eq!(finished["state"], "cancelled");
        assert!(finished["historyId"].is_null());
        let history = handle_frame(
            &state,
            &request("ai-history.list", r#"{"query":"","offset":0,"limit":10}"#),
        )
        .await
        .result
        .unwrap();
        assert_eq!(history["items"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn log_rules_rpc_saves_matches_and_removes_only_through_a_confirmed_plan() {
        async fn rules(state: &BackendState, params: serde_json::Value) -> RpcResponse {
            handle_frame(state, &request("log.rules", &params.to_string())).await
        }
        fn code(response: RpcResponse) -> String {
            assert!(!response.ok);
            response.error.unwrap().code.to_owned()
        }
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();

        let empty = rules(&state, serde_json::json!({ "action": "list" }))
            .await
            .result
            .unwrap();
        assert_eq!(empty, serde_json::json!({ "rules": [], "maximum": 128 }));
        let added = rules(&state, serde_json::json!({
            "action": "add", "name": "webshell", "pattern": r"eval\(|base64_decode", "severity": "high",
        }))
        .await
        .result
        .unwrap();
        let id = added["id"].as_str().unwrap().to_owned();
        assert!(id.starts_with("log-rule-"));
        assert_eq!(added["severity"], "high");

        // Each refusal has its own code, so the page can say what to change.
        for (params, expected) in [
            (
                serde_json::json!({ "action": "add", "name": "WebShell", "pattern": "x", "severity": "low" }),
                "log-rule-name-taken",
            ),
            (
                serde_json::json!({ "action": "add", "name": "broken", "pattern": "(", "severity": "low" }),
                "log-rule-pattern-invalid",
            ),
            (
                serde_json::json!({ "action": "add", "name": "  ", "pattern": "x", "severity": "low" }),
                "log-rule-name-invalid",
            ),
            (
                serde_json::json!({ "action": "add", "name": "x", "pattern": "x", "severity": "extreme" }),
                "invalid-params",
            ),
            (
                serde_json::json!({ "action": "add", "name": "x", "pattern": "x", "severity": "low", "path": "/etc" }),
                "invalid-params",
            ),
            (serde_json::json!({ "action": "export" }), "invalid-params"),
            (
                serde_json::json!({ "action": "list", "path": "/etc" }),
                "invalid-params",
            ),
            (
                serde_json::json!({ "action": "match", "lines": vec!["x"; 501] }),
                "invalid-params",
            ),
            (
                serde_json::json!({ "action": "plan-remove", "id": "not-a-rule" }),
                "log-rule-not-found",
            ),
        ] {
            assert_eq!(
                code(rules(&state, params.clone()).await),
                expected,
                "{params}"
            );
        }

        // Matching is core's, case-insensitive, first rule wins, one answer per line.
        let matched = rules(&state, serde_json::json!({
            "action": "match",
            "lines": ["GET /up.php?c=eval(base64_decode('aGk='))", "an ordinary line", "EVAL(1)"],
        }))
        .await
        .result
        .unwrap();
        assert_eq!(matched["ruleCount"], 1);
        assert_eq!(matched["matches"][0]["name"], "webshell");
        assert_eq!(matched["matches"][0]["id"], id.as_str());
        assert!(matched["matches"][1].is_null());
        assert_eq!(matched["matches"][2]["severity"], "high");

        // Removing: a cancelled plan cannot be confirmed afterwards.
        let plan = rules(
            &state,
            serde_json::json!({ "action": "plan-remove", "id": id }),
        )
        .await
        .result
        .unwrap();
        assert!(plan["summary"].as_str().unwrap().contains("webshell"));
        assert!(plan["summary"].as_str().unwrap().contains("不可恢复"));
        let handle = plan["handle"].as_str().unwrap().to_owned();
        let cancelled = rules(
            &state,
            serde_json::json!({ "action": "cancel-remove", "handle": handle }),
        )
        .await;
        assert_eq!(cancelled.result.unwrap()["cancelled"], true);
        assert_eq!(
            code(
                rules(
                    &state,
                    serde_json::json!({ "action": "confirm-remove", "handle": handle })
                )
                .await
            ),
            "log-rule-plan-invalid"
        );
        assert_eq!(
            rules(&state, serde_json::json!({ "action": "list" }))
                .await
                .result
                .unwrap()["rules"]
                .as_array()
                .unwrap()
                .len(),
            1
        );

        let plan = rules(
            &state,
            serde_json::json!({ "action": "plan-remove", "id": id }),
        )
        .await
        .result
        .unwrap();
        let removed = rules(
            &state,
            serde_json::json!({ "action": "confirm-remove", "handle": plan["handle"] }),
        )
        .await
        .result
        .unwrap();
        assert_eq!(
            removed,
            serde_json::json!({ "ruleId": id, "verified": true })
        );
        assert_eq!(
            rules(&state, serde_json::json!({ "action": "list" }))
                .await
                .result
                .unwrap()["rules"],
            serde_json::json!([])
        );
        assert_eq!(
            code(
                rules(
                    &state,
                    serde_json::json!({ "action": "plan-remove", "id": id })
                )
                .await
            ),
            "log-rule-not-found"
        );
    }

    #[tokio::test]
    async fn postgresql_runtime_expected_refusals_are_finite_results_without_echoed_inputs() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        for params in [
            serde_json::json!({"action":"list","bindingHandle":"private-marker"}),
            serde_json::json!({"action":"begin","bindingHandle":"private-marker","profileHandle":"private-marker","retainEvidence":false}),
            serde_json::json!({"action":"delete","bindingHandle":"private-marker","planHandle":"private-marker"}),
            serde_json::json!({"action":"poll","bindingHandle":"private-marker","jobHandle":"private-marker"}),
            serde_json::json!({"action":"cancel","bindingHandle":"private-marker","jobHandle":"private-marker"}),
            serde_json::json!({"action":"retain","bindingHandle":"private-marker","jobHandle":"private-marker"}),
            serde_json::json!({"action":"discard-evidence","bindingHandle":"private-marker","jobHandle":"private-marker"}),
        ] {
            let response =
                handle_frame(&state, &request("postgresql.runtime", &params.to_string())).await;
            assert!(response.ok);
            let result = response.result.unwrap();
            assert_eq!(result["kind"], "rejected");
            assert_eq!(result["code"], "stale");
            assert_eq!(result["action"], params["action"]);
            assert!(!result.to_string().contains("private-marker"));
        }
        let response = handle_frame(
            &state,
            &request(
                "postgresql.runtime",
                r#"{"action":"list","bindingHandle":"b","sql":"private-marker"}"#,
            ),
        )
        .await;
        assert!(!response.ok);
        assert_eq!(response.error.as_ref().unwrap().code, "invalid-params");
        assert!(
            !serde_json::to_string(&response)
                .unwrap()
                .contains("private-marker")
        );
    }

    #[tokio::test]
    async fn nginx_repair_rpc_rejects_injected_and_unbound_intents_without_echoing_input() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        for (params, code) in [
            (
                serde_json::json!({"action":"discover","bindingHandle":"never-connected"}),
                "nginx-repair-stale",
            ),
            (
                serde_json::json!({"action":"execute","bindingHandle":"never-connected","planHandle":"p"}),
                "nginx-repair-stale",
            ),
            (
                serde_json::json!({"action":"restore","bindingHandle":"never-connected","recordHandle":"r"}),
                "nginx-repair-stale",
            ),
            (
                serde_json::json!({"action":"discover","bindingHandle":""}),
                "invalid-params",
            ),
            (
                serde_json::json!({"action":"plan","bindingHandle":"b","configurationHandle":"g","candidateHandle":"c","replacement":"private-marker"}),
                "invalid-params",
            ),
            (
                serde_json::json!({"action":"execute","bindingHandle":"b","planHandle":"p","confirmed":true}),
                "invalid-params",
            ),
            (
                serde_json::json!({"action":"shell","bindingHandle":"b","command":"private-marker"}),
                "invalid-params",
            ),
        ] {
            let response =
                handle_frame(&state, &request("nginx.repair", &params.to_string())).await;
            assert!(!response.ok);
            assert_eq!(response.error.as_ref().unwrap().code, code);
            let encoded = serde_json::to_string(&response).unwrap();
            assert!(!encoded.contains("private-marker"));
            assert!(!encoded.contains("never-connected"));
        }
    }

    #[tokio::test]
    async fn case_workspace_rejects_unbound_and_injected_archive_intents() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        for (params, code) in [
            (
                serde_json::json!({"action":"list","bindingHandle":"never-connected"}),
                "case-workspace-stale",
            ),
            (
                serde_json::json!({"action":"create","bindingHandle":"never-connected","title":"private-marker","mutationId":"create-case-0001"}),
                "case-workspace-stale",
            ),
            (
                serde_json::json!({"action":"note","bindingHandle":"never-connected","caseId":"case","title":"private-marker","content":"synthetic"}),
                "case-workspace-stale",
            ),
            (
                serde_json::json!({"action":"list","bindingHandle":"b","target":"private-marker"}),
                "invalid-params",
            ),
            (
                serde_json::json!({"action":"note","bindingHandle":"b","caseId":"case","title":"note","content":"private-marker","externalSha256":"00".repeat(32)}),
                "invalid-params",
            ),
            (
                serde_json::json!({"action":"attach-note","bindingHandle":"b","caseId":"case","noteId":"private-marker","revision":"bad"}),
                "invalid-params",
            ),
            (
                serde_json::json!({"action":"items","bindingHandle":"b","snapshotHandle":"s","section":"evidence","offset":1001,"query":"private-marker"}),
                "invalid-params",
            ),
            (
                serde_json::json!({"action":"report","bindingHandle":"b","snapshotHandle":"s","incident":{"title":"private-marker"}}),
                "invalid-params",
            ),
            (
                serde_json::json!({"action":"delete","bindingHandle":"b","caseId":"private-marker"}),
                "invalid-params",
            ),
        ] {
            let response =
                handle_frame(&state, &request("case.workspace", &params.to_string())).await;
            assert!(!response.ok);
            assert_eq!(response.error.as_ref().unwrap().code, code);
            let encoded = serde_json::to_string(&response).unwrap();
            assert!(!encoded.contains("private-marker"));
            assert!(!encoded.contains("never-connected"));
        }
        let target = lovelyhawk_core::target::TargetIdentity::new("never-connected").unwrap();
        assert_eq!(
            state
                .services
                .investigation()
                .cases()
                .overview(&target)
                .unwrap()
                .total_cases,
            0
        );
    }

    #[tokio::test]
    async fn packet_capture_evidence_rejects_paths_names_commands_and_unbound_jobs() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let binding = "00000000-0000-4000-8000-000000000001";
        let interface = "00000000-0000-4000-8000-000000000002";
        let input = serde_json::json!({"durationSeconds": 10, "packetLimit": 6});
        for (params, code) in [
            (
                serde_json::json!({"action":"begin","bindingHandle":binding,"interfaceHandle":interface,"input":input,"selectedDirectory":root.0.join("private-marker")}),
                "packet-capture-evidence-stale",
            ),
            (
                serde_json::json!({"action":"poll","bindingHandle":binding,"jobHandle":"unknown"}),
                "packet-capture-evidence-stale",
            ),
            (
                serde_json::json!({"action":"cancel","bindingHandle":binding,"jobHandle":"unknown"}),
                "packet-capture-evidence-stale",
            ),
            (
                serde_json::json!({"action":"begin","bindingHandle":binding,"interfaceHandle":interface,"input":input,"selectedDirectory":"relative"}),
                "invalid-params",
            ),
            // The interface is named only by its handle, never by a name the
            // page typed; the file on the target is never the page's to name.
            (
                serde_json::json!({"action":"begin","bindingHandle":binding,"interface":"eth0; private-marker","input":input,"selectedDirectory":root.0}),
                "invalid-params",
            ),
            (
                serde_json::json!({"action":"begin","bindingHandle":binding,"interfaceHandle":interface,"input":input,"selectedDirectory":root.0,"remotePath":"/tmp/private-marker.pcap"}),
                "invalid-params",
            ),
            (
                serde_json::json!({"action":"begin","bindingHandle":binding,"interfaceHandle":interface,"input":{"durationSeconds":10,"command":"private-marker"},"selectedDirectory":root.0}),
                "invalid-params",
            ),
            (
                serde_json::json!({"action":"poll","bindingHandle":binding,"jobHandle":"j","path":"private-marker"}),
                "invalid-params",
            ),
            (
                serde_json::json!({"action":"export","bindingHandle":binding,"jobHandle":"j"}),
                "invalid-params",
            ),
        ] {
            let response = handle_frame(
                &state,
                &request("packet-capture.evidence", &params.to_string()),
            )
            .await;
            assert!(!response.ok, "{params}");
            assert_eq!(response.error.as_ref().unwrap().code, code, "{params}");
            assert!(
                !serde_json::to_string(&response)
                    .unwrap()
                    .contains("private-marker")
            );
        }
        assert!(!root.0.join("private-marker").exists());
        assert!(
            !std::fs::read_dir(&root.0)
                .unwrap()
                .filter_map(Result::ok)
                .any(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("LovelyHawk-evidence-"))
        );
    }

    #[tokio::test]
    async fn pod_file_evidence_names_the_pod_only_by_handles_and_never_a_host_path() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let binding = "00000000-0000-4000-8000-000000000001";
        let snapshot = "00000000-0000-4000-8000-000000000002";
        let row = "00000000-0000-4000-8000-000000000003";
        let begin = |extra: serde_json::Value| {
            let mut params = serde_json::json!({
                "action": "begin", "bindingHandle": binding, "snapshotHandle": snapshot,
                "rowHandle": row, "container": null, "path": "/etc/hostname",
                "selectedDirectory": root.0,
            });
            for (key, value) in extra.as_object().unwrap() {
                params[key] = value.clone();
            }
            params
        };
        for (params, code) in [
            // Handles that name nothing: no pod, no folder, nothing run.
            (
                begin(serde_json::json!({"selectedDirectory": root.0.join("private-marker")})),
                "kubernetes-pod-evidence-stale",
            ),
            (
                serde_json::json!({"action":"poll","bindingHandle":binding,"jobHandle":"unknown"}),
                "kubernetes-pod-evidence-stale",
            ),
            (
                serde_json::json!({"action":"cancel","bindingHandle":binding,"jobHandle":"unknown"}),
                "kubernetes-pod-evidence-stale",
            ),
            (
                begin(serde_json::json!({"selectedDirectory": "relative"})),
                "invalid-params",
            ),
            (
                begin(serde_json::json!({"path": "/etc/../private-marker"})),
                "invalid-params",
            ),
            (
                begin(serde_json::json!({"path": "private-marker"})),
                "invalid-params",
            ),
            // The pod is the list's, and the copy on the host is never the page's to name.
            (
                begin(serde_json::json!({"namespace": "private-marker"})),
                "invalid-params",
            ),
            (
                begin(serde_json::json!({"hostPath": "/tmp/private-marker.bin"})),
                "invalid-params",
            ),
            (
                serde_json::json!({"action":"export","bindingHandle":binding,"jobHandle":"j"}),
                "invalid-params",
            ),
        ] {
            let response = handle_frame(
                &state,
                &request("kubernetes.pod.file-evidence", &params.to_string()),
            )
            .await;
            assert!(!response.ok, "{params}");
            assert_eq!(response.error.as_ref().unwrap().code, code, "{params}");
            assert!(
                !serde_json::to_string(&response)
                    .unwrap()
                    .contains("private-marker")
            );
        }
        assert!(!root.0.join("private-marker").exists());
        assert!(
            !std::fs::read_dir(&root.0)
                .unwrap()
                .filter_map(Result::ok)
                .any(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("LovelyHawk-evidence-"))
        );
    }

    /// A manifest export names the object only by its list handles; a kind,
    /// a namespace or a name in the request is refused, and nothing the
    /// request carried comes back in the answer.
    #[tokio::test]
    async fn a_manifest_export_names_the_object_only_by_handles() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let base = serde_json::json!({
            "bindingHandle": "00000000-0000-4000-8000-000000000001",
            "snapshotHandle": "00000000-0000-4000-8000-000000000002",
            "rowHandle": "00000000-0000-4000-8000-000000000003",
        });
        let with = |key: &str, value: serde_json::Value| {
            let mut params = base.clone();
            params[key] = value;
            params
        };
        for (params, code) in [
            // No such connection: nothing is read.
            (base.clone(), "kubernetes-binding-unavailable"),
            (with("kind", serde_json::json!("secret")), "invalid-params"),
            (
                with("namespace", serde_json::json!("private-marker")),
                "invalid-params",
            ),
            (
                with("name", serde_json::json!("private-marker")),
                "invalid-params",
            ),
            (with("rowHandle", serde_json::json!("")), "invalid-params"),
        ] {
            let response = handle_frame(
                &state,
                &request("kubernetes.manifest.export", &params.to_string()),
            )
            .await;
            assert!(!response.ok, "{params}");
            assert_eq!(response.error.as_ref().unwrap().code, code, "{params}");
            assert!(
                !serde_json::to_string(&response)
                    .unwrap()
                    .contains("private-marker")
            );
        }
    }

    #[tokio::test]
    async fn file_evidence_rejects_injected_commands_paths_and_unbound_jobs() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        for (params, code) in [
            (
                serde_json::json!({"action":"begin","bindingHandle":"b","pathHandle":"p","selectedDirectory":root.0.join("private-marker")}),
                "file-evidence-stale",
            ),
            (
                serde_json::json!({"action":"poll","bindingHandle":"b","jobHandle":"unknown"}),
                "file-evidence-stale",
            ),
            (
                serde_json::json!({"action":"cancel","bindingHandle":"b","jobHandle":"unknown"}),
                "file-evidence-stale",
            ),
            (
                serde_json::json!({"action":"begin","bindingHandle":"b","pathHandle":"p","selectedDirectory":"relative"}),
                "invalid-params",
            ),
            (
                serde_json::json!({"action":"begin","bindingHandle":"b","pathHandle":"p","selectedDirectory":root.0,"path":"private-marker"}),
                "invalid-params",
            ),
            (
                serde_json::json!({"action":"poll","bindingHandle":"b","jobHandle":"j","command":"private-marker"}),
                "invalid-params",
            ),
        ] {
            let response = handle_frame(
                &state,
                &request("emergency.file-evidence", &params.to_string()),
            )
            .await;
            assert!(!response.ok);
            assert_eq!(response.error.as_ref().unwrap().code, code);
            assert!(
                !serde_json::to_string(&response)
                    .unwrap()
                    .contains("private-marker")
            );
        }
        assert!(!root.0.join("private-marker").exists());
    }

    #[tokio::test]
    async fn bootstrap_exposes_the_complete_page_registry_and_no_data_path() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let response = handle_frame(&state, &request("app.bootstrap", "{}")).await;
        assert!(response.ok);
        let result = response.result.unwrap();
        assert_eq!(result["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(result["pages"].as_array().unwrap().len(), 14);
        assert!(result.get("dataRoot").is_none());
        assert_eq!(
            result["pages"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|page| page["migrationState"] == "ready")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn settings_rpc_round_trips_only_the_credential_free_portable_view() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let loaded = handle_frame(&state, &request("settings.get", "{}"))
            .await
            .result
            .unwrap();
        assert_eq!(loaded["theme"], "light");
        assert!(loaded.get("dataRoot").is_none());
        assert!(loaded.get("path").is_none());

        let mut input = loaded;
        input["theme"] = serde_json::json!("dark");
        input["ui"]["sidebarWidth"] = serde_json::json!(344);
        input["ai"]["providers"] = serde_json::json!([{
            "id": "debug-provider",
            "label": "</option><script>plain-text</script>",
            "kind": "open-ai-compatible",
            "endpoint": "http://127.0.0.1:11434/v1",
            "model": "local-model",
            "enabled": true
        }]);
        input["ai"]["defaultProviderId"] = serde_json::json!("debug-provider");
        let saved = handle_frame(
            &state,
            &request("settings.save", &serde_json::to_string(&input).unwrap()),
        )
        .await;
        assert!(saved.ok);
        let saved = saved.result.unwrap();
        assert_eq!(saved["theme"], "dark");
        assert_eq!(saved["ui"]["sidebarWidth"], 344);
        assert_eq!(saved["ai"]["providers"][0]["hasApiKey"], false);
        assert_eq!(
            saved["ai"]["providers"][0]["label"],
            "</option><script>plain-text</script>"
        );
        assert!(root.0.join("data").join("settings.json").is_file());
    }

    #[tokio::test]
    async fn settings_rpc_rejects_extra_paths_and_secret_fields_without_echo() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let loaded = handle_frame(&state, &request("settings.get", "{}"))
            .await
            .result
            .unwrap();

        let extra_get = handle_frame(
            &state,
            &request("settings.get", r#"{"dataRoot":"hostile-root-marker"}"#),
        )
        .await;
        assert_eq!(extra_get.error.unwrap().code, "invalid-params");

        let mut with_path = loaded.clone();
        with_path["dataRoot"] = serde_json::json!("hostile-root-marker");
        let rejected = handle_frame(
            &state,
            &request("settings.save", &serde_json::to_string(&with_path).unwrap()),
        )
        .await;
        let encoded = serde_json::to_string(&rejected).unwrap();
        assert_eq!(rejected.error.unwrap().code, "invalid-params");
        assert!(!encoded.contains("hostile-root-marker"));

        let mut with_secret = loaded;
        with_secret["ai"]["providers"] = serde_json::json!([{
            "id": "secret-provider",
            "label": "Provider",
            "kind": "open-ai-compatible",
            "endpoint": "https://example.test/v1",
            "model": "model",
            "enabled": true,
            "apiKey": "secret-marker-must-not-cross"
        }]);
        let rejected = handle_frame(
            &state,
            &request(
                "settings.save",
                &serde_json::to_string(&with_secret).unwrap(),
            ),
        )
        .await;
        let encoded = serde_json::to_string(&rejected).unwrap();
        assert_eq!(rejected.error.unwrap().code, "invalid-params");
        assert!(!encoded.contains("secret-marker-must-not-cross"));
    }

    #[tokio::test]
    async fn settings_secret_lifecycle_rpc_is_write_only_planned_single_use_and_verified() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let mut input = handle_frame(&state, &request("settings.get", "{}"))
            .await
            .result
            .unwrap();
        input["ai"]["providers"] = serde_json::json!([{
            "id": "debug-provider",
            "label": "Debug provider",
            "kind": "open-ai-compatible",
            "endpoint": "http://127.0.0.1:11434/v1",
            "model": "local-model",
            "enabled": true
        }]);
        input["ai"]["defaultProviderId"] = serde_json::json!("debug-provider");
        assert!(
            handle_frame(
                &state,
                &request("settings.save", &serde_json::to_string(&input).unwrap()),
            )
            .await
            .ok
        );

        let secret = "settings-rpc-secret-marker-must-not-return";
        let replaced = handle_frame(
            &state,
            &request(
                "settings.ai-api-key.replace",
                &serde_json::json!({ "providerId": "debug-provider", "apiKey": secret })
                    .to_string(),
            ),
        )
        .await;
        assert!(replaced.ok);
        assert_eq!(
            replaced.result.as_ref().unwrap()["providerId"],
            "debug-provider"
        );
        assert_eq!(replaced.result.as_ref().unwrap()["hasApiKey"], true);
        assert!(!serde_json::to_string(&replaced).unwrap().contains(secret));

        let clear_cancelled = handle_frame(
            &state,
            &request(
                "settings.ai-api-key.clear.plan",
                r#"{"providerId":"debug-provider"}"#,
            ),
        )
        .await
        .result
        .unwrap();
        assert_eq!(clear_cancelled["kind"], "clear-ai-api-key");
        let clear_cancel_handle = clear_cancelled["handle"].as_str().unwrap();
        assert!(!clear_cancel_handle.contains("debug-provider"));
        let cancelled = handle_frame(
            &state,
            &request(
                "settings.mutation.cancel",
                &serde_json::json!({ "mutationHandle": clear_cancel_handle }).to_string(),
            ),
        )
        .await;
        assert_eq!(cancelled.result.unwrap()["cancelled"], true);
        let consumed = handle_frame(
            &state,
            &request(
                "settings.mutation.confirm",
                &serde_json::json!({ "mutationHandle": clear_cancel_handle }).to_string(),
            ),
        )
        .await;
        assert_eq!(consumed.error.unwrap().code, "settings-plan-invalid");
        let unchanged = handle_frame(&state, &request("settings.get", "{}"))
            .await
            .result
            .unwrap();
        assert_eq!(unchanged["ai"]["providers"][0]["hasApiKey"], true);

        let clear = handle_frame(
            &state,
            &request(
                "settings.ai-api-key.clear.plan",
                r#"{"providerId":"debug-provider"}"#,
            ),
        )
        .await
        .result
        .unwrap();
        let cleared = handle_frame(
            &state,
            &request(
                "settings.mutation.confirm",
                &serde_json::json!({ "mutationHandle": clear["handle"] }).to_string(),
            ),
        )
        .await;
        assert_eq!(cleared.result.unwrap()["kind"], "clear-ai-api-key");
        let cleared_snapshot = handle_frame(&state, &request("settings.get", "{}"))
            .await
            .result
            .unwrap();
        assert_eq!(cleared_snapshot["ai"]["providers"][0]["hasApiKey"], false);

        assert!(
            handle_frame(
                &state,
                &request(
                    "settings.ai-api-key.replace",
                    r#"{"providerId":"debug-provider","apiKey":"replacement"}"#,
                ),
            )
            .await
            .ok
        );
        let remove_cancelled = handle_frame(
            &state,
            &request(
                "settings.ai-provider.remove.plan",
                r#"{"providerId":"debug-provider"}"#,
            ),
        )
        .await
        .result
        .unwrap();
        let remove_cancel_handle = remove_cancelled["handle"].as_str().unwrap();
        assert!(
            handle_frame(
                &state,
                &request(
                    "settings.mutation.cancel",
                    &serde_json::json!({ "mutationHandle": remove_cancel_handle }).to_string(),
                ),
            )
            .await
            .ok
        );
        assert_eq!(
            handle_frame(&state, &request("settings.get", "{}"))
                .await
                .result
                .unwrap()["ai"]["providers"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let remove = handle_frame(
            &state,
            &request(
                "settings.ai-provider.remove.plan",
                r#"{"providerId":"debug-provider"}"#,
            ),
        )
        .await
        .result
        .unwrap();
        let removed = handle_frame(
            &state,
            &request(
                "settings.mutation.confirm",
                &serde_json::json!({ "mutationHandle": remove["handle"] }).to_string(),
            ),
        )
        .await;
        assert_eq!(removed.result.unwrap()["kind"], "remove-ai-provider");
        assert!(
            handle_frame(&state, &request("settings.get", "{}"))
                .await
                .result
                .unwrap()["ai"]["providers"]
                .as_array()
                .unwrap()
                .is_empty()
        );

        let forged = handle_frame(
            &state,
            &request(
                "settings.ai-api-key.replace",
                &serde_json::json!({
                    "providerId": "debug-provider",
                    "apiKey": secret,
                    "path": "C:/private"
                })
                .to_string(),
            ),
        )
        .await;
        assert_eq!(forged.error.as_ref().unwrap().code, "invalid-params");
        assert!(!serde_json::to_string(&forged).unwrap().contains(secret));
    }

    #[tokio::test]
    async fn ai_history_rpc_routes_fixed_bounded_operations_and_internal_export() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let empty = handle_frame(
            &state,
            &request("ai-history.list", r#"{"query":"","offset":0,"limit":100}"#),
        )
        .await;
        assert!(empty.ok);
        assert_eq!(empty.result.as_ref().unwrap()["total"], 0);

        let hostile = "</script><img src=x onerror=plain-text()>";
        let record = state
            .services
            .investigation()
            .ai_history()
            .add(AddAiHistory {
                provider: hostile.to_owned(),
                model: "local-model".to_owned(),
                prompt: hostile.to_owned(),
                result: hostile.to_owned(),
                source: "test".to_owned(),
            })
            .unwrap();
        let list = handle_frame(
            &state,
            &request(
                "ai-history.list",
                r#"{"query":"plain-text","offset":0,"limit":100}"#,
            ),
        )
        .await;
        assert!(list.ok);
        assert_eq!(list.result.as_ref().unwrap()["total"], 1);
        assert_eq!(
            list.result.as_ref().unwrap()["items"][0]["provider"],
            hostile
        );

        let id_params = serde_json::json!({ "id": record.id }).to_string();
        let detail = handle_frame(&state, &request("ai-history.get", &id_params)).await;
        assert!(detail.ok);
        assert_eq!(detail.result.as_ref().unwrap()["prompt"], hostile);
        assert!(detail.result.as_ref().unwrap().get("path").is_none());

        let plan = handle_frame(&state, &request("ai-history.remove.plan", &id_params)).await;
        assert!(plan.ok);
        let proposal = plan.result.unwrap();
        assert_eq!(proposal["kind"], "remove");
        assert_eq!(proposal["affectedRecords"], 1);
        assert_eq!(proposal["summary"], "这条 AI 历史会被永久删除，无法恢复。");
        let handle_params = serde_json::json!({ "handle": proposal["handle"] }).to_string();
        let cancelled = handle_frame(
            &state,
            &request("ai-history.mutation.cancel", &handle_params),
        )
        .await;
        assert_eq!(cancelled.result.unwrap()["cancelled"], true);
        let consumed = handle_frame(
            &state,
            &request("ai-history.mutation.confirm", &handle_params),
        )
        .await;
        assert!(!consumed.ok);
        assert_eq!(consumed.error.unwrap().code, "ai-history-plan-invalid");

        let export = handle_frame(
            &state,
            &request("ai-history.export", r#"{"format":"json"}"#),
        )
        .await;
        assert!(export.ok);
        let payload = export.result.unwrap();
        assert_eq!(payload["recordCount"], 1);
        assert_eq!(payload["mediaType"], "application/json");
        assert!(
            payload["suggestedName"]
                .as_str()
                .unwrap()
                .ends_with(".json")
        );
        assert!(payload["contents"].as_str().unwrap().contains(hostile));

        let clear = handle_frame(&state, &request("ai-history.clear.plan", "{}")).await;
        assert!(clear.ok);
        let clear_proposal = clear.result.unwrap();
        assert_eq!(clear_proposal["kind"], "clear");
        assert_eq!(
            clear_proposal["summary"],
            "这 1 条 AI 历史会被永久删除，无法恢复；确认之后新产生的记录会保留。"
        );
        let clear_handle = serde_json::json!({ "handle": clear_proposal["handle"] }).to_string();
        let cleared = handle_frame(
            &state,
            &request("ai-history.mutation.confirm", &clear_handle),
        )
        .await;
        assert!(cleared.ok);
        assert_eq!(cleared.result.unwrap()["verified"], true);
    }

    #[tokio::test]
    async fn ai_history_rpc_rejects_unknown_fields_without_echoing_them() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let marker = "renderer-forged-ai-record-marker";
        let response = handle_frame(
            &state,
            &request(
                "ai-history.list",
                &serde_json::json!({
                    "query": "",
                    "offset": 0,
                    "limit": 100,
                    "record": { "prompt": marker }
                })
                .to_string(),
            ),
        )
        .await;
        assert!(!response.ok);
        assert_eq!(response.error.as_ref().unwrap().code, "invalid-params");
        assert!(!serde_json::to_string(&response).unwrap().contains(marker));
    }

    #[tokio::test]
    async fn command_history_rpc_routes_are_fixed_scoped_and_reject_unknown_fields() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let binding = "missing-binding-marker";
        let cases = [
            (
                "command-history.list",
                serde_json::json!({ "bindingHandle": binding, "query": "", "offset": 0, "limit": 25 }),
            ),
            (
                "command-history.get",
                serde_json::json!({ "bindingHandle": binding, "recordId": "record-1" }),
            ),
            (
                "command-history.replay.plan",
                serde_json::json!({ "bindingHandle": binding, "recordId": "record-1" }),
            ),
            (
                "command-history.remove.plan",
                serde_json::json!({ "bindingHandle": binding, "recordId": "record-1" }),
            ),
            (
                "command-history.clear.plan",
                serde_json::json!({ "bindingHandle": binding }),
            ),
            (
                "command-history.mutation.confirm",
                serde_json::json!({ "bindingHandle": binding, "mutationHandle": "mutation-1" }),
            ),
            (
                "command-history.mutation.cancel",
                serde_json::json!({ "bindingHandle": binding, "mutationHandle": "mutation-1" }),
            ),
        ];
        for (method, params) in cases {
            let response = handle_frame(&state, &request(method, &params.to_string())).await;
            assert!(
                !response.ok,
                "{method} unexpectedly accepted a missing binding"
            );
            assert!(!serde_json::to_string(&response).unwrap().contains(binding));
        }

        let marker = "forged-command-must-not-echo";
        let forged = handle_frame(
            &state,
            &request(
                "command-history.list",
                &serde_json::json!({
                    "bindingHandle": binding,
                    "query": "",
                    "offset": 0,
                    "limit": 25,
                    "command": marker
                })
                .to_string(),
            ),
        )
        .await;
        assert!(!forged.ok);
        assert_eq!(forged.error.as_ref().unwrap().code, "invalid-params");
        assert!(!serde_json::to_string(&forged).unwrap().contains(marker));
    }

    #[tokio::test]
    async fn baseline_read_rpc_routes_are_exact_scoped_and_never_echo_renderer_ingredients() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();

        let catalog = handle_frame(&state, &request("baseline.catalog.get", "{}")).await;
        assert!(catalog.ok);
        let catalog_text = serde_json::to_string(&catalog).unwrap();
        assert!(catalog_text.contains("itemHandle"));
        assert!(!catalog_text.contains("/etc/"));

        let binding = "11111111-1111-4111-8111-111111111111";
        for method in ["baseline.scan", "baseline.history.list"] {
            let response = handle_frame(
                &state,
                &request(
                    method,
                    &serde_json::json!({ "bindingHandle": binding }).to_string(),
                ),
            )
            .await;
            assert!(!response.ok, "{method} accepted a missing binding");
            let failure = response.error.as_ref().unwrap();
            assert_eq!(failure.code, "baseline-binding-unavailable", "{method}");
            assert_eq!(
                failure.message, "The baseline target binding is missing or stale.",
                "{method}"
            );
            assert!(!serde_json::to_string(&response).unwrap().contains(binding));
        }

        let marker = "renderer-forged-baseline-command-path-target-secret";
        for (method, params) in [
            (
                "baseline.catalog.get",
                serde_json::json!({ "command": marker }),
            ),
            (
                "baseline.scan",
                serde_json::json!({ "bindingHandle": binding, "targetIdentity": marker }),
            ),
            (
                "baseline.history.list",
                serde_json::json!({ "bindingHandle": binding, "path": marker }),
            ),
        ] {
            let response = handle_frame(&state, &request(method, &params.to_string())).await;
            assert!(!response.ok);
            assert_eq!(response.error.as_ref().unwrap().code, "invalid-params");
            assert!(!serde_json::to_string(&response).unwrap().contains(marker));
        }

        let invalid_binding = "../HOSTILE_BASELINE_BINDING_MUST_NOT_ECHO";
        let response = handle_frame(
            &state,
            &request(
                "baseline.scan",
                &serde_json::json!({ "bindingHandle": invalid_binding }).to_string(),
            ),
        )
        .await;
        assert!(!response.ok);
        assert_eq!(response.error.as_ref().unwrap().code, "invalid-params");
        assert!(
            !serde_json::to_string(&response)
                .unwrap()
                .contains(invalid_binding)
        );
    }

    #[tokio::test]
    async fn check_audit_read_rpc_routes_are_exact_scoped_and_never_echo_renderer_ingredients() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let binding = "11111111-1111-4111-8111-111111111111";
        let snapshot = "22222222-2222-4222-8222-222222222222";

        for (method, params) in [
            (
                "check-audit.catalog.get",
                serde_json::json!({
                    "bindingHandle": binding,
                    "input": { "customCommandNames": [] },
                }),
            ),
            (
                "check-audit.status.collect",
                serde_json::json!({
                    "bindingHandle": binding,
                    "snapshotHandle": snapshot,
                }),
            ),
            (
                "check-audit.log.read",
                serde_json::json!({
                    "bindingHandle": binding,
                    "snapshotHandle": snapshot,
                    "input": { "limit": 100, "search": null },
                }),
            ),
        ] {
            let response = handle_frame(&state, &request(method, &params.to_string())).await;
            assert!(!response.ok, "{method} accepted a missing binding");
            let failure = response.error.as_ref().unwrap();
            assert_eq!(failure.code, "check-audit-binding-unavailable", "{method}");
            assert_eq!(
                failure.message, "The command-audit target binding is missing or stale.",
                "{method}"
            );
            assert!(!serde_json::to_string(&response).unwrap().contains(binding));
        }

        let marker = "renderer-forged-check-audit-command-path-session-target";
        for (method, params) in [
            (
                "check-audit.catalog.get",
                serde_json::json!({
                    "bindingHandle": binding,
                    "input": { "customCommandNames": [] },
                    "command": marker,
                }),
            ),
            (
                "check-audit.catalog.get",
                serde_json::json!({
                    "bindingHandle": binding,
                    "input": { "customCommandNames": [] },
                    "path": marker,
                }),
            ),
            (
                "check-audit.status.collect",
                serde_json::json!({
                    "bindingHandle": binding,
                    "snapshotHandle": snapshot,
                    "session": marker,
                }),
            ),
            (
                "check-audit.log.read",
                serde_json::json!({
                    "bindingHandle": binding,
                    "snapshotHandle": snapshot,
                    "input": { "limit": 100, "search": null },
                    "target": marker,
                }),
            ),
        ] {
            let response = handle_frame(&state, &request(method, &params.to_string())).await;
            assert!(!response.ok, "{method} accepted a renderer-forged field");
            assert_eq!(response.error.as_ref().unwrap().code, "invalid-params");
            assert!(!serde_json::to_string(&response).unwrap().contains(marker));
        }
    }

    #[tokio::test]
    async fn baseline_actions_name_settings_and_history_only_by_handles() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let binding = "missing-baseline-action-binding";
        let handle = "baseline-item-00000000";
        for (method, params) in [
            (
                "baseline.action.plan",
                serde_json::json!({
                    "bindingHandle": binding,
                    "action": { "kind": "change", "changes": [{ "itemHandle": handle, "value": "no" }], "reload": "defer" },
                }),
            ),
            (
                "baseline.action.plan",
                serde_json::json!({
                    "bindingHandle": binding,
                    "action": { "kind": "restore", "historyHandle": handle, "historyItemHandle": handle },
                }),
            ),
            (
                "baseline.action.confirm",
                serde_json::json!({ "bindingHandle": binding, "planHandle": handle }),
            ),
            (
                "baseline.action.execute",
                serde_json::json!({ "bindingHandle": binding, "planHandle": handle }),
            ),
            (
                "baseline.action.cancel",
                serde_json::json!({ "bindingHandle": binding, "planHandle": handle }),
            ),
        ] {
            let response = handle_frame(&state, &request(method, &params.to_string())).await;
            assert!(!response.ok, "{method} accepted a missing binding");
            assert_eq!(
                response.error.as_ref().unwrap().code,
                "baseline-binding-unavailable",
                "{method}"
            );
            assert!(!serde_json::to_string(&response).unwrap().contains(binding));
        }

        // A file, a command, a reload of the page's own or a record id is no handle.
        let marker = "renderer-forged-baseline-action";
        for action in [
            serde_json::json!({ "kind": "change", "changes": [{ "itemHandle": handle, "value": "no", "file": marker }], "reload": "defer" }),
            serde_json::json!({ "kind": "change", "changes": [{ "itemHandle": handle, "value": "no" }], "reload": "restart" }),
            serde_json::json!({ "kind": "change", "changes": [{ "itemHandle": handle, "value": "no" }], "reload": "defer", "command": marker }),
            serde_json::json!({ "kind": "restore", "historyHandle": handle, "historyItemHandle": handle, "recordId": marker }),
            serde_json::json!({ "kind": "write", "path": marker }),
        ] {
            let params = serde_json::json!({ "bindingHandle": binding, "action": action });
            let response = handle_frame(
                &state,
                &request("baseline.action.plan", &params.to_string()),
            )
            .await;
            assert!(!response.ok, "{params}");
            assert_eq!(
                response.error.as_ref().unwrap().code,
                "invalid-params",
                "{params}"
            );
            assert!(!serde_json::to_string(&response).unwrap().contains(marker));
        }
    }

    #[tokio::test]
    async fn check_audit_actions_name_commands_only_by_catalog_handles() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let binding = "missing-check-audit-action-binding";
        let snapshot = "33333333-3333-4333-8333-333333333333";
        let command = "44444444-4444-4444-8444-444444444444";
        for (method, params) in [
            (
                "check-audit.action.plan",
                serde_json::json!({
                    "bindingHandle": binding, "snapshotHandle": snapshot,
                    "action": { "kind": "collect", "commandHandles": [command] },
                }),
            ),
            (
                "check-audit.action.plan",
                serde_json::json!({
                    "bindingHandle": binding, "snapshotHandle": snapshot,
                    "action": { "kind": "clear-log" },
                }),
            ),
            (
                "check-audit.action.confirm",
                serde_json::json!({ "bindingHandle": binding, "planHandle": command }),
            ),
            (
                "check-audit.action.execute",
                serde_json::json!({ "bindingHandle": binding, "planHandle": command }),
            ),
            (
                "check-audit.action.cancel",
                serde_json::json!({ "bindingHandle": binding, "planHandle": command }),
            ),
        ] {
            let response = handle_frame(&state, &request(method, &params.to_string())).await;
            assert!(!response.ok, "{method} accepted a missing binding");
            assert_eq!(
                response.error.as_ref().unwrap().code,
                "check-audit-binding-unavailable",
                "{method}"
            );
            assert!(!serde_json::to_string(&response).unwrap().contains(binding));
        }

        // A path, a program name, a shell line or an unknown action is no handle.
        let marker = "renderer-forged-check-audit-action";
        for action in [
            serde_json::json!({ "kind": "collect", "commandHandles": [command], "path": marker }),
            serde_json::json!({ "kind": "collect", "commandNames": [marker] }),
            serde_json::json!({ "kind": "clear-log", "logPath": marker }),
            serde_json::json!({ "kind": "deploy", "commandHandles": [command] }),
            serde_json::json!({ "kind": "run", "command": marker }),
        ] {
            let params = serde_json::json!({
                "bindingHandle": binding, "snapshotHandle": snapshot, "action": action,
            });
            let response = handle_frame(
                &state,
                &request("check-audit.action.plan", &params.to_string()),
            )
            .await;
            assert!(!response.ok, "{params}");
            assert_eq!(
                response.error.as_ref().unwrap().code,
                "invalid-params",
                "{params}"
            );
            assert!(!serde_json::to_string(&response).unwrap().contains(marker));
        }
    }

    #[tokio::test]
    async fn log_analysis_read_rpc_routes_are_exact_scoped_and_never_echo_renderer_ingredients() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let binding = "11111111-1111-4111-8111-111111111111";
        let snapshot = "22222222-2222-4222-8222-222222222222";
        let source_a = "33333333-3333-4333-8333-333333333333";
        let source_b = "44444444-4444-4444-8444-444444444444";

        for (method, params) in [
            (
                "log-analysis.sources.discover",
                serde_json::json!({ "bindingHandle": binding }),
            ),
            (
                "log-analysis.source.read",
                serde_json::json!({
                    "bindingHandle": binding,
                    "snapshotHandle": snapshot,
                    "sourceHandle": source_a,
                    "input": {
                        "page": 1,
                        "pageSize": 100,
                        "keyword": null,
                        "date": null,
                        "journalUnit": null,
                    },
                }),
            ),
            (
                "log-analysis.sources.correlate",
                serde_json::json!({
                    "bindingHandle": binding,
                    "snapshotHandle": snapshot,
                    "input": { "sourceHandles": [source_a, source_b], "lineLimit": 200 },
                }),
            ),
            (
                "log-analysis.iocs.search",
                serde_json::json!({
                    "bindingHandle": binding,
                    "snapshotHandle": snapshot,
                    "input": { "sourceHandles": [source_a], "indicators": ["203.0.113.7"] },
                }),
            ),
        ] {
            let response = handle_frame(&state, &request(method, &params.to_string())).await;
            assert!(!response.ok, "{method} accepted a missing binding");
            let failure = response.error.as_ref().unwrap();
            assert_eq!(failure.code, "log-analysis-binding-unavailable", "{method}");
            assert_eq!(
                failure.message, "The log investigation target binding is missing or stale.",
                "{method}"
            );
            let text = serde_json::to_string(&response).unwrap();
            for secret in [binding, snapshot, source_a, source_b] {
                assert!(!text.contains(secret), "{method} echoed {secret}");
            }
        }

        let marker = "renderer-forged-log-command-path-session-target-secret";
        for (method, params) in [
            (
                "log-analysis.sources.discover",
                serde_json::json!({ "bindingHandle": binding, "command": marker }),
            ),
            (
                "log-analysis.source.read",
                serde_json::json!({
                    "bindingHandle": binding,
                    "snapshotHandle": snapshot,
                    "sourceHandle": source_a,
                    "input": {
                        "page": 1,
                        "pageSize": 100,
                        "keyword": null,
                        "date": null,
                        "journalUnit": null,
                        "path": marker,
                    },
                }),
            ),
            (
                "log-analysis.sources.correlate",
                serde_json::json!({
                    "bindingHandle": binding,
                    "snapshotHandle": snapshot,
                    "input": { "sourceHandles": [source_a, source_b], "lineLimit": 200 },
                    "session": marker,
                }),
            ),
            (
                "log-analysis.iocs.search",
                serde_json::json!({
                    "bindingHandle": binding,
                    "snapshotHandle": snapshot,
                    "input": { "sourceHandles": [source_a], "indicators": ["203.0.113.7"] },
                    "target": marker,
                }),
            ),
        ] {
            let response = handle_frame(&state, &request(method, &params.to_string())).await;
            assert!(!response.ok, "{method} accepted a renderer-forged field");
            assert_eq!(response.error.as_ref().unwrap().code, "invalid-params");
            assert!(!serde_json::to_string(&response).unwrap().contains(marker));
        }

        let invalid_binding = "../HOSTILE_LOG_BINDING_MUST_NOT_ECHO";
        let response = handle_frame(
            &state,
            &request(
                "log-analysis.sources.discover",
                &serde_json::json!({ "bindingHandle": invalid_binding }).to_string(),
            ),
        )
        .await;
        assert!(!response.ok);
        assert_eq!(response.error.as_ref().unwrap().code, "invalid-params");
        assert!(
            !serde_json::to_string(&response)
                .unwrap()
                .contains(invalid_binding)
        );
    }

    #[tokio::test]
    async fn kubernetes_read_rpc_routes_are_exact_scoped_and_never_echo_renderer_ingredients() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let binding = "11111111-1111-4111-8111-111111111111";
        let snapshot = "22222222-2222-4222-8222-222222222222";
        let row = "33333333-3333-4333-8333-333333333333";

        for (method, params) in [
            (
                "kubernetes.availability.get",
                serde_json::json!({ "bindingHandle": binding }),
            ),
            (
                "kubernetes.resources.list",
                serde_json::json!({
                    "bindingHandle": binding,
                    "input": { "tab": "pods", "namespaceScope": null },
                }),
            ),
            (
                "kubernetes.resource.detail.get",
                serde_json::json!({
                    "bindingHandle": binding,
                    "snapshotHandle": snapshot,
                    "rowHandle": row,
                }),
            ),
            (
                "kubernetes.pod.logs.get",
                serde_json::json!({
                    "bindingHandle": binding,
                    "snapshotHandle": snapshot,
                    "rowHandle": row,
                }),
            ),
        ] {
            let response = handle_frame(&state, &request(method, &params.to_string())).await;
            assert!(!response.ok, "{method} accepted a missing binding");
            let failure = response.error.as_ref().unwrap();
            assert_eq!(failure.code, "kubernetes-binding-unavailable", "{method}");
            assert_eq!(
                failure.message, "The Kubernetes target binding is missing or stale.",
                "{method}"
            );
            let text = serde_json::to_string(&response).unwrap();
            for capability in [binding, snapshot, row] {
                assert!(!text.contains(capability), "{method} echoed {capability}");
            }
        }

        let marker = "renderer-forged-kubernetes-command-path-session-target-secret";
        for (method, params) in [
            (
                "kubernetes.availability.get",
                serde_json::json!({ "bindingHandle": binding, "command": marker }),
            ),
            (
                "kubernetes.resources.list",
                serde_json::json!({
                    "bindingHandle": binding,
                    "input": {
                        "tab": "pods",
                        "namespaceScope": null,
                        "namespace": marker,
                    },
                }),
            ),
            (
                "kubernetes.resource.detail.get",
                serde_json::json!({
                    "bindingHandle": binding,
                    "snapshotHandle": snapshot,
                    "rowHandle": row,
                    "resourceName": marker,
                }),
            ),
            (
                "kubernetes.pod.logs.get",
                serde_json::json!({
                    "bindingHandle": binding,
                    "snapshotHandle": snapshot,
                    "rowHandle": row,
                    "tailLines": marker,
                }),
            ),
        ] {
            let response = handle_frame(&state, &request(method, &params.to_string())).await;
            assert!(!response.ok, "{method} accepted a renderer-forged field");
            assert_eq!(response.error.as_ref().unwrap().code, "invalid-params");
            assert!(!serde_json::to_string(&response).unwrap().contains(marker));
        }

        let invalid_binding = "../HOSTILE_KUBERNETES_BINDING_MUST_NOT_ECHO";
        let response = handle_frame(
            &state,
            &request(
                "kubernetes.availability.get",
                &serde_json::json!({ "bindingHandle": invalid_binding }).to_string(),
            ),
        )
        .await;
        assert!(!response.ok);
        assert_eq!(response.error.as_ref().unwrap().code, "invalid-params");
        assert!(
            !serde_json::to_string(&response)
                .unwrap()
                .contains(invalid_binding)
        );
    }

    #[test]
    fn a_pod_shell_that_did_not_open_says_which_of_the_reasons_it_was() {
        let code = |subject: &'static str| {
            pod_shell_failure(CoreError::Validation {
                subject,
                message: "HOSTILE_POD_MESSAGE_MUST_NOT_ECHO".to_owned(),
            })
        };
        for (subject, expected) in [
            ("Kubernetes pod shell", "kubernetes-pod-not-running"),
            ("container shell", "kubernetes-pod-shell-missing"),
            ("Kubernetes pod exec", "kubernetes-pod-exec-forbidden"),
            ("Kubernetes permission", "kubernetes-forbidden"),
            ("Kubernetes command", "kubernetes-pod-exec-failed"),
        ] {
            let failure = code(subject);
            assert_eq!(failure.code, expected, "{subject}");
            assert!(!failure.public_message.contains("HOSTILE"), "{subject}");
            assert!(failure.public_message.ends_with('。'), "{subject}");
        }
    }

    #[test]
    fn an_account_refusal_says_which_reason_it_was() {
        use lovelyhawk_core::system_info::{
            USER_ACCOUNT_ROOT_REFUSAL, USER_ACCOUNT_SESSION_REFUSAL, USER_ACCOUNT_STATE_REFUSAL,
        };
        let refused = |subject: &'static str| {
            system_info_failure(SystemInfoApiError::ActionUnavailable(
                CoreError::Validation {
                    subject,
                    message: "alice cannot be deleted: HOSTILE_DETAIL".to_owned(),
                },
            ))
        };
        for (subject, code) in [
            (USER_ACCOUNT_SESSION_REFUSAL, "system-info-account-session"),
            (USER_ACCOUNT_ROOT_REFUSAL, "system-info-account-root"),
            (USER_ACCOUNT_STATE_REFUSAL, "system-info-account-state"),
            ("process identity", "system-info-action-unavailable"),
        ] {
            let failure = refused(subject);
            assert_eq!(failure.code, code, "{subject}");
            assert!(!failure.public_message.contains("HOSTILE"), "{subject}");
        }
    }

    #[test]
    fn a_terminal_on_a_target_that_dropped_off_says_the_connection_is_gone() {
        // What the log showed when a lab host went down: "SSH connection to
        // the target is gone: Channel send error", reported as a terminal
        // failure, a missing shell, or a failed kubectl exec. Each window can
        // only say the right thing if the code says the connection is gone,
        // the way every other page's `-binding-unavailable` code does.
        let gone = || CoreError::SshDisconnected {
            message: "Channel send error".to_owned(),
        };
        for failure in [
            terminal_failure(TerminalApiError::Core(gone())),
            container_shell_failure(gone()),
            pod_shell_failure(gone()),
        ] {
            assert!(
                failure.code.ends_with("-binding-unavailable"),
                "{}",
                failure.code
            );
            assert!(!failure.public_message.contains("Channel send error"));
        }
        // An ordinary failure keeps its own code.
        assert_eq!(
            terminal_failure(TerminalApiError::Core(CoreError::Ssh {
                operation: "open terminal",
                message: "remote probe exited with Some(1)".to_owned(),
            }))
            .code,
            "terminal-operation-failed"
        );
        assert_eq!(
            container_shell_failure(CoreError::Validation {
                subject: "container shell",
                message: "none".to_owned(),
            })
            .code,
            "docker-container-shell-missing"
        );
    }

    #[test]
    fn a_listing_or_pod_file_that_failed_says_which_answer_it_was() {
        let invalid = |subject: &'static str, message: &str| CoreError::Validation {
            subject,
            message: message.to_owned(),
        };
        for (message, expected) in [
            (
                "这个目录不存在，或者不是目录",
                "container-directory-missing",
            ),
            ("没有权限进入这个目录", "container-directory-denied"),
            ("a record was malformed", "container-directory-unreadable"),
        ] {
            let failure = exec_listing_failure(
                invalid("exec directory listing", message),
                docker_exec_failure,
            );
            assert_eq!(failure.code, expected, "{message}");
        }
        // Not a listing answer: the place's own mapping.
        assert_eq!(
            exec_listing_failure(invalid("Kubernetes pod shell", "x"), pod_shell_failure).code,
            "kubernetes-pod-not-running"
        );
        assert_eq!(
            exec_listing_failure(invalid("Kubernetes command", "x"), docker_exec_failure).code,
            "container-exec-failed"
        );
        for (message, expected) in [
            ("这个文件不存在", "kubernetes-pod-file-missing"),
            (
                "文件有 9 字节，超过了查看上限 8 字节",
                "kubernetes-pod-file-too-large",
            ),
            (
                "这不是普通文件（可能是符号链接、目录或设备），不能在这里查看",
                "kubernetes-pod-file-not-regular",
            ),
            ("读取期间文件变了（a → b）", "kubernetes-pod-file-changed"),
            (
                "读到的内容和文件的长度或摘要对不上",
                "kubernetes-pod-file-not-text",
            ),
        ] {
            let failure = pod_file_failure(invalid("Kubernetes pod file", message));
            assert_eq!(failure.code, expected, "{message}");
            assert!(failure.public_message.ends_with('。'));
        }
        assert_eq!(
            pod_file_failure(invalid("Kubernetes pod shell", "x")).code,
            "kubernetes-pod-not-running"
        );
    }

    #[test]
    fn kubernetes_rpc_names_and_failure_mapping_are_closed_and_redacted() {
        for method in [
            "kubernetes.availability.get",
            "kubernetes.resources.list",
            "kubernetes.resource.detail.get",
            "kubernetes.pod.logs.get",
            "kubernetes.pod.terminal.open",
            "kubernetes.pod.directory.list",
            "kubernetes.pod.file.read",
            "kubernetes.pod.file-evidence",
            "kubernetes.manifest.export",
        ] {
            assert!(
                serde_json::from_value::<RpcMethod>(serde_json::json!(method)).is_ok(),
                "missing fixed Kubernetes RPC method {method}"
            );
        }
        for alias in [
            "kubernetes.get",
            "kubernetes.execute",
            "kubernetes.command.run",
            "kubernetes.resource.get",
            "kubernetes.pod.logs.tail",
            "kubernetes.pod.exec",
            "kubernetes.pod.terminal",
        ] {
            assert!(serde_json::from_value::<RpcMethod>(serde_json::json!(alias)).is_err());
        }

        let cases = [
            (
                KubernetesReadApiError::Core(CoreError::Validation {
                    subject: "HOSTILE_KUBERNETES_CORE_SUBJECT_MUST_NOT_ECHO",
                    message: "HOSTILE_KUBERNETES_CORE_MESSAGE_MUST_NOT_ECHO".to_owned(),
                }),
                "kubernetes-operation-failed",
                "LovelyHawk could not complete the Kubernetes read operation.",
            ),
            (
                KubernetesReadApiError::RegistryUnavailable,
                "kubernetes-operation-failed",
                "LovelyHawk could not complete the Kubernetes read operation.",
            ),
            (
                KubernetesReadApiError::BindingUnavailable,
                "kubernetes-binding-unavailable",
                "The Kubernetes target binding is missing or stale.",
            ),
            (
                KubernetesReadApiError::InvalidHandle,
                "invalid-params",
                "The Kubernetes read request parameters are invalid.",
            ),
            (
                KubernetesReadApiError::InvalidInput,
                "invalid-params",
                "The Kubernetes read request parameters are invalid.",
            ),
            (
                KubernetesReadApiError::NamespaceUnavailable,
                "kubernetes-namespace-unavailable",
                "The Kubernetes namespace selection is missing, expired, or stale.",
            ),
            (
                KubernetesReadApiError::SnapshotUnavailable,
                "kubernetes-resource-unavailable",
                "The Kubernetes resource is missing, expired, or stale.",
            ),
            (
                KubernetesReadApiError::RowUnavailable,
                "kubernetes-resource-unavailable",
                "The Kubernetes resource is missing, expired, or stale.",
            ),
            (
                KubernetesReadApiError::LogsUnavailable,
                "kubernetes-logs-unavailable",
                "Pod logs are unavailable for this Kubernetes resource.",
            ),
            (
                KubernetesReadApiError::LogsNotReady,
                "kubernetes-logs-not-ready",
                "The kubelet could not hand over this container log right now.",
            ),
            (
                KubernetesReadApiError::Forbidden,
                "kubernetes-forbidden",
                "The Kubernetes API server refused this account the read (RBAC).",
            ),
            (
                KubernetesReadApiError::from(CoreError::Validation {
                    subject: "Kubernetes permission",
                    message: "HOSTILE_KUBERNETES_CORE_MESSAGE_MUST_NOT_ECHO".to_owned(),
                }),
                "kubernetes-forbidden",
                "The Kubernetes API server refused this account the read (RBAC).",
            ),
            (
                KubernetesReadApiError::Capacity,
                "kubernetes-capacity",
                "The bounded Kubernetes read capacity has been reached.",
            ),
            (
                KubernetesReadApiError::ConcurrencyLimit,
                "kubernetes-capacity",
                "The bounded Kubernetes read capacity has been reached.",
            ),
        ];
        for (error, expected_code, expected_message) in cases {
            let failure = kubernetes_read_failure(error);
            assert_eq!(failure.code, expected_code);
            assert_eq!(failure.public_message, expected_message);
            assert!(failure.source.is_none());
            assert!(!failure.operation.contains("HOSTILE_KUBERNETES"));
            assert!(!failure.public_message.contains("HOSTILE_KUBERNETES"));
        }
    }

    #[tokio::test]
    async fn docker_read_rpc_routes_are_exact_scoped_and_never_echo_renderer_ingredients() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let binding = "11111111-1111-4111-8111-111111111111";
        let snapshot = "22222222-2222-4222-8222-222222222222";
        let resource = "33333333-3333-4333-8333-333333333333";

        for (method, params) in [
            (
                "docker.containers.refresh",
                serde_json::json!({ "bindingHandle": binding }),
            ),
            (
                "docker.collection.get",
                serde_json::json!({
                    "bindingHandle": binding,
                    "snapshotHandle": snapshot,
                    "kind": "stats",
                }),
            ),
            (
                "docker.resource.inspect",
                serde_json::json!({
                    "bindingHandle": binding,
                    "snapshotHandle": snapshot,
                    "kind": "container",
                    "resourceHandle": resource,
                }),
            ),
            (
                "docker.security.audit.get",
                serde_json::json!({
                    "bindingHandle": binding,
                    "snapshotHandle": snapshot,
                }),
            ),
            (
                "docker.container.logs.get",
                serde_json::json!({
                    "bindingHandle": binding,
                    "snapshotHandle": snapshot,
                    "containerHandle": resource,
                    "tail": 100,
                }),
            ),
        ] {
            let response = handle_frame(&state, &request(method, &params.to_string())).await;
            assert!(!response.ok, "{method} accepted a missing binding");
            let failure = response.error.as_ref().unwrap();
            assert_eq!(failure.code, "docker-binding-unavailable", "{method}");
            assert_eq!(
                failure.message, "The Docker target binding is missing or stale.",
                "{method}"
            );
            let text = serde_json::to_string(&response).unwrap();
            for capability in [binding, snapshot, resource] {
                assert!(!text.contains(capability), "{method} echoed {capability}");
            }
        }

        let marker = "renderer-forged-docker-shell-path-target-session-mutation-secret";
        for (method, params) in [
            (
                "docker.containers.refresh",
                serde_json::json!({ "bindingHandle": binding, "command": marker }),
            ),
            (
                "docker.collection.get",
                serde_json::json!({
                    "bindingHandle": binding,
                    "snapshotHandle": snapshot,
                    "kind": "stats",
                    "remotePath": marker,
                }),
            ),
            (
                "docker.resource.inspect",
                serde_json::json!({
                    "bindingHandle": binding,
                    "snapshotHandle": snapshot,
                    "kind": "container",
                    "resourceHandle": resource,
                    "containerId": marker,
                }),
            ),
            (
                "docker.security.audit.get",
                serde_json::json!({
                    "bindingHandle": binding,
                    "snapshotHandle": snapshot,
                    "targetGuard": marker,
                }),
            ),
            (
                "docker.container.logs.get",
                serde_json::json!({
                    "bindingHandle": binding,
                    "snapshotHandle": snapshot,
                    "containerHandle": resource,
                    "tail": 100,
                    "sessionId": marker,
                }),
            ),
        ] {
            let response = handle_frame(&state, &request(method, &params.to_string())).await;
            assert!(!response.ok, "{method} accepted a renderer-forged field");
            assert_eq!(response.error.as_ref().unwrap().code, "invalid-params");
            assert!(!serde_json::to_string(&response).unwrap().contains(marker));
        }

        let invalid_handle = format!("../{marker}");
        for (method, params) in [
            (
                "docker.containers.refresh",
                serde_json::json!({ "bindingHandle": invalid_handle.as_str() }),
            ),
            (
                "docker.collection.get",
                serde_json::json!({
                    "bindingHandle": binding,
                    "snapshotHandle": invalid_handle.as_str(),
                    "kind": "stats",
                }),
            ),
            (
                "docker.resource.inspect",
                serde_json::json!({
                    "bindingHandle": binding,
                    "snapshotHandle": snapshot,
                    "kind": "container",
                    "resourceHandle": invalid_handle.as_str(),
                }),
            ),
            (
                "docker.security.audit.get",
                serde_json::json!({
                    "bindingHandle": binding,
                    "snapshotHandle": invalid_handle.as_str(),
                }),
            ),
            (
                "docker.container.logs.get",
                serde_json::json!({
                    "bindingHandle": binding,
                    "snapshotHandle": snapshot,
                    "containerHandle": invalid_handle.as_str(),
                    "tail": 100,
                }),
            ),
        ] {
            let response = handle_frame(&state, &request(method, &params.to_string())).await;
            assert!(!response.ok, "{method} accepted an invalid capability");
            assert_eq!(response.error.as_ref().unwrap().code, "invalid-params");
            assert!(
                !serde_json::to_string(&response)
                    .unwrap()
                    .contains(&invalid_handle)
            );
        }

        for (method, params) in [
            (
                "docker.collection.get",
                serde_json::json!({
                    "bindingHandle": binding,
                    "snapshotHandle": snapshot,
                    "kind": marker,
                }),
            ),
            (
                "docker.resource.inspect",
                serde_json::json!({
                    "bindingHandle": binding,
                    "snapshotHandle": snapshot,
                    "kind": marker,
                    "resourceHandle": resource,
                }),
            ),
        ] {
            let response = handle_frame(&state, &request(method, &params.to_string())).await;
            assert!(!response.ok, "{method} accepted an open resource kind");
            assert_eq!(response.error.as_ref().unwrap().code, "invalid-params");
            assert!(!serde_json::to_string(&response).unwrap().contains(marker));
        }

        for tail in [0, 1_001] {
            let response = handle_frame(
                &state,
                &request(
                    "docker.container.logs.get",
                    &serde_json::json!({
                        "bindingHandle": binding,
                        "snapshotHandle": snapshot,
                        "containerHandle": resource,
                        "tail": tail,
                    })
                    .to_string(),
                ),
            )
            .await;
            assert!(!response.ok, "Docker logs accepted tail {tail}");
            assert_eq!(response.error.as_ref().unwrap().code, "invalid-params");
        }
    }

    #[test]
    fn docker_rpc_names_state_and_failure_mapping_are_closed_and_redacted() {
        for method in [
            "docker.containers.refresh",
            "docker.collection.get",
            "docker.resource.inspect",
            "docker.security.audit.get",
            "docker.container.logs.get",
            "docker.container.terminal.open",
            "docker.container.directory.list",
            "docker.container.changes.get",
            "docker.container.processes.get",
        ] {
            assert!(
                serde_json::from_value::<RpcMethod>(serde_json::json!(method)).is_ok(),
                "missing fixed Docker RPC method {method}"
            );
        }
        for alias in [
            "docker.refresh",
            "docker.execute",
            "docker.collection",
            "docker.resource.get",
            "docker.security-audit.get",
            "docker.logs.get",
            "docker.container.exec",
        ] {
            assert!(serde_json::from_value::<RpcMethod>(serde_json::json!(alias)).is_err());
        }

        let source = include_str!("lib.rs");
        let state = source
            .split("pub struct BackendState")
            .nth(1)
            .and_then(|value| value.split("struct NoteReplayEntry").next())
            .unwrap();
        // Shared, because the mutation side resolves its container handles
        // through the read side's registry. Two registries would let a handle
        // that names nothing to the pane still name something to an action.
        let state_field = ["docker_read: ", "Arc<DockerReadApi>"].concat();
        assert_eq!(state.matches(&state_field).count(), 1);
        assert_eq!(
            state
                .matches(&["docker_write: ", "DockerWriteApi"].concat())
                .count(),
            1
        );
        let open = source
            .split("impl BackendState")
            .nth(1)
            .and_then(|value| value.split("async fn replay_note_mutation").next())
            .unwrap();
        let initializer = ["let docker_read = ", "Arc::new(DockerReadApi::new"].concat();
        assert_eq!(open.matches(&initializer).count(), 1);
        assert_eq!(
            open.matches(&["Arc::clone(&docker_read)"].concat()).count(),
            1
        );
        let params_start = ["struct Docker", "BindingParams"].concat();
        let params = source
            .split(&params_start)
            .nth(1)
            .and_then(|value| {
                value
                    .split(&["struct EmergencyCommand", "BindingParams"].concat())
                    .next()
            })
            .unwrap();
        // Field declarations only, not the whole region: what must never
        // appear is a Docker request *carrying* one of these primitives, and a
        // struct named after the thing it opens — or a comment explaining why
        // it carries none of them — is not that. Scanning the raw text made the
        // check fire on its own documentation, which is the kind of failure
        // that gets a real rule loosened to shut it up.
        fn declared_fields(region: &str) -> Vec<&str> {
            region
                .lines()
                .map(str::trim)
                .filter(|line| {
                    !line.starts_with("//")
                        && !line.starts_with('#')
                        && line.ends_with(',')
                        && line.contains(": ")
                })
                .collect()
        }
        const FORBIDDEN_PRIMITIVES: [&str; 9] = [
            "command", "path", "target", "session", "mutation", "file", "terminal", "export",
            "generic",
        ];
        // Narrowing the scan is only safe if it still fires on the thing it
        // exists to catch, so prove that here rather than trusting it.
        let leak = declared_fields(
            "struct X {\n    /// a terminal handle\n    terminal_handle: String,\n}",
        );
        assert_eq!(leak, vec!["terminal_handle: String,"]);
        assert!(
            FORBIDDEN_PRIMITIVES
                .iter()
                .any(|forbidden| leak[0].contains(forbidden))
        );

        let fields = declared_fields(params);
        assert!(
            !fields.is_empty(),
            "Docker params field scan matched nothing; the extraction above is broken"
        );
        for forbidden in FORBIDDEN_PRIMITIVES {
            for field in &fields {
                assert!(
                    !field.contains(forbidden),
                    "Docker params exposed forbidden primitive {forbidden} in `{field}`"
                );
            }
        }

        let cases = [
            (
                DockerReadApiError::Core,
                "docker-operation-failed",
                "LovelyHawk could not complete the Docker read operation.",
            ),
            (
                DockerReadApiError::RegistryUnavailable,
                "docker-operation-failed",
                "LovelyHawk could not complete the Docker read operation.",
            ),
            (
                DockerReadApiError::BindingUnavailable,
                "docker-binding-unavailable",
                "The Docker target binding is missing or stale.",
            ),
            (
                DockerReadApiError::InvalidHandle,
                "invalid-params",
                "The Docker read request parameters are invalid.",
            ),
            (
                DockerReadApiError::InvalidKind,
                "invalid-params",
                "The Docker read request parameters are invalid.",
            ),
            (
                DockerReadApiError::InvalidBounds,
                "invalid-params",
                "The Docker read request parameters are invalid.",
            ),
            (
                DockerReadApiError::InvalidSnapshot,
                "docker-snapshot-unavailable",
                "The Docker snapshot is missing, expired, or stale.",
            ),
            (
                DockerReadApiError::SnapshotStale,
                "docker-snapshot-unavailable",
                "The Docker snapshot is missing, expired, or stale.",
            ),
            (
                DockerReadApiError::InvalidResource,
                "docker-resource-unavailable",
                "The Docker resource is missing, expired, or stale.",
            ),
            (
                DockerReadApiError::Capacity,
                "docker-capacity",
                "The bounded Docker read capacity has been reached.",
            ),
        ];
        for (error, expected_code, expected_message) in cases {
            let failure = docker_read_failure(error);
            assert_eq!(failure.code, expected_code);
            assert_eq!(failure.public_message, expected_message);
            assert!(failure.source.is_none());
            assert!(!failure.operation.contains("HOSTILE_DOCKER"));
            assert!(!failure.public_message.contains("HOSTILE_DOCKER"));
        }
    }

    #[tokio::test]
    async fn emergency_command_rpc_routes_are_exact_scoped_and_never_echo_renderer_ingredients() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let binding = "11111111-1111-4111-8111-111111111111";
        let snapshot = "22222222-2222-4222-8222-222222222222";
        let command = "33333333-3333-4333-8333-333333333333";

        for (method, params) in [
            (
                "emergency-command.catalog.load",
                serde_json::json!({ "bindingHandle": binding }),
            ),
            (
                "emergency-command.run",
                serde_json::json!({
                    "bindingHandle": binding,
                    "snapshotHandle": snapshot,
                    "commandHandle": command,
                }),
            ),
        ] {
            let response = handle_frame(&state, &request(method, &params.to_string())).await;
            assert!(!response.ok, "{method} accepted a missing binding");
            let failure = response.error.as_ref().unwrap();
            assert_eq!(
                failure.code, "emergency-command-binding-unavailable",
                "{method}"
            );
            assert_eq!(
                failure.message, "The emergency command target binding is missing or stale.",
                "{method}"
            );
            let text = serde_json::to_string(&response).unwrap();
            for capability in [binding, snapshot, command] {
                assert!(!text.contains(capability), "{method} echoed {capability}");
            }
        }

        let marker = "renderer-forged-emergency-command-shell-path-target-session-secret";
        for (method, params) in [
            (
                "emergency-command.catalog.load",
                serde_json::json!({ "bindingHandle": binding, "shell": marker }),
            ),
            (
                "emergency-command.run",
                serde_json::json!({
                    "bindingHandle": binding,
                    "snapshotHandle": snapshot,
                    "commandHandle": command,
                    "targetIdentity": marker,
                }),
            ),
        ] {
            let response = handle_frame(&state, &request(method, &params.to_string())).await;
            assert!(!response.ok, "{method} accepted a renderer-forged field");
            assert_eq!(response.error.as_ref().unwrap().code, "invalid-params");
            assert!(!serde_json::to_string(&response).unwrap().contains(marker));
        }

        let invalid_binding = "../HOSTILE_EMERGENCY_BINDING_MUST_NOT_ECHO";
        let response = handle_frame(
            &state,
            &request(
                "emergency-command.catalog.load",
                &serde_json::json!({ "bindingHandle": invalid_binding }).to_string(),
            ),
        )
        .await;
        assert!(!response.ok);
        assert_eq!(response.error.as_ref().unwrap().code, "invalid-params");
        assert!(
            !serde_json::to_string(&response)
                .unwrap()
                .contains(invalid_binding)
        );
    }

    /// The one place a Docker request may name a path: container files. The
    /// fields are pinned, so a path cannot spread to other requests by way of
    /// these structs, and nothing that runs or exports may join them.
    #[test]
    fn container_file_params_carry_only_their_reviewed_fields() {
        for method in [
            "docker.container.file.read",
            "docker.container.file.plan-write",
            "docker.container.file.plan-copy",
        ] {
            assert!(
                serde_json::from_value::<RpcMethod>(serde_json::json!(method)).is_ok(),
                "missing container file method {method}"
            );
        }
        let source = include_str!("lib.rs");
        let section = source
            .split(&["// Container file parameters", ", kept apart"].concat())
            .nth(1)
            .and_then(|value| {
                value
                    .split(&["struct EmergencyCommand", "RunParams"].concat())
                    .next()
            })
            .unwrap();
        let mut fields = section
            .lines()
            .map(str::trim)
            .filter(|line| !line.starts_with("//") && line.ends_with(',') && line.contains(": "))
            .collect::<Vec<_>>();
        fields.sort_unstable();
        fields.dedup();
        assert_eq!(
            fields,
            [
                "binding_handle: String,",
                "container_handle: String,",
                "container_name: String,",
                "direction: DockerFileCopyDirection,",
                "file_handle: String,",
                "path: String,",
                "snapshot_handle: String,",
                "source: String,",
                "target: String,",
                "text: String,",
            ]
        );
        for forbidden in [
            "command", "session", "terminal", "export", "generic", "mutation",
        ] {
            assert!(
                fields.iter().all(|field| !field.contains(forbidden)),
                "{forbidden}"
            );
        }
        // Unknown fields are refused, so nothing rides along.
        assert!(
            serde_json::from_value::<DockerFileWriteParams>(serde_json::json!({
                "bindingHandle": "b", "fileHandle": "f", "text": "x", "path": "/etc/passwd"
            }))
            .is_err()
        );
    }

    #[test]
    fn emergency_command_rpc_names_and_failure_mapping_are_closed_and_redacted() {
        for method in [
            "emergency-command.catalog.load",
            "emergency-command.run",
            "emergency-command.history.locate",
        ] {
            assert!(
                serde_json::from_value::<RpcMethod>(serde_json::json!(method)).is_ok(),
                "missing fixed emergency command RPC method {method}"
            );
        }
        for alias in [
            "emergency-command.execute",
            "emergency-command.shell.run",
            "emergency-command.file.read",
            "emergency-command.terminal.open",
            "emergency-command.invoke",
        ] {
            assert!(serde_json::from_value::<RpcMethod>(serde_json::json!(alias)).is_err());
        }

        let cases = [
            (
                EmergencyCommandApiError::Core,
                "emergency-command-operation-failed",
                "LovelyHawk could not complete the emergency command operation.",
            ),
            (
                EmergencyCommandApiError::RegistryUnavailable,
                "emergency-command-operation-failed",
                "LovelyHawk could not complete the emergency command operation.",
            ),
            (
                EmergencyCommandApiError::BindingUnavailable,
                "emergency-command-binding-unavailable",
                "The emergency command target binding is missing or stale.",
            ),
            (
                EmergencyCommandApiError::InvalidHandle,
                "invalid-params",
                "The emergency command request parameters are invalid.",
            ),
            (
                EmergencyCommandApiError::InvalidCatalog,
                "emergency-command-catalog-unavailable",
                "The emergency command catalog is missing, expired, or stale.",
            ),
            (
                EmergencyCommandApiError::CatalogStale,
                "emergency-command-catalog-unavailable",
                "The emergency command catalog is missing, expired, or stale.",
            ),
            (
                EmergencyCommandApiError::Busy,
                "emergency-command-capacity",
                "The bounded emergency command capacity has been reached.",
            ),
            (
                EmergencyCommandApiError::Capacity,
                "emergency-command-capacity",
                "The bounded emergency command capacity has been reached.",
            ),
            (
                EmergencyCommandApiError::Deadline,
                "emergency-command-timeout",
                "The emergency command operation exceeded its deadline.",
            ),
            (
                EmergencyCommandApiError::InvalidReceipt,
                "emergency-command-result-invalid",
                "The emergency command result was rejected.",
            ),
        ];
        for (error, expected_code, expected_message) in cases {
            let failure = emergency_command_failure(error);
            assert_eq!(failure.code, expected_code);
            assert_eq!(failure.public_message, expected_message);
            assert!(failure.source.is_none());
        }
    }

    #[tokio::test]
    async fn packet_capture_live_rpc_routes_are_exact_scoped_and_never_echo_renderer_ingredients() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let binding = "11111111-1111-4111-8111-111111111111";
        let interface = "22222222-2222-4222-8222-222222222222";
        let capture = "33333333-3333-4333-8333-333333333333";
        let marker = "renderer-packet-filter-secret-must-not-echo";

        for (method, params) in [
            (
                "packet-capture.interfaces.list",
                serde_json::json!({ "bindingHandle": binding }),
            ),
            (
                "packet-capture.start",
                serde_json::json!({
                    "bindingHandle": binding,
                    "interfaceHandle": interface,
                    "input": {
                        "filter": marker,
                        "packetLimit": 1,
                        "durationSeconds": 1,
                    },
                }),
            ),
            (
                "packet-capture.poll",
                serde_json::json!({
                    "bindingHandle": binding,
                    "captureHandle": capture,
                    "afterSequence": 0,
                }),
            ),
            (
                "packet-capture.stop",
                serde_json::json!({
                    "bindingHandle": binding,
                    "captureHandle": capture,
                }),
            ),
        ] {
            let response = handle_frame(&state, &request(method, &params.to_string())).await;
            assert!(!response.ok, "{method} accepted a missing binding");
            let failure = response.error.as_ref().unwrap();
            assert_eq!(
                failure.code, "packet-capture-binding-unavailable",
                "{method}"
            );
            assert_eq!(
                failure.message, "The live packet capture target binding is missing or stale.",
                "{method}"
            );
            let text = serde_json::to_string(&response).unwrap();
            for capability in [binding, interface, capture, marker] {
                assert!(!text.contains(capability), "{method} echoed {capability}");
            }
        }

        let forged = "renderer-forged-packet-shell-path-target-session-secret";
        for (method, mut params) in [
            (
                "packet-capture.interfaces.list",
                serde_json::json!({ "bindingHandle": binding }),
            ),
            (
                "packet-capture.start",
                serde_json::json!({
                    "bindingHandle": binding,
                    "interfaceHandle": interface,
                    "input": {
                        "filter": null,
                        "packetLimit": 1,
                        "durationSeconds": 1,
                    },
                }),
            ),
            (
                "packet-capture.poll",
                serde_json::json!({
                    "bindingHandle": binding,
                    "captureHandle": capture,
                    "afterSequence": 0,
                }),
            ),
            (
                "packet-capture.stop",
                serde_json::json!({
                    "bindingHandle": binding,
                    "captureHandle": capture,
                }),
            ),
        ] {
            params["shell"] = serde_json::json!(forged);
            let response = handle_frame(&state, &request(method, &params.to_string())).await;
            assert!(!response.ok, "{method} accepted a renderer-forged field");
            assert_eq!(response.error.as_ref().unwrap().code, "invalid-params");
            assert!(!serde_json::to_string(&response).unwrap().contains(forged));
        }

        let response = handle_frame(
            &state,
            &request(
                "packet-capture.start",
                &serde_json::json!({
                    "bindingHandle": binding,
                    "interfaceHandle": interface,
                    "input": {
                        "filter": null,
                        "packetLimit": 1,
                        "durationSeconds": 1,
                        "command": forged,
                    },
                })
                .to_string(),
            ),
        )
        .await;
        assert!(!response.ok);
        assert_eq!(response.error.as_ref().unwrap().code, "invalid-params");
        assert!(!serde_json::to_string(&response).unwrap().contains(forged));

        let invalid_binding = "../HOSTILE_PACKET_BINDING_MUST_NOT_ECHO";
        let response = handle_frame(
            &state,
            &request(
                "packet-capture.interfaces.list",
                &serde_json::json!({ "bindingHandle": invalid_binding }).to_string(),
            ),
        )
        .await;
        assert!(!response.ok);
        assert_eq!(response.error.as_ref().unwrap().code, "invalid-params");
        assert!(
            !serde_json::to_string(&response)
                .unwrap()
                .contains(invalid_binding)
        );
    }

    #[test]
    fn packet_capture_live_rpc_names_state_and_failure_mapping_are_closed_and_redacted() {
        for method in [
            "packet-capture.interfaces.list",
            "packet-capture.start",
            "packet-capture.poll",
            "packet-capture.stop",
        ] {
            assert!(
                serde_json::from_value::<RpcMethod>(serde_json::json!(method)).is_ok(),
                "missing fixed packet capture RPC method {method}"
            );
        }
        for alias in [
            "packet-capture.interface.list",
            "packet-capture.execute",
            "packet-capture.command.run",
            "packet-capture.file.read",
            "packet-capture.terminal.open",
            "packet-capture.export",
            "packet-capture.invoke",
        ] {
            assert!(serde_json::from_value::<RpcMethod>(serde_json::json!(alias)).is_err());
        }

        let source = include_str!("lib.rs");
        let state = source
            .split("pub struct BackendState")
            .nth(1)
            .and_then(|value| value.split("struct NoteReplayEntry").next())
            .unwrap();
        assert_eq!(
            state
                .matches("packet_capture_live: PacketCaptureLiveApi")
                .count(),
            1
        );
        let open = source
            .split("impl BackendState")
            .nth(1)
            .and_then(|value| value.split("async fn replay_note_mutation").next())
            .unwrap();
        assert_eq!(
            open.matches("PacketCaptureLiveApi::new(services.clone(), Arc::clone(&ssh))")
                .count(),
            1
        );
        let params = source
            .split("struct PacketCaptureBindingParams")
            .nth(1)
            .and_then(|value| value.split("struct ApplicationLogFilterParams").next())
            .unwrap();
        for forbidden in [
            "interface_name",
            "target",
            "session",
            "connection",
            "command",
            "shell",
            "path",
            "mutation",
            "file",
            "terminal",
            "export",
            "generic",
        ] {
            assert!(
                !params.contains(forbidden),
                "packet capture params exposed forbidden primitive {forbidden}"
            );
        }

        let cases = [
            (
                PacketCaptureLiveApiError::Core,
                "packet-capture-operation-failed",
                "LovelyHawk could not complete the live packet capture operation.",
            ),
            (
                PacketCaptureLiveApiError::RegistryUnavailable,
                "packet-capture-operation-failed",
                "LovelyHawk could not complete the live packet capture operation.",
            ),
            (
                PacketCaptureLiveApiError::BindingUnavailable,
                "packet-capture-binding-unavailable",
                "The live packet capture target binding is missing or stale.",
            ),
            (
                PacketCaptureLiveApiError::InvalidHandle,
                "invalid-params",
                "The live packet capture request parameters are invalid.",
            ),
            (
                PacketCaptureLiveApiError::InvalidInput,
                "invalid-params",
                "The live packet capture request parameters are invalid.",
            ),
            (
                PacketCaptureLiveApiError::InvalidCursor,
                "invalid-params",
                "The live packet capture request parameters are invalid.",
            ),
            (
                PacketCaptureLiveApiError::InterfaceUnavailable,
                "packet-capture-interface-unavailable",
                "The packet capture interface is missing, expired, or stale.",
            ),
            (
                PacketCaptureLiveApiError::CaptureUnavailable,
                "packet-capture-unavailable",
                "The live packet capture is missing, expired, or stale.",
            ),
            // Three situations, three next steps: stop the one you have, close
            // one elsewhere, or wait a moment. They used to share a sentence.
            (
                PacketCaptureLiveApiError::CaptureAlreadyActive,
                "packet-capture-already-running",
                "This target already has a live capture running.",
            ),
            (
                PacketCaptureLiveApiError::RegistryCapacity,
                "packet-capture-too-many",
                "Too many live captures are running at once.",
            ),
            (
                PacketCaptureLiveApiError::ConcurrencyLimit,
                "packet-capture-busy",
                "The previous packet capture request is still being handled.",
            ),
            (
                PacketCaptureLiveApiError::OutputLimit,
                "packet-capture-output-invalid",
                "The live packet capture output was rejected.",
            ),
            (
                PacketCaptureLiveApiError::ProtocolViolation,
                "packet-capture-output-invalid",
                "The live packet capture output was rejected.",
            ),
            (
                PacketCaptureLiveApiError::TimedOut,
                "packet-capture-timeout",
                "The live packet capture operation exceeded its deadline.",
            ),
        ];
        for (error, expected_code, expected_message) in cases {
            let failure = packet_capture_live_failure(error);
            assert_eq!(failure.code, expected_code);
            assert_eq!(failure.public_message, expected_message);
            assert!(failure.source.is_none());
        }
    }

    #[tokio::test]
    async fn integrity_rpc_routes_are_exact_scoped_and_never_echo_capabilities() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let binding = "11111111-1111-4111-8111-111111111111";
        let baseline = "22222222-2222-4222-8222-222222222222";
        let operation = "33333333-3333-4333-8333-333333333333";

        let catalog = handle_frame(&state, &request("integrity.presets.get", "{}")).await;
        assert!(catalog.ok);
        let catalog = catalog.result.unwrap();
        assert_eq!(catalog["maximumSelected"], 6);
        assert_eq!(catalog["presets"].as_array().unwrap().len(), 6);

        for (method, params) in [
            (
                "integrity.baselines.list",
                serde_json::json!({ "bindingHandle": binding }),
            ),
            (
                "integrity.comparison.start",
                serde_json::json!({
                    "bindingHandle": binding,
                    "baselineHandle": baseline,
                }),
            ),
            (
                "integrity.comparison.poll",
                serde_json::json!({
                    "bindingHandle": binding,
                    "operationHandle": operation,
                    "afterEvent": 0,
                    "limit": 1,
                }),
            ),
            (
                "integrity.comparison.cancel",
                serde_json::json!({
                    "bindingHandle": binding,
                    "operationHandle": operation,
                }),
            ),
        ] {
            let response = handle_frame(&state, &request(method, &params.to_string())).await;
            assert!(!response.ok, "{method} accepted a missing binding");
            let failure = response.error.as_ref().unwrap();
            assert_eq!(failure.code, "integrity-binding-unavailable", "{method}");
            assert_eq!(
                failure.message, "The file-integrity binding is missing, expired, or stale.",
                "{method}"
            );
            let text = serde_json::to_string(&response).unwrap();
            for capability in [binding, baseline, operation] {
                assert!(!text.contains(capability), "{method} echoed {capability}");
            }
        }

        let forged = "renderer-forged-integrity-shell-path-target-session-secret";
        for (method, mut params) in [
            ("integrity.presets.get", serde_json::json!({})),
            (
                "integrity.baselines.list",
                serde_json::json!({ "bindingHandle": binding }),
            ),
            (
                "integrity.comparison.start",
                serde_json::json!({
                    "bindingHandle": binding,
                    "baselineHandle": baseline,
                }),
            ),
            (
                "integrity.comparison.poll",
                serde_json::json!({
                    "bindingHandle": binding,
                    "operationHandle": operation,
                    "afterEvent": 0,
                    "limit": 1,
                }),
            ),
            (
                "integrity.comparison.cancel",
                serde_json::json!({
                    "bindingHandle": binding,
                    "operationHandle": operation,
                }),
            ),
        ] {
            params["shell"] = serde_json::json!(forged);
            let response = handle_frame(&state, &request(method, &params.to_string())).await;
            assert!(!response.ok, "{method} accepted a forged field");
            assert_eq!(response.error.as_ref().unwrap().code, "invalid-params");
            assert!(!serde_json::to_string(&response).unwrap().contains(forged));
        }

        let invalid_bounds = handle_frame(
            &state,
            &request(
                "integrity.comparison.poll",
                &serde_json::json!({
                    "bindingHandle": binding,
                    "operationHandle": operation,
                    "afterEvent": 0,
                    "limit": 0,
                })
                .to_string(),
            ),
        )
        .await;
        assert!(!invalid_bounds.ok);
        assert_eq!(
            invalid_bounds.error.as_ref().unwrap().code,
            "invalid-params"
        );
    }

    #[test]
    fn integrity_baseline_creation_takes_only_a_binding_and_preset_ids() {
        for method in [
            "integrity.baseline.create.start",
            "integrity.baseline.create.poll",
            "integrity.baseline.create.cancel",
        ] {
            assert!(
                serde_json::from_value::<RpcMethod>(serde_json::json!(method)).is_ok(),
                "missing {method}"
            );
        }
        assert!(
            serde_json::from_value::<IntegrityCreateParams>(serde_json::json!({
                "bindingHandle": "b", "presetIds": ["etc"]
            }))
            .is_ok()
        );
        // A path, a command or anything else riding along is refused whole.
        for extra in [
            "paths",
            "path",
            "customPaths",
            "command",
            "remoteRoot",
            "targetIdentity",
        ] {
            let mut params = serde_json::json!({ "bindingHandle": "b", "presetIds": ["etc"] });
            params[extra] = serde_json::json!("/etc");
            assert!(
                serde_json::from_value::<IntegrityCreateParams>(params).is_err(),
                "{extra}"
            );
        }
        let source = include_str!("lib.rs");
        let fields = source
            .split("struct IntegrityCreateParams {")
            .nth(1)
            .and_then(|value| value.split('}').next())
            .unwrap();
        assert_eq!(
            fields
                .split(',')
                .map(str::trim)
                .filter(|field| !field.is_empty())
                .collect::<Vec<_>>(),
            ["binding_handle: String", "preset_ids: Vec<String>"]
        );
    }

    #[test]
    fn integrity_rpc_names_state_params_and_failures_are_closed_and_redacted() {
        for method in [
            "integrity.presets.get",
            "integrity.baselines.list",
            "integrity.comparison.start",
            "integrity.comparison.poll",
            "integrity.comparison.cancel",
        ] {
            assert!(
                serde_json::from_value::<RpcMethod>(serde_json::json!(method)).is_ok(),
                "missing fixed File Integrity RPC method {method}"
            );
        }
        for alias in [
            "integrity.create",
            "integrity.quarantine",
            "integrity.path.read",
            "integrity.file.read",
            "integrity.shell.run",
            "integrity.terminal.open",
            "integrity.export",
            "integrity.invoke",
            "integrity.command.run",
        ] {
            assert!(serde_json::from_value::<RpcMethod>(serde_json::json!(alias)).is_err());
        }

        let source = include_str!("lib.rs");
        let state = source
            .split("pub struct BackendState")
            .nth(1)
            .and_then(|value| value.split("struct NoteReplayEntry").next())
            .unwrap();
        assert_eq!(state.matches("integrity: Arc<IntegrityApi>").count(), 1);
        let open = source
            .split("impl BackendState")
            .nth(1)
            .and_then(|value| value.split("async fn replay_note_mutation").next())
            .unwrap();
        assert_eq!(open.matches("Arc::new(IntegrityApi::new").count(), 1);
        let params = source
            .split("struct IntegrityBindingParams")
            .nth(1)
            .and_then(|value| value.split("struct SettingsProviderParams").next())
            .unwrap();
        assert_eq!(params.matches("deny_unknown_fields").count(), 4);
        for forbidden in [
            "target",
            "session",
            "connection",
            "command",
            "shell",
            "path",
            "mutation",
            "file",
            "terminal",
            "export",
            "generic",
            "quarantine",
            "create",
        ] {
            assert!(
                !params.contains(forbidden),
                "File Integrity params exposed forbidden primitive {forbidden}"
            );
        }

        let core = integrity_failure(IntegrityApiError::Core(CoreError::Validation {
            subject: "password=hunter",
            message: "renderer-marker-must-not-echo".to_owned(),
        }));
        assert_eq!(core.code, "integrity-operation-failed");
        assert_eq!(
            core.public_message,
            "LovelyHawk could not complete the file-integrity operation."
        );
        assert!(core.source.is_some());

        let cases = [
            (
                IntegrityApiError::RegistryUnavailable,
                "integrity-operation-failed",
                "LovelyHawk could not complete the file-integrity operation.",
            ),
            (
                IntegrityApiError::BindingUnavailable,
                "integrity-binding-unavailable",
                "The file-integrity binding is missing, expired, or stale.",
            ),
            (
                IntegrityApiError::InvalidHandle,
                "invalid-params",
                "The file-integrity request parameters are invalid.",
            ),
            (
                IntegrityApiError::InvalidBounds,
                "invalid-params",
                "The file-integrity request parameters are invalid.",
            ),
            (
                IntegrityApiError::BaselineUnavailable,
                "integrity-baseline-unavailable",
                "The file-integrity baseline is missing, expired, or stale.",
            ),
            (
                IntegrityApiError::OperationUnavailable,
                "integrity-comparison-unavailable",
                "The file-integrity comparison is missing, expired, or stale.",
            ),
            (
                IntegrityApiError::ComparisonUnavailable,
                "integrity-comparison-invalid",
                "The file-integrity comparison result is unavailable or invalid.",
            ),
            (
                IntegrityApiError::Capacity,
                "integrity-capacity",
                "The bounded file-integrity capacity has been reached.",
            ),
        ];
        for (error, expected_code, expected_message) in cases {
            let failure = integrity_failure(error);
            assert_eq!(failure.code, expected_code);
            assert_eq!(failure.public_message, expected_message);
            assert!(failure.source.is_none());
        }
    }

    #[tokio::test]
    async fn application_log_rpc_routes_are_exact_bounded_and_do_not_echo_forged_fields() {
        let root = TestRoot::new();
        let capture = DiagnosticLogCapture::new(DiagnosticLogLevel::Debug);
        let state =
            BackendState::open_with_diagnostic_capture(root.0.clone(), Arc::clone(&capture))
                .unwrap();
        let subscriber = tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(std::io::sink)
                    .with_filter(tracing_subscriber::filter::LevelFilter::INFO),
            )
            .with(capture.layer());
        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!(
                target: "lovelyhawk_application_log_test",
                detail = "plain text",
                "hostile <script>text</script>"
            );
        });
        let filter = serde_json::json!({
            "filter": { "minimumLevel": null, "search": "" },
        });

        let listed = handle_frame(
            &state,
            &request("application-log.list", &filter.to_string()),
        )
        .await;
        assert!(listed.ok);
        let snapshot = listed.result.unwrap();
        assert_eq!(snapshot["capacity"], 500);
        assert_eq!(snapshot["totalBuffered"], 1);
        assert_eq!(
            snapshot["entries"][0]["message"],
            "hostile <script>text</script>"
        );
        for forbidden in [
            "bindingHandle",
            "connectionId",
            "sessionId",
            "targetIdentity",
            "path",
            "contents",
        ] {
            assert!(snapshot.get(forbidden).is_none());
        }

        let preview = handle_frame(
            &state,
            &request("application-log.preview.get", &filter.to_string()),
        )
        .await;
        assert!(preview.ok);
        assert!(
            preview.result.unwrap()["content"]
                .as_str()
                .unwrap()
                .contains("hostile <script>")
        );

        let export = handle_frame(
            &state,
            &request("application-log.export.prepare", &filter.to_string()),
        )
        .await;
        assert!(export.ok);
        let payload = export.result.unwrap();
        assert_eq!(payload["format"], "text");
        assert_eq!(payload["mediaType"], "text/plain; charset=utf-8");
        assert!(payload.get("path").is_none());

        let level = handle_frame(
            &state,
            &request("application-log.level.set", r#"{"level":"error"}"#),
        )
        .await;
        assert!(level.ok);
        assert_eq!(
            level.result.unwrap(),
            serde_json::json!({
                "level": "error",
                "persisted": false,
            })
        );

        let cleared = handle_frame(&state, &request("application-log.buffer.clear", "{}")).await;
        assert!(cleared.ok);
        let clear = cleared.result.unwrap();
        assert_eq!(clear["clearedEntries"], 1);
        assert_eq!(clear["volatileOnly"], true);
        assert_eq!(clear["persistedFilesAffected"], false);

        let forged = "renderer-forged-log-shell-path-target-session-secret";
        for (method, params) in [
            (
                "application-log.list",
                serde_json::json!({
                    "filter": { "minimumLevel": null, "search": "" },
                    "shell": forged,
                }),
            ),
            (
                "application-log.level.set",
                serde_json::json!({ "level": "info", "shell": forged }),
            ),
            (
                "application-log.buffer.clear",
                serde_json::json!({ "shell": forged }),
            ),
            (
                "application-log.preview.get",
                serde_json::json!({
                    "filter": { "minimumLevel": null, "search": "" },
                    "shell": forged,
                }),
            ),
            (
                "application-log.export.prepare",
                serde_json::json!({
                    "filter": { "minimumLevel": null, "search": "" },
                    "shell": forged,
                }),
            ),
        ] {
            let response = handle_frame(&state, &request(method, &params.to_string())).await;
            assert!(!response.ok, "{method} accepted a forged field");
            assert_eq!(response.error.as_ref().unwrap().code, "invalid-params");
            assert!(!serde_json::to_string(&response).unwrap().contains(forged));
        }

        let nested = handle_frame(
            &state,
            &request(
                "application-log.list",
                &serde_json::json!({
                    "filter": {
                        "minimumLevel": null,
                        "search": "",
                        "path": forged,
                    },
                })
                .to_string(),
            ),
        )
        .await;
        assert!(!nested.ok);
        assert_eq!(nested.error.as_ref().unwrap().code, "invalid-params");
        assert!(!serde_json::to_string(&nested).unwrap().contains(forged));

        let control = handle_frame(
            &state,
            &request(
                "application-log.list",
                &serde_json::json!({
                    "filter": { "minimumLevel": null, "search": "secret\0marker" },
                })
                .to_string(),
            ),
        )
        .await;
        assert!(!control.ok);
        assert_eq!(control.error.as_ref().unwrap().code, "invalid-params");
        assert!(!serde_json::to_string(&control).unwrap().contains("secret"));
    }

    #[test]
    fn application_log_rpc_composition_is_single_local_and_fail_closed() {
        for method in [
            "application-log.list",
            "application-log.level.set",
            "application-log.buffer.clear",
            "application-log.preview.get",
            "application-log.export.prepare",
        ] {
            assert!(
                serde_json::from_value::<RpcMethod>(serde_json::json!(method)).is_ok(),
                "missing fixed Application Log RPC method {method}"
            );
        }
        for alias in [
            "application-log.invoke",
            "application-log.stderr.read",
            "application-log.file.read",
            "application-log.path.read",
            "application-log.shell.run",
            "application-log.terminal.open",
            "application-log.export.write",
            "application-log.persisted.clear",
        ] {
            assert!(serde_json::from_value::<RpcMethod>(serde_json::json!(alias)).is_err());
        }

        let source = include_str!("lib.rs");
        let state = source
            .split("pub struct BackendState")
            .nth(1)
            .and_then(|value| value.split("struct NoteReplayEntry").next())
            .unwrap();
        assert_eq!(state.matches("diagnostic_log: DiagnosticLogApi").count(), 1);
        let open = source
            .split("impl BackendState")
            .nth(1)
            .and_then(|value| value.split("async fn replay_note_mutation").next())
            .unwrap();
        assert_eq!(
            open.matches("DiagnosticLogApi::new(diagnostic_capture)")
                .count(),
            1
        );
        let params = source
            .split("struct ApplicationLogFilterParams")
            .nth(1)
            .and_then(|value| value.split("struct IntegrityBindingParams").next())
            .unwrap();
        assert_eq!(params.matches("deny_unknown_fields").count(), 2);
        for forbidden in [
            "binding",
            "target",
            "session",
            "connection",
            "command",
            "shell",
            "path",
            "terminal",
            "file",
            "generic",
        ] {
            assert!(!params.contains(forbidden));
        }

        let failure = diagnostic_log_failure(DiagnosticLogApiError::SearchContainsControl);
        assert_eq!(failure.code, "invalid-params");
        assert_eq!(
            failure.public_message,
            "The application log request parameters are invalid."
        );
        assert!(failure.source.is_none());

        let main_source = include_str!("main.rs");
        assert_eq!(
            main_source
                .matches("DiagnosticLogCapture::new(DiagnosticLogLevel::Info)")
                .count(),
            1
        );
        assert_eq!(main_source.matches(".try_init()").count(), 1);
        assert!(main_source.contains(".with_filter(stderr_filter)"));
        assert!(main_source.contains(".with(diagnostic_capture.layer())"));
        assert!(main_source.contains(
            "BackendState::open_with_diagnostic_capture(archive_root, diagnostic_capture)"
        ));

        let disconnect = source
            .split("RpcMethod::SshBindingDisconnect")
            .nth(1)
            .and_then(|value| value.split("RpcMethod::TerminalOpen").next())
            .unwrap();
        assert!(!disconnect.contains("diagnostic_log.clear_buffer"));
    }

    #[test]
    fn ssh_disconnect_closes_read_capabilities_before_real_disconnect() {
        let source = include_str!("lib.rs");
        let branch = source
            .split("RpcMethod::SshBindingDisconnect")
            .nth(1)
            .and_then(|value| value.split("RpcMethod::TerminalOpen").next())
            .unwrap();
        let baseline_close = branch
            .find("self.baseline_read.close_binding(&params.binding_handle);")
            .unwrap();
        let baseline_action_close = branch
            .find("self.baseline_write.close_binding(&params.binding_handle);")
            .unwrap();
        let check_audit_close = branch
            .find("self.check_audit_read.close_binding(&params.binding_handle);")
            .unwrap();
        let check_audit_action_close = branch
            .find("self.check_audit_write.close_binding(&params.binding_handle);")
            .unwrap();
        let integrity_close = branch
            .find("self.integrity.close_binding(&params.binding_handle);")
            .unwrap();
        let log_analysis_close = branch
            .find("self.log_analysis_read.close_binding(&params.binding_handle);")
            .unwrap();
        let kubernetes_close = branch
            .find("self.kubernetes_read.close_binding(&params.binding_handle);")
            .unwrap();
        let kubernetes_action_close = branch
            .find("self.kubernetes_write.close_binding(&params.binding_handle);")
            .unwrap();
        let emergency_command_close = branch
            .find("self.emergency_command.close_binding(&params.binding_handle);")
            .unwrap();
        let docker_close = branch
            .find("self.docker_read.close_binding(&params.binding_handle);")
            .unwrap();
        // A pending action plan outlives its binding otherwise, and the next
        // connection would find an approval it never gave.
        let docker_action_close = branch
            .find("self.docker_write.close_binding(&params.binding_handle);")
            .unwrap();
        let packet_capture_close = branch.find("self.packet_capture_live").unwrap();
        let disconnect = branch
            .find(".disconnect_binding(&params.binding_handle)")
            .unwrap();
        assert!(baseline_close < disconnect);
        assert!(baseline_action_close < disconnect);
        assert!(check_audit_close < disconnect);
        assert!(check_audit_action_close < disconnect);
        assert!(integrity_close < disconnect);
        assert!(log_analysis_close < disconnect);
        assert!(kubernetes_close < disconnect);
        assert!(kubernetes_action_close < disconnect);
        assert!(emergency_command_close < disconnect);
        assert!(docker_close < disconnect);
        assert!(docker_action_close < disconnect);
        assert!(packet_capture_close < disconnect);
        assert!(integrity_close < packet_capture_close);
    }

    #[tokio::test]
    async fn terminal_rpc_routes_are_fixed_bounded_and_do_not_echo_capabilities() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let binding = "missing-terminal-binding-marker";
        let handle = "11111111-2222-4333-8444-555555555555";
        let cases = [
            (
                "terminal.open",
                serde_json::json!({ "bindingHandle": binding, "columns": 80, "rows": 24 }),
                "terminal-binding-unavailable",
            ),
            (
                "terminal.poll",
                serde_json::json!({ "handle": handle, "maximumEvents": 64, "maximumBytes": 262144 }),
                "terminal-unavailable",
            ),
            (
                "terminal.input",
                serde_json::json!({ "handle": handle, "bytesBase64": "YQ==" }),
                "terminal-unavailable",
            ),
            (
                "terminal.resize",
                serde_json::json!({ "handle": handle, "columns": 100, "rows": 30 }),
                "terminal-unavailable",
            ),
            (
                "terminal.render-snapshot",
                serde_json::json!({ "handle": handle }),
                "terminal-unavailable",
            ),
            (
                "terminal.search",
                serde_json::json!({
                    "handle": handle,
                    "query": "needle",
                    "caseSensitive": false,
                    "regex": false,
                    "maximumResults": 16
                }),
                "terminal-unavailable",
            ),
            (
                "terminal.close",
                serde_json::json!({ "handle": handle }),
                "terminal-unavailable",
            ),
        ];
        for (method, params, expected_code) in cases {
            let response = handle_frame(&state, &request(method, &params.to_string())).await;
            assert!(!response.ok, "{method}");
            assert_eq!(
                response.error.as_ref().unwrap().code,
                expected_code,
                "{method}"
            );
            let encoded = serde_json::to_string(&response).unwrap();
            assert!(!encoded.contains(binding));
            assert!(!encoded.contains(handle));
        }

        let marker = "renderer-forged-terminal-command-marker";
        let forged = handle_frame(
            &state,
            &request(
                "terminal.open",
                &serde_json::json!({
                    "bindingHandle": binding,
                    "columns": 80,
                    "rows": 24,
                    "command": marker
                })
                .to_string(),
            ),
        )
        .await;
        assert_eq!(forged.error.as_ref().unwrap().code, "invalid-params");
        assert!(!serde_json::to_string(&forged).unwrap().contains(marker));
    }

    #[tokio::test]
    async fn directory_terminal_rpc_takes_browser_handles_never_a_path_or_command() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let binding = "missing-directory-terminal-binding";
        let browser = "11111111-2222-4333-8444-555555555555";
        let directory = "66666666-7777-4888-9999-aaaaaaaaaaaa";
        let missing = handle_frame(
            &state,
            &request(
                "terminal.open-directory",
                &serde_json::json!({
                    "bindingHandle": binding,
                    "browserHandle": browser,
                    "directoryHandle": directory,
                    "columns": 80,
                    "rows": 24
                })
                .to_string(),
            ),
        )
        .await;
        assert!(!missing.ok);
        assert_eq!(
            missing.error.as_ref().unwrap().code,
            "sftp-browser-binding-unavailable"
        );
        let encoded = serde_json::to_string(&missing).unwrap();
        for echoed in [binding, browser, directory] {
            assert!(!encoded.contains(echoed));
        }

        let marker = "/tmp/renderer-forged-directory-marker";
        for forged_field in ["path", "directory", "command", "shell"] {
            let mut params = serde_json::json!({
                "bindingHandle": binding,
                "browserHandle": browser,
                "directoryHandle": directory,
                "columns": 80,
                "rows": 24
            });
            params[forged_field] = serde_json::Value::from(marker);
            let forged = handle_frame(
                &state,
                &request("terminal.open-directory", &params.to_string()),
            )
            .await;
            assert_eq!(
                forged.error.as_ref().unwrap().code,
                "invalid-params",
                "{forged_field}"
            );
            assert!(!serde_json::to_string(&forged).unwrap().contains(marker));
        }
        let without_directory = handle_frame(
            &state,
            &request(
                "terminal.open-directory",
                &serde_json::json!({
                    "bindingHandle": binding,
                    "browserHandle": browser,
                    "columns": 80,
                    "rows": 24
                })
                .to_string(),
            ),
        )
        .await;
        assert_eq!(
            without_directory.error.as_ref().unwrap().code,
            "invalid-params"
        );
    }

    #[tokio::test]
    async fn java_hot_update_rpc_takes_handles_or_a_checked_jar_path_and_echoes_nothing() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let binding = "missing-java-binding-marker";
        for params in [
            serde_json::json!({ "action": "scan", "bindingHandle": binding }),
            serde_json::json!({ "action": "history", "bindingHandle": binding }),
            serde_json::json!({ "action": "execute", "bindingHandle": binding, "planHandle": "p" }),
        ] {
            let response =
                handle_frame(&state, &request("java.hot-update", &params.to_string())).await;
            assert_eq!(
                response.error.as_ref().unwrap().code,
                "java-binding-unavailable",
                "{params}"
            );
            assert!(!serde_json::to_string(&response).unwrap().contains(binding));
        }
        let marker = "/opt/forged-java-marker.jar";
        for forged in [
            serde_json::json!({ "action": "inspect", "bindingHandle": binding, "snapshotHandle": "s", "jarHandle": "j", "path": marker }),
            serde_json::json!({ "action": "scan", "bindingHandle": binding, "command": marker }),
            serde_json::json!({ "action": "plan", "bindingHandle": binding, "snapshotHandle": "s", "jarHandle": "j", "entry": "A.class", "stagedHandle": "c", "localPath": marker }),
            serde_json::json!({ "action": "stage", "bindingHandle": binding, "localPath": marker }),
            // A typed path is only ever an absolute .jar path, refused before any target is touched.
            serde_json::json!({ "action": "inspect-path", "bindingHandle": binding, "snapshotHandle": "s", "path": "/opt/forged-java-marker.jar/../../etc/shadow" }),
            serde_json::json!({ "action": "inspect-path", "bindingHandle": binding, "snapshotHandle": "s", "path": "/opt/forged-java-marker.jar; id" }),
        ] {
            let response =
                handle_frame(&state, &request("java.hot-update", &forged.to_string())).await;
            assert_eq!(
                response.error.as_ref().unwrap().code,
                "invalid-params",
                "{forged}"
            );
            assert!(!serde_json::to_string(&response).unwrap().contains(marker));
            assert!(
                !serde_json::to_string(&response)
                    .unwrap()
                    .contains("forged-java-marker")
            );
        }
        let typed = handle_frame(
            &state,
            &request(
                "java.hot-update",
                &serde_json::json!({ "action": "inspect-path", "bindingHandle": binding, "snapshotHandle": "s", "path": marker }).to_string(),
            ),
        )
        .await;
        assert_eq!(
            typed.error.as_ref().unwrap().code,
            "java-binding-unavailable"
        );
        assert!(!serde_json::to_string(&typed).unwrap().contains(marker));
        // The host's stage method takes a local path, so it must never be a
        // page method: the host bridge test keeps it off the main allowlist.
        let staged = handle_frame(
            &state,
            &request(
                "java.hot-update.class.stage",
                &serde_json::json!({ "bindingHandle": binding, "localPath": marker, "name": "A.class" }).to_string(),
            ),
        )
        .await;
        assert_eq!(
            staged.error.as_ref().unwrap().code,
            "java-binding-unavailable"
        );
        assert!(!serde_json::to_string(&staged).unwrap().contains(marker));
    }

    #[tokio::test]
    async fn disposal_report_rpc_routes_are_fixed_scoped_and_reject_renderer_ingredients() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let binding = "missing-disposal-binding";
        let report = "missing-disposal-report";
        let cases = [
            (
                "disposal-report.generate",
                serde_json::json!({ "bindingHandle": binding }),
            ),
            (
                "disposal-report.content.get",
                serde_json::json!({
                    "bindingHandle": binding,
                    "reportHandle": report,
                    "format": "summary"
                }),
            ),
            (
                "disposal-report.export",
                serde_json::json!({
                    "bindingHandle": binding,
                    "reportHandle": report,
                    "format": "html"
                }),
            ),
        ];
        for (method, params) in cases {
            let response = handle_frame(&state, &request(method, &params.to_string())).await;
            assert!(!response.ok, "{method} accepted a missing binding");
            let encoded = serde_json::to_string(&response).unwrap();
            assert!(!encoded.contains(binding));
            assert!(!encoded.contains(report));
        }

        let marker = "renderer-forged-disposal-ingredient";
        for (method, params) in [
            (
                "disposal-report.generate",
                serde_json::json!({ "bindingHandle": binding, "target": marker }),
            ),
            (
                "disposal-report.content.get",
                serde_json::json!({
                    "bindingHandle": binding,
                    "reportHandle": report,
                    "format": "html",
                    "body": marker
                }),
            ),
            (
                "disposal-report.export",
                serde_json::json!({
                    "bindingHandle": binding,
                    "reportHandle": report,
                    "format": "markdown",
                    "path": marker
                }),
            ),
        ] {
            let response = handle_frame(&state, &request(method, &params.to_string())).await;
            assert!(!response.ok);
            assert_eq!(response.error.as_ref().unwrap().code, "invalid-params");
            assert!(!serde_json::to_string(&response).unwrap().contains(marker));
        }
    }

    #[tokio::test]
    async fn unknown_methods_and_hostile_fields_fail_closed_without_echoing_input() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let hostile = br#"{"protocol":"lovelyhawk-backend/v1","requestId":"request-1","method":"shell.execute","params":{"command":"</script><script>steal()</script>"}}"#;
        let response = handle_frame(&state, hostile).await;
        assert!(!response.ok);
        let encoded = serde_json::to_string(&response).unwrap();
        assert!(encoded.contains("invalid-request"));
        assert!(!encoded.contains("steal"));
        assert!(!encoded.contains("shell.execute"));
    }

    #[tokio::test]
    async fn connection_list_returns_only_bounded_credential_free_summaries() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let response = handle_frame(&state, &request("connections.list", "{}")).await;
        assert!(response.ok);
        assert_eq!(response.result.unwrap(), Value::Array(Vec::new()));
    }

    #[tokio::test]
    async fn a_damaged_connection_store_is_reported_as_unreadable_and_left_alone() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let store = root.0.join("data").join("connections.json");
        fs::write(&store, b"{ this is not the store").unwrap();
        let response = handle_frame(&state, &request("connections.list", "{}")).await;
        assert!(!response.ok);
        assert_eq!(response.error.unwrap().code, "connections-store-unreadable");
        // Nothing rewrote the file the operator may want to recover.
        assert_eq!(fs::read(&store).unwrap(), b"{ this is not the store");
    }

    #[tokio::test]
    async fn connection_rpc_routes_crud_and_one_time_delete_without_returning_secrets() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let input = r#"{
            "connection": {
                "id": "server-1",
                "name": "Incident host",
                "host": "10.0.0.8",
                "port": 22,
                "username": "root",
                "authMethod": "password",
                "privateKeyPath": null,
                "certificatePath": null,
                "agentIdentityFingerprint": null,
                "jumpHost": null,
                "tags": ["critical"],
                "notes": "plain text only",
                "environment": "competition",
                "role": null,
                "group": "red-team"
            },
            "secrets": {
                "password": { "action": "replace", "value": "never-return-this-secret" }
            }
        }"#;

        let created = handle_frame(&state, &request("connections.create", input)).await;
        assert!(created.ok);
        let encoded = serde_json::to_string(&created).unwrap();
        assert!(encoded.contains("\"hasPassword\":true"));
        assert!(!encoded.contains("never-return-this-secret"));

        let fetched =
            handle_frame(&state, &request("connections.get", r#"{"id":"server-1"}"#)).await;
        assert!(fetched.ok);
        assert_eq!(fetched.result.unwrap()["id"], "server-1");

        let cancelled_prompt = handle_frame(
            &state,
            &request("connections.delete.plan", r#"{"id":"server-1"}"#),
        )
        .await;
        assert!(cancelled_prompt.ok);
        let cancelled_handle = cancelled_prompt.result.unwrap()["handle"]
            .as_str()
            .unwrap()
            .to_owned();
        let cancelled_params = format!(r#"{{"handle":"{cancelled_handle}"}}"#);
        let cancelled = handle_frame(
            &state,
            &request("connections.delete.cancel", &cancelled_params),
        )
        .await;
        assert!(cancelled.ok);
        assert_eq!(
            cancelled.result.unwrap(),
            serde_json::json!({ "cancelled": true })
        );

        let repeated_cancel = handle_frame(
            &state,
            &request("connections.delete.cancel", &cancelled_params),
        )
        .await;
        assert!(!repeated_cancel.ok);
        assert!(
            !serde_json::to_string(&repeated_cancel)
                .unwrap()
                .contains(&cancelled_handle)
        );
        let cancelled_confirmation = handle_frame(
            &state,
            &request("connections.delete.confirm", &cancelled_params),
        )
        .await;
        assert!(!cancelled_confirmation.ok);
        assert!(
            handle_frame(&state, &request("connections.get", r#"{"id":"server-1"}"#))
                .await
                .ok
        );

        let prompt = handle_frame(
            &state,
            &request("connections.delete.plan", r#"{"id":"server-1"}"#),
        )
        .await;
        assert!(prompt.ok);
        let handle = prompt.result.unwrap()["handle"]
            .as_str()
            .unwrap()
            .to_owned();
        let confirmation = format!(r#"{{"handle":"{handle}"}}"#);

        let deleted = handle_frame(
            &state,
            &request("connections.delete.confirm", &confirmation),
        )
        .await;
        assert!(deleted.ok);
        assert_eq!(deleted.result.unwrap()["verified"], true);

        let repeated = handle_frame(
            &state,
            &request("connections.delete.confirm", &confirmation),
        )
        .await;
        assert!(!repeated.ok);
        assert_eq!(
            repeated.error.as_ref().unwrap().code,
            "connection-not-found"
        );
        assert!(!serde_json::to_string(&repeated).unwrap().contains(&handle));
    }

    #[tokio::test]
    async fn connection_rpc_parameter_dtos_reject_unknown_fields_without_echoing_them() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let response = handle_frame(
            &state,
            &request(
                "connections.get",
                r#"{"id":"server-1","unexpected":"do-not-echo"}"#,
            ),
        )
        .await;
        assert!(!response.ok);
        assert_eq!(response.error.as_ref().unwrap().code, "invalid-params");
        assert!(
            !serde_json::to_string(&response)
                .unwrap()
                .contains("do-not-echo")
        );

        let cancel = handle_frame(
            &state,
            &request(
                "connections.delete.cancel",
                r#"{"handle":"0123456789abcdef0123456789abcdef","unexpected":"do-not-echo"}"#,
            ),
        )
        .await;
        assert!(!cancel.ok);
        assert_eq!(cancel.error.as_ref().unwrap().code, "invalid-params");
        assert!(
            !serde_json::to_string(&cancel)
                .unwrap()
                .contains("do-not-echo")
        );
    }

    #[tokio::test]
    async fn connection_file_rpcs_are_path_internal_secret_free_and_create_only() {
        let source_root = TestRoot::new();
        let source = BackendState::open(source_root.0.clone()).unwrap();
        let created = handle_frame(
            &source,
            &request(
                "connections.create",
                r#"{
                    "connection": {
                        "id": "source-id",
                        "name": "Imported incident host",
                        "host": "10.0.0.80",
                        "port": 22,
                        "username": "root",
                        "authMethod": "password",
                        "privateKeyPath": null,
                        "certificatePath": null,
                        "agentIdentityFingerprint": null,
                        "jumpHost": null,
                        "tags": ["critical"],
                        "notes": "plain text only",
                        "environment": "competition",
                        "role": null,
                        "group": "red-team"
                    },
                    "secrets": {
                        "password": { "action": "replace", "value": "never-export-this-secret" }
                    }
                }"#,
            ),
        )
        .await;
        assert!(created.ok);

        let export_path = source_root.0.join("selected-connections.json");
        let export_params = serde_json::to_string(&serde_json::json!({
            "path": export_path,
        }))
        .unwrap();
        let exported =
            handle_frame(&source, &request("connections.export-file", &export_params)).await;
        assert!(exported.ok);
        assert_eq!(exported.result, Some(serde_json::json!({ "count": 1 })));
        let file = fs::read_to_string(&export_path).unwrap();
        assert!(!file.contains("never-export-this-secret"));
        assert!(!file.contains("source-id"));
        assert!(
            !serde_json::to_string(&exported)
                .unwrap()
                .contains(export_path.to_string_lossy().as_ref())
        );

        let existing =
            handle_frame(&source, &request("connections.export-file", &export_params)).await;
        assert!(!existing.ok);
        assert!(
            !serde_json::to_string(&existing)
                .unwrap()
                .contains(export_path.to_string_lossy().as_ref())
        );

        let target_root = TestRoot::new();
        let target = BackendState::open(target_root.0.clone()).unwrap();
        let imported =
            handle_frame(&target, &request("connections.import-file", &export_params)).await;
        assert!(imported.ok);
        assert_eq!(
            imported.result,
            Some(serde_json::json!({
                "imported": 1,
                "skippedExisting": 0,
                "skippedDuplicate": 0
            }))
        );
        let list = handle_frame(&target, &request("connections.list", "{}")).await;
        let list_result = list.result.unwrap();
        let entry = &list_result.as_array().unwrap()[0];
        assert_ne!(entry["id"], "source-id");
        assert_eq!(entry["hasPassword"], false);

        let hostile_path = target_root.0.join("hostile.json");
        fs::write(
            &hostile_path,
            br#"{"payload":"</script><script>steal()</script>"}"#,
        )
        .unwrap();
        let hostile_params = serde_json::to_string(&serde_json::json!({
            "path": hostile_path,
        }))
        .unwrap();
        let hostile = handle_frame(
            &target,
            &request("connections.import-file", &hostile_params),
        )
        .await;
        assert!(!hostile.ok);
        let encoded = serde_json::to_string(&hostile).unwrap();
        assert!(!encoded.contains("steal"));
        assert!(!encoded.contains(hostile_path.to_string_lossy().as_ref()));

        let unknown = handle_frame(
            &target,
            &request(
                "connections.import-file",
                r#"{"path":"C:\\safe.json","contents":"do-not-echo"}"#,
            ),
        )
        .await;
        assert!(!unknown.ok);
        assert_eq!(unknown.error.as_ref().unwrap().code, "invalid-params");
        assert!(
            !serde_json::to_string(&unknown)
                .unwrap()
                .contains("do-not-echo")
        );
    }

    #[tokio::test]
    async fn ssh_controller_rpc_is_fixed_and_missing_capabilities_do_not_echo_identifiers() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let missing = handle_frame(
            &state,
            &request(
                "ssh.connect.start",
                r#"{"connectionId":"hostile-missing-connection"}"#,
            ),
        )
        .await;
        assert!(!missing.ok);
        assert_eq!(
            missing.error.as_ref().unwrap().code,
            "ssh-capability-not-found"
        );
        assert!(
            !serde_json::to_string(&missing)
                .unwrap()
                .contains("hostile-missing-connection")
        );

        let unknown_field = handle_frame(
            &state,
            &request(
                "ssh.attempt.get",
                r#"{"attemptHandle":"opaque","sessionId":"must-not-be-accepted"}"#,
            ),
        )
        .await;
        assert!(!unknown_field.ok);
        assert_eq!(unknown_field.error.as_ref().unwrap().code, "invalid-params");
        assert!(
            !serde_json::to_string(&unknown_field)
                .unwrap()
                .contains("must-not-be-accepted")
        );
    }

    #[tokio::test]
    async fn ssh_probe_rpc_validates_drafts_without_returning_write_only_secrets() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let response = handle_frame(
            &state,
            &request(
                "ssh.probe.start",
                r#"{
                    "connection": {
                        "id": "server-1",
                        "name": "Hostile draft",
                        "host": "server.example;id",
                        "port": 22,
                        "username": "root",
                        "authMethod": "password",
                        "privateKeyPath": null,
                        "certificatePath": null,
                        "agentIdentityFingerprint": null,
                        "jumpHost": null,
                        "tags": [],
                        "notes": null,
                        "environment": null,
                        "role": null,
                        "group": null
                    },
                    "secrets": {
                        "password": {
                            "action": "replace",
                            "value": "probe-secret-must-not-return"
                        }
                    }
                }"#,
            ),
        )
        .await;
        assert!(!response.ok);
        assert_eq!(response.error.as_ref().unwrap().code, "ssh-invalid");
        let encoded = serde_json::to_string(&response).unwrap();
        assert!(!encoded.contains("probe-secret-must-not-return"));
        assert!(!encoded.contains("server.example;id"));
    }

    #[tokio::test]
    async fn system_info_row_actions_reject_forged_keys_handles_and_stale_bindings() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let hostile_handle = "missing-binding-must-not-echo";

        // A key outside the closed set is refused as a parameter, before any
        // binding or snapshot is consulted.
        for forged in [
            "process.kill -9",
            "shell.rm-rf",
            "",
            "network.disconnect.now",
        ] {
            let params = serde_json::json!({
                "bindingHandle": hostile_handle,
                "snapshotHandle": "snapshot",
                "rowId": "row",
                "action": forged,
            });
            let refused = handle_frame(
                &state,
                &request("system-info.row.inspect", &params.to_string()),
            )
            .await;
            assert!(!refused.ok, "{forged:?} was not refused");
            assert_eq!(refused.error.as_ref().unwrap().code, "invalid-params");
            assert!(
                !serde_json::to_string(&refused)
                    .unwrap()
                    .contains(forged.trim())
                    || forged.is_empty()
            );
        }

        // A real key with no live binding behind it is a lost target, named
        // the same way every other target-bound capability names it.
        for (method, action) in [
            ("system-info.row.inspect", "process.open-files"),
            ("system-info.row.action.plan", "process.signal.kill"),
        ] {
            let params = serde_json::json!({
                "bindingHandle": hostile_handle,
                "snapshotHandle": "snapshot",
                "rowId": "row",
                "action": action,
            });
            let lost = handle_frame(&state, &request(method, &params.to_string())).await;
            assert!(!lost.ok);
            assert_eq!(
                lost.error.as_ref().unwrap().code,
                "system-info-binding-unavailable",
                "{method}: {}",
                serde_json::to_string(&lost).unwrap()
            );
            assert!(
                !serde_json::to_string(&lost)
                    .unwrap()
                    .contains(hostile_handle)
            );
        }
        let listing = serde_json::json!({
            "bindingHandle": hostile_handle,
            "snapshotHandle": "snapshot",
            "rowId": "row",
        });
        let lost = handle_frame(
            &state,
            &request("system-info.row.actions.list", &listing.to_string()),
        )
        .await;
        assert_eq!(
            lost.error.as_ref().unwrap().code,
            "system-info-binding-unavailable"
        );

        // Plan handles are only ever the sidecar's own, and a forged one with
        // no binding is refused without reaching the registry.
        let plan_params = serde_json::json!({
            "bindingHandle": hostile_handle,
            "planHandle": "forged-plan",
        });
        for method in [
            "system-info.row.action.confirm",
            "system-info.row.action.execute",
            "system-info.row.action.cancel",
        ] {
            let refused = handle_frame(&state, &request(method, &plan_params.to_string())).await;
            assert!(!refused.ok, "{method} accepted a forged plan");
            assert_eq!(
                refused.error.as_ref().unwrap().code,
                "system-info-binding-unavailable"
            );
        }

        // Extra fields are not tolerated: a command smuggled next to the
        // action is a malformed request, not an ignored one.
        let smuggled = serde_json::json!({
            "bindingHandle": hostile_handle,
            "snapshotHandle": "snapshot",
            "rowId": "row",
            "action": "process.open-files",
            "command": "id",
        });
        let refused = handle_frame(
            &state,
            &request("system-info.row.inspect", &smuggled.to_string()),
        )
        .await;
        assert_eq!(refused.error.as_ref().unwrap().code, "invalid-params");
    }

    #[tokio::test]
    async fn system_info_rpc_exposes_a_closed_catalog_and_rejects_stale_capabilities() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();

        let catalog = handle_frame(&state, &request("system-info.catalog.get", "{}")).await;
        assert!(catalog.ok);
        let catalog = catalog.result.unwrap();
        let tabs = catalog.as_array().unwrap();
        assert_eq!(tabs.len(), 25);
        assert_eq!(
            tabs.iter()
                .filter_map(|tab| tab["key"].as_str())
                .collect::<std::collections::HashSet<_>>()
                .len(),
            25
        );
        assert!(tabs.iter().all(|tab| {
            tab["columns"]
                .as_array()
                .is_some_and(|columns| !columns.is_empty())
        }));

        let hostile_handle = "missing-binding-must-not-echo";
        let summary_params = serde_json::json!({ "bindingHandle": hostile_handle });
        let summary = handle_frame(
            &state,
            &request("system-info.summary.get", &summary_params.to_string()),
        )
        .await;
        assert!(!summary.ok);
        // Named like every other target-bound capability, so the window can
        // recognise a lost target without knowing which feature asked.
        assert_eq!(
            summary.error.as_ref().unwrap().code,
            "system-info-binding-unavailable"
        );
        assert!(
            !serde_json::to_string(&summary)
                .unwrap()
                .contains(hostile_handle)
        );

        let hostile_collect = serde_json::json!({
            "bindingHandle": hostile_handle,
            "tab": "processes",
            "maximumRows": 100,
            "command": "id"
        });
        let rejected = handle_frame(
            &state,
            &request("system-info.table.collect", &hostile_collect.to_string()),
        )
        .await;
        assert!(!rejected.ok);
        assert_eq!(rejected.error.as_ref().unwrap().code, "invalid-params");
        assert!(
            !serde_json::to_string(&rejected)
                .unwrap()
                .contains(hostile_handle)
        );
    }

    #[tokio::test]
    async fn configuration_rpc_routes_catalog_draft_revision_copy_export_and_close() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();

        let catalog = handle_frame(&state, &request("config.catalog.get", "{}")).await;
        assert!(catalog.ok);
        let catalog = catalog.result.unwrap();
        let products = catalog["products"].as_array().unwrap();
        assert_eq!(products.len(), 9);
        assert_eq!(
            products
                .iter()
                .map(|product| product["features"].as_array().unwrap().len())
                .sum::<usize>(),
            137
        );
        assert!(products.iter().any(|product| product["key"] == "haproxy"));
        assert!(products.iter().any(|product| product["key"] == "mongodb"));

        let generated = handle_frame(
            &state,
            &request("config.quick.generate", r#"{"product":"nginx"}"#),
        )
        .await;
        assert!(generated.ok);
        let generated = generated.result.unwrap();
        assert_eq!(generated["product"], "nginx");
        assert_eq!(generated["revision"], 1);
        assert!(generated.get("contents").is_none());
        let handle = generated["handle"].as_str().unwrap().to_owned();
        let artifact_key = generated["artifacts"][0]["key"]
            .as_str()
            .unwrap()
            .to_owned();

        let revise_params = serde_json::json!({
            "handle": handle,
            "revision": 1,
            "input": { "product": "apache" }
        });
        let revised = handle_frame(
            &state,
            &request("config.quick.revise", &revise_params.to_string()),
        )
        .await;
        assert!(revised.ok);
        let revised = revised.result.unwrap();
        assert_eq!(revised["product"], "apache");
        assert_eq!(revised["revision"], 2);
        let revised_artifact_key = revised["artifacts"][0]["key"].as_str().unwrap().to_owned();

        let stale_copy = serde_json::json!({ "handle": handle, "revision": 1 });
        let stale = handle_frame(
            &state,
            &request("config.quick.copy", &stale_copy.to_string()),
        )
        .await;
        assert!(!stale.ok);
        assert_eq!(stale.error.as_ref().unwrap().code, "configuration-invalid");
        assert!(!serde_json::to_string(&stale).unwrap().contains(&handle));

        let current = serde_json::json!({ "handle": handle, "revision": 2 });
        let copied =
            handle_frame(&state, &request("config.quick.copy", &current.to_string())).await;
        assert!(copied.ok);
        let copied = copied.result.unwrap();
        assert_eq!(copied["revision"], 2);
        assert!(
            !copied["artifacts"][0]["contents"]
                .as_str()
                .unwrap()
                .is_empty()
        );

        let artifact_params = serde_json::json!({
            "handle": handle,
            "revision": 2,
            "artifactKey": revised_artifact_key
        });
        let artifact = handle_frame(
            &state,
            &request("config.quick.artifact", &artifact_params.to_string()),
        )
        .await;
        assert!(artifact.ok);
        let artifact = artifact.result.unwrap();
        assert!(!artifact["suggestedName"].as_str().unwrap().is_empty());
        assert!(!artifact["contents"].as_str().unwrap().is_empty());

        let closed =
            handle_frame(&state, &request("config.quick.close", &current.to_string())).await;
        assert!(closed.ok);
        assert_eq!(
            closed.result.unwrap(),
            serde_json::json!({ "closed": true })
        );

        let after_close =
            handle_frame(&state, &request("config.quick.copy", &current.to_string())).await;
        assert!(!after_close.ok);
        assert_eq!(
            after_close.error.as_ref().unwrap().code,
            "configuration-draft-not-found"
        );

        // The old artifact key cannot be used to smuggle an unknown parameter,
        // and exact serde DTOs must fail before touching the registry.
        let hostile = serde_json::json!({
            "handle": handle,
            "revision": 2,
            "artifactKey": artifact_key,
            "path": "C:/renderer-controlled-output"
        });
        let rejected = handle_frame(
            &state,
            &request("config.quick.artifact", &hostile.to_string()),
        )
        .await;
        assert!(!rejected.ok);
        assert_eq!(rejected.error.as_ref().unwrap().code, "invalid-params");
        assert!(
            !serde_json::to_string(&rejected)
                .unwrap()
                .contains("renderer-controlled-output")
        );
    }

    #[tokio::test]
    async fn config_bundle_export_writes_a_new_folder_and_names_an_existing_one() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let generated = handle_frame(
            &state,
            &request("config.quick.generate", r#"{"product":"tomcat"}"#),
        )
        .await;
        let draft = generated.result.unwrap();
        let parent = root.0.join("exports");
        std::fs::create_dir(&parent).unwrap();
        let params = serde_json::json!({
            "handle": draft["handle"],
            "revision": draft["revision"],
            "parentDirectory": parent,
        });
        let first = handle_frame(
            &state,
            &request("config.quick.bundle.export", &params.to_string()),
        )
        .await;
        assert!(first.ok, "{first:?}");
        assert_eq!(
            first.result.unwrap(),
            serde_json::json!({ "directoryName": "lovelyhawk-tomcat-new-empty-review-bundle", "fileCount": 3 })
        );
        let again = handle_frame(
            &state,
            &request("config.quick.bundle.export", &params.to_string()),
        )
        .await;
        assert_eq!(
            again.error.as_ref().unwrap().code,
            "configuration-destination-exists"
        );

        for hostile in [
            serde_json::json!({ "handle": draft["handle"], "revision": draft["revision"], "parentDirectory": "relative/folder" }),
            serde_json::json!({ "handle": draft["handle"], "revision": draft["revision"], "parentDirectory": parent, "artifactKey": "server.xml" }),
        ] {
            let rejected = handle_frame(
                &state,
                &request("config.quick.bundle.export", &hostile.to_string()),
            )
            .await;
            assert_eq!(rejected.error.as_ref().unwrap().code, "invalid-params");
        }
    }

    #[tokio::test]
    async fn security_reference_favorites_are_validated_by_the_core_store() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let invalid = request(
            "security-reference.set-favorites",
            r#"{"favoriteIds":["not-a-catalog-entry"]}"#,
        );
        let response = handle_frame(&state, &invalid).await;
        assert!(!response.ok);
        assert_eq!(response.error.unwrap().code, "favorites-save-failed");

        let valid = request(
            "security-reference.set-favorites",
            r#"{"favoriteIds":["py-sqli"]}"#,
        );
        let response = handle_frame(&state, &valid).await;
        assert!(response.ok);
        assert_eq!(response.result.unwrap()["favoriteIds"][0], "py-sqli");
    }

    #[tokio::test]
    async fn notes_delete_cancel_rpc_consumes_the_opaque_plan_without_side_effects() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let created = handle_frame(
            &state,
            &request(
                "notes.create",
                r#"{"mutationId":"mutation-create-0001","title":"Keep","content":"evidence","tags":[]}"#,
            ),
        )
        .await;
        assert!(created.ok);
        let created = created.result.unwrap();
        let note_id = created["id"].as_str().unwrap().to_owned();
        let revision = created["revision"].as_str().unwrap();
        let plan_params = format!(
            r#"{{"id":"{note_id}","expectedRevision":"{revision}","mutationId":"mutation-plan-000001"}}"#
        );
        let planned = handle_frame(&state, &request("notes.delete.plan", &plan_params)).await;
        assert!(planned.ok);
        let handle = planned.result.unwrap()["handle"]
            .as_str()
            .unwrap()
            .to_owned();
        let handle_params =
            format!(r#"{{"handle":"{handle}","mutationId":"mutation-cancel-0001"}}"#);

        let cancelled = handle_frame(&state, &request("notes.delete.cancel", &handle_params)).await;
        assert!(cancelled.ok);
        assert_eq!(cancelled.result.unwrap()["cancelled"], true);

        let confirmation_params =
            format!(r#"{{"handle":"{handle}","mutationId":"mutation-confirm-001"}}"#);
        let confirmation = handle_frame(
            &state,
            &request("notes.delete.confirm", &confirmation_params),
        )
        .await;
        assert!(!confirmation.ok);
        assert_eq!(
            confirmation.error.as_ref().unwrap().code,
            "delete-plan-invalid"
        );
        let get_params = format!(r#"{{"id":"{note_id}"}}"#);
        let loaded = handle_frame(&state, &request("notes.get", &get_params)).await;
        assert!(loaded.ok);
        assert_eq!(loaded.result.unwrap()["id"], note_id);
        assert!(
            state
                .services
                .operation_journal()
                .entries()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn notes_create_replay_is_single_write_and_survives_sidecar_restart() {
        let root = TestRoot::new();
        let params = r#"{"mutationId":"mutation-create-replay","title":"Once","content":"evidence","tags":[]}"#;
        let note_id = {
            let state = BackendState::open(root.0.clone()).unwrap();
            let first = handle_frame(&state, &request("notes.create", params)).await;
            let replay = handle_frame(&state, &request("notes.create", params)).await;
            assert!(first.ok && replay.ok);
            assert_eq!(first.result.as_ref(), replay.result.as_ref());
            let listed = handle_frame(
                &state,
                &request("notes.list", r#"{"query":"","offset":0,"limit":100}"#),
            )
            .await;
            assert_eq!(listed.result.unwrap()["total"], 1);
            first.result.unwrap()["id"].as_str().unwrap().to_owned()
        };

        let reopened = BackendState::open(root.0.clone()).unwrap();
        let replayed = handle_frame(&reopened, &request("notes.create", params)).await;
        assert!(replayed.ok);
        assert_eq!(replayed.result.as_ref().unwrap()["id"], note_id);
        let revision = replayed.result.as_ref().unwrap()["revision"]
            .as_str()
            .unwrap()
            .to_owned();
        let get_params = format!(r#"{{"id":"{note_id}"}}"#);
        let loaded = handle_frame(&reopened, &request("notes.get", &get_params)).await;
        assert!(loaded.ok);
        assert_eq!(loaded.result.unwrap()["title"], "Once");
        let listed = handle_frame(
            &reopened,
            &request("notes.list", r#"{"query":"","offset":0,"limit":100}"#),
        )
        .await;
        assert_eq!(listed.result.unwrap()["total"], 1);
        let conflict = handle_frame(
            &reopened,
            &request(
                "notes.create",
                r#"{"mutationId":"mutation-create-replay","title":"Different","content":"evidence","tags":[]}"#,
            ),
        )
        .await;
        assert!(!conflict.ok);

        let planned = handle_frame(
            &reopened,
            &request(
                "notes.delete.plan",
                &format!(r#"{{"id":"{note_id}","expectedRevision":"{revision}","mutationId":"mutation-plan-replay01"}}"#),
            ),
        )
        .await
        .result
        .unwrap();
        let handle = planned["handle"].as_str().unwrap();
        let deleted = handle_frame(
            &reopened,
            &request(
                "notes.delete.confirm",
                &format!(r#"{{"handle":"{handle}","mutationId":"mutation-confirm-replay"}}"#),
            ),
        )
        .await;
        assert!(deleted.ok);
        let empty = handle_frame(
            &reopened,
            &request("notes.list", r#"{"query":"","offset":0,"limit":100}"#),
        )
        .await;
        assert_eq!(empty.result.unwrap()["total"], 0);
    }

    #[tokio::test]
    async fn note_replay_waits_for_one_in_flight_operation_and_rejects_key_reuse() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let params = serde_json::json!({"mutationId": "mutation-inflight-001", "value": 1});
        let first_calls = calls.clone();
        let second_calls = calls.clone();
        let first = state.replay_note_mutation(
            "notes.test",
            "mutation-inflight-001",
            &params,
            || async move {
                first_calls.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                Ok(to_value(serde_json::json!({"done": true})))
            },
        );
        let second = state.replay_note_mutation(
            "notes.test",
            "mutation-inflight-001",
            &params,
            || async move {
                second_calls.fetch_add(1, Ordering::SeqCst);
                Ok(to_value(serde_json::json!({"done": false})))
            },
        );
        let (first, second) = tokio::join!(first, second);
        assert_eq!(first.unwrap().unwrap(), second.unwrap().unwrap());
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let conflict = state
            .replay_note_mutation(
                "notes.test",
                "mutation-inflight-001",
                &serde_json::json!({"mutationId": "mutation-inflight-001", "value": 2}),
                || async { Ok(to_value(serde_json::json!({"done": false}))) },
            )
            .await
            .unwrap_err();
        assert_eq!(conflict.code, "notes-idempotency-conflict");
    }

    #[tokio::test]
    async fn stale_note_revisions_and_delete_plans_fail_closed() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let created = handle_frame(
            &state,
            &request(
                "notes.create",
                r#"{"mutationId":"mutation-create-stale","title":"Before","content":"evidence","tags":[]}"#,
            ),
        )
        .await
        .result
        .unwrap();
        let id = created["id"].as_str().unwrap();
        let old_revision = created["revision"].as_str().unwrap();
        let plan_params = format!(
            r#"{{"id":"{id}","expectedRevision":"{old_revision}","mutationId":"mutation-plan-stale01"}}"#
        );
        let plan = handle_frame(&state, &request("notes.delete.plan", &plan_params))
            .await
            .result
            .unwrap();
        let handle = plan["handle"].as_str().unwrap();
        let update_params = format!(
            r#"{{"id":"{id}","expectedRevision":"{old_revision}","mutationId":"mutation-update-stale","title":"After"}}"#
        );
        let updated = handle_frame(&state, &request("notes.update", &update_params)).await;
        assert!(updated.ok);

        let stale_update = handle_frame(
            &state,
            &request(
                "notes.update",
                &format!(r#"{{"id":"{id}","expectedRevision":"{old_revision}","mutationId":"mutation-update-stale2","content":"late"}}"#),
            ),
        )
        .await;
        assert_eq!(stale_update.error.unwrap().code, "notes-revision-conflict");

        let stale_delete = handle_frame(
            &state,
            &request(
                "notes.delete.confirm",
                &format!(r#"{{"handle":"{handle}","mutationId":"mutation-confirm-stale"}}"#),
            ),
        )
        .await;
        assert_eq!(stale_delete.error.unwrap().code, "notes-revision-conflict");
        let loaded = handle_frame(
            &state,
            &request("notes.get", &format!(r#"{{"id":"{id}"}}"#)),
        )
        .await;
        assert_eq!(loaded.result.unwrap()["title"], "After");
    }

    #[tokio::test]
    async fn frame_reader_bounds_attacker_controlled_lines_and_recovers_at_newline() {
        let mut bytes = vec![b'x'; MAX_REQUEST_BYTES + 1];
        bytes.extend_from_slice(b"\n{}\r\n");
        let mut reader = BufReader::new(bytes.as_slice());
        assert_eq!(read_frame(&mut reader).await.unwrap(), FrameRead::TooLarge);
        assert_eq!(
            read_frame(&mut reader).await.unwrap(),
            FrameRead::Data(b"{}".to_vec().into())
        );
        assert_eq!(read_frame(&mut reader).await.unwrap(), FrameRead::Eof);
    }

    #[test]
    fn request_frame_drop_and_debug_contracts_protect_raw_parameters() {
        fn assert_zeroizes_on_drop<T: ZeroizeOnDrop>() {}

        assert_zeroizes_on_drop::<RequestFrame>();
        let mut frame = RequestFrame::from(b"raw-secret-parameter".to_vec());
        let debug = format!("{frame:?}");
        assert!(debug.contains("len"));
        assert!(!debug.contains("raw-secret-parameter"));
        frame.wipe();
        assert!(frame.as_bytes().is_empty());

        let request: RpcRequest = serde_json::from_slice(&request(
            "connections.create",
            r#"{"password":{"action":"replace","value":"parsed-secret-parameter"}}"#,
        ))
        .unwrap();
        let debug = format!("{request:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("parsed-secret-parameter"));
    }

    #[test]
    fn archive_root_cli_requires_one_explicit_absolute_path() {
        let absolute = std::env::temp_dir().join("lovelyres-archive");
        assert_eq!(
            parse_archive_root([
                OsString::from("--archive-root"),
                absolute.clone().into_os_string()
            ])
            .unwrap(),
            absolute
        );
        assert!(parse_archive_root(Vec::<OsString>::new()).is_err());
        assert!(
            parse_archive_root([OsString::from("--archive-root"), OsString::from("relative")])
                .is_err()
        );
        assert!(
            parse_archive_root([
                OsString::from("--archive-root"),
                std::env::temp_dir().into_os_string(),
                OsString::from("extra")
            ])
            .is_err()
        );
    }
}
