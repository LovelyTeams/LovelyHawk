#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
//! Bounded, typed process boundary between Electron and `lovelyres-core`.

mod ai_history_api;
mod baseline_read_api;
mod check_audit_read_api;
mod command_history_api;
mod config_api;
mod connections_api;
mod diagnostic_log_api;
mod disposal_report_api;
mod docker_read_api;
mod emergency_command_api;
mod emergency_path_api;
mod firewall_read_api;
mod integrity_api;
mod kubernetes_read_api;
mod log_analysis_read_api;
mod middleware_read_api;
mod notes_api;
mod packet_capture_live_api;
mod settings_api;
mod sftp_browser_api;
mod snapshot_read_api;
mod ssh_api;
mod system_info_api;
mod terminal_api;

use std::{
    collections::HashMap,
    ffi::OsString,
    fmt,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use lovelyres_core::{BackendServices, CoreError, CoreResult, PortableStore, report::ReportFormat};
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
    ai_history_api::{AiHistoryApi, AiHistoryApiError, AiHistoryExportFormat},
    baseline_read_api::{BaselineReadApi, BaselineReadApiError},
    check_audit_read_api::{
        CheckAuditCatalogInput, CheckAuditLogInput, CheckAuditReadApi, CheckAuditReadApiError,
    },
    command_history_api::{CommandHistoryApi, CommandHistoryApiError},
    config_api::{ConfigApi, ConfigGenerateInput, config_catalog},
    connections_api::{ConnectionWriteInput, ConnectionsApi},
    diagnostic_log_api::{DiagnosticLogApi, DiagnosticLogApiError, DiagnosticLogFilterInput},
    disposal_report_api::{DisposalReportApi, DisposalReportApiError, DisposalReportPreviewFormat},
    docker_read_api::{DockerReadApi, DockerReadApiError},
    emergency_command_api::{EmergencyCommandApi, EmergencyCommandApiError},
    emergency_path_api::{EmergencyPathAction, EmergencyPathApiError},
    firewall_read_api::{FirewallReadApi, FirewallReadApiError},
    integrity_api::{IntegrityApi, IntegrityApiError},
    kubernetes_read_api::{KubernetesListInput, KubernetesReadApi, KubernetesReadApiError},
    log_analysis_read_api::{
        LogAnalysisReadApi, LogAnalysisReadApiError, LogCorrelationInput, LogIocSearchInput,
        LogSourceReadInput,
    },
    middleware_read_api::{MiddlewareReadApi, MiddlewareReadApiError},
    notes_api::{NotesApi, NotesApiError},
    packet_capture_live_api::{
        PacketCaptureLiveApi, PacketCaptureLiveApiError, PacketCaptureStartInput,
    },
    settings_api::{
        SettingsAiApiKeyReplacementInput, SettingsApi, SettingsApiError, SettingsSaveInput,
    },
    sftp_browser_api::{SftpBrowserApi, SftpBrowserApiError, SftpOperationRequest},
    snapshot_read_api::{SnapshotDiffInput, SnapshotReadApi, SnapshotReadApiError},
    ssh_api::{SecretResponses, SshApi},
    system_info_api::{SystemInfoApi, SystemInfoApiError},
    terminal_api::{TerminalApi, TerminalApiError},
};

pub const PROTOCOL_VERSION: &str = "lovelyres-backend/v1";
// A maximal typed note can expand when JSON escapes control characters. The
// process boundary remains hard-bounded while still accepting every value the
// core notes contract permits.
pub const MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_REQUEST_ID_BYTES: usize = 128;
const MAX_NOTE_REPLAYS: usize = 256;
const NOTE_REPLAY_TTL: Duration = Duration::from_secs(10 * 60);

#[derive(Debug)]
pub struct BackendState {
    services: BackendServices,
    ai_history: AiHistoryApi,
    baseline_read: BaselineReadApi,
    check_audit_read: CheckAuditReadApi,
    command_history: CommandHistoryApi,
    config: ConfigApi,
    connections: ConnectionsApi,
    disposal_report: DisposalReportApi,
    diagnostic_log: DiagnosticLogApi,
    docker_read: DockerReadApi,
    emergency_command: EmergencyCommandApi,
    sftp_browser: SftpBrowserApi,
    firewall_read: FirewallReadApi,
    integrity: Arc<IntegrityApi>,
    kubernetes_read: KubernetesReadApi,
    log_analysis_read: LogAnalysisReadApi,
    middleware_read: MiddlewareReadApi,
    notes: NotesApi,
    note_replays: parking_lot::Mutex<HashMap<String, NoteReplayEntry>>,
    packet_capture_live: PacketCaptureLiveApi,
    ssh: Arc<SshApi>,
    settings: SettingsApi,
    snapshot_read: SnapshotReadApi,
    system_info: SystemInfoApi,
    terminal: TerminalApi,
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
                    message: "the static catalog exceeds its bounded Electron projection"
                        .to_owned(),
                }
            })?;
        let check_audit_read = CheckAuditReadApi::new(services.clone(), Arc::clone(&ssh));
        let command_history = CommandHistoryApi::new(services.clone(), Arc::clone(&ssh));
        let disposal_report = DisposalReportApi::new(services.clone(), Arc::clone(&ssh));
        let diagnostic_log = DiagnosticLogApi::new(diagnostic_capture);
        let docker_read = DockerReadApi::new(services.clone(), Arc::clone(&ssh));
        let emergency_command = EmergencyCommandApi::new(services.clone(), Arc::clone(&ssh));
        let sftp_browser = SftpBrowserApi::new(services.clone(), Arc::clone(&ssh));
        let firewall_read = FirewallReadApi::new(services.clone(), Arc::clone(&ssh));
        let integrity = Arc::new(IntegrityApi::new(services.clone(), Arc::clone(&ssh)));
        let kubernetes_read = KubernetesReadApi::new(services.clone(), Arc::clone(&ssh));
        let log_analysis_read = LogAnalysisReadApi::new(services.clone(), Arc::clone(&ssh));
        let middleware_read = MiddlewareReadApi::new(services.clone(), Arc::clone(&ssh));
        let packet_capture_live = PacketCaptureLiveApi::new(services.clone(), Arc::clone(&ssh));
        let settings = SettingsApi::new(&services);
        let snapshot_read = SnapshotReadApi::new(services.clone(), Arc::clone(&ssh));
        let system_info = SystemInfoApi::new(services.clone(), Arc::clone(&ssh));
        let terminal = TerminalApi::new(services.clone(), Arc::clone(&ssh));
        Ok(Self {
            services,
            ai_history: AiHistoryApi::default(),
            baseline_read,
            check_audit_read,
            command_history,
            config: ConfigApi::default(),
            connections,
            disposal_report,
            diagnostic_log,
            docker_read,
            emergency_command,
            sftp_browser,
            firewall_read,
            integrity,
            kubernetes_read,
            log_analysis_read,
            middleware_read,
            notes: NotesApi::default(),
            note_replays: parking_lot::Mutex::new(HashMap::new()),
            packet_capture_live,
            ssh,
            settings,
            snapshot_read,
            system_info,
            terminal,
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
                            self.snapshot_read.close_binding(&params.binding_handle);
                            self.firewall_read.close_binding(&params.binding_handle);
                            self.baseline_read.close_binding(&params.binding_handle);
                            self.middleware_read.close_binding(&params.binding_handle);
                            self.check_audit_read.close_binding(&params.binding_handle);
                            self.integrity.close_binding(&params.binding_handle);
                            self.log_analysis_read.close_binding(&params.binding_handle);
                            self.kubernetes_read.close_binding(&params.binding_handle);
                            self.emergency_command.close_binding(&params.binding_handle);
                            self.docker_read.close_binding(&params.binding_handle);
                            self.sftp_browser.close_binding(&params.binding_handle);
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
            RpcMethod::SnapshotList => parse_params::<SnapshotBindingParams>(request.params)
                .and_then(|params| {
                    self.snapshot_read
                        .list_snapshots(&params.binding_handle)
                        .map(to_value)
                        .map_err(snapshot_read_failure)
                }),
            RpcMethod::SnapshotDetailGet => parse_params::<SnapshotDetailParams>(request.params)
                .and_then(|params| {
                    self.snapshot_read
                        .get_detail(&params.binding_handle, &params.snapshot_handle)
                        .map(to_value)
                        .map_err(snapshot_read_failure)
                }),
            RpcMethod::SnapshotForensicDiff => parse_params::<SnapshotDiffParams>(request.params)
                .and_then(|params| {
                    self.snapshot_read
                        .diff_forensic(&params.binding_handle, params.input)
                        .map(to_value)
                        .map_err(snapshot_read_failure)
                }),
            RpcMethod::FirewallInspect => {
                match parse_params::<FirewallBindingParams>(request.params) {
                    Ok(params) => self
                        .firewall_read
                        .inspect(&params.binding_handle)
                        .await
                        .map(to_value)
                        .map_err(firewall_read_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::FirewallChangeHistoryList => {
                match parse_params::<FirewallBindingParams>(request.params) {
                    Ok(params) => self
                        .firewall_read
                        .list_history(&params.binding_handle)
                        .await
                        .map(to_value)
                        .map_err(firewall_read_failure),
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
            RpcMethod::MiddlewareDiscover => {
                match parse_params::<MiddlewareBindingParams>(request.params) {
                    Ok(params) => self
                        .middleware_read
                        .discover(&params.binding_handle)
                        .await
                        .map(to_value)
                        .map_err(middleware_read_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::MiddlewareConfigurationLoad => {
                match parse_params::<MiddlewareConfigurationParams>(request.params) {
                    Ok(params) => self
                        .middleware_read
                        .load_configuration(
                            &params.binding_handle,
                            &params.discovery_handle,
                            &params.instance_handle,
                        )
                        .await
                        .map(to_value)
                        .map_err(middleware_read_failure),
                    Err(failure) => Err(failure),
                }
            }
            RpcMethod::MiddlewareHistoryList => {
                match parse_params::<MiddlewareBindingParams>(request.params) {
                    Ok(params) => self
                        .middleware_read
                        .list_history(&params.binding_handle)
                        .await
                        .map(to_value)
                        .map_err(middleware_read_failure),
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
                match parse_params::<KubernetesRowParams>(request.params) {
                    Ok(params) => self
                        .kubernetes_read
                        .pod_logs(
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
                        )
                        .await
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

    fn bootstrap(&self) -> Result<BootstrapResult, RpcFailure> {
        let settings = self.services.settings().load().map_err(|error| {
            RpcFailure::core(
                "load settings for bootstrap",
                "bootstrap-failed",
                "LovelyRes could not load its portable settings.",
                error,
            )
        })?;
        Ok(BootstrapResult {
            product_name: "LovelyRes",
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
                    "LovelyRes could not save the security-reference favorites.",
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
    #[serde(rename = "snapshot.list")]
    SnapshotList,
    #[serde(rename = "snapshot.detail.get")]
    SnapshotDetailGet,
    #[serde(rename = "snapshot.forensic.diff")]
    SnapshotForensicDiff,
    #[serde(rename = "firewall.inspect")]
    FirewallInspect,
    #[serde(rename = "firewall.change-history.list")]
    FirewallChangeHistoryList,
    #[serde(rename = "baseline.catalog.get")]
    BaselineCatalogGet,
    #[serde(rename = "baseline.scan")]
    BaselineScan,
    #[serde(rename = "baseline.history.list")]
    BaselineHistoryList,
    #[serde(rename = "baseline.file.read")]
    BaselineFileRead,
    #[serde(rename = "middleware.discover")]
    MiddlewareDiscover,
    #[serde(rename = "middleware.configuration.load")]
    MiddlewareConfigurationLoad,
    #[serde(rename = "middleware.history.list")]
    MiddlewareHistoryList,
    #[serde(rename = "check-audit.catalog.get")]
    CheckAuditCatalogGet,
    #[serde(rename = "check-audit.status.collect")]
    CheckAuditStatusCollect,
    #[serde(rename = "check-audit.log.read")]
    CheckAuditLogRead,
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
    #[serde(rename = "emergency-command.catalog.load")]
    EmergencyCommandCatalogLoad,
    #[serde(rename = "emergency-command.run")]
    EmergencyCommandRun,
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
    #[serde(rename = "config.quick.artifact")]
    ConfigQuickArtifact,
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
struct SnapshotBindingParams {
    binding_handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SnapshotDetailParams {
    binding_handle: String,
    snapshot_handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SnapshotDiffParams {
    binding_handle: String,
    input: SnapshotDiffInput,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FirewallBindingParams {
    binding_handle: String,
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
struct MiddlewareBindingParams {
    binding_handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MiddlewareConfigurationParams {
    binding_handle: String,
    discovery_handle: String,
    instance_handle: String,
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EmergencyCommandBindingParams {
    binding_handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EmergencyCommandRunParams {
    binding_handle: String,
    snapshot_handle: String,
    command_handle: String,
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SftpBrowserStageParams {
    binding_handle: String,
    /// Chosen by the operator in the native open dialog and forwarded by main.
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
                    "LovelyRes could not complete the notes operation.",
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
        _ => (
            "connections-operation-failed",
            "LovelyRes could not complete the connection operation.",
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
            "LovelyRes could not complete the SSH controller operation.",
        ),
    };
    RpcFailure::core("run SSH controller operation", code, public_message, error)
}

fn terminal_failure(error: TerminalApiError) -> RpcFailure {
    match error {
        TerminalApiError::Core(source) => RpcFailure::core(
            "run target-bound terminal operation",
            "terminal-operation-failed",
            "LovelyRes could not complete the terminal operation.",
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
            public_message: "LovelyRes could not complete the terminal operation.",
            source: None,
        },
        TerminalApiError::OutputLimit
        | TerminalApiError::SnapshotLimit
        | TerminalApiError::SearchLimit
        | TerminalApiError::ProtocolViolation => RpcFailure {
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
            "LovelyRes could not complete the configuration operation.",
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
            "LovelyRes could not complete the system-information operation.",
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
        SystemInfoApiError::InvalidSnapshot
        | SystemInfoApiError::InvalidRow
        | SystemInfoApiError::DetailUnavailable => RpcFailure {
            operation: "validate system-information snapshot row",
            code: "system-info-snapshot-invalid",
            public_message: "The system-information snapshot or row is missing or stale.",
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
            public_message: "LovelyRes could not complete the system-information operation.",
            source: None,
        },
    }
}

fn snapshot_read_failure(error: SnapshotReadApiError) -> RpcFailure {
    match error {
        SnapshotReadApiError::Core | SnapshotReadApiError::RegistryUnavailable => RpcFailure {
            operation: "run bounded snapshot investigation",
            code: "snapshot-operation-failed",
            public_message: "LovelyRes could not complete the snapshot investigation.",
            source: None,
        },
        SnapshotReadApiError::BindingUnavailable => RpcFailure {
            operation: "validate snapshot SSH binding",
            code: "snapshot-binding-unavailable",
            public_message: "The snapshot target binding is missing or stale.",
            source: None,
        },
        SnapshotReadApiError::InvalidHandle | SnapshotReadApiError::InvalidInput => RpcFailure {
            operation: "validate snapshot request",
            code: "invalid-params",
            public_message: "The snapshot request parameters are invalid.",
            source: None,
        },
        SnapshotReadApiError::InvalidSnapshot | SnapshotReadApiError::SnapshotStale => RpcFailure {
            operation: "validate snapshot capability",
            code: "snapshot-unavailable",
            public_message: "The snapshot capability is missing, expired, or stale.",
            source: None,
        },
        SnapshotReadApiError::Capacity => RpcFailure {
            operation: "bound snapshot investigation",
            code: "snapshot-capacity",
            public_message: "The bounded snapshot investigation capacity has been reached.",
            source: None,
        },
    }
}

fn firewall_read_failure(error: FirewallReadApiError) -> RpcFailure {
    match error {
        FirewallReadApiError::Core | FirewallReadApiError::RegistryUnavailable => RpcFailure {
            operation: "run bounded firewall investigation",
            code: "firewall-operation-failed",
            public_message: "LovelyRes could not complete the firewall investigation.",
            source: None,
        },
        FirewallReadApiError::BindingUnavailable => RpcFailure {
            operation: "validate firewall SSH binding",
            code: "firewall-binding-unavailable",
            public_message: "The firewall target binding is missing or stale.",
            source: None,
        },
        FirewallReadApiError::InvalidHandle => RpcFailure {
            operation: "validate firewall request",
            code: "invalid-params",
            public_message: "The firewall request parameters are invalid.",
            source: None,
        },
        FirewallReadApiError::RegistryCapacity | FirewallReadApiError::ConcurrencyLimit => {
            RpcFailure {
                operation: "bound firewall investigation",
                code: "firewall-capacity",
                public_message: "The bounded firewall investigation capacity has been reached.",
                source: None,
            }
        }
        FirewallReadApiError::OutputLimit => RpcFailure {
            operation: "bound firewall investigation output",
            code: "firewall-output-limit",
            public_message: "The firewall investigation result exceeds its safety limit.",
            source: None,
        },
    }
}

fn baseline_read_failure(error: BaselineReadApiError) -> RpcFailure {
    match error {
        BaselineReadApiError::Core | BaselineReadApiError::RegistryUnavailable => RpcFailure {
            operation: "run bounded baseline investigation",
            code: "baseline-operation-failed",
            public_message: "LovelyRes could not complete the baseline investigation.",
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

fn middleware_read_failure(error: MiddlewareReadApiError) -> RpcFailure {
    match error {
        MiddlewareReadApiError::Core | MiddlewareReadApiError::RegistryUnavailable => RpcFailure {
            operation: "run bounded middleware investigation",
            code: "middleware-operation-failed",
            public_message: "LovelyRes could not complete the middleware investigation.",
            source: None,
        },
        MiddlewareReadApiError::BindingUnavailable => RpcFailure {
            operation: "validate middleware SSH binding",
            code: "middleware-binding-unavailable",
            public_message: "The middleware target binding is missing or stale.",
            source: None,
        },
        MiddlewareReadApiError::InvalidHandle
        | MiddlewareReadApiError::InvalidSnapshot
        | MiddlewareReadApiError::SnapshotStale => RpcFailure {
            operation: "validate middleware request",
            code: "invalid-params",
            public_message: "The middleware request parameters are invalid or stale.",
            source: None,
        },
        MiddlewareReadApiError::InvalidData => RpcFailure {
            operation: "validate middleware investigation output",
            code: "middleware-output-invalid",
            public_message: "The middleware investigation result is invalid.",
            source: None,
        },
        MiddlewareReadApiError::OutputLimit => RpcFailure {
            operation: "bound middleware investigation output",
            code: "middleware-output-limit",
            public_message: "The middleware investigation result exceeds its safety limit.",
            source: None,
        },
        MiddlewareReadApiError::ConcurrencyLimit => RpcFailure {
            operation: "bound middleware investigation",
            code: "middleware-capacity",
            public_message: "The bounded middleware investigation capacity has been reached.",
            source: None,
        },
    }
}

fn check_audit_read_failure(error: CheckAuditReadApiError) -> RpcFailure {
    match error {
        CheckAuditReadApiError::Core | CheckAuditReadApiError::RegistryUnavailable => RpcFailure {
            operation: "run bounded command-audit investigation",
            code: "check-audit-operation-failed",
            public_message: "LovelyRes could not complete the command-audit investigation.",
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

fn log_analysis_read_failure(error: LogAnalysisReadApiError) -> RpcFailure {
    match error {
        LogAnalysisReadApiError::Core | LogAnalysisReadApiError::RegistryUnavailable => {
            RpcFailure {
                operation: "run bounded log investigation",
                code: "log-analysis-operation-failed",
                public_message: "LovelyRes could not complete the log investigation.",
                source: None,
            }
        }
        LogAnalysisReadApiError::BindingUnavailable => RpcFailure {
            operation: "validate log investigation SSH binding",
            code: "log-analysis-binding-unavailable",
            public_message: "The log investigation target binding is missing or stale.",
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

fn kubernetes_read_failure(error: KubernetesReadApiError) -> RpcFailure {
    match error {
        KubernetesReadApiError::Core(_) | KubernetesReadApiError::RegistryUnavailable => {
            RpcFailure {
                operation: "run bounded Kubernetes read investigation",
                code: "kubernetes-operation-failed",
                public_message: "LovelyRes could not complete the Kubernetes read operation.",
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
        KubernetesReadApiError::Capacity | KubernetesReadApiError::ConcurrencyLimit => RpcFailure {
            operation: "bound Kubernetes read investigation",
            code: "kubernetes-capacity",
            public_message: "The bounded Kubernetes read capacity has been reached.",
            source: None,
        },
    }
}

fn docker_read_failure(error: DockerReadApiError) -> RpcFailure {
    match error {
        DockerReadApiError::Core | DockerReadApiError::RegistryUnavailable => RpcFailure {
            operation: "run bounded Docker read investigation",
            code: "docker-operation-failed",
            public_message: "LovelyRes could not complete the Docker read operation.",
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
            public_message: "LovelyRes could not complete the SFTP browser operation.",
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
        SftpBrowserApiError::Deadline => RpcFailure {
            operation: "bound SFTP browser deadline",
            code: "sftp-browser-timeout",
            public_message: "The SFTP browser operation exceeded its deadline.",
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
                public_message: "LovelyRes could not complete the emergency command operation.",
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
            public_message: "LovelyRes could not act on that path.",
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
                public_message: "LovelyRes could not complete the live packet capture operation.",
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
        PacketCaptureLiveApiError::CaptureAlreadyActive
        | PacketCaptureLiveApiError::RegistryCapacity
        | PacketCaptureLiveApiError::ConcurrencyLimit => RpcFailure {
            operation: "bound live packet capture operation",
            code: "packet-capture-capacity",
            public_message: "The bounded live packet capture capacity has been reached.",
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
            "LovelyRes could not complete the file-integrity operation.",
            source,
        ),
        IntegrityApiError::RegistryUnavailable => RpcFailure {
            operation: "access file-integrity registry",
            code: "integrity-operation-failed",
            public_message: "LovelyRes could not complete the file-integrity operation.",
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
            "LovelyRes could not complete the settings operation.",
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
            "LovelyRes could not complete the AI history operation.",
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
            "LovelyRes could not complete the command history operation.",
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
            "LovelyRes could not complete the disposal report operation.",
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
    Response,
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
    use PageGroup::{Intelligence, Investigation, Operations, Response, Target, Triage};

    vec![
        PageDescriptor {
            id: "system-info",
            group: Target,
            title: "主机全景",
            icon: "◎",
            capability: ConnectedTarget,
            summary: "汇总远端主机运行状态与关键资源。",
            primary_action: "刷新主机信息",
            sections: &["系统概况", "CPU 与内存", "磁盘与网络"],
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
            sections: &["容器", "镜像", "网络"],
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
            sections: &["工作负载", "事件", "资源"],
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
            summary: "以计划、确认和审计方式执行应急动作。",
            primary_action: "创建命令计划",
            sections: &["命令工作台", "执行结果", "回滚"],
            migration_state: Pending,
        },
        PageDescriptor {
            id: "log-analysis",
            group: Investigation,
            title: "日志分析",
            icon: "≡",
            capability: ConnectedTarget,
            summary: "采集、筛选并关联分析远端日志。",
            primary_action: "选择日志",
            sections: &["数据源", "时间线", "规则命中"],
            migration_state: Pending,
        },
        PageDescriptor {
            id: "packet-capture",
            group: Investigation,
            title: "网络抓包",
            icon: "⌁",
            capability: ConnectedTarget,
            summary: "受控抓包、流量查看与证据导出。",
            primary_action: "配置抓包",
            sections: &["接口", "实时数据", "证据"],
            migration_state: Pending,
        },
        PageDescriptor {
            id: "check-audit",
            group: Investigation,
            title: "核查审计",
            icon: "✓",
            capability: ConnectedTarget,
            summary: "核查账号、服务、网络与安全配置。",
            primary_action: "开始核查",
            sections: &["核查项", "发现", "建议"],
            migration_state: Pending,
        },
        PageDescriptor {
            id: "integrity",
            group: Investigation,
            title: "文件完整性",
            icon: "◆",
            capability: ConnectedTarget,
            summary: "列出并比较已有文件完整性基线。",
            primary_action: "刷新已有基线",
            sections: &["固定目录", "已有基线", "比较结果"],
            migration_state: Pending,
        },
        PageDescriptor {
            id: "notes",
            group: Investigation,
            title: "Notes",
            icon: "✎",
            capability: LocalWorkspace,
            summary: "记录并整理目标调查笔记。",
            primary_action: "新建笔记",
            sections: &["笔记列表", "编辑器", "附件索引"],
            migration_state: Pending,
        },
        PageDescriptor {
            id: "firewall",
            group: Response,
            title: "边界隔离",
            icon: "⛨",
            capability: ConnectedTarget,
            summary: "审阅并计划边界隔离与恢复。",
            primary_action: "创建隔离计划",
            sections: &["当前规则", "隔离计划", "恢复记录"],
            migration_state: Pending,
        },
        PageDescriptor {
            id: "snapshot",
            group: Response,
            title: "取证快照",
            icon: "◉",
            capability: ConnectedTarget,
            summary: "只读查看便携索引中的目录与取证快照。",
            primary_action: "查看快照",
            sections: &["目录索引", "取证字段", "只读差异"],
            migration_state: Pending,
        },
        PageDescriptor {
            id: "database",
            group: Operations,
            title: "数据库",
            icon: "▤",
            capability: ConnectedTarget,
            summary: "连接数据库并安全执行查询与巡检。",
            primary_action: "选择连接",
            sections: &["连接", "查询", "历史"],
            migration_state: Pending,
        },
        PageDescriptor {
            id: "middleware",
            group: Operations,
            title: "中间件",
            icon: "⚙",
            capability: ConnectedTarget,
            summary: "无损查看、校验、应用并恢复常见中间件配置。",
            primary_action: "扫描中间件",
            sections: &["实例与健康", "完整配置", "变更与恢复"],
            migration_state: Pending,
        },
        PageDescriptor {
            id: "java-hot-update",
            group: Operations,
            title: "Java 热更新",
            icon: "♨",
            capability: ConnectedTarget,
            summary: "分析并执行受控 Java 热更新。",
            primary_action: "选择进程",
            sections: &["JVM", "类与方法", "部署记录"],
            migration_state: Pending,
        },
        PageDescriptor {
            id: "batch-servers",
            group: Operations,
            title: "多机批量",
            icon: "▦",
            capability: ConnectedTarget,
            summary: "对多个目标计划和执行一致的任务。",
            primary_action: "创建批量任务",
            sections: &["目标", "任务模板", "结果"],
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
            "The Electron application and Rust backend use different protocol versions.",
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
    use lovelyres_core::investigation::AddAiHistory;
    use tracing_subscriber::prelude::*;
    use uuid::Uuid;

    #[derive(Debug)]
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("lovelyres-electron-backend-{}", Uuid::new_v4()));
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

    #[tokio::test]
    async fn bootstrap_exposes_the_complete_page_registry_and_no_data_path() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let response = handle_frame(&state, &request("app.bootstrap", "{}")).await;
        assert!(response.ok);
        let result = response.result.unwrap();
        assert_eq!(result["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(result["pages"].as_array().unwrap().len(), 18);
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
        assert_eq!(
            proposal["summary"],
            "永久删除这条 AI 历史？此操作不可恢复。"
        );
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
            "永久清空计划中的 1 条 AI 历史？此操作不可恢复；确认后新增记录会保留。"
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
    async fn snapshot_read_rpc_routes_are_fixed_scoped_and_reject_renderer_ingredients() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let binding = "missing-snapshot-binding-marker";
        let cases = [
            (
                "snapshot.list",
                serde_json::json!({ "bindingHandle": binding }),
            ),
            (
                "snapshot.detail.get",
                serde_json::json!({
                    "bindingHandle": binding,
                    "snapshotHandle": "opaque-snapshot-one"
                }),
            ),
            (
                "snapshot.forensic.diff",
                serde_json::json!({
                    "bindingHandle": binding,
                    "input": {
                        "olderSnapshotHandle": "opaque-snapshot-older",
                        "newerSnapshotHandle": "opaque-snapshot-newer"
                    }
                }),
            ),
        ];
        for (method, params) in cases {
            let response = handle_frame(&state, &request(method, &params.to_string())).await;
            assert!(!response.ok, "{method} accepted a missing binding");
            assert_eq!(
                response.error.as_ref().unwrap().code,
                "snapshot-binding-unavailable",
                "{method}"
            );
            assert!(!serde_json::to_string(&response).unwrap().contains(binding));
        }

        let marker = "renderer-forged-snapshot-path-identity-command-secret";
        for (method, params) in [
            (
                "snapshot.list",
                serde_json::json!({ "bindingHandle": binding, "targetIdentity": marker }),
            ),
            (
                "snapshot.detail.get",
                serde_json::json!({
                    "bindingHandle": binding,
                    "snapshotHandle": "opaque-snapshot-one",
                    "path": marker
                }),
            ),
            (
                "snapshot.forensic.diff",
                serde_json::json!({
                    "bindingHandle": binding,
                    "input": {
                        "olderSnapshotHandle": "opaque-snapshot-older",
                        "newerSnapshotHandle": "opaque-snapshot-newer",
                        "snapshotId": marker
                    }
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
    async fn firewall_read_rpc_routes_are_exact_scoped_and_never_echo_renderer_ingredients() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let binding = "11111111-1111-4111-8111-111111111111";
        for method in ["firewall.inspect", "firewall.change-history.list"] {
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
            assert_eq!(failure.code, "firewall-binding-unavailable", "{method}");
            assert_eq!(
                failure.message, "The firewall target binding is missing or stale.",
                "{method}"
            );
            assert!(!serde_json::to_string(&response).unwrap().contains(binding));
        }

        let marker = "renderer-forged-firewall-command-path-target-secret";
        for (method, params) in [
            (
                "firewall.inspect",
                serde_json::json!({ "bindingHandle": binding, "command": marker }),
            ),
            (
                "firewall.change-history.list",
                serde_json::json!({ "bindingHandle": binding, "path": marker }),
            ),
        ] {
            let response = handle_frame(&state, &request(method, &params.to_string())).await;
            assert!(!response.ok);
            assert_eq!(response.error.as_ref().unwrap().code, "invalid-params");
            assert!(!serde_json::to_string(&response).unwrap().contains(marker));
        }

        let invalid_binding = "HOSTILE_FIREWALL_BINDING_MUST_NOT_ECHO";
        let response = handle_frame(
            &state,
            &request(
                "firewall.inspect",
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
    async fn middleware_read_rpc_routes_are_exact_scoped_and_never_echo_renderer_ingredients() {
        let root = TestRoot::new();
        let state = BackendState::open(root.0.clone()).unwrap();
        let binding = "11111111-1111-4111-8111-111111111111";
        let discovery = "22222222-2222-4222-8222-222222222222";
        let instance = "33333333-3333-4333-8333-333333333333";

        for (method, params) in [
            (
                "middleware.discover",
                serde_json::json!({ "bindingHandle": binding }),
            ),
            (
                "middleware.configuration.load",
                serde_json::json!({
                    "bindingHandle": binding,
                    "discoveryHandle": discovery,
                    "instanceHandle": instance,
                }),
            ),
            (
                "middleware.history.list",
                serde_json::json!({ "bindingHandle": binding }),
            ),
        ] {
            let response = handle_frame(&state, &request(method, &params.to_string())).await;
            assert!(!response.ok);
            assert_eq!(
                response.error.as_ref().unwrap().code,
                "middleware-binding-unavailable"
            );
            let text = serde_json::to_string(&response).unwrap();
            assert!(!text.contains(binding));
            assert!(!text.contains(discovery));
            assert!(!text.contains(instance));
        }

        let marker = "renderer-forged-middleware-command-path-target-secret";
        for (method, params) in [
            (
                "middleware.discover",
                serde_json::json!({ "bindingHandle": binding, "command": marker }),
            ),
            (
                "middleware.configuration.load",
                serde_json::json!({
                    "bindingHandle": binding,
                    "discoveryHandle": discovery,
                    "instanceHandle": instance,
                    "path": marker,
                }),
            ),
            (
                "middleware.history.list",
                serde_json::json!({ "bindingHandle": binding, "targetIdentity": marker }),
            ),
        ] {
            let response = handle_frame(&state, &request(method, &params.to_string())).await;
            assert!(!response.ok);
            assert_eq!(response.error.as_ref().unwrap().code, "invalid-params");
            assert!(!serde_json::to_string(&response).unwrap().contains(marker));
        }

        let invalid_binding = "../HOSTILE_MIDDLEWARE_BINDING_MUST_NOT_ECHO";
        let response = handle_frame(
            &state,
            &request(
                "middleware.discover",
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
    fn kubernetes_rpc_names_and_failure_mapping_are_closed_and_redacted() {
        for method in [
            "kubernetes.availability.get",
            "kubernetes.resources.list",
            "kubernetes.resource.detail.get",
            "kubernetes.pod.logs.get",
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
                "LovelyRes could not complete the Kubernetes read operation.",
            ),
            (
                KubernetesReadApiError::RegistryUnavailable,
                "kubernetes-operation-failed",
                "LovelyRes could not complete the Kubernetes read operation.",
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
        let state_field = ["docker_read: ", "DockerReadApi"].concat();
        assert_eq!(state.matches(&state_field).count(), 1);
        let open = source
            .split("impl BackendState")
            .nth(1)
            .and_then(|value| value.split("async fn replay_note_mutation").next())
            .unwrap();
        let initializer = ["let docker_read = ", "DockerReadApi::new"].concat();
        assert_eq!(open.matches(&initializer).count(), 1);
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
        for forbidden in [
            "command", "path", "target", "session", "mutation", "file", "terminal", "export",
            "generic",
        ] {
            assert!(
                !params.contains(forbidden),
                "Docker params exposed forbidden primitive {forbidden}"
            );
        }

        let cases = [
            (
                DockerReadApiError::Core,
                "docker-operation-failed",
                "LovelyRes could not complete the Docker read operation.",
            ),
            (
                DockerReadApiError::RegistryUnavailable,
                "docker-operation-failed",
                "LovelyRes could not complete the Docker read operation.",
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

    #[test]
    fn emergency_command_rpc_names_and_failure_mapping_are_closed_and_redacted() {
        for method in ["emergency-command.catalog.load", "emergency-command.run"] {
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
                "LovelyRes could not complete the emergency command operation.",
            ),
            (
                EmergencyCommandApiError::RegistryUnavailable,
                "emergency-command-operation-failed",
                "LovelyRes could not complete the emergency command operation.",
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
                "LovelyRes could not complete the live packet capture operation.",
            ),
            (
                PacketCaptureLiveApiError::RegistryUnavailable,
                "packet-capture-operation-failed",
                "LovelyRes could not complete the live packet capture operation.",
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
            (
                PacketCaptureLiveApiError::CaptureAlreadyActive,
                "packet-capture-capacity",
                "The bounded live packet capture capacity has been reached.",
            ),
            (
                PacketCaptureLiveApiError::RegistryCapacity,
                "packet-capture-capacity",
                "The bounded live packet capture capacity has been reached.",
            ),
            (
                PacketCaptureLiveApiError::ConcurrencyLimit,
                "packet-capture-capacity",
                "The bounded live packet capture capacity has been reached.",
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
            "LovelyRes could not complete the file-integrity operation."
        );
        assert!(core.source.is_some());

        let cases = [
            (
                IntegrityApiError::RegistryUnavailable,
                "integrity-operation-failed",
                "LovelyRes could not complete the file-integrity operation.",
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
                target: "lovelyres_application_log_test",
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
        let close = branch
            .find("self.firewall_read.close_binding(&params.binding_handle);")
            .unwrap();
        let baseline_close = branch
            .find("self.baseline_read.close_binding(&params.binding_handle);")
            .unwrap();
        let middleware_close = branch
            .find("self.middleware_read.close_binding(&params.binding_handle);")
            .unwrap();
        let check_audit_close = branch
            .find("self.check_audit_read.close_binding(&params.binding_handle);")
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
        let emergency_command_close = branch
            .find("self.emergency_command.close_binding(&params.binding_handle);")
            .unwrap();
        let docker_close = branch
            .find("self.docker_read.close_binding(&params.binding_handle);")
            .unwrap();
        let packet_capture_close = branch.find("self.packet_capture_live").unwrap();
        let disconnect = branch
            .find(".disconnect_binding(&params.binding_handle)")
            .unwrap();
        assert!(close < disconnect);
        assert!(baseline_close < disconnect);
        assert!(middleware_close < disconnect);
        assert!(check_audit_close < disconnect);
        assert!(integrity_close < disconnect);
        assert!(log_analysis_close < disconnect);
        assert!(kubernetes_close < disconnect);
        assert!(emergency_command_close < disconnect);
        assert!(docker_close < disconnect);
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
        let hostile = br#"{"protocol":"lovelyres-backend/v1","requestId":"request-1","method":"shell.execute","params":{"command":"</script><script>steal()</script>"}}"#;
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
