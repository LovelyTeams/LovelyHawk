//! Windows Incident Response API over RDP Dynamic Virtual Channel (DVC).

use std::fmt;

use lovelyhawk_core::{
    BackendServices,
    windows_incident::{
        DvcRuntimeStatus, WindowsAccountsSnapshot, WindowsBaselineSnapshot, WindowsFilePreview,
        WindowsFilesSnapshot, WindowsLogsSnapshot, WindowsNetworkSnapshot, WindowsOverviewSnapshot,
        WindowsProcessInspection, WindowsProcessesSnapshot, WindowsRegistrySnapshot,
        WindowsStartupSnapshot, fileless_powershell_script,
    },
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WindowsEvidencePartRequest {
    pub file_id: String,
    pub offset: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(
    tag = "action",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum WindowsIncidentRequest {
    Status {},
    RegisterPlugin {},
    UnregisterPlugin {},
    StartListener {},
    OpenRemoteDesktop {},
    RevealAgent {},
    SendChat {
        text: String,
        session_id: String,
    },
    RunCommand {
        command: String,
        session_id: String,
    },
    PullFile {
        remote_path: String,
        session_id: String,
    },
    CollectOverview {
        session_id: String,
    },
    CollectBaseline {
        session_id: String,
    },
    CollectProcesses {
        session_id: String,
    },
    InspectProcess {
        pid: u32,
        start_time: String,
        session_id: String,
    },
    CollectNetwork {
        session_id: String,
    },
    CollectStartup {
        session_id: String,
    },
    CollectAccounts {
        session_id: String,
    },
    CollectLogs {
        category: String,
        session_id: String,
    },
    CollectFiles {
        path: String,
        session_id: String,
    },
    PreviewFile {
        path: String,
        session_id: String,
    },
    CollectRegistry {
        key_path: String,
        session_id: String,
    },
    RemediateBaseline {
        rule_id: String,
        session_id: String,
    },
    KillProcess {
        pid: u32,
        start_time: String,
        session_id: String,
    },
    RemoveStartup {
        source_type: String,
        name: String,
        location: String,
        session_id: String,
    },
    DisableAccount {
        name: String,
        sid: String,
        session_id: String,
    },
    DeleteFile {
        path: String,
        dir_path: String,
        session_id: String,
    },
    DeleteRegistryValue {
        key_path: String,
        value_name: String,
        session_id: String,
    },
}

impl WindowsIncidentRequest {
    fn session_id(&self) -> Option<&str> {
        match self {
            Self::SendChat { session_id, .. }
            | Self::RunCommand { session_id, .. }
            | Self::PullFile { session_id, .. }
            | Self::CollectOverview { session_id }
            | Self::CollectBaseline { session_id }
            | Self::CollectProcesses { session_id }
            | Self::InspectProcess { session_id, .. }
            | Self::CollectNetwork { session_id }
            | Self::CollectStartup { session_id }
            | Self::CollectAccounts { session_id }
            | Self::CollectLogs { session_id, .. }
            | Self::CollectFiles { session_id, .. }
            | Self::PreviewFile { session_id, .. }
            | Self::CollectRegistry { session_id, .. }
            | Self::RemediateBaseline { session_id, .. }
            | Self::KillProcess { session_id, .. }
            | Self::RemoveStartup { session_id, .. }
            | Self::DisableAccount { session_id, .. }
            | Self::DeleteFile { session_id, .. }
            | Self::DeleteRegistryValue { session_id, .. } => Some(session_id),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub(crate) enum WindowsIncidentResponse {
    Status {
        status: DvcRuntimeStatus,
        fileless_script: String,
    },
    CommandOutput {
        output: String,
        status: DvcRuntimeStatus,
    },
    Overview {
        snapshot: WindowsOverviewSnapshot,
    },
    Baseline {
        snapshot: WindowsBaselineSnapshot,
    },
    Processes {
        snapshot: WindowsProcessesSnapshot,
    },
    ProcessInspection {
        inspection: WindowsProcessInspection,
    },
    Network {
        snapshot: WindowsNetworkSnapshot,
    },
    Startup {
        snapshot: WindowsStartupSnapshot,
    },
    Accounts {
        snapshot: WindowsAccountsSnapshot,
    },
    Logs {
        snapshot: WindowsLogsSnapshot,
    },
    Files {
        snapshot: WindowsFilesSnapshot,
    },
    FilePreview {
        preview: WindowsFilePreview,
    },
    Registry {
        snapshot: WindowsRegistrySnapshot,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WindowsIncidentError {
    Invalid,
    Failed,
}

impl fmt::Display for WindowsIncidentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Invalid => "the Windows incident response request is invalid",
            Self::Failed => "the Windows DVC operation failed",
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct WindowsIncidentApi {
    services: BackendServices,
}

impl WindowsIncidentApi {
    pub(crate) fn new(services: BackendServices) -> Self {
        Self { services }
    }

    pub(crate) fn evidence_part(
        &self,
        request: WindowsEvidencePartRequest,
    ) -> Result<lovelyhawk_core::windows_incident::WindowsEvidencePart, WindowsIncidentError> {
        if request.file_id.len() != 36 || uuid::Uuid::parse_str(&request.file_id).is_err() {
            return Err(WindowsIncidentError::Invalid);
        }
        self.services
            .windows_incident()
            .received_evidence_part(&request.file_id, request.offset)
            .map_err(|_| WindowsIncidentError::Failed)
    }

    pub(crate) async fn dispatch(
        &self,
        request: WindowsIncidentRequest,
    ) -> Result<WindowsIncidentResponse, WindowsIncidentError> {
        if request
            .session_id()
            .is_some_and(|id| id.len() != 36 || uuid::Uuid::parse_str(id).is_err())
        {
            return Err(WindowsIncidentError::Invalid);
        }
        let svc = self.services.windows_incident().clone();
        match request {
            WindowsIncidentRequest::Status {} => Ok(WindowsIncidentResponse::Status {
                status: svc.status(),
                fileless_script: fileless_powershell_script(),
            }),
            WindowsIncidentRequest::RegisterPlugin {} => {
                let status = tokio::task::spawn_blocking(move || svc.register_plugin(None))
                    .await
                    .map_err(|_| WindowsIncidentError::Failed)?
                    .map_err(|_| WindowsIncidentError::Failed)?;
                Ok(WindowsIncidentResponse::Status {
                    status,
                    fileless_script: fileless_powershell_script(),
                })
            }
            WindowsIncidentRequest::UnregisterPlugin {} => {
                let status = tokio::task::spawn_blocking(move || svc.unregister_plugin())
                    .await
                    .map_err(|_| WindowsIncidentError::Failed)?
                    .map_err(|_| WindowsIncidentError::Failed)?;
                Ok(WindowsIncidentResponse::Status {
                    status,
                    fileless_script: fileless_powershell_script(),
                })
            }
            WindowsIncidentRequest::StartListener {} => {
                let status = tokio::task::spawn_blocking(move || svc.start_listener())
                    .await
                    .map_err(|_| WindowsIncidentError::Failed)?
                    .map_err(|_| WindowsIncidentError::Failed)?;
                Ok(WindowsIncidentResponse::Status {
                    status,
                    fileless_script: fileless_powershell_script(),
                })
            }
            WindowsIncidentRequest::OpenRemoteDesktop {}
            | WindowsIncidentRequest::RevealAgent {} => {
                let open_client = matches!(request, WindowsIncidentRequest::OpenRemoteDesktop {});
                let status = tokio::task::spawn_blocking(move || {
                    if open_client {
                        svc.open_remote_desktop()?;
                    } else {
                        svc.reveal_agent()?;
                    }
                    Ok::<_, lovelyhawk_core::CoreError>(svc.status())
                })
                .await
                .map_err(|_| WindowsIncidentError::Failed)?
                .map_err(|_| WindowsIncidentError::Failed)?;
                Ok(WindowsIncidentResponse::Status {
                    status,
                    fileless_script: fileless_powershell_script(),
                })
            }
            WindowsIncidentRequest::SendChat { text, session_id } => {
                if text.trim().is_empty() || text.len() > 8192 {
                    return Err(WindowsIncidentError::Invalid);
                }
                let status = tokio::task::spawn_blocking(move || svc.send_chat(&text, &session_id))
                    .await
                    .map_err(|_| WindowsIncidentError::Failed)?
                    .map_err(|_| WindowsIncidentError::Failed)?;
                Ok(WindowsIncidentResponse::Status {
                    status,
                    fileless_script: fileless_powershell_script(),
                })
            }
            WindowsIncidentRequest::RunCommand {
                command,
                session_id,
            } => {
                if command.trim().is_empty() || command.len() > 16384 {
                    return Err(WindowsIncidentError::Invalid);
                }
                let (output, status) = tokio::task::spawn_blocking(move || {
                    let out = svc.run_remote_command(&command, &session_id)?;
                    Ok::<_, lovelyhawk_core::CoreError>((out, svc.status()))
                })
                .await
                .map_err(|_| WindowsIncidentError::Failed)?
                .map_err(|_| WindowsIncidentError::Failed)?;
                Ok(WindowsIncidentResponse::CommandOutput { output, status })
            }
            WindowsIncidentRequest::PullFile {
                remote_path,
                session_id,
            } => {
                if remote_path.trim().is_empty()
                    || remote_path.len() > 1024
                    || remote_path.contains(['\0', '\r', '\n'])
                {
                    return Err(WindowsIncidentError::Invalid);
                }
                let status = tokio::task::spawn_blocking(move || {
                    svc.pull_remote_file(&remote_path, &session_id)
                })
                .await
                .map_err(|_| WindowsIncidentError::Failed)?
                .map_err(|_| WindowsIncidentError::Failed)?;
                Ok(WindowsIncidentResponse::Status {
                    status,
                    fileless_script: fileless_powershell_script(),
                })
            }
            WindowsIncidentRequest::CollectOverview { session_id } => {
                let snapshot =
                    tokio::task::spawn_blocking(move || svc.collect_overview(&session_id))
                        .await
                        .map_err(|_| WindowsIncidentError::Failed)?
                        .map_err(|_| WindowsIncidentError::Failed)?;
                Ok(WindowsIncidentResponse::Overview { snapshot })
            }
            WindowsIncidentRequest::CollectBaseline { session_id } => {
                let snapshot =
                    tokio::task::spawn_blocking(move || svc.collect_baseline(&session_id))
                        .await
                        .map_err(|_| WindowsIncidentError::Failed)?
                        .map_err(|_| WindowsIncidentError::Failed)?;
                Ok(WindowsIncidentResponse::Baseline { snapshot })
            }
            WindowsIncidentRequest::CollectProcesses { session_id } => {
                let snapshot =
                    tokio::task::spawn_blocking(move || svc.collect_processes(&session_id))
                        .await
                        .map_err(|_| WindowsIncidentError::Failed)?
                        .map_err(|_| WindowsIncidentError::Failed)?;
                Ok(WindowsIncidentResponse::Processes { snapshot })
            }
            WindowsIncidentRequest::InspectProcess {
                pid,
                start_time,
                session_id,
            } => {
                if !lovelyhawk_core::windows_incident::valid_process_identity(pid, &start_time) {
                    return Err(WindowsIncidentError::Invalid);
                }
                let inspection = tokio::task::spawn_blocking(move || {
                    svc.inspect_process(pid, &start_time, &session_id)
                })
                .await
                .map_err(|_| WindowsIncidentError::Failed)?
                .map_err(|_| WindowsIncidentError::Failed)?;
                Ok(WindowsIncidentResponse::ProcessInspection { inspection })
            }
            WindowsIncidentRequest::CollectNetwork { session_id } => {
                let snapshot =
                    tokio::task::spawn_blocking(move || svc.collect_network(&session_id))
                        .await
                        .map_err(|_| WindowsIncidentError::Failed)?
                        .map_err(|_| WindowsIncidentError::Failed)?;
                Ok(WindowsIncidentResponse::Network { snapshot })
            }
            WindowsIncidentRequest::CollectStartup { session_id } => {
                let snapshot =
                    tokio::task::spawn_blocking(move || svc.collect_startup(&session_id))
                        .await
                        .map_err(|_| WindowsIncidentError::Failed)?
                        .map_err(|_| WindowsIncidentError::Failed)?;
                Ok(WindowsIncidentResponse::Startup { snapshot })
            }
            WindowsIncidentRequest::CollectAccounts { session_id } => {
                let snapshot =
                    tokio::task::spawn_blocking(move || svc.collect_accounts(&session_id))
                        .await
                        .map_err(|_| WindowsIncidentError::Failed)?
                        .map_err(|_| WindowsIncidentError::Failed)?;
                Ok(WindowsIncidentResponse::Accounts { snapshot })
            }
            WindowsIncidentRequest::CollectLogs {
                category,
                session_id,
            } => {
                if !matches!(
                    category.as_str(),
                    "all"
                        | "logon"
                        | "account"
                        | "service"
                        | "powershell"
                        | "failed-logon"
                        | "rdp"
                        | "defender"
                        | "tasks"
                        | "sysmon"
                        | "clear-log"
                        | "process"
                        | "security"
                        | "system"
                        | "application"
                        | "wmi"
                ) {
                    return Err(WindowsIncidentError::Invalid);
                }
                let snapshot =
                    tokio::task::spawn_blocking(move || svc.collect_logs(&category, &session_id))
                        .await
                        .map_err(|_| WindowsIncidentError::Failed)?
                        .map_err(|_| WindowsIncidentError::Failed)?;
                Ok(WindowsIncidentResponse::Logs { snapshot })
            }
            WindowsIncidentRequest::CollectFiles { path, session_id } => {
                if path.trim().is_empty() || path.len() > 1024 || path.contains(['\0', '\r', '\n'])
                {
                    return Err(WindowsIncidentError::Invalid);
                }
                let snapshot =
                    tokio::task::spawn_blocking(move || svc.collect_files(&path, &session_id))
                        .await
                        .map_err(|_| WindowsIncidentError::Failed)?
                        .map_err(|_| WindowsIncidentError::Failed)?;
                Ok(WindowsIncidentResponse::Files { snapshot })
            }
            WindowsIncidentRequest::PreviewFile { path, session_id } => {
                if path.trim().is_empty() || path.len() > 1024 || path.contains(['\0', '\r', '\n'])
                {
                    return Err(WindowsIncidentError::Invalid);
                }
                let preview =
                    tokio::task::spawn_blocking(move || svc.preview_file(&path, &session_id))
                        .await
                        .map_err(|_| WindowsIncidentError::Failed)?
                        .map_err(|_| WindowsIncidentError::Failed)?;
                Ok(WindowsIncidentResponse::FilePreview { preview })
            }
            WindowsIncidentRequest::CollectRegistry {
                key_path,
                session_id,
            } => {
                if key_path.trim().is_empty()
                    || key_path.len() > 1024
                    || key_path.contains(['\0', '\r', '\n'])
                {
                    return Err(WindowsIncidentError::Invalid);
                }
                let snapshot = tokio::task::spawn_blocking(move || {
                    svc.collect_registry(&key_path, &session_id)
                })
                .await
                .map_err(|_| WindowsIncidentError::Failed)?
                .map_err(|_| WindowsIncidentError::Failed)?;
                Ok(WindowsIncidentResponse::Registry { snapshot })
            }
            WindowsIncidentRequest::RemediateBaseline {
                rule_id,
                session_id,
            } => {
                if lovelyhawk_core::windows_incident::baseline_remediation_script(&rule_id)
                    .is_none()
                {
                    return Err(WindowsIncidentError::Invalid);
                }
                let snapshot = tokio::task::spawn_blocking(move || {
                    svc.remediate_baseline(&rule_id, &session_id)
                })
                .await
                .map_err(|_| WindowsIncidentError::Failed)?
                .map_err(|_| WindowsIncidentError::Failed)?;
                Ok(WindowsIncidentResponse::Baseline { snapshot })
            }
            WindowsIncidentRequest::KillProcess {
                pid,
                start_time,
                session_id,
            } => {
                if lovelyhawk_core::windows_incident::build_kill_process_ps_script(pid, &start_time)
                    .is_none()
                {
                    return Err(WindowsIncidentError::Invalid);
                }
                let snapshot = tokio::task::spawn_blocking(move || {
                    svc.kill_process(pid, &start_time, &session_id)
                })
                .await
                .map_err(|_| WindowsIncidentError::Failed)?
                .map_err(|_| WindowsIncidentError::Failed)?;
                Ok(WindowsIncidentResponse::Processes { snapshot })
            }
            WindowsIncidentRequest::RemoveStartup {
                source_type,
                name,
                location,
                session_id,
            } => {
                if lovelyhawk_core::windows_incident::build_remove_startup_ps_script(
                    &source_type,
                    &name,
                    &location,
                )
                .is_none()
                {
                    return Err(WindowsIncidentError::Invalid);
                }
                let snapshot = tokio::task::spawn_blocking(move || {
                    svc.remove_startup(&source_type, &name, &location, &session_id)
                })
                .await
                .map_err(|_| WindowsIncidentError::Failed)?
                .map_err(|_| WindowsIncidentError::Failed)?;
                Ok(WindowsIncidentResponse::Startup { snapshot })
            }
            WindowsIncidentRequest::DisableAccount {
                name,
                sid,
                session_id,
            } => {
                if lovelyhawk_core::windows_incident::build_disable_account_ps_script(&name, &sid)
                    .is_none()
                {
                    return Err(WindowsIncidentError::Invalid);
                }
                let snapshot = tokio::task::spawn_blocking(move || {
                    svc.disable_account(&name, &sid, &session_id)
                })
                .await
                .map_err(|_| WindowsIncidentError::Failed)?
                .map_err(|_| WindowsIncidentError::Failed)?;
                Ok(WindowsIncidentResponse::Accounts { snapshot })
            }
            WindowsIncidentRequest::DeleteFile {
                path,
                dir_path,
                session_id,
            } => {
                if lovelyhawk_core::windows_incident::build_delete_file_ps_script(&path, &dir_path)
                    .is_none()
                {
                    return Err(WindowsIncidentError::Invalid);
                }
                let snapshot = tokio::task::spawn_blocking(move || {
                    svc.delete_file(&path, &dir_path, &session_id)
                })
                .await
                .map_err(|_| WindowsIncidentError::Failed)?
                .map_err(|_| WindowsIncidentError::Failed)?;
                Ok(WindowsIncidentResponse::Files { snapshot })
            }
            WindowsIncidentRequest::DeleteRegistryValue {
                key_path,
                value_name,
                session_id,
            } => {
                if lovelyhawk_core::windows_incident::build_delete_registry_value_ps_script(
                    &key_path,
                    &value_name,
                )
                .is_none()
                {
                    return Err(WindowsIncidentError::Invalid);
                }
                let snapshot = tokio::task::spawn_blocking(move || {
                    svc.delete_registry_value(&key_path, &value_name, &session_id)
                })
                .await
                .map_err(|_| WindowsIncidentError::Failed)?
                .map_err(|_| WindowsIncidentError::Failed)?;
                Ok(WindowsIncidentResponse::Registry { snapshot })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::WindowsIncidentRequest;
    #[test]
    fn local_intents_and_process_inspection_reject_extra_fields() {
        for action in [
            "status",
            "register-plugin",
            "unregister-plugin",
            "start-listener",
            "open-remote-desktop",
            "reveal-agent",
        ] {
            assert!(
                serde_json::from_value::<WindowsIncidentRequest>(
                    serde_json::json!({"action":action})
                )
                .is_ok()
            );
            assert!(
                serde_json::from_value::<WindowsIncidentRequest>(
                    serde_json::json!({"action":action,"command":"injected"})
                )
                .is_err()
            );
        }
        assert!(serde_json::from_value::<WindowsIncidentRequest>(serde_json::json!({"action":"inspect-process","pid":1,"startTime":"2026-10-24T00:00:00Z","sessionId":"00000000-0000-4000-8000-000000000001","path":"C:\\x"})).is_err());
    }
}
