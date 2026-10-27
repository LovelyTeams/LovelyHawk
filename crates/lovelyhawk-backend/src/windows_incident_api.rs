//! Windows Incident Response API over RDP Dynamic Virtual Channel (DVC).

use std::fmt;

use lovelyhawk_core::{
    BackendServices,
    windows_incident::{
        BaselineChangePlan, BaselineChangeReport, DvcRuntimeStatus, WindowsAccountsSnapshot,
        WindowsBaselineSnapshot, WindowsFileAccess, WindowsFilePreview, WindowsFilesSnapshot,
        WindowsLogsSnapshot, WindowsNetworkSnapshot, WindowsOverviewSnapshot,
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
    InspectFileAccess {
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
    PlanBaseline {
        rule_ids: Vec<String>,
        session_id: String,
    },
    ApplyBaselinePlan {
        plan_id: String,
        session_id: String,
    },
    DiscardBaselinePlan {
        plan_id: String,
        session_id: String,
    },
    CancelBaselinePlan {
        plan_id: String,
        session_id: String,
    },
    BaselinePlanProgress {
        plan_id: String,
        session_id: String,
    },
    BaselineHistory {
        session_id: String,
    },
    PlanBaselineRestore {
        record_id: String,
        session_id: String,
    },
    CollectInventory {
        kind: lovelyhawk_core::windows_incident::WindowsInventoryKind,
        session_id: String,
    },
    PlanControl {
        object_id: String,
        operation: lovelyhawk_core::windows_incident::ControlOperation,
        session_id: String,
    },
    ApplyControl {
        plan_id: String,
        session_id: String,
    },
    DiscardControlPlan {
        plan_id: String,
        session_id: String,
    },
    ControlHistory {
        session_id: String,
    },
    PlanControlRestore {
        record_id: String,
        session_id: String,
    },
    PlanProcessChange {
        pid: u32,
        start_time: String,
        tree: bool,
        session_id: String,
    },
    ApplyProcessPlan {
        plan_id: String,
        session_id: String,
    },
    DiscardProcessPlan {
        plan_id: String,
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
            | Self::InspectFileAccess { session_id, .. }
            | Self::PreviewFile { session_id, .. }
            | Self::CollectRegistry { session_id, .. }
            | Self::PlanBaseline { session_id, .. }
            | Self::ApplyBaselinePlan { session_id, .. }
            | Self::DiscardBaselinePlan { session_id, .. }
            | Self::CancelBaselinePlan { session_id, .. }
            | Self::BaselinePlanProgress { session_id, .. }
            | Self::BaselineHistory { session_id }
            | Self::PlanBaselineRestore { session_id, .. }
            | Self::CollectInventory { session_id, .. }
            | Self::PlanControl { session_id, .. }
            | Self::ApplyControl { session_id, .. }
            | Self::DiscardControlPlan { session_id, .. }
            | Self::ControlHistory { session_id }
            | Self::PlanControlRestore { session_id, .. }
            | Self::PlanProcessChange { session_id, .. }
            | Self::ApplyProcessPlan { session_id, .. }
            | Self::DiscardProcessPlan { session_id, .. }
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
    ControlPlan {
        plan: lovelyhawk_core::windows_incident::ControlPlan,
    },
    ControlReport {
        report: lovelyhawk_core::windows_incident::ControlReport,
    },
    ControlHistory {
        records: Vec<lovelyhawk_core::windows_incident::ControlReport>,
    },
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
    Inventory {
        snapshot: lovelyhawk_core::windows_incident::WindowsInventorySnapshot,
    },
    ProcessPlan {
        plan: lovelyhawk_core::windows_incident::ProcessChangePlan,
    },
    ProcessChange {
        report: lovelyhawk_core::windows_incident::ProcessChangeReport,
    },
    BaselinePlan {
        plan: BaselineChangePlan,
    },
    BaselineChange {
        report: BaselineChangeReport,
    },
    BaselineProgress {
        report: Option<BaselineChangeReport>,
    },
    BaselineHistory {
        records: Vec<BaselineChangeReport>,
    },
    BaselineAcknowledged {
        accepted: bool,
    },
    BaselineChangeError {
        message: String,
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
    FileAccess {
        inspection: WindowsFileAccess,
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
            WindowsIncidentRequest::PlanBaseline {
                rule_ids,
                session_id,
            } => {
                if rule_ids.is_empty()
                    || rule_ids.len() > 19
                    || rule_ids
                        .iter()
                        .any(|id| !lovelyhawk_core::windows_incident::baseline_change_supported(id))
                    || rule_ids
                        .iter()
                        .collect::<std::collections::HashSet<_>>()
                        .len()
                        != rule_ids.len()
                {
                    return Err(WindowsIncidentError::Invalid);
                }
                let result = tokio::task::spawn_blocking(move || {
                    svc.plan_baseline_changes(&rule_ids, &session_id)
                })
                .await
                .map_err(|_| WindowsIncidentError::Failed)?;
                Ok(match result {
                    Ok(plan) => WindowsIncidentResponse::BaselinePlan { plan },
                    Err(error) => baseline_change_error(error),
                })
            }
            WindowsIncidentRequest::ApplyBaselinePlan {
                plan_id,
                session_id,
            } => {
                if uuid::Uuid::parse_str(&plan_id).is_err() || plan_id.len() != 36 {
                    return Err(WindowsIncidentError::Invalid);
                }
                let result = tokio::task::spawn_blocking(move || {
                    svc.apply_baseline_plan(&plan_id, &session_id)
                })
                .await
                .map_err(|_| WindowsIncidentError::Failed)?;
                Ok(match result {
                    Ok(report) => WindowsIncidentResponse::BaselineChange { report },
                    Err(error) => baseline_change_error(error),
                })
            }
            WindowsIncidentRequest::PlanBaselineRestore {
                record_id,
                session_id,
            } => {
                if uuid::Uuid::parse_str(&record_id).is_err() || record_id.len() != 36 {
                    return Err(WindowsIncidentError::Invalid);
                }
                let result = tokio::task::spawn_blocking(move || {
                    svc.plan_baseline_restore(&record_id, &session_id)
                })
                .await
                .map_err(|_| WindowsIncidentError::Failed)?;
                Ok(match result {
                    Ok(plan) => WindowsIncidentResponse::BaselinePlan { plan },
                    Err(error) => baseline_change_error(error),
                })
            }
            WindowsIncidentRequest::DiscardBaselinePlan {
                plan_id,
                session_id,
            } => {
                if uuid::Uuid::parse_str(&plan_id).is_err() || plan_id.len() != 36 {
                    return Err(WindowsIncidentError::Invalid);
                }
                svc.discard_baseline_plan(&plan_id, &session_id);
                Ok(WindowsIncidentResponse::BaselineAcknowledged { accepted: true })
            }
            WindowsIncidentRequest::CancelBaselinePlan {
                plan_id,
                session_id,
            } => {
                if uuid::Uuid::parse_str(&plan_id).is_err() || plan_id.len() != 36 {
                    return Err(WindowsIncidentError::Invalid);
                }
                Ok(WindowsIncidentResponse::BaselineAcknowledged {
                    accepted: svc.cancel_baseline_changes(&plan_id, &session_id),
                })
            }
            WindowsIncidentRequest::BaselinePlanProgress {
                plan_id,
                session_id,
            } => {
                if uuid::Uuid::parse_str(&plan_id).is_err() || plan_id.len() != 36 {
                    return Err(WindowsIncidentError::Invalid);
                }
                Ok(WindowsIncidentResponse::BaselineProgress {
                    report: svc.baseline_change_progress(&plan_id, &session_id),
                })
            }
            WindowsIncidentRequest::BaselineHistory { session_id } => {
                let result =
                    tokio::task::spawn_blocking(move || svc.baseline_change_history(&session_id))
                        .await
                        .map_err(|_| WindowsIncidentError::Failed)?;
                Ok(match result {
                    Ok(records) => WindowsIncidentResponse::BaselineHistory { records },
                    Err(error) => baseline_change_error(error),
                })
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
            WindowsIncidentRequest::InspectFileAccess { path, session_id } => {
                if path.is_empty() || path.len() > 1024 || path.contains(['\0', '\r', '\n']) {
                    return Err(WindowsIncidentError::Invalid);
                }
                let inspection = tokio::task::spawn_blocking(move || {
                    svc.inspect_file_access(&path, &session_id)
                })
                .await
                .map_err(|_| WindowsIncidentError::Failed)?
                .map_err(|_| WindowsIncidentError::Failed)?;
                Ok(WindowsIncidentResponse::FileAccess { inspection })
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
            WindowsIncidentRequest::CollectInventory { kind, session_id } => {
                let snapshot =
                    tokio::task::spawn_blocking(move || svc.collect_inventory(kind, &session_id))
                        .await
                        .map_err(|_| WindowsIncidentError::Failed)?
                        .map_err(|_| WindowsIncidentError::Failed)?;
                Ok(WindowsIncidentResponse::Inventory { snapshot })
            }
            WindowsIncidentRequest::PlanControl {
                object_id,
                operation,
                session_id,
            } => {
                if object_id.len() != 36 || uuid::Uuid::parse_str(&object_id).is_err() {
                    return Err(WindowsIncidentError::Invalid);
                }
                let result = tokio::task::spawn_blocking(move || {
                    svc.plan_control(&object_id, operation, &session_id)
                })
                .await
                .map_err(|_| WindowsIncidentError::Failed)?;
                Ok(match result {
                    Ok(plan) => WindowsIncidentResponse::ControlPlan { plan },
                    Err(e) => control_error(e),
                })
            }
            WindowsIncidentRequest::PlanControlRestore {
                record_id,
                session_id,
            } => {
                if record_id.len() != 36 || uuid::Uuid::parse_str(&record_id).is_err() {
                    return Err(WindowsIncidentError::Invalid);
                }
                let result = tokio::task::spawn_blocking(move || {
                    svc.plan_control_restore(&record_id, &session_id)
                })
                .await
                .map_err(|_| WindowsIncidentError::Failed)?;
                Ok(match result {
                    Ok(plan) => WindowsIncidentResponse::ControlPlan { plan },
                    Err(e) => control_error(e),
                })
            }
            WindowsIncidentRequest::ApplyControl {
                plan_id,
                session_id,
            } => {
                if plan_id.len() != 36 || uuid::Uuid::parse_str(&plan_id).is_err() {
                    return Err(WindowsIncidentError::Invalid);
                }
                let result =
                    tokio::task::spawn_blocking(move || svc.apply_control(&plan_id, &session_id))
                        .await
                        .map_err(|_| WindowsIncidentError::Failed)?;
                Ok(match result {
                    Ok(report) => WindowsIncidentResponse::ControlReport { report },
                    Err(e) => control_error(e),
                })
            }
            WindowsIncidentRequest::DiscardControlPlan {
                plan_id,
                session_id,
            } => {
                if plan_id.len() != 36 || uuid::Uuid::parse_str(&plan_id).is_err() {
                    return Err(WindowsIncidentError::Invalid);
                }
                svc.discard_control_plan(&plan_id, &session_id);
                Ok(WindowsIncidentResponse::BaselineAcknowledged { accepted: true })
            }
            WindowsIncidentRequest::ControlHistory { .. } => {
                let result = tokio::task::spawn_blocking(move || svc.control_history())
                    .await
                    .map_err(|_| WindowsIncidentError::Failed)?;
                Ok(match result {
                    Ok(records) => WindowsIncidentResponse::ControlHistory { records },
                    Err(e) => control_error(e),
                })
            }
            WindowsIncidentRequest::PlanProcessChange {
                pid,
                start_time,
                tree,
                session_id,
            } => {
                if lovelyhawk_core::windows_incident::build_kill_process_ps_script(pid, &start_time)
                    .is_none()
                {
                    return Err(WindowsIncidentError::Invalid);
                }
                let result = tokio::task::spawn_blocking(move || {
                    svc.plan_process_change(pid, &start_time, tree, &session_id)
                })
                .await
                .map_err(|_| WindowsIncidentError::Failed)?;
                Ok(match result {
                    Ok(plan) => WindowsIncidentResponse::ProcessPlan { plan },
                    Err(error) => process_change_error(error),
                })
            }
            WindowsIncidentRequest::ApplyProcessPlan {
                plan_id,
                session_id,
            } => {
                if plan_id.len() != 36 || uuid::Uuid::parse_str(&plan_id).is_err() {
                    return Err(WindowsIncidentError::Invalid);
                }
                let result = tokio::task::spawn_blocking(move || {
                    svc.apply_process_plan(&plan_id, &session_id)
                })
                .await
                .map_err(|_| WindowsIncidentError::Failed)?;
                Ok(match result {
                    Ok(report) => WindowsIncidentResponse::ProcessChange { report },
                    Err(error) => process_change_error(error),
                })
            }
            WindowsIncidentRequest::DiscardProcessPlan {
                plan_id,
                session_id,
            } => {
                if plan_id.len() != 36 || uuid::Uuid::parse_str(&plan_id).is_err() {
                    return Err(WindowsIncidentError::Invalid);
                }
                svc.discard_process_plan(&plan_id, &session_id);
                Ok(WindowsIncidentResponse::BaselineAcknowledged { accepted: true })
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

fn process_change_error(error: lovelyhawk_core::CoreError) -> WindowsIncidentResponse {
    let message=match error {
        lovelyhawk_core::CoreError::Validation { subject:"windows process plan",message } => message,
        _ => "进程计划或操作记录保存失败，请核对便携数据目录和连接；如果已经执行，请重新采集核对，不能重复旧计划。".into(),
    };
    WindowsIncidentResponse::BaselineChangeError { message }
}
fn control_error(error: lovelyhawk_core::CoreError) -> WindowsIncidentResponse {
    let message = match error {
        lovelyhawk_core::CoreError::Validation {
            subject: "windows control" | "windows script",
            message,
        } => message,
        _ => "无法完成操作或保存本机记录，请核对连接和数据目录；如操作已开始，请重新采集核实。"
            .into(),
    };
    WindowsIncidentResponse::BaselineChangeError { message }
}

fn baseline_change_error(error: lovelyhawk_core::CoreError) -> WindowsIncidentResponse {
    let message=match error {
        lovelyhawk_core::CoreError::Validation { subject:"windows baseline plan" | "windows process plan", message } => message,
        _ => "配置计划或历史保存失败。请核对便携数据目录的可写性与连接状态；如已开始执行，请先查看历史并复核目标，不要重复旧计划。".to_owned(),
    };
    WindowsIncidentResponse::BaselineChangeError { message }
}

#[cfg(test)]
mod tests {
    #[test]
    fn control_intents_accept_only_ids_and_closed_operations() {
        let id = "00000000-0000-4000-8000-000000000001";
        let request = serde_json::json!({"action":"plan-control","objectId":id,"sessionId":id,"operation":"stop"});
        assert!(serde_json::from_value::<super::WindowsIncidentRequest>(request.clone()).is_ok());
        for extra in ["name", "command", "force", "elevate"] {
            let mut changed = request.clone();
            changed[extra] = "injected".into();
            assert!(serde_json::from_value::<super::WindowsIncidentRequest>(changed).is_err());
        }
        let mut changed = request;
        changed["operation"] = "delete".into();
        assert!(serde_json::from_value::<super::WindowsIncidentRequest>(changed).is_err());
        assert!(serde_json::from_value::<super::WindowsIncidentRequest>(serde_json::json!({"action":"apply-control","planId":id,"sessionId":id,"operation":"disable"})).is_err());
    }
    #[test]
    fn fixed_baseline_plans_and_file_diagnosis_reject_injected_parameters() {
        let session = "00000000-0000-4000-8000-000000000001";
        for action in [
            "plan-baseline",
            "apply-baseline-plan",
            "plan-baseline-restore",
            "inspect-file-access",
        ] {
            assert!(serde_json::from_value::<super::WindowsIncidentRequest>(serde_json::json!({"action":action,"sessionId":session,"path":"injected","desired":0})).is_err());
        }
        assert!(serde_json::from_value::<super::WindowsIncidentRequest>(serde_json::json!({"action":"remediate-baseline","sessionId":session,"ruleId":"wdigest"})).is_err());
        assert!(serde_json::from_value::<super::WindowsIncidentRequest>(serde_json::json!({"action":"apply-baseline-plan","sessionId":session,"planId":session})).is_ok());
        assert!(serde_json::from_value::<super::WindowsIncidentRequest>(serde_json::json!({"action":"inspect-file-access","sessionId":session,"path":"C:\\sample.txt"})).is_ok());
    }

    use super::WindowsIncidentRequest;
    #[test]
    fn process_plans_and_inventory_scopes_reject_extra_or_open_ended_parameters() {
        let session = "00000000-0000-4000-8000-000000000001";
        for kind in ["services", "drivers", "tasks"] {
            assert!(serde_json::from_value::<WindowsIncidentRequest>(serde_json::json!({"action":"collect-inventory","kind":kind,"sessionId":session})).is_ok());
        }
        for request in [
            serde_json::json!({"action":"collect-inventory","kind":"services;cmd","sessionId":session}),
            serde_json::json!({"action":"plan-process-change","pid":900,"startTime":"2026-10-27T00:00:00Z","tree":true,"sessionId":session,"pids":[123]}),
            serde_json::json!({"action":"apply-process-plan","planId":session,"sessionId":session,"force":true}),
        ] {
            assert!(serde_json::from_value::<WindowsIncidentRequest>(request).is_err());
        }
    }

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
