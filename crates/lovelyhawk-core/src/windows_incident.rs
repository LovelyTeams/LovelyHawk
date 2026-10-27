//! Windows Incident Response over RDP Dynamic Virtual Channel (DVC).
//!
//! Provides:
//! - In-process COM LocalServer plugin management and per-user registry setup
//! - Fileless PowerShell DVC agent script generator (embeds C# `wtsapi32.dll` P/Invoke)
//! - Read-only remote collection and risk analysis across 9 incident response modules:
//!   Overview, Baseline, Processes, Network, Startup/Persistence, Accounts, Event Logs,
//!   Files (with DVC file pull/push), and Registry inspection.

use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
pub use lovelyhawk_win_dvc::{
    ADDIN_NAME, COMPAT_CHANNEL_NAME, DvcHub, DvcLogEntry, DvcReceivedFile, DvcRegistrationStatus,
    DvcRuntimeStatus, PLUGIN_CLSID_STR, PRIMARY_CHANNEL_NAME, query_registration,
    register_addin_per_user, unregister_addin_per_user,
};
use serde::{Deserialize, Serialize};

use crate::{CoreError, CoreResult};
mod baseline;
mod baseline_change;
mod control;
mod inventory;
mod process_change;
mod script_transport;
mod startup_catalog;
pub use baseline_change::{
    BaselineChangeItem, BaselineChangePlan, BaselineChangeReport, BaselineChangeState,
    BaselinePlanItem, baseline_change_supported,
};
pub use control::{
    ControlOperation, ControlPlan, ControlReport, ControlResultState, InventoryDetails,
};
pub use inventory::{
    WindowsInventoryEntry, WindowsInventoryKind, WindowsInventorySnapshot, parse_inventory_json,
};
pub use process_change::{
    ProcessChangeItem, ProcessChangePlan, ProcessChangeReport, ProcessChangeState, ProcessPlanItem,
};
pub use startup_catalog::{
    STARTUP_CATEGORIES, StartupCategory, StartupCategoryResult, StartupCoverage,
    parse_startup_catalog,
};

const DEFAULT_COLLECTION_TIMEOUT: Duration = Duration::from_secs(45);
pub const WINDOWS_EVIDENCE_PART_BYTES: usize = 256 * 1024;
pub const WINDOWS_EVIDENCE_MAX_BYTES: usize = 8 * 1024 * 1024;

/// Host-only payload: no local path or recovered bytes are given to the page.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsEvidencePart {
    pub file_id: String,
    pub name: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub offset: u64,
    pub bytes: Vec<u8>,
}

impl WindowsEvidencePart {
    pub fn verifies(&self, bytes: &[u8]) -> bool {
        use sha2::Digest as _;
        bytes.len() <= WINDOWS_EVIDENCE_MAX_BYTES
            && bytes.len() as u64 == self.size_bytes
            && format!("{:x}", sha2::Sha256::digest(bytes)).eq_ignore_ascii_case(&self.sha256)
    }
}

/// Risk level assigned to an observation or finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsRiskLevel {
    High,
    Medium,
    Low,
    Normal,
}

/// Overview summary of the remote Windows host inside the RDP session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsOverviewSnapshot {
    pub hostname: String,
    pub os_caption: String,
    pub os_version: String,
    pub architecture: String,
    pub domain_or_workgroup: String,
    pub part_of_domain: bool,
    pub current_user: String,
    pub is_elevated: bool,
    pub session_name: String,
    pub boot_time: String,
    pub uptime_hours: u64,
    pub cpu_name: String,
    pub cpu_cores: u32,
    pub cpu_load_percent: u32,
    pub memory_total_mb: u64,
    pub memory_used_mb: u64,
    pub memory_usage_percent: u32,
    pub system_drive_free_gb: u64,
    pub system_drive_total_gb: u64,
    pub defender_enabled: Option<bool>,
    pub realtime_protection: Option<bool>,
    pub firewall_domain_enabled: Option<bool>,
    pub firewall_private_enabled: Option<bool>,
    pub firewall_public_enabled: Option<bool>,
    pub high_risk_count: u32,
    pub medium_risk_count: u32,
    pub highlights: Vec<String>,
    pub facts: Vec<WindowsHostFact>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsHostFact {
    pub group: String,
    pub label: String,
    pub value: String,
}

/// One Windows security baseline check item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsBaselineItem {
    pub id: String,
    pub category: String,
    pub title: String,
    pub current_value: String,
    pub expected_value: String,
    /// `"pass"` | `"warn"` | `"fail"` | `"unknown"` | `"not-applicable"`
    pub status: String,
    pub severity: WindowsRiskLevel,
    pub description: String,
    pub recommendation: String,
    pub remediation_available: bool,
}

/// Baseline check snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsBaselineSnapshot {
    pub total_checks: u32,
    pub passed_count: u32,
    pub failed_count: u32,
    pub warning_count: u32,
    pub unknown_count: u32,
    pub not_applicable_count: u32,
    pub items: Vec<WindowsBaselineItem>,
}

/// One running Windows process with incident-response risk assessment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsProcessEntry {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub executable_path: String,
    pub command_line: String,
    pub user: String,
    pub session_id: u32,
    pub working_set_mb: u64,
    pub start_time: String,
    pub risk_level: WindowsRiskLevel,
    pub risk_reasons: Vec<String>,
}

/// Process table snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsProcessesSnapshot {
    pub total_count: u32,
    pub suspicious_count: u32,
    pub processes: Vec<WindowsProcessEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsProcessService {
    pub name: String,
    pub display_name: String,
    pub state: String,
    pub start_mode: String,
    pub path: String,
    pub account: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsProcessModule {
    pub name: String,
    pub path: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsProcessInspection {
    pub pid: u32,
    pub start_time: String,
    pub observed_at: String,
    pub user: String,
    pub services: Vec<WindowsProcessService>,
    pub modules: Vec<WindowsProcessModule>,
    pub network: Vec<WindowsNetworkEntry>,
    pub warnings: Vec<String>,
}

/// One active TCP/UDP endpoint or connection on the Windows host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsNetworkEntry {
    pub protocol: String,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: u32,
    pub process_name: String,
    pub process_path: String,
    pub risk_level: WindowsRiskLevel,
    pub risk_reason: String,
}

/// Network table snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsNetworkSnapshot {
    pub total_count: u32,
    pub suspicious_count: u32,
    pub connections: Vec<WindowsNetworkEntry>,
}

/// One persistence / autorun item (Registry Run, Startup folder, Scheduled Task, Service).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsStartupEntry {
    #[serde(default)]
    pub category: StartupCategory,
    pub source_type: String,
    pub name: String,
    pub location: String,
    pub command: String,
    pub run_as: String,
    pub state: String,
    pub risk_level: WindowsRiskLevel,
    pub risk_reason: String,
}

/// Startup & persistence snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsStartupSnapshot {
    pub total_count: u32,
    pub suspicious_count: u32,
    pub entries: Vec<WindowsStartupEntry>,
    pub categories: Vec<StartupCategoryResult>,
    pub warnings: Vec<String>,
    pub observed_at: String,
    pub truncated: bool,
}

/// One local Windows user account with security posture flags.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsAccountEntry {
    pub name: String,
    pub full_name: String,
    pub enabled: bool,
    pub is_admin: bool,
    pub sid: String,
    pub rid: u32,
    pub last_logon: String,
    pub password_required: bool,
    pub password_expires: bool,
    pub risk_level: WindowsRiskLevel,
    pub risk_reasons: Vec<String>,
}

/// Local accounts snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsAccountsSnapshot {
    pub total_count: u32,
    pub admin_count: u32,
    pub suspicious_count: u32,
    pub accounts: Vec<WindowsAccountEntry>,
}

/// One Windows Event Log record relevant to incident response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsEventLogEntry {
    pub record_id: u64,
    pub time_created: String,
    pub channel: String,
    pub event_id: u32,
    pub level: String,
    pub category: String,
    pub summary: String,
    pub detail: String,
    #[serde(default)]
    pub detail_truncated: bool,
    pub risk_level: WindowsRiskLevel,
}

/// Event logs snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsLogsSnapshot {
    pub category_filter: String,
    pub total_count: u32,
    pub high_risk_count: u32,
    #[serde(default)]
    pub warnings: Vec<String>,
    pub entries: Vec<WindowsEventLogEntry>,
}

/// One directory or file entry in the remote Windows filesystem browser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsFileEntry {
    pub name: String,
    pub full_path: String,
    pub entry_type: String,
    pub size_bytes: u64,
    pub last_write_time: String,
    pub sha256: String,
    #[serde(default)]
    pub hidden: bool,
    #[serde(default)]
    pub system: bool,
    pub risk_level: WindowsRiskLevel,
    pub risk_reason: String,
}

/// Remote directory listing snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsFilesSnapshot {
    pub current_path: String,
    /// Entries in the folder; `entries` holds at most the listing cap.
    pub total_entries: u64,
    pub truncated: bool,
    pub entries: Vec<WindowsFileEntry>,
}

/// The first bytes of one remote file, for the file manager's preview pane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsFilePreview {
    pub full_path: String,
    pub size_bytes: u64,
    pub last_write_time: String,
    pub preview_b64: String,
    pub preview_bytes: u64,
    pub truncated: bool,
}

/// One registry value inside a key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsRegistryValue {
    pub name: String,
    pub kind: String,
    pub data: String,
    #[serde(default)]
    pub truncated: bool,
    pub risk_level: WindowsRiskLevel,
    pub risk_reason: String,
}

/// Remote registry key inspection snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsRegistrySnapshot {
    pub key_path: String,
    pub subkeys: Vec<String>,
    pub values: Vec<WindowsRegistryValue>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsFileAccessRule {
    pub identity: String,
    pub rights: String,
    pub access: String,
    pub inherited: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsFileProcess {
    pub pid: u32,
    pub name: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsFileService {
    pub name: String,
    pub display_name: String,
    pub state: String,
    pub start_mode: String,
    pub path: String,
    pub kind: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsFileAccess {
    pub path: String,
    pub observed_at: String,
    pub attributes: String,
    pub owner: String,
    pub access_rules: Vec<WindowsFileAccessRule>,
    pub processes: Vec<WindowsFileProcess>,
    pub services: Vec<WindowsFileService>,
    pub warnings: Vec<String>,
}

/// High-level service owned by `BackendServices`.
#[derive(Debug, Clone, Default)]
pub struct WindowsIncidentService {
    hub: DvcHub,
    baseline_store: Option<crate::store::PortableStore>,
    baseline_changes: std::sync::Arc<baseline_change::BaselineChanges>,
    process_changes: std::sync::Arc<process_change::ProcessChanges>,
    control_changes: std::sync::Arc<control::ControlChanges>,
}

impl WindowsIncidentService {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_store(store: crate::store::PortableStore) -> Self {
        Self {
            baseline_store: Some(store),
            ..Self::new()
        }
    }

    pub fn status(&self) -> DvcRuntimeStatus {
        self.hub.status()
    }

    pub fn register_plugin(&self, custom_command: Option<&str>) -> CoreResult<DvcRuntimeStatus> {
        self.hub
            .register_plugin(custom_command)
            .map_err(|e| CoreError::validation("windows_incident.register", e))
    }

    pub fn unregister_plugin(&self) -> CoreResult<DvcRuntimeStatus> {
        self.hub
            .unregister_plugin()
            .map_err(|e| CoreError::validation("windows_incident.unregister", e))
    }

    pub fn shutdown(&self) {
        self.hub.shutdown();
    }

    pub fn start_listener(&self) -> CoreResult<DvcRuntimeStatus> {
        self.hub
            .ensure_listener_started()
            .map_err(|e| CoreError::validation("windows_incident.start_listener", e))
    }

    /// Starts the system Remote Desktop client with no arguments; the operator
    /// picks the host inside it. Nothing from the page reaches the command.
    pub fn open_remote_desktop(&self) -> CoreResult<()> {
        #[cfg(windows)]
        {
            let client = std::env::var_os("SystemRoot")
                .map(|root| {
                    std::path::PathBuf::from(root)
                        .join("System32")
                        .join("mstsc.exe")
                })
                .filter(|path| path.is_absolute() && path.is_file())
                .ok_or_else(|| {
                    CoreError::validation("windows_incident.rdp", "无法定位系统远程桌面客户端")
                })?;
            std::process::Command::new(client)
                .spawn()
                .map(|_| ())
                .map_err(|_| {
                    CoreError::validation("windows_incident.open_mstsc", "无法启动远程桌面客户端")
                })
        }
        #[cfg(not(windows))]
        {
            Err(CoreError::validation(
                "windows_incident.open_mstsc",
                "远程桌面客户端只在 Windows 上可用",
            ))
        }
    }

    /// Opens Explorer with the session agent shipped beside this executable
    /// selected, so the operator can copy it into the Remote Desktop window.
    pub fn reveal_agent(&self) -> CoreResult<()> {
        let agent = agent_executable_path().ok_or_else(|| {
            CoreError::validation(
                "windows_incident.reveal_agent",
                "程序目录中没有找到 lovelyhawk-win-agent.exe",
            )
        })?;
        #[cfg(windows)]
        {
            let mut select = std::ffi::OsString::from("/select,");
            select.push(agent.as_os_str());
            let explorer = std::env::var_os("SystemRoot")
                .map(|root| std::path::PathBuf::from(root).join("explorer.exe"))
                .filter(|path| path.is_absolute() && path.is_file())
                .ok_or_else(|| {
                    CoreError::validation("windows_incident.reveal_agent", "无法定位系统资源管理器")
                })?;
            std::process::Command::new(explorer)
                .arg(select)
                .spawn()
                .map(|_| ())
                .map_err(|_| {
                    CoreError::validation("windows_incident.reveal_agent", "无法打开资源管理器")
                })
        }
        #[cfg(not(windows))]
        {
            let _ = agent;
            Err(CoreError::validation(
                "windows_incident.reveal_agent",
                "资源管理器只在 Windows 上可用",
            ))
        }
    }

    pub fn send_chat(&self, text: &str, session_id: &str) -> CoreResult<DvcRuntimeStatus> {
        if text.trim().is_empty() || text.len() > 8192 {
            return Err(CoreError::validation(
                "windows_incident.send_chat",
                "message must be non-empty and at most 8192 bytes",
            ));
        }
        self.hub
            .send_chat_for_session(text, session_id)
            .map_err(|e| CoreError::validation("windows_incident.send_chat", e))
    }

    pub fn run_remote_command(&self, command: &str, session_id: &str) -> CoreResult<String> {
        if command.trim().is_empty() || command.len() > 16384 {
            return Err(CoreError::validation(
                "windows_incident.run_remote_command",
                "command must be non-empty and at most 16384 bytes",
            ));
        }
        self.hub
            .execute_command_for_session(command, DEFAULT_COLLECTION_TIMEOUT, session_id)
            .map_err(|e| CoreError::validation("windows_incident.run_remote_command", e))
    }

    pub fn pull_remote_file(
        &self,
        remote_path: &str,
        session_id: &str,
    ) -> CoreResult<DvcRuntimeStatus> {
        let trimmed = remote_path.trim();
        if trimmed.is_empty() || trimmed.len() > 1024 || trimmed.contains(['\0', '\r', '\n']) {
            return Err(CoreError::validation(
                "windows_incident.pull_remote_file",
                "invalid remote file path",
            ));
        }
        let ps = build_file_pull_ps_script(trimmed);
        let cleaned = self.run_native_or_ps(&format!("pull-file:{trimmed}"), &ps, session_id)?;
        #[derive(Deserialize)]
        struct PullFilePayload {
            name: String,
            b64: String,
            sha256: String,
        }
        let payload: PullFilePayload = serde_json::from_str(cleaned.trim()).map_err(|e| {
            CoreError::validation(
                "windows_incident.pull_remote_file",
                format!("解析远程文件回传数据失败: {e}"),
            )
        })?;
        if payload.b64.len() > 12 * 1024 * 1024 {
            return Err(CoreError::validation(
                "windows_incident.pull_remote_file",
                "远程文件超过 8 MB 上限",
            ));
        }
        let raw = BASE64.decode(payload.b64.trim()).map_err(|e| {
            CoreError::validation(
                "windows_incident.pull_remote_file",
                format!("解码远程文件 Base64 失败: {e}"),
            )
        })?;
        use sha2::Digest as _;
        if raw.len() > 8 * 1024 * 1024
            || !format!("{:x}", sha2::Sha256::digest(&raw)).eq_ignore_ascii_case(&payload.sha256)
        {
            return Err(CoreError::validation(
                "windows_incident.pull_remote_file",
                "文件大小或 SHA256 校验失败，未记为成功接收",
            ));
        }
        self.hub.on_incoming_for_session(
            lovelyhawk_win_dvc::DvcWireMessage {
                from: "server".to_owned(),
                seq: 0,
                msg_type: "file_start".to_owned(),
                text: String::new(),
                name: Some(payload.name.clone()),
                size: Some(raw.len() as u64),
                b64: None,
                sha256: None,
            },
            session_id,
        );
        self.hub.on_incoming_for_session(
            lovelyhawk_win_dvc::DvcWireMessage {
                from: "server".to_owned(),
                seq: 0,
                msg_type: "file_chunk".to_owned(),
                text: String::new(),
                name: None,
                size: None,
                b64: Some(payload.b64),
                sha256: None,
            },
            session_id,
        );
        let accepted = self.hub.on_incoming_for_session(
            lovelyhawk_win_dvc::DvcWireMessage {
                from: "server".to_owned(),
                seq: 0,
                msg_type: "file_end".to_owned(),
                text: String::new(),
                name: Some(payload.name),
                size: Some(raw.len() as u64),
                b64: None,
                sha256: Some(payload.sha256),
            },
            session_id,
        );
        if !accepted {
            return Err(CoreError::validation(
                "windows_incident.pull_remote_file",
                "接收期间会话发生变化，请重试",
            ));
        }
        Ok(self.hub.status())
    }

    pub fn push_file_bytes(&self, file_name: &str, bytes: &[u8]) -> CoreResult<DvcRuntimeStatus> {
        self.hub
            .send_file_bytes(file_name, bytes)
            .map_err(|e| CoreError::validation("windows_incident.push_file", e))
    }

    pub fn received_file_bytes(&self, file_id: &str) -> Option<(String, Vec<u8>)> {
        self.hub.received_file_bytes(file_id)
    }

    pub fn received_evidence_part(
        &self,
        file_id: &str,
        offset: u64,
    ) -> CoreResult<WindowsEvidencePart> {
        if uuid::Uuid::parse_str(file_id).is_err() || offset > WINDOWS_EVIDENCE_MAX_BYTES as u64 {
            return Err(CoreError::validation(
                "windows_incident.evidence",
                "取证文件请求无效",
            ));
        }
        let file = self
            .hub
            .received_file_part(file_id, offset as usize, WINDOWS_EVIDENCE_PART_BYTES)
            .filter(|file| file.size_bytes <= WINDOWS_EVIDENCE_MAX_BYTES as u64)
            .ok_or_else(|| {
                CoreError::validation(
                    "windows_incident.evidence",
                    "取证文件已不在缓存中、校验失败或超过大小上限",
                )
            })?;
        Ok(WindowsEvidencePart {
            file_id: file.file_id,
            name: file.name,
            size_bytes: file.size_bytes,
            sha256: file.sha256,
            offset,
            bytes: file.content,
        })
    }

    fn run_native_or_ps(
        &self,
        native_spec: &str,
        fallback_ps: &str,
        session_id: &str,
    ) -> CoreResult<String> {
        let native_cmd = format!("__NATIVE_COLLECT__:{native_spec}");
        let raw = self
            .hub
            .execute_command_for_session(&native_cmd, DEFAULT_COLLECTION_TIMEOUT, session_id)
            .map_err(|e| CoreError::validation("windows_incident.collect", e))?;
        if let Ok(cleaned) = strip_exit_prefix(&raw)
            && cleaned.trim_start().starts_with(['{', '['])
        {
            return Ok(cleaned);
        }
        if raw.starts_with("[error]")
            && !raw.contains("未知原生采集指令")
            && !raw.contains("此采集端使用 PowerShell 查询")
        {
            return Err(CoreError::validation(
                "windows_incident.collect",
                "采集端查询未完成，请检查权限、输出上限或查询时限，缩小范围后重试",
            ));
        }
        let cmd = encode_powershell_command(fallback_ps);
        let raw_ps = self
            .hub
            .execute_command_for_session(&cmd, DEFAULT_COLLECTION_TIMEOUT, session_id)
            .map_err(|e| CoreError::validation("windows_incident.collect", e))?;
        strip_exit_prefix(&raw_ps)
    }

    pub fn collect_overview(&self, session_id: &str) -> CoreResult<WindowsOverviewSnapshot> {
        let json_str = self.run_native_or_ps("overview-v2", PS_COLLECT_OVERVIEW, session_id)?;
        parse_overview_json(&json_str)
    }

    pub fn collect_baseline(&self, session_id: &str) -> CoreResult<WindowsBaselineSnapshot> {
        let json_str = self.run_native_or_ps("baseline-v3", PS_COLLECT_BASELINE, session_id)?;
        parse_baseline_json(&json_str)
    }

    pub fn collect_processes(&self, session_id: &str) -> CoreResult<WindowsProcessesSnapshot> {
        let json_str = self.run_native_or_ps("processes-v2", PS_COLLECT_PROCESSES, session_id)?;
        parse_processes_json(&json_str)
    }

    pub fn collect_network(&self, session_id: &str) -> CoreResult<WindowsNetworkSnapshot> {
        let json_str = self.run_native_or_ps("network-v2", PS_COLLECT_NETWORK, session_id)?;
        parse_network_json(&json_str)
    }

    pub fn inspect_process(
        &self,
        pid: u32,
        start_time: &str,
        session_id: &str,
    ) -> CoreResult<WindowsProcessInspection> {
        let script = lovelyhawk_win_dvc::windows_read_queries::process_inspection(pid, start_time)
            .ok_or_else(|| {
                CoreError::validation("windows_incident.process", "进程身份无效，请刷新列表")
            })?;
        let raw = self.run_native_or_ps(
            &format!("inspect-process:{pid}:{start_time}"),
            &script,
            session_id,
        )?;
        parse_process_inspection(&raw, pid, start_time)
    }

    pub fn collect_startup(&self, session_id: &str) -> CoreResult<WindowsStartupSnapshot> {
        self.collect_startup_catalog(session_id)
    }

    pub fn collect_accounts(&self, session_id: &str) -> CoreResult<WindowsAccountsSnapshot> {
        let json_str = self.run_native_or_ps(
            "accounts-v2",
            lovelyhawk_win_dvc::windows_read_queries::ACCOUNTS,
            session_id,
        )?;
        parse_accounts_json(&json_str)
    }

    pub fn collect_logs(
        &self,
        category: &str,
        session_id: &str,
    ) -> CoreResult<WindowsLogsSnapshot> {
        let script = lovelyhawk_win_dvc::windows_read_queries::logs(category)
            .ok_or_else(|| CoreError::validation("windows_incident.logs", "不支持的日志类别"))?;
        let json_str =
            self.run_native_or_ps(&format!("logs-v2:{category}"), &script, session_id)?;
        parse_logs_json(&json_str, category)
    }

    pub fn collect_files(
        &self,
        dir_path: &str,
        session_id: &str,
    ) -> CoreResult<WindowsFilesSnapshot> {
        if dir_path.trim().is_empty()
            || dir_path.len() > 1024
            || dir_path.contains(['\0', '\r', '\n'])
        {
            return Err(CoreError::validation(
                "windows_incident.files",
                "目录路径无效",
            ));
        }
        let script = build_files_ps_script(dir_path);
        let json_str =
            self.run_native_or_ps(&format!("files-v2:{dir_path}"), &script, session_id)?;
        parse_files_json(&json_str)
    }

    pub fn preview_file(
        &self,
        file_path: &str,
        session_id: &str,
    ) -> CoreResult<WindowsFilePreview> {
        let path = file_path.trim();
        if path.is_empty() || path.len() > 1024 || path.contains(['\0', '\r', '\n']) {
            return Err(CoreError::validation(
                "windows_incident.preview",
                "文件路径无效",
            ));
        }
        let script = build_file_preview_ps_script(path);
        let json_str =
            self.run_native_or_ps(&format!("preview-file:{path}"), &script, session_id)?;
        parse_file_preview_json(&json_str)
    }

    pub fn inspect_file_access(
        &self,
        path: &str,
        session_id: &str,
    ) -> CoreResult<WindowsFileAccess> {
        if path.is_empty() || path.len() > 1024 || path.contains(['\0', '\r', '\n']) {
            return Err(CoreError::validation("windows file access", "文件路径无效"));
        }
        let script = include_str!("windows_incident/file_access.ps1")
            .replace("__PATH__", &BASE64.encode(path.as_bytes()));
        let raw = self
            .hub
            .execute_command_for_session(
                &encode_powershell_command(&script),
                DEFAULT_COLLECTION_TIMEOUT,
                session_id,
            )
            .map_err(|_| CoreError::validation("windows file access", "文件访问诊断未完成"))?;
        let output = strip_exit_prefix(&raw)?;
        if output.len() > 512 * 1024 {
            return Err(CoreError::validation("windows file access", "诊断返回超限"));
        }
        let result: WindowsFileAccess = serde_json::from_str(&output)
            .map_err(|_| CoreError::validation("windows file access", "文件访问诊断返回不完整"))?;
        if result.path.len() > 4096
            || result.owner.len() > 4096
            || result.attributes.len() > 4096
            || result.observed_at.len() > 64
            || result.access_rules.len() > 64
            || result.processes.len() > 256
            || result.services.len() > 256
            || result.warnings.len() > 16
            || result.warnings.iter().any(|v| v.len() > 4096)
            || result.access_rules.iter().any(|v| {
                v.identity.len() > 4096
                    || v.rights.len() > 4096
                    || !matches!(v.access.as_str(), "Allow" | "Deny")
            })
            || result.processes.iter().any(|v| v.name.len() > 4096)
            || result.services.iter().any(|v| {
                v.name.len() > 4096
                    || v.display_name.len() > 4096
                    || v.path.len() > 32768
                    || v.state.len() > 64
                    || v.start_mode.len() > 64
                    || !matches!(v.kind.as_str(), "driver" | "service")
            })
        {
            return Err(CoreError::validation("windows file access", "诊断范围超限"));
        }
        Ok(result)
    }

    pub fn collect_registry(
        &self,
        key_path: &str,
        session_id: &str,
    ) -> CoreResult<WindowsRegistrySnapshot> {
        let script = lovelyhawk_win_dvc::windows_read_queries::registry(key_path)
            .ok_or_else(|| CoreError::validation("windows_incident.registry", "注册表路径无效"))?;
        let json_str =
            self.run_native_or_ps(&format!("registry-v2:{key_path}"), &script, session_id)?;
        parse_registry_json(&json_str)
    }

    fn run_ps_mutation(&self, ps_script: &str, session_id: &str) -> CoreResult<String> {
        let wrapped = format!(
            "$ErrorActionPreference = 'Stop'\ntry {{\n{ps_script}\nWrite-Output '__OK__'\n}} catch {{\n  Write-Output ('[error] ' + $_.Exception.Message)\n}}"
        );
        let cmd = encode_powershell_command(&wrapped);
        let raw = self
            .hub
            .execute_command_for_session(&cmd, DEFAULT_COLLECTION_TIMEOUT, session_id)
            .map_err(|e| CoreError::validation("windows_incident.action", e))?;
        let cleaned = strip_exit_prefix(&raw)?;
        for line in cleaned.lines() {
            if let Some(err) = line.trim().strip_prefix("[error]") {
                return Err(CoreError::validation(
                    "windows_incident.action",
                    format!("远程处置未完成: {}", err.trim()),
                ));
            }
        }
        if !cleaned.contains("__OK__") {
            return Err(CoreError::validation(
                "windows_incident.action",
                "远程处置未返回完成确认，请检查当前会话权限后重试",
            ));
        }
        Ok(cleaned)
    }

    pub fn kill_process(
        &self,
        pid: u32,
        start_time: &str,
        session_id: &str,
    ) -> CoreResult<WindowsProcessesSnapshot> {
        let script = build_kill_process_ps_script(pid, start_time).ok_or_else(|| {
            CoreError::validation(
                "windows_incident.kill_process",
                "进程身份参数无效或属于受保护系统进程",
            )
        })?;
        self.run_ps_mutation(&script, session_id)?;
        self.collect_processes(session_id)
    }

    pub fn remove_startup(
        &self,
        source_type: &str,
        name: &str,
        location: &str,
        session_id: &str,
    ) -> CoreResult<WindowsStartupSnapshot> {
        let script =
            build_remove_startup_ps_script(source_type, name, location).ok_or_else(|| {
                CoreError::validation(
                    "windows_incident.remove_startup",
                    "启动项参数无效或属于系统核心登录键（请前往注册表模块人工核实）",
                )
            })?;
        self.run_ps_mutation(&script, session_id)?;
        self.collect_startup(session_id)
    }

    pub fn disable_account(
        &self,
        name: &str,
        sid: &str,
        session_id: &str,
    ) -> CoreResult<WindowsAccountsSnapshot> {
        let script = build_disable_account_ps_script(name, sid).ok_or_else(|| {
            CoreError::validation("windows_incident.disable_account", "账户名称或 SID 无效")
        })?;
        self.run_ps_mutation(&script, session_id)?;
        self.collect_accounts(session_id)
    }

    pub fn delete_file(
        &self,
        file_path: &str,
        dir_path: &str,
        session_id: &str,
    ) -> CoreResult<WindowsFilesSnapshot> {
        let script = build_delete_file_ps_script(file_path, dir_path).ok_or_else(|| {
            CoreError::validation(
                "windows_incident.delete_file",
                "文件路径无效或属于受保护系统目录根路径",
            )
        })?;
        self.run_ps_mutation(&script, session_id)?;
        self.collect_files(dir_path, session_id)
    }

    pub fn delete_registry_value(
        &self,
        key_path: &str,
        value_name: &str,
        session_id: &str,
    ) -> CoreResult<WindowsRegistrySnapshot> {
        let script =
            build_delete_registry_value_ps_script(key_path, value_name).ok_or_else(|| {
                CoreError::validation(
                    "windows_incident.delete_registry_value",
                    "注册表路径或值名称无效，或属于受保护系统登录项",
                )
            })?;
        self.run_ps_mutation(&script, session_id)?;
        self.collect_registry(key_path, session_id)
    }
}

pub fn build_kill_process_ps_script(pid: u32, start_time: &str) -> Option<String> {
    if pid <= 4 || !valid_process_identity(pid, start_time) {
        return None;
    }
    let escaped_start = start_time.replace('\'', "''");
    Some(format!(
        r#"
$targetPid = [uint32]{pid}
$expectedStart = '{escaped_start}'
$selfProc = Get-CimInstance Win32_Process -Filter "ProcessId=$PID" -OperationTimeoutSec 5
if ($targetPid -eq $PID -or ($selfProc -and [uint32]$selfProc.ParentProcessId -eq $targetPid)) {{
  throw '拒绝终止当前应急响应采集端进程自身。'
}}
$p = Get-CimInstance Win32_Process -Filter "ProcessId=$targetPid" -OperationTimeoutSec 8
if (-not $p -or -not $p.CreationDate -or $p.CreationDate.ToUniversalTime().ToString('o') -ne $expectedStart) {{
  throw '目标进程已退出或 PID 已被复用，请刷新进程列表后再核实。'
}}
$protected = @('system', 'idle', 'registry', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe', 'lsass.exe', 'winlogon.exe', 'fontdrvhost.exe', 'dwm.exe')
if ($protected -contains ([string]$p.Name).ToLowerInvariant()) {{
  throw "拒绝终止系统核心进程 ($($p.Name))，以免导致系统崩溃或会话中断。"
}}
Stop-Process -Id $targetPid -Force -ErrorAction Stop
for ($i = 0; $i -lt 10; $i++) {{
  $check = Get-CimInstance Win32_Process -Filter "ProcessId=$targetPid" -OperationTimeoutSec 3 -ErrorAction SilentlyContinue
  if (-not $check -or -not $check.CreationDate -or $check.CreationDate.ToUniversalTime().ToString('o') -ne $expectedStart) {{ break }}
  Start-Sleep -Milliseconds 100
}}
$still = Get-CimInstance Win32_Process -Filter "ProcessId=$targetPid" -OperationTimeoutSec 5 -ErrorAction SilentlyContinue
if ($still -and $still.CreationDate -and $still.CreationDate.ToUniversalTime().ToString('o') -eq $expectedStart) {{
  throw '已发送终止信号，但目标进程仍在运行（可能受系统保护或权限不足）。'
}}
"#
    ))
}

fn canonical_registry_provider(key_path: &str) -> Option<(String, String)> {
    let trimmed = key_path.trim();
    if trimmed.is_empty() || trimmed.len() > 1024 || trimmed.contains(['\0', '\r', '\n']) {
        return None;
    }
    let upper = trimmed.to_ascii_uppercase();
    let (alias, hive, suffix) = [
        ("HKLM", "HKEY_LOCAL_MACHINE"),
        ("HKCU", "HKEY_CURRENT_USER"),
        ("HKU", "HKEY_USERS"),
        ("HKCR", "HKEY_CLASSES_ROOT"),
        ("HKCC", "HKEY_CURRENT_CONFIG"),
    ]
    .into_iter()
    .find_map(|(alias, hive)| {
        [
            format!("{alias}:\\"),
            format!("{alias}\\"),
            format!("{hive}\\"),
        ]
        .iter()
        .find(|prefix| upper.starts_with(prefix.as_str()))
        .map(|prefix| (alias, hive, trimmed[prefix.len()..].trim_end_matches('\\')))
    })?;
    if suffix.is_empty() {
        return None;
    }
    Some((
        format!("{alias}:\\{suffix}"),
        format!("Registry::{hive}\\{suffix}"),
    ))
}

pub fn build_delete_registry_value_ps_script(key_path: &str, value_name: &str) -> Option<String> {
    let (canonical, provider) = canonical_registry_provider(key_path)?;
    if value_name.is_empty() || value_name.len() > 512 || value_name.contains(['\0', '\r', '\n']) {
        return None;
    }
    let canonical_lower = canonical.to_ascii_lowercase();
    let val_lower = value_name.to_ascii_lowercase();
    if canonical_lower.ends_with("\\winlogon")
        && matches!(
            val_lower.as_str(),
            "shell" | "userinit" | "winlogon\\shell" | "winlogon\\userinit"
        )
    {
        return None;
    }
    let escaped_provider = provider.replace('\'', "''");
    let escaped_name = value_name.replace('\'', "''");
    Some(format!(
        r#"
$provider = '{escaped_provider}'
$valName = '{escaped_name}'
$item = Get-Item -LiteralPath $provider -ErrorAction Stop
if ($item.GetValueNames() -notcontains $valName) {{
  throw '目标注册表值不存在或已被删除，请刷新注册表键后核实。'
}}
Remove-ItemProperty -LiteralPath $provider -Name $valName -Force -ErrorAction Stop
$after = Get-Item -LiteralPath $provider -ErrorAction Stop
if ($after.GetValueNames() -contains $valName) {{
  throw '注册表键值删除未生效，请检查当前账户权限。'
}}
"#
    ))
}

pub fn build_remove_startup_ps_script(
    source_type: &str,
    name: &str,
    location: &str,
) -> Option<String> {
    let src = source_type.trim().to_ascii_lowercase();
    let name_trimmed = name.trim();
    let loc_trimmed = location.trim();
    if name_trimmed.is_empty()
        || name_trimmed.len() > 512
        || loc_trimmed.is_empty()
        || loc_trimmed.len() > 1024
        || name_trimmed.contains(['\0', '\r', '\n'])
        || loc_trimmed.contains(['\0', '\r', '\n'])
    {
        return None;
    }
    if src == "registry" || src == "registry run" {
        return build_delete_registry_value_ps_script(loc_trimmed, name_trimmed);
    }
    if src == "startup-folder" || src == "startup folder" {
        if name_trimmed.contains(['\\', '/']) || name_trimmed == "." || name_trimmed == ".." {
            return None;
        }
        let escaped_name = name_trimmed.replace('\'', "''");
        let escaped_loc = loc_trimmed.replace('\'', "''");
        return Some(format!(
            r#"
$loc = '{escaped_loc}'
$fileName = '{escaped_name}'
$dir = if ($loc -ieq 'Startup') {{
  Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'
}} elseif ($loc -ieq 'Common Startup') {{
  'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp'
}} else {{
  [Environment]::ExpandEnvironmentVariables($loc)
}}
$full = Join-Path $dir $fileName
if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {{
  throw "未找到启动目录文件: $full"
}}
$item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
try {{ $item.Attributes = [System.IO.FileAttributes]::Normal }} catch {{}}
Remove-Item -LiteralPath $item.FullName -Force -ErrorAction Stop
if (Test-Path -LiteralPath $item.FullName) {{
  throw '启动目录文件删除后仍存在，可能被占用或权限不足。'
}}
"#
        ));
    }
    if src == "scheduled-task" || src == "scheduled task" {
        if name_trimmed.eq_ignore_ascii_case("Microsoft")
            || loc_trimmed
                .to_ascii_lowercase()
                .starts_with("\\microsoft\\")
        {
            return None;
        }
        let escaped_name = name_trimmed.replace('\'', "''");
        let escaped_loc = loc_trimmed.replace('\'', "''");
        return Some(format!(
            r#"
$taskName = '{escaped_name}'
$loc = '{escaped_loc}'
$taskPath = if ($loc -ieq 'C:\Windows\System32\Tasks' -or [string]::IsNullOrWhiteSpace($loc)) {{ '\' }} elseif ($loc.EndsWith('\')) {{ $loc }} else {{ "$loc\" }}
if ($taskPath -like '\Microsoft\*') {{
  throw '安全限制：拒绝移除系统内置 Microsoft 计划任务。'
}}
Unregister-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Confirm:$false -ErrorAction Stop
"#
        ));
    }
    if src == "service" {
        let escaped_name = name_trimmed.replace('\'', "''");
        return Some(format!(
            r#"
$svcName = '{escaped_name}'
$protected = @('rpcss', 'dcomlaunch', 'LSM', 'samss', 'eventlog', 'plugplay', 'bfe', 'mpssvc', 'termservice', 'windefend')
if ($protected -contains $svcName.ToLowerInvariant()) {{
  throw "拒绝停止或禁用系统关键服务 ($svcName)。"
}}
Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
Set-Service -Name $svcName -StartupType Disabled -ErrorAction Stop
"#
        ));
    }
    None
}

pub fn build_disable_account_ps_script(name: &str, sid: &str) -> Option<String> {
    let name_trimmed = name.trim();
    let sid_trimmed = sid.trim();
    if name_trimmed.is_empty()
        || name_trimmed.len() > 256
        || sid_trimmed.len() < 6
        || sid_trimmed.len() > 128
        || name_trimmed.contains(['\0', '\r', '\n'])
        || !sid_trimmed.starts_with("S-1-")
        || !sid_trimmed[4..]
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'-')
    {
        return None;
    }
    let escaped_name = name_trimmed.replace('\'', "''");
    let escaped_sid = sid_trimmed.replace('\'', "''");
    Some(format!(
        r#"
$targetSid = '{escaped_sid}'
$expectedName = '{escaped_name}'
$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($targetSid -eq $currentSid -or $expectedName -ieq $env:USERNAME) {{
  throw '安全限制：拒绝禁用当前正在执行应急响应的会话登录账户。'
}}
$u = Get-LocalUser -SID $targetSid -ErrorAction Stop
if ($u.Name -ne $expectedName) {{
  throw '目标账户名称与 SID 不匹配，请刷新账户列表后重试。'
}}
Disable-LocalUser -SID $targetSid -ErrorAction Stop
$after = Get-LocalUser -SID $targetSid -ErrorAction Stop
if ($after.Enabled) {{
  throw '禁用账户未生效，请检查管理员权限。'
}}
"#
    ))
}

pub fn build_delete_file_ps_script(file_path: &str, dir_path: &str) -> Option<String> {
    let f = file_path.trim();
    let d = dir_path.trim();
    if f.len() < 4
        || f.len() > 1024
        || d.is_empty()
        || d.len() > 1024
        || f.contains(['\0', '\r', '\n'])
        || d.contains(['\0', '\r', '\n'])
    {
        return None;
    }
    let bytes = f.as_bytes();
    let absolute_path =
        bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && matches!(bytes[2], b'\\' | b'/');
    if !(absolute_path || f.starts_with('%')) {
        return None;
    }
    let normalized = f.replace('/', "\\");
    if normalized
        .split('\\')
        .any(|seg| seg == ".." || seg.is_empty() && normalized.ends_with(":\\"))
    {
        return None;
    }
    let lower = normalized.to_ascii_lowercase();
    if let Some(leaf) = lower.strip_prefix("c:\\windows\\system32\\")
        && !leaf.contains('\\')
        && matches!(
            leaf,
            "ntoskrnl.exe"
                | "hal.dll"
                | "kernel32.dll"
                | "kernelbase.dll"
                | "ntdll.dll"
                | "user32.dll"
                | "advapi32.dll"
                | "cmd.exe"
                | "powershell.exe"
                | "mstsc.exe"
                | "svchost.exe"
                | "lsass.exe"
                | "services.exe"
                | "wininit.exe"
                | "winlogon.exe"
                | "csrss.exe"
                | "smss.exe"
                | "explorer.exe"
        )
    {
        return None;
    }
    let escaped = f.replace('\'', "''");
    Some(format!(
        r#"
$rawPath = [Environment]::ExpandEnvironmentVariables('{escaped}')
if (-not (Test-Path -LiteralPath $rawPath)) {{
  throw '目标文件不存在或已被移除，请刷新目录后核实。'
}}
$item = Get-Item -LiteralPath $rawPath -Force -ErrorAction Stop
if ($item.PSIsContainer) {{
  throw '安全限制：快速删除仅限单个文件，不支持递归删除文件夹。'
}}
if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {{
  throw '安全限制：目标为符号链接或重解析点，已拒绝删除。'
}}
try {{ $item.Attributes = [System.IO.FileAttributes]::Normal }} catch {{}}
Remove-Item -LiteralPath $item.FullName -Force -ErrorAction Stop
if (Test-Path -LiteralPath $item.FullName) {{
  throw '文件删除未完成，可能被活跃进程锁定（请先结束对应进程）或权限不足。'
}}
"#
    ))
}

/// The session agent beside the running executable, when it is shipped there.
pub fn agent_executable_path() -> Option<std::path::PathBuf> {
    let directory = std::env::current_exe().ok()?.parent()?.to_path_buf();
    let agent = directory.join(if cfg!(windows) {
        "lovelyhawk-win-agent.exe"
    } else {
        "lovelyhawk-win-agent"
    });
    agent.is_file().then_some(agent)
}

/// Encode a PowerShell snippet into a universal `powershell.exe -EncodedCommand <B64>` invocation.
///
/// Works identically across:
/// - the fileless PowerShell DVC agent
/// - the standalone Rust `lovelyhawk-win-agent.exe`
/// - the Python `demo_server.py`
pub fn encode_powershell_command(ps_script: &str) -> String {
    let wrapped = format!(
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; $ErrorActionPreference = 'SilentlyContinue'; {ps_script}"
    );
    let utf16: Vec<u8> = wrapped
        .encode_utf16()
        .flat_map(|w| w.to_le_bytes())
        .collect();
    let b64 = BASE64.encode(&utf16);
    format!("powershell.exe -NoProfile -NonInteractive -EncodedCommand {b64}")
}

fn strip_exit_prefix(raw: &str) -> CoreResult<String> {
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix("[error]") {
        return Err(CoreError::validation(
            "windows_incident.remote",
            format!("远程执行错误: {}", rest.trim()),
        ));
    }
    if let Some(after_bracket) = trimmed.strip_prefix("[exit=")
        && let Some(newline_pos) = after_bracket.find(']')
    {
        let body = after_bracket[newline_pos + 1..].trim();
        return Ok(body.to_owned());
    }
    Ok(trimmed.to_owned())
}

/// Generate the self-contained, fileless PowerShell script that connects to the DVC channel
/// from inside a remote Windows RDP session using inline C# P/Invoke of `wtsapi32.dll`.
pub fn fileless_powershell_script() -> String {
    let bytes: Vec<u8> = fileless_powershell_source()
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    format!(
        "powershell.exe -NoLogo -NoProfile -EncodedCommand {}",
        BASE64.encode(bytes)
    )
}

pub fn fileless_powershell_source() -> String {
    r#"# LovelyHawk Windows 应急响应 - 免落地 RDP DVC 会话采集端
# 用法：在远程 RDP 会话内打开 PowerShell，直接粘贴本脚本回车即可连接。
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Continue'

if (-not ('LovelyHawkDvcNative' -as [type])) {
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class LovelyHawkDvcNative {
    public const uint WTS_CURRENT_SESSION = 0xFFFFFFFF;
    public const uint WTS_CHANNEL_OPTION_DYNAMIC = 0x00000001;

    [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    public static extern IntPtr WTSVirtualChannelOpenEx(
        uint SessionId,
        string pVirtualName,
        uint flags);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    public static extern bool WTSVirtualChannelRead(
        IntPtr hChannelHandle,
        uint TimeOut,
        byte[] Buffer,
        uint BufferSize,
        out uint pBytesRead);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    public static extern bool WTSVirtualChannelWrite(
        IntPtr hChannelHandle,
        byte[] Buffer,
        uint Length,
        out uint pBytesWritten);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    public static extern bool WTSVirtualChannelClose(IntPtr hChannelHandle);
}
"@
}

$script:seq = 1
function Send-DvcFrame([hashtable]$obj) {
    $obj['from'] = 'server'
    $obj['seq'] = $script:seq
    $script:seq++
    $json = ($obj | ConvertTo-Json -Depth 10 -Compress)
    $body = [System.Text.Encoding]::UTF8.GetBytes($json)
    $lenBytes = [BitConverter]::GetBytes([uint32]$body.Length)
    $frame = New-Object byte[] ($body.Length + 4)
    [Array]::Copy($lenBytes, 0, $frame, 0, 4)
    [Array]::Copy($body, 0, $frame, 4, $body.Length)
    $written = [uint32]0
    $ok = [LovelyHawkDvcNative]::WTSVirtualChannelWrite($ch, $frame, [uint32]$frame.Length, [ref]$written)
    if (-not $ok -or $written -ne $frame.Length) { throw '通道写入未完成，请重新连接。' }
}

function Invoke-DvcCommand([string]$cmdText) {
    $oldPref = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    try {
        if ($cmdText.StartsWith('__NATIVE_COLLECT__:')) { return '[error] 此采集端使用 PowerShell 查询' }
        if ($cmdText -match '-EncodedCommand\s+([A-Za-z0-9+/=]+)') {
            $b64 = $Matches[1]
            $scriptText = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b64))
            Write-Host "[*] 正在进程内执行 PowerShell 采集脚本..." -ForegroundColor Cyan
            $res = & ([scriptblock]::Create($scriptText)) | Out-String -Width 8192
            return "[exit=0]`n" + ([string]$res).Trim()
        } else {
            Write-Host "[*] 正在执行已确认的命令..." -ForegroundColor Cyan
            $res = & cmd.exe /c $cmdText 2>&1 | Out-String -Width 8192
            return "[exit=0]`n" + ([string]$res).Trim()
        }
    } catch {
        return "[error] " + $_.Exception.Message
    } finally {
        $ErrorActionPreference = $oldPref
    }
}

# The channel closes when the RDP session disconnects or the workbench restarts;
# the agent opens it again with a growing delay until Ctrl+C. Old commands are never replayed.
$delay = 1
$hinted = $false
while ($true) {
    $ch = [LovelyHawkDvcNative]::WTSVirtualChannelOpenEx(
        [LovelyHawkDvcNative]::WTS_CURRENT_SESSION,
        "dvc::lovelyhawk::winir",
        [LovelyHawkDvcNative]::WTS_CHANNEL_OPTION_DYNAMIC)
    if ($ch -eq [IntPtr]::Zero) {
        $ch = [LovelyHawkDvcNative]::WTSVirtualChannelOpenEx(
            [LovelyHawkDvcNative]::WTS_CURRENT_SESSION,
            "dvc::demo::chat",
            [LovelyHawkDvcNative]::WTS_CHANNEL_OPTION_DYNAMIC)
    }
    if ($ch -eq [IntPtr]::Zero) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if (-not $hinted) {
            Write-Host "[!] WTSVirtualChannelOpenEx 失败 (Win32 Error=$err)。请确认：" -ForegroundColor Red
            Write-Host "    1. 当前窗口运行在远程桌面 (RDP) 会话中" -ForegroundColor Yellow
            Write-Host "    2. 客户端 LovelyHawk 已注册 RDP 插件并开启 DVC 监听" -ForegroundColor Yellow
            $hinted = $true
        } else {
            Write-Host "[!] 通道仍未就绪 (Win32 Error=$err)" -ForegroundColor Yellow
        }
        Write-Host "[*] $delay 秒后重试；按 Ctrl+C 退出。" -ForegroundColor Yellow
        Start-Sleep -Seconds $delay
        $delay = [Math]::Min($delay * 2, 30)
        continue
    }

    Write-Host "[+] LovelyHawk DVC 通道已连接！正在等待应急响应工作台指令 (按 Ctrl+C 退出)..." -ForegroundColor Green
    $hinted = $false
    $started = Get-Date
    $readBuf = New-Object byte[] 4096
    $pduStream = New-Object System.IO.MemoryStream
    [byte[]]$frameAcc = @()
    $recvFileStream = $null
    $recvFilePath = $null

    try {
        while ($true) {
            $n = [uint32]0
            $ok = [LovelyHawkDvcNative]::WTSVirtualChannelRead($ch, 2000, $readBuf, [uint32]$readBuf.Length, [ref]$n)
            if (-not $ok) {
                $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                if ($err -eq 1460 -or $err -eq 996 -or $err -eq 0) { continue }
                Write-Host "[!] 通道读取结束 (code=$err)" -ForegroundColor Yellow
                break
            }
            if ($n -eq 0) { continue }
            if ($n -lt 8) { continue }
            $flags = [BitConverter]::ToUInt32($readBuf, 4)
            if (($flags -band 1) -ne 0) {
                $pduStream.SetLength(0)
                $pduStream.Position = 0
            }
            if ($pduStream.Length + $n - 8 -gt 16777220) { throw '通道数据超限' }
            $pduStream.Write($readBuf, 8, [int]($n - 8))
            if (($flags -band 2) -eq 0) { continue }

            $pduBytes = $pduStream.ToArray()
            $pduStream.SetLength(0)
            $pduStream.Position = 0

            if ($frameAcc.Length -eq 0) {
                $frameAcc = $pduBytes
            } else {
                $combined = New-Object byte[] ($frameAcc.Length + $pduBytes.Length)
                [Array]::Copy($frameAcc, 0, $combined, 0, $frameAcc.Length)
                [Array]::Copy($pduBytes, 0, $combined, $frameAcc.Length, $pduBytes.Length)
                $frameAcc = $combined
            }

            while ($frameAcc.Length -ge 4) {
                $fLen = [BitConverter]::ToUInt32($frameAcc, 0)
                if ($fLen -gt 16777216) { throw '通道消息超限' }
                if ($frameAcc.Length -lt (4 + $fLen)) { break }
                $msgJson = [System.Text.Encoding]::UTF8.GetString($frameAcc, 4, [int]$fLen)
                $remLen = $frameAcc.Length - (4 + [int]$fLen)
                if ($remLen -gt 0) {
                    $rest = New-Object byte[] $remLen
                    [Array]::Copy($frameAcc, 4 + [int]$fLen, $rest, 0, $remLen)
                    $frameAcc = $rest
                } else {
                    $frameAcc = @()
                }

                $msg = $msgJson | ConvertFrom-Json
                if ($msg.type -eq 'cmd') {
                    $outText = Invoke-DvcCommand ([string]$msg.text)
                    Send-DvcFrame @{ type = 'result'; text = $outText }
                } elseif ($msg.type -eq 'file_start') {
                    $recvDir = Join-Path (Get-Location).Path 'recv'
                    New-Item -ItemType Directory -Force -Path $recvDir | Out-Null
                    $safeName = [System.IO.Path]::GetFileName([string]$msg.name)
                    $recvFilePath = Join-Path $recvDir $safeName
                    $recvFileStream = [System.IO.File]::Open($recvFilePath, [System.IO.FileMode]::Create)
                    Write-Host "[recv] <- $safeName ($($msg.size) bytes)" -ForegroundColor Cyan
                } elseif ($msg.type -eq 'file_chunk' -and $null -ne $recvFileStream) {
                    $chunkBytes = [Convert]::FromBase64String([string]$msg.b64)
                    $recvFileStream.Write($chunkBytes, 0, $chunkBytes.Length)
                } elseif ($msg.type -eq 'file_end' -and $null -ne $recvFileStream) {
                    $recvFileStream.Close()
                    $recvFileStream = $null
                    Write-Host "[recv] 已保存至: $recvFilePath" -ForegroundColor Green
                } else {
                    Write-Host "<- [$($msg.from)]: $($msg.text)" -ForegroundColor Gray
                }
            }
        }
    } catch {
        Write-Host "[!] 通道异常：$($_.Exception.Message)" -ForegroundColor Yellow
    } finally {
        if ($null -ne $recvFileStream) { $recvFileStream.Close() }
        [void][LovelyHawkDvcNative]::WTSVirtualChannelClose($ch)
        Write-Host "[*] DVC 通道已关闭。" -ForegroundColor Yellow
    }
    if (((Get-Date) - $started).TotalSeconds -ge 30) { $delay = 1 }
    Write-Host "[*] $delay 秒后自动重连；按 Ctrl+C 退出。旧指令不会重放。" -ForegroundColor Yellow
    Start-Sleep -Seconds $delay
    $delay = [Math]::Min($delay * 2, 30)
}
"#
    .to_owned()
}

// ---------------------------------------------------------------------------
// PowerShell Collectors & Rust Risk Analyzers
// ---------------------------------------------------------------------------

const PS_COLLECT_OVERVIEW: &str = lovelyhawk_win_dvc::windows_read_queries::OVERVIEW;

pub fn parse_overview_json(json_str: &str) -> CoreResult<WindowsOverviewSnapshot> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct RawOverview {
        #[serde(default)]
        hostname: String,
        #[serde(default)]
        os_caption: String,
        #[serde(default)]
        os_version: String,
        #[serde(default)]
        architecture: String,
        #[serde(default)]
        domain_or_workgroup: String,
        #[serde(default)]
        part_of_domain: bool,
        #[serde(default)]
        current_user: String,
        #[serde(default)]
        is_elevated: bool,
        #[serde(default)]
        session_name: String,
        #[serde(default)]
        boot_time: String,
        #[serde(default)]
        uptime_hours: u64,
        #[serde(default)]
        cpu_name: String,
        #[serde(default)]
        cpu_cores: u32,
        #[serde(default)]
        cpu_load_percent: u32,
        #[serde(default)]
        memory_total_mb: u64,
        #[serde(default)]
        memory_used_mb: u64,
        #[serde(default)]
        memory_usage_percent: u32,
        #[serde(default)]
        system_drive_free_gb: u64,
        #[serde(default)]
        system_drive_total_gb: u64,
        #[serde(default)]
        defender_enabled: Option<bool>,
        #[serde(default)]
        realtime_protection: Option<bool>,
        #[serde(default)]
        firewall_domain_enabled: Option<bool>,
        #[serde(default)]
        firewall_private_enabled: Option<bool>,
        #[serde(default)]
        firewall_public_enabled: Option<bool>,
        #[serde(default)]
        facts: Vec<WindowsHostFact>,
        #[serde(default)]
        warnings: Vec<String>,
    }

    let raw: RawOverview = serde_json::from_str(extract_json_slice(json_str)).map_err(|e| {
        CoreError::validation(
            "windows_incident.overview",
            format!("解析主机总览 JSON 失败: {e}"),
        )
    })?;

    let mut high_risk_count = 0;
    let mut medium_risk_count = 0;
    let mut highlights = Vec::new();

    if raw.realtime_protection == Some(false) {
        high_risk_count += 1;
        highlights.push("Windows Defender 实时保护当前处于关闭状态".to_owned());
    }
    if [
        raw.firewall_domain_enabled,
        raw.firewall_public_enabled,
        raw.firewall_private_enabled,
    ]
    .contains(&Some(false))
    {
        medium_risk_count += 1;
        highlights.push("部分 Windows 防火墙网络配置文件未启用".to_owned());
    }
    if !raw.is_elevated {
        highlights.push("当前 RDP 会话未以管理员权限运行，部分安全日志和系统项可能受限".to_owned());
    }
    if [
        raw.defender_enabled,
        raw.realtime_protection,
        raw.firewall_domain_enabled,
        raw.firewall_private_enabled,
        raw.firewall_public_enabled,
    ]
    .contains(&None)
    {
        highlights.push("部分防护状态未能读取，不能据此判定已开启或已关闭".to_owned());
    }
    if raw.facts.len() > 256
        || raw.warnings.len() > 64
        || raw
            .facts
            .iter()
            .any(|f| f.group.len() > 256 || f.label.len() > 1024 || f.value.len() > 32 * 1024)
    {
        return Err(CoreError::validation(
            "windows_incident.overview",
            "主机信息超过上限",
        ));
    }
    if highlights.is_empty() {
        highlights.push(
            "防病毒实时保护与防火墙核心配置已开启，建议继续核查进程、启动项与安全事件日志"
                .to_owned(),
        );
    }

    Ok(WindowsOverviewSnapshot {
        hostname: raw.hostname,
        os_caption: raw.os_caption,
        os_version: raw.os_version,
        architecture: raw.architecture,
        domain_or_workgroup: raw.domain_or_workgroup,
        part_of_domain: raw.part_of_domain,
        current_user: raw.current_user,
        is_elevated: raw.is_elevated,
        session_name: raw.session_name,
        boot_time: raw.boot_time,
        uptime_hours: raw.uptime_hours,
        cpu_name: raw.cpu_name,
        cpu_cores: raw.cpu_cores,
        cpu_load_percent: raw.cpu_load_percent,
        memory_total_mb: raw.memory_total_mb,
        memory_used_mb: raw.memory_used_mb,
        memory_usage_percent: raw.memory_usage_percent,
        system_drive_free_gb: raw.system_drive_free_gb,
        system_drive_total_gb: raw.system_drive_total_gb,
        defender_enabled: raw.defender_enabled,
        realtime_protection: raw.realtime_protection,
        firewall_domain_enabled: raw.firewall_domain_enabled,
        firewall_private_enabled: raw.firewall_private_enabled,
        firewall_public_enabled: raw.firewall_public_enabled,
        high_risk_count,
        medium_risk_count,
        highlights,
        facts: raw.facts,
        warnings: raw.warnings,
    })
}

const PS_COLLECT_BASELINE: &str = lovelyhawk_win_dvc::windows_read_queries::BASELINE;

pub fn parse_baseline_json(json_str: &str) -> CoreResult<WindowsBaselineSnapshot> {
    let raw: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(extract_json_slice(json_str)).map_err(|e| {
            CoreError::validation(
                "windows_incident.baseline",
                format!("解析基线配置失败: {e}"),
            )
        })?;
    type RuleSpec = (
        &'static str,
        &'static str,
        &'static str,
        &'static str,
        &'static str,
        &'static [&'static str],
        &'static str,
    );
    let rules: &[RuleSpec] = &[
        (
            "rdp-nla",
            "远程桌面",
            "RDP 网络级身份验证 (NLA)",
            "rdpNla",
            "1",
            &["1"],
            "RDP-Tcp\\UserAuthentication；仅观察配置，仍需客户端连接复核。",
        ),
        (
            "rdp-encryption",
            "远程桌面",
            "RDP 加密级别",
            "rdpEnc",
            "3 或 4",
            &["3", "4"],
            "RDP-Tcp\\MinEncryptionLevel；FIPS 模式有兼容性前提，不建议盲目启用。",
        ),
        (
            "wdigest",
            "凭据保护",
            "WDigest 明文凭据缓存",
            "wdigest",
            "0",
            &["0"],
            "WDigest\\UseLogonCredential；缺失键时需结合系统版本判断默认行为。",
        ),
        (
            "lsass-ppl",
            "凭据保护",
            "LSA 受保护进程配置",
            "lsassPpl",
            "1 或 2",
            &["1", "2"],
            "Lsa\\RunAsPPL；注册表配置不能证明当前 LSASS 已受保护，值 2 依赖版本支持。",
        ),
        (
            "uac",
            "权限控制",
            "UAC 管理员批准模式",
            "uacLua",
            "1",
            &["1"],
            "Policies\\System\\EnableLUA；变更涉及重启和应用兼容性。",
        ),
        (
            "guest",
            "账户安全",
            "内置 Guest 账户",
            "guestEnabled",
            "false",
            &["false"],
            "按 SID 末尾 501 识别账户，禁用 Guest 可减少不必要的访客入口。",
        ),
        (
            "auto-logon",
            "账户安全",
            "Winlogon 自动登录",
            "autoLogon",
            "0",
            &["0"],
            "Winlogon\\AutoAdminLogon；不读取或返回 DefaultPassword。",
        ),
        (
            "smb1",
            "SMB",
            "SMBv1 服务端协议",
            "smb1",
            "0",
            &["0"],
            "Get-SmbServerConfiguration 的 EnableSMB1Protocol；不覆盖客户端组件或业务兼容性。",
        ),
        (
            "defender-rt",
            "防病毒",
            "Defender 实时保护",
            "defenderRealtime",
            "true",
            &["true"],
            "Get-MpComputerStatus 的 RealTimeProtectionEnabled；使用其他防病毒产品时需人工核对。",
        ),
        (
            "firewall",
            "防火墙",
            "三种网络配置文件防火墙",
            "fwDisabledCount",
            "0",
            &["0"],
            "Get-NetFirewallProfile -PolicyStore ActiveStore；只有三种配置均取得时才判定。",
        ),
        (
            "ps-scriptblock-logging",
            "日志审计",
            "PowerShell 脚本块日志",
            "psScriptBlock",
            "1",
            &["1"],
            "ScriptBlockLogging\\EnableScriptBlockLogging；记录可能含敏感业务文本，应设置访问与保留策略。",
        ),
        (
            "ps-module-logging",
            "日志审计",
            "PowerShell 模块日志开关",
            "psModuleLogging",
            "1",
            &["1"],
            "ModuleLogging\\EnableModuleLogging；还需核对 ModuleNames 的覆盖范围。",
        ),
        (
            "ps-transcription",
            "日志审计",
            "PowerShell 转录开关",
            "psTranscription",
            "1",
            &["1"],
            "Transcription\\EnableTranscripting；还需确认输出目录权限、保留时间与敏感信息访问。",
        ),
        (
            "uac-prompt",
            "权限控制",
            "管理员提权提示",
            "uacPrompt",
            "2 或 5",
            &["2", "5"],
            "Policies\\System\\ConsentPromptBehaviorAdmin；避免无提示静默提权。",
        ),
        (
            "uac-secure-desktop",
            "权限控制",
            "安全桌面提权提示",
            "secureDesktop",
            "1",
            &["1"],
            "Policies\\System\\PromptOnSecureDesktop；检查配置不触发提权。",
        ),
        (
            "uac-filter-admin",
            "权限控制",
            "内置管理员批准模式",
            "uacFilterAdmin",
            "1",
            &["1"],
            "Policies\\System\\FilterAdministratorToken；适用性需结合内置管理员的实际用途。",
        ),
        (
            "blank-password",
            "账户安全",
            "空口令限制为控制台登录",
            "limitBlankPasswords",
            "1",
            &["1"],
            "Lsa\\LimitBlankPasswordUse；不读取账户口令。",
        ),
        (
            "anonymous",
            "账户安全",
            "限制匿名枚举共享",
            "restrictAnonymous",
            "1 或 2",
            &["1", "2"],
            "Lsa\\RestrictAnonymous；变更前需评估历史系统及域兼容性。",
        ),
        (
            "anonymous-sam",
            "账户安全",
            "禁止匿名枚举 SAM",
            "restrictAnonymousSam",
            "1",
            &["1"],
            "Lsa\\RestrictAnonymousSAM；需与其他匿名访问策略共同核对。",
        ),
        (
            "ntlm",
            "凭据保护",
            "LAN Manager 身份验证级别",
            "lmCompatibility",
            "5",
            &["5"],
            "Lsa\\LmCompatibilityLevel；级别 5 拒绝 LM/NTLM，应先核查旧客户端兼容性。",
        ),
        (
            "lm-hash",
            "凭据保护",
            "不存储 LM 哈希配置",
            "noLmHash",
            "1",
            &["1"],
            "Lsa\\NoLMHash；启用不会清除已有哈希，需要相关账户后续更改口令。",
        ),
        (
            "smb-server-sign",
            "SMB",
            "服务端要求 SMB 签名",
            "smbSigning",
            "1",
            &["1"],
            "Get-SmbServerConfiguration.RequireSecuritySignature；连接策略和 SMB 加密需另行核对。",
        ),
        (
            "smb-client-sign",
            "SMB",
            "客户端要求 SMB 签名",
            "smbClientSigning",
            "1",
            &["1"],
            "Get-SmbClientConfiguration.RequireSecuritySignature；需评估旧 NAS 兼容性。",
        ),
        (
            "smb-insecure-guest",
            "SMB",
            "禁止不安全的 SMB 来宾登录",
            "smbGuest",
            "0",
            &["0"],
            "Get-SmbClientConfiguration.EnableInsecureGuestLogons；不推断服务端账户权限。",
        ),
        (
            "defender-tamper",
            "防病毒",
            "Defender 防篡改保护",
            "defenderTamper",
            "1",
            &["1"],
            "Get-MpComputerStatus.IsTamperProtected；产品、版本或管理模式不提供该属性时保持未知。",
        ),
        (
            "winrm-basic",
            "远程管理",
            "WinRM Basic 认证策略",
            "winrmBasic",
            "0",
            &["0"],
            "Policies\\Microsoft\\Windows\\WinRM\\Service\\AllowBasic；策略缺失不等于实际启用，需核查运行配置。",
        ),
        (
            "winrm-cleartext",
            "远程管理",
            "WinRM 非加密流量策略",
            "winrmUnencrypted",
            "0",
            &["0"],
            "Policies\\Microsoft\\Windows\\WinRM\\Service\\AllowUnencryptedTraffic；策略缺失不推断运行值。",
        ),
        (
            "remote-registry",
            "远程管理",
            "远程注册表服务启动方式",
            "remoteRegistry",
            "Disabled",
            &["Disabled"],
            "Get-Service RemoteRegistry.StartType；依赖此服务的管理软件需单独评估。",
        ),
        (
            "rdp-security-layer",
            "远程桌面",
            "RDP 要求 TLS 安全层",
            "rdpSecurityLayer",
            "2",
            &["2"],
            "RDP-Tcp\\SecurityLayer；配置不能代替证书与实际连接验证。",
        ),
        (
            "installer-machine",
            "权限控制",
            "本机 Windows Installer 提权策略",
            "alwaysInstallMachine",
            "0",
            &["0"],
            "HKLM Installer\\AlwaysInstallElevated；风险取决于 HKCU 同名策略，单项开启只是线索。",
        ),
        (
            "installer-user",
            "权限控制",
            "当前用户 Windows Installer 提权策略",
            "alwaysInstallUser",
            "0",
            &["0"],
            "HKCU Installer\\AlwaysInstallElevated；只观察当前运行采集端的用户。",
        ),
        (
            "autorun",
            "执行控制",
            "关闭各类驱动器自动运行",
            "autoRun",
            "255",
            &["255"],
            "Policies\\Explorer\\NoDriveTypeAutoRun；版本与其他 AutoPlay 策略需一起核对。",
        ),
    ];
    let mut items: Vec<_> = rules.iter().map(|(id, category, title, field, expected, allowed, description)| {
        let value = raw.get(*field).filter(|v| !v.is_null()).and_then(|v| match v {
            serde_json::Value::String(s) => Some(s.clone()),
            serde_json::Value::Bool(_) | serde_json::Value::Number(_) => Some(v.to_string()),
            _ => None,
        });
        let pass = value.as_deref().is_some_and(|v| allowed.contains(&v));
        let unknown = value.is_none() || (*id == "lsass-ppl" && value.as_deref() == Some("2") && raw.get("lsassPplValue2Supported").and_then(serde_json::Value::as_bool) != Some(true));
        WindowsBaselineItem {
            id: (*id).to_owned(), category: (*category).to_owned(), title: (*title).to_owned(),
            current_value: value.map(|v| format!("{field} = {v}")).unwrap_or_else(|| "未取得 / 未显式配置（无法判断）".to_owned()),
            expected_value: (*expected).to_owned(),
            status: if unknown { "unknown" } else if pass { "pass" } else { "fail" }.to_owned(),
            severity: if unknown { WindowsRiskLevel::Low } else if pass { WindowsRiskLevel::Normal } else if matches!(*id, "wdigest" | "smb1" | "guest" | "auto-logon" | "defender-rt") { WindowsRiskLevel::High } else { WindowsRiskLevel::Medium },
            description: (*description).to_owned(),
            recommendation: if unknown { "先核对当前系统版本、组件、读取权限及缺失配置的默认行为；未读取到的值不能算通过。" } else { "结合系统版本和业务依赖确认适用性，保留原配置后制定变更计划，并独立验证实际生效情况。" }.to_owned(),
            remediation_available: !unknown && !pass && baseline_change_supported(id),
        }
    }).collect();
    baseline::append_checks(&raw, &mut items);
    Ok(WindowsBaselineSnapshot {
        total_checks: items.len() as u32,
        passed_count: items.iter().filter(|i| i.status == "pass").count() as u32,
        failed_count: items.iter().filter(|i| i.status == "fail").count() as u32,
        warning_count: items.iter().filter(|i| i.status == "warn").count() as u32,
        unknown_count: items.iter().filter(|i| i.status == "unknown").count() as u32,
        not_applicable_count: items
            .iter()
            .filter(|i| i.status == "not-applicable")
            .count() as u32,
        items,
    })
}

const PS_COLLECT_PROCESSES: &str = lovelyhawk_win_dvc::windows_read_queries::PROCESSES;

pub fn valid_process_identity(pid: u32, start_time: &str) -> bool {
    pid > 0 && start_time.len() <= 64 && chrono::DateTime::parse_from_rfc3339(start_time).is_ok()
}

pub fn parse_process_inspection(
    raw: &str,
    pid: u32,
    start_time: &str,
) -> CoreResult<WindowsProcessInspection> {
    let invalid = || {
        CoreError::validation(
            "windows_incident.process",
            "进程关联结果不完整、超过上限或身份已变化",
        )
    };
    let mut value: serde_json::Value =
        serde_json::from_str(extract_json_slice(raw)).map_err(|_| invalid())?;
    let network = parse_network_json(&value.get("network").ok_or_else(invalid)?.to_string())?;
    if network.connections.len() > 2048 || network.connections.iter().any(|n| n.pid != pid) {
        return Err(invalid());
    }
    value["network"] = serde_json::to_value(network.connections).map_err(|_| invalid())?;
    let result: WindowsProcessInspection = serde_json::from_value(value).map_err(|_| invalid())?;
    let text_ok = |s: &str| s.len() <= 32 * 1024 && !s.contains('\0');
    if result.pid != pid
        || result.start_time != start_time
        || result.services.len() > 256
        || result.modules.len() > 512
        || result.warnings.len() > 64
        || result.warnings.iter().any(|s| !text_ok(s))
        || result.services.iter().any(|s| {
            [
                &s.name,
                &s.display_name,
                &s.path,
                &s.account,
                &s.state,
                &s.start_mode,
            ]
            .iter()
            .any(|s| !text_ok(s))
        })
        || result
            .modules
            .iter()
            .any(|m| !text_ok(&m.name) || !text_ok(&m.path))
        || chrono::DateTime::parse_from_rfc3339(&result.observed_at).is_err()
        || result.user.len() > 1024
    {
        return Err(invalid());
    }
    Ok(result)
}

pub fn parse_processes_json(json_str: &str) -> CoreResult<WindowsProcessesSnapshot> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct RawProc {
        #[serde(default)]
        pid: u32,
        #[serde(default)]
        ppid: u32,
        #[serde(default)]
        name: String,
        #[serde(default)]
        executable_path: String,
        #[serde(default)]
        command_line: String,
        #[serde(default)]
        user: String,
        #[serde(default)]
        session_id: u32,
        #[serde(default)]
        working_set_mb: u64,
        #[serde(default)]
        start_time: String,
    }

    let raw_list: Vec<RawProc> = parse_json_vec(json_str, "windows_incident.processes")?;
    let mut processes = Vec::with_capacity(raw_list.len());
    let mut suspicious_count = 0;

    for p in raw_list {
        let (risk_level, risk_reasons) =
            evaluate_process_risk(&p.name, &p.executable_path, &p.command_line);
        if matches!(
            risk_level,
            WindowsRiskLevel::High | WindowsRiskLevel::Medium
        ) {
            suspicious_count += 1;
        }
        processes.push(WindowsProcessEntry {
            pid: p.pid,
            ppid: p.ppid,
            name: p.name,
            executable_path: p.executable_path,
            command_line: p.command_line,
            user: p.user,
            session_id: p.session_id,
            working_set_mb: p.working_set_mb,
            start_time: p.start_time,
            risk_level,
            risk_reasons,
        });
    }

    processes.sort_by_key(|p| match p.risk_level {
        WindowsRiskLevel::High => 0,
        WindowsRiskLevel::Medium => 1,
        WindowsRiskLevel::Low => 2,
        WindowsRiskLevel::Normal => 3,
    });

    Ok(WindowsProcessesSnapshot {
        total_count: processes.len() as u32,
        suspicious_count,
        processes,
    })
}

pub fn evaluate_process_risk(
    name: &str,
    exe_path: &str,
    cmd_line: &str,
) -> (WindowsRiskLevel, Vec<String>) {
    let name_l = name.to_ascii_lowercase();
    let path_l = exe_path.to_ascii_lowercase();
    let cmd_l = cmd_line.to_ascii_lowercase();
    let mut reasons = Vec::new();
    let mut high = false;

    if path_l.contains("\\appdata\\local\\temp")
        || path_l.contains("\\windows\\temp")
        || path_l.contains("\\users\\public")
        || path_l.contains("\\perflogs")
        || path_l.contains("$recycle.bin")
    {
        high = true;
        reasons.push("进程从高危临时或公共可写目录启动".to_owned());
    }

    if cmd_l.contains("-enc")
        || cmd_l.contains("frombase64string")
        || cmd_l.contains("downloadstring")
        || cmd_l.contains("invoke-expression")
        || cmd_l.contains(" -w hidden")
        || cmd_l.contains("-windowstyle hidden")
    {
        high = true;
        reasons.push("命令行包含编码载荷、隐蔽窗口或远程下载执行特征".to_owned());
    }

    if matches!(
        name_l.as_str(),
        "mshta.exe"
            | "regsvr32.exe"
            | "certutil.exe"
            | "bitsadmin.exe"
            | "wscript.exe"
            | "cscript.exe"
    ) && (cmd_l.contains("http://") || cmd_l.contains("https://") || cmd_l.contains("scrobj"))
    {
        high = true;
        reasons.push("系统工具 (LOLBin) 携带外部 URL 或脚本参数运行".to_owned());
    }

    if matches!(
        name_l.as_str(),
        "svchost.exe" | "lsass.exe" | "csrss.exe" | "services.exe"
    ) && !path_l.is_empty()
        && !path_l.starts_with("c:\\windows\\system32")
        && !path_l.starts_with("c:\\windows\\syswow64")
    {
        high = true;
        reasons.push("核心系统进程名运行在非 System32 标准路径，疑似伪装".to_owned());
    }

    if !high && path_l.contains("\\programdata\\") && !path_l.contains("\\microsoft\\") {
        reasons.push("运行于 ProgramData 非系统子目录，建议核查签名".to_owned());
    }

    let level = if high {
        WindowsRiskLevel::High
    } else if !reasons.is_empty() {
        WindowsRiskLevel::Medium
    } else {
        WindowsRiskLevel::Normal
    };
    (level, reasons)
}

const PS_COLLECT_NETWORK: &str = lovelyhawk_win_dvc::windows_read_queries::NETWORK;

pub fn parse_network_json(json_str: &str) -> CoreResult<WindowsNetworkSnapshot> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct RawNet {
        #[serde(default)]
        protocol: String,
        #[serde(default)]
        local_address: String,
        #[serde(default)]
        local_port: u16,
        #[serde(default)]
        remote_address: String,
        #[serde(default)]
        remote_port: u16,
        #[serde(default)]
        state: String,
        #[serde(default)]
        pid: u32,
        #[serde(default)]
        process_name: String,
        #[serde(default)]
        process_path: String,
    }

    let raw_list: Vec<RawNet> = parse_json_vec(json_str, "windows_incident.network")?;
    let mut connections = Vec::with_capacity(raw_list.len());
    let mut suspicious_count = 0;

    for c in raw_list {
        let (risk_level, risk_reason) = evaluate_network_risk(
            &c.remote_address,
            c.remote_port,
            &c.process_name,
            &c.process_path,
        );
        if matches!(
            risk_level,
            WindowsRiskLevel::High | WindowsRiskLevel::Medium
        ) {
            suspicious_count += 1;
        }
        connections.push(WindowsNetworkEntry {
            protocol: c.protocol,
            local_address: c.local_address,
            local_port: c.local_port,
            remote_address: c.remote_address,
            remote_port: c.remote_port,
            state: c.state,
            pid: c.pid,
            process_name: c.process_name,
            process_path: c.process_path,
            risk_level,
            risk_reason,
        });
    }

    connections.sort_by_key(|c| match c.risk_level {
        WindowsRiskLevel::High => 0,
        WindowsRiskLevel::Medium => 1,
        WindowsRiskLevel::Low => 2,
        WindowsRiskLevel::Normal => 3,
    });

    Ok(WindowsNetworkSnapshot {
        total_count: connections.len() as u32,
        suspicious_count,
        connections,
    })
}

fn evaluate_network_risk(
    remote_addr: &str,
    remote_port: u16,
    proc_name: &str,
    proc_path: &str,
) -> (WindowsRiskLevel, String) {
    let name_l = proc_name.to_ascii_lowercase();
    let path_l = proc_path.to_ascii_lowercase();
    let is_external = !remote_addr.is_empty()
        && remote_addr != "0.0.0.0"
        && remote_addr != "::"
        && remote_addr != "127.0.0.1"
        && remote_addr != "::1";

    if is_external
        && matches!(
            name_l.as_str(),
            "powershell.exe"
                | "cmd.exe"
                | "mshta.exe"
                | "wscript.exe"
                | "cscript.exe"
                | "rundll32.exe"
                | "regsvr32.exe"
                | "certutil.exe"
        )
    {
        return (
            WindowsRiskLevel::High,
            format!("脚本或命令行解释器 ({proc_name}) 存在活动外联连接"),
        );
    }

    if is_external && (path_l.contains("\\temp\\") || path_l.contains("\\users\\public")) {
        return (
            WindowsRiskLevel::High,
            "位于临时/公共目录的进程发起外部网络连接".to_owned(),
        );
    }

    if matches!(remote_port, 4444 | 5555 | 6666 | 1337 | 3333 | 14444 | 9001) {
        return (
            WindowsRiskLevel::Medium,
            format!("连接常见可疑控制或矿池端口 ({remote_port})"),
        );
    }

    (WindowsRiskLevel::Normal, String::new())
}

pub fn parse_startup_json(json_str: &str) -> CoreResult<WindowsStartupSnapshot> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct RawStartup {
        #[serde(default)]
        category: StartupCategory,
        #[serde(default)]
        source_type: String,
        #[serde(default)]
        name: String,
        #[serde(default)]
        location: String,
        #[serde(default)]
        command: String,
        #[serde(default)]
        run_as: String,
        #[serde(default)]
        state: String,
    }

    let raw_list: Vec<RawStartup> = parse_json_vec(json_str, "windows_incident.startup")?;
    let mut entries = Vec::with_capacity(raw_list.len());
    let mut suspicious_count = 0;

    for item in raw_list {
        let cmd_l = item.command.to_ascii_lowercase();
        let (risk_level, risk_reason) = if cmd_l.contains("\\temp\\")
            || cmd_l.contains("\\users\\public")
            || cmd_l.contains("powershell")
            || cmd_l.contains("mshta")
            || cmd_l.contains("regsvr32")
            || cmd_l.contains("wscript")
            || cmd_l.contains("-enc")
        {
            suspicious_count += 1;
            (
                WindowsRiskLevel::High,
                "启动项调用脚本解释器或指向临时/公共可写目录".to_owned(),
            )
        } else if cmd_l.contains("\\appdata\\") {
            suspicious_count += 1;
            (
                WindowsRiskLevel::Medium,
                "启动项位于用户 AppData 目录，建议核实文件签名与来源".to_owned(),
            )
        } else {
            (WindowsRiskLevel::Normal, String::new())
        };

        entries.push(WindowsStartupEntry {
            category: item.category,
            source_type: item.source_type,
            name: item.name,
            location: item.location,
            command: item.command,
            run_as: item.run_as,
            state: item.state,
            risk_level,
            risk_reason,
        });
    }

    Ok(WindowsStartupSnapshot {
        total_count: entries.len() as u32,
        suspicious_count,
        entries,
        categories: Vec::new(),
        warnings: vec!["旧采集格式没有分类覆盖信息，不代表完整启动项清单。".into()],
        observed_at: String::new(),
        truncated: true,
    })
}

pub fn parse_accounts_json(json_str: &str) -> CoreResult<WindowsAccountsSnapshot> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct RawAcc {
        #[serde(default)]
        name: String,
        #[serde(default)]
        full_name: String,
        #[serde(default)]
        enabled: bool,
        #[serde(default)]
        is_admin: bool,
        #[serde(default)]
        sid: String,
        #[serde(default)]
        rid: u32,
        #[serde(default)]
        last_logon: String,
        #[serde(default)]
        password_required: bool,
        #[serde(default)]
        password_expires: bool,
    }

    let raw_list: Vec<RawAcc> = parse_json_vec(json_str, "windows_incident.accounts")?;
    let mut accounts = Vec::with_capacity(raw_list.len());
    let mut admin_count = 0;
    let mut suspicious_count = 0;

    for u in raw_list {
        if u.is_admin {
            admin_count += 1;
        }
        let mut reasons = Vec::new();
        let mut high = false;

        if u.name.ends_with('$') {
            high = true;
            reasons.push("账户名以 '$' 结尾，疑似隐藏/影子后门账户".to_owned());
        }
        if u.name.eq_ignore_ascii_case("guest") && u.enabled {
            high = true;
            reasons.push("内置 Guest 账户处于启用状态".to_owned());
        }
        if u.enabled && !u.password_required {
            reasons.push("账户已启用但未要求设置密码 (PasswordRequired=false)".to_owned());
        }

        let risk_level = if high {
            suspicious_count += 1;
            WindowsRiskLevel::High
        } else if !reasons.is_empty() {
            suspicious_count += 1;
            WindowsRiskLevel::Medium
        } else {
            WindowsRiskLevel::Normal
        };

        accounts.push(WindowsAccountEntry {
            name: u.name,
            full_name: u.full_name,
            enabled: u.enabled,
            is_admin: u.is_admin,
            sid: u.sid,
            rid: u.rid,
            last_logon: u.last_logon,
            password_required: u.password_required,
            password_expires: u.password_expires,
            risk_level,
            risk_reasons: reasons,
        });
    }

    Ok(WindowsAccountsSnapshot {
        total_count: accounts.len() as u32,
        admin_count,
        suspicious_count,
        accounts,
    })
}

pub fn parse_logs_json(json_str: &str, category_filter: &str) -> CoreResult<WindowsLogsSnapshot> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct RawLog {
        #[serde(default)]
        record_id: u64,
        #[serde(default)]
        time_created: String,
        #[serde(default)]
        channel: String,
        #[serde(default)]
        event_id: u32,
        #[serde(default)]
        level: String,
        #[serde(default)]
        summary: String,
        #[serde(default)]
        detail: String,
        #[serde(default)]
        detail_truncated: bool,
    }

    let trimmed = json_str.trim();
    #[derive(Deserialize)]
    struct LogPayload {
        entries: Vec<RawLog>,
        warnings: Vec<String>,
    }
    let payload: serde_json::Value = serde_json::from_str(extract_json_slice(trimmed))
        .map_err(|_| CoreError::validation("windows_incident.logs", "无法解析日志采集结果"))?;
    let (raw_list, warnings) = if payload.get("entries").is_some() {
        let value: LogPayload = serde_json::from_value(payload)
            .map_err(|_| CoreError::validation("windows_incident.logs", "日志采集结果不完整"))?;
        (value.entries, value.warnings)
    } else {
        (
            parse_json_vec::<RawLog>(trimmed, "windows_incident.logs")?,
            vec!["旧采集端未报告通道读取范围，请重新采集。".to_owned()],
        )
    };
    if raw_list.len() > 4096 || warnings.len() > 64 {
        return Err(CoreError::validation(
            "windows_incident.logs",
            "日志记录超过读取上限",
        ));
    }
    let mut entries = Vec::with_capacity(raw_list.len());
    let mut high_risk_count = 0;

    for e in raw_list {
        let (category, risk_level) = match (e.channel.to_ascii_lowercase().as_str(), e.event_id) {
            ("security", 1102) | ("system", 104) => ("日志清除", WindowsRiskLevel::High),
            ("system", 7045) => ("服务安装", WindowsRiskLevel::High),
            ("security", 4720 | 4732) => ("账户与权限变更", WindowsRiskLevel::High),
            ("security", 4625) => ("登录失败", WindowsRiskLevel::Medium),
            ("microsoft-windows-powershell/operational", 4104) => {
                ("PowerShell 脚本块", WindowsRiskLevel::Medium)
            }
            ("security", 4688) => ("进程创建", WindowsRiskLevel::Low),
            ("security", 4624) => ("登录成功", WindowsRiskLevel::Normal),
            _ => ("系统事件", WindowsRiskLevel::Normal),
        };
        if risk_level == WindowsRiskLevel::High {
            high_risk_count += 1;
        }
        entries.push(WindowsEventLogEntry {
            record_id: e.record_id,
            time_created: e.time_created,
            channel: e.channel,
            event_id: e.event_id,
            level: if e.level.is_empty() {
                "信息".to_owned()
            } else {
                e.level
            },
            category: category.to_owned(),
            summary: e.summary,
            detail: e.detail,
            detail_truncated: e.detail_truncated,
            risk_level,
        });
    }

    Ok(WindowsLogsSnapshot {
        category_filter: category_filter.to_owned(),
        total_count: entries.len() as u32,
        high_risk_count,
        warnings,
        entries,
    })
}

fn ps_single_quote(input: &str) -> String {
    format!("'{}'", input.replace('\'', "''"))
}

fn build_files_ps_script(dir_path: &str) -> String {
    let target = if dir_path.trim().is_empty() {
        "C:\\Users\\Public"
    } else {
        dir_path.trim()
    };
    let quoted = ps_single_quote(target);
    format!(
        r#"
$targetPath = [Environment]::ExpandEnvironmentVariables({quoted})
$ErrorActionPreference = 'Stop'
$targetPath = (Get-Item -LiteralPath $targetPath -Force).FullName
$all = @(Get-ChildItem -LiteralPath $targetPath -Force | Select-Object -First 10001 | Sort-Object @{{Expression={{-not $_.PSIsContainer}}}}, Name)
$items = $all | Select-Object -First 1000
$hashesRemaining = 24
$out = foreach ($f in $items) {{
  $hashVal = ''
  if (-not $f.PSIsContainer -and $hashesRemaining -gt 0 -and $f.Length -lt 5MB -and $f.Extension -in @('.exe','.dll','.ps1','.bat','.vbs','.hta','.jsp','.aspx','.php')) {{
    $hashesRemaining--
    try {{ $hashVal = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash }} catch {{ $hashVal = '' }}
  }}
  [ordered]@{{
    name = [string]$f.Name
    fullPath = [string]$f.FullName
    entryType = if ($f.PSIsContainer) {{ 'dir' }} else {{ 'file' }}
    sizeBytes = if ($f.PSIsContainer) {{ [uint64]0 }} else {{ [uint64]$f.Length }}
    lastWriteTime = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
    sha256 = [string]$hashVal
    hidden = [bool]($f.Attributes -band [IO.FileAttributes]::Hidden)
    system = [bool]($f.Attributes -band [IO.FileAttributes]::System)
  }}
}}
[ordered]@{{
  currentPath = [string]$targetPath
  totalEntries = $all.Count
  truncated = $all.Count -gt 1000
  entries = @($out)
}} | ConvertTo-Json -Depth 4 -Compress
"#
    )
}

fn build_file_preview_ps_script(file_path: &str) -> String {
    let quoted = ps_single_quote(file_path);
    format!(
        r#"
$p = [Environment]::ExpandEnvironmentVariables({quoted})
if (-not (Test-Path -LiteralPath $p -PathType Leaf)) {{
  throw "文件不存在: $p"
}}
$info = Get-Item -LiteralPath $p -Force
$stream = [System.IO.File]::OpenRead($info.FullName)
try {{
  $buffer = New-Object byte[] ([Math]::Min($info.Length, {PREVIEW_BYTES}))
  $read = $stream.Read($buffer, 0, $buffer.Length)
}} finally {{ $stream.Dispose() }}
[ordered]@{{
  fullPath = [string]$info.FullName
  sizeBytes = [uint64]$info.Length
  lastWriteTime = $info.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
  b64 = [Convert]::ToBase64String($buffer, 0, $read)
  truncated = $info.Length -gt $read
}} | ConvertTo-Json -Compress
"#
    )
}

/// Bytes read for a text / hex preview; matches the session agent's cap.
pub const PREVIEW_BYTES: u64 = 16 * 1024;

pub fn parse_file_preview_json(json_str: &str) -> CoreResult<WindowsFilePreview> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct RawPreview {
        full_path: String,
        #[serde(default)]
        size_bytes: u64,
        #[serde(default)]
        last_write_time: String,
        #[serde(default)]
        b64: String,
        #[serde(default)]
        truncated: bool,
    }
    let raw: RawPreview = serde_json::from_str(extract_json_slice(json_str)).map_err(|e| {
        CoreError::validation(
            "windows_incident.preview",
            format!("解析文件预览 JSON 失败: {e}"),
        )
    })?;
    if raw.b64.len() > 4 * PREVIEW_BYTES.div_ceil(3) as usize {
        return Err(CoreError::validation(
            "windows_incident.preview",
            "文件预览超过允许的大小",
        ));
    }
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw.b64.as_bytes())
        .map_err(|_| CoreError::validation("windows_incident.preview", "文件预览内容无法解码"))?;
    if bytes.len() as u64 > PREVIEW_BYTES {
        return Err(CoreError::validation(
            "windows_incident.preview",
            "文件预览超过允许的大小",
        ));
    }
    Ok(WindowsFilePreview {
        full_path: raw.full_path,
        size_bytes: raw.size_bytes,
        last_write_time: raw.last_write_time,
        preview_b64: raw.b64,
        preview_bytes: bytes.len() as u64,
        truncated: raw.truncated || raw.size_bytes > bytes.len() as u64,
    })
}

fn build_file_pull_ps_script(file_path: &str) -> String {
    let quoted = ps_single_quote(file_path);
    format!(
        r#"
$p = [Environment]::ExpandEnvironmentVariables({quoted})
if (-not (Test-Path -LiteralPath $p -PathType Leaf)) {{
  throw "文件不存在: $p"
}}
$info = Get-Item -LiteralPath $p -Force
if ($info.Length -gt 8MB) {{
  throw "单次 DVC 取证文件上限为 8MB (当前 $($info.Length) 字节)"
}}
$ErrorActionPreference = 'Stop'
$stream = [System.IO.File]::Open($info.FullName, 'Open', 'Read', 'ReadWrite')
$hasher = [System.Security.Cryptography.SHA256]::Create()
try {{
  $bytes = New-Object byte[] ([int]$info.Length + 1)
  $count = 0
  while ($count -lt $bytes.Length) {{
    $n = $stream.Read($bytes, $count, $bytes.Length - $count)
    if ($n -eq 0) {{ break }}
    $count += $n
  }}
  if ($count -gt 8MB -or $count -ne $info.Length) {{ throw '读取期间文件大小变化，请重试。' }}
  $sha = [BitConverter]::ToString($hasher.ComputeHash($bytes, 0, $count)).Replace('-', '').ToLowerInvariant()
  $b64 = [Convert]::ToBase64String($bytes, 0, $count)
}} finally {{ $stream.Dispose(); $hasher.Dispose() }}
[ordered]@{{
  name = [string]$info.Name
  b64 = $b64
  sha256 = [string]$sha
}} | ConvertTo-Json -Compress
"#
    )
}

pub fn parse_files_json(json_str: &str) -> CoreResult<WindowsFilesSnapshot> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct RawFile {
        #[serde(default)]
        name: String,
        #[serde(default)]
        full_path: String,
        #[serde(default)]
        entry_type: String,
        #[serde(default)]
        size_bytes: u64,
        #[serde(default)]
        last_write_time: String,
        #[serde(default)]
        sha256: String,
        #[serde(default)]
        hidden: bool,
        #[serde(default)]
        system: bool,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct RawPayload {
        #[serde(default)]
        current_path: String,
        #[serde(default)]
        total_entries: Option<u64>,
        #[serde(default)]
        truncated: bool,
        #[serde(default)]
        entries: Vec<RawFile>,
    }

    let raw: RawPayload = serde_json::from_str(extract_json_slice(json_str)).map_err(|e| {
        CoreError::validation(
            "windows_incident.files",
            format!("解析目录列表 JSON 失败: {e}"),
        )
    })?;

    let entries = raw
        .entries
        .into_iter()
        .map(|f| {
            let lower = f.name.to_ascii_lowercase();
            let path_l = f.full_path.to_ascii_lowercase();
            let (risk_level, risk_reason) = if f.entry_type == "file"
                && (lower.ends_with(".exe")
                    || lower.ends_with(".ps1")
                    || lower.ends_with(".bat")
                    || lower.ends_with(".vbs")
                    || lower.ends_with(".hta"))
                && (path_l.contains("\\temp")
                    || path_l.contains("\\users\\public")
                    || path_l.contains("\\startup"))
            {
                (
                    WindowsRiskLevel::High,
                    "临时/公共/启动目录下存在可执行文件或脚本".to_owned(),
                )
            } else if f.entry_type == "file" && f.hidden && !f.system && !f.sha256.is_empty() {
                (
                    WindowsRiskLevel::Medium,
                    "隐藏属性的可执行文件或脚本，常见于落地后门".to_owned(),
                )
            } else if !f.sha256.is_empty() {
                (
                    WindowsRiskLevel::Low,
                    "可执行/脚本组件（已自动计算 SHA256）".to_owned(),
                )
            } else {
                (WindowsRiskLevel::Normal, String::new())
            };
            WindowsFileEntry {
                name: f.name,
                full_path: f.full_path,
                entry_type: f.entry_type,
                size_bytes: f.size_bytes,
                last_write_time: f.last_write_time,
                sha256: f.sha256,
                hidden: f.hidden,
                system: f.system,
                risk_level,
                risk_reason,
            }
        })
        .collect::<Vec<_>>();

    Ok(WindowsFilesSnapshot {
        current_path: raw.current_path,
        total_entries: raw.total_entries.unwrap_or(entries.len() as u64),
        truncated: raw.truncated,
        entries,
    })
}

pub fn parse_registry_json(json_str: &str) -> CoreResult<WindowsRegistrySnapshot> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct RawVal {
        #[serde(default)]
        name: String,
        #[serde(default)]
        kind: String,
        #[serde(default)]
        data: String,
        #[serde(default)]
        truncated: bool,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct RawReg {
        #[serde(default)]
        key_path: String,
        #[serde(default)]
        subkeys: Vec<String>,
        #[serde(default)]
        values: Vec<RawVal>,
        #[serde(default)]
        warnings: Vec<String>,
    }

    let raw: RawReg = serde_json::from_str(extract_json_slice(json_str)).map_err(|e| {
        CoreError::validation(
            "windows_incident.registry",
            format!("解析注册表 JSON 失败: {e}"),
        )
    })?;

    let key_l = raw.key_path.to_ascii_lowercase();
    let values = raw
        .values
        .into_iter()
        .map(|v| {
            let name_l = v.name.to_ascii_lowercase();
            let data_l = v.data.to_ascii_lowercase();
            let (risk_level, risk_reason) =
                if name_l == "debugger" && key_l.contains("image file execution options") {
                    (
                        WindowsRiskLevel::High,
                        "IFEO 映像劫持 Debugger 键值，常见于 sethc/utilman 粘滞键后门".to_owned(),
                    )
                } else if data_l.contains("powershell")
                    || data_l.contains("\\temp\\")
                    || data_l.contains("\\users\\public")
                    || data_l.contains("mshta")
                    || data_l.contains("regsvr32")
                {
                    (
                        WindowsRiskLevel::High,
                        "注册表值指向脚本解释器或高危临时/公共目录".to_owned(),
                    )
                } else {
                    (WindowsRiskLevel::Normal, String::new())
                };
            WindowsRegistryValue {
                name: v.name,
                kind: v.kind,
                data: v.data,
                truncated: v.truncated,
                risk_level,
                risk_reason,
            }
        })
        .collect();

    Ok(WindowsRegistrySnapshot {
        key_path: raw.key_path,
        subkeys: raw.subkeys,
        values,
        warnings: raw.warnings,
    })
}

fn extract_json_slice(raw: &str) -> &str {
    let trimmed = raw.trim();
    if let Some(idx) = trimmed.find(['{', '[']) {
        &trimmed[idx..]
    } else {
        trimmed
    }
}

fn parse_json_vec<T: for<'de> Deserialize<'de>>(
    json_str: &str,
    operation: &'static str,
) -> CoreResult<Vec<T>> {
    let slice = extract_json_slice(json_str);
    if slice.is_empty() {
        return Ok(Vec::new());
    }
    if slice.starts_with('[') {
        serde_json::from_str::<Vec<T>>(slice)
            .map_err(|e| CoreError::validation(operation, format!("JSON 数组解析失败: {e}")))
    } else {
        let single: T = serde_json::from_str(slice)
            .map_err(|e| CoreError::validation(operation, format!("JSON 对象解析失败: {e}")))?;
        Ok(vec![single])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_listing_keeps_attributes_counts_and_flags_hidden_executables() {
        let json = r#"{"currentPath":"C:\\Users\\Public","totalEntries":1200,"truncated":true,"entries":[
            {"name":"a.exe","fullPath":"C:\\Data\\a.exe","entryType":"file","sizeBytes":10,"lastWriteTime":"t","sha256":"ab","hidden":true,"system":false},
            {"name":"dir","fullPath":"C:\\Data\\dir","entryType":"dir","sizeBytes":0,"lastWriteTime":"t","sha256":""}]}"#;
        let snapshot = parse_files_json(json).unwrap();
        assert_eq!(snapshot.total_entries, 1200);
        assert!(snapshot.truncated);
        assert!(snapshot.entries[0].hidden);
        assert_eq!(snapshot.entries[0].risk_level, WindowsRiskLevel::Medium);
        assert!(!snapshot.entries[1].hidden);
        // An older agent sends neither field: counts fall back to what arrived.
        let old = parse_files_json(r#"{"currentPath":"C:\\","entries":[]}"#).unwrap();
        assert_eq!(old.total_entries, 0);
        assert!(!old.truncated);
    }

    #[test]
    fn file_preview_is_bounded_and_marks_partial_reads() {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(b"MZ\x90\x00hello");
        let preview = parse_file_preview_json(&format!(
            r#"{{"fullPath":"C:\\x.exe","sizeBytes":99999,"lastWriteTime":"t","b64":"{b64}","truncated":false}}"#
        ))
        .unwrap();
        assert_eq!(preview.preview_bytes, 9);
        assert!(preview.truncated);
        let oversized = base64::engine::general_purpose::STANDARD.encode(vec![0_u8; 20 * 1024]);
        assert!(
            parse_file_preview_json(&format!(
                r#"{{"fullPath":"C:\\x","sizeBytes":1,"b64":"{oversized}"}}"#
            ))
            .is_err()
        );
        assert!(parse_file_preview_json(r#"{"fullPath":"C:\\x","b64":"%%%"}"#).is_err());
    }

    #[test]
    fn fileless_powershell_script_contains_wts_pinvoke_and_channels() {
        let command = fileless_powershell_script();
        assert!(!command.contains(['\r', '\n']));
        assert!(
            command.len() < 32767,
            "must fit the Windows process command-line limit"
        );
        let encoded = command.split_whitespace().last().unwrap();
        let bytes = BASE64.decode(encoded).unwrap();
        let words: Vec<_> = bytes
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        let script = String::from_utf16(&words).unwrap();
        assert_eq!(script, fileless_powershell_source());
        assert!(script.contains("WTSVirtualChannelOpenEx"));
        assert!(script.contains("dvc::lovelyhawk::winir"));
        assert!(script.contains("dvc::demo::chat"));
    }

    #[test]
    fn process_risk_flags_encoded_powershell_and_temp_paths() {
        let (level, reasons) = evaluate_process_risk(
            "powershell.exe",
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell.exe -NoP -w hidden -enc SQBFAFgA",
        );
        assert_eq!(level, WindowsRiskLevel::High);
        assert!(!reasons.is_empty());

        let (level2, _) = evaluate_process_risk(
            "updater.exe",
            "C:\\Users\\Public\\updater.exe",
            "C:\\Users\\Public\\updater.exe",
        );
        assert_eq!(level2, WindowsRiskLevel::High);
    }

    #[test]
    fn baseline_parser_detects_wdigest_and_guest_risks() {
        let sample = r#"{"rdpNla":0,"rdpEnc":3,"uacLua":1,"wdigest":1,"lsassPpl":0,"autoLogon":"0","smb1":0,"guestEnabled":true,"defenderRealtime":false,"fwDisabledCount":1,"psScriptBlock":0}"#;
        let snap = parse_baseline_json(sample).unwrap();
        assert_eq!(snap.total_checks, 69);
        assert_eq!(snap.unknown_count, 58);
        assert!(snap.failed_count >= 4);
    }

    #[test]
    fn unavailable_baselines_never_count_as_secure_and_event_ids_need_channels() {
        let baseline = parse_baseline_json("{}").unwrap();
        assert_eq!(baseline.unknown_count, 69);
        assert_eq!(baseline.passed_count, 0);
        assert_eq!(baseline.failed_count, 0);
        let unsupported = parse_baseline_json(r#"{"lsassPpl":2}"#).unwrap();
        assert_eq!(
            unsupported
                .items
                .iter()
                .find(|item| item.id == "lsass-ppl")
                .unwrap()
                .status,
            "unknown"
        );
        let supported =
            parse_baseline_json(r#"{"lsassPpl":2,"lsassPplValue2Supported":true}"#).unwrap();
        assert_eq!(
            supported
                .items
                .iter()
                .find(|item| item.id == "lsass-ppl")
                .unwrap()
                .status,
            "pass"
        );
        let logs = parse_logs_json(r#"{"entries":[{"channel":"Application","eventId":1102},{"channel":"Security","eventId":1102}],"warnings":[]}"#, "all").unwrap();
        assert_eq!(logs.high_risk_count, 1);
        assert_eq!(logs.entries[0].risk_level, WindowsRiskLevel::Normal);
    }

    #[test]
    fn process_relationships_reject_reused_pid_and_unrelated_network_rows() {
        let time = "2026-10-24T10:00:00Z";
        let mut payload = serde_json::json!({"pid":12,"startTime":time,"observedAt":time,"user":"lab","services":[],"modules":[],"network":[],"warnings":[]});
        assert!(parse_process_inspection(&payload.to_string(), 12, time).is_ok());
        assert!(parse_process_inspection(&payload.to_string(), 13, time).is_err());
        assert!(
            parse_process_inspection(&payload.to_string(), 12, "2026-10-24T09:00:00Z").is_err()
        );
        payload["network"] = serde_json::json!([{"pid":13}]);
        assert!(parse_process_inspection(&payload.to_string(), 12, time).is_err());
    }

    #[test]
    fn accounts_parser_flags_shadow_dollar_account() {
        let sample = r#"[{"name":"support$","fullName":"","enabled":true,"isAdmin":true,"sid":"S-1-5-21-1001","rid":1001,"lastLogon":"2026-10-24 12:00","passwordRequired":true,"passwordExpires":false}]"#;
        let snap = parse_accounts_json(sample).unwrap();
        assert_eq!(snap.suspicious_count, 1);
        assert_eq!(snap.accounts[0].risk_level, WindowsRiskLevel::High);
    }

    #[test]
    fn log_and_registry_parsers_keep_evidence_gaps_and_actual_record_identifiers() {
        let logs = parse_logs_json(r#"{"entries":[{"recordId":983745,"channel":"Security","eventId":4625,"timeCreated":"2026-10-24T10:00:00+08:00","detail":"partial event","detailTruncated":true}],"warnings":["System: access denied"]}"#, "logon").unwrap();
        assert_eq!(logs.entries[0].record_id, 983745);
        assert!(logs.entries[0].detail_truncated);
        assert_eq!(logs.warnings, ["System: access denied"]);
        assert!(parse_logs_json("", "all").is_err());
        let registry = parse_registry_json(r#"{"keyPath":"HKCU:\\Software\\Test","subkeys":[],"values":[{"name":"","kind":"String","data":"%TEMP%\\a","truncated":true}],"warnings":["subkey limit"]}"#).unwrap();
        assert!(registry.values[0].name.is_empty());
        assert_eq!(registry.values[0].data, "%TEMP%\\a");
        assert!(registry.values[0].truncated);
        assert_eq!(registry.warnings, ["subkey limit"]);
    }

    #[test]
    fn evidence_reassembly_rechecks_size_and_content_before_saving() {
        let part = WindowsEvidencePart {
            file_id: uuid::Uuid::new_v4().to_string(),
            name: "sample.bin".to_owned(),
            size_bytes: 4,
            offset: 0,
            bytes: vec![],
            sha256: "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7".to_owned(),
        };
        assert!(part.verifies(b"data"));
        assert!(!part.verifies(b"date"));
        assert!(!part.verifies(b"data!"));
        assert!(
            WindowsIncidentService::new()
                .received_evidence_part("C:\\fake", 0)
                .is_err()
        );
    }

    #[cfg(windows)]
    #[test]
    fn native_and_powershell_file_pull_hash_the_exact_bounded_bytes() {
        use std::os::windows::process::CommandExt;
        let directory =
            std::env::temp_dir().join(format!("lovelyhawk-pull-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("binary'样本.bin");
        let executable = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32\\WindowsPowerShell\\v1.0\\powershell.exe");
        for bytes in [b"data".as_slice(), b"".as_slice()] {
            std::fs::write(&path, bytes).unwrap();
            let invocation =
                encode_powershell_command(&build_file_pull_ps_script(&path.to_string_lossy()));
            let output = std::process::Command::new(&executable)
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-EncodedCommand",
                    invocation.split_whitespace().last().unwrap(),
                ])
                .creation_flags(0x08000000)
                .output()
                .unwrap();
            assert!(output.status.success(), "bounded PowerShell pull failed");
            let ps: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            let native_text = lovelyhawk_win_dvc::native_collect::handle_native_collect(&format!(
                "pull-file:{}",
                path.display()
            ));
            let native: serde_json::Value =
                serde_json::from_str(&strip_exit_prefix(&native_text).unwrap()).unwrap();
            use sha2::Digest as _;
            let expected = format!("{:x}", sha2::Sha256::digest(bytes));
            for payload in [ps, native] {
                assert_eq!(payload["b64"], BASE64.encode(bytes));
                assert_eq!(payload["sha256"], expected);
                assert_eq!(payload["name"], "binary'样本.bin");
            }
        }
        std::fs::File::create(&path)
            .unwrap()
            .set_len(8 * 1024 * 1024 + 1)
            .unwrap();
        let rejected = lovelyhawk_win_dvc::native_collect::handle_native_collect(&format!(
            "pull-file:{}",
            path.display()
        ));
        assert!(strip_exit_prefix(&rejected).is_err());
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn native_rust_collectors_round_trip_all_nine_modules() {
        use lovelyhawk_win_dvc::native_collect::handle_native_collect;

        let ov = strip_exit_prefix(&handle_native_collect("overview")).unwrap();
        let ov_snap = parse_overview_json(&ov).unwrap();
        assert!(!ov_snap.hostname.is_empty());

        let bl = strip_exit_prefix(&handle_native_collect("baseline")).unwrap();
        let bl_snap = parse_baseline_json(&bl).unwrap();
        assert_eq!(bl_snap.total_checks, 69);

        let pr = strip_exit_prefix(&handle_native_collect("processes")).unwrap();
        let pr_snap = parse_processes_json(&pr).unwrap();
        assert!(pr_snap.total_count > 0);
        let this = pr_snap
            .processes
            .iter()
            .find(|p| p.pid == std::process::id())
            .unwrap();
        // The test's own process is always readable, elevated or not.
        assert!(
            this.user.contains('\\'),
            "own process owner: {:?}",
            this.user
        );
        let details = strip_exit_prefix(&handle_native_collect(&format!(
            "inspect-process:{}:{}",
            this.pid, this.start_time
        )))
        .unwrap();
        let inspection = parse_process_inspection(&details, this.pid, &this.start_time).unwrap();
        assert!(
            inspection.modules.iter().any(|m| m
                .path
                .eq_ignore_ascii_case(&std::env::current_exe().unwrap().to_string_lossy())),
            "the test executable must be in its own loaded module list"
        );

        let net = strip_exit_prefix(&handle_native_collect("network")).unwrap();
        let net_snap = parse_network_json(&net).unwrap();
        assert!(net_snap.total_count > 0);

        let st = strip_exit_prefix(&handle_native_collect("startup")).unwrap();
        let _st_snap = parse_startup_json(&st).unwrap();

        let ac = strip_exit_prefix(&handle_native_collect("accounts")).unwrap();
        let ac_snap = parse_accounts_json(&ac).unwrap();
        assert!(ac_snap.total_count > 0);

        let lg = strip_exit_prefix(&handle_native_collect("logs:all")).unwrap();
        let _lg_snap = parse_logs_json(&lg, "all").unwrap();

        let fl = strip_exit_prefix(&handle_native_collect("files:C:\\Windows")).unwrap();
        let fl_snap = parse_files_json(&fl).unwrap();
        assert!(!fl_snap.entries.is_empty());

        let rg = strip_exit_prefix(&handle_native_collect(
            "registry:HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        ))
        .unwrap();
        let rg_snap = parse_registry_json(&rg).unwrap();
        assert!(!rg_snap.values.is_empty());
    }

    #[test]
    fn disposal_builders_enforce_identity_and_safety_boundaries() {
        assert!(baseline_change_supported("wdigest"));
        assert!(baseline_change_supported("rdp-nla"));
        assert!(!baseline_change_supported("defender-tamper"));
        assert!(!baseline_change_supported("unknown-rule"));

        assert!(build_kill_process_ps_script(0, "2026-10-24T09:30:00Z").is_none());
        assert!(build_kill_process_ps_script(4, "2026-10-24T09:30:00Z").is_none());
        assert!(build_kill_process_ps_script(900, "not-a-timestamp").is_none());
        assert!(build_kill_process_ps_script(900, "2026-10-24T09:30:00Z").is_some());

        assert!(build_delete_file_ps_script("C:\\", "C:\\").is_none());
        assert!(
            build_delete_file_ps_script("C:\\Users\\..\\Windows\\Temp\\a.exe", "C:\\Users")
                .is_none()
        );
        assert!(
            build_delete_file_ps_script(
                "C:\\Windows\\System32\\ntoskrnl.exe",
                "C:\\Windows\\System32"
            )
            .is_none()
        );
        assert!(
            build_delete_file_ps_script("C:\\Users\\Public\\dropper.exe", "C:\\Users\\Public")
                .is_some()
        );

        assert!(
            build_delete_registry_value_ps_script(
                "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                "Shell"
            )
            .is_none()
        );
        assert!(
            build_delete_registry_value_ps_script(
                "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                ""
            )
            .is_none()
        );
        assert!(
            build_delete_registry_value_ps_script(
                "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "Updater"
            )
            .is_some()
        );

        assert!(
            build_remove_startup_ps_script(
                "registry",
                "Winlogon\\Userinit",
                "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
            )
            .is_none()
        );
        assert!(
            build_remove_startup_ps_script(
                "Registry Run",
                "System Update",
                "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
            )
            .is_some()
        );
        assert!(
            build_remove_startup_ps_script(
                "scheduled-task",
                "Updater",
                "\\Microsoft\\Windows\\UpdateOrchestrator"
            )
            .is_none()
        );
        assert!(build_remove_startup_ps_script("scheduled-task", "BackdoorTask", "\\").is_some());

        assert!(build_disable_account_ps_script("support$", "invalid-sid").is_none());
        assert!(build_disable_account_ps_script("support$", "S-1-5-21-1001").is_some());
    }
}
