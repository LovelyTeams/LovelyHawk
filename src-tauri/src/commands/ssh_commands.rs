// SSH connect/disconnect/execute/terminal commands

use std::io::Read;
use std::path::{Path, PathBuf};

use crate::packet_capture;
use crate::ssh_manager_russh;
use crate::types;
use crate::AppState;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tauri::State;
use tauri_plugin_dialog::DialogExt;

// 统一实现见 crate::shell_escape —— 此前本函数在 6 个文件里各存一份复制
use crate::shell_escape::shq as shell_quote;

fn command_timeout(timeout_sec: Option<u64>) -> std::time::Duration {
    std::time::Duration::from_secs(timeout_sec.unwrap_or(60).clamp(5, 600))
}

fn command_with_cwd(command: &str, cwd: Option<&str>) -> String {
    match cwd.map(str::trim).filter(|value| !value.is_empty()) {
        Some(path) => format!("cd {} && {}", shell_quote(path), command),
        None => command.to_string(),
    }
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SSHAuthRequest {
    pub auth_type: String,
    pub password: Option<String>,
    pub key_path: Option<String>,
    pub key_passphrase: Option<String>,
    pub certificate_path: Option<String>,
    #[serde(default)]
    pub keyboard_interactive_responses: Vec<String>,
    pub agent_identity_fingerprint: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SSHJumpHostRequest {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub authentication: SSHAuthRequest,
    pub expected_host_key_fingerprint: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SSHAdvancedConnectRequest {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub authentication: SSHAuthRequest,
    pub expected_host_key_fingerprint: Option<String>,
    pub jump_host: Option<SSHJumpHostRequest>,
}

fn read_auth_file(path: Option<&str>, label: &str) -> Result<Option<String>, String> {
    path.filter(|value| !value.trim().is_empty())
        .map(|path| {
            std::fs::read_to_string(path)
                .map_err(|error| format!("读取{}失败（{}）: {}", label, path, error))
        })
        .transpose()
}

fn materialize_auth(
    request: SSHAuthRequest,
) -> Result<ssh_manager_russh::SSHAuthentication, String> {
    if request.keyboard_interactive_responses.len() > 16
        || request
            .keyboard_interactive_responses
            .iter()
            .any(|response| response.len() > 4096)
    {
        return Err("keyboard-interactive 响应超过安全上限".to_string());
    }

    let method = match request.auth_type.as_str() {
        "password" => ssh_manager_russh::SSHAuthMethod::Password,
        "key" => ssh_manager_russh::SSHAuthMethod::PrivateKey,
        "certificate" => ssh_manager_russh::SSHAuthMethod::OpenSshCertificate,
        "keyboard-interactive" => ssh_manager_russh::SSHAuthMethod::KeyboardInteractive,
        "agent" => ssh_manager_russh::SSHAuthMethod::Agent,
        other => return Err(format!("不支持的 SSH 认证方式: {}", other)),
    };
    let private_key = read_auth_file(request.key_path.as_deref(), "SSH 私钥")?;
    let certificate = read_auth_file(request.certificate_path.as_deref(), "OpenSSH 用户证书")?;

    if matches!(
        method,
        ssh_manager_russh::SSHAuthMethod::PrivateKey
            | ssh_manager_russh::SSHAuthMethod::OpenSshCertificate
    ) && private_key.is_none()
    {
        return Err("密钥/证书认证需要选择私钥文件".to_string());
    }
    if method == ssh_manager_russh::SSHAuthMethod::OpenSshCertificate && certificate.is_none() {
        return Err("证书认证需要选择 OpenSSH *-cert.pub 文件".to_string());
    }

    Ok(ssh_manager_russh::SSHAuthentication {
        method,
        password: request.password,
        private_key,
        private_key_passphrase: request.key_passphrase,
        certificate,
        keyboard_interactive_responses: request.keyboard_interactive_responses,
        agent_identity_fingerprint: request.agent_identity_fingerprint,
    })
}

fn materialize_connect_options(
    request: SSHAdvancedConnectRequest,
) -> Result<ssh_manager_russh::SSHConnectOptions, String> {
    if request.host.trim().is_empty() || request.username.trim().is_empty() {
        return Err("SSH 主机和用户名不能为空".to_string());
    }
    let jump_host = request
        .jump_host
        .map(|jump| {
            if jump.host.trim().is_empty() || jump.username.trim().is_empty() {
                return Err("堡垒机主机和用户名不能为空".to_string());
            }
            Ok(ssh_manager_russh::SSHJumpHostOptions {
                host: jump.host,
                port: jump.port,
                username: jump.username,
                authentication: materialize_auth(jump.authentication)?,
                expected_host_key_fingerprint: jump.expected_host_key_fingerprint,
            })
        })
        .transpose()?;
    Ok(ssh_manager_russh::SSHConnectOptions {
        host: request.host,
        port: request.port,
        username: request.username,
        authentication: materialize_auth(request.authentication)?,
        expected_host_key_fingerprint: request.expected_host_key_fingerprint,
        jump_host,
    })
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file =
        std::fs::File::open(path).map_err(|error| format!("读取本地 PCAP 失败: {}", error))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("计算本地 PCAP 哈希失败: {}", error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn sibling_staging_path(destination: &Path, suffix: &str) -> Result<PathBuf, String> {
    let parent = destination
        .parent()
        .ok_or_else(|| "PCAP 保存路径缺少父目录".to_string())?;
    let name = destination
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "PCAP 保存文件名无效".to_string())?;
    Ok(parent.join(format!(
        ".{}.lovelyres-{}-{}",
        name,
        suffix,
        uuid::Uuid::new_v4()
    )))
}

fn commit_verified_download(staging: &Path, destination: &Path) -> Result<(), String> {
    let backup = sibling_staging_path(destination, "backup")?;
    let had_existing = destination.exists();
    if had_existing {
        std::fs::rename(destination, &backup)
            .map_err(|error| format!("暂存原有目标文件失败: {}", error))?;
    }

    if let Err(error) = std::fs::rename(staging, destination) {
        if had_existing {
            if let Err(restore_error) = std::fs::rename(&backup, destination) {
                return Err(format!(
                    "提交已验证 PCAP 失败: {}; 恢复原文件也失败: {}",
                    error, restore_error
                ));
            }
        }
        return Err(format!("提交已验证 PCAP 失败: {}", error));
    }

    if had_existing {
        std::fs::remove_file(&backup)
            .map_err(|error| format!("清理 PCAP 覆盖备份失败: {}", error))?;
    }
    Ok(())
}

fn cleanup_remote_pcap(
    manager: &ssh_manager_russh::SSHManagerRussh,
    session_id: &str,
    remote_path: &str,
) -> bool {
    if !packet_capture::is_managed_remote_pcap_path(remote_path) {
        return false;
    }
    let path = shell_quote(remote_path);
    let command = format!("rm -f -- {path} && test ! -e {path}");
    manager
        .execute_dashboard_command_as_user_on_session_with_timeout(
            session_id,
            &command,
            None,
            std::time::Duration::from_secs(15),
        )
        .is_ok_and(|output| output.is_success())
}

// SSH 连接管理命令
#[tauri::command]
pub async fn load_ssh_connections(
    state: State<'_, AppState>,
) -> Result<Vec<types::SSHConnection>, String> {
    let manager = crate::lock_or_recover(&state.ssh_connection_manager);
    manager.load_connections().map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn save_ssh_connections(
    connections: Vec<types::SSHConnection>,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let manager = crate::lock_or_recover(&state.ssh_connection_manager);
    manager
        .save_connections(&connections)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn encrypt_password(
    password: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let manager = crate::lock_or_recover(&state.ssh_connection_manager);
    manager
        .encrypt_password(&password)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn decrypt_password(
    encrypted_password: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let manager = crate::lock_or_recover(&state.ssh_connection_manager);
    manager
        .decrypt_password(&encrypted_password)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn ssh_connect_direct(
    host: String,
    port: u16,
    username: String,
    password: Option<String>,
    auth_type: Option<String>,
    key_path: Option<String>,
    key_passphrase: Option<String>,
    expected_host_key_fingerprint: Option<String>,
    state: State<'_, AppState>,
) -> Result<ssh_manager_russh::SSHConnectionStatus, String> {
    #[cfg(debug_assertions)]
    {
        crate::alog_info!("=== [Tauri] ssh_connect_direct 被调用 ===");
        crate::alog_info!("  Host: {}", host);
        crate::alog_info!("  Port: {}", port);
        crate::alog_info!("  Username: {}", username);
        crate::alog_info!("  Auth Type: {:?}", auth_type);
    }

    let auth = auth_type.as_deref().unwrap_or("password");
    let manager = &state.ssh_manager;

    let result = match auth {
        "key" => {
            // 密钥认证：如果有 key_path，读取密钥内容传给 russh
            if let Some(kp) = &key_path {
                let key_content =
                    std::fs::read_to_string(kp).map_err(|e| format!("读取密钥文件失败: {}", e))?;
                manager.connect(
                    &host,
                    port,
                    &username,
                    key_passphrase.as_deref(),
                    Some(&key_content),
                    expected_host_key_fingerprint.as_deref(),
                )
            } else {
                Err("密钥认证需要提供密钥路径".to_string())
            }
        }
        _ => {
            // 密码认证
            manager.connect(
                &host,
                port,
                &username,
                password.as_deref(),
                None,
                expected_host_key_fingerprint.as_deref(),
            )
        }
    };

    match &result {
        Ok(_) => crate::alog_info!("[Tauri] SSH 连接成功"),
        Err(e) => crate::alog_info!("[Tauri] SSH 连接失败: {}", e),
    }

    result?;
    manager
        .get_connection_status()
        .ok_or_else(|| "SSH 已连接，但无法读取目标身份".to_string())
}

#[tauri::command]
pub async fn ssh_connect_advanced(
    request: SSHAdvancedConnectRequest,
    state: State<'_, AppState>,
) -> Result<ssh_manager_russh::SSHConnectionStatus, String> {
    let manager = &state.ssh_manager;
    let options = materialize_connect_options(request)?;
    manager.connect_with_options(options)?;
    manager
        .get_connection_status()
        .ok_or_else(|| "SSH 已连接，但无法读取目标身份".to_string())
}

/// 测试SSH连接（使用 russh）- 复用已有的 Tokio runtime 避免重复创建
#[tauri::command]
pub async fn ssh_test_connection(
    host: String,
    port: u16,
    username: String,
    auth_type: String,
    password: Option<String>,
    key_path: Option<String>,
    key_passphrase: Option<String>,
    _certificate_path: Option<String>,
    expected_host_key_fingerprint: Option<String>,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    crate::alog_info!(
        "[ssh_test_connection] 开始测试连接: {}@{}:{}",
        username,
        host,
        port
    );

    // 复用 AppState 的 manager，避免创建新的 Tokio runtime
    let manager = &state.ssh_manager;

    let previous_session = manager.get_current_session_id();
    let result = match auth_type.as_str() {
        "key" => {
            if let Some(kp) = &key_path {
                let key_content =
                    std::fs::read_to_string(kp).map_err(|e| format!("读取密钥文件失败: {}", e))?;
                manager.connect(
                    &host,
                    port,
                    &username,
                    key_passphrase.as_deref(),
                    Some(&key_content),
                    expected_host_key_fingerprint.as_deref(),
                )
            } else {
                Err("密钥认证需要提供密钥路径".to_string())
            }
        }
        _ => manager.connect(
            &host,
            port,
            &username,
            password.as_deref(),
            None,
            expected_host_key_fingerprint.as_deref(),
        ),
    };

    match result {
        Ok(session_id) => {
            // Disconnect the test session
            let _ = manager.disconnect_session(&session_id);
            if let Some(previous_session) = previous_session {
                let _ = manager.set_current_session_id(&previous_session);
            }
            crate::alog_info!("[ssh_test_connection] 测试成功");
            Ok(true)
        }
        Err(e) => {
            crate::alog_info!("[ssh_test_connection] 测试失败: {}", e);
            Err(e)
        }
    }
}

#[tauri::command]
pub async fn ssh_test_connection_advanced(
    request: SSHAdvancedConnectRequest,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let manager = &state.ssh_manager;
    let previous_session = manager.get_current_session_id();
    let session_id = manager.connect_with_options(materialize_connect_options(request)?)?;
    manager.disconnect_session(&session_id)?;
    if let Some(previous_session) = previous_session {
        manager.set_current_session_id(&previous_session)?;
    }
    Ok(true)
}

#[tauri::command]
pub async fn ssh_disconnect_direct(state: State<'_, AppState>) -> Result<(), String> {
    let manager = &state.ssh_manager;
    manager.disconnect().map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn ssh_disconnect_session_direct(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state.ssh_manager.disconnect_session(&session_id)
}

#[tauri::command]
pub async fn ssh_set_current_session(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state.ssh_manager.set_current_session_id(&session_id)
}

#[tauri::command]
pub async fn start_packet_capture(
    interface: String,
    filter: Option<String>,
    count: Option<u32>,
    session_id: String,
    window: tauri::Window,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let manager = &state.ssh_manager;
    manager.start_packet_capture_on_session(&session_id, &interface, filter, count, window)
}

#[tauri::command]
pub async fn stop_packet_capture(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let manager = &state.ssh_manager;
    manager.stop_packet_capture_on_session(&session_id)
}

#[tauri::command]
pub async fn capture_pcap_evidence(
    interface: String,
    filter: Option<String>,
    packet_limit: Option<u32>,
    duration_seconds: u32,
    session_id: String,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<packet_capture::PcapEvidenceReceipt, String> {
    let remote_path = packet_capture::new_remote_pcap_path();
    let command = packet_capture::generate_pcap_evidence_command(
        &interface,
        filter.as_deref(),
        packet_limit,
        duration_seconds,
        &remote_path,
    )?;
    let normalized_filter = filter
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let captured_at = chrono::Utc::now();
    let suggested_name = format!(
        "lovelyres-capture-{}.pcap",
        captured_at.format("%Y%m%d-%H%M%S")
    );
    let selected = app
        .dialog()
        .file()
        .set_title("保存原始 PCAP 证据")
        .set_file_name(&suggested_name)
        .add_filter("PCAP capture", &["pcap"])
        .blocking_save_file();

    let Some(selected) = selected else {
        return Ok(packet_capture::PcapEvidenceReceipt {
            cancelled: true,
            local_path: None,
            sha256: None,
            size_bytes: None,
            interface,
            filter: normalized_filter,
            packet_limit,
            duration_seconds,
            captured_at: captured_at.to_rfc3339(),
            remote_cleanup_verified: true,
        });
    };
    let destination = selected
        .into_path()
        .map_err(|error| format!("PCAP 保存路径无效: {}", error))?;
    crate::path_guard::ensure_safe_download_target(&destination.to_string_lossy())?;
    let staging = sibling_staging_path(&destination, "download")?;
    crate::path_guard::ensure_safe_download_target(&staging.to_string_lossy())?;

    let manager = &state.ssh_manager;
    let output = match manager.execute_dashboard_command_as_user_on_session_with_timeout(
        &session_id,
        &command,
        None,
        std::time::Duration::from_secs(duration_seconds as u64 + 20),
    ) {
        Ok(output) => output,
        Err(error) => {
            let _ = cleanup_remote_pcap(manager, &session_id, &remote_path);
            return Err(format!("原始 PCAP 采集失败: {}", error));
        }
    };
    if !output.is_success() {
        let _ = cleanup_remote_pcap(manager, &session_id, &remote_path);
        return Err(format!(
            "原始 PCAP 采集失败（exit={:?}, timeout={}）: {}",
            output.exit_code, output.timed_out, output.output
        ));
    }
    let metadata = match packet_capture::parse_pcap_evidence_output(&output.output) {
        Ok(metadata) => metadata,
        Err(error) => {
            let _ = cleanup_remote_pcap(manager, &session_id, &remote_path);
            return Err(error);
        }
    };

    if let Err(error) =
        manager.download_file_on_session(&session_id, &remote_path, &staging.to_string_lossy())
    {
        let _ = std::fs::remove_file(&staging);
        let _ = cleanup_remote_pcap(manager, &session_id, &remote_path);
        return Err(format!("下载原始 PCAP 失败: {}", error));
    }

    let local_size = match std::fs::metadata(&staging) {
        Ok(metadata) => metadata.len(),
        Err(error) => {
            let _ = std::fs::remove_file(&staging);
            let _ = cleanup_remote_pcap(manager, &session_id, &remote_path);
            return Err(format!("读取本地 PCAP 元数据失败: {}", error));
        }
    };
    let local_hash = match sha256_file(&staging) {
        Ok(hash) => hash,
        Err(error) => {
            let _ = std::fs::remove_file(&staging);
            let _ = cleanup_remote_pcap(manager, &session_id, &remote_path);
            return Err(error);
        }
    };
    if local_size != metadata.size_bytes || local_hash != metadata.sha256 {
        let _ = std::fs::remove_file(&staging);
        let _ = cleanup_remote_pcap(manager, &session_id, &remote_path);
        return Err(format!(
            "PCAP 完整性校验失败：远端 {} bytes/{}, 本地 {} bytes/{}",
            metadata.size_bytes, metadata.sha256, local_size, local_hash
        ));
    }
    if let Err(error) = commit_verified_download(&staging, &destination) {
        let _ = std::fs::remove_file(&staging);
        let _ = cleanup_remote_pcap(manager, &session_id, &remote_path);
        return Err(error);
    }
    let remote_cleanup_verified = cleanup_remote_pcap(manager, &session_id, &remote_path);

    Ok(packet_capture::PcapEvidenceReceipt {
        cancelled: false,
        local_path: Some(destination.to_string_lossy().into_owned()),
        sha256: Some(metadata.sha256),
        size_bytes: Some(metadata.size_bytes),
        interface,
        filter: normalized_filter,
        packet_limit,
        duration_seconds,
        captured_at: captured_at.to_rfc3339(),
        remote_cleanup_verified,
    })
}

#[tauri::command]
pub async fn get_network_interfaces(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<packet_capture::NetworkInterface>, String> {
    let manager = &state.ssh_manager;
    let cmd = packet_capture::generate_list_interfaces_command();
    let output = manager
        .execute_dashboard_command_as_user_on_session_with_timeout(
            &session_id,
            &cmd,
            None,
            std::time::Duration::from_secs(60),
        )
        .map_err(|e| format!("获取网络接口失败: {}", e))?;

    let mut interfaces: Vec<packet_capture::NetworkInterface> = Vec::new();
    let mut index = 0u32;

    for line in output.output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let name = parts[0].to_string();
            let ip = parts[1].split('/').next().unwrap_or(parts[1]).to_string();

            if let Some(existing) = interfaces.iter_mut().find(|i| i.name == name) {
                if !existing.ips.contains(&ip) {
                    existing.ips.push(ip);
                }
            } else {
                index += 1;
                interfaces.push(packet_capture::NetworkInterface {
                    name,
                    index,
                    mac: None,
                    ips: vec![ip],
                });
            }
        }
    }

    Ok(interfaces)
}

#[tauri::command]
pub async fn ssh_execute_command_direct(
    command: String,
    username: Option<String>,
    session_id: String,
    state: State<'_, AppState>,
) -> Result<ssh_manager_russh::TerminalOutput, String> {
    let manager = &state.ssh_manager;
    let result = manager
        .execute_dashboard_command_as_user_on_session_with_timeout(
            &session_id,
            &command,
            username.as_deref(),
            std::time::Duration::from_secs(60),
        )
        .map_err(|e| e.to_string());

    result
}

#[tauri::command]
pub async fn ssh_execute_dashboard_command_direct(
    command: String,
    session_id: String,
    state: State<'_, AppState>,
) -> Result<ssh_manager_russh::TerminalOutput, String> {
    let manager = &state.ssh_manager;
    let result = manager
        .execute_dashboard_command_as_user_on_session_with_timeout(
            &session_id,
            &command,
            None,
            std::time::Duration::from_secs(60),
        )
        .map_err(|e| e.to_string());

    result
}

/// 批量并行执行多条SSH命令（一次IPC调用，后端并行打开多个SSH channel）
#[tauri::command]
pub async fn ssh_execute_batch_commands(
    commands: Vec<String>,
    session_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<ssh_manager_russh::BatchCommandResult>, String> {
    let manager = &state.ssh_manager;
    let results = manager.execute_batch_commands_on_session(&session_id, &commands)?;

    Ok(results
        .into_iter()
        .enumerate()
        .map(|(i, r)| match r {
            Ok(output) => ssh_manager_russh::BatchCommandResult {
                command: commands.get(i).cloned().unwrap_or_default(),
                success: output.is_success(),
                error: if output.is_success() {
                    None
                } else if output.timed_out {
                    Some("命令执行超时".to_string())
                } else {
                    Some(format!("命令退出状态未知或非 0: {:?}", output.exit_code))
                },
                output: Some(output),
            },
            Err(e) => ssh_manager_russh::BatchCommandResult {
                command: commands.get(i).cloned().unwrap_or_default(),
                success: false,
                output: None,
                error: Some(e),
            },
        })
        .collect())
}

#[tauri::command]
pub async fn ssh_execute_emergency_command_direct(
    command: String,
    username: Option<String>,
    timeout_sec: Option<u64>,
    cwd: Option<String>,
    session_id: String,
    state: State<'_, AppState>,
) -> Result<ssh_manager_russh::TerminalOutput, String> {
    let manager = &state.ssh_manager;
    let timeout = command_timeout(timeout_sec);
    let effective_command = command_with_cwd(&command, cwd.as_deref());
    let result = manager
        .execute_dashboard_command_as_user_on_session_with_timeout(
            &session_id,
            &effective_command,
            username.as_deref(),
            timeout,
        )
        .map_err(|e| e.to_string());

    result
}

/// 执行检测报告中AI生成的命令
#[tauri::command]
pub async fn execute_detection_command(
    command: String,
    session_id: String,
    state: State<'_, AppState>,
) -> Result<ssh_manager_russh::TerminalOutput, String> {
    crate::alog_info!("[AI命令执行] 开始执行: {}", command);

    let manager = &state.ssh_manager;
    let result = manager
        .execute_dashboard_command_as_user_on_session_with_timeout(
            &session_id,
            &command,
            None,
            std::time::Duration::from_secs(60),
        )
        .map_err(|e| {
            crate::alog_info!("[AI命令执行] 执行失败: {}", e);
            e.to_string()
        });

    match &result {
        Ok(output) => {
            crate::alog_info!("[AI命令执行] 执行成功");
            crate::alog_info!("   输出长度: {} 字符", output.output.len());
            if let Some(exit_code) = output.exit_code {
                crate::alog_info!("   退出码: {}", exit_code);
            }
        }
        Err(e) => {
            crate::alog_info!("[AI命令执行] 执行失败: {}", e);
        }
    }

    result
}

/// 测试SSH连接质量 - 对比交互式终端和直接命令执行
#[tauri::command]
pub async fn test_ssh_performance(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let manager = &state.ssh_manager;

    let test_commands = vec![
        ("echo test", "基础响应测试"),
        ("pwd", "目录查询测试"),
        ("date", "系统时间测试"),
        ("whoami", "用户查询测试"),
    ];

    let mut results = Vec::new();
    results.push("=== 直接命令执行性能测试 ===".to_string());

    for (cmd, desc) in test_commands {
        let start = std::time::Instant::now();
        match manager.execute_dashboard_command_as_user_on_session_with_timeout(
            &session_id,
            cmd,
            None,
            std::time::Duration::from_secs(60),
        ) {
            Ok(_) => {
                let duration = start.elapsed();
                results.push(format!("{}: {:?}", desc, duration));
                crate::alog_info!("[SSH性能-直接] {}: {:?}", desc, duration);
            }
            Err(e) => {
                results.push(format!("{}: 失败 - {}", desc, e));
            }
        }
    }

    results.push("\n=== 性能分析建议 ===".to_string());
    results.push("如果直接命令执行很快，但交互式终端很慢，问题可能在于:".to_string());
    results.push("1. Shell初始化配置(.bashrc, .profile)".to_string());
    results.push("2. 复杂的命令提示符(PS1)".to_string());
    results.push("3. PTY配置问题".to_string());
    results.push("4. 环境变量处理".to_string());

    Ok(results.join("\n"))
}

/// 检测Shell配置可能导致的性能问题
#[tauri::command]
pub async fn diagnose_shell_performance(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let manager = &state.ssh_manager;

    let mut results = Vec::new();
    results.push("=== Shell性能诊断 ===".to_string());

    // 检测shell类型
    let start = std::time::Instant::now();
    match manager.execute_dashboard_command_as_user_on_session_with_timeout(
        &session_id,
        "echo $SHELL",
        None,
        std::time::Duration::from_secs(60),
    ) {
        Ok(output) => {
            results.push(format!(
                "Shell类型: {} (耗时: {:?})",
                output.output.trim(),
                start.elapsed()
            ));
        }
        Err(e) => {
            results.push(format!("获取Shell类型失败: {}", e));
        }
    }

    // 检测.bashrc大小
    let start = std::time::Instant::now();
    match manager.execute_dashboard_command_as_user_on_session_with_timeout(
        &session_id,
        "wc -l ~/.bashrc 2>/dev/null || echo 'no .bashrc'",
        None,
        std::time::Duration::from_secs(60),
    ) {
        Ok(output) => {
            results.push(format!(
                ".bashrc行数: {} (耗时: {:?})",
                output.output.trim(),
                start.elapsed()
            ));
        }
        Err(e) => {
            results.push(format!("检测.bashrc失败: {}", e));
        }
    }

    // 检测PS1复杂度
    let start = std::time::Instant::now();
    match manager.execute_dashboard_command_as_user_on_session_with_timeout(
        &session_id,
        "echo \"PS1长度: ${#PS1}\"",
        None,
        std::time::Duration::from_secs(60),
    ) {
        Ok(output) => {
            results.push(format!(
                "命令提示符: {} (耗时: {:?})",
                output.output.trim(),
                start.elapsed()
            ));
        }
        Err(e) => {
            results.push(format!("检测PS1失败: {}", e));
        }
    }

    // 测试简单命令
    let start = std::time::Instant::now();
    match manager.execute_dashboard_command_as_user_on_session_with_timeout(
        &session_id,
        "true",
        None,
        std::time::Duration::from_secs(60),
    ) {
        Ok(_) => {
            results.push(format!("简单命令(true): 耗时 {:?}", start.elapsed()));
        }
        Err(e) => {
            results.push(format!("简单命令失败: {}", e));
        }
    }

    results.push("\n=== 建议 ===".to_string());
    results.push("如果简单命令很快，问题可能在交互式终端的Shell配置".to_string());
    results.push("尝试: export PS1='$ ' 来简化命令提示符".to_string());

    Ok(results.join("\n"))
}

/// 检测系统类型（后端实现，更高效）
#[tauri::command]
pub async fn detect_system_type(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    use serde_json::json;

    crate::alog_info!("[后端] 开始系统类型检测...");

    let manager = &state.ssh_manager;

    if !manager.is_session_connected(&session_id) {
        crate::alog_info!("[后端] 没有活动的 SSH 连接");
        return Err("没有活动的 SSH 连接".to_string());
    }

    // 1. 读取 /etc/os-release
    crate::alog_info!("[后端] 读取 os-release...");
    let os_release_cmd =
        "cat /etc/os-release 2>/dev/null || cat /etc/lsb-release 2>/dev/null || echo 'ID=generic'";
    let os_release_output = manager
        .execute_dashboard_command_as_user_on_session_with_timeout(
            &session_id,
            os_release_cmd,
            None,
            std::time::Duration::from_secs(60),
        )
        .map_err(|e| {
            crate::alog_info!("[后端] 读取 os-release 失败: {}", e);
            format!("读取 os-release 失败: {}", e)
        })?;

    crate::alog_info!("[后端] os-release 读取成功");
    let os_release_content = os_release_output.output;

    // 2. 检测包管理器
    crate::alog_info!("[后端] 检测包管理器...");
    let pkg_mgr_cmd = "which apt 2>/dev/null && echo 'apt' || which yum 2>/dev/null && echo 'yum' || which dnf 2>/dev/null && echo 'dnf' || which pacman 2>/dev/null && echo 'pacman' || which zypper 2>/dev/null && echo 'zypper' || which apk 2>/dev/null && echo 'apk' || echo 'unknown'";
    let pkg_mgr_output = manager
        .execute_dashboard_command_as_user_on_session_with_timeout(
            &session_id,
            pkg_mgr_cmd,
            None,
            std::time::Duration::from_secs(60),
        )
        .map_err(|e| {
            crate::alog_info!("[后端] 检测包管理器失败: {}", e);
            format!("检测包管理器失败: {}", e)
        })?;

    crate::alog_info!("[后端] 包管理器检测成功");
    let package_manager = pkg_mgr_output
        .output
        .lines()
        .last()
        .unwrap_or("unknown")
        .trim();

    // 3. 检测 init 系统
    crate::alog_info!("[后端] 检测 init 系统...");
    let init_cmd = "ps -p 1 -o comm= 2>/dev/null";
    let init_output = manager
        .execute_dashboard_command_as_user_on_session_with_timeout(
            &session_id,
            init_cmd,
            None,
            std::time::Duration::from_secs(60),
        )
        .map_err(|e| {
            crate::alog_info!("[后端] 检测 init 系统失败: {}", e);
            format!("检测 init 系统失败: {}", e)
        })?;

    crate::alog_info!("[后端] init 系统检测成功");

    let init_output_str = init_output.output.trim().to_lowercase();
    let init_system = if init_output_str.contains("systemd") {
        "systemd"
    } else if init_output_str.contains("init") {
        "sysvinit"
    } else if init_output_str.contains("upstart") {
        "upstart"
    } else if init_output_str.contains("openrc") {
        "openrc"
    } else {
        "unknown"
    };

    // 4. 解析 os-release 内容
    let mut id = "generic".to_string();
    let mut id_like = String::new();
    let mut name = "Linux".to_string();
    let mut version = String::new();
    let mut pretty_name = "Generic Linux".to_string();

    for line in os_release_content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("ID=") && !trimmed.starts_with("ID_LIKE=") {
            id = trimmed[3..]
                .trim_matches(|c| c == '"' || c == '\'')
                .to_lowercase();
        } else if trimmed.starts_with("ID_LIKE=") {
            id_like = trimmed[8..]
                .trim_matches(|c| c == '"' || c == '\'')
                .to_lowercase();
        } else if trimmed.starts_with("NAME=") {
            name = trimmed[5..]
                .trim_matches(|c| c == '"' || c == '\'')
                .to_string();
        } else if trimmed.starts_with("VERSION_ID=") {
            version = trimmed[11..]
                .trim_matches(|c| c == '"' || c == '\'')
                .to_string();
        } else if trimmed.starts_with("PRETTY_NAME=") {
            pretty_name = trimmed[12..]
                .trim_matches(|c| c == '"' || c == '\'')
                .to_string();
        }
    }

    // 5. 识别系统类型
    let combined = format!("{} {} {} {}", id, id_like, name, pretty_name).to_lowercase();

    let system_type = if id == "kylin" {
        "kylin"
    } else if id == "uos" || id == "uniontech" {
        "uos"
    } else if id == "deepin" {
        "deepin"
    } else if id == "openeuler" {
        "openeuler"
    } else if id == "anolis" {
        "anolis"
    } else if id == "ubuntu" {
        "ubuntu"
    } else if id == "debian" {
        "debian"
    } else if id == "centos" {
        "centos"
    } else if id == "rhel" {
        "rhel"
    } else if id == "fedora" {
        "fedora"
    } else if id == "arch" {
        "arch"
    } else if id == "opensuse" || id == "suse" {
        "opensuse"
    } else if id == "alpine" {
        "alpine"
    } else if !id_like.is_empty() {
        // 根据 ID_LIKE 判断
        if id_like.contains("ubuntu") {
            "ubuntu"
        } else if id_like.contains("debian") {
            "debian"
        } else if id_like.contains("rhel") || id_like.contains("fedora") {
            if combined.contains("centos") {
                "centos"
            } else if combined.contains("fedora") {
                "fedora"
            } else {
                "rhel"
            }
        } else if id_like.contains("arch") {
            "arch"
        } else if id_like.contains("suse") {
            "opensuse"
        } else {
            "generic"
        }
    } else {
        "generic"
    };

    crate::alog_info!(
        "系统检测完成: type={}, name={}, version={}",
        system_type,
        name,
        version
    );

    Ok(json!({
        "type": system_type,
        "name": name,
        "version": version,
        "prettyName": pretty_name,
        "packageManager": package_manager,
        "initSystem": init_system
    }))
}

/// 一次性探测目标实际能力。前端按 session_id 缓存，切换目标后不会复用。
#[tauri::command]
pub async fn ssh_probe_capabilities(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<crate::ssh_compat::TargetCapabilities, String> {
    state
        .ssh_manager
        .probe_target_capabilities_on_session(&session_id)
}

// SSH 终端管理命令

/// 创建 SSH 终端会话
#[tauri::command]
pub async fn ssh_create_terminal_session(
    window: tauri::Window,
    terminal_id: String,
    cols: u16,
    rows: u16,
    session_id: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    // 获取终端创建锁，确保原子性
    let _creation_lock = crate::lock_or_recover(&state.ssh_terminal_creation_lock);

    let manager = &state.ssh_manager;

    if !manager.is_session_connected(&session_id) {
        return Err("没有活动的 SSH 连接".to_string());
    }

    match manager.create_terminal_session_on_session(
        &session_id,
        window,
        &terminal_id,
        cols as u32,
        rows as u32,
    ) {
        Ok(_) => {
            crate::alog_info!("创建终端会话成功: {}", terminal_id);
            Ok(terminal_id)
        }
        Err(e) => {
            crate::alog_info!("创建终端会话失败: {}", e);
            Err(e.to_string())
        }
    }
}

/// 关闭 SSH 终端会话
#[tauri::command]
pub async fn ssh_close_terminal_session(
    terminal_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let manager = &state.ssh_manager;

    match manager.close_terminal_session(&terminal_id) {
        Ok(_) => {
            crate::alog_info!("关闭终端会话成功: {}", terminal_id);
            Ok(())
        }
        Err(e) => {
            crate::alog_info!("关闭终端会话失败: {}", e);
            Err(e.to_string())
        }
    }
}

/// 关闭所有 SSH 终端会话
#[tauri::command]
pub async fn ssh_close_all_terminal_sessions(state: State<'_, AppState>) -> Result<usize, String> {
    let manager = &state.ssh_manager;

    match manager.close_all_terminal_sessions() {
        Ok(_) => {
            crate::alog_info!("关闭所有终端会话成功");
            Ok(0) // Return 0 since we don't track count in russh impl
        }
        Err(e) => {
            crate::alog_info!("关闭所有终端会话失败: {}", e);
            Err(e.to_string())
        }
    }
}

/// 向 SSH 终端发送输入
#[tauri::command]
pub async fn ssh_send_input(
    terminal_id: String,
    data: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let manager = &state.ssh_manager;

    match manager.send_terminal_input(&terminal_id, data.as_bytes().to_vec()) {
        Ok(_) => Ok(()),
        Err(e) => {
            crate::alog_info!("发送终端输入失败: {}", e);
            Err(e.to_string())
        }
    }
}

/// 获取 SSH 终端自动补全建议
#[tauri::command]
pub async fn ssh_get_completion(
    input: String,
    #[allow(unused_variables)] cursor_position: usize,
    session_id: String,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let manager = &state.ssh_manager;

    // 基本的命令补全逻辑
    let words: Vec<&str> = input.split_whitespace().collect();
    let mut completions = Vec::new();

    if words.is_empty() || (words.len() == 1 && !input.ends_with(' ')) {
        // 补全命令
        let common_commands = vec![
            "ls",
            "cd",
            "pwd",
            "cat",
            "grep",
            "find",
            "ps",
            "top",
            "htop",
            "df",
            "du",
            "free",
            "uname",
            "whoami",
            "id",
            "groups",
            "chmod",
            "chown",
            "cp",
            "mv",
            "rm",
            "mkdir",
            "rmdir",
            "tar",
            "gzip",
            "gunzip",
            "zip",
            "unzip",
            "vim",
            "nano",
            "less",
            "more",
            "head",
            "tail",
            "ssh",
            "scp",
            "rsync",
            "wget",
            "curl",
            "systemctl",
            "service",
            "crontab",
            "history",
            "awk",
            "sed",
            "sort",
            "uniq",
            "wc",
            "tr",
        ];

        let prefix = words.last().unwrap_or(&"");
        for cmd in common_commands {
            if cmd.starts_with(prefix) {
                completions.push(cmd.to_string());
            }
        }
    } else {
        // 尝试文件/目录补全
        let last_word = words.last().unwrap_or(&"");

        // 构建 ls 命令来获取文件列表
        let dir_path = if last_word.contains('/') {
            let path_parts: Vec<&str> = last_word.rsplitn(2, '/').collect();
            if path_parts.len() == 2 {
                path_parts[1]
            } else {
                "."
            }
        } else {
            "."
        };

        // 执行 ls 命令获取文件列表(dir_path 来自补全输入,需转义,避免含空格/$()/; 的路径被当作命令)
        match manager.execute_dashboard_command_as_user_on_session_with_timeout(
            &session_id,
            &format!("ls -1a {}", shell_quote(dir_path)),
            None,
            std::time::Duration::from_secs(60),
        ) {
            Ok(output) => {
                let files: Vec<&str> = output.output.lines().collect();
                let filename_prefix = if last_word.contains('/') {
                    last_word.split('/').last().unwrap_or("")
                } else {
                    last_word
                };

                for file in files {
                    if file.starts_with(filename_prefix) && file != "." && file != ".." {
                        // 用 match 而非 contains + unwrap：两者本来是耦合的，
                        // 一旦有人改了上面的判空条件，unwrap 就会变成崩溃点。
                        let full_path = match last_word.rfind('/') {
                            Some(idx) => format!("{}{}", &last_word[..idx + 1], file),
                            None => file.to_string(),
                        };
                        completions.push(full_path);
                    }
                }
            }
            Err(_) => {
                // 如果无法获取文件列表，返回空补全
            }
        }
    }

    Ok(serde_json::json!({
        "completions": completions
    }))
}

#[tauri::command]
pub async fn get_bash_environment_info(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<types::BashEnvironmentInfo, String> {
    let manager = &state.ssh_manager;
    manager
        .get_bash_environment_info_on_session(&session_id)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_command_completion(
    input: String,
    session_id: String,
    state: State<'_, AppState>,
) -> Result<types::CommandCompletion, String> {
    let manager = &state.ssh_manager;
    manager
        .get_command_completion_on_session(&session_id, &input)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn ssh_get_connection_status(
    state: State<'_, AppState>,
) -> Result<Option<ssh_manager_russh::SSHConnectionStatus>, String> {
    let manager = &state.ssh_manager;
    let status = manager.get_connection_status();
    Ok(status)
}

// ═══ busybox 管理 ═══

/// 检测远端是否已有 busybox，返回路径或空
#[tauri::command]
pub async fn busybox_detect(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let manager = &state.ssh_manager;
    let cmd = r#"for p in /tmp/busybox /usr/local/bin/busybox /usr/bin/busybox /bin/busybox; do [ -x "$p" ] && echo "$p" && exit 0; done; which busybox 2>/dev/null || echo ''"#;
    let output = manager
        .execute_dashboard_command_as_user_on_session_with_timeout(
            &session_id,
            cmd,
            None,
            std::time::Duration::from_secs(60),
        )
        .map_err(|e| format!("检测 busybox 失败: {}", e))?;
    Ok(output.output.trim().to_string())
}

/// 从本地上传 busybox 静态二进制到远端 /tmp/busybox
#[tauri::command]
pub async fn busybox_install(
    local_path: String,
    session_id: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let manager = &state.ssh_manager;
    let remote_path = "/tmp/busybox";

    // 1. 通过 SFTP 上传本地文件到远端
    manager
        .upload_file_on_session(&session_id, &local_path, remote_path)
        .map_err(|e| format!("上传 busybox 失败: {}", e))?;

    // 2. 添加执行权限并验证
    let verify_command = format!(
        "chmod +x {} && {} --help 2>&1 | head -1 && echo 'INSTALL_OK:{}'",
        remote_path, remote_path, remote_path
    );
    let verify = manager
        .execute_dashboard_command_as_user_on_session_with_timeout(
            &session_id,
            &verify_command,
            None,
            std::time::Duration::from_secs(60),
        )
        .map_err(|e| format!("验证 busybox 失败: {}", e))?;

    Ok(verify.output)
}

/// 启用 busybox 模式（所有后续命令优先用 busybox sh 执行）
#[tauri::command]
pub async fn busybox_enable(
    path: String,
    session_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let manager = &state.ssh_manager;
    manager.set_busybox_path_on_session(&session_id, Some(path));
    Ok(())
}

/// 禁用 busybox 模式（恢复使用系统原生命令）
#[tauri::command]
pub async fn busybox_disable(session_id: String, state: State<'_, AppState>) -> Result<(), String> {
    let manager = &state.ssh_manager;
    manager.set_busybox_path_on_session(&session_id, None);
    Ok(())
}

/// 获取当前 busybox 状态
#[tauri::command]
pub async fn busybox_status(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<Option<String>, String> {
    let manager = &state.ssh_manager;
    Ok(manager.get_busybox_path_on_session(&session_id))
}

#[cfg(test)]
mod pcap_evidence_tests {
    use super::{commit_verified_download, sha256_file};

    #[test]
    fn verified_download_commit_replaces_destination_only_after_staging_exists() {
        let root =
            std::env::temp_dir().join(format!("lovelyres-pcap-commit-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("create fixture root");
        let destination = root.join("capture.pcap");
        let staging = root.join("capture.part");
        std::fs::write(&destination, b"old evidence").expect("write old fixture");
        std::fs::write(&staging, b"new verified evidence").expect("write staging fixture");

        commit_verified_download(&staging, &destination).expect("commit verified fixture");

        assert_eq!(
            std::fs::read(&destination).expect("read committed fixture"),
            b"new verified evidence"
        );
        assert!(!staging.exists());
        assert_eq!(
            std::fs::read_dir(&root).expect("list fixture root").count(),
            1,
            "overwrite backup must be removed"
        );
        std::fs::remove_dir_all(&root).expect("clean fixture root");
    }

    #[test]
    fn sha256_file_matches_known_digest() {
        let path =
            std::env::temp_dir().join(format!("lovelyres-pcap-hash-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, b"abc").expect("write hash fixture");
        assert_eq!(
            sha256_file(&path).expect("hash fixture"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        std::fs::remove_file(path).expect("clean hash fixture");
    }
}
