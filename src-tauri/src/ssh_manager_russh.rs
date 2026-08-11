// SSH Manager using russh library
// This implementation uses a dedicated background thread with its own Tokio runtime
// to avoid nested runtime issues when called from Tauri's async context

use russh::client::{Config, Handle, Handler, KeyboardInteractiveAuthResponse};
use russh::keys::agent::{
    client::{AgentClient, AgentStream},
    AgentIdentity,
};
use russh::keys::{Certificate, PrivateKeyWithHashAlg, PublicKey};
use russh::{ChannelMsg, Disconnect};
use russh_sftp::client::SftpSession;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::thread;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ================== Types ==================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalOutput {
    pub command: String,
    pub output: String,
    pub exit_code: Option<i32>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub duration_ms: u64,
    pub timed_out: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchCommandResult {
    pub command: String,
    pub success: bool,
    pub output: Option<TerminalOutput>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtomicSftpWriteReceipt {
    pub path: String,
    pub backup_path: String,
    pub bytes_written: usize,
    pub preserved_permissions: Option<u32>,
    pub preserved_uid: Option<u32>,
    pub preserved_gid: Option<u32>,
}

impl TerminalOutput {
    pub fn new(command: &str, output: &str, exit_code: Option<i32>) -> Self {
        Self {
            command: command.to_string(),
            output: output.to_string(),
            exit_code,
            timestamp: chrono::Utc::now(),
            duration_ms: 0,
            timed_out: false,
        }
    }

    pub fn with_duration(mut self, duration: std::time::Duration) -> Self {
        self.duration_ms = duration.as_millis().min(u128::from(u64::MAX)) as u64;
        self
    }

    pub fn timeout(command: &str, duration: std::time::Duration) -> Self {
        Self {
            command: command.to_string(),
            output: format!("命令执行超时（{} 秒）", duration.as_secs()),
            exit_code: None,
            timestamp: chrono::Utc::now(),
            duration_ms: duration.as_millis().min(u128::from(u64::MAX)) as u64,
            timed_out: true,
        }
    }

    pub fn is_success(&self) -> bool {
        !self.timed_out && self.exit_code == Some(0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SftpFileInfo {
    pub name: String,
    pub path: String,
    pub file_type: String, // "directory", "file", "symlink", "other"
    pub is_dir: bool,      // 保留向后兼容
    pub size: u64,
    pub modified: Option<String>,
    pub permissions: Option<String>,
    pub owner: Option<String>,
    pub group: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SftpFileDetails {
    pub name: String,
    pub path: String,
    pub file_type: String,
    pub size: u64,
    pub permissions: String,
    pub owner: Option<String>,
    pub group: Option<String>,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub accessed: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SSHConnectionStatus {
    pub connected: bool,
    pub session_id: String,
    pub host_key_fingerprint: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub last_activity: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_method: String,
    pub host_key_fingerprint: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SSHAuthMethod {
    Password,
    PrivateKey,
    OpenSshCertificate,
    KeyboardInteractive,
    Agent,
}

impl SSHAuthMethod {
    fn label(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::PrivateKey => "key",
            Self::OpenSshCertificate => "certificate",
            Self::KeyboardInteractive => "keyboard-interactive",
            Self::Agent => "agent",
        }
    }
}

#[derive(Clone)]
pub struct SSHAuthentication {
    pub method: SSHAuthMethod,
    pub password: Option<String>,
    pub private_key: Option<String>,
    pub private_key_passphrase: Option<String>,
    pub certificate: Option<String>,
    pub keyboard_interactive_responses: Vec<String>,
    pub agent_identity_fingerprint: Option<String>,
}

impl SSHAuthentication {
    fn password(password: Option<&str>) -> Self {
        Self {
            method: SSHAuthMethod::Password,
            password: password.map(str::to_string),
            private_key: None,
            private_key_passphrase: None,
            certificate: None,
            keyboard_interactive_responses: Vec::new(),
            agent_identity_fingerprint: None,
        }
    }

    fn private_key(private_key: &str, passphrase: Option<&str>) -> Self {
        Self {
            method: SSHAuthMethod::PrivateKey,
            password: None,
            private_key: Some(private_key.to_string()),
            private_key_passphrase: passphrase.map(str::to_string),
            certificate: None,
            keyboard_interactive_responses: Vec::new(),
            agent_identity_fingerprint: None,
        }
    }
}

#[derive(Clone)]
pub struct SSHJumpHostOptions {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub authentication: SSHAuthentication,
    pub expected_host_key_fingerprint: Option<String>,
}

#[derive(Clone)]
pub struct SSHConnectOptions {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub authentication: SSHAuthentication,
    pub expected_host_key_fingerprint: Option<String>,
    pub jump_host: Option<SSHJumpHostOptions>,
}

// ================== SSH Client Handler ==================

#[derive(Debug, Clone, PartialEq, Eq)]
enum HostKeyVerification {
    Pending,
    Trusted { fingerprint: String },
    Unknown { fingerprint: String },
    Learned { fingerprint: String },
    Mismatch { expected: String, observed: String },
    Error(String),
}

static KNOWN_HOSTS_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
const HOST_KEY_CONFIRMATION_PREFIX: &str = "LOVELYRES_SSH_HOST_KEY_CONFIRM:";

fn host_key_confirmation_error(host: &str, port: u16, username: &str, fingerprint: &str) -> String {
    format!(
        "{}{}",
        HOST_KEY_CONFIRMATION_PREFIX,
        serde_json::json!({
            "code": "HOST_KEY_CONFIRMATION_REQUIRED",
            "host": host,
            "port": port,
            "username": username,
            "fingerprint": fingerprint,
        })
    )
}

fn fingerprint(public_key: &PublicKey) -> String {
    public_key
        .fingerprint(russh::keys::HashAlg::Sha256)
        .to_string()
}

fn set_known_hosts_permissions(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("设置 known_hosts 权限失败: {}", e))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn verify_or_learn_host_key(
    host: &str,
    port: u16,
    public_key: &PublicKey,
    known_hosts_path: &Path,
    expected_host_key_fingerprint: Option<&str>,
) -> HostKeyVerification {
    let observed = fingerprint(public_key);
    let lock = KNOWN_HOSTS_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = match lock.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    match russh::keys::check_known_hosts_path(host, port, public_key, known_hosts_path) {
        Ok(true) => HostKeyVerification::Trusted {
            fingerprint: observed,
        },
        Ok(false) if expected_host_key_fingerprint == Some(observed.as_str()) => {
            match russh::keys::known_hosts::learn_known_hosts_path(
                host,
                port,
                public_key,
                known_hosts_path,
            )
            .map_err(|e| e.to_string())
            .and_then(|_| set_known_hosts_permissions(known_hosts_path))
            {
                Ok(()) => HostKeyVerification::Learned {
                    fingerprint: observed,
                },
                Err(error) => HostKeyVerification::Error(error),
            }
        }
        Ok(false) if expected_host_key_fingerprint.is_some() => HostKeyVerification::Mismatch {
            expected: expected_host_key_fingerprint
                .unwrap_or_default()
                .to_string(),
            observed,
        },
        Ok(false) => HostKeyVerification::Unknown {
            fingerprint: observed,
        },
        Err(russh::keys::Error::KeyChanged { .. }) => {
            let expected =
                russh::keys::known_hosts::known_host_keys_path(host, port, known_hosts_path)
                    .ok()
                    .and_then(|keys| keys.first().map(|(_, key)| fingerprint(key)))
                    .unwrap_or_else(|| "unknown".to_string());
            HostKeyVerification::Mismatch { expected, observed }
        }
        Err(error) => HostKeyVerification::Error(error.to_string()),
    }
}

struct ClientHandler {
    host: String,
    port: u16,
    known_hosts_path: PathBuf,
    expected_host_key_fingerprint: Option<String>,
    verification: Arc<Mutex<HostKeyVerification>>,
}

impl ClientHandler {
    fn new(
        host: &str,
        port: u16,
        known_hosts_path: PathBuf,
        expected_host_key_fingerprint: Option<String>,
        verification: Arc<Mutex<HostKeyVerification>>,
    ) -> Self {
        Self {
            host: host.to_string(),
            port,
            known_hosts_path,
            expected_host_key_fingerprint,
            verification,
        }
    }
}

impl Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        let result = verify_or_learn_host_key(
            &self.host,
            self.port,
            server_public_key,
            &self.known_hosts_path,
            self.expected_host_key_fingerprint.as_deref(),
        );
        let accepted = matches!(
            result,
            HostKeyVerification::Trusted { .. } | HostKeyVerification::Learned { .. }
        );
        match self.verification.lock() {
            Ok(mut state) => *state = result,
            Err(poisoned) => *poisoned.into_inner() = result,
        }
        Ok(accepted)
    }
}

// 统一实现见 crate::shell_escape —— 此前本函数在 6 个文件里各存一份复制
use crate::shell_escape::shq as shell_quote;

// ================== Worker Thread Messages ==================

enum WorkerCommand {
    Connect {
        options: SSHConnectOptions,
        response_tx: mpsc::Sender<Result<String, String>>,
    },
    ExecuteCommand {
        session_id: String,
        command: String,
        timeout: std::time::Duration,
        response_tx: mpsc::Sender<Result<TerminalOutput, String>>,
    },
    ListSftpFiles {
        session_id: String,
        path: String,
        response_tx: mpsc::Sender<Result<Vec<SftpFileInfo>, String>>,
    },
    ReadSftpFile {
        session_id: String,
        path: String,
        response_tx: mpsc::Sender<Result<Vec<u8>, String>>,
    },
    WriteSftpFile {
        session_id: String,
        path: String,
        content: Vec<u8>,
        response_tx: mpsc::Sender<Result<(), String>>,
    },
    AtomicWriteSftpFile {
        session_id: String,
        path: String,
        backup_path: String,
        content: Vec<u8>,
        response_tx: mpsc::Sender<Result<AtomicSftpWriteReceipt, String>>,
    },
    DeleteSftpFile {
        session_id: String,
        path: String,
        response_tx: mpsc::Sender<Result<(), String>>,
    },
    CreateSftpDirectory {
        session_id: String,
        path: String,
        response_tx: mpsc::Sender<Result<(), String>>,
    },
    RenameSftpFile {
        session_id: String,
        old_path: String,
        new_path: String,
        response_tx: mpsc::Sender<Result<(), String>>,
    },
    Disconnect {
        session_id: String,
        response_tx: mpsc::Sender<Result<(), String>>,
    },
    DisconnectAll {
        response_tx: mpsc::Sender<Result<(), String>>,
    },
    GetConnectionInfo {
        session_id: String,
        response_tx: mpsc::Sender<Option<ConnectionInfo>>,
    },
    ProbeCapabilities {
        session_id: String,
        response_tx: mpsc::Sender<Result<crate::ssh_compat::TargetCapabilities, String>>,
    },
    IsConnected {
        session_id: String,
        response_tx: mpsc::Sender<bool>,
    },
    ListSessions {
        response_tx: mpsc::Sender<Vec<String>>,
    },
    // Terminal session commands
    CreateTerminalSession {
        session_id: String,
        terminal_id: String,
        cols: u32,
        rows: u32,
        window: tauri::Window,
        response_tx: mpsc::Sender<Result<(), String>>,
    },
    CloseTerminalSession {
        terminal_id: String,
        response_tx: mpsc::Sender<Result<(), String>>,
    },
    CloseAllTerminalSessions {
        response_tx: mpsc::Sender<Result<(), String>>,
    },
    SendTerminalInput {
        terminal_id: String,
        data: Vec<u8>,
        response_tx: mpsc::Sender<Result<(), String>>,
    },
    ResizeTerminal {
        terminal_id: String,
        cols: u32,
        rows: u32,
        response_tx: mpsc::Sender<Result<(), String>>,
    },
    // Packet Capture commands
    StartPacketCapture {
        session_id: String,
        interface: String,
        filter: Option<String>,
        count: Option<u32>,
        window: tauri::Window,
        response_tx: mpsc::Sender<Result<(), String>>,
    },
    StopPacketCapture {
        session_id: String,
        response_tx: mpsc::Sender<Result<(), String>>,
    },
    ExecuteBatch {
        session_id: String,
        commands: Vec<String>,
        response_tx: mpsc::Sender<Result<Vec<Result<TerminalOutput, String>>, String>>,
    },
    Shutdown,
}

// ================== Session Data ==================

struct SessionData {
    handle: Arc<Handle<ClientHandler>>,
    // A direct-tcpip stream depends on the jump session remaining alive.
    _jump_handle: Option<Arc<Handle<ClientHandler>>>,
    info: ConnectionInfo,
    // Store active packet capture channel to allow stopping it
    packet_capture_channel: Option<tokio::sync::oneshot::Sender<()>>,
}

// ================== Terminal Session Data ==================

use russh::client::Msg;
use tauri::Emitter;

struct TerminalSession {
    channel: russh::Channel<Msg>,
    _session_id: String,
    _window: tauri::Window,
}

// ================== Async Helper Functions ==================

const KEYBOARD_INTERACTIVE_CHALLENGE_PREFIX: &str = "LOVELYRES_SSH_KBDINT_REQUIRED:";

struct ConnectedHandles {
    target: Handle<ClientHandler>,
    jump: Option<Handle<ClientHandler>>,
    host_key_fingerprint: String,
}

fn ssh_client_config() -> Arc<Config> {
    Arc::new(Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(300)),
        keepalive_interval: Some(std::time::Duration::from_secs(30)),
        keepalive_max: 3,
        ..Default::default()
    })
}

fn client_handler(
    host: &str,
    port: u16,
    expected_host_key_fingerprint: Option<&str>,
) -> Result<(ClientHandler, Arc<Mutex<HostKeyVerification>>), String> {
    let known_hosts_path = crate::types::AppDataPaths::new()
        .map_err(|e| format!("初始化 known_hosts 失败: {}", e))?
        .app_data_dir
        .join("known_hosts");
    let verification = Arc::new(Mutex::new(HostKeyVerification::Pending));
    Ok((
        ClientHandler::new(
            host,
            port,
            known_hosts_path,
            expected_host_key_fingerprint.map(str::to_string),
            Arc::clone(&verification),
        ),
        verification,
    ))
}

fn verification_state(verification: &Arc<Mutex<HostKeyVerification>>) -> HostKeyVerification {
    match verification.lock() {
        Ok(state) => state.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}

fn connect_error(
    host: &str,
    port: u16,
    username: &str,
    verification: &Arc<Mutex<HostKeyVerification>>,
    error: russh::Error,
) -> String {
    match verification_state(verification) {
        HostKeyVerification::Unknown { fingerprint } => {
            return host_key_confirmation_error(host, port, username, &fingerprint)
        }
        HostKeyVerification::Mismatch { expected, observed } => {
            return format!(
                "SSH 主机密钥已变化，已阻止连接。目标 {}:{}，已记录 {}，本次 {}",
                host, port, expected, observed,
            )
        }
        HostKeyVerification::Error(error) => return format!("SSH 主机密钥校验失败: {}", error),
        _ => {}
    }

    let error = error.to_string();
    if error.contains("10061") || error.contains("Connection refused") {
        format!(
            "连接被拒绝 ({}:{})：目标端口未开放或 SSH 服务未运行",
            host, port
        )
    } else if error.contains("10060") || error.contains("timed out") {
        format!("连接超时 ({}:{})：无法到达目标主机", host, port)
    } else if error.contains("10065") || error.contains("No route") {
        format!("无法路由到主机 ({}:{})：网络不可达", host, port)
    } else {
        format!("连接失败 ({}:{}): {}", host, port, error)
    }
}

fn confirmed_fingerprint(
    host: &str,
    port: u16,
    username: &str,
    verification: &Arc<Mutex<HostKeyVerification>>,
) -> Result<String, String> {
    match verification_state(verification) {
        HostKeyVerification::Trusted { fingerprint }
        | HostKeyVerification::Learned { fingerprint } => Ok(fingerprint),
        HostKeyVerification::Unknown { fingerprint } => Err(host_key_confirmation_error(
            host,
            port,
            username,
            &fingerprint,
        )),
        HostKeyVerification::Mismatch { expected, observed } => Err(format!(
            "SSH 主机密钥不匹配：已记录 {}，本次 {}",
            expected, observed
        )),
        HostKeyVerification::Error(error) => Err(format!("SSH 主机密钥校验失败: {}", error)),
        HostKeyVerification::Pending => Err("SSH 服务器未提供可验证的主机密钥".to_string()),
    }
}

async fn resolve_ssh_addresses(host: &str, port: u16) -> Result<Vec<std::net::SocketAddr>, String> {
    // Tuple-based resolution handles raw IPv4, raw IPv6 and DNS names without manual brackets.
    let addresses = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::lookup_host((host, port)),
    )
    .await
    .map_err(|_| format!("DNS resolution timed out for host: {}", host))?
    .map_err(|e| format!("Failed to resolve host: {}", e))?;
    let mut unique = Vec::new();
    for address in addresses {
        if !unique.contains(&address) {
            unique.push(address);
        }
    }
    if unique.is_empty() {
        Err(format!("No addresses found for host: {}", host))
    } else {
        Ok(unique)
    }
}

async fn connect_direct_transport(
    host: &str,
    port: u16,
    username: &str,
    expected_host_key_fingerprint: Option<&str>,
) -> Result<(Handle<ClientHandler>, String), String> {
    let addresses = resolve_ssh_addresses(host, port).await?;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
    let mut failures = Vec::new();

    for address in addresses {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let attempt_timeout = remaining.min(std::time::Duration::from_secs(6));
        let (handler, verification) = client_handler(host, port, expected_host_key_fingerprint)?;
        match tokio::time::timeout(
            attempt_timeout,
            russh::client::connect(ssh_client_config(), address, handler),
        )
        .await
        {
            Ok(Ok(handle)) => {
                let fingerprint = confirmed_fingerprint(host, port, username, &verification)?;
                return Ok((handle, fingerprint));
            }
            Ok(Err(error)) => {
                let mapped = connect_error(host, port, username, &verification, error);
                if !matches!(
                    verification_state(&verification),
                    HostKeyVerification::Pending
                ) {
                    return Err(mapped);
                }
                failures.push(format!("{}: {}", address, mapped));
            }
            Err(_) => failures.push(format!("{}: 连接超时", address)),
        }
    }

    Err(format!(
        "连接失败 ({}:{})，已尝试所有解析地址：{}",
        host,
        port,
        failures.join("；")
    ))
}

fn keyboard_interactive_challenge(
    host: &str,
    port: u16,
    username: &str,
    name: &str,
    instructions: &str,
    prompts: &[russh::client::Prompt],
    supplied_responses: usize,
) -> String {
    format!(
        "{}{}",
        KEYBOARD_INTERACTIVE_CHALLENGE_PREFIX,
        serde_json::json!({
            "code": "KEYBOARD_INTERACTIVE_REQUIRED",
            "host": host,
            "port": port,
            "username": username,
            "name": name,
            "instructions": instructions,
            "suppliedResponses": supplied_responses,
            "prompts": prompts.iter().map(|prompt| serde_json::json!({
                "prompt": prompt.prompt,
                "echo": prompt.echo,
            })).collect::<Vec<_>>(),
        })
    )
}

fn rsa_policy_error(detail: &str) -> String {
    format!(
        "RSA 密钥已按安全策略拒绝：RustCrypto rsa 仍受 RUSTSEC-2023-0071 影响且无修复版本。{}请改用 Ed25519/ECDSA、SSH Agent，或在受控环境外部使用系统 OpenSSH。",
        if detail.is_empty() { String::new() } else { format!("{}。", detail) },
    )
}

fn map_private_key_error(key: &str, error: impl std::fmt::Display) -> String {
    let text = error.to_string();
    if key.contains("BEGIN RSA PRIVATE KEY")
        || text.to_ascii_lowercase().contains("ssh-rsa")
        || text.to_ascii_lowercase().contains("rsa")
    {
        rsa_policy_error("")
    } else {
        format!("无法解析 SSH 私钥: {}", text)
    }
}

#[cfg(unix)]
async fn connect_ssh_agent() -> Result<AgentClient<Box<dyn AgentStream + Send + Unpin>>, String> {
    AgentClient::connect_env()
        .await
        .map(AgentClient::dynamic)
        .map_err(|error| format!("无法连接 SSH_AUTH_SOCK: {}", error))
}

#[cfg(windows)]
async fn connect_ssh_agent() -> Result<AgentClient<Box<dyn AgentStream + Send + Unpin>>, String> {
    match AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent").await {
        Ok(agent) => Ok(agent.dynamic()),
        Err(open_ssh_error) => AgentClient::connect_pageant()
            .await
            .map(AgentClient::dynamic)
            .map_err(|pageant_error| {
                format!(
                    "无法连接 Windows OpenSSH Agent ({}) 或 Pageant ({})",
                    open_ssh_error, pageant_error
                )
            }),
    }
}

async fn authenticate_with_agent(
    handle: &mut Handle<ClientHandler>,
    username: &str,
    requested_fingerprint: Option<&str>,
) -> Result<(), String> {
    let mut agent = connect_ssh_agent().await?;
    let identities = agent
        .request_identities()
        .await
        .map_err(|error| format!("读取 SSH Agent 身份失败: {}", error))?;
    if identities.is_empty() {
        return Err("SSH Agent 中没有可用身份，请先运行 ssh-add".to_string());
    }

    let mut attempted = 0usize;
    for identity in identities {
        let public_key = identity.public_key();
        let fingerprint = public_key
            .fingerprint(russh::keys::HashAlg::Sha256)
            .to_string();
        if requested_fingerprint.is_some_and(|requested| requested != fingerprint) {
            continue;
        }
        attempted += 1;

        let result = match &identity {
            AgentIdentity::PublicKey { key, .. } => handle
                .authenticate_publickey_with(username, key.clone(), None, &mut agent)
                .await
                .map_err(|error| error.to_string())?,
            AgentIdentity::Certificate { certificate, .. } => handle
                .authenticate_certificate_with(username, certificate.clone(), None, &mut agent)
                .await
                .map_err(|error| error.to_string())?,
        };
        if result.success() {
            return Ok(());
        }
    }

    if attempted == 0 && requested_fingerprint.is_some() {
        Err("SSH Agent 中不存在所选指纹的身份".to_string())
    } else {
        Err(format!(
            "SSH Agent 的 {} 个候选身份均被服务器拒绝",
            attempted
        ))
    }
}

async fn authenticate_handle(
    handle: &mut Handle<ClientHandler>,
    host: &str,
    port: u16,
    username: &str,
    authentication: &SSHAuthentication,
) -> Result<(), String> {
    let timeout = std::time::Duration::from_secs(20);
    match authentication.method {
        SSHAuthMethod::Password => {
            let password = authentication
                .password
                .as_deref()
                .ok_or_else(|| "密码认证需要提供密码".to_string())?;
            let result =
                tokio::time::timeout(timeout, handle.authenticate_password(username, password))
                    .await
                    .map_err(|_| "Password authentication timed out (20s)".to_string())?
                    .map_err(|error| format!("Password authentication failed: {}", error))?;
            result
                .success()
                .then_some(())
                .ok_or_else(|| "服务器拒绝了密码认证".to_string())
        }
        SSHAuthMethod::PrivateKey | SSHAuthMethod::OpenSshCertificate => {
            let key = authentication
                .private_key
                .as_deref()
                .ok_or_else(|| "密钥认证需要提供私钥".to_string())?;
            let passphrase = authentication
                .private_key_passphrase
                .as_deref()
                .filter(|value| !value.is_empty());
            let key_pair = russh::keys::decode_secret_key(key, passphrase)
                .map_err(|error| map_private_key_error(key, error))?;
            let result = if authentication.method == SSHAuthMethod::OpenSshCertificate {
                let certificate = authentication
                    .certificate
                    .as_deref()
                    .ok_or_else(|| "证书认证需要提供 OpenSSH 用户证书".to_string())?;
                let certificate = Certificate::from_openssh(certificate)
                    .map_err(|error| format!("无法解析 OpenSSH 用户证书: {}", error))?;
                tokio::time::timeout(
                    timeout,
                    handle.authenticate_openssh_cert(username, Arc::new(key_pair), certificate),
                )
                .await
                .map_err(|_| "Certificate authentication timed out (20s)".to_string())?
                .map_err(|error| format!("Certificate authentication failed: {}", error))?
            } else {
                let key = PrivateKeyWithHashAlg::new(Arc::new(key_pair), None);
                tokio::time::timeout(timeout, handle.authenticate_publickey(username, key))
                    .await
                    .map_err(|_| "Key authentication timed out (20s)".to_string())?
                    .map_err(|error| format!("Key authentication failed: {}", error))?
            };
            result
                .success()
                .then_some(())
                .ok_or_else(|| "服务器拒绝了密钥/证书认证".to_string())
        }
        SSHAuthMethod::KeyboardInteractive => {
            let mut response = tokio::time::timeout(
                timeout,
                handle.authenticate_keyboard_interactive_start(username, None::<String>),
            )
            .await
            .map_err(|_| "Keyboard-interactive authentication timed out (20s)".to_string())?
            .map_err(|error| format!("Keyboard-interactive authentication failed: {}", error))?;
            let mut cursor = 0usize;
            for _round in 0..8 {
                match response {
                    KeyboardInteractiveAuthResponse::Success => return Ok(()),
                    KeyboardInteractiveAuthResponse::Failure { .. } => {
                        return Err("服务器拒绝了 keyboard-interactive 认证".to_string())
                    }
                    KeyboardInteractiveAuthResponse::InfoRequest {
                        name,
                        instructions,
                        prompts,
                    } => {
                        let remaining = authentication
                            .keyboard_interactive_responses
                            .len()
                            .saturating_sub(cursor);
                        if remaining < prompts.len() {
                            let missing = &prompts[remaining..];
                            return Err(keyboard_interactive_challenge(
                                host,
                                port,
                                username,
                                &name,
                                &instructions,
                                missing,
                                authentication.keyboard_interactive_responses.len(),
                            ));
                        }
                        let next = authentication.keyboard_interactive_responses
                            [cursor..cursor + prompts.len()]
                            .to_vec();
                        cursor += prompts.len();
                        response = tokio::time::timeout(
                            timeout,
                            handle.authenticate_keyboard_interactive_respond(next),
                        )
                        .await
                        .map_err(|_| "Keyboard-interactive response timed out (20s)".to_string())?
                        .map_err(|error| {
                            format!("Keyboard-interactive response failed: {}", error)
                        })?;
                    }
                }
            }
            Err("Keyboard-interactive 认证轮次超过安全上限（8）".to_string())
        }
        SSHAuthMethod::Agent => tokio::time::timeout(
            timeout,
            authenticate_with_agent(
                handle,
                username,
                authentication.agent_identity_fingerprint.as_deref(),
            ),
        )
        .await
        .map_err(|_| "SSH Agent authentication timed out (20s)".to_string())?,
    }
}

async fn connect_async(options: &SSHConnectOptions) -> Result<ConnectedHandles, String> {
    if let Some(jump) = &options.jump_host {
        let (mut jump_handle, _) = connect_direct_transport(
            &jump.host,
            jump.port,
            &jump.username,
            jump.expected_host_key_fingerprint.as_deref(),
        )
        .await?;
        authenticate_handle(
            &mut jump_handle,
            &jump.host,
            jump.port,
            &jump.username,
            &jump.authentication,
        )
        .await?;

        let channel = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            jump_handle.channel_open_direct_tcpip(
                &options.host,
                u32::from(options.port),
                "127.0.0.1",
                0,
            ),
        )
        .await
        .map_err(|_| "堡垒机 direct-tcpip 隧道建立超时（15 秒）".to_string())?
        .map_err(|error| format!("堡垒机拒绝 direct-tcpip 隧道: {}", error))?;

        let (handler, verification) = client_handler(
            &options.host,
            options.port,
            options.expected_host_key_fingerprint.as_deref(),
        )?;
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            russh::client::connect_stream(ssh_client_config(), channel.into_stream(), handler),
        )
        .await
        .map_err(|_| "通过堡垒机连接目标超时（15 秒）".to_string())?;
        let mut target = result.map_err(|error| {
            connect_error(
                &options.host,
                options.port,
                &options.username,
                &verification,
                error,
            )
        })?;
        let host_key_fingerprint = confirmed_fingerprint(
            &options.host,
            options.port,
            &options.username,
            &verification,
        )?;
        authenticate_handle(
            &mut target,
            &options.host,
            options.port,
            &options.username,
            &options.authentication,
        )
        .await?;
        Ok(ConnectedHandles {
            target,
            jump: Some(jump_handle),
            host_key_fingerprint,
        })
    } else {
        let (mut target, host_key_fingerprint) = connect_direct_transport(
            &options.host,
            options.port,
            &options.username,
            options.expected_host_key_fingerprint.as_deref(),
        )
        .await?;
        authenticate_handle(
            &mut target,
            &options.host,
            options.port,
            &options.username,
            &options.authentication,
        )
        .await?;
        Ok(ConnectedHandles {
            target,
            jump: None,
            host_key_fingerprint,
        })
    }
}

async fn execute_command_async(
    handle: &Handle<ClientHandler>,
    command: &str,
) -> Result<TerminalOutput, String> {
    // Open a session channel
    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("Failed to open channel: {}", e))?;

    // Execute command
    channel
        .exec(true, command)
        .await
        .map_err(|e| format!("Failed to execute command: {}", e))?;

    // Read output
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit_code: Option<i32> = None;

    let mut channel = channel;
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Data { data }) => {
                stdout.extend_from_slice(&data);
            }
            Some(ChannelMsg::ExtendedData { data, ext }) => {
                if ext == 1 {
                    // stderr
                    stderr.extend_from_slice(&data);
                }
            }
            Some(ChannelMsg::ExitStatus { exit_status }) => {
                exit_code = Some(exit_status as i32);
            }
            Some(ChannelMsg::Eof) | None => {
                break;
            }
            _ => {}
        }
    }

    // Combine stdout and stderr, with stderr appended if not empty
    let mut output = String::from_utf8_lossy(&stdout).to_string();
    if !stderr.is_empty() {
        if !output.is_empty() && !output.ends_with('\n') {
            output.push('\n');
        }
        output.push_str(&String::from_utf8_lossy(&stderr));
    }

    Ok(TerminalOutput::new(command, &output, exit_code))
}

async fn probe_sftp_support(handle: &Handle<ClientHandler>) -> bool {
    let probe = async {
        let channel = handle
            .channel_open_session()
            .await
            .map_err(|error| error.to_string())?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|error| error.to_string())?;
        let _sftp = SftpSession::new(channel.into_stream())
            .await
            .map_err(|error| error.to_string())?;
        Ok::<(), String>(())
    };
    matches!(
        tokio::time::timeout(std::time::Duration::from_secs(3), probe).await,
        Ok(Ok(()))
    )
}

async fn probe_pty_support(handle: &Handle<ClientHandler>) -> bool {
    let probe = async {
        let channel = handle.channel_open_session().await?;
        channel
            .request_pty(true, "xterm-256color", 80, 24, 0, 0, &[])
            .await?;
        channel.close().await?;
        Ok::<(), russh::Error>(())
    };
    matches!(
        tokio::time::timeout(std::time::Duration::from_secs(3), probe).await,
        Ok(Ok(()))
    )
}

async fn probe_target_capabilities_async(
    handle: &Handle<ClientHandler>,
) -> Result<crate::ssh_compat::TargetCapabilities, String> {
    let command_probe = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        execute_command_async(handle, crate::ssh_compat::CAPABILITY_PROBE_SCRIPT),
    );
    let (command_result, sftp, pty) = tokio::join!(
        command_probe,
        probe_sftp_support(handle),
        probe_pty_support(handle),
    );
    let mut capabilities = match command_result {
        Ok(Ok(output)) if output.is_success() => {
            match crate::ssh_compat::parse_capability_probe(&output.output) {
                Ok(capabilities) => capabilities,
                Err(error) => {
                    let mut fallback = crate::ssh_compat::TargetCapabilities::default();
                    fallback.probe_error = Some(error);
                    fallback
                }
            }
        }
        Ok(Ok(output)) => {
            let mut fallback = crate::ssh_compat::TargetCapabilities::default();
            fallback.probe_error = Some(format!(
                "目标拒绝能力探测命令，退出码 {:?}",
                output.exit_code
            ));
            fallback
        }
        Ok(Err(error)) => {
            let mut fallback = crate::ssh_compat::TargetCapabilities::default();
            fallback.probe_error = Some(format!("目标无法执行能力探测命令: {}", error));
            fallback
        }
        Err(_) => {
            let mut fallback = crate::ssh_compat::TargetCapabilities::default();
            fallback.probe_error = Some("目标能力探测命令超时（5 秒）".to_string());
            fallback
        }
    };
    capabilities.sftp = sftp;
    capabilities.pty = pty;
    Ok(capabilities)
}

async fn list_sftp_files_async(
    handle: &Handle<ClientHandler>,
    path: &str,
) -> Result<Vec<SftpFileInfo>, String> {
    // Open SFTP subsystem
    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("Failed to open channel: {}", e))?;

    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| format!("Failed to request SFTP subsystem: {}", e))?;

    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| format!("Failed to create SFTP session: {}", e))?;

    // Read directory
    let dir = sftp
        .read_dir(path)
        .await
        .map_err(|e| format!("Failed to read directory: {}", e))?;

    let mut files = Vec::new();
    for entry in dir {
        let file_name = entry.file_name();
        let file_path = if path.ends_with('/') {
            format!("{}{}", path, file_name)
        } else {
            format!("{}/{}", path, file_name)
        };

        let attrs = entry.metadata();
        // 根据 permissions 字段判断文件类型
        // Unix 文件类型掩码: 0o170000
        // S_IFDIR  = 0o040000 (目录)
        // S_IFREG  = 0o100000 (普通文件)
        // S_IFLNK  = 0o120000 (符号链接)
        let (file_type, is_dir) = if let Some(perms) = attrs.permissions {
            let file_type_bits = perms & 0o170000;
            match file_type_bits {
                0o040000 => ("directory".to_string(), true), // S_IFDIR
                0o120000 => ("symlink".to_string(), false),  // S_IFLNK
                0o100000 => ("file".to_string(), false),     // S_IFREG
                _ => ("other".to_string(), false),
            }
        } else {
            // 如果没有 permissions，使用 file_type() 方法
            let ft = entry.file_type();
            if ft.is_dir() {
                ("directory".to_string(), true)
            } else if ft.is_symlink() {
                ("symlink".to_string(), false)
            } else {
                ("file".to_string(), false)
            }
        };
        let size = attrs.size.unwrap_or(0);

        let modified = attrs.mtime.map(|t| {
            chrono::DateTime::from_timestamp(t as i64, 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_default()
        });

        let permissions = attrs.permissions.map(|p| format!("{:o}", p));

        // Extract owner/group: prefer string names (SFTP v4+), fall back to uid/gid
        let owner = attrs
            .user
            .clone()
            .or_else(|| attrs.uid.map(|u| u.to_string()));
        let group = attrs
            .group
            .clone()
            .or_else(|| attrs.gid.map(|g| g.to_string()));

        files.push(SftpFileInfo {
            name: file_name,
            path: file_path,
            file_type,
            is_dir,
            size,
            modified,
            permissions,
            owner,
            group,
        });
    }

    Ok(files)
}

async fn read_sftp_file_async(
    handle: &Handle<ClientHandler>,
    path: &str,
) -> Result<Vec<u8>, String> {
    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("Failed to open channel: {}", e))?;

    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| format!("Failed to request SFTP subsystem: {}", e))?;

    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| format!("Failed to create SFTP session: {}", e))?;

    let mut file = sftp
        .open(path)
        .await
        .map_err(|e| format!("Failed to open file: {}", e))?;

    let mut content = Vec::new();
    file.read_to_end(&mut content)
        .await
        .map_err(|e| format!("Failed to read file: {}", e))?;

    Ok(content)
}

async fn write_sftp_file_async(
    handle: &Handle<ClientHandler>,
    path: &str,
    content: &[u8],
) -> Result<(), String> {
    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("Failed to open channel: {}", e))?;

    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| format!("Failed to request SFTP subsystem: {}", e))?;

    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| format!("Failed to create SFTP session: {}", e))?;

    let mut file = sftp
        .create(path)
        .await
        .map_err(|e| format!("Failed to create file: {}", e))?;

    file.write_all(content)
        .await
        .map_err(|e| format!("Failed to write file: {}", e))?;

    Ok(())
}

async fn atomic_write_sftp_file_async(
    handle: &Handle<ClientHandler>,
    path: &str,
    backup_path: &str,
    content: &[u8],
) -> Result<AtomicSftpWriteReceipt, String> {
    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("Failed to open channel: {}", e))?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| format!("Failed to request SFTP subsystem: {}", e))?;
    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| format!("Failed to create SFTP session: {}", e))?;

    let link_metadata = sftp
        .symlink_metadata(path)
        .await
        .map_err(|e| format!("Failed to inspect original file: {}", e))?;
    if link_metadata.is_symlink() {
        return Err("Atomic editor refuses to replace symbolic links".to_string());
    }
    if !link_metadata.is_regular() {
        return Err("Atomic editor target must be a regular file".to_string());
    }
    let metadata = sftp
        .metadata(path)
        .await
        .map_err(|e| format!("Failed to stat original file: {}", e))?;
    if sftp.metadata(backup_path).await.is_ok() {
        return Err("Backup path already exists; refusing to overwrite it".to_string());
    }

    let temp_path = format!("{}.lovelyres.tmp.{}", path, uuid::Uuid::new_v4());
    let mut temp_file = sftp
        .create(&temp_path)
        .await
        .map_err(|e| format!("Failed to create temporary file: {}", e))?;
    if let Err(error) = temp_file.write_all(content).await {
        let _ = sftp.remove_file(&temp_path).await;
        return Err(format!("Failed to write temporary file: {}", error));
    }

    let preserved = russh_sftp::protocol::FileAttributes {
        uid: metadata.uid,
        gid: metadata.gid,
        permissions: metadata.permissions,
        ..Default::default()
    };
    if let Err(error) = temp_file.set_metadata(preserved).await {
        let _ = sftp.remove_file(&temp_path).await;
        return Err(format!(
            "Failed to preserve file ownership/permissions: {}",
            error
        ));
    }
    if let Err(error) = temp_file.sync_all().await {
        let _ = sftp.remove_file(&temp_path).await;
        return Err(format!("Failed to sync temporary file: {}", error));
    }
    if let Err(error) = temp_file.close().await {
        let _ = sftp.remove_file(&temp_path).await;
        return Err(format!("Failed to close temporary file: {}", error));
    }

    sftp.rename(path, backup_path)
        .await
        .map_err(|e| format!("Failed to create backup: {}", e))?;
    if let Err(error) = sftp.rename(&temp_path, path).await {
        let restore = sftp.rename(backup_path, path).await;
        let _ = sftp.remove_file(&temp_path).await;
        return Err(format!(
            "Failed to install temporary file: {}; original restore: {}",
            error,
            if restore.is_ok() { "ok" } else { "failed" }
        ));
    }

    let mut verify_file = match sftp.open(path).await {
        Ok(file) => file,
        Err(error) => {
            let _ = sftp.remove_file(path).await;
            let restore = sftp.rename(backup_path, path).await;
            return Err(format!(
                "Verification open failed: {}; original restore: {}",
                error,
                if restore.is_ok() { "ok" } else { "failed" }
            ));
        }
    };
    let mut verify_content = Vec::new();
    if let Err(error) = verify_file.read_to_end(&mut verify_content).await {
        let _ = sftp.remove_file(path).await;
        let restore = sftp.rename(backup_path, path).await;
        return Err(format!(
            "Verification read failed: {}; original restore: {}",
            error,
            if restore.is_ok() { "ok" } else { "failed" }
        ));
    }
    if verify_content != content {
        let _ = sftp.remove_file(path).await;
        let restore = sftp.rename(backup_path, path).await;
        return Err(format!(
            "Read-back mismatch after atomic write; original restore: {}",
            if restore.is_ok() { "ok" } else { "failed" }
        ));
    }

    Ok(AtomicSftpWriteReceipt {
        path: path.to_string(),
        backup_path: backup_path.to_string(),
        bytes_written: content.len(),
        preserved_permissions: metadata.permissions,
        preserved_uid: metadata.uid,
        preserved_gid: metadata.gid,
    })
}

async fn delete_sftp_file_async(handle: &Handle<ClientHandler>, path: &str) -> Result<(), String> {
    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("Failed to open channel: {}", e))?;

    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| format!("Failed to request SFTP subsystem: {}", e))?;

    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| format!("Failed to create SFTP session: {}", e))?;

    sftp.remove_file(path)
        .await
        .map_err(|e| format!("Failed to delete file: {}", e))?;

    Ok(())
}

async fn create_sftp_directory_async(
    handle: &Handle<ClientHandler>,
    path: &str,
) -> Result<(), String> {
    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("Failed to open channel: {}", e))?;

    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| format!("Failed to request SFTP subsystem: {}", e))?;

    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| format!("Failed to create SFTP session: {}", e))?;

    sftp.create_dir(path)
        .await
        .map_err(|e| format!("Failed to create directory: {}", e))?;

    Ok(())
}

async fn rename_sftp_file_async(
    handle: &Handle<ClientHandler>,
    old_path: &str,
    new_path: &str,
) -> Result<(), String> {
    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("Failed to open channel: {}", e))?;

    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| format!("Failed to request SFTP subsystem: {}", e))?;

    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| format!("Failed to create SFTP session: {}", e))?;

    sftp.rename(old_path, new_path)
        .await
        .map_err(|e| format!("Failed to rename file: {}", e))?;

    Ok(())
}

// ================== Worker Thread ==================

fn run_worker(rx: mpsc::Receiver<WorkerCommand>) {
    // Create a new Tokio runtime in this dedicated thread
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("Failed to create Tokio runtime for SSH worker");

    rt.block_on(async {
        let mut sessions: HashMap<String, SessionData> = HashMap::new();
        let terminal_sessions: Arc<tokio::sync::Mutex<HashMap<String, TerminalSession>>> = 
            Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        
        loop {
            // Check for commands (non-blocking with a small timeout to allow checking)
            let cmd = match rx.recv() {
                Ok(cmd) => cmd,
                Err(_) => break, // Channel closed
            };
            
            match cmd {
                WorkerCommand::Connect {
                    options,
                    response_tx,
                } => {
                    let result = connect_async(&options).await;
                    match result {
                        Ok(connected) => {
                            let session_id = format!(
                                "{}@{}:{}#{}",
                                options.username,
                                options.host,
                                options.port,
                                uuid::Uuid::new_v4()
                            );
                            let info = ConnectionInfo {
                                host: options.host.clone(),
                                port: options.port,
                                username: options.username.clone(),
                                auth_method: options.authentication.method.label().to_string(),
                                host_key_fingerprint: connected.host_key_fingerprint,
                            };
                            sessions.insert(
                                session_id.clone(),
                                SessionData {
                                    handle: Arc::new(connected.target),
                                    _jump_handle: connected.jump.map(Arc::new),
                                    info,
                                    packet_capture_channel: None,
                                },
                            );
                            let _ = response_tx.send(Ok(session_id));
                        }
                        Err(e) => {
                            let _ = response_tx.send(Err(e));
                        }
                    }
                }
                
                WorkerCommand::ExecuteCommand { session_id, command, timeout, response_tx } => {
                    if let Some(session) = sessions.get(&session_id) {
                        let handle = Arc::clone(&session.handle);
                        tokio::spawn(async move {
                            let start = std::time::Instant::now();
                            let result = match tokio::time::timeout(
                                timeout,
                                execute_command_async(&handle, &command),
                            ).await {
                                Ok(result) => result.map(|output| output.with_duration(start.elapsed())),
                                Err(_) => Ok(TerminalOutput::timeout(&command, timeout)),
                            };
                            let _ = response_tx.send(result);
                        });
                    } else {
                        let _ = response_tx.send(Err(format!("Session not found: {}", session_id)));
                    }
                }
                
                WorkerCommand::ListSftpFiles { session_id, path, response_tx } => {
                    if let Some(session) = sessions.get(&session_id) {
                        let handle = Arc::clone(&session.handle);
                        tokio::spawn(async move {
                            let result = list_sftp_files_async(&handle, &path).await;
                            let _ = response_tx.send(result);
                        });
                    } else {
                        let _ = response_tx.send(Err(format!("Session not found: {}", session_id)));
                    }
                }

                WorkerCommand::ReadSftpFile { session_id, path, response_tx } => {
                    if let Some(session) = sessions.get(&session_id) {
                        let handle = Arc::clone(&session.handle);
                        tokio::spawn(async move {
                            let result = read_sftp_file_async(&handle, &path).await;
                            let _ = response_tx.send(result);
                        });
                    } else {
                        let _ = response_tx.send(Err(format!("Session not found: {}", session_id)));
                    }
                }
                
                WorkerCommand::WriteSftpFile { session_id, path, content, response_tx } => {
                    if let Some(session) = sessions.get(&session_id) {
                        let handle = Arc::clone(&session.handle);
                        tokio::spawn(async move {
                            let result = write_sftp_file_async(&handle, &path, &content).await;
                            let _ = response_tx.send(result);
                        });
                    } else {
                        let _ = response_tx.send(Err(format!("Session not found: {}", session_id)));
                    }
                }

                WorkerCommand::AtomicWriteSftpFile { session_id, path, backup_path, content, response_tx } => {
                    if let Some(session) = sessions.get(&session_id) {
                        let handle = Arc::clone(&session.handle);
                        tokio::spawn(async move {
                            let result = atomic_write_sftp_file_async(&handle, &path, &backup_path, &content).await;
                            let _ = response_tx.send(result);
                        });
                    } else {
                        let _ = response_tx.send(Err(format!("Session not found: {}", session_id)));
                    }
                }

                WorkerCommand::DeleteSftpFile { session_id, path, response_tx } => {
                    if let Some(session) = sessions.get(&session_id) {
                        let handle = Arc::clone(&session.handle);
                        tokio::spawn(async move {
                            let result = delete_sftp_file_async(&handle, &path).await;
                            let _ = response_tx.send(result);
                        });
                    } else {
                        let _ = response_tx.send(Err(format!("Session not found: {}", session_id)));
                    }
                }

                WorkerCommand::CreateSftpDirectory { session_id, path, response_tx } => {
                    if let Some(session) = sessions.get(&session_id) {
                        let handle = Arc::clone(&session.handle);
                        tokio::spawn(async move {
                            let result = create_sftp_directory_async(&handle, &path).await;
                            let _ = response_tx.send(result);
                        });
                    } else {
                        let _ = response_tx.send(Err(format!("Session not found: {}", session_id)));
                    }
                }

                WorkerCommand::RenameSftpFile { session_id, old_path, new_path, response_tx } => {
                    if let Some(session) = sessions.get(&session_id) {
                        let handle = Arc::clone(&session.handle);
                        tokio::spawn(async move {
                            let result = rename_sftp_file_async(&handle, &old_path, &new_path).await;
                            let _ = response_tx.send(result);
                        });
                    } else {
                        let _ = response_tx.send(Err(format!("Session not found: {}", session_id)));
                    }
                }
                
                WorkerCommand::Disconnect { session_id, response_tx } => {
                    let result = if let Some(session) = sessions.remove(&session_id) {
                        let _ = session.handle.disconnect(Disconnect::ByApplication, "User disconnected", "en").await;
                        Ok(())
                    } else {
                        Err(format!("Session not found: {}", session_id))
                    };
                    let _ = response_tx.send(result);
                }
                
                WorkerCommand::DisconnectAll { response_tx } => {
                    for (_, session) in sessions.drain() {
                        let _ = session.handle.disconnect(Disconnect::ByApplication, "User disconnected", "en").await;
                    }
                    let _ = response_tx.send(Ok(()));
                }
                
                WorkerCommand::GetConnectionInfo { session_id, response_tx } => {
                    let info = sessions.get(&session_id).map(|s| s.info.clone());
                    let _ = response_tx.send(info);
                }
                WorkerCommand::ProbeCapabilities { session_id, response_tx } => {
                    if let Some(session) = sessions.get(&session_id) {
                        let handle = Arc::clone(&session.handle);
                        tokio::spawn(async move {
                            let result = probe_target_capabilities_async(&handle).await;
                            let _ = response_tx.send(result);
                        });
                    } else {
                        let _ = response_tx.send(Err(format!("Session not found: {}", session_id)));
                    }
                }
                
                WorkerCommand::IsConnected { session_id, response_tx } => {
                    let connected = sessions.contains_key(&session_id);
                    let _ = response_tx.send(connected);
                }
                
                WorkerCommand::ListSessions { response_tx } => {
                    let session_ids: Vec<String> = sessions.keys().cloned().collect();
                    let _ = response_tx.send(session_ids);
                }
                
                // Terminal session commands
                WorkerCommand::CreateTerminalSession { session_id, terminal_id, cols, rows, window, response_tx } => {
                    let result = if let Some(session) = sessions.get(&session_id) {
                        // Open a channel for the terminal
                        match session.handle.channel_open_session().await {
                            Ok(channel) => {
                                // Request PTY
                                let pty_result = channel.request_pty(
                                    true,
                                    "xterm-256color",
                                    cols,
                                    rows,
                                    0, // pixel width
                                    0, // pixel height
                                    &[], // modes
                                ).await;
                                
                                if let Err(e) = pty_result {
                                    let _ = response_tx.send(Err(format!("Failed to request PTY: {}", e)));
                                    continue;
                                }
                                
                                // Request shell
                                if let Err(e) = channel.request_shell(true).await {
                                    let _ = response_tx.send(Err(format!("Failed to request shell: {}", e)));
                                    continue;
                                }
                                
                                // Create terminal session
                                let terminal_session = TerminalSession {
                                    channel,
                                    _session_id: session_id.clone(),
                                    _window: window.clone(),
                                };
                                
                                // Store it
                                let terminal_id_clone = terminal_id.clone();
                                let mut terminals = terminal_sessions.lock().await;
                                terminals.insert(terminal_id.clone(), terminal_session);
                                drop(terminals);
                                
                                // Spawn a task to read output from the channel and emit to window
                                let terminal_sessions_clone = terminal_sessions.clone();
                                let window_clone = window.clone();
                                
                                tokio::spawn(async move {
                                    loop {
                                        let mut terminals = terminal_sessions_clone.lock().await;
                                        if let Some(term) = terminals.get_mut(&terminal_id_clone) {
                                            // Try to receive data from the channel
                                            match tokio::time::timeout(
                                                std::time::Duration::from_millis(50),
                                                term.channel.wait()
                                            ).await {
                                                Ok(Some(msg)) => {
                                                    match msg {
                                                        ChannelMsg::Data { data } => {
                                                            // Send data to frontend using the same format as ssh_manager.rs
                                                            let output = String::from_utf8_lossy(&data).to_string();
                                                            let _ = window_clone.emit(
                                                                "ssh_terminal_data",
                                                                serde_json::json!({"terminalId": terminal_id_clone, "data": output}),
                                                            );
                                                        }
                                                        ChannelMsg::ExtendedData { data, ext } => {
                                                            // stderr (ext == 1)
                                                            if ext == 1 {
                                                                let output = String::from_utf8_lossy(&data).to_string();
                                                                let _ = window_clone.emit(
                                                                    "ssh_terminal_data",
                                                                    serde_json::json!({"terminalId": terminal_id_clone, "data": output}),
                                                                );
                                                            }
                                                        }
                                                        ChannelMsg::ExitStatus { exit_status: _ } => {
                                                            let _ = window_clone.emit(
                                                                "ssh_terminal_closed",
                                                                serde_json::json!({"terminalId": terminal_id_clone}),
                                                            );
                                                            break;
                                                        }
                                                        ChannelMsg::Eof => {
                                                            let _ = window_clone.emit(
                                                                "ssh_terminal_closed",
                                                                serde_json::json!({"terminalId": terminal_id_clone}),
                                                            );
                                                            break;
                                                        }
                                                        ChannelMsg::Close => {
                                                            break;
                                                        }
                                                        _ => {}
                                                    }
                                                }
                                                Ok(None) => {
                                                    // Channel closed
                                                    break;
                                                }
                                                Err(_) => {
                                                    // Timeout - continue
                                                }
                                            }
                                        } else {
                                            // Terminal removed
                                            break;
                                        }
                                        drop(terminals);
                                        // Small yield to prevent busy loop
                                        tokio::task::yield_now().await;
                                    }
                                    
                                    // Clean up terminal session when done
                                    let mut terminals = terminal_sessions_clone.lock().await;
                                    terminals.remove(&terminal_id_clone);
                                });
                                
                                Ok(())
                            }
                            Err(e) => Err(format!("Failed to open channel: {}", e)),
                        }
                    } else {
                        Err(format!("Session not found: {}", session_id))
                    };
                    let _ = response_tx.send(result);
                }
                
                WorkerCommand::SendTerminalInput { terminal_id, data, response_tx } => {
                    let mut terminals = terminal_sessions.lock().await;
                    let result = if let Some(term) = terminals.get_mut(&terminal_id) {
                        term.channel.data(&data[..]).await
                            .map_err(|e| format!("Failed to send data: {}", e))
                    } else {
                        Err(format!("Terminal session not found: {}", terminal_id))
                    };
                    drop(terminals);
                    let _ = response_tx.send(result);
                }
                
                WorkerCommand::CloseTerminalSession { terminal_id, response_tx } => {
                    let mut terminals = terminal_sessions.lock().await;
                    let result = if let Some(term) = terminals.remove(&terminal_id) {
                        let _ = term.channel.eof().await;
                        let _ = term.channel.close().await;
                        Ok(())
                    } else {
                        Ok(()) // Already closed
                    };
                    drop(terminals);
                    let _ = response_tx.send(result);
                }
                
                WorkerCommand::CloseAllTerminalSessions { response_tx } => {
                    let mut terminals = terminal_sessions.lock().await;
                    for (_, term) in terminals.drain() {
                        let _ = term.channel.eof().await;
                        let _ = term.channel.close().await;
                    }
                    drop(terminals);
                    let _ = response_tx.send(Ok(()));
                }
                
                WorkerCommand::ResizeTerminal { terminal_id, cols, rows, response_tx } => {
                    let terminals = terminal_sessions.lock().await;
                    let result = if let Some(term) = terminals.get(&terminal_id) {
                        term.channel.window_change(cols, rows, 0, 0).await
                            .map_err(|e| format!("Failed to resize terminal: {}", e))
                    } else {
                        Err(format!("Terminal session not found: {}", terminal_id))
                    };
                    drop(terminals);
                    let _ = response_tx.send(result);
                }

                WorkerCommand::StartPacketCapture { session_id, interface, filter, count, window, response_tx } => {
                    let result = if let Some(session) = sessions.get_mut(&session_id) {
                        // Stop existing capture if any
                        if let Some(tx) = session.packet_capture_channel.take() {
                            let _ = tx.send(());
                        }

                        // Create new cancellation channel
                        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
                        session.packet_capture_channel = Some(cancel_tx);

                        // Generate command
                        let cmd = crate::packet_capture::generate_tcpdump_command(&interface, filter.as_deref(), count);
                        let window_clone = window.clone();

                        // Open the channel BEFORE spawning the task (can't clone Handle)
                        match session.handle.channel_open_session().await {
                            Ok(mut channel) => {
                                // Execute the capture command
                                let cmd_bytes: Vec<u8> = cmd.as_bytes().to_vec();
                                if let Err(e) = channel.exec(true, cmd_bytes.as_slice()).await {
                                    let _ = window_clone.emit("packet_capture_error", format!("Failed to execute command: {}", e));
                                } else {
                                    // Spawn capture task to read output
                                    tokio::spawn(async move {
                                        let mut cancel_rx = cancel_rx;
                                        let mut buffer = Vec::new();
                                        let mut packet_id = 0;

                                        loop {
                                            tokio::select! {
                                                _ = &mut cancel_rx => {
                                                    // Cancelled
                                                    let _ = channel.close().await;
                                                    break;
                                                }
                                                msg = channel.wait() => {
                                                    match msg {
                                                        Some(ChannelMsg::Data { data }) => {
                                                            buffer.extend_from_slice(&data);
                                                            
                                                            // Process lines
                                                            while let Some(pos) = buffer.iter().position(|&b| b == b'\n') {
                                                                let line_bytes = buffer.drain(..=pos).collect::<Vec<u8>>();
                                                                let line = String::from_utf8_lossy(&line_bytes);
                                                                let trimmed_line = line.trim();
                                                                
                                                                if !trimmed_line.is_empty() {
                                                                    packet_id += 1;
                                                                    let packet = crate::packet_capture::parse_tcpdump_line(trimmed_line, packet_id);
                                                                    let _ = window_clone.emit("packet_capture_data", packet);
                                                                }
                                                            }
                                                        }
                                                        Some(ChannelMsg::ExtendedData { data, .. }) => {
                                                            let info = String::from_utf8_lossy(&data);
                                                            let _ = window_clone.emit("packet_capture_info", info.to_string());
                                                        }
                                                        Some(ChannelMsg::ExitStatus { .. }) | Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => {
                                                            break;
                                                        }
                                                        _ => {}
                                                    }
                                                }
                                            }
                                        }
                                        
                                        let _ = window_clone.emit("packet_capture_stopped", ());
                                    });
                                }
                            }
                            Err(e) => {
                                let _ = window_clone.emit("packet_capture_error", format!("Failed to open channel: {}", e));
                            }
                        }

                        Ok(())
                    } else {
                        Err(format!("Session not found: {}", session_id))
                    };
                    let _ = response_tx.send(result);
                }

                WorkerCommand::StopPacketCapture { session_id, response_tx } => {
                    let result = if let Some(session) = sessions.get_mut(&session_id) {
                        if let Some(tx) = session.packet_capture_channel.take() {
                            let _ = tx.send(());
                            Ok(())
                        } else {
                            Ok(()) // Already stopped
                        }
                    } else {
                        Err(format!("Session not found: {}", session_id))
                    };
                    let _ = response_tx.send(result);
                }
                
                WorkerCommand::ExecuteBatch { session_id, commands, response_tx } => {
                    if let Some(session) = sessions.get(&session_id) {
                        let handle = Arc::clone(&session.handle);
                        tokio::spawn(async move {
                            // Execute all commands in parallel using separate SSH channels
                            let mut futures = Vec::with_capacity(commands.len());
                            for cmd in &commands {
                                futures.push(execute_command_async(&handle, cmd));
                            }
                            let results = futures::future::join_all(futures).await;
                            let _ = response_tx.send(Ok(results));
                        });
                    } else {
                        let _ = response_tx.send(Err(format!("Session not found: {}", session_id)));
                    }
                }
                
                WorkerCommand::Shutdown => {
                    // Disconnect all sessions before shutdown
                    for (_, session) in sessions.drain() {
                        let _ = session.handle.disconnect(Disconnect::ByApplication, "Shutdown", "en").await;
                    }
                    break;
                }
            }
        }
    });
}

// ================== Main SSHManager Struct ==================

pub struct SSHManagerRussh {
    /// Wrapped in Mutex to make SSHManagerRussh Sync-safe.
    /// The Mutex is only held for the duration of send() (microseconds),
    /// NOT for the entire command execution, enabling true concurrency.
    worker_tx: Mutex<mpsc::Sender<WorkerCommand>>,
    _worker_handle: Mutex<thread::JoinHandle<()>>,
    // Track current active session for backward compatibility
    current_session: Arc<Mutex<Option<String>>>,
    /// Per-session busybox path. Never let one target's trusted shell wrap commands on another.
    busybox_paths: Mutex<HashMap<String, String>>,
}

impl SSHManagerRussh {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || run_worker(rx));

        Self {
            worker_tx: Mutex::new(tx),
            _worker_handle: Mutex::new(handle),
            current_session: Arc::new(Mutex::new(None)),
            busybox_paths: Mutex::new(HashMap::new()),
        }
    }

    /// Send a command to the worker thread. The Mutex is only held for send().
    fn send_to_worker(&self, cmd: WorkerCommand) -> Result<(), String> {
        self.worker_tx
            .lock()
            .map_err(|_| "Failed to acquire worker lock".to_string())?
            .send(cmd)
            .map_err(|_| "Worker thread has shut down".to_string())
    }

    fn get_current_session(&self) -> Result<String, String> {
        self.current_session
            .lock()
            .map_err(|_| "Failed to lock session".to_string())?
            .clone()
            .ok_or_else(|| "No active session. Please connect first.".to_string())
    }

    fn set_current_session(&self, session_id: Option<String>) {
        if let Ok(mut guard) = self.current_session.lock() {
            *guard = session_id;
        }
    }

    // ================== Connection Methods ==================

    /// Connect to SSH server (backward compatible - sets as current session)
    pub fn connect(
        &self,
        host: &str,
        port: u16,
        username: &str,
        password: Option<&str>,
        private_key: Option<&str>,
        expected_host_key_fingerprint: Option<&str>,
    ) -> Result<String, String> {
        let authentication = if let Some(private_key) = private_key {
            SSHAuthentication::private_key(private_key, password)
        } else {
            SSHAuthentication::password(password)
        };
        self.connect_with_options(SSHConnectOptions {
            host: host.to_string(),
            port,
            username: username.to_string(),
            authentication,
            expected_host_key_fingerprint: expected_host_key_fingerprint.map(str::to_string),
            jump_host: None,
        })
    }

    pub fn connect_with_options(&self, options: SSHConnectOptions) -> Result<String, String> {
        let (response_tx, response_rx) = mpsc::channel();

        self.send_to_worker(WorkerCommand::Connect {
            options,
            response_tx,
        })?;

        let result = response_rx
            .recv_timeout(std::time::Duration::from_secs(30))
            .map_err(|_| "连接超时：服务器在 30 秒内未响应".to_string())??;

        // Set as current session
        self.set_current_session(Some(result.clone()));

        Ok(result)
    }

    /// Execute command on current session (backward compatible)
    /// 如果启用了 busybox 模式，自动用 busybox sh -c 包裹命令
    pub fn execute_command(&self, command: &str) -> Result<TerminalOutput, String> {
        self.execute_command_with_timeout(command, std::time::Duration::from_secs(60))
    }

    pub fn execute_command_with_timeout(
        &self,
        command: &str,
        timeout: std::time::Duration,
    ) -> Result<TerminalOutput, String> {
        let session_id = self.get_current_session()?;
        let final_command = self.wrap_with_busybox_on_session(&session_id, command);
        self.execute_command_on_session_with_timeout(&session_id, &final_command, timeout)
    }

    /// 如果 busybox 已启用，用 busybox sh -c 执行命令
    /// busybox sh 是静态链接的，不受 LD_PRELOAD 和被篡改的系统命令影响
    fn wrap_with_busybox_on_session(&self, session_id: &str, command: &str) -> String {
        if let Ok(guard) = self.busybox_paths.lock() {
            if let Some(bb) = guard.get(session_id) {
                // 用 busybox sh -c 执行，确保 PATH 优先使用 busybox 自带命令
                // 设置 PATH 让 busybox 内置命令优先于系统命令
                let quoted_busybox = shell_quote(bb);
                let quoted_command = shell_quote(command);
                return format!(
                    "export BUSYBOX={}; {} sh -c {}",
                    quoted_busybox, quoted_busybox, quoted_command,
                );
            }
        }
        command.to_string()
    }

    // ── busybox 管理 ──

    /// 设置 busybox 路径（启用 busybox 模式）
    pub fn set_busybox_path_on_session(&self, session_id: &str, path: Option<String>) {
        if let Ok(mut guard) = self.busybox_paths.lock() {
            match path {
                Some(path) => {
                    guard.insert(session_id.to_string(), path);
                }
                None => {
                    guard.remove(session_id);
                }
            }
        }
    }

    /// 获取指定会话的 busybox 路径
    pub fn get_busybox_path_on_session(&self, session_id: &str) -> Option<String> {
        self.busybox_paths
            .lock()
            .ok()
            .and_then(|guard| guard.get(session_id).cloned())
    }

    /// Execute command on specific session
    pub fn execute_command_on_session(
        &self,
        session_id: &str,
        command: &str,
    ) -> Result<TerminalOutput, String> {
        self.execute_command_on_session_with_timeout(
            session_id,
            command,
            std::time::Duration::from_secs(60),
        )
    }

    pub fn execute_command_on_session_with_timeout(
        &self,
        session_id: &str,
        command: &str,
        timeout: std::time::Duration,
    ) -> Result<TerminalOutput, String> {
        let (response_tx, response_rx) = mpsc::channel();

        self.send_to_worker(WorkerCommand::ExecuteCommand {
            session_id: session_id.to_string(),
            command: command.to_string(),
            timeout,
            response_tx,
        })?;

        let wait_timeout = timeout + std::time::Duration::from_secs(2);
        response_rx
            .recv_timeout(wait_timeout)
            .map_err(|_| format!("命令执行超时（{} 秒）", timeout.as_secs()))?
    }

    /// Execute multiple commands in parallel on the current session
    pub fn execute_batch_commands(
        &self,
        commands: &[String],
    ) -> Result<Vec<Result<TerminalOutput, String>>, String> {
        let session_id = self.get_current_session()?;
        self.execute_batch_commands_on_session(&session_id, commands)
    }

    pub fn execute_batch_commands_on_session(
        &self,
        session_id: &str,
        commands: &[String],
    ) -> Result<Vec<Result<TerminalOutput, String>>, String> {
        let (response_tx, response_rx) = mpsc::channel();

        self.send_to_worker(WorkerCommand::ExecuteBatch {
            session_id: session_id.to_string(),
            commands: commands.to_vec(),
            response_tx,
        })?;

        // Longer timeout for batch: 60s base + 5s per command
        let timeout_secs = 60 + (commands.len() as u64 * 5);
        response_rx
            .recv_timeout(std::time::Duration::from_secs(timeout_secs))
            .map_err(|_| format!("批量命令执行超时（{} 秒）", timeout_secs))?
    }

    // ================== SFTP Methods ==================

    /// List files in directory on current session
    pub fn list_sftp_files(&self, path: &str) -> Result<Vec<SftpFileInfo>, String> {
        let session_id = self.get_current_session()?;
        self.list_sftp_files_on_session(&session_id, path)
    }

    /// List files in directory on specific session
    pub fn list_sftp_files_on_session(
        &self,
        session_id: &str,
        path: &str,
    ) -> Result<Vec<SftpFileInfo>, String> {
        let (response_tx, response_rx) = mpsc::channel();

        self.send_to_worker(WorkerCommand::ListSftpFiles {
            session_id: session_id.to_string(),
            path: path.to_string(),
            response_tx,
        })?;

        response_rx
            .recv_timeout(std::time::Duration::from_secs(120))
            .map_err(|_| "操作超时（120 秒）".to_string())?
    }

    /// Read file contents on current session
    pub fn read_sftp_file(&self, path: &str) -> Result<Vec<u8>, String> {
        let session_id = self.get_current_session()?;
        self.read_sftp_file_on_session(&session_id, path)
    }

    /// Read file contents on specific session
    pub fn read_sftp_file_on_session(
        &self,
        session_id: &str,
        path: &str,
    ) -> Result<Vec<u8>, String> {
        let (response_tx, response_rx) = mpsc::channel();

        self.send_to_worker(WorkerCommand::ReadSftpFile {
            session_id: session_id.to_string(),
            path: path.to_string(),
            response_tx,
        })?;

        response_rx
            .recv_timeout(std::time::Duration::from_secs(120))
            .map_err(|_| "操作超时（120 秒）".to_string())?
    }

    /// Write file on current session
    pub fn write_sftp_file(&self, path: &str, content: &[u8]) -> Result<(), String> {
        let session_id = self.get_current_session()?;
        self.write_sftp_file_on_session(&session_id, path, content)
    }

    /// Write file on specific session
    pub fn write_sftp_file_on_session(
        &self,
        session_id: &str,
        path: &str,
        content: &[u8],
    ) -> Result<(), String> {
        let (response_tx, response_rx) = mpsc::channel();

        self.send_to_worker(WorkerCommand::WriteSftpFile {
            session_id: session_id.to_string(),
            path: path.to_string(),
            content: content.to_vec(),
            response_tx,
        })?;

        response_rx
            .recv_timeout(std::time::Duration::from_secs(120))
            .map_err(|_| "操作超时（120 秒）".to_string())?
    }

    pub fn atomic_write_sftp_file_on_session(
        &self,
        session_id: &str,
        path: &str,
        backup_path: &str,
        content: &[u8],
    ) -> Result<AtomicSftpWriteReceipt, String> {
        let (response_tx, response_rx) = mpsc::channel();
        self.send_to_worker(WorkerCommand::AtomicWriteSftpFile {
            session_id: session_id.to_string(),
            path: path.to_string(),
            backup_path: backup_path.to_string(),
            content: content.to_vec(),
            response_tx,
        })?;
        response_rx
            .recv_timeout(std::time::Duration::from_secs(120))
            .map_err(|_| "操作超时（120 秒）".to_string())?
    }

    /// Delete file on current session
    pub fn delete_sftp_file(&self, path: &str) -> Result<(), String> {
        let session_id = self.get_current_session()?;
        self.delete_sftp_file_on_session(&session_id, path)
    }

    /// Delete file on specific session
    pub fn delete_sftp_file_on_session(&self, session_id: &str, path: &str) -> Result<(), String> {
        let (response_tx, response_rx) = mpsc::channel();

        self.send_to_worker(WorkerCommand::DeleteSftpFile {
            session_id: session_id.to_string(),
            path: path.to_string(),
            response_tx,
        })?;

        response_rx
            .recv_timeout(std::time::Duration::from_secs(120))
            .map_err(|_| "操作超时（120 秒）".to_string())?
    }

    /// Create directory on current session
    pub fn create_sftp_directory(&self, path: &str) -> Result<(), String> {
        let session_id = self.get_current_session()?;
        self.create_sftp_directory_on_session(&session_id, path)
    }

    /// Create directory on specific session
    pub fn create_sftp_directory_on_session(
        &self,
        session_id: &str,
        path: &str,
    ) -> Result<(), String> {
        let (response_tx, response_rx) = mpsc::channel();

        self.send_to_worker(WorkerCommand::CreateSftpDirectory {
            session_id: session_id.to_string(),
            path: path.to_string(),
            response_tx,
        })?;

        response_rx
            .recv_timeout(std::time::Duration::from_secs(120))
            .map_err(|_| "操作超时（120 秒）".to_string())?
    }

    /// Rename file on current session
    pub fn rename_sftp_file(&self, old_path: &str, new_path: &str) -> Result<(), String> {
        let session_id = self.get_current_session()?;
        self.rename_sftp_file_on_session(&session_id, old_path, new_path)
    }

    /// Rename file on specific session
    pub fn rename_sftp_file_on_session(
        &self,
        session_id: &str,
        old_path: &str,
        new_path: &str,
    ) -> Result<(), String> {
        let (response_tx, response_rx) = mpsc::channel();

        self.send_to_worker(WorkerCommand::RenameSftpFile {
            session_id: session_id.to_string(),
            old_path: old_path.to_string(),
            new_path: new_path.to_string(),
            response_tx,
        })?;

        response_rx
            .recv_timeout(std::time::Duration::from_secs(120))
            .map_err(|_| "操作超时（120 秒）".to_string())?
    }

    // ================== Session Management ==================

    /// Disconnect current session (backward compatible)
    pub fn disconnect(&self) -> Result<(), String> {
        if let Some(session_id) = self.current_session.lock().ok().and_then(|g| g.clone()) {
            self.disconnect_session(&session_id)?;
            self.set_current_session(None);
        }
        Ok(())
    }

    /// Disconnect specific session
    pub fn disconnect_session(&self, session_id: &str) -> Result<(), String> {
        let (response_tx, response_rx) = mpsc::channel();

        self.send_to_worker(WorkerCommand::Disconnect {
            session_id: session_id.to_string(),
            response_tx,
        })?;

        let result = response_rx
            .recv_timeout(std::time::Duration::from_secs(120))
            .map_err(|_| "操作超时（120 秒）".to_string())?;
        if result.is_ok() {
            if let Ok(mut paths) = self.busybox_paths.lock() {
                paths.remove(session_id);
            }
        }

        // If disconnecting current session, clear it
        if let Ok(guard) = self.current_session.lock() {
            if guard.as_ref() == Some(&session_id.to_string()) {
                drop(guard);
                self.set_current_session(None);
            }
        }

        result
    }

    /// Disconnect all sessions
    pub fn disconnect_all(&self) -> Result<(), String> {
        let (response_tx, response_rx) = mpsc::channel();

        self.send_to_worker(WorkerCommand::DisconnectAll { response_tx })?;

        self.set_current_session(None);
        if let Ok(mut paths) = self.busybox_paths.lock() {
            paths.clear();
        }

        response_rx
            .recv_timeout(std::time::Duration::from_secs(120))
            .map_err(|_| "操作超时（120 秒）".to_string())?
    }

    /// Check if current session is connected (backward compatible)
    pub fn is_connected(&self) -> bool {
        if let Some(session_id) = self.current_session.lock().ok().and_then(|g| g.clone()) {
            self.is_session_connected(&session_id)
        } else {
            false
        }
    }

    /// Check if specific session is connected
    pub fn is_session_connected(&self, session_id: &str) -> bool {
        let (response_tx, response_rx) = mpsc::channel();

        if self
            .send_to_worker(WorkerCommand::IsConnected {
                session_id: session_id.to_string(),
                response_tx,
            })
            .is_err()
        {
            return false;
        }

        response_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap_or(false)
    }

    /// Get connection info for current session
    pub fn get_connection_info(&self) -> Option<ConnectionInfo> {
        let session_id = self.current_session.lock().ok()?.clone()?;
        self.get_session_connection_info(&session_id)
    }

    /// Get connection info for specific session
    pub fn get_session_connection_info(&self, session_id: &str) -> Option<ConnectionInfo> {
        let (response_tx, response_rx) = mpsc::channel();

        if self
            .send_to_worker(WorkerCommand::GetConnectionInfo {
                session_id: session_id.to_string(),
                response_tx,
            })
            .is_err()
        {
            return None;
        }

        response_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .ok()
            .flatten()
    }

    pub fn probe_target_capabilities_on_session(
        &self,
        session_id: &str,
    ) -> Result<crate::ssh_compat::TargetCapabilities, String> {
        let (response_tx, response_rx) = mpsc::channel();
        self.send_to_worker(WorkerCommand::ProbeCapabilities {
            session_id: session_id.to_string(),
            response_tx,
        })?;
        response_rx
            .recv_timeout(std::time::Duration::from_secs(12))
            .map_err(|_| "目标能力探测在 12 秒内未返回".to_string())?
    }

    /// List all active sessions
    pub fn list_sessions(&self) -> Vec<String> {
        let (response_tx, response_rx) = mpsc::channel();

        if self
            .send_to_worker(WorkerCommand::ListSessions { response_tx })
            .is_err()
        {
            return Vec::new();
        }

        response_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap_or_default()
    }

    /// Get current session ID
    pub fn get_current_session_id(&self) -> Option<String> {
        self.current_session.lock().ok()?.clone()
    }

    /// Set current session by ID
    pub fn set_current_session_id(&self, session_id: &str) -> Result<(), String> {
        if self.is_session_connected(session_id) {
            self.set_current_session(Some(session_id.to_string()));
            Ok(())
        } else {
            Err(format!("Session not found: {}", session_id))
        }
    }

    // ================== Dashboard Command Methods (backward compatibility) ==================

    /// Execute dashboard command (same as execute_command, for backward compatibility)
    pub fn execute_dashboard_command(&self, command: &str) -> Result<TerminalOutput, String> {
        self.execute_command(command)
    }

    pub fn execute_dashboard_command_with_timeout(
        &self,
        command: &str,
        timeout: std::time::Duration,
    ) -> Result<TerminalOutput, String> {
        self.execute_command_with_timeout(command, timeout)
    }

    /// Execute dashboard command as specific user
    pub fn execute_dashboard_command_as_user(
        &self,
        command: &str,
        username: Option<&str>,
    ) -> Result<TerminalOutput, String> {
        self.execute_dashboard_command_as_user_with_timeout(
            command,
            username,
            std::time::Duration::from_secs(60),
        )
    }

    pub fn execute_dashboard_command_as_user_with_timeout(
        &self,
        command: &str,
        username: Option<&str>,
        timeout: std::time::Duration,
    ) -> Result<TerminalOutput, String> {
        let final_command = Self::command_as_user(command, username);

        self.execute_command_with_timeout(&final_command, timeout)
    }

    pub fn execute_dashboard_command_as_user_on_session_with_timeout(
        &self,
        session_id: &str,
        command: &str,
        username: Option<&str>,
        timeout: std::time::Duration,
    ) -> Result<TerminalOutput, String> {
        let final_command = Self::command_as_user(command, username);
        let final_command = self.wrap_with_busybox_on_session(session_id, &final_command);
        self.execute_command_on_session_with_timeout(session_id, &final_command, timeout)
    }

    fn command_as_user(command: &str, username: Option<&str>) -> String {
        if let Some(user) = username {
            // Use sudo -u to switch user for command execution
            // Use su -c as fallback if sudo is not available
            let quoted_user = shell_quote(user);
            let quoted_command = shell_quote(command);
            format!(
                "if command -v sudo >/dev/null 2>&1; then sudo -n -u {} sh -c {}; else su - {} -c {}; fi",
                quoted_user,
                quoted_command,
                quoted_user,
                quoted_command,
            )
        } else {
            command.to_string()
        }
    }

    /// Get connection status (backward compatibility)
    pub fn get_connection_status(&self) -> Option<SSHConnectionStatus> {
        let session_id = self.get_current_session_id()?;
        if let Some(info) = self.get_session_connection_info(&session_id) {
            Some(SSHConnectionStatus {
                connected: true,
                session_id,
                host_key_fingerprint: info.host_key_fingerprint,
                host: info.host,
                port: info.port,
                username: info.username,
                last_activity: chrono::Utc::now(),
            })
        } else {
            None
        }
    }

    /// Get file details via SFTP
    pub fn get_file_details(&self, path: &str) -> Result<SftpFileDetails, String> {
        let session_id = self.get_current_session()?;
        self.get_file_details_on_session(&session_id, path)
    }

    pub fn get_file_details_on_session(
        &self,
        session_id: &str,
        path: &str,
    ) -> Result<SftpFileDetails, String> {
        // Execute stat command to get file details
        let stat_cmd = format!(
            "stat -c '%n|%F|%s|%a|%U|%G|%W|%Y|%X' {} 2>/dev/null || ls -la {}",
            shell_quote(path),
            shell_quote(path),
        );

        let output = self.execute_dashboard_command_as_user_on_session_with_timeout(
            session_id,
            &stat_cmd,
            None,
            std::time::Duration::from_secs(60),
        )?;
        let output_str = output.output.trim();

        // Try to parse stat output
        let parts: Vec<&str> = output_str.split('|').collect();
        if parts.len() >= 9 {
            let name = std::path::Path::new(parts[0])
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| parts[0].to_string());

            let file_type = match parts[1] {
                "regular file" => "file",
                "regular empty file" => "file",
                "directory" => "directory",
                "symbolic link" => "symlink",
                "block special file" => "block",
                "character special file" => "char",
                "socket" => "socket",
                "FIFO" => "fifo",
                _ => "unknown",
            };

            let size: u64 = parts[2].parse().unwrap_or(0);
            let permissions = parts[3].to_string();
            let owner = Some(parts[4].to_string());
            let group = Some(parts[5].to_string());

            let created = parts[6]
                .parse::<i64>()
                .ok()
                .filter(|&t| t > 0)
                .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string());

            let modified = parts[7]
                .parse::<i64>()
                .ok()
                .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string());

            let accessed = parts[8]
                .parse::<i64>()
                .ok()
                .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string());

            Ok(SftpFileDetails {
                name,
                path: path.to_string(),
                file_type: file_type.to_string(),
                size,
                permissions,
                owner,
                group,
                created,
                modified,
                accessed,
            })
        } else {
            // Fallback: parse ls -la output
            let name = std::path::Path::new(path)
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| path.to_string());

            Ok(SftpFileDetails {
                name,
                path: path.to_string(),
                file_type: "unknown".to_string(),
                size: 0,
                permissions: "unknown".to_string(),
                owner: None,
                group: None,
                created: None,
                modified: None,
                accessed: None,
            })
        }
    }

    // ================== Additional Methods for Backward Compatibility ==================

    /// Create interactive terminal session
    pub fn create_terminal_session(
        &self,
        window: tauri::Window,
        terminal_id: &str,
        cols: u32,
        rows: u32,
    ) -> Result<(), String> {
        let session_id = self.get_current_session()?;
        self.create_terminal_session_on_session(&session_id, window, terminal_id, cols, rows)
    }

    pub fn create_terminal_session_on_session(
        &self,
        session_id: &str,
        window: tauri::Window,
        terminal_id: &str,
        cols: u32,
        rows: u32,
    ) -> Result<(), String> {
        let (response_tx, response_rx) = mpsc::channel();

        self.send_to_worker(WorkerCommand::CreateTerminalSession {
            session_id: session_id.to_string(),
            terminal_id: terminal_id.to_string(),
            cols,
            rows,
            window,
            response_tx,
        })?;

        response_rx
            .recv_timeout(std::time::Duration::from_secs(30))
            .map_err(|_| "Timeout waiting for terminal session creation".to_string())?
    }

    /// Close terminal session
    pub fn close_terminal_session(&self, terminal_id: &str) -> Result<(), String> {
        let (response_tx, response_rx) = mpsc::channel();

        self.send_to_worker(WorkerCommand::CloseTerminalSession {
            terminal_id: terminal_id.to_string(),
            response_tx,
        })?;

        response_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .map_err(|_| "Timeout waiting for terminal close".to_string())?
    }

    /// Close all terminal sessions
    pub fn close_all_terminal_sessions(&self) -> Result<(), String> {
        let (response_tx, response_rx) = mpsc::channel();

        self.send_to_worker(WorkerCommand::CloseAllTerminalSessions { response_tx })?;

        response_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .map_err(|_| "Timeout waiting for close all terminals".to_string())?
    }

    /// Send input to terminal
    pub fn send_terminal_input(&self, terminal_id: &str, data: Vec<u8>) -> Result<(), String> {
        let (response_tx, response_rx) = mpsc::channel();

        self.send_to_worker(WorkerCommand::SendTerminalInput {
            terminal_id: terminal_id.to_string(),
            data,
            response_tx,
        })?;

        response_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| "Timeout waiting for terminal input send".to_string())?
    }

    /// Resize terminal
    pub fn resize_terminal(&self, terminal_id: &str, cols: u32, rows: u32) -> Result<(), String> {
        let (response_tx, response_rx) = mpsc::channel();

        self.send_to_worker(WorkerCommand::ResizeTerminal {
            terminal_id: terminal_id.to_string(),
            cols,
            rows,
            response_tx,
        })?;

        response_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| "Timeout waiting for terminal resize".to_string())?
    }

    /// Change file permissions
    pub fn chmod_sftp(&self, path: &str, mode: u32) -> Result<(), String> {
        let session_id = self.get_current_session()?;
        self.chmod_sftp_on_session(&session_id, path, mode)
    }

    pub fn chmod_sftp_on_session(
        &self,
        session_id: &str,
        path: &str,
        mode: u32,
    ) -> Result<(), String> {
        let cmd = format!("chmod {:o} -- {}", mode, shell_quote(path));
        let output = self.execute_dashboard_command_as_user_on_session_with_timeout(
            session_id,
            &cmd,
            None,
            std::time::Duration::from_secs(60),
        )?;
        if !output.is_success() {
            return Err(format!("修改权限失败: {}", output.output));
        }
        Ok(())
    }

    // ================== Packet Capture Methods ==================

    pub fn start_packet_capture(
        &self,
        interface: &str,
        filter: Option<String>,
        count: Option<u32>,
        window: tauri::Window,
    ) -> Result<(), String> {
        let session_id = self.get_current_session()?;
        self.start_packet_capture_on_session(&session_id, interface, filter, count, window)
    }

    pub fn start_packet_capture_on_session(
        &self,
        session_id: &str,
        interface: &str,
        filter: Option<String>,
        count: Option<u32>,
        window: tauri::Window,
    ) -> Result<(), String> {
        let (response_tx, response_rx) = mpsc::channel();

        self.send_to_worker(WorkerCommand::StartPacketCapture {
            session_id: session_id.to_string(),
            interface: interface.to_string(),
            filter,
            count,
            window,
            response_tx,
        })?;

        response_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| "Timeout waiting for packet capture start".to_string())?
    }

    pub fn stop_packet_capture(&self) -> Result<(), String> {
        let session_id = self.get_current_session()?;
        self.stop_packet_capture_on_session(&session_id)
    }

    pub fn stop_packet_capture_on_session(&self, session_id: &str) -> Result<(), String> {
        let (response_tx, response_rx) = mpsc::channel();

        self.send_to_worker(WorkerCommand::StopPacketCapture {
            session_id: session_id.to_string(),
            response_tx,
        })?;

        response_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| "Timeout waiting for packet capture stop".to_string())?
    }

    /// Get bash environment info
    pub fn get_bash_environment_info(&self) -> Result<crate::types::BashEnvironmentInfo, String> {
        let session_id = self.get_current_session()?;
        self.get_bash_environment_info_on_session(&session_id)
    }

    pub fn get_bash_environment_info_on_session(
        &self,
        session_id: &str,
    ) -> Result<crate::types::BashEnvironmentInfo, String> {
        let cmd = r#"echo "BASH_VERSION=$BASH_VERSION"
echo "SHELL=$SHELL"
echo "PS1=$PS1"
echo "PWD=$PWD"
echo "HOME=$HOME"
echo "USER=$USER"
echo "HOSTNAME=$(hostname)"
echo "PATH=$PATH""#;

        let output = self.execute_dashboard_command_as_user_on_session_with_timeout(
            session_id,
            cmd,
            None,
            std::time::Duration::from_secs(60),
        )?;

        let mut bash_version = String::new();
        let mut shell_type = String::new();
        let mut ps1 = String::new();
        let mut pwd = String::new();
        let mut home = String::new();
        let mut user = String::new();
        let mut hostname = String::new();
        let mut path = String::new();

        for line in output.output.lines() {
            if let Some(val) = line.strip_prefix("BASH_VERSION=") {
                bash_version = val.to_string();
            } else if let Some(val) = line.strip_prefix("SHELL=") {
                shell_type = if val.contains("bash") {
                    "bash".to_string()
                } else {
                    "sh".to_string()
                };
            } else if let Some(val) = line.strip_prefix("PS1=") {
                ps1 = val.to_string();
            } else if let Some(val) = line.strip_prefix("PWD=") {
                pwd = val.to_string();
            } else if let Some(val) = line.strip_prefix("HOME=") {
                home = val.to_string();
            } else if let Some(val) = line.strip_prefix("USER=") {
                user = val.to_string();
            } else if let Some(val) = line.strip_prefix("HOSTNAME=") {
                hostname = val.to_string();
            } else if let Some(val) = line.strip_prefix("PATH=") {
                path = val.to_string();
            }
        }

        Ok(crate::types::BashEnvironmentInfo {
            bash_version,
            shell_type,
            ps1,
            pwd,
            home,
            user,
            hostname,
            path,
        })
    }

    /// Get command completion suggestions
    pub fn get_command_completion(
        &self,
        input: &str,
    ) -> Result<crate::types::CommandCompletion, String> {
        let session_id = self.get_current_session()?;
        self.get_command_completion_on_session(&session_id, input)
    }

    pub fn get_command_completion_on_session(
        &self,
        session_id: &str,
        input: &str,
    ) -> Result<crate::types::CommandCompletion, String> {
        // Simple completion using compgen
        let cmd = format!(
            "compgen -c '{}' 2>/dev/null | head -20",
            input.replace("'", "'\\''")
        );
        let output = self.execute_dashboard_command_as_user_on_session_with_timeout(
            session_id,
            &cmd,
            None,
            std::time::Duration::from_secs(60),
        )?;
        let completions: Vec<String> = output.output.lines().map(|s| s.to_string()).collect();

        Ok(crate::types::CommandCompletion {
            completions,
            prefix: input.to_string(),
        })
    }

    /// Compress file
    pub fn compress_file(
        &self,
        source_path: &str,
        target_path: &str,
        format: &str,
    ) -> Result<(), String> {
        let session_id = self.get_current_session()?;
        self.compress_file_on_session(&session_id, source_path, target_path, format)
    }

    pub fn compress_file_on_session(
        &self,
        session_id: &str,
        source_path: &str,
        target_path: &str,
        format: &str,
    ) -> Result<(), String> {
        let cmd = match format.to_lowercase().as_str() {
            "zip" => format!(
                "zip -r -- {} {}",
                shell_quote(target_path),
                shell_quote(source_path),
            ),
            "tar.gz" | "tgz" => format!(
                "tar -czf {} -- {}",
                shell_quote(target_path),
                shell_quote(source_path),
            ),
            "tar.bz2" => format!(
                "tar -cjf {} -- {}",
                shell_quote(target_path),
                shell_quote(source_path),
            ),
            "tar" => format!(
                "tar -cf {} -- {}",
                shell_quote(target_path),
                shell_quote(source_path),
            ),
            _ => return Err(format!("Unsupported compression format: {}", format)),
        };

        let output = self.execute_dashboard_command_as_user_on_session_with_timeout(
            session_id,
            &cmd,
            None,
            std::time::Duration::from_secs(120),
        )?;
        if !output.is_success() {
            return Err(format!("Compression failed: {}", output.output));
        }
        Ok(())
    }

    /// Extract file
    pub fn extract_file(
        &self,
        source_path: &str,
        target_dir: &str,
        overwrite: bool,
    ) -> Result<(), String> {
        let session_id = self.get_current_session()?;
        self.extract_file_on_session(&session_id, source_path, target_dir, overwrite)
    }

    pub fn extract_file_on_session(
        &self,
        session_id: &str,
        source_path: &str,
        target_dir: &str,
        overwrite: bool,
    ) -> Result<(), String> {
        // Detect format and extract
        let cmd = if source_path.ends_with(".zip") {
            format!(
                "unzip {} {} -d {}",
                if overwrite { "-o" } else { "-n" },
                shell_quote(source_path),
                shell_quote(target_dir),
            )
        } else if source_path.ends_with(".tar.gz") || source_path.ends_with(".tgz") {
            format!(
                "tar -xzf {} -C {} {}",
                shell_quote(source_path),
                shell_quote(target_dir),
                if overwrite { "" } else { "--skip-old-files" }
            )
        } else if source_path.ends_with(".tar.bz2") {
            format!(
                "tar -xjf {} -C {} {}",
                shell_quote(source_path),
                shell_quote(target_dir),
                if overwrite { "" } else { "--skip-old-files" }
            )
        } else if source_path.ends_with(".tar") {
            format!(
                "tar -xf {} -C {} {}",
                shell_quote(source_path),
                shell_quote(target_dir),
                if overwrite { "" } else { "--skip-old-files" }
            )
        } else {
            return Err(format!("Unknown archive format: {}", source_path));
        };

        let output = self.execute_dashboard_command_as_user_on_session_with_timeout(
            session_id,
            &cmd,
            None,
            std::time::Duration::from_secs(120),
        )?;
        if !output.is_success() {
            return Err(format!("Extraction failed: {}", output.output));
        }
        Ok(())
    }

    /// Upload file from local to remote
    pub fn upload_file(&self, local_path: &str, remote_path: &str) -> Result<(), String> {
        let session_id = self.get_current_session()?;
        self.upload_file_on_session(&session_id, local_path, remote_path)
    }

    pub fn upload_file_on_session(
        &self,
        session_id: &str,
        local_path: &str,
        remote_path: &str,
    ) -> Result<(), String> {
        // Read local file
        let content =
            std::fs::read(local_path).map_err(|e| format!("Failed to read local file: {}", e))?;

        // Write to remote via SFTP
        self.write_sftp_file_on_session(session_id, remote_path, &content)
    }

    /// Download file from remote to local
    pub fn download_file(&self, remote_path: &str, local_path: &str) -> Result<(), String> {
        let session_id = self.get_current_session()?;
        self.download_file_on_session(&session_id, remote_path, local_path)
    }

    pub fn download_file_on_session(
        &self,
        session_id: &str,
        remote_path: &str,
        local_path: &str,
    ) -> Result<(), String> {
        // Read from remote via SFTP
        let content = self.read_sftp_file_on_session(session_id, remote_path)?;

        // Write to local file
        std::fs::write(local_path, &content)
            .map_err(|e| format!("Failed to write local file: {}", e))?;

        Ok(())
    }

    /// Create directory (alias for create_sftp_directory for backward compatibility)
    pub fn create_directory(&self, path: &str) -> Result<(), String> {
        self.create_sftp_directory(path)
    }
}

impl Default for SSHManagerRussh {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SSHManagerRussh {
    fn drop(&mut self) {
        // Send shutdown command to worker thread
        let _ = self.send_to_worker(WorkerCommand::Shutdown);
    }
}

#[cfg(test)]
mod terminal_output_tests {
    use super::{
        host_key_confirmation_error, keyboard_interactive_challenge, map_private_key_error,
        resolve_ssh_addresses, verify_or_learn_host_key, HostKeyVerification, TerminalOutput,
        HOST_KEY_CONFIRMATION_PREFIX, KEYBOARD_INTERACTIVE_CHALLENGE_PREFIX,
    };

    #[test]
    fn success_requires_zero_exit_code_and_no_timeout() {
        assert!(TerminalOutput::new("true", "", Some(0)).is_success());
        assert!(!TerminalOutput::new("false", "", Some(1)).is_success());
        assert!(!TerminalOutput::new("unknown", "", None).is_success());
        assert!(
            !TerminalOutput::timeout("sleep 10", std::time::Duration::from_secs(1)).is_success()
        );
    }

    #[test]
    fn known_hosts_requires_confirmation_then_rejects_changed_keys() {
        let path =
            std::env::temp_dir().join(format!("lovelyres-known-hosts-{}", uuid::Uuid::new_v4(),));
        let first = russh::keys::parse_public_key_base64(
            "AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ",
        )
        .expect("first public key");
        let changed = russh::keys::parse_public_key_base64(
            "AAAAC3NzaC1lZDI1NTE5AAAAILIG2T/B0l0gaqj3puu510tu9N1OkQ4znY3LYuEm5zCF",
        )
        .expect("changed public key");

        let observed = match verify_or_learn_host_key("example.test", 22, &first, &path, None) {
            HostKeyVerification::Unknown { fingerprint } => fingerprint,
            result => panic!("expected unknown host key, got {result:?}"),
        };
        assert!(!path.exists());
        assert!(matches!(
            verify_or_learn_host_key(
                "example.test",
                22,
                &first,
                &path,
                Some("SHA256:not-the-confirmed-key"),
            ),
            HostKeyVerification::Mismatch { .. }
        ));
        assert!(!path.exists());
        assert!(matches!(
            verify_or_learn_host_key("example.test", 22, &first, &path, Some(&observed)),
            HostKeyVerification::Learned { .. }
        ));
        assert!(matches!(
            verify_or_learn_host_key("example.test", 22, &first, &path, None),
            HostKeyVerification::Trusted { .. }
        ));
        assert!(matches!(
            verify_or_learn_host_key("example.test", 22, &changed, &path, Some(&observed)),
            HostKeyVerification::Mismatch { .. }
        ));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn unknown_host_key_error_has_a_machine_readable_contract() {
        let error = host_key_confirmation_error(
            "example.test",
            2222,
            "incident-user",
            "SHA256:confirmed-key",
        );
        let payload = error
            .strip_prefix(HOST_KEY_CONFIRMATION_PREFIX)
            .expect("confirmation error prefix");
        let value: serde_json::Value = serde_json::from_str(payload).expect("confirmation JSON");

        assert_eq!(value["code"], "HOST_KEY_CONFIRMATION_REQUIRED");
        assert_eq!(value["host"], "example.test");
        assert_eq!(value["port"], 2222);
        assert_eq!(value["username"], "incident-user");
        assert_eq!(value["fingerprint"], "SHA256:confirmed-key");
    }

    #[test]
    fn keyboard_interactive_challenge_contains_prompts_but_no_responses() {
        let prompts = vec![russh::client::Prompt {
            prompt: "Verification code:".to_string(),
            echo: false,
        }];
        let error = keyboard_interactive_challenge(
            "target.test",
            22,
            "incident",
            "MFA",
            "Enter OTP",
            &prompts,
            1,
        );
        let payload = error
            .strip_prefix(KEYBOARD_INTERACTIVE_CHALLENGE_PREFIX)
            .expect("keyboard challenge prefix");
        let value: serde_json::Value = serde_json::from_str(payload).expect("challenge JSON");
        assert_eq!(value["host"], "target.test");
        assert_eq!(value["prompts"][0]["echo"], false);
        assert!(!payload.contains("123456"));
    }

    #[test]
    fn rsa_private_keys_fail_closed_with_an_actionable_policy() {
        let error = map_private_key_error(
            "-----BEGIN RSA PRIVATE KEY-----\ninvalid\n-----END RSA PRIVATE KEY-----",
            "unsupported",
        );
        assert!(error.contains("RUSTSEC-2023-0071"));
        assert!(error.contains("Ed25519/ECDSA"));
    }

    #[tokio::test]
    async fn raw_ipv6_literals_are_resolved_without_manual_brackets() {
        let addresses = resolve_ssh_addresses("::1", 2222)
            .await
            .expect("resolve IPv6 loopback");
        let address = addresses.first().expect("at least one IPv6 address");
        assert!(address.is_ipv6());
        assert_eq!(address.port(), 2222);
    }
}

#[cfg(all(test, unix))]
mod real_linux_ssh_contract_tests {
    use super::{
        shell_quote, SSHAuthMethod, SSHAuthentication, SSHConnectOptions, SSHJumpHostOptions,
        SSHManagerRussh,
    };
    use sha2::{Digest, Sha256};
    use std::time::Duration;

    fn optional_env(name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|value| !value.is_empty())
    }

    fn bool_env(name: &str, default: bool) -> bool {
        optional_env(name)
            .map(|value| !matches!(value.as_str(), "0" | "false" | "no"))
            .unwrap_or(default)
    }

    fn authentication(prefix: &str) -> SSHAuthentication {
        let name = |suffix: &str| format!("{}_{}", prefix, suffix);
        let auth_type = optional_env(&name("AUTH_TYPE")).unwrap_or_else(|| "password".to_string());
        let method = match auth_type.as_str() {
            "password" => SSHAuthMethod::Password,
            "key" => SSHAuthMethod::PrivateKey,
            "certificate" => SSHAuthMethod::OpenSshCertificate,
            "keyboard-interactive" => SSHAuthMethod::KeyboardInteractive,
            "agent" => SSHAuthMethod::Agent,
            other => panic!("unsupported test auth type: {other}"),
        };
        let read = |suffix: &str| {
            optional_env(&name(suffix))
                .map(|path| std::fs::read_to_string(path).expect("read SSH compatibility fixture"))
        };
        SSHAuthentication {
            method,
            password: optional_env(&name("PASSWORD")),
            private_key: read("KEY_PATH"),
            private_key_passphrase: optional_env(&name("KEY_PASSPHRASE")),
            certificate: read("CERTIFICATE_PATH"),
            keyboard_interactive_responses: optional_env(&name("KBDINT_RESPONSES_JSON"))
                .map(|json| serde_json::from_str(&json).expect("keyboard responses JSON"))
                .unwrap_or_default(),
            agent_identity_fingerprint: optional_env(&name("AGENT_IDENTITY_FINGERPRINT")),
        }
    }

    fn direct_password_options(expected_fingerprint: String) -> SSHConnectOptions {
        SSHConnectOptions {
            host: std::env::var("LOVELYRES_TEST_SSH_HOST").expect("test SSH host"),
            port: std::env::var("LOVELYRES_TEST_SSH_PORT")
                .expect("test SSH port")
                .parse::<u16>()
                .expect("numeric test SSH port"),
            username: std::env::var("LOVELYRES_TEST_SSH_USER").expect("test SSH user"),
            authentication: SSHAuthentication {
                method: SSHAuthMethod::Password,
                password: Some(
                    std::env::var("LOVELYRES_TEST_SSH_PASSWORD").expect("test SSH password"),
                ),
                private_key: None,
                private_key_passphrase: None,
                certificate: None,
                keyboard_interactive_responses: Vec::new(),
                agent_identity_fingerprint: None,
            },
            expected_host_key_fingerprint: Some(expected_fingerprint),
            jump_host: None,
        }
    }

    #[test]
    #[ignore = "requires LOVELYRES_TEST_SSH_* and a real Linux SSH target"]
    fn real_linux_ssh_contract() {
        let host = std::env::var("LOVELYRES_TEST_SSH_HOST").expect("test SSH host");
        let port = std::env::var("LOVELYRES_TEST_SSH_PORT")
            .expect("test SSH port")
            .parse::<u16>()
            .expect("numeric test SSH port");
        let username = std::env::var("LOVELYRES_TEST_SSH_USER").expect("test SSH user");
        let fingerprint =
            std::env::var("LOVELYRES_TEST_SSH_FINGERPRINT").expect("test SSH fingerprint");

        let jump_host =
            optional_env("LOVELYRES_TEST_SSH_JUMP_HOST").map(|jump_host| SSHJumpHostOptions {
                host: jump_host,
                port: std::env::var("LOVELYRES_TEST_SSH_JUMP_PORT")
                    .unwrap_or_else(|_| "22".to_string())
                    .parse()
                    .expect("jump port"),
                username: std::env::var("LOVELYRES_TEST_SSH_JUMP_USER").expect("jump user"),
                authentication: authentication("LOVELYRES_TEST_SSH_JUMP"),
                expected_host_key_fingerprint: optional_env("LOVELYRES_TEST_SSH_JUMP_FINGERPRINT"),
            });

        let manager = SSHManagerRussh::new();
        let session = manager
            .connect_with_options(SSHConnectOptions {
                host: host.clone(),
                port,
                username: username.clone(),
                authentication: authentication("LOVELYRES_TEST_SSH"),
                expected_host_key_fingerprint: Some(fingerprint),
                jump_host,
            })
            .expect("connect to real Linux target with confirmed fingerprint");

        let capabilities = manager
            .probe_target_capabilities_on_session(&session)
            .expect("probe target capabilities");
        assert!(capabilities.exec);
        assert_eq!(
            capabilities.sftp,
            bool_env("LOVELYRES_TEST_EXPECT_SFTP", true)
        );
        assert_eq!(
            capabilities.pty,
            bool_env("LOVELYRES_TEST_EXPECT_PTY", true)
        );

        let success = manager
            .execute_command_on_session_with_timeout(
                &session,
                "printf lovelyres-linux-contract",
                Duration::from_secs(5),
            )
            .expect("execute successful command");
        assert!(success.is_success());
        assert_eq!(success.output, "lovelyres-linux-contract");

        let failure = manager
            .execute_command_on_session_with_timeout(
                &session,
                "sh -c 'exit 7'",
                Duration::from_secs(5),
            )
            .expect("receive non-zero command receipt");
        assert_eq!(failure.exit_code, Some(7));
        assert!(!failure.is_success());

        if capabilities.sftp {
            let remote_path = format!("/tmp/lovelyres-contract-{}", uuid::Uuid::new_v4());
            manager
                .write_sftp_file_on_session(&session, &remote_path, b"evidence")
                .expect("write SFTP evidence fixture");
            assert_eq!(
                manager
                    .read_sftp_file_on_session(&session, &remote_path)
                    .expect("read SFTP evidence fixture"),
                b"evidence",
            );
            let cleanup = manager
                .execute_command_on_session_with_timeout(
                    &session,
                    &format!("rm -f -- {}", shell_quote(&remote_path)),
                    Duration::from_secs(5),
                )
                .expect("clean up remote fixture");
            assert!(cleanup.is_success());
        }

        if bool_env("LOVELYRES_TEST_EXPECT_PCAP", true) && capabilities.sftp {
            let pcap_path = crate::packet_capture::new_remote_pcap_path();
            let pcap_command = crate::packet_capture::generate_pcap_evidence_command(
                "any",
                None,
                Some(100),
                2,
                &pcap_path,
            )
            .expect("build bounded PCAP command");
            let pcap_output = manager
                .execute_command_on_session_with_timeout(
                    &session,
                    &pcap_command,
                    Duration::from_secs(10),
                )
                .expect("capture real PCAP artifact");
            assert!(pcap_output.is_success(), "{}", pcap_output.output);
            let pcap_metadata =
                crate::packet_capture::parse_pcap_evidence_output(&pcap_output.output)
                    .expect("parse remote PCAP receipt");
            let pcap_bytes = manager
                .read_sftp_file_on_session(&session, &pcap_path)
                .expect("read raw PCAP over SFTP");
            assert_eq!(pcap_bytes.len() as u64, pcap_metadata.size_bytes);
            assert!(pcap_bytes.len() >= 24, "PCAP global header must be present");
            assert_eq!(
                format!("{:x}", Sha256::digest(&pcap_bytes)),
                pcap_metadata.sha256
            );
            let quoted_pcap_path = shell_quote(&pcap_path);
            let pcap_cleanup = manager
                .execute_command_on_session_with_timeout(
                    &session,
                    &format!("rm -f -- {quoted_pcap_path} && test ! -e {quoted_pcap_path}"),
                    Duration::from_secs(5),
                )
                .expect("clean remote PCAP fixture");
            assert!(pcap_cleanup.is_success());
        }

        manager
            .disconnect_session(&session)
            .expect("disconnect test session");
    }

    #[test]
    #[ignore = "requires LOVELYRES_TEST_SSH_* and an externally stopped SSH target"]
    fn real_ssh_disconnect_contract() {
        let fingerprint =
            std::env::var("LOVELYRES_TEST_SSH_FINGERPRINT").expect("test SSH fingerprint");
        let manager = SSHManagerRussh::new();
        let session = manager
            .connect_with_options(direct_password_options(fingerprint))
            .expect("connect before forced disconnect");
        let ready =
            std::env::var("LOVELYRES_TEST_DISCONNECT_READY_FILE").expect("disconnect ready file");
        std::fs::write(&ready, b"ready").expect("signal disconnect readiness");

        let started = std::time::Instant::now();
        let result = manager.execute_command_on_session_with_timeout(
            &session,
            "sleep 30",
            Duration::from_secs(20),
        );
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "disconnect was not detected promptly"
        );
        assert!(result.is_err() || !result.expect("non-success receipt").is_success());
    }

    #[test]
    #[ignore = "requires LOVELYRES_TEST_SSH_* and a stale fingerprint"]
    fn real_ssh_host_key_change_contract() {
        let stale =
            std::env::var("LOVELYRES_TEST_SSH_STALE_FINGERPRINT").expect("stale host fingerprint");
        let manager = SSHManagerRussh::new();
        let error = manager
            .connect_with_options(direct_password_options(stale))
            .expect_err("changed host key must be rejected");
        assert!(
            error.contains("密钥") || error.contains("fingerprint"),
            "{error}"
        );
        assert!(manager.list_sessions().is_empty());
    }

    #[test]
    #[ignore = "requires LOVELYRES_TEST_SSH_* and a forced-command account"]
    fn real_ssh_restricted_account_contract() {
        let fingerprint =
            std::env::var("LOVELYRES_TEST_SSH_FINGERPRINT").expect("test SSH fingerprint");
        let manager = SSHManagerRussh::new();
        let session = manager
            .connect_with_options(direct_password_options(fingerprint))
            .expect("restricted account can authenticate");
        let output = manager
            .execute_command_on_session_with_timeout(
                &session,
                "printf should-not-run",
                Duration::from_secs(5),
            )
            .expect("restricted command receipt");
        assert!(!output.is_success());
        let capabilities = manager
            .probe_target_capabilities_on_session(&session)
            .expect("restricted target still returns a degradation contract");
        assert!(!capabilities.exec);
        assert!(capabilities.probe_error.is_some());
    }
}
