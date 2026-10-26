//! Windows RDP Dynamic Virtual Channel (DVC) COM LocalServer plugin, registry
//! helper, wire protocol, and remote session agent routines.

use std::collections::VecDeque;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::Utc;
use parking_lot::{Condvar, Mutex};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod native_collect;
pub mod windows_read_queries;
pub mod agent_runtime;
pub mod rdp_viewport;

/// COM CLSID shared with the RDP client AddIn registration.
pub const PLUGIN_CLSID_STR: &str = "{D9B80669-C06A-4BD1-9CB1-3B7168C9E3A3}";
/// AddIn registry subkey name read by `mstsc.exe`.
pub const ADDIN_NAME: &str = "SimpleRdpPlugin";
/// Primary DVC channel name for LovelyHawk Windows Incident Response.
pub const PRIMARY_CHANNEL_NAME: &str = "dvc::lovelyhawk::winir";
/// Compatible DVC channel name used by the interactive demo.
pub const COMPAT_CHANNEL_NAME: &str = "dvc::demo::chat";

/// Maximum frame payload size (16 MiB).
pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;
/// Raw bytes per file chunk before base64 encoding (48 KiB).
pub const FILE_CHUNK_SIZE: usize = 48 * 1024;
/// Maximum number of chat/command messages retained in memory.
const MAX_MESSAGE_LOG: usize = 200;
/// Maximum number of received files retained in memory.
const MAX_RECEIVED_FILES: usize = 32;

/// One wire message exchanged over the DVC stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DvcWireMessage {
    pub from: String,
    pub seq: u64,
    #[serde(rename = "type", default = "default_msg_type")]
    pub msg_type: String,
    #[serde(default)]
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

fn default_msg_type() -> String {
    "chat".to_owned()
}

impl DvcWireMessage {
    pub fn chat(from: &str, seq: u64, text: impl Into<String>) -> Self {
        Self {
            from: from.to_owned(),
            seq,
            msg_type: "chat".to_owned(),
            text: text.into(),
            name: None,
            size: None,
            b64: None,
            sha256: None,
        }
    }

    pub fn cmd(from: &str, seq: u64, command: impl Into<String>) -> Self {
        Self {
            from: from.to_owned(),
            seq,
            msg_type: "cmd".to_owned(),
            text: command.into(),
            name: None,
            size: None,
            b64: None,
            sha256: None,
        }
    }

    pub fn result(from: &str, seq: u64, output: impl Into<String>) -> Self {
        Self {
            from: from.to_owned(),
            seq,
            msg_type: "result".to_owned(),
            text: output.into(),
            name: None,
            size: None,
            b64: None,
            sha256: None,
        }
    }
}

/// Encode a `DvcWireMessage` with a 4-byte little-endian length prefix.
pub fn encode_frame(msg: &DvcWireMessage) -> Result<Vec<u8>, String> {
    let body = serde_json::to_vec(msg).map_err(|e| format!("serialize frame failed: {e}"))?;
    if body.len() > MAX_FRAME_SIZE {
        return Err(format!("frame exceeds maximum size ({} bytes)", body.len()));
    }
    let len = body.len() as u32;
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Streaming decoder for `[u32 len][json]` frames over a DVC byte stream.
#[derive(Debug, Default)]
pub struct StreamDecoder {
    buf: Vec<u8>,
}

impl StreamDecoder {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn feed(&mut self, data: &[u8]) -> Result<Vec<DvcWireMessage>, String> {
        self.buf.extend_from_slice(data);
        let mut out = Vec::new();
        while self.buf.len() >= 4 {
            let len =
                u32::from_le_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
            if len > MAX_FRAME_SIZE {
                self.buf.clear();
                return Err(format!("implausible frame length: {len}"));
            }
            if self.buf.len() < 4 + len {
                break;
            }
            let body = &self.buf[4..4 + len];
            let parsed: DvcWireMessage =
                serde_json::from_slice(body).map_err(|e| format!("invalid frame JSON: {e}"))?;
            self.buf.drain(..4 + len);
            out.push(parsed);
        }
        Ok(out)
    }
}

/// Reassembles 8-byte `CHANNEL_PDU_HEADER` fragments read from `WTSVirtualChannelRead`.
#[derive(Debug, Default)]
pub struct PduReassembler {
    buf: Vec<u8>,
    started: bool,
}

const PDU_HEADER_SIZE: usize = 8;
const PDU_FLAG_FIRST: u32 = 0x01;
const PDU_FLAG_LAST: u32 = 0x02;

impl PduReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_read(&mut self, raw_pdu: &[u8]) -> Option<Vec<u8>> {
        if raw_pdu.len() < PDU_HEADER_SIZE {
            return None;
        }
        let flags = u32::from_le_bytes([raw_pdu[4], raw_pdu[5], raw_pdu[6], raw_pdu[7]]);
        let payload = &raw_pdu[PDU_HEADER_SIZE..];
        if (flags & PDU_FLAG_FIRST) != 0 {
            self.buf.clear();
            self.started = true;
        } else if !self.started {
            return None;
        }
        if self.buf.len() + payload.len() > MAX_FRAME_SIZE + 65536 {
            self.buf.clear();
            self.started = false;
            return None;
        }
        self.buf.extend_from_slice(payload);
        if (flags & PDU_FLAG_LAST) != 0 {
            self.started = false;
            Some(std::mem::take(&mut self.buf))
        } else {
            None
        }
    }
}

/// Registry status for the RDP client AddIn and COM LocalServer32.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DvcRegistrationStatus {
    pub registered: bool,
    pub clsid: String,
    pub addin_name: String,
    pub local_server_command: Option<String>,
}

/// One logged message on the DVC channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DvcLogEntry {
    pub timestamp: String,
    pub direction: String,
    pub kind: String,
    pub summary: String,
}

/// One file received over DVC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DvcReceivedFile {
    pub file_id: String,
    pub name: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub verified: bool,
    pub received_at: String,
    #[serde(skip)]
    pub content: Vec<u8>,
}

/// Current runtime state of the COM LocalServer DVC listener.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DvcRuntimeStatus {
    pub registration: DvcRegistrationStatus,
    pub listener_running: bool,
    pub rdp_plugin_initialized: bool,
    pub channel_connected: bool,
    pub active_channel_name: Option<String>,
    pub connected_since: Option<String>,
    pub session_id: Option<String>,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub recent_logs: Vec<DvcLogEntry>,
    pub received_files: Vec<DvcReceivedFile>,
}

#[derive(Debug)]
struct InProgressFile {
    name: String,
    expected_size: u64,
    buf: Vec<u8>,
    hasher: Sha256,
}

type ChannelWriteFn = Arc<dyn Fn(&[u8]) -> Result<(), String> + Send + Sync>;

struct SharedDvcState {
    listener_running: bool,
    rdp_plugin_initialized: bool,
    channel_connected: bool,
    active_channel_name: Option<String>,
    connected_since: Option<String>,
    session_id: Option<String>,
    messages_sent: u64,
    messages_received: u64,
    next_seq: u64,
    recent_logs: VecDeque<DvcLogEntry>,
    received_files: VecDeque<DvcReceivedFile>,
    in_progress_file: Option<InProgressFile>,
    pending_results: VecDeque<String>,
    writer: Option<ChannelWriteFn>,
}

impl std::fmt::Debug for SharedDvcState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedDvcState")
            .field("listener_running", &self.listener_running)
            .field("channel_connected", &self.channel_connected)
            .finish()
    }
}

impl Default for SharedDvcState {
    fn default() -> Self {
        Self {
            listener_running: false,
            rdp_plugin_initialized: false,
            channel_connected: false,
            active_channel_name: None,
            connected_since: None,
            session_id: None,
            messages_sent: 0,
            messages_received: 0,
            next_seq: 1,
            recent_logs: VecDeque::new(),
            received_files: VecDeque::new(),
            in_progress_file: None,
            pending_results: VecDeque::new(),
            writer: None,
        }
    }
}

impl SharedDvcState {
    fn push_log(&mut self, direction: &str, kind: &str, summary: impl Into<String>) {
        if self.recent_logs.len() >= MAX_MESSAGE_LOG {
            self.recent_logs.pop_front();
        }
        self.recent_logs.push_back(DvcLogEntry {
            timestamp: Utc::now().format("%H:%M:%S").to_string(),
            direction: direction.to_owned(),
            kind: kind.to_owned(),
            summary: summary.into(),
        });
    }
}

/// Returns true when a command-line argument is the COM LocalServer activation
/// switch (`-Embedding` or `/Embedding`) passed by `svchost.exe`/`rpcss` when
/// `mstsc.exe` probes a registered out-of-process DVC plugin.
pub fn is_com_embedding_arg(arg: &std::ffi::OsStr) -> bool {
    arg.to_str().is_some_and(|s| {
        s.eq_ignore_ascii_case("-embedding") || s.eq_ignore_ascii_case("/embedding")
    })
}

/// Returns true if any argument in the iterator is `-Embedding` or `/Embedding`.
pub fn has_com_embedding_arg<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    args.into_iter().any(|arg| is_com_embedding_arg(arg.as_ref()))
}

/// Thread-safe handle to the in-process DVC COM LocalServer hub.
#[derive(Debug, Clone)]
pub struct DvcHub {
    state: Arc<Mutex<SharedDvcState>>,
    result_cv: Arc<Condvar>,
    cmd_lock: Arc<Mutex<()>>,
    started: Arc<AtomicBool>,
    owned_registration: Arc<AtomicBool>,
}

impl Default for DvcHub {
    fn default() -> Self {
        Self::new()
    }
}

impl DvcHub {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(SharedDvcState::default())),
            result_cv: Arc::new(Condvar::new()),
            cmd_lock: Arc::new(Mutex::new(())),
            started: Arc::new(AtomicBool::new(false)),
            owned_registration: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn register_plugin(
        &self,
        custom_command: Option<&str>,
    ) -> Result<DvcRuntimeStatus, String> {
        register_addin_per_user(custom_command)?;
        self.owned_registration.store(true, Ordering::SeqCst);
        let _ = self.ensure_listener_started();
        Ok(self.status())
    }

    pub fn unregister_plugin(&self) -> Result<DvcRuntimeStatus, String> {
        self.owned_registration.store(false, Ordering::SeqCst);
        unregister_addin_per_user()?;
        Ok(self.status())
    }

    /// Removes the per-user DVC AddIn registration if this hub registered it,
    /// so closing LovelyHawk does not leave `mstsc.exe` launching the app via
    /// COM `LocalServer32`.
    pub fn shutdown(&self) {
        if self.owned_registration.swap(false, Ordering::SeqCst) {
            let _ = unregister_addin_per_user();
        }
    }

    pub fn status(&self) -> DvcRuntimeStatus {
        let registration = query_registration();
        let guard = self.state.lock();
        DvcRuntimeStatus {
            registration,
            listener_running: guard.listener_running,
            rdp_plugin_initialized: guard.rdp_plugin_initialized,
            channel_connected: guard.channel_connected,
            active_channel_name: guard.active_channel_name.clone(),
            connected_since: guard.connected_since.clone(),
            session_id: guard.session_id.clone(),
            messages_sent: guard.messages_sent,
            messages_received: guard.messages_received,
            recent_logs: guard.recent_logs.iter().cloned().collect(),
            received_files: guard
                .received_files
                .iter()
                .map(|f| DvcReceivedFile {
                    file_id: f.file_id.clone(),
                    name: f.name.clone(),
                    size_bytes: f.size_bytes,
                    sha256: f.sha256.clone(),
                    verified: f.verified,
                    received_at: f.received_at.clone(),
                    content: Vec::new(),
                })
                .collect(),
        }
    }

    pub fn received_file_bytes(&self, file_id: &str) -> Option<(String, Vec<u8>)> {
        let guard = self.state.lock();
        guard
            .received_files
            .iter()
            .find(|f| f.file_id == file_id && f.verified)
            .map(|f| (f.name.clone(), f.content.clone()))
    }

    /// Returns one bounded slice of an already verified, immutable receipt.
    pub fn received_file_part(
        &self,
        file_id: &str,
        offset: usize,
        limit: usize,
    ) -> Option<DvcReceivedFile> {
        let guard = self.state.lock();
        let file = guard
            .received_files
            .iter()
            .find(|file| file.file_id == file_id && file.verified)?;
        let bytes = file
            .content
            .get(offset..offset.saturating_add(limit).min(file.content.len()))?;
        Some(DvcReceivedFile {
            file_id: file.file_id.clone(),
            name: file.name.clone(),
            size_bytes: file.size_bytes,
            sha256: file.sha256.clone(),
            verified: true,
            received_at: file.received_at.clone(),
            content: bytes.to_vec(),
        })
    }

    pub fn ensure_listener_started(&self) -> Result<DvcRuntimeStatus, String> {
        if !self.started.swap(true, Ordering::SeqCst) {
            let hub = self.clone();
            if let Err(err) = spawn_com_local_server(hub) {
                self.started.store(false, Ordering::SeqCst);
                return Err(err);
            }
        }
        Ok(self.status())
    }

    fn send_wire(&self, msg: DvcWireMessage) -> Result<(), String> {
        self.send_wire_for_session(msg, None)
    }

    fn send_wire_for_session(
        &self,
        mut msg: DvcWireMessage,
        expected: Option<&str>,
    ) -> Result<(), String> {
        let writer = {
            let mut guard = self.state.lock();
            if expected.is_some()
                && (guard.session_id.as_deref() != expected || !guard.channel_connected)
            {
                return Err("远程会话已变化，本次操作未发送。".to_owned());
            }
            let Some(writer) = guard.writer.clone() else {
                return Err(
                    "DVC 通道尚未连接，请确认已建立 RDP 连接并在远程会话中启动采集端。".to_owned(),
                );
            };
            msg.seq = guard.next_seq;
            guard.next_seq += 1;
            writer
        };
        let frame = encode_frame(&msg)?;
        if let Err(err) = writer(&frame) {
            let mut guard = self.state.lock();
            guard.push_log("system", "error", format!("发送失败: {err}"));
            return Err(err);
        }
        let mut guard = self.state.lock();
        guard.messages_sent += 1;
        if msg.msg_type == "chat" || msg.msg_type == "cmd" {
            let preview: String = msg.text.chars().take(120).collect();
            guard.push_log("out", &msg.msg_type, preview);
        }
        Ok(())
    }

    pub fn send_chat(&self, text: &str) -> Result<DvcRuntimeStatus, String> {
        let msg = DvcWireMessage::chat("client", 0, text);
        self.send_wire(msg)?;
        Ok(self.status())
    }

    pub fn send_chat_for_session(
        &self,
        text: &str,
        session_id: &str,
    ) -> Result<DvcRuntimeStatus, String> {
        self.send_wire_for_session(DvcWireMessage::chat("client", 0, text), Some(session_id))?;
        Ok(self.status())
    }

    /// Send a shell/PowerShell command over DVC and wait for the corresponding `result` frame.
    pub fn execute_command(&self, command: &str, timeout: Duration) -> Result<String, String> {
        let session_id = self
            .state
            .lock()
            .session_id
            .clone()
            .ok_or_else(|| "DVC 通道尚未连接。".to_owned())?;
        self.execute_command_for_session(command, timeout, &session_id)
    }

    pub fn execute_command_for_session(
        &self,
        command: &str,
        timeout: Duration,
        session_id: &str,
    ) -> Result<String, String> {
        let _serial = self.cmd_lock.lock();
        {
            let mut guard = self.state.lock();
            if guard.session_id.as_deref() != Some(session_id) || !guard.channel_connected {
                return Err("远程会话已变化，本次命令未发送。".to_owned());
            }
            guard.pending_results.clear();
        }
        let msg = DvcWireMessage::cmd("client", 0, command);
        self.send_wire_for_session(msg, Some(session_id))?;

        let deadline = Instant::now() + timeout;
        let mut guard = self.state.lock();
        loop {
            if !guard.channel_connected || guard.session_id.as_deref() != Some(session_id) {
                return Err("DVC 通道已断开或会话已变化。".to_owned());
            }
            if let Some(output) = guard.pending_results.pop_front() {
                return Ok(output);
            }
            let now = Instant::now();
            if now >= deadline {
                // Legacy agents do not echo a request ID. A timed-out reply must
                // never be consumed by the next command on this channel.
                guard.channel_connected = false;
                guard.session_id = None;
                guard.writer = None;
                guard.pending_results.clear();
                guard.push_log(
                    "system",
                    "error",
                    "命令等待超时，通道已暂停；请重新启动远程采集端。",
                );
                return Err("等待远程响应超时；请重新启动远程采集端后重试。".to_owned());
            }
            let wait_for = deadline.duration_since(now);
            let _ = self.result_cv.wait_for(&mut guard, wait_for);
        }
    }

    /// Push a file from the local machine to the remote RDP session over DVC.
    pub fn send_file_bytes(
        &self,
        file_name: &str,
        data: &[u8],
    ) -> Result<DvcRuntimeStatus, String> {
        let start_msg = DvcWireMessage {
            from: "client".to_owned(),
            seq: 0,
            msg_type: "file_start".to_owned(),
            text: String::new(),
            name: Some(file_name.to_owned()),
            size: Some(data.len() as u64),
            b64: None,
            sha256: None,
        };
        self.send_wire(start_msg)?;
        let mut hasher = Sha256::new();
        for chunk in data.chunks(FILE_CHUNK_SIZE) {
            hasher.update(chunk);
            let chunk_msg = DvcWireMessage {
                from: "client".to_owned(),
                seq: 0,
                msg_type: "file_chunk".to_owned(),
                text: String::new(),
                name: None,
                size: None,
                b64: Some(BASE64.encode(chunk)),
                sha256: None,
            };
            self.send_wire(chunk_msg)?;
        }
        let digest = format!("{:x}", hasher.finalize());
        let end_msg = DvcWireMessage {
            from: "client".to_owned(),
            seq: 0,
            msg_type: "file_end".to_owned(),
            text: String::new(),
            name: Some(file_name.to_owned()),
            size: Some(data.len() as u64),
            b64: None,
            sha256: Some(digest),
        };
        self.send_wire(end_msg)?;
        {
            let mut guard = self.state.lock();
            guard.push_log(
                "out",
                "file",
                format!("已发送文件 {file_name}（{} 字节）", data.len()),
            );
        }
        Ok(self.status())
    }

    pub fn on_incoming_message(&self, msg: DvcWireMessage) {
        self.accept_incoming(msg, None);
    }

    pub fn on_incoming_for_session(&self, msg: DvcWireMessage, session_id: &str) -> bool {
        self.accept_incoming(msg, Some(session_id))
    }

    fn accept_incoming(&self, msg: DvcWireMessage, expected: Option<&str>) -> bool {
        let mut guard = self.state.lock();
        if expected.is_some()
            && (guard.session_id.as_deref() != expected || !guard.channel_connected)
        {
            return false;
        }
        guard.messages_received += 1;
        match msg.msg_type.as_str() {
            "result" => {
                let preview: String = msg.text.chars().take(120).collect();
                guard.push_log("in", "result", preview);
                guard.pending_results.push_back(msg.text);
                self.result_cv.notify_all();
            }
            "file_start" => {
                let name = msg.name.unwrap_or_else(|| "unnamed.bin".to_owned());
                let size = msg.size.unwrap_or(0);
                guard.push_log("in", "file", format!("开始接收文件 {name}（{size} 字节）"));
                guard.in_progress_file = Some(InProgressFile {
                    name,
                    expected_size: size,
                    buf: Vec::with_capacity((size as usize).min(MAX_FRAME_SIZE)),
                    hasher: Sha256::new(),
                });
            }
            "file_chunk" => {
                if let (Some(b64), Some(active)) =
                    (msg.b64.as_deref(), guard.in_progress_file.as_mut())
                    && let Ok(bytes) = BASE64.decode(b64)
                    && active.buf.len() + bytes.len() <= MAX_FRAME_SIZE
                {
                    active.hasher.update(&bytes);
                    active.buf.extend_from_slice(&bytes);
                }
            }
            "file_end" => {
                if let Some(active) = guard.in_progress_file.take() {
                    let digest = format!("{:x}", active.hasher.finalize());
                    let expected_sha = msg.sha256.unwrap_or_default();
                    let size_bytes = active.buf.len() as u64;
                    let verified = size_bytes == active.expected_size
                        && expected_sha.len() == 64
                        && expected_sha.eq_ignore_ascii_case(&digest);
                    let summary = format!(
                        "接收完成 {}（{} 字节，SHA256 校验{}）",
                        active.name,
                        size_bytes,
                        if verified { "通过" } else { "不一致" }
                    );
                    guard.push_log("in", "file", summary);
                    if guard.received_files.len() >= MAX_RECEIVED_FILES {
                        guard.received_files.pop_front();
                    }
                    guard.received_files.push_back(DvcReceivedFile {
                        file_id: uuid::Uuid::new_v4().to_string(),
                        name: active.name,
                        size_bytes,
                        sha256: digest,
                        verified,
                        received_at: Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                        content: active.buf,
                    });
                }
            }
            _ => {
                guard.push_log("in", &msg.msg_type, msg.text);
            }
        }
        true
    }
}

#[cfg(windows)]
mod win_impl {
    use super::*;
    use std::ffi::c_void;
    use windows::Win32::Foundation::{
        CLASS_E_NOAGGREGATION, RPC_E_CHANGED_MODE, RPC_E_TOO_LATE, TRUE,
    };
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, CLSCTX_LOCAL_SERVER, COINIT_MULTITHREADED, CoCreateInstance,
        CoInitializeEx, CoInitializeSecurity, CoRegisterClassObject, CoResumeClassObjects,
        CoRevokeClassObject, CoUninitialize, IClassFactory, IClassFactory_Impl,
        IGlobalInterfaceTable, REGCLS_MULTIPLEUSE, REGCLS_SUSPENDED, RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
    };
    use windows::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_SZ, RegCloseKey, RegCreateKeyW,
        RegDeleteTreeW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
    };
    use windows::Win32::System::RemoteDesktop::{
        IWTSListener, IWTSListenerCallback, IWTSListenerCallback_Impl, IWTSPlugin, IWTSPlugin_Impl,
        IWTSVirtualChannel, IWTSVirtualChannelCallback, IWTSVirtualChannelCallback_Impl,
        IWTSVirtualChannelManager,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        DispatchMessageW, MSG, PM_REMOVE, PeekMessageW, TranslateMessage, WM_QUIT,
    };
    use windows_core::{
        BOOL, BSTR, Error, GUID, IUnknown, Interface, OutRef, PCSTR, PCWSTR, Ref,
        Result as WinResult, implement,
    };

    const CLSID_RDP_PLUGIN: GUID = GUID::from_u128(0xD9B80669_C06A_4BD1_9CB1_3B7168C9E3A3);
    const CLSID_STD_GLOBAL_INTERFACE_TABLE: GUID =
        GUID::from_u128(0x00000323_0000_0000_c000_000000000046);
    const PRIMARY_CHANNEL_CSTR: &[u8] = b"dvc::lovelyhawk::winir\0";
    const COMPAT_CHANNEL_CSTR: &[u8] = b"dvc::demo::chat\0";

    fn wide_null(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn reg_create_key(root: HKEY, sub_key: &str) -> bool {
        let w = wide_null(sub_key);
        let mut h = HKEY::default();
        // SAFETY: `w` is null-terminated UTF-16 and `h` is a valid out pointer.
        unsafe {
            if RegCreateKeyW(root, PCWSTR(w.as_ptr()), &mut h).is_ok() {
                let _ = RegCloseKey(h);
                true
            } else {
                false
            }
        }
    }

    fn reg_set_sz(root: HKEY, sub_key: &str, name: &str, value: &str) -> bool {
        let sub_w = wide_null(sub_key);
        let name_w = wide_null(name);
        let val_w = wide_null(value);
        let mut h = HKEY::default();
        // SAFETY: all wide buffers remain valid for the duration of the Win32 calls.
        unsafe {
            if RegOpenKeyExW(root, PCWSTR(sub_w.as_ptr()), Some(0), KEY_WRITE, &mut h).is_err() {
                return false;
            }
            let bytes = std::slice::from_raw_parts(val_w.as_ptr() as *const u8, val_w.len() * 2);
            let ok =
                RegSetValueExW(h, PCWSTR(name_w.as_ptr()), Some(0), REG_SZ, Some(bytes)).is_ok();
            let _ = RegCloseKey(h);
            ok
        }
    }

    fn reg_read_sz(root: HKEY, sub_key: &str, name: &str) -> Option<String> {
        let sub_w = wide_null(sub_key);
        let name_w = wide_null(name);
        let mut h = HKEY::default();
        // SAFETY: standard two-call pattern for `RegQueryValueExW`.
        unsafe {
            if RegOpenKeyExW(root, PCWSTR(sub_w.as_ptr()), Some(0), KEY_READ, &mut h).is_err() {
                return None;
            }
            let mut size: u32 = 0;
            if RegQueryValueExW(
                h,
                PCWSTR(name_w.as_ptr()),
                None,
                None,
                None,
                Some(&mut size),
            )
            .is_err()
                || size < 2
            {
                let _ = RegCloseKey(h);
                return None;
            }
            let mut buf = vec![0u8; size as usize];
            let ok = RegQueryValueExW(
                h,
                PCWSTR(name_w.as_ptr()),
                None,
                None,
                Some(buf.as_mut_ptr()),
                Some(&mut size),
            )
            .is_ok();
            let _ = RegCloseKey(h);
            if !ok {
                return None;
            }
            let u16_len = (size as usize) / 2;
            let words: Vec<u16> = (0..u16_len)
                .map(|i| u16::from_le_bytes([buf[i * 2], buf[i * 2 + 1]]))
                .take_while(|&c| c != 0)
                .collect();
            Some(String::from_utf16_lossy(&words))
        }
    }

    fn reg_delete_tree(root: HKEY, sub_key: &str) {
        let w = wide_null(sub_key);
        // SAFETY: `w` is a null-terminated UTF-16 string.
        unsafe {
            let _ = RegDeleteTreeW(root, PCWSTR(w.as_ptr()));
        }
    }

    pub fn query_registration() -> DvcRegistrationStatus {
        let clsid_key = format!("Software\\Classes\\CLSID\\{PLUGIN_CLSID_STR}\\LocalServer32");
        let addin_key =
            format!("Software\\Microsoft\\Terminal Server Client\\Default\\AddIns\\{ADDIN_NAME}");
        let local_server_command = reg_read_sz(HKEY_CURRENT_USER, &clsid_key, "");
        let addin_val = reg_read_sz(HKEY_CURRENT_USER, &addin_key, "Name");
        let registered = local_server_command.is_some()
            && addin_val
                .as_deref()
                .is_some_and(|v| v.eq_ignore_ascii_case(PLUGIN_CLSID_STR));
        DvcRegistrationStatus {
            registered,
            clsid: PLUGIN_CLSID_STR.to_owned(),
            addin_name: ADDIN_NAME.to_owned(),
            local_server_command,
        }
    }

    pub fn register_addin_per_user(
        custom_command: Option<&str>,
    ) -> Result<DvcRegistrationStatus, String> {
        let cmd = match custom_command {
            Some(c) if !c.trim().is_empty() => c.trim().to_owned(),
            _ => {
                let exe =
                    std::env::current_exe().map_err(|e| format!("无法解析当前程序路径: {e}"))?;
                format!("\"{}\" -Embedding", exe.to_string_lossy())
            }
        };
        let clsid_key = format!("Software\\Classes\\CLSID\\{PLUGIN_CLSID_STR}");
        let local_server_key = format!("{clsid_key}\\LocalServer32");
        let addin_key =
            format!("Software\\Microsoft\\Terminal Server Client\\Default\\AddIns\\{ADDIN_NAME}");

        if !reg_create_key(HKEY_CURRENT_USER, &clsid_key)
            || !reg_set_sz(
                HKEY_CURRENT_USER,
                &clsid_key,
                "",
                "LovelyHawk Windows Incident Response DVC Plugin",
            )
            || !reg_create_key(HKEY_CURRENT_USER, &local_server_key)
            || !reg_set_sz(HKEY_CURRENT_USER, &local_server_key, "", &cmd)
            || !reg_create_key(HKEY_CURRENT_USER, &addin_key)
            || !reg_set_sz(HKEY_CURRENT_USER, &addin_key, "Name", PLUGIN_CLSID_STR)
        {
            return Err("写入 HKCU 注册表项失败。".to_owned());
        }
        Ok(query_registration())
    }

    pub fn unregister_addin_per_user() -> Result<DvcRegistrationStatus, String> {
        let clsid_key = format!("Software\\Classes\\CLSID\\{PLUGIN_CLSID_STR}");
        let addin_key =
            format!("Software\\Microsoft\\Terminal Server Client\\Default\\AddIns\\{ADDIN_NAME}");
        reg_delete_tree(HKEY_CURRENT_USER, &addin_key);
        reg_delete_tree(HKEY_CURRENT_USER, &clsid_key);
        Ok(query_registration())
    }

    #[derive(Clone, Copy)]
    struct GitChannel {
        git_cookie: u32,
    }

    impl GitChannel {
        fn register(ch: &IWTSVirtualChannel) -> WinResult<Self> {
            // SAFETY: Registering the channel interface in the process-wide COM
            // Global Interface Table (GIT) on the apartment thread that received
            // `OnNewChannelConnection`, so any worker thread (STA or MTA) can
            // unmarshal a thread-valid proxy before calling `Write`.
            unsafe {
                let git: IGlobalInterfaceTable = CoCreateInstance(
                    &CLSID_STD_GLOBAL_INTERFACE_TABLE,
                    None::<&IUnknown>,
                    CLSCTX_INPROC_SERVER,
                )?;
                let git_cookie = git.RegisterInterfaceInGlobal(ch, &IWTSVirtualChannel::IID)?;
                Ok(Self { git_cookie })
            }
        }

        fn write(self, bytes: &[u8]) -> Result<(), String> {
            // SAFETY: Initializes COM on the calling thread if needed, fetches a
            // proxy marshaled specifically for the calling thread's apartment from
            // the Global Interface Table, and invokes `IWTSVirtualChannel::Write`.
            unsafe {
                let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
                let git: IGlobalInterfaceTable = CoCreateInstance(
                    &CLSID_STD_GLOBAL_INTERFACE_TABLE,
                    None::<&IUnknown>,
                    CLSCTX_INPROC_SERVER,
                )
                .map_err(|e| format!("获取 IGlobalInterfaceTable 失败: {e}"))?;
                let mut raw_ptr: *mut c_void = std::ptr::null_mut();
                git.GetInterfaceFromGlobal(self.git_cookie, &IWTSVirtualChannel::IID, &mut raw_ptr)
                    .map_err(|e| format!("跨线程解封 IWTSVirtualChannel 失败: {e}"))?;
                if raw_ptr.is_null() {
                    return Err("解封后的 IWTSVirtualChannel 指针为空。".to_owned());
                }
                let local_ch = IWTSVirtualChannel::from_raw(raw_ptr);
                local_ch
                    .Write(bytes, None::<&IUnknown>)
                    .map_err(|e| format!("DVC Write 失败: {e}"))
            }
        }
    }

    #[implement(IWTSVirtualChannelCallback)]
    struct ChannelCallback {
        hub: DvcHub,
        channel_name: String,
        session_id: String,
        decoder: Mutex<StreamDecoder>,
    }

    impl IWTSVirtualChannelCallback_Impl for ChannelCallback_Impl {
        fn OnDataReceived(&self, cb_size: u32, p_buffer: *const u8) -> WinResult<()> {
            if p_buffer.is_null() || cb_size == 0 || cb_size as usize > MAX_FRAME_SIZE + 65536 {
                return Ok(());
            }
            // SAFETY: `p_buffer` is valid for `cb_size` bytes during `OnDataReceived`.
            let slice = unsafe { std::slice::from_raw_parts(p_buffer, cb_size as usize) };
            let messages = {
                let mut dec = self.decoder.lock();
                dec.feed(slice)
            };
            match messages {
                Ok(list) => {
                    for msg in list {
                        self.hub.on_incoming_for_session(msg, &self.session_id);
                    }
                }
                Err(err) => {
                    let mut guard = self.hub.state.lock();
                    guard.push_log("in", "error", format!("帧解析错误: {err}"));
                }
            }
            Ok(())
        }

        fn OnClose(&self) -> WinResult<()> {
            let mut guard = self.hub.state.lock();
            if guard.session_id.as_deref() != Some(&self.session_id) {
                return Ok(());
            }
            guard.channel_connected = false;
            guard.session_id = None;
            guard.writer = None;
            guard.push_log(
                "system",
                "status",
                format!("通道已关闭 ({})", self.channel_name),
            );
            self.hub.result_cv.notify_all();
            Ok(())
        }
    }

    #[implement(IWTSListenerCallback)]
    struct ListenerCallback {
        hub: DvcHub,
        channel_name: String,
    }

    impl IWTSListenerCallback_Impl for ListenerCallback_Impl {
        fn OnNewChannelConnection(
            &self,
            channel: Ref<'_, IWTSVirtualChannel>,
            _data: &BSTR,
            accept: *mut BOOL,
            callback: OutRef<'_, IWTSVirtualChannelCallback>,
        ) -> WinResult<()> {
            let ch = channel.ok()?;
            let git_ch = GitChannel::register(ch)?;
            let write_lock = Arc::new(Mutex::new(()));
            let writer: ChannelWriteFn = Arc::new(move |bytes: &[u8]| {
                let _g = write_lock.lock();
                git_ch.write(bytes)
            });

            let session_id = uuid::Uuid::new_v4().to_string();
            {
                let mut guard = self.hub.state.lock();
                guard.channel_connected = true;
                guard.active_channel_name = Some(self.channel_name.clone());
                guard.connected_since = Some(Utc::now().to_rfc3339());
                guard.session_id = Some(session_id.clone());
                guard.pending_results.clear();
                guard.in_progress_file = None;
                guard.writer = Some(writer);
                guard.push_log(
                    "system",
                    "status",
                    format!("远程会话已建立 DVC 通道 ({})", self.channel_name),
                );
                self.hub.result_cv.notify_all();
            }

            let cb: IWTSVirtualChannelCallback = ChannelCallback {
                hub: self.hub.clone(),
                channel_name: self.channel_name.clone(),
                session_id,
                decoder: Mutex::new(StreamDecoder::new()),
            }
            .into();

            // SAFETY: COM caller provides valid out pointer for `accept`.
            unsafe {
                if !accept.is_null() {
                    *accept = TRUE;
                }
            }
            let _ = callback.write(Some(cb));
            Ok(())
        }
    }

    #[implement(IWTSPlugin)]
    struct WinIrPlugin {
        hub: DvcHub,
        listeners: Mutex<Vec<IWTSListener>>,
    }

    impl IWTSPlugin_Impl for WinIrPlugin_Impl {
        fn Initialize(&self, channel_manager: Ref<'_, IWTSVirtualChannelManager>) -> WinResult<()> {
            let mgr = channel_manager.ok()?;
            let mut created = Vec::new();
            for (cstr, label) in [
                (PRIMARY_CHANNEL_CSTR, PRIMARY_CHANNEL_NAME),
                (COMPAT_CHANNEL_CSTR, COMPAT_CHANNEL_NAME),
            ] {
                let cb: IWTSListenerCallback = ListenerCallback {
                    hub: self.hub.clone(),
                    channel_name: label.to_owned(),
                }
                .into();
                // SAFETY: `cstr` is a static null-terminated ASCII string.
                let listener = unsafe { mgr.CreateListener(PCSTR(cstr.as_ptr()), 0, &cb)? };
                created.push(listener);
            }
            *self.listeners.lock() = created;
            let mut guard = self.hub.state.lock();
            guard.rdp_plugin_initialized = true;
            guard.push_log(
                "system",
                "status",
                "mstsc 已加载 DVC 插件并注册监听 (dvc::lovelyhawk::winir, dvc::demo::chat)",
            );
            Ok(())
        }

        fn Connected(&self) -> WinResult<()> {
            let mut guard = self.hub.state.lock();
            guard.push_log("system", "status", "RDP 会话已连接");
            Ok(())
        }

        fn Disconnected(&self, disconnect_code: u32) -> WinResult<()> {
            let mut guard = self.hub.state.lock();
            guard.channel_connected = false;
            guard.writer = None;
            guard.push_log(
                "system",
                "status",
                format!("RDP 会话已断开 (code=0x{disconnect_code:08X})"),
            );
            self.hub.result_cv.notify_all();
            Ok(())
        }

        fn Terminated(&self) -> WinResult<()> {
            self.listeners.lock().clear();
            let mut guard = self.hub.state.lock();
            guard.rdp_plugin_initialized = false;
            guard.channel_connected = false;
            guard.writer = None;
            guard.push_log("system", "status", "RDP 客户端已退出");
            self.hub.result_cv.notify_all();
            Ok(())
        }
    }

    #[implement(IClassFactory)]
    struct PluginClassFactory {
        hub: DvcHub,
    }

    impl IClassFactory_Impl for PluginClassFactory_Impl {
        fn CreateInstance(
            &self,
            outer: Ref<'_, IUnknown>,
            iid: *const GUID,
            object: *mut *mut c_void,
        ) -> WinResult<()> {
            if outer.is_some() {
                return Err(Error::new(
                    CLASS_E_NOAGGREGATION,
                    "Aggregation not supported",
                ));
            }
            let plugin: IWTSPlugin = WinIrPlugin {
                hub: self.hub.clone(),
                listeners: Mutex::new(Vec::new()),
            }
            .into();
            // SAFETY: COM caller provides valid `iid` and `object` pointers.
            unsafe { plugin.query(&*iid, object).ok() }
        }

        fn LockServer(&self, _lock: BOOL) -> WinResult<()> {
            Ok(())
        }
    }

    pub fn spawn_com_local_server(hub: DvcHub) -> Result<(), String> {
        let (tx, rx) = std::sync::mpsc::channel::<Result<(), String>>();
        std::thread::Builder::new()
            .name("lovelyhawk-dvc-com-server".to_owned())
            .spawn(move || {
                // SAFETY: COM initialization and class factory registration on dedicated thread.
                unsafe {
                    let hr = CoInitializeEx(None, COINIT_MULTITHREADED);
                    if hr.is_err() && hr != RPC_E_CHANGED_MODE {
                        let _ = tx.send(Err(format!("CoInitializeEx 失败: {hr:?}")));
                        return;
                    }
                    let sec = CoInitializeSecurity(
                        None,
                        -1,
                        None,
                        None,
                        RPC_C_AUTHN_LEVEL_DEFAULT,
                        RPC_C_IMP_LEVEL_IMPERSONATE,
                        None,
                        Default::default(),
                        None,
                    );
                    if let Err(e) = sec
                        && e.code() != RPC_E_TOO_LATE
                    {
                        tracing::debug!("CoInitializeSecurity returned {e:?}");
                    }

                    let factory: IClassFactory = PluginClassFactory { hub: hub.clone() }.into();
                    let cookie = match CoRegisterClassObject(
                        &CLSID_RDP_PLUGIN,
                        &factory,
                        CLSCTX_LOCAL_SERVER,
                        REGCLS_MULTIPLEUSE | REGCLS_SUSPENDED,
                    ) {
                        Ok(c) => c,
                        Err(e) => {
                            let _ = tx.send(Err(format!("CoRegisterClassObject 失败: {e}")));
                            CoUninitialize();
                            return;
                        }
                    };
                    if let Err(e) = CoResumeClassObjects() {
                        let _ = CoRevokeClassObject(cookie);
                        CoUninitialize();
                        let _ = tx.send(Err(format!("CoResumeClassObjects 失败: {e}")));
                        return;
                    }

                    {
                        let mut guard = hub.state.lock();
                        guard.listener_running = true;
                        guard.push_log(
                            "system",
                            "status",
                            format!("COM LocalServer 已启动 (CLSID={PLUGIN_CLSID_STR})"),
                        );
                    }
                    let _ = tx.send(Ok(()));

                    let mut msg = MSG::default();
                    loop {
                        while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).into() {
                            if msg.message == WM_QUIT {
                                let _ = CoRevokeClassObject(cookie);
                                CoUninitialize();
                                return;
                            }
                            let _ = TranslateMessage(&msg);
                            DispatchMessageW(&msg);
                        }
                        std::thread::sleep(Duration::from_millis(15));
                    }
                }
            })
            .map_err(|e| format!("无法启动 COM LocalServer 线程: {e}"))?;

        rx.recv_timeout(Duration::from_secs(5))
            .map_err(|e| format!("等待 COM LocalServer 启动超时: {e}"))?
    }
}

#[cfg(not(windows))]
mod win_impl {
    use super::*;

    pub fn query_registration() -> DvcRegistrationStatus {
        DvcRegistrationStatus {
            registered: false,
            clsid: PLUGIN_CLSID_STR.to_owned(),
            addin_name: ADDIN_NAME.to_owned(),
            local_server_command: None,
        }
    }

    pub fn register_addin_per_user(
        _custom_command: Option<&str>,
    ) -> Result<DvcRegistrationStatus, String> {
        Err("RDP DVC 插件注册仅在 Windows 主机上可用。".to_owned())
    }

    pub fn unregister_addin_per_user() -> Result<DvcRegistrationStatus, String> {
        Err("RDP DVC 插件卸载仅在 Windows 主机上可用。".to_owned())
    }

    pub fn spawn_com_local_server(_hub: DvcHub) -> Result<(), String> {
        Err("RDP DVC COM LocalServer 仅在 Windows 主机上可用。".to_owned())
    }
}

pub use win_impl::{
    query_registration, register_addin_per_user, spawn_com_local_server, unregister_addin_per_user,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_session_is_refused_before_any_command_or_chat_is_sent() {
        let hub = DvcHub::new();
        let writes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        {
            let mut state = hub.state.lock();
            state.channel_connected = true;
            state.session_id = Some("current".to_owned());
            let counter = writes.clone();
            state.writer = Some(Arc::new(move |_| {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }));
        }
        assert!(
            hub.execute_command_for_session("whoami", Duration::ZERO, "previous")
                .is_err()
        );
        assert!(hub.send_chat_for_session("hello", "previous").is_err());
        assert_eq!(writes.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn timed_out_and_previous_channel_replies_cannot_complete_a_new_command() {
        let hub = DvcHub::new();
        {
            let mut state = hub.state.lock();
            state.channel_connected = true;
            state.session_id = Some("first".to_owned());
            state.writer = Some(Arc::new(|_| Ok(())));
        }
        assert!(
            hub.execute_command_for_session("query", Duration::ZERO, "first")
                .is_err()
        );
        assert!(!hub.status().channel_connected);
        let reply = |text: &str| DvcWireMessage {
            from: "server".to_owned(),
            seq: 1,
            msg_type: "result".to_owned(),
            text: text.to_owned(),
            name: None,
            size: None,
            b64: None,
            sha256: None,
        };
        assert!(!hub.on_incoming_for_session(reply("late"), "first"));
        {
            let mut state = hub.state.lock();
            state.channel_connected = true;
            state.session_id = Some("second".to_owned());
            let responder = hub.clone();
            state.writer = Some(Arc::new(move |_| {
                assert!(!responder.on_incoming_for_session(reply("old channel"), "first"));
                responder.on_incoming_for_session(reply("current result"), "second");
                Ok(())
            }));
        }
        assert_eq!(
            hub.execute_command_for_session("query", Duration::from_secs(1), "second")
                .unwrap(),
            "current result"
        );
        hub.state.lock().writer = None;
    }

    #[test]
    fn only_verified_receipts_can_be_read_in_bounded_parts() {
        let hub = DvcHub::new();
        for digest in [
            "",
            "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7",
        ] {
            for msg in [
                DvcWireMessage {
                    from: "server".into(),
                    seq: 0,
                    msg_type: "file_start".into(),
                    text: String::new(),
                    name: Some("sample.bin".into()),
                    size: Some(4),
                    b64: None,
                    sha256: None,
                },
                DvcWireMessage {
                    from: "server".into(),
                    seq: 0,
                    msg_type: "file_chunk".into(),
                    text: String::new(),
                    name: None,
                    size: None,
                    b64: Some("ZGF0YQ==".into()),
                    sha256: None,
                },
                DvcWireMessage {
                    from: "server".into(),
                    seq: 0,
                    msg_type: "file_end".into(),
                    text: String::new(),
                    name: None,
                    size: None,
                    b64: None,
                    sha256: Some(digest.into()),
                },
            ] {
                hub.on_incoming_message(msg);
            }
        }
        let files = hub.status().received_files;
        assert!(!files[0].verified);
        assert!(hub.received_file_part(&files[0].file_id, 0, 4).is_none());
        let part = hub.received_file_part(&files[1].file_id, 2, 2).unwrap();
        assert_eq!(part.content, b"ta");
        assert_eq!(part.size_bytes, 4);
        assert!(hub.received_file_part(&files[1].file_id, 5, 2).is_none());
    }

    #[test]
    fn stream_decoder_reassembles_split_frames_and_utf8() {
        let msg = DvcWireMessage::chat("server", 7, "你好 Windows 应急响应");
        let frame = encode_frame(&msg).unwrap();
        let mut dec = StreamDecoder::new();
        assert!(dec.feed(&frame[..5]).unwrap().is_empty());
        let got = dec.feed(&frame[5..]).unwrap();
        assert_eq!(got, vec![msg]);
    }

    #[test]
    fn pdu_reassembler_joins_first_and_last_fragments() {
        let mut reassembler = PduReassembler::new();
        let mut pdu1 = Vec::new();
        pdu1.extend_from_slice(&10u32.to_le_bytes());
        pdu1.extend_from_slice(&PDU_FLAG_FIRST.to_le_bytes());
        pdu1.extend_from_slice(b"hello ");
        assert!(reassembler.push_read(&pdu1).is_none());

        let mut pdu2 = Vec::new();
        pdu2.extend_from_slice(&10u32.to_le_bytes());
        pdu2.extend_from_slice(&PDU_FLAG_LAST.to_le_bytes());
        pdu2.extend_from_slice(b"world");
        let full = reassembler.push_read(&pdu2).unwrap();
        assert_eq!(full, b"hello world");
    }

    #[test]
    fn com_embedding_switch_is_detected_case_insensitively() {
        assert!(has_com_embedding_arg(["-Embedding"]));
        assert!(has_com_embedding_arg(["/embedding"]));
        assert!(has_com_embedding_arg(["--other", "-EMBEDDING"]));
        assert!(!has_com_embedding_arg(["--help", "embedding"]));
        assert!(!has_com_embedding_arg(Vec::<&str>::new()));
    }
}
