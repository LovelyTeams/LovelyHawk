//! Native SSH transport with a dedicated Tokio runtime and typed event streams.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use russh::client::{Config, Handle, Handler, KeyboardInteractiveAuthResponse, Msg, Prompt};
use russh::keys::agent::{
    AgentIdentity,
    client::{AgentClient, AgentStream},
};
use russh::keys::{Certificate, PrivateKeyWithHashAlg, PublicKey};
use russh::{ChannelMsg, Disconnect};
use russh_sftp::{client::SftpSession, protocol::OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};
use tokio::task::JoinSet;
use zeroize::Zeroizing;

use crate::connections::{
    ConnectionConfig, ConnectionProbePlan, ConnectionRepository, ConnectionSecretChanges,
    JumpHostConfig, ResolvedConnection, SshAuthMethod,
};
use crate::crypto::SecretValue;
use crate::events::{
    EventChannelDefaults, TerminalEvent, TerminalEventKind, TerminalEventReceiver,
    TerminalEventSender, TerminalTransport, terminal_event_channel,
};
use crate::postgresql_native::{NATIVE_READ_TIMEOUT, NativeRuntimeRead, NativeRuntimeRequest};
use crate::sftp::{BACKUP_DIRECTORY_MODE, BACKUP_FILE_MODE, RemotePath};
use crate::target::TargetGuard;
use crate::types::{BashEnvironmentInfo, CommandCompletion};
use crate::{
    CoreError, CoreResult, PortableStore, SshHostRole, SshKeyboardInteractiveChallenge,
    SshKeyboardInteractivePrompt,
};

/// Names the failure of the SFTP protocol handshake, as opposed to opening the
/// channel or asking for the subsystem.
///
/// Reaching this point means the server took the request and then never
/// completed the exchange. By far the most common reason is an `sshd` with no
/// `Subsystem sftp` line, which is worth saying out loud: the alternative is a
/// ten-second wait ending in a message about the file browser being
/// unavailable, which reads as the feature being broken.
pub const SFTP_HANDSHAKE_OPERATION: &str = "SFTP subsystem handshake";

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const AUTH_TIMEOUT: Duration = Duration::from_secs(20);
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_OPERATION_TIMEOUT: Duration = Duration::from_secs(90);
const SFTP_OPERATION_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const OPEN_TERMINAL_TIMEOUT: Duration = Duration::from_secs(30);
const DISCONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const SHUTDOWN_GRACE: Duration = Duration::from_millis(500);
const MAX_KEY_BYTES: u64 = 4 * 1024 * 1024;
const MAX_COMMAND_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
const MAX_SENSITIVE_COMMAND_STREAM_BYTES: usize = 4 * 1024 * 1024;
const MAX_SENSITIVE_COMMAND_STDIN_BYTES: usize = 64 * 1024;
const SSH_COMMAND_CAPACITY: usize = 256;
const CONNECT_CONCURRENCY: usize = 4;
const CONNECT_PENDING_CAPACITY: usize = 16;
const SESSION_OPERATION_CONCURRENCY: usize = 4;
const SESSION_OPERATION_CAPACITY: usize = 16;
const TERMINAL_CONTROL_CAPACITY: usize = 64;
const MAX_COMPLETION_INPUT_BYTES: usize = 4_096;
const MAX_COMPLETION_CANDIDATES: usize = 100;
const MAX_COMPLETION_CANDIDATE_BYTES: usize = 4_096;
const MAX_KEYBOARD_INTERACTIVE_ROUNDS: usize = 8;
const MAX_KEYBOARD_INTERACTIVE_PROMPTS: usize = 16;
const MAX_KEYBOARD_INTERACTIVE_RESPONSES: usize = 32;
const MAX_KEYBOARD_INTERACTIVE_RESPONSE_BYTES: usize = 4_096;
const MAX_KEYBOARD_INTERACTIVE_TOTAL_RESPONSE_BYTES: usize = 32 * 1_024;
const MAX_KEYBOARD_INTERACTIVE_LABEL_BYTES: usize = 4_096;
const MAX_KEYBOARD_INTERACTIVE_INSTRUCTIONS_BYTES: usize = 16 * 1_024;

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

const COMMON_SHELL_COMMANDS: &[&str] = &[
    "awk",
    "cat",
    "cd",
    "chmod",
    "chown",
    "cp",
    "crontab",
    "curl",
    "df",
    "du",
    "find",
    "free",
    "grep",
    "groups",
    "gunzip",
    "gzip",
    "head",
    "history",
    "htop",
    "id",
    "less",
    "ls",
    "mkdir",
    "more",
    "mv",
    "nano",
    "ps",
    "pwd",
    "rm",
    "rmdir",
    "rsync",
    "scp",
    "sed",
    "service",
    "sort",
    "ssh",
    "systemctl",
    "tail",
    "tar",
    "top",
    "tr",
    "uname",
    "uniq",
    "unzip",
    "vim",
    "wc",
    "wget",
    "whoami",
    "zip",
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostKeyConfirmations {
    pub target_fingerprint: Option<String>,
    pub jump_host_fingerprint: Option<String>,
}

/// Short-lived authorization supplied to one SSH connection attempt.
///
/// Host-key confirmations are non-secret and may survive retries. Keyboard-
/// interactive responses are bounded, never serialized, and redacted from Debug.
pub struct SshConnectAuthorization {
    host_keys: HostKeyConfirmations,
    target_keyboard_interactive_responses: Vec<SecretValue>,
    jump_keyboard_interactive_responses: Vec<SecretValue>,
}

impl Default for SshConnectAuthorization {
    fn default() -> Self {
        Self::from(HostKeyConfirmations::default())
    }
}

impl From<HostKeyConfirmations> for SshConnectAuthorization {
    fn from(host_keys: HostKeyConfirmations) -> Self {
        Self {
            host_keys,
            target_keyboard_interactive_responses: Vec::new(),
            jump_keyboard_interactive_responses: Vec::new(),
        }
    }
}

impl Clone for SshConnectAuthorization {
    fn clone(&self) -> Self {
        Self {
            host_keys: self.host_keys.clone(),
            target_keyboard_interactive_responses: self
                .target_keyboard_interactive_responses
                .iter()
                .map(|value| SecretValue::new(value.expose()))
                .collect(),
            jump_keyboard_interactive_responses: self
                .jump_keyboard_interactive_responses
                .iter()
                .map(|value| SecretValue::new(value.expose()))
                .collect(),
        }
    }
}

impl fmt::Debug for SshConnectAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SshConnectAuthorization")
            .field("host_keys", &self.host_keys)
            .field(
                "target_keyboard_interactive_response_count",
                &self.target_keyboard_interactive_responses.len(),
            )
            .field(
                "jump_keyboard_interactive_response_count",
                &self.jump_keyboard_interactive_responses.len(),
            )
            .finish()
    }
}

impl SshConnectAuthorization {
    pub fn host_keys(&self) -> &HostKeyConfirmations {
        &self.host_keys
    }

    pub fn host_keys_mut(&mut self) -> &mut HostKeyConfirmations {
        &mut self.host_keys
    }

    pub fn keyboard_interactive_response_count(&self, role: SshHostRole) -> usize {
        self.responses(role).len()
    }

    pub fn push_keyboard_interactive_response(
        &mut self,
        role: SshHostRole,
        response: SecretValue,
    ) -> CoreResult<()> {
        self.extend_keyboard_interactive_responses(role, vec![response])
    }

    pub fn extend_keyboard_interactive_responses(
        &mut self,
        role: SshHostRole,
        new_responses: Vec<SecretValue>,
    ) -> CoreResult<()> {
        if new_responses
            .iter()
            .any(|response| response.expose().len() > MAX_KEYBOARD_INTERACTIVE_RESPONSE_BYTES)
        {
            return Err(CoreError::validation(
                "SSH keyboard-interactive response",
                "each response must be no larger than 4 KiB",
            ));
        }
        let existing = self.responses(role);
        if existing.len().saturating_add(new_responses.len()) > MAX_KEYBOARD_INTERACTIVE_RESPONSES {
            return Err(CoreError::validation(
                "SSH keyboard-interactive response",
                "an attempt may contain at most 32 responses",
            ));
        }
        let total = existing
            .iter()
            .map(|value| value.expose().len())
            .sum::<usize>()
            .saturating_add(
                new_responses
                    .iter()
                    .map(|value| value.expose().len())
                    .sum::<usize>(),
            );
        if total > MAX_KEYBOARD_INTERACTIVE_TOTAL_RESPONSE_BYTES {
            return Err(CoreError::validation(
                "SSH keyboard-interactive response",
                "responses may contain at most 32 KiB in total",
            ));
        }
        self.responses_mut(role).extend(new_responses);
        Ok(())
    }

    fn responses(&self, role: SshHostRole) -> &[SecretValue] {
        match role {
            SshHostRole::Target => &self.target_keyboard_interactive_responses,
            SshHostRole::JumpHost => &self.jump_keyboard_interactive_responses,
        }
    }

    fn responses_mut(&mut self, role: SshHostRole) -> &mut Vec<SecretValue> {
        match role {
            SshHostRole::Target => &mut self.target_keyboard_interactive_responses,
            SshHostRole::JumpHost => &mut self.jump_keyboard_interactive_responses,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshConnectionStatus {
    pub session_id: String,
    pub connection_id: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub host_key_fingerprint: String,
    pub connected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshConnectionProbeResult {
    pub connection_id: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub host_key_fingerprint: String,
    pub checked_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct SshConnectionProbeSuccess {
    pub result: SshConnectionProbeResult,
    pub verified_plan: ConnectionProbePlan,
}

/// An SSH session bound to the target epoch that minted it.
///
/// The private fields prevent callers from combining host A's target guard with
/// host B's raw session id. Domain services still validate the target guard
/// immediately before dispatch and after applying the result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundSshSession {
    session_id: String,
    connection_id: String,
    target: TargetGuard,
}

impl BoundSshSession {
    pub(crate) fn from_status(
        target: TargetGuard,
        status: &SshConnectionStatus,
        binding_subject: &'static str,
    ) -> CoreResult<Self> {
        if status.connection_id != target.identity.as_str() {
            return Err(CoreError::validation(
                binding_subject,
                "SSH session connection does not match the guarded target identity",
            ));
        }
        Ok(Self {
            session_id: status.session_id.clone(),
            connection_id: status.connection_id.clone(),
            target,
        })
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }

    pub fn target(&self) -> &TargetGuard {
        &self.target
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshCommandOutput {
    pub command: String,
    pub output: String,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub timed_out: bool,
}

/// Per-stream limits for a core-owned command whose output may contain
/// credentials or other sensitive configuration values.
///
/// This transport is crate-private on purpose: callers cannot turn it into a
/// second arbitrary shell surface. Domain services must still provide a
/// closed command and validate their own wire contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SshSensitiveCommandLimits {
    stdout_bytes: usize,
    stderr_bytes: usize,
}

impl SshSensitiveCommandLimits {
    pub(crate) fn new(stdout_bytes: usize, stderr_bytes: usize) -> CoreResult<Self> {
        if stdout_bytes == 0
            || stderr_bytes == 0
            || stdout_bytes > MAX_SENSITIVE_COMMAND_STREAM_BYTES
            || stderr_bytes > MAX_SENSITIVE_COMMAND_STREAM_BYTES
        {
            return Err(CoreError::validation(
                "sensitive SSH output limits",
                "each stream must be between 1 byte and 4 MiB",
            ));
        }
        Ok(Self {
            stdout_bytes,
            stderr_bytes,
        })
    }
}

pub(crate) struct SshSensitiveCommandOutput {
    pub(crate) stdout: Zeroizing<Vec<u8>>,
    pub(crate) stderr: Zeroizing<Vec<u8>>,
    pub(crate) exit_code: Option<i32>,
    pub(crate) duration_ms: u64,
}

impl fmt::Debug for SshSensitiveCommandOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SshSensitiveCommandOutput")
            .field("stdout_bytes", &self.stdout.len())
            .field("stderr_bytes", &self.stderr.len())
            .field("exit_code", &self.exit_code)
            .field("duration_ms", &self.duration_ms)
            .finish()
    }
}

/// Lets the operator stop an upload or download that is already moving bytes.
///
/// The copy checks it between chunks and races it against each read and
/// write, then removes what it had written before answering, so a cancelled
/// transfer leaves no half file behind. Clones share the same switch.
#[derive(Clone, Debug)]
pub struct SftpTransferCancel(Arc<watch::Sender<bool>>);

impl Default for SftpTransferCancel {
    fn default() -> Self {
        Self(Arc::new(watch::channel(false).0))
    }
}

impl SftpTransferCancel {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.send_replace(true);
    }

    pub fn is_cancelled(&self) -> bool {
        *self.0.borrow()
    }

    async fn cancelled(&self) {
        let mut receiver = self.0.subscribe();
        let _ = receiver.wait_for(|cancelled| *cancelled).await;
    }
}

/// What a cancelled transfer answers; `sftp::is_transfer_cancelled` reads it.
pub(crate) const TRANSFER_CANCELLED: &str = "cancelled by the operator; no partial file was kept";

#[derive(Debug)]
pub(crate) enum SftpRequest {
    Canonicalize {
        path: String,
    },
    List {
        path: String,
        maximum_entries: usize,
    },
    Metadata {
        path: String,
        follow_symlink: bool,
    },
    Exists {
        path: String,
    },
    Read {
        path: String,
        maximum_bytes: u64,
    },
    WriteNew {
        path: String,
        content: Vec<u8>,
        mode: Option<u32>,
    },
    UploadNew {
        local_path: PathBuf,
        remote_path: String,
        maximum_bytes: u64,
        cancel: SftpTransferCancel,
    },
    DownloadNew {
        remote_path: String,
        local_path: PathBuf,
        maximum_bytes: u64,
        cancel: SftpTransferCancel,
    },
    CollectFileEvidence {
        remote_path: String,
        destination: std::fs::File,
        progress: crate::file_evidence::FileEvidenceProgress,
    },
    CreateDirectory {
        path: String,
    },
    Rename {
        from: String,
        to: String,
        require_destination_absent: bool,
    },
    MoveToBackup {
        path: String,
        backup_directory: String,
        backup_path: String,
        expected_sha256: Option<String>,
        maximum_bytes: u64,
    },
    Remove {
        path: String,
        directory: bool,
    },
    Chmod {
        path: String,
        mode: u32,
    },
    AtomicWrite {
        path: String,
        backup_directory: String,
        backup_path: String,
        content: Vec<u8>,
        maximum_bytes: u64,
        expected_sha256: Option<String>,
        expected_canonical_path: Option<String>,
    },
}

#[derive(Debug)]
pub(crate) enum SftpResponse {
    Unit,
    Path(String),
    Entries(Vec<SftpRawEntry>),
    Metadata(SftpRawMetadata),
    Exists(bool),
    Bytes(Vec<u8>),
    Transfer { bytes: u64 },
    AtomicWrite(SftpAtomicWriteReceipt),
    FileEvidence(crate::file_evidence::FileEvidenceReadProof),
}

impl SftpResponse {
    pub(crate) const fn kind(&self) -> &'static str {
        match self {
            Self::Unit => "unit",
            Self::Path(_) => "path",
            Self::Entries(_) => "entries",
            Self::Metadata(_) => "metadata",
            Self::Exists(_) => "exists",
            Self::Bytes(_) => "bytes",
            Self::Transfer { .. } => "transfer",
            Self::AtomicWrite(_) => "atomic-write",
            Self::FileEvidence(_) => "file-evidence",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SftpRawEntry {
    pub name: String,
    pub path: String,
    pub metadata: SftpRawMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SftpRawMetadata {
    pub size: u64,
    pub permissions: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub modified_unix_seconds: Option<u32>,
    pub is_file: bool,
    pub is_directory: bool,
    pub is_symlink: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SftpAtomicWriteReceipt {
    pub path: String,
    pub backup_path: String,
    pub bytes_written: u64,
    pub previous_permissions: Option<u32>,
    pub installed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContainerPtyRuntime {
    Docker,
    Podman,
}

impl ContainerPtyRuntime {
    const fn program(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Podman => "podman",
        }
    }
}

/// The variable every container shell carries, so its process tree can be
/// found again once the window is gone. `docker exec` and `podman exec` leave
/// the process they started running inside the container when their client
/// goes away; closing a window must not leave work running in someone's
/// container.
const CONTAINER_SESSION_VARIABLE: &str = "LOVELYHAWK_TERMINAL";

fn validate_container_session_marker(marker: &str) -> CoreResult<()> {
    if marker.len() == 32 && marker.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(CoreError::validation(
            "container session marker",
            "must be 32 hexadecimal characters",
        ))
    }
}

/// Ends, inside the container, every process started from one container
/// shell: hang-up first, then kill whatever is left a second later. Runs as a
/// plain exec over the same SSH session, after the shell's own channel closed.
/// The cleanup's own shell does not carry the marker, so it never ends itself.
pub(crate) fn container_session_cleanup_command(
    runtime: ContainerPtyRuntime,
    container_id: &str,
    marker: &str,
) -> CoreResult<String> {
    validate_container_id_for_exec(container_id)?;
    validate_container_session_marker(marker)?;
    Ok(format!(
        "{} exec -- {} /bin/sh -c {}",
        runtime.program(),
        crate::shell_escape::shq(container_id),
        crate::shell_escape::shq(&session_cleanup_script(marker))
    ))
}

/// The same cleanup for a pod's shell. `kubectl exec` leaves what it started
/// running when its client goes away just as a container runtime does. It
/// runs in the container the shell ran in: another container of the pod has
/// its own processes and never sees the shell's.
pub(crate) fn pod_session_cleanup_command(
    namespace: &str,
    pod: &str,
    container: Option<&str>,
    marker: &str,
) -> CoreResult<String> {
    crate::kubernetes::validate_pod_reference(namespace, pod)?;
    validate_container_session_marker(marker)?;
    Ok(format!(
        "kubectl exec {} -n {}{} -- /bin/sh -c {}",
        crate::shell_escape::shq(pod),
        crate::shell_escape::shq(namespace),
        pod_container_flag(container)?,
        crate::shell_escape::shq(&session_cleanup_script(marker))
    ))
}

/// ` -c <container>` for a named container, nothing for the pod's default.
fn pod_container_flag(container: Option<&str>) -> CoreResult<String> {
    match container {
        None => Ok(String::new()),
        Some(name) => {
            crate::kubernetes::validate_container_name(name)?;
            Ok(format!(" -c {}", crate::shell_escape::shq(name)))
        }
    }
}

fn session_cleanup_script(marker: &str) -> String {
    format!(
        "m={CONTAINER_SESSION_VARIABLE}={marker}; \
         hit() {{ for p in /proc/[0-9]*; do [ -r \"$p/environ\" ] || continue; \
         if tr '\\000' '\\n' < \"$p/environ\" 2>/dev/null | grep -qx \"$m\"; then echo \"${{p#/proc/}}\"; fi; done; }}; \
         pids=$(hit); [ -n \"$pids\" ] && kill -HUP $pids 2>/dev/null; \
         sleep 1; pids=$(hit); [ -n \"$pids\" ] && kill -KILL $pids 2>/dev/null; exit 0"
    )
}

fn validate_container_id_for_exec(container_id: &str) -> CoreResult<()> {
    if (12..=64).contains(&container_id.len())
        && container_id.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        Ok(())
    } else {
        Err(CoreError::validation(
            "container PTY id",
            "must be a 12..=64 character hexadecimal runtime id",
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContainerPtyShell {
    Sh,
    Bash,
    Ash,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContainerPtyRequest {
    terminal_id: String,
    runtime: ContainerPtyRuntime,
    container_id: String,
    shell: ContainerPtyShell,
    size: (u16, u16),
    marker: String,
}

/// A shell in one pod, by the namespace and name core read from the cluster,
/// in the container the operator chose among the listed ones; with none
/// named, kubectl picks the pod's default container, as it does for
/// `kubectl exec` typed by hand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PodPtyRequest {
    pub(crate) terminal_id: String,
    pub(crate) namespace: String,
    pub(crate) pod: String,
    pub(crate) container: Option<String>,
    pub(crate) shell: ContainerPtyShell,
    pub(crate) size: (u16, u16),
    pub(crate) marker: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PacketCapturePtyRequest {
    terminal_id: String,
    command: String,
}

impl PacketCapturePtyRequest {
    pub(crate) fn new(terminal_id: String, command: String) -> CoreResult<Self> {
        if command.trim().is_empty() || command.len() > 16 * 1024 {
            return Err(CoreError::validation(
                "packet capture command",
                "must be non-empty and at most 16 KiB",
            ));
        }
        Ok(Self {
            terminal_id,
            command,
        })
    }
}

impl ContainerPtyRequest {
    pub(crate) fn new(
        terminal_id: String,
        runtime: ContainerPtyRuntime,
        container_id: String,
        shell: ContainerPtyShell,
        size: (u16, u16),
        marker: String,
    ) -> Self {
        Self {
            terminal_id,
            runtime,
            container_id,
            shell,
            size,
            marker,
        }
    }
}

impl ContainerPtyShell {
    const fn program(self) -> &'static str {
        match self {
            Self::Sh => "/bin/sh",
            Self::Bash => "/bin/bash",
            Self::Ash => "/bin/ash",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TerminalLaunch {
    LoginShell,
    LoginShellAt {
        directory: RemotePath,
    },
    ContainerExec {
        runtime: ContainerPtyRuntime,
        container_id: String,
        shell: ContainerPtyShell,
        marker: String,
    },
    PodExec {
        namespace: String,
        pod: String,
        container: Option<String>,
        shell: ContainerPtyShell,
        marker: String,
    },
    PacketCapture {
        command: String,
    },
}

impl TerminalLaunch {
    fn pod_exec(
        namespace: String,
        pod: String,
        container: Option<String>,
        shell: ContainerPtyShell,
        marker: String,
    ) -> CoreResult<Self> {
        crate::kubernetes::validate_pod_reference(&namespace, &pod)?;
        if let Some(container) = &container {
            crate::kubernetes::validate_container_name(container)?;
        }
        validate_container_session_marker(&marker)?;
        Ok(Self::PodExec {
            namespace,
            pod,
            container,
            shell,
            marker,
        })
    }

    fn container_exec(
        runtime: ContainerPtyRuntime,
        container_id: String,
        shell: ContainerPtyShell,
        marker: String,
    ) -> CoreResult<Self> {
        validate_container_id_for_exec(&container_id)?;
        validate_container_session_marker(&marker)?;
        Ok(Self::ContainerExec {
            runtime,
            container_id,
            shell,
            marker,
        })
    }

    fn exec_command(&self) -> Option<String> {
        match self {
            Self::LoginShell => None,
            Self::LoginShellAt { directory } => Some(format!(
                "cd -- {} && exec \"${{SHELL:-/bin/sh}}\" -l",
                crate::shell_escape::shq(directory.as_str())
            )),
            Self::ContainerExec {
                runtime,
                container_id,
                shell,
                marker,
            } => Some(format!(
                "{} exec -it -e {CONTAINER_SESSION_VARIABLE}={marker} -- {} {}",
                runtime.program(),
                crate::shell_escape::shq(container_id),
                shell.program()
            )),
            // kubectl exec has no `-e`, so the shell sets the marker on itself
            // and then becomes the interactive shell: every process the
            // operator starts inherits it, which is what cleanup looks for.
            Self::PodExec {
                namespace,
                pod,
                container,
                shell,
                marker,
            } => Some(format!(
                "kubectl exec -it {} -n {}{} -- {} -c {}",
                crate::shell_escape::shq(pod),
                crate::shell_escape::shq(namespace),
                container
                    .as_deref()
                    .map(|container| format!(" -c {}", crate::shell_escape::shq(container)))
                    .unwrap_or_default(),
                shell.program(),
                crate::shell_escape::shq(&format!(
                    "{CONTAINER_SESSION_VARIABLE}={marker}; export {CONTAINER_SESSION_VARIABLE}; exec {}",
                    shell.program()
                ))
            )),
            Self::PacketCapture { command } => Some(command.clone()),
        }
    }
}

#[derive(Debug)]
enum TerminalControl {
    Input(Vec<u8>),
    Resize {
        columns: u16,
        rows: u16,
    },
    /// Bytes sent as the session ends, ahead of its close even when the close
    /// request overtakes them in the pump.
    FinalInput(Vec<u8>),
}

#[derive(Debug)]
pub struct SshTerminalSession {
    terminal_id: String,
    control: mpsc::Sender<TerminalControl>,
    close: TerminalCloseHandle,
    events: TerminalEventReceiver,
}

impl SshTerminalSession {
    pub fn terminal_id(&self) -> &str {
        &self.terminal_id
    }

    pub fn events(&self) -> &TerminalEventReceiver {
        &self.events
    }

    pub async fn recv(&self) -> CoreResult<TerminalEvent> {
        self.events.recv().await
    }

    pub(crate) fn request_close(&self) {
        self.close.request_close();
    }

    /// Types Ctrl-C into the terminal, then closes it.
    ///
    /// The hangup a channel close may bring is not relied on alone: a command
    /// that writes nothing (tcpdump with no matching traffic) would otherwise
    /// only notice when it next writes, or at its own time limit. The interrupt
    /// reaches the foreground process group through the PTY.
    pub(crate) fn interrupt_and_close(&self) {
        let _ = self
            .control
            .try_send(TerminalControl::FinalInput(vec![0x03]));
        self.close.request_close();
    }

    fn closed_error() -> CoreError {
        CoreError::ssh("terminal control", "terminal is closed")
    }

    async fn send_control(&self, control: TerminalControl) -> CoreResult<()> {
        let mut closed = self.close.subscribe();
        if *closed.borrow() {
            return Err(Self::closed_error());
        }
        tokio::select! {
            biased;
            _ = closed.changed() => Err(Self::closed_error()),
            result = self.control.send(control) => {
                result.map_err(|_| Self::closed_error())
            }
        }
    }
}

impl Drop for SshTerminalSession {
    fn drop(&mut self) {
        self.close.request_close();
    }
}

#[async_trait]
impl TerminalTransport for SshTerminalSession {
    fn events(&self) -> &TerminalEventReceiver {
        &self.events
    }

    async fn write_input(&self, bytes: Vec<u8>) -> CoreResult<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        self.send_control(TerminalControl::Input(bytes)).await
    }

    async fn resize(&self, columns: u16, rows: u16) -> CoreResult<()> {
        if columns == 0 || rows == 0 {
            return Err(CoreError::validation(
                "terminal size",
                "columns and rows must be non-zero",
            ));
        }
        self.send_control(TerminalControl::Resize { columns, rows })
            .await
    }

    async fn close(&self) -> CoreResult<()> {
        self.close.request_close();
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct TerminalCloseHandle {
    close: watch::Sender<bool>,
}

impl TerminalCloseHandle {
    fn request_close(&self) {
        self.close.send_replace(true);
    }

    fn subscribe(&self) -> watch::Receiver<bool> {
        self.close.subscribe()
    }

    fn is_closed(&self) -> bool {
        self.close.is_closed()
    }
}

#[derive(Clone)]
pub struct SshService {
    inner: Arc<SshServiceInner>,
    connections: ConnectionRepository,
}

impl fmt::Debug for SshService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SshService")
            .field("runtime", &"dedicated")
            .finish_non_exhaustive()
    }
}

struct SshServiceInner {
    commands: mpsc::Sender<WorkerCommand>,
    shutdown: watch::Sender<bool>,
    worker: Mutex<Option<thread::JoinHandle<()>>>,
}

impl Drop for SshServiceInner {
    fn drop(&mut self) {
        // This priority channel cannot be starved by a full request queue.
        self.shutdown.send_replace(true);
        if let Ok(worker) = self.worker.get_mut() {
            // Dropping a JoinHandle detaches. Shutdown must never block the UI
            // on a long-running remote command.
            let _ = worker.take();
        }
    }
}

impl SshService {
    pub fn new(store: PortableStore, connections: ConnectionRepository) -> CoreResult<Self> {
        let known_hosts_path = store.root().join("known_hosts");
        let (commands, receiver) = mpsc::channel(SSH_COMMAND_CAPACITY);
        let (shutdown, shutdown_rx) = watch::channel(false);
        let worker = thread::Builder::new()
            .name("lovelyres-ssh".to_owned())
            .spawn(move || run_worker(receiver, shutdown_rx, known_hosts_path))
            .map_err(|source| CoreError::io("start SSH runtime", store.root(), source))?;
        Ok(Self {
            inner: Arc::new(SshServiceInner {
                commands,
                shutdown,
                worker: Mutex::new(Some(worker)),
            }),
            connections,
        })
    }

    pub async fn connect(
        &self,
        connection_id: &str,
        confirmations: HostKeyConfirmations,
    ) -> CoreResult<SshConnectionStatus> {
        self.connect_authorized(connection_id, confirmations.into())
            .await
    }

    pub async fn connect_authorized(
        &self,
        connection_id: &str,
        authorization: SshConnectAuthorization,
    ) -> CoreResult<SshConnectionStatus> {
        let resolved = self.connections.resolve_for_backend(connection_id)?;
        self.connect_resolved(connection_id, resolved, authorization)
            .await
    }

    pub fn prepare_probe(
        &self,
        config: ConnectionConfig,
        changes: ConnectionSecretChanges,
    ) -> CoreResult<ConnectionProbePlan> {
        self.connections.prepare_probe(config, changes)
    }

    pub async fn probe_authorized(
        &self,
        plan: &ConnectionProbePlan,
        authorization: SshConnectAuthorization,
    ) -> CoreResult<SshConnectionProbeSuccess> {
        let confirmed_jump_host_key = authorization.host_keys().jump_host_fingerprint.clone();
        let (reply, response) = oneshot::channel();
        self.send(WorkerCommand::Probe {
            request: Box::new(PendingConnect {
                resolved: plan.resolve_for_backend()?,
                authorization,
            }),
            reply,
        })?;
        let result = receive(response, "test SSH connection").await??;
        let verified_plan = plan.clone().with_verified_host_keys(
            &result.host_key_fingerprint,
            confirmed_jump_host_key.as_deref(),
        )?;
        Ok(SshConnectionProbeSuccess {
            result,
            verified_plan,
        })
    }

    async fn connect_resolved(
        &self,
        connection_id: &str,
        resolved: ResolvedConnection,
        authorization: SshConnectAuthorization,
    ) -> CoreResult<SshConnectionStatus> {
        let expected_host_key_fingerprint = resolved.config.host_key_fingerprint.clone();
        let expected_host = resolved.config.host.clone();
        let expected_port = resolved.config.port;
        let expected_username = resolved.config.username.clone();
        let (reply, response) = oneshot::channel();
        self.send(WorkerCommand::Connect {
            request: Box::new(PendingConnect {
                resolved,
                authorization,
            }),
            reply,
        })?;
        let status = receive(response, "connect").await??;

        self.finalize_connected_status(
            connection_id,
            &expected_host,
            expected_port,
            &expected_username,
            expected_host_key_fingerprint.as_deref(),
            &status,
        )
        .await?;
        Ok(status)
    }

    async fn finalize_connected_status(
        &self,
        connection_id: &str,
        expected_host: &str,
        expected_port: u16,
        expected_username: &str,
        expected_host_key_fingerprint: Option<&str>,
        status: &SshConnectionStatus,
    ) -> CoreResult<()> {
        let persisted = self
            .connections
            .compare_and_set_host_key_fingerprint(
                connection_id,
                expected_host,
                expected_port,
                expected_username,
                expected_host_key_fingerprint,
                &status.host_key_fingerprint,
            )
            .and_then(|_| {
                self.connections
                    .mark_connected(connection_id, status.connected_at)
            });
        if let Err(error) = persisted {
            // The actor already owns a live handle at this point. Never make it
            // unreachable merely because portable metadata could not commit.
            let _ = self.disconnect(&status.session_id).await;
            return Err(error);
        }
        Ok(())
    }

    pub async fn disconnect(&self, session_id: &str) -> CoreResult<()> {
        validate_runtime_id("SSH session id", session_id)?;
        let (reply, response) = oneshot::channel();
        self.send(WorkerCommand::Disconnect {
            session_id: session_id.to_owned(),
            reply,
        })?;
        receive(response, "disconnect").await?
    }

    pub async fn list_sessions(&self) -> CoreResult<Vec<SshConnectionStatus>> {
        let (reply, response) = oneshot::channel();
        self.send(WorkerCommand::ListSessions { reply })?;
        receive(response, "list sessions").await
    }

    /// Mint a guarded session from actor-owned status.
    ///
    /// The domain service that owns the `TargetContext` must validate the guard
    /// before this call and after applying any asynchronous result.
    pub async fn bind_session(
        &self,
        target: TargetGuard,
        session_id: &str,
    ) -> CoreResult<BoundSshSession> {
        validate_runtime_id("SSH session id", session_id)?;
        let status = self
            .list_sessions()
            .await?
            .into_iter()
            .find(|status| status.session_id == session_id)
            .ok_or_else(|| CoreError::NotFound {
                entity: "SSH session",
                id: session_id.to_owned(),
            })?;
        BoundSshSession::from_status(target, &status, "SSH session binding")
    }

    /// Compatibility surface for callers that have not yet adopted target-bound sessions.
    pub async fn execute(
        &self,
        session_id: &str,
        command: String,
        timeout: Duration,
    ) -> CoreResult<SshCommandOutput> {
        self.execute_internal(session_id, None, command, timeout)
            .await
    }

    pub async fn execute_bound(
        &self,
        session: &BoundSshSession,
        command: String,
        timeout: Duration,
    ) -> CoreResult<SshCommandOutput> {
        self.execute_internal(
            session.session_id(),
            Some(session.connection_id().to_owned()),
            command,
            timeout,
        )
        .await
    }

    /// Executes a core-owned command through the same target-bound actor while
    /// keeping command text and both output streams out of ordinary
    /// `SshCommandOutput`, serialization, and debug paths.
    pub(crate) async fn execute_bound_sensitive(
        &self,
        session: &BoundSshSession,
        command: Zeroizing<String>,
        stdin: Zeroizing<Vec<u8>>,
        timeout: Duration,
        limits: SshSensitiveCommandLimits,
    ) -> CoreResult<SshSensitiveCommandOutput> {
        validate_runtime_id("SSH session id", session.session_id())?;
        if command.trim().is_empty() || command.len() > 1024 * 1024 {
            return Err(CoreError::validation(
                "sensitive SSH command",
                "must be non-empty and at most 1 MiB",
            ));
        }
        if stdin.len() > MAX_SENSITIVE_COMMAND_STDIN_BYTES {
            return Err(CoreError::validation(
                "sensitive SSH stdin",
                "must be at most 64 KiB",
            ));
        }
        if timeout.is_zero() || timeout > Duration::from_secs(24 * 60 * 60) {
            return Err(CoreError::validation(
                "sensitive SSH command timeout",
                "must be between one nanosecond and 24 hours",
            ));
        }
        let (reply, response) = oneshot::channel();
        self.send(WorkerCommand::ExecuteSensitive {
            session_id: session.session_id().to_owned(),
            expected_connection_id: session.connection_id().to_owned(),
            command,
            stdin,
            timeout,
            limits,
            reply,
        })?;
        receive(response, "execute sensitive command").await?
    }

    /// Runs only the closed PostgreSQL runtime read over a direct-tcpip channel.
    /// The same actor admission, connection identity and cancellation rules apply.
    pub(crate) async fn read_postgresql_runtime_bound(
        &self,
        session: &BoundSshSession,
        request: NativeRuntimeRequest,
    ) -> CoreResult<NativeRuntimeRead> {
        validate_runtime_id("SSH session id", session.session_id())?;
        let (reply, response) = oneshot::channel();
        self.send(WorkerCommand::PostgresqlRuntime {
            session_id: session.session_id().to_owned(),
            expected_connection_id: session.connection_id().to_owned(),
            request: Box::new(request),
            reply,
        })?;
        receive(response, "PostgreSQL runtime read").await?
    }

    /// Reads the small shell capability view used by the native terminal.
    /// The command is static and the result is bounded by the normal SSH exec
    /// ceiling; no remote value is ever interpolated back into a command.
    pub async fn bash_environment_bound(
        &self,
        session: &BoundSshSession,
    ) -> CoreResult<BashEnvironmentInfo> {
        let output = self
            .execute_bound(
                session,
                bash_environment_probe().to_owned(),
                Duration::from_secs(15),
            )
            .await?;
        if output.exit_code.is_some_and(|code| code != 0) {
            return Err(CoreError::ssh(
                "bash environment",
                format!("remote probe exited with {:?}", output.exit_code),
            ));
        }
        Ok(parse_bash_environment(&output.output))
    }

    /// Mirrors the legacy `get_command_completion` behavior with a typed,
    /// target-bound result. Input is passed as a shell argument through `shq`;
    /// it is never inserted into executable shell syntax.
    pub async fn command_completion_bound(
        &self,
        session: &BoundSshSession,
        input: &str,
        cursor: usize,
    ) -> CoreResult<CommandCompletion> {
        let word = completion_word(input, cursor)?;
        if word.value.is_empty() {
            return Ok(word.empty_result());
        }
        let command = format!(
            "bash -lc 'compgen -c -- \"$1\" 2>/dev/null | LC_ALL=C sort -u | head -{MAX_COMPLETION_CANDIDATES}' lovelyres {}",
            crate::shell_escape::shq(word.value)
        );
        let output = self
            .execute_bound(session, command, Duration::from_secs(15))
            .await?;
        Ok(CommandCompletion {
            candidates: parse_completion_candidates(&output.output, word.value),
            replacement_start: word.start,
            replacement_end: word.end,
        })
    }

    /// Mirrors the legacy `ssh_get_completion` behavior: a conservative local
    /// command catalog for the first word and a quoted remote directory listing
    /// for path/argument completion.
    pub async fn shell_completion_bound(
        &self,
        session: &BoundSshSession,
        input: &str,
        cursor: usize,
    ) -> CoreResult<CommandCompletion> {
        let word = completion_word(input, cursor)?;
        if word.first_word {
            let candidates = COMMON_SHELL_COMMANDS
                .iter()
                .copied()
                .filter(|candidate| candidate.starts_with(word.value))
                .map(str::to_owned)
                .collect();
            return Ok(CommandCompletion {
                candidates,
                replacement_start: word.start,
                replacement_end: word.end,
            });
        }
        let (directory, visible_prefix, filename_prefix) = completion_path_parts(word.value);
        let command = format!(
            "LC_ALL=C ls -1A -- {} 2>/dev/null | head -{MAX_COMPLETION_CANDIDATES}",
            crate::shell_escape::shq(directory)
        );
        let output = self
            .execute_bound(session, command, Duration::from_secs(15))
            .await?;
        let candidates = parse_completion_candidates(&output.output, filename_prefix)
            .into_iter()
            .map(|candidate| format!("{visible_prefix}{candidate}"))
            .collect();
        Ok(CommandCompletion {
            candidates,
            replacement_start: word.start,
            replacement_end: word.end,
        })
    }

    pub(crate) async fn execute_for_connection(
        &self,
        session_id: &str,
        expected_connection_id: &str,
        command: String,
        timeout: Duration,
    ) -> CoreResult<SshCommandOutput> {
        validate_runtime_id("SSH connection id", expected_connection_id)?;
        self.execute_internal(
            session_id,
            Some(expected_connection_id.to_owned()),
            command,
            timeout,
        )
        .await
    }

    async fn execute_internal(
        &self,
        session_id: &str,
        expected_connection_id: Option<String>,
        command: String,
        timeout: Duration,
    ) -> CoreResult<SshCommandOutput> {
        validate_runtime_id("SSH session id", session_id)?;
        if command.trim().is_empty() || command.len() > 1024 * 1024 {
            return Err(CoreError::validation(
                "SSH command",
                "must be non-empty and at most 1 MiB",
            ));
        }
        if timeout.is_zero() || timeout > Duration::from_secs(24 * 60 * 60) {
            return Err(CoreError::validation(
                "SSH command timeout",
                "must be between one nanosecond and 24 hours",
            ));
        }
        let (reply, response) = oneshot::channel();
        self.send(WorkerCommand::Execute {
            session_id: session_id.to_owned(),
            expected_connection_id,
            command,
            timeout,
            reply,
        })?;
        receive(response, "execute command").await?
    }

    /// Compatibility surface for callers that have not yet adopted target-bound sessions.
    pub async fn open_terminal(
        &self,
        session_id: &str,
        terminal_id: String,
        columns: u16,
        rows: u16,
    ) -> CoreResult<SshTerminalSession> {
        self.open_terminal_internal(
            session_id,
            None,
            terminal_id,
            TerminalLaunch::LoginShell,
            columns,
            rows,
        )
        .await
    }

    pub async fn open_terminal_bound(
        &self,
        session: &BoundSshSession,
        terminal_id: String,
        columns: u16,
        rows: u16,
    ) -> CoreResult<SshTerminalSession> {
        self.open_terminal_internal(
            session.session_id(),
            Some(session.connection_id().to_owned()),
            terminal_id,
            TerminalLaunch::LoginShell,
            columns,
            rows,
        )
        .await
    }

    pub(crate) async fn open_directory_terminal_bound(
        &self,
        session: &BoundSshSession,
        terminal_id: String,
        directory: RemotePath,
        columns: u16,
        rows: u16,
    ) -> CoreResult<SshTerminalSession> {
        self.open_terminal_internal(
            session.session_id(),
            Some(session.connection_id().to_owned()),
            terminal_id,
            TerminalLaunch::LoginShellAt { directory },
            columns,
            rows,
        )
        .await
    }

    pub(crate) async fn open_container_terminal_bound(
        &self,
        session: &BoundSshSession,
        request: ContainerPtyRequest,
    ) -> CoreResult<SshTerminalSession> {
        let launch = TerminalLaunch::container_exec(
            request.runtime,
            request.container_id,
            request.shell,
            request.marker,
        )?;
        self.open_terminal_internal(
            session.session_id(),
            Some(session.connection_id().to_owned()),
            request.terminal_id,
            launch,
            request.size.0,
            request.size.1,
        )
        .await
    }

    pub(crate) async fn open_pod_terminal_bound(
        &self,
        session: &BoundSshSession,
        request: PodPtyRequest,
    ) -> CoreResult<SshTerminalSession> {
        let launch = TerminalLaunch::pod_exec(
            request.namespace,
            request.pod,
            request.container,
            request.shell,
            request.marker,
        )?;
        self.open_terminal_internal(
            session.session_id(),
            Some(session.connection_id().to_owned()),
            request.terminal_id,
            launch,
            request.size.0,
            request.size.1,
        )
        .await
    }

    pub(crate) async fn open_packet_capture_bound(
        &self,
        session: &BoundSshSession,
        request: PacketCapturePtyRequest,
    ) -> CoreResult<SshTerminalSession> {
        self.open_terminal_internal(
            session.session_id(),
            Some(session.connection_id().to_owned()),
            request.terminal_id,
            TerminalLaunch::PacketCapture {
                command: request.command,
            },
            120,
            40,
        )
        .await
    }

    async fn open_terminal_internal(
        &self,
        session_id: &str,
        expected_connection_id: Option<String>,
        terminal_id: String,
        launch: TerminalLaunch,
        columns: u16,
        rows: u16,
    ) -> CoreResult<SshTerminalSession> {
        validate_runtime_id("SSH session id", session_id)?;
        validate_runtime_id("terminal id", &terminal_id)?;
        if columns == 0 || rows == 0 {
            return Err(CoreError::validation(
                "terminal size",
                "columns and rows must be non-zero",
            ));
        }
        let (reply, response) = oneshot::channel();
        self.send(WorkerCommand::OpenTerminal {
            session_id: session_id.to_owned(),
            expected_connection_id,
            terminal_id,
            launch,
            columns,
            rows,
            reply,
        })?;
        receive(response, "open terminal").await?
    }

    pub(crate) async fn sftp(
        &self,
        session_id: &str,
        expected_connection_id: &str,
        request: SftpRequest,
    ) -> CoreResult<SftpResponse> {
        validate_runtime_id("SSH session id", session_id)?;
        validate_runtime_id("SSH connection id", expected_connection_id)?;
        let (reply, response) = oneshot::channel();
        self.send(WorkerCommand::Sftp {
            session_id: session_id.to_owned(),
            expected_connection_id: expected_connection_id.to_owned(),
            request: Box::new(request),
            reply,
        })?;
        receive(response, "SFTP request").await?
    }

    fn send(&self, command: WorkerCommand) -> CoreResult<()> {
        self.inner.commands.try_send(command).map_err(|error| {
            let message = match error {
                mpsc::error::TrySendError::Full(_) => "dedicated SSH runtime queue is full",
                mpsc::error::TrySendError::Closed(_) => "dedicated SSH runtime is unavailable",
            };
            CoreError::ssh("runtime", message)
        })
    }

    #[cfg(test)]
    pub(crate) async fn install_test_session(
        &self,
        status: SshConnectionStatus,
        harness: Arc<TestSessionHarness>,
    ) -> CoreResult<()> {
        let (reply, response) = oneshot::channel();
        self.send(WorkerCommand::InstallTestSession {
            status,
            harness,
            reply,
        })?;
        receive(response, "install test SSH session").await
    }
}

async fn receive<T>(response: oneshot::Receiver<T>, operation: &'static str) -> CoreResult<T> {
    response
        .await
        .map_err(|_| CoreError::ssh(operation, "SSH runtime dropped the response"))
}

fn validate_runtime_id(subject: &'static str, value: &str) -> CoreResult<()> {
    if value.trim().is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(CoreError::validation(
            subject,
            "must be non-empty, at most 128 bytes, and contain no control characters",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct CompletionWord<'a> {
    value: &'a str,
    start: usize,
    end: usize,
    first_word: bool,
}

impl CompletionWord<'_> {
    fn empty_result(self) -> CommandCompletion {
        CommandCompletion {
            candidates: Vec::new(),
            replacement_start: self.start,
            replacement_end: self.end,
        }
    }
}

fn completion_word(input: &str, cursor: usize) -> CoreResult<CompletionWord<'_>> {
    if input.len() > MAX_COMPLETION_INPUT_BYTES {
        return Err(CoreError::validation(
            "terminal completion input",
            format!("must be at most {MAX_COMPLETION_INPUT_BYTES} bytes"),
        ));
    }
    if cursor > input.len() || !input.is_char_boundary(cursor) {
        return Err(CoreError::validation(
            "terminal completion cursor",
            "must be a UTF-8 boundary within the input",
        ));
    }
    if input.chars().any(|character| character == '\0') {
        return Err(CoreError::validation(
            "terminal completion input",
            "must not contain NUL",
        ));
    }
    let head = &input[..cursor];
    let start = head
        .char_indices()
        .rev()
        .find(|(_, character)| character.is_whitespace())
        .map_or(0, |(index, character)| index + character.len_utf8());
    Ok(CompletionWord {
        value: &head[start..],
        start,
        end: cursor,
        first_word: head[..start].trim().is_empty(),
    })
}

fn completion_path_parts(word: &str) -> (&str, &str, &str) {
    let Some(slash) = word.rfind('/') else {
        return (".", "", word);
    };
    let directory = if slash == 0 { "/" } else { &word[..slash] };
    let visible_prefix = &word[..=slash];
    let filename_prefix = &word[slash + 1..];
    (directory, visible_prefix, filename_prefix)
}

fn parse_completion_candidates(output: &str, prefix: &str) -> Vec<String> {
    let mut candidates = output
        .lines()
        .filter(|candidate| {
            !candidate.is_empty()
                && candidate.len() <= MAX_COMPLETION_CANDIDATE_BYTES
                && candidate.starts_with(prefix)
                && !candidate.chars().any(char::is_control)
        })
        .take(MAX_COMPLETION_CANDIDATES)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.dedup();
    candidates
}

fn bash_environment_probe() -> &'static str {
    r#"if command -v bash >/dev/null 2>&1; then
bash -lc 'printf "shell=%s\n" "${SHELL:-bash}"; printf "version=%s\n" "${BASH_VERSION:-}"; if type compgen >/dev/null 2>&1; then echo completion=1; else echo completion=0; fi; if type history >/dev/null 2>&1; then echo history=1; else echo history=0; fi'
else
printf 'shell=%s\n' "${SHELL:-sh}"
printf 'version=\ncompletion=0\nhistory=0\n'
fi"#
}

fn parse_bash_environment(output: &str) -> BashEnvironmentInfo {
    let mut environment = BashEnvironmentInfo {
        shell: "sh".to_owned(),
        version: String::new(),
        supports_completion: false,
        supports_history: false,
    };
    for line in output.lines().take(16) {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if value.len() > 4_096 || value.chars().any(char::is_control) {
            continue;
        }
        match key {
            "shell" => environment.shell = value.to_owned(),
            "version" => environment.version = value.to_owned(),
            "completion" => environment.supports_completion = value == "1",
            "history" => environment.supports_history = value == "1",
            _ => {}
        }
    }
    environment
}

struct ConnectRequest {
    connection_id: String,
    host: String,
    port: u16,
    username: String,
    authentication: Authentication,
    expected_host_key_fingerprint: Option<String>,
    jump_host: Option<JumpHostRequest>,
}

struct PendingConnect {
    resolved: ResolvedConnection,
    authorization: SshConnectAuthorization,
}

impl fmt::Debug for PendingConnect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingConnect")
            .field("connection_id", &self.resolved.config.id)
            .field("authorization", &self.authorization)
            .finish()
    }
}

impl fmt::Debug for ConnectRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectRequest")
            .field("connection_id", &self.connection_id)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("authentication", &self.authentication)
            .field(
                "expected_host_key_fingerprint",
                &self.expected_host_key_fingerprint,
            )
            .field("jump_host", &self.jump_host)
            .finish()
    }
}

impl ConnectRequest {
    async fn materialize(
        resolved: ResolvedConnection,
        authorization: SshConnectAuthorization,
    ) -> CoreResult<Self> {
        let SshConnectAuthorization {
            host_keys: confirmations,
            target_keyboard_interactive_responses,
            jump_keyboard_interactive_responses,
        } = authorization;
        let ConnectionConfig {
            id,
            host,
            port,
            username,
            auth_method,
            private_key_path,
            certificate_path,
            agent_identity_fingerprint,
            jump_host,
            host_key_fingerprint,
            ..
        } = resolved.config;
        let expected_host_key_fingerprint = merge_confirmation(
            "target SSH host key confirmation",
            host_key_fingerprint,
            confirmations.target_fingerprint,
        )?;
        let authentication = Authentication::materialize(
            auth_method,
            resolved.password,
            private_key_path,
            resolved.key_passphrase,
            certificate_path,
            agent_identity_fingerprint,
            target_keyboard_interactive_responses,
        )
        .await?;
        let jump_host = match jump_host {
            Some(jump) => Some(
                JumpHostRequest::materialize(
                    jump,
                    resolved.jump_host_password,
                    resolved.jump_host_key_passphrase,
                    confirmations.jump_host_fingerprint,
                    jump_keyboard_interactive_responses,
                )
                .await?,
            ),
            None if confirmations.jump_host_fingerprint.is_some() => {
                return Err(CoreError::validation(
                    "jump SSH host key confirmation",
                    "connection has no jump host",
                ));
            }
            None => None,
        };
        Ok(Self {
            connection_id: id,
            host,
            port,
            username,
            authentication,
            expected_host_key_fingerprint,
            jump_host,
        })
    }
}

struct JumpHostRequest {
    host: String,
    port: u16,
    username: String,
    authentication: Authentication,
    expected_host_key_fingerprint: Option<String>,
}

impl fmt::Debug for JumpHostRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JumpHostRequest")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("authentication", &self.authentication)
            .field(
                "expected_host_key_fingerprint",
                &self.expected_host_key_fingerprint,
            )
            .finish()
    }
}

impl JumpHostRequest {
    async fn materialize(
        config: JumpHostConfig,
        password: Option<SecretValue>,
        private_key_passphrase: Option<SecretValue>,
        confirmation: Option<String>,
        keyboard_interactive_responses: Vec<SecretValue>,
    ) -> CoreResult<Self> {
        let expected_host_key_fingerprint = merge_confirmation(
            "jump SSH host key confirmation",
            config.host_key_fingerprint,
            confirmation,
        )?;
        let authentication = Authentication::materialize(
            config.auth_method,
            password,
            config.private_key_path,
            private_key_passphrase,
            config.certificate_path,
            config.agent_identity_fingerprint,
            keyboard_interactive_responses,
        )
        .await?;
        Ok(Self {
            host: config.host,
            port: config.port,
            username: config.username,
            authentication,
            expected_host_key_fingerprint,
        })
    }
}

fn merge_confirmation(
    subject: &'static str,
    stored: Option<String>,
    supplied: Option<String>,
) -> CoreResult<Option<String>> {
    if let (Some(stored), Some(supplied)) = (&stored, &supplied)
        && stored != supplied
    {
        return Err(CoreError::validation(
            subject,
            "supplied fingerprint differs from the persisted trust record",
        ));
    }
    let fingerprint = stored.or(supplied);
    if let Some(value) = &fingerprint
        && (!value.starts_with("SHA256:")
            || value.len() > 256
            || value.chars().any(char::is_control))
    {
        return Err(CoreError::validation(
            subject,
            "fingerprint must use the SHA256: OpenSSH representation",
        ));
    }
    Ok(fingerprint)
}

struct Authentication {
    method: SshAuthMethod,
    password: Option<SecretValue>,
    private_key: Option<SecretValue>,
    private_key_passphrase: Option<SecretValue>,
    certificate: Option<String>,
    agent_identity_fingerprint: Option<String>,
    keyboard_interactive_responses: Vec<SecretValue>,
}

impl fmt::Debug for Authentication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Authentication")
            .field("method", &self.method)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field(
                "private_key",
                &self.private_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "private_key_passphrase",
                &self.private_key_passphrase.as_ref().map(|_| "[REDACTED]"),
            )
            .field("certificate", &self.certificate.as_ref().map(|_| "present"))
            .field(
                "agent_identity_fingerprint",
                &self.agent_identity_fingerprint,
            )
            .field(
                "keyboard_interactive_response_count",
                &self.keyboard_interactive_responses.len(),
            )
            .finish()
    }
}

impl Authentication {
    async fn materialize(
        method: SshAuthMethod,
        password: Option<SecretValue>,
        private_key_path: Option<PathBuf>,
        private_key_passphrase: Option<SecretValue>,
        certificate_path: Option<PathBuf>,
        agent_identity_fingerprint: Option<String>,
        keyboard_interactive_responses: Vec<SecretValue>,
    ) -> CoreResult<Self> {
        let private_key = match (method, private_key_path) {
            (SshAuthMethod::PublicKey | SshAuthMethod::Certificate, Some(path)) => Some(
                SecretValue::new(read_credential_file("private key", &path).await?),
            ),
            _ => None,
        };
        let certificate = match (method, certificate_path) {
            (SshAuthMethod::Certificate, Some(path)) => {
                Some(read_credential_file("OpenSSH certificate", &path).await?)
            }
            _ => None,
        };
        match method {
            SshAuthMethod::Password if password.is_none() => {
                return Err(CoreError::validation(
                    "SSH password",
                    "password authentication has no stored password",
                ));
            }
            SshAuthMethod::PublicKey if private_key.is_none() => {
                return Err(CoreError::validation(
                    "SSH private key",
                    "public-key authentication requires an absolute key path",
                ));
            }
            SshAuthMethod::Certificate if private_key.is_none() || certificate.is_none() => {
                return Err(CoreError::validation(
                    "SSH certificate",
                    "certificate authentication requires private-key and certificate paths",
                ));
            }
            _ => {}
        }
        Ok(Self {
            method,
            password,
            private_key,
            private_key_passphrase,
            certificate,
            agent_identity_fingerprint,
            keyboard_interactive_responses,
        })
    }
}

async fn read_credential_file(subject: &'static str, path: &Path) -> CoreResult<String> {
    if !path.is_absolute() {
        return Err(CoreError::validation(subject, "path must be absolute"));
    }
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|source| CoreError::io("open credential file", path, source))?;
    let metadata = file
        .metadata()
        .await
        .map_err(|source| CoreError::io("inspect credential file", path, source))?;
    if !metadata.is_file() || metadata.len() > MAX_KEY_BYTES {
        return Err(CoreError::validation(
            subject,
            "must be a regular file no larger than 4 MiB",
        ));
    }
    let mut limited = file.take(MAX_KEY_BYTES + 1);
    let mut bytes = Vec::new();
    limited
        .read_to_end(&mut bytes)
        .await
        .map_err(|source| CoreError::io("read credential file", path, source))?;
    if bytes.len() as u64 > MAX_KEY_BYTES {
        return Err(CoreError::validation(
            subject,
            "file grew beyond the 4 MiB credential limit while it was read",
        ));
    }
    String::from_utf8(bytes).map_err(|error| {
        CoreError::validation(subject, format!("credential file must be UTF-8: {error}"))
    })
}

enum WorkerCommand {
    Connect {
        request: Box<PendingConnect>,
        reply: oneshot::Sender<CoreResult<SshConnectionStatus>>,
    },
    Probe {
        request: Box<PendingConnect>,
        reply: oneshot::Sender<CoreResult<SshConnectionProbeResult>>,
    },
    Disconnect {
        session_id: String,
        reply: oneshot::Sender<CoreResult<()>>,
    },
    ListSessions {
        reply: oneshot::Sender<Vec<SshConnectionStatus>>,
    },
    Execute {
        session_id: String,
        expected_connection_id: Option<String>,
        command: String,
        timeout: Duration,
        reply: oneshot::Sender<CoreResult<SshCommandOutput>>,
    },
    PostgresqlRuntime {
        session_id: String,
        expected_connection_id: String,
        request: Box<NativeRuntimeRequest>,
        reply: oneshot::Sender<CoreResult<NativeRuntimeRead>>,
    },
    ExecuteSensitive {
        session_id: String,
        expected_connection_id: String,
        command: Zeroizing<String>,
        stdin: Zeroizing<Vec<u8>>,
        timeout: Duration,
        limits: SshSensitiveCommandLimits,
        reply: oneshot::Sender<CoreResult<SshSensitiveCommandOutput>>,
    },
    OpenTerminal {
        session_id: String,
        expected_connection_id: Option<String>,
        terminal_id: String,
        launch: TerminalLaunch,
        columns: u16,
        rows: u16,
        reply: oneshot::Sender<CoreResult<SshTerminalSession>>,
    },
    Sftp {
        session_id: String,
        expected_connection_id: String,
        request: Box<SftpRequest>,
        reply: oneshot::Sender<CoreResult<SftpResponse>>,
    },
    #[cfg(test)]
    InstallTestSession {
        status: SshConnectionStatus,
        harness: Arc<TestSessionHarness>,
        reply: oneshot::Sender<()>,
    },
}

#[derive(Debug, Clone)]
struct CancellationSource {
    cancelled: watch::Sender<bool>,
}

#[derive(Debug, Clone)]
struct CancellationToken {
    cancelled: watch::Receiver<bool>,
}

fn cancellation_pair() -> (CancellationSource, CancellationToken) {
    let (cancelled, receiver) = watch::channel(false);
    (
        CancellationSource { cancelled },
        CancellationToken {
            cancelled: receiver,
        },
    )
}

impl CancellationSource {
    fn token(&self) -> CancellationToken {
        CancellationToken {
            cancelled: self.cancelled.subscribe(),
        }
    }

    fn cancel(&self) {
        self.cancelled.send_replace(true);
    }
}

impl CancellationToken {
    fn is_cancelled(&self) -> bool {
        *self.cancelled.borrow()
    }

    async fn cancelled(&mut self) {
        if self.is_cancelled() {
            return;
        }
        loop {
            if self.cancelled.changed().await.is_err() || self.is_cancelled() {
                return;
            }
        }
    }
}

#[derive(Clone)]
enum SessionHandle {
    Real(Arc<Handle<ClientHandler>>),
    #[cfg(test)]
    Test(Arc<TestSessionHarness>),
}

impl fmt::Debug for SessionHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Real(_) => formatter.write_str("SessionHandle::Real(..)"),
            #[cfg(test)]
            Self::Test(_) => formatter.write_str("SessionHandle::Test(..)"),
        }
    }
}

struct SessionData {
    handle: SessionHandle,
    _jump_handle: Option<Arc<Handle<ClientHandler>>>,
    status: SshConnectionStatus,
    cancellation: CancellationSource,
    pending: Arc<Semaphore>,
    execution: Arc<Semaphore>,
    terminals: Arc<Mutex<Vec<TerminalCloseHandle>>>,
}

impl SessionData {
    fn new(
        handle: SessionHandle,
        jump_handle: Option<Arc<Handle<ClientHandler>>>,
        status: SshConnectionStatus,
    ) -> Self {
        let (cancellation, _) = cancellation_pair();
        Self {
            handle,
            _jump_handle: jump_handle,
            status,
            cancellation,
            pending: Arc::new(Semaphore::new(SESSION_OPERATION_CAPACITY)),
            execution: Arc::new(Semaphore::new(SESSION_OPERATION_CONCURRENCY)),
            terminals: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn bind(
        &self,
        expected_connection_id: Option<&str>,
        binding_subject: &'static str,
    ) -> CoreResult<(ActorBoundSession, OwnedSemaphorePermit)> {
        if expected_connection_id.is_some_and(|expected| expected != self.status.connection_id) {
            return Err(CoreError::validation(
                binding_subject,
                "session does not belong to the expected connection",
            ));
        }
        let admission = self
            .pending
            .clone()
            .try_acquire_owned()
            .map_err(|_| CoreError::ssh("runtime", "SSH session operation queue is full"))?;
        Ok((
            ActorBoundSession {
                handle: self.handle.clone(),
                status: self.status.clone(),
                cancellation: self.cancellation.token(),
                execution: self.execution.clone(),
            },
            admission,
        ))
    }

    fn cancel(&self) {
        self.cancellation.cancel();
        if let Ok(mut terminals) = self.terminals.lock() {
            for terminal in terminals.drain(..) {
                terminal.request_close();
            }
        }
    }
}

#[derive(Debug, Clone)]
struct ActorBoundSession {
    handle: SessionHandle,
    status: SshConnectionStatus,
    cancellation: CancellationToken,
    execution: Arc<Semaphore>,
}

enum ActorCompletion {
    Connect {
        reply: oneshot::Sender<CoreResult<SshConnectionStatus>>,
        result: CoreResult<(
            SshConnectionStatus,
            Handle<ClientHandler>,
            Option<Handle<ClientHandler>>,
        )>,
    },
    OpenTerminal {
        session_id: String,
        reply: oneshot::Sender<CoreResult<SshTerminalSession>>,
        result: CoreResult<(SshTerminalSession, TerminalCloseHandle)>,
    },
    Finished,
}

fn run_worker(
    commands: mpsc::Receiver<WorkerCommand>,
    shutdown: watch::Receiver<bool>,
    known_hosts_path: PathBuf,
) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_name("lovelyres-ssh-io")
        .enable_all()
        .build();
    let Ok(runtime) = runtime else {
        return;
    };
    runtime.block_on(router_loop(commands, shutdown, known_hosts_path));
}

async fn router_loop(
    mut commands: mpsc::Receiver<WorkerCommand>,
    mut shutdown: watch::Receiver<bool>,
    known_hosts_path: PathBuf,
) {
    let mut sessions = HashMap::<String, SessionData>::new();
    let mut tasks = JoinSet::<ActorCompletion>::new();
    let connect_pending = Arc::new(Semaphore::new(CONNECT_PENDING_CAPACITY));
    let connect_execution = Arc::new(Semaphore::new(CONNECT_CONCURRENCY));
    let (runtime_cancellation, _) = cancellation_pair();

    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            completion = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Ok(completion)) = completion {
                    apply_completion(completion, &mut sessions, &mut tasks);
                }
            }
            command = commands.recv() => {
                let Some(command) = command else {
                    break;
                };
                match command {
                WorkerCommand::Connect { request, reply } => {
                    if reply.is_closed() {
                        continue;
                    }
                    let Ok(admission) = connect_pending.clone().try_acquire_owned() else {
                        let _ = reply.send(Err(CoreError::ssh(
                            "runtime",
                            "SSH connect queue is full",
                        )));
                        continue;
                    };
                    tasks.spawn(run_connect_task(
                        *request,
                        known_hosts_path.clone(),
                        connect_execution.clone(),
                        admission,
                        runtime_cancellation.token(),
                        reply,
                    ));
                }
                WorkerCommand::Probe { request, reply } => {
                    if reply.is_closed() {
                        continue;
                    }
                    let Ok(admission) = connect_pending.clone().try_acquire_owned() else {
                        let _ = reply.send(Err(CoreError::ssh(
                            "runtime",
                            "SSH connect queue is full",
                        )));
                        continue;
                    };
                    tasks.spawn(run_probe_task(
                        *request,
                        known_hosts_path.clone(),
                        connect_execution.clone(),
                        admission,
                        runtime_cancellation.token(),
                        reply,
                    ));
                }
                WorkerCommand::Disconnect { session_id, reply } => {
                    if let Some(session) = sessions.remove(&session_id) {
                        session.cancel();
                        tasks.spawn(async move {
                            let result = disconnect_handle(session.handle, "LovelyHawk disconnect").await;
                            if !reply.is_closed() {
                                let _ = reply.send(result);
                            }
                            ActorCompletion::Finished
                        });
                    } else {
                        let _ = reply.send(Err(CoreError::NotFound {
                            entity: "SSH session",
                            id: session_id,
                        }));
                    }
                }
                WorkerCommand::ListSessions { reply } => {
                    let mut listed = sessions
                        .values()
                        .map(|session| session.status.clone())
                        .collect::<Vec<_>>();
                    listed.sort_by_key(|left| left.connected_at);
                    let _ = reply.send(listed);
                }
                WorkerCommand::Execute {
                    session_id,
                    expected_connection_id,
                    command,
                    timeout,
                    reply,
                } => {
                    match bind_actor_session(
                        &sessions,
                        &session_id,
                        expected_connection_id.as_deref(),
                        "SSH session binding",
                    ) {
                        Ok((session, admission)) => {
                            tasks.spawn(run_session_response(
                                session,
                                admission,
                                reply,
                                "execute command",
                                timeout.saturating_add(Duration::from_secs(1)),
                                move |handle| execute_on_handle(handle, command, timeout),
                            ));
                        }
                        Err(error) => {
                            let _ = reply.send(Err(error));
                        }
                    }
                }
                WorkerCommand::PostgresqlRuntime { session_id, expected_connection_id, request, reply } => {
                    match bind_actor_session(&sessions, &session_id, Some(&expected_connection_id), "PostgreSQL SSH session binding") {
                        Ok((session, admission)) => {
                            tasks.spawn(run_session_response(session, admission, reply, "PostgreSQL runtime read", NATIVE_READ_TIMEOUT,
                                move |handle| execute_postgresql_runtime_on_handle(handle, *request)));
                        }
                        Err(error) => { let _ = reply.send(Err(error)); }
                    }
                }
                WorkerCommand::ExecuteSensitive {
                    session_id,
                    expected_connection_id,
                    command,
                    stdin,
                    timeout,
                    limits,
                    reply,
                } => {
                    match bind_actor_session(
                        &sessions,
                        &session_id,
                        Some(&expected_connection_id),
                        "sensitive SSH session binding",
                    ) {
                        Ok((session, admission)) => {
                            tasks.spawn(run_session_response(
                                session,
                                admission,
                                reply,
                                "execute sensitive command",
                                timeout.saturating_add(Duration::from_secs(1)),
                                move |handle| {
                                    execute_sensitive_on_handle(
                                        handle, command, stdin, timeout, limits,
                                    )
                                },
                            ));
                        }
                        Err(error) => {
                            let _ = reply.send(Err(error));
                        }
                    }
                }
                WorkerCommand::OpenTerminal {
                    session_id,
                    expected_connection_id,
                    terminal_id,
                    launch,
                    columns,
                    rows,
                    reply,
                } => {
                    match bind_actor_session(
                        &sessions,
                        &session_id,
                        expected_connection_id.as_deref(),
                        "SSH session binding",
                    ) {
                        Ok((session, admission)) => {
                            tasks.spawn(run_open_terminal_task(
                                session,
                                admission,
                                terminal_id,
                                launch,
                                columns,
                                rows,
                                reply,
                            ));
                        }
                        Err(error) => {
                            let _ = reply.send(Err(error));
                        }
                    }
                }
                WorkerCommand::Sftp {
                    session_id,
                    expected_connection_id,
                    request,
                    reply,
                } => {
                    let deadline = if matches!(&*request, SftpRequest::CollectFileEvidence { .. }) {
                        crate::file_evidence::FILE_EVIDENCE_DEADLINE
                    } else {
                        SFTP_OPERATION_TIMEOUT
                    };
                    match bind_actor_session(
                        &sessions,
                        &session_id,
                        Some(&expected_connection_id),
                        "SFTP session binding",
                    ) {
                        Ok((session, admission)) => {
                            tasks.spawn(run_session_response(
                                session,
                                admission,
                                reply,
                                "SFTP request",
                                deadline,
                                move |handle| sftp_on_handle(handle, *request),
                            ));
                        }
                        Err(error) => {
                            let _ = reply.send(Err(error));
                        }
                    }
                }
                #[cfg(test)]
                WorkerCommand::InstallTestSession {
                    status,
                    harness,
                    reply,
                } => {
                    sessions.insert(
                        status.session_id.clone(),
                        SessionData::new(SessionHandle::Test(harness), None, status),
                    );
                    let _ = reply.send(());
                }
                }
            }
        }
    }

    commands.close();
    runtime_cancellation.cancel();
    let mut cleanup = JoinSet::new();
    for (_, session) in sessions.drain() {
        session.cancel();
        cleanup.spawn(disconnect_handle(session.handle, "LovelyHawk shutdown"));
    }
    tasks.abort_all();
    let deadline = tokio::time::sleep(SHUTDOWN_GRACE);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            biased;
            _ = &mut deadline => {
                cleanup.abort_all();
                break;
            }
            result = cleanup.join_next(), if !cleanup.is_empty() => {
                let _ = result;
            }
            else => break,
        }
    }
}

fn bind_actor_session(
    sessions: &HashMap<String, SessionData>,
    session_id: &str,
    expected_connection_id: Option<&str>,
    binding_subject: &'static str,
) -> CoreResult<(ActorBoundSession, OwnedSemaphorePermit)> {
    sessions
        .get(session_id)
        .ok_or_else(|| CoreError::NotFound {
            entity: "SSH session",
            id: session_id.to_owned(),
        })?
        .bind(expected_connection_id, binding_subject)
}

fn apply_completion(
    completion: ActorCompletion,
    sessions: &mut HashMap<String, SessionData>,
    tasks: &mut JoinSet<ActorCompletion>,
) {
    match completion {
        ActorCompletion::Connect { reply, result } => match result {
            Ok((status, target, jump)) => {
                let session_id = status.session_id.clone();
                if sessions.contains_key(&session_id) {
                    let _ = reply.send(Err(CoreError::ssh(
                        "connect",
                        "server returned a duplicate SSH session id",
                    )));
                    tasks.spawn(async move {
                        let _ = disconnect_handle(
                            SessionHandle::Real(Arc::new(target)),
                            "LovelyHawk duplicate session cleanup",
                        )
                        .await;
                        ActorCompletion::Finished
                    });
                    return;
                }
                if reply.send(Ok(status.clone())).is_ok() {
                    sessions.insert(
                        session_id,
                        SessionData::new(
                            SessionHandle::Real(Arc::new(target)),
                            jump.map(Arc::new),
                            status,
                        ),
                    );
                } else {
                    tasks.spawn(async move {
                        let _ = disconnect_handle(
                            SessionHandle::Real(Arc::new(target)),
                            "LovelyHawk abandoned connect cleanup",
                        )
                        .await;
                        ActorCompletion::Finished
                    });
                }
            }
            Err(error) => {
                let _ = reply.send(Err(error));
            }
        },
        ActorCompletion::OpenTerminal {
            session_id,
            reply,
            result,
        } => match result {
            Ok((terminal, close)) if sessions.contains_key(&session_id) => {
                if reply.send(Ok(terminal)).is_ok()
                    && let Some(session) = sessions.get(&session_id)
                    && let Ok(mut terminals) = session.terminals.lock()
                {
                    terminals.retain(|terminal| !terminal.is_closed());
                    terminals.push(close);
                } else {
                    close.request_close();
                }
            }
            Ok((_, close)) => {
                close.request_close();
                let _ = reply.send(Err(CoreError::NotFound {
                    entity: "SSH session",
                    id: session_id,
                }));
            }
            Err(error) => {
                let _ = reply.send(Err(error));
            }
        },
        ActorCompletion::Finished => {}
    }
}

async fn run_connect_task(
    pending: PendingConnect,
    known_hosts_path: PathBuf,
    execution: Arc<Semaphore>,
    _admission: OwnedSemaphorePermit,
    mut cancellation: CancellationToken,
    mut reply: oneshot::Sender<CoreResult<SshConnectionStatus>>,
) -> ActorCompletion {
    let execution = tokio::select! {
        biased;
        _ = cancellation.cancelled() => return ActorCompletion::Finished,
        _ = reply.closed() => return ActorCompletion::Finished,
        permit = execution.acquire_owned() => match permit {
            Ok(permit) => permit,
            Err(_) => return ActorCompletion::Connect {
                reply,
                result: Err(CoreError::ssh("connect", "SSH runtime is shutting down")),
            },
        },
    };
    let operation = async move {
        let request = ConnectRequest::materialize(pending.resolved, pending.authorization).await?;
        connect_worker(request, &known_hosts_path).await
    };
    tokio::pin!(operation);
    let result = tokio::select! {
        biased;
        _ = cancellation.cancelled() => return ActorCompletion::Finished,
        _ = reply.closed() => return ActorCompletion::Finished,
        result = tokio::time::timeout(CONNECT_OPERATION_TIMEOUT, &mut operation) => {
            result.unwrap_or_else(|_| Err(CoreError::ssh("connect", "operation timed out")))
        }
    };
    drop(execution);
    ActorCompletion::Connect { reply, result }
}

async fn run_probe_task(
    pending: PendingConnect,
    known_hosts_path: PathBuf,
    execution: Arc<Semaphore>,
    _admission: OwnedSemaphorePermit,
    mut cancellation: CancellationToken,
    mut reply: oneshot::Sender<CoreResult<SshConnectionProbeResult>>,
) -> ActorCompletion {
    let execution = tokio::select! {
        biased;
        _ = cancellation.cancelled() => return ActorCompletion::Finished,
        _ = reply.closed() => return ActorCompletion::Finished,
        permit = execution.acquire_owned() => match permit {
            Ok(permit) => permit,
            Err(_) => {
                let _ = reply.send(Err(CoreError::ssh(
                    "test SSH connection",
                    "SSH runtime is shutting down",
                )));
                return ActorCompletion::Finished;
            }
        },
    };
    let operation = async move {
        let request = ConnectRequest::materialize(pending.resolved, pending.authorization).await?;
        let (status, target, jump) = connect_worker(request, &known_hosts_path).await?;
        finish_probe_connection(
            status,
            SessionHandle::Real(Arc::new(target)),
            jump.map(|jump| SessionHandle::Real(Arc::new(jump))),
        )
        .await
    };
    tokio::pin!(operation);
    let result = tokio::select! {
        biased;
        _ = cancellation.cancelled() => return ActorCompletion::Finished,
        _ = reply.closed() => return ActorCompletion::Finished,
        result = tokio::time::timeout(CONNECT_OPERATION_TIMEOUT, &mut operation) => {
            result.unwrap_or_else(|_| {
                Err(CoreError::ssh(
                    "test SSH connection",
                    "operation timed out",
                ))
            })
        }
    };
    drop(execution);
    let _ = reply.send(result);
    ActorCompletion::Finished
}

async fn finish_probe_connection(
    status: SshConnectionStatus,
    target: SessionHandle,
    jump: Option<SessionHandle>,
) -> CoreResult<SshConnectionProbeResult> {
    let target_result = disconnect_handle(target, "LovelyHawk connection probe").await;
    let jump_result = match jump {
        Some(jump) => disconnect_handle(jump, "LovelyHawk jump connection probe").await,
        None => Ok(()),
    };
    target_result?;
    jump_result?;
    Ok(SshConnectionProbeResult {
        connection_id: status.connection_id,
        host: status.host,
        port: status.port,
        username: status.username,
        host_key_fingerprint: status.host_key_fingerprint,
        checked_at: Utc::now(),
    })
}

async fn run_session_response<T, F, Fut>(
    session: ActorBoundSession,
    _admission: OwnedSemaphorePermit,
    mut reply: oneshot::Sender<CoreResult<T>>,
    operation: &'static str,
    timeout: Duration,
    make_future: F,
) -> ActorCompletion
where
    T: Send + 'static,
    F: FnOnce(SessionHandle) -> Fut + Send + 'static,
    Fut: Future<Output = CoreResult<T>> + Send,
{
    let mut cancellation = session.cancellation;
    let deadline = tokio::time::Instant::now() + timeout;
    let admission_timeout = tokio::time::sleep_until(deadline);
    tokio::pin!(admission_timeout);
    let execution = tokio::select! {
        biased;
        _ = cancellation.cancelled() => {
            let _ = reply.send(Err(operation_cancelled(&session.status, operation)));
            return ActorCompletion::Finished;
        }
        _ = reply.closed() => return ActorCompletion::Finished,
        _ = &mut admission_timeout => {
            let _ = reply.send(Err(CoreError::ssh(operation, "operation timed out before admission")));
            return ActorCompletion::Finished;
        }
        permit = session.execution.acquire_owned() => match permit {
            Ok(permit) => permit,
            Err(_) => {
                let _ = reply.send(Err(CoreError::ssh(operation, "SSH runtime is shutting down")));
                return ActorCompletion::Finished;
            }
        },
    };
    let result = {
        let future = make_future(session.handle);
        tokio::pin!(future);
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => Err(operation_cancelled(&session.status, operation)),
            _ = reply.closed() => return ActorCompletion::Finished,
            result = tokio::time::timeout_at(deadline, &mut future) => {
                result.unwrap_or_else(|_| Err(CoreError::ssh(operation, "operation timed out")))
            }
        }
    };
    drop(execution);
    let _ = reply.send(result);
    ActorCompletion::Finished
}

async fn run_open_terminal_task(
    session: ActorBoundSession,
    _admission: OwnedSemaphorePermit,
    terminal_id: String,
    launch: TerminalLaunch,
    columns: u16,
    rows: u16,
    mut reply: oneshot::Sender<CoreResult<SshTerminalSession>>,
) -> ActorCompletion {
    let session_id = session.status.session_id.clone();
    let mut cancellation = session.cancellation;
    let execution = tokio::select! {
        biased;
        _ = cancellation.cancelled() => {
            return ActorCompletion::OpenTerminal {
                session_id,
                reply,
                result: Err(operation_cancelled(&session.status, "open terminal")),
            };
        }
        _ = reply.closed() => return ActorCompletion::Finished,
        permit = session.execution.acquire_owned() => match permit {
            Ok(permit) => permit,
            Err(_) => return ActorCompletion::OpenTerminal {
                session_id,
                reply,
                result: Err(CoreError::ssh("open terminal", "SSH runtime is shutting down")),
            },
        },
    };
    let future = open_terminal_on_handle(
        session.handle,
        terminal_id,
        launch,
        columns,
        rows,
        cancellation.clone(),
    );
    tokio::pin!(future);
    let result = tokio::select! {
        biased;
        _ = cancellation.cancelled() => {
            Err(operation_cancelled(&session.status, "open terminal"))
        }
        _ = reply.closed() => return ActorCompletion::Finished,
        result = tokio::time::timeout(OPEN_TERMINAL_TIMEOUT, &mut future) => {
            result.unwrap_or_else(|_| Err(CoreError::ssh("open terminal", "operation timed out")))
        }
    };
    drop(execution);
    ActorCompletion::OpenTerminal {
        session_id,
        reply,
        result,
    }
}

fn operation_cancelled(status: &SshConnectionStatus, operation: &'static str) -> CoreError {
    CoreError::OperationCancelled {
        operation_id: format!("ssh:{}:{operation}", status.session_id),
    }
}

async fn execute_on_handle(
    handle: SessionHandle,
    command: String,
    timeout: Duration,
) -> CoreResult<SshCommandOutput> {
    match handle {
        SessionHandle::Real(handle) => execute_command(&handle, command, timeout).await,
        #[cfg(test)]
        SessionHandle::Test(harness) => harness.execute(command).await,
    }
}

async fn execute_postgresql_runtime_on_handle(
    handle: SessionHandle,
    request: NativeRuntimeRequest,
) -> CoreResult<NativeRuntimeRead> {
    match handle {
        SessionHandle::Real(handle) => {
            let channel = handle
                .channel_open_direct_tcpip(
                    request.host(),
                    u32::from(request.port()),
                    "127.0.0.1",
                    0,
                )
                .await
                .map_err(|_| {
                    CoreError::ssh(
                        "PostgreSQL forwarding",
                        "SSH 未能连接该数据库地址，请核对服务监听与转发权限",
                    )
                })?;
            crate::postgresql_native::read_over_stream(
                channel.into_stream(),
                request,
                |input| async move {
                    use crate::postgresql_process::{
                        MAX_OUTPUT, PostgresqlHostInspection, ProcessUnavailableReason, TIMEOUT,
                    };
                    let payload =
                        Zeroizing::new(serde_json::to_vec(&input).expect("finite process input"));
                    match execute_sensitive_command(
                        &handle,
                        crate::postgresql_process::command(),
                        payload,
                        TIMEOUT,
                        SshSensitiveCommandLimits::new(MAX_OUTPUT, 4096)
                            .expect("finite process output bounds"),
                    )
                    .await
                    {
                        Ok(output) if output.exit_code == Some(0) && output.stderr.is_empty() => {
                            PostgresqlHostInspection::parse(output.stdout, &input)
                        }
                        Ok(output) if output.exit_code == Some(127) => {
                            PostgresqlHostInspection::unavailable(
                                ProcessUnavailableReason::Unsupported,
                            )
                        }
                        Ok(_) => PostgresqlHostInspection::unavailable(
                            ProcessUnavailableReason::InvalidOutput,
                        ),
                        Err(_) => PostgresqlHostInspection::unavailable(
                            ProcessUnavailableReason::TransportUnavailable,
                        ),
                    }
                },
            )
            .await
        }
        #[cfg(test)]
        SessionHandle::Test(_) => Err(CoreError::Unsupported {
            feature: "native PostgreSQL in a command-only SSH fixture",
        }),
    }
}

async fn execute_sensitive_on_handle(
    handle: SessionHandle,
    command: Zeroizing<String>,
    stdin: Zeroizing<Vec<u8>>,
    timeout: Duration,
    limits: SshSensitiveCommandLimits,
) -> CoreResult<SshSensitiveCommandOutput> {
    match handle {
        SessionHandle::Real(handle) => {
            execute_sensitive_command(&handle, command, stdin, timeout, limits).await
        }
        #[cfg(test)]
        SessionHandle::Test(harness) => harness.execute_sensitive(command, stdin, limits).await,
    }
}

async fn sftp_on_handle(handle: SessionHandle, request: SftpRequest) -> CoreResult<SftpResponse> {
    match handle {
        SessionHandle::Real(handle) => sftp_request(&handle, request).await,
        #[cfg(test)]
        SessionHandle::Test(harness) => harness.sftp(request).await,
    }
}

async fn open_terminal_on_handle(
    handle: SessionHandle,
    terminal_id: String,
    launch: TerminalLaunch,
    columns: u16,
    rows: u16,
    cancellation: CancellationToken,
) -> CoreResult<(SshTerminalSession, TerminalCloseHandle)> {
    match handle {
        SessionHandle::Real(handle) => {
            open_terminal(&handle, terminal_id, launch, columns, rows, cancellation).await
        }
        #[cfg(test)]
        SessionHandle::Test(harness) => {
            harness
                .open_terminal(terminal_id, launch, columns, rows, cancellation)
                .await
        }
    }
}

async fn disconnect_handle(handle: SessionHandle, message: &'static str) -> CoreResult<()> {
    let operation = async {
        match handle {
            SessionHandle::Real(handle) => handle
                .disconnect(Disconnect::ByApplication, message, "en")
                .await
                .map_err(|error| CoreError::ssh("disconnect", error.to_string())),
            #[cfg(test)]
            SessionHandle::Test(harness) => harness.disconnect().await,
        }
    };
    tokio::time::timeout(DISCONNECT_TIMEOUT, operation)
        .await
        .unwrap_or_else(|_| Err(CoreError::ssh("disconnect", "operation timed out")))
}

async fn connect_worker(
    request: ConnectRequest,
    known_hosts_path: &Path,
) -> CoreResult<(
    SshConnectionStatus,
    Handle<ClientHandler>,
    Option<Handle<ClientHandler>>,
)> {
    let ConnectRequest {
        connection_id,
        host,
        port,
        username,
        authentication,
        expected_host_key_fingerprint,
        jump_host,
    } = request;
    let (mut target, jump, observed) = if let Some(jump) = jump_host {
        let (mut jump_handle, _) = connect_direct(
            SshHostRole::JumpHost,
            &jump.host,
            jump.port,
            &jump.username,
            jump.expected_host_key_fingerprint.as_deref(),
            known_hosts_path,
        )
        .await?;
        authenticate(
            &mut jump_handle,
            SshHostRole::JumpHost,
            &jump.host,
            jump.port,
            &jump.username,
            &jump.authentication,
        )
        .await?;
        let channel = tokio::time::timeout(
            CONNECT_TIMEOUT,
            jump_handle.channel_open_direct_tcpip(&host, u32::from(port), "127.0.0.1", 0),
        )
        .await
        .map_err(|_| CoreError::ssh("jump tunnel", "direct-tcpip request timed out"))?
        .map_err(|error| CoreError::ssh("jump tunnel", error.to_string()))?;
        let verification = Arc::new(Mutex::new(HostKeyVerification::Pending));
        let handler = ClientHandler::new(
            &host,
            port,
            known_hosts_path.to_path_buf(),
            expected_host_key_fingerprint.clone(),
            Arc::clone(&verification),
        );
        let target = tokio::time::timeout(
            CONNECT_TIMEOUT,
            russh::client::connect_stream(ssh_client_config(), channel.into_stream(), handler),
        )
        .await
        .map_err(|_| CoreError::ssh("connect through jump host", "connection timed out"))?
        .map_err(|error| {
            map_connect_error(
                SshHostRole::Target,
                &host,
                port,
                &username,
                &verification,
                error,
            )
        })?;
        let observed =
            confirmed_fingerprint(SshHostRole::Target, &host, port, &username, &verification)?;
        (target, Some(jump_handle), observed)
    } else {
        let (target, observed) = connect_direct(
            SshHostRole::Target,
            &host,
            port,
            &username,
            expected_host_key_fingerprint.as_deref(),
            known_hosts_path,
        )
        .await?;
        (target, None, observed)
    };
    authenticate(
        &mut target,
        SshHostRole::Target,
        &host,
        port,
        &username,
        &authentication,
    )
    .await?;
    let connected_at = Utc::now();
    let status = SshConnectionStatus {
        session_id: uuid::Uuid::new_v4().to_string(),
        connection_id,
        host,
        port,
        username,
        host_key_fingerprint: observed,
        connected_at,
    };
    Ok((status, target, jump))
}

fn ssh_client_config() -> Arc<Config> {
    Arc::new(Config {
        inactivity_timeout: Some(Duration::from_secs(300)),
        keepalive_interval: Some(Duration::from_secs(30)),
        keepalive_max: 3,
        ..Default::default()
    })
}

async fn connect_direct(
    role: SshHostRole,
    host: &str,
    port: u16,
    username: &str,
    expected: Option<&str>,
    known_hosts_path: &Path,
) -> CoreResult<(Handle<ClientHandler>, String)> {
    let addresses = resolve_ssh_addresses(host, port).await?;
    if addresses.is_empty() {
        return Err(CoreError::ssh(
            "DNS",
            format!("no address found for {host}"),
        ));
    }
    let deadline = tokio::time::Instant::now() + CONNECT_TIMEOUT;
    let mut failures = Vec::new();
    for address in addresses {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let verification = Arc::new(Mutex::new(HostKeyVerification::Pending));
        let handler = ClientHandler::new(
            host,
            port,
            known_hosts_path.to_path_buf(),
            expected.map(str::to_owned),
            Arc::clone(&verification),
        );
        match tokio::time::timeout(
            remaining.min(Duration::from_secs(6)),
            russh::client::connect(ssh_client_config(), address, handler),
        )
        .await
        {
            Ok(Ok(handle)) => {
                return Ok((
                    handle,
                    confirmed_fingerprint(role, host, port, username, &verification)?,
                ));
            }
            Ok(Err(error)) => {
                let mapped = map_connect_error(role, host, port, username, &verification, error);
                if !matches!(
                    verification_state(&verification),
                    HostKeyVerification::Pending
                ) {
                    return Err(mapped);
                }
                failures.push(format!("{address}: {mapped}"));
            }
            Err(_) => failures.push(format!("{address}: timed out")),
        }
    }
    Err(CoreError::ssh(
        "connect",
        format!("all resolved addresses failed: {}", failures.join("; ")),
    ))
}

async fn resolve_ssh_addresses(host: &str, port: u16) -> CoreResult<Vec<std::net::SocketAddr>> {
    let addresses = tokio::time::timeout(DNS_TIMEOUT, tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| CoreError::ssh("DNS", format!("resolution timed out for {host}")))?
        .map_err(|error| CoreError::ssh("DNS", error.to_string()))?
        .collect::<Vec<_>>();
    Ok(addresses)
}

async fn authenticate(
    handle: &mut Handle<ClientHandler>,
    role: SshHostRole,
    host: &str,
    port: u16,
    username: &str,
    authentication: &Authentication,
) -> CoreResult<()> {
    let accepted = match authentication.method {
        SshAuthMethod::Password => {
            let password = authentication.password.as_ref().ok_or_else(|| {
                CoreError::validation("SSH password", "password authentication has no password")
            })?;
            tokio::time::timeout(
                AUTH_TIMEOUT,
                handle.authenticate_password(username, password.expose()),
            )
            .await
            .map_err(|_| CoreError::ssh("password authentication", "timed out"))?
            .map_err(|error| CoreError::ssh("password authentication", error.to_string()))?
        }
        SshAuthMethod::PublicKey | SshAuthMethod::Certificate => {
            let private_key = authentication.private_key.as_ref().ok_or_else(|| {
                CoreError::validation("SSH private key", "private key is unavailable")
            })?;
            let passphrase = authentication
                .private_key_passphrase
                .as_ref()
                .map(SecretValue::expose)
                .filter(|value| !value.is_empty());
            let key = Arc::new(
                russh::keys::decode_secret_key(private_key.expose(), passphrase)
                    .map_err(|error| CoreError::ssh("private-key decoding", error.to_string()))?,
            );
            if authentication.method == SshAuthMethod::Certificate {
                let certificate = authentication.certificate.as_ref().ok_or_else(|| {
                    CoreError::validation("SSH certificate", "certificate is unavailable")
                })?;
                let certificate = Certificate::from_openssh(certificate)
                    .map_err(|error| CoreError::ssh("certificate decoding", error.to_string()))?;
                if certificate.algorithm().is_rsa() {
                    // russh 0.62 names every RSA certificate
                    // `ssh-rsa-cert-v01@openssh.com` whatever hash it signs
                    // with, so the only consistent login is a SHA-1 signature.
                    // OpenSSH before 8.8 (or with that algorithm re-enabled)
                    // accepts it; 8.8+ refuses it, and says so in its log
                    // only. The operator gets the reason here instead of "the
                    // server rejected the credential". Fixed upstream in a
                    // later russh; see docs/SSH_COMPATIBILITY.md.
                    let mut signer = InProcessSigner(key);
                    let result = tokio::time::timeout(
                        AUTH_TIMEOUT,
                        handle.authenticate_certificate_with(
                            username,
                            certificate,
                            None,
                            &mut signer,
                        ),
                    )
                    .await
                    .map_err(|_| CoreError::ssh("certificate authentication", "timed out"))?
                    .map_err(|error| {
                        CoreError::ssh("certificate authentication", error.to_string())
                    })?;
                    if !result.success() {
                        return Err(CoreError::ssh(
                            "RSA certificate authentication",
                            "the server refused an RSA certificate signed with SHA-1 (ssh-rsa-cert-v01). OpenSSH 8.8 and later accept RSA certificates only with SHA-2, which this SSH library cannot send yet; use an Ed25519 or ECDSA certificate, or log in with the RSA private key itself",
                        ));
                    }
                    result
                } else {
                    tokio::time::timeout(
                        AUTH_TIMEOUT,
                        handle.authenticate_openssh_cert(username, key, certificate),
                    )
                    .await
                    .map_err(|_| CoreError::ssh("certificate authentication", "timed out"))?
                    .map_err(|error| {
                        CoreError::ssh("certificate authentication", error.to_string())
                    })?
                }
            } else {
                // RSA keys sign with the hash the server asks for; every other
                // algorithm carries its own and gets exactly one attempt.
                let hashes = if key.algorithm().is_rsa() {
                    rsa_hash_candidates(handle).await
                } else {
                    vec![None]
                };
                let mut outcome = None;
                for hash in hashes {
                    let signing = PrivateKeyWithHashAlg::new(key.clone(), hash);
                    let result = tokio::time::timeout(
                        AUTH_TIMEOUT,
                        handle.authenticate_publickey(username, signing),
                    )
                    .await
                    .map_err(|_| CoreError::ssh("public-key authentication", "timed out"))?
                    .map_err(|error| {
                        CoreError::ssh("public-key authentication", error.to_string())
                    })?;
                    let success = result.success();
                    outcome = Some(result);
                    if success {
                        break;
                    }
                }
                outcome.ok_or_else(|| {
                    CoreError::ssh("public-key authentication", "no signature hash to try")
                })?
            }
        }
        SshAuthMethod::Agent => {
            authenticate_with_agent(
                handle,
                username,
                authentication.agent_identity_fingerprint.as_deref(),
            )
            .await?;
            return Ok(());
        }
        SshAuthMethod::KeyboardInteractive => {
            authenticate_keyboard_interactive(
                handle,
                role,
                host,
                port,
                username,
                &authentication.keyboard_interactive_responses,
            )
            .await?;
            return Ok(());
        }
    };
    accepted
        .success()
        .then_some(())
        .ok_or_else(|| CoreError::ssh("authentication", "server rejected the credential"))
}

async fn authenticate_keyboard_interactive(
    handle: &mut Handle<ClientHandler>,
    role: SshHostRole,
    host: &str,
    port: u16,
    username: &str,
    supplied_responses: &[SecretValue],
) -> CoreResult<()> {
    if supplied_responses.len() > MAX_KEYBOARD_INTERACTIVE_RESPONSES
        || supplied_responses
            .iter()
            .any(|response| response.expose().len() > MAX_KEYBOARD_INTERACTIVE_RESPONSE_BYTES)
        || supplied_responses
            .iter()
            .map(|response| response.expose().len())
            .sum::<usize>()
            > MAX_KEYBOARD_INTERACTIVE_TOTAL_RESPONSE_BYTES
    {
        return Err(CoreError::validation(
            "SSH keyboard-interactive responses",
            "response bounds were exceeded",
        ));
    }

    let mut response = tokio::time::timeout(
        AUTH_TIMEOUT,
        handle.authenticate_keyboard_interactive_start(username, None::<String>),
    )
    .await
    .map_err(|_| CoreError::ssh("keyboard-interactive authentication", "timed out"))?
    .map_err(|error| CoreError::ssh("keyboard-interactive authentication", error.to_string()))?;
    let mut consumed = 0usize;

    for _round in 0..MAX_KEYBOARD_INTERACTIVE_ROUNDS {
        match response {
            KeyboardInteractiveAuthResponse::Success => {
                if consumed != supplied_responses.len() {
                    return Err(CoreError::validation(
                        "SSH keyboard-interactive responses",
                        "server accepted authentication before all supplied responses were consumed",
                    ));
                }
                return Ok(());
            }
            KeyboardInteractiveAuthResponse::Failure {
                remaining_methods,
                partial_success,
            } => {
                return Err(CoreError::ssh(
                    "keyboard-interactive authentication",
                    format!(
                        "server rejected the responses (partial success: {partial_success}; remaining methods: {remaining_methods:?})"
                    ),
                ));
            }
            KeyboardInteractiveAuthResponse::InfoRequest {
                name,
                instructions,
                prompts,
            } => {
                let challenge = keyboard_interactive_challenge(
                    KeyboardInteractiveEndpoint {
                        role,
                        host,
                        port,
                        username,
                    },
                    name,
                    instructions,
                    prompts,
                    consumed,
                )?;
                let end = consumed.saturating_add(challenge.prompts.len());
                if end > supplied_responses.len() {
                    return Err(CoreError::SshKeyboardInteractiveRequired {
                        challenge: Box::new(challenge),
                    });
                }
                let answers = supplied_responses[consumed..end]
                    .iter()
                    .map(|response| response.expose().to_owned())
                    .collect::<Vec<_>>();
                consumed = end;
                response = tokio::time::timeout(
                    AUTH_TIMEOUT,
                    handle.authenticate_keyboard_interactive_respond(answers),
                )
                .await
                .map_err(|_| CoreError::ssh("keyboard-interactive authentication", "timed out"))?
                .map_err(|error| {
                    CoreError::ssh("keyboard-interactive authentication", error.to_string())
                })?;
            }
        }
    }

    Err(CoreError::ssh(
        "keyboard-interactive authentication",
        "server exceeded the eight-round challenge limit",
    ))
}

#[derive(Debug, Clone, Copy)]
struct KeyboardInteractiveEndpoint<'a> {
    role: SshHostRole,
    host: &'a str,
    port: u16,
    username: &'a str,
}

fn keyboard_interactive_challenge(
    endpoint: KeyboardInteractiveEndpoint<'_>,
    name: String,
    instructions: String,
    prompts: Vec<Prompt>,
    supplied_responses: usize,
) -> CoreResult<SshKeyboardInteractiveChallenge> {
    if prompts.len() > MAX_KEYBOARD_INTERACTIVE_PROMPTS {
        return Err(CoreError::validation(
            "SSH keyboard-interactive challenge",
            "a challenge may contain at most 16 prompts",
        ));
    }
    validate_keyboard_interactive_text(
        "SSH keyboard-interactive challenge name",
        &name,
        MAX_KEYBOARD_INTERACTIVE_LABEL_BYTES,
        false,
    )?;
    validate_keyboard_interactive_text(
        "SSH keyboard-interactive instructions",
        &instructions,
        MAX_KEYBOARD_INTERACTIVE_INSTRUCTIONS_BYTES,
        true,
    )?;
    let prompts = prompts
        .into_iter()
        .map(|prompt| {
            validate_keyboard_interactive_text(
                "SSH keyboard-interactive prompt",
                &prompt.prompt,
                MAX_KEYBOARD_INTERACTIVE_LABEL_BYTES,
                false,
            )?;
            Ok(SshKeyboardInteractivePrompt {
                prompt: prompt.prompt,
                echo: prompt.echo,
            })
        })
        .collect::<CoreResult<Vec<_>>>()?;
    Ok(SshKeyboardInteractiveChallenge {
        role: endpoint.role,
        host: endpoint.host.to_owned(),
        port: endpoint.port,
        username: endpoint.username.to_owned(),
        name,
        instructions,
        prompts,
        supplied_responses,
    })
}

fn validate_keyboard_interactive_text(
    subject: &'static str,
    value: &str,
    maximum_bytes: usize,
    multiline: bool,
) -> CoreResult<()> {
    if value.len() > maximum_bytes
        || value
            .chars()
            .any(|character| character.is_control() && !(multiline && "\r\n\t".contains(character)))
    {
        return Err(CoreError::validation(
            subject,
            "server text is too large or contains unsupported control characters",
        ));
    }
    Ok(())
}

/// The signature hashes to try for an RSA identity, best first.
///
/// OpenSSH 8.8+ refuses SHA-1 `ssh-rsa`, so the server's announced
/// `server-sig-algs` decides: rsa-sha2-512/256 when it lists them, SHA-1 only
/// for a server that says that is all it has. A server that announces nothing
/// (OpenSSH 7.2–7.3 accept SHA-2 without saying so; older ones only SHA-1)
/// gets rsa-sha2-256 first and SHA-1 second.
///
/// RSA private keys are signed in this process with RustCrypto `rsa`, which
/// carries RUSTSEC-2023-0071 (a timing side channel, no fixed release). An
/// SSH client signs once per login, over a network, so the many precise
/// timings that attack needs are not available to it; the trade was made so
/// that the RSA keys many hosts are still set up with can log in at all.
/// See docs/SSH_COMPATIBILITY.md.
async fn rsa_hash_candidates(handle: &Handle<ClientHandler>) -> Vec<Option<russh::keys::HashAlg>> {
    use russh::keys::HashAlg;
    match tokio::time::timeout(Duration::from_secs(5), handle.best_supported_rsa_hash()).await {
        Ok(Ok(Some(best))) => vec![best],
        _ => vec![Some(HashAlg::Sha256), None],
    }
}

/// Signs a certificate login with a private key held in this process, with
/// an explicit hash. russh's own certificate login signs RSA with ssh-key's
/// default hash, which does not match the `ssh-rsa-cert-v01` name russh 0.62
/// sends for it; this signer makes the two agree.
struct InProcessSigner(Arc<russh::keys::PrivateKey>);

#[derive(Debug)]
enum InProcessSignError {
    Send,
    Sign(String),
}

impl From<russh::SendError> for InProcessSignError {
    fn from(_: russh::SendError) -> Self {
        Self::Send
    }
}

impl fmt::Display for InProcessSignError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send => formatter.write_str("the SSH session closed during authentication"),
            Self::Sign(message) => write!(formatter, "signing failed: {message}"),
        }
    }
}

impl russh::Signer for InProcessSigner {
    type Error = InProcessSignError;

    fn auth_sign(
        &mut self,
        _identity: &AgentIdentity,
        hash_alg: Option<russh::keys::HashAlg>,
        mut to_sign: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, Self::Error>> + Send {
        let key = PrivateKeyWithHashAlg::new(self.0.clone(), hash_alg);
        async move {
            use russh::keys::signature::Signer as _;
            use russh::keys::ssh_encoding::Encode as _;
            let signature = key
                .try_sign(&to_sign)
                .map_err(|error| InProcessSignError::Sign(error.to_string()))?;
            // The same shape an agent's answer is appended in: the encoded
            // signature (algorithm name, then bytes) as one length-prefixed blob.
            let blob = signature
                .encode_vec()
                .map_err(|error| InProcessSignError::Sign(error.to_string()))?;
            blob.as_slice()
                .encode(&mut to_sign)
                .map_err(|error| InProcessSignError::Sign(error.to_string()))?;
            Ok(to_sign)
        }
    }
}

#[cfg(unix)]
async fn connect_ssh_agent() -> CoreResult<AgentClient<Box<dyn AgentStream + Send + Unpin>>> {
    AgentClient::connect_env()
        .await
        .map(AgentClient::dynamic)
        .map_err(|error| CoreError::ssh("agent connection", error.to_string()))
}

#[cfg(windows)]
async fn connect_ssh_agent() -> CoreResult<AgentClient<Box<dyn AgentStream + Send + Unpin>>> {
    match AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent").await {
        Ok(agent) => Ok(agent.dynamic()),
        Err(open_ssh_error) => AgentClient::connect_pageant()
            .await
            .map(AgentClient::dynamic)
            .map_err(|pageant_error| {
                CoreError::ssh(
                    "agent connection",
                    format!(
                        "Windows OpenSSH agent failed ({open_ssh_error}); Pageant failed ({pageant_error})"
                    ),
                )
            }),
    }
}

async fn authenticate_with_agent(
    handle: &mut Handle<ClientHandler>,
    username: &str,
    requested_fingerprint: Option<&str>,
) -> CoreResult<()> {
    let operation = async {
        let mut agent = connect_ssh_agent().await?;
        let identities = agent
            .request_identities()
            .await
            .map_err(|error| CoreError::ssh("agent identities", error.to_string()))?;
        let mut attempted = 0usize;
        // Asked once, and only if an RSA identity is actually offered.
        let mut rsa_hashes = None;
        for identity in identities {
            let public_key = identity.public_key();
            let fingerprint = fingerprint(&public_key);
            if requested_fingerprint.is_some_and(|requested| requested != fingerprint) {
                continue;
            }
            // The agent signs, so an RSA private key never enters this
            // process; it only needs to be told which hash the server takes.
            let hashes = if matches!(identity, AgentIdentity::Certificate { .. })
                && public_key.algorithm().is_rsa()
            {
                // Same limit as an RSA certificate file: russh can only name
                // it `ssh-rsa-cert-v01`, so only a SHA-1 signature matches.
                vec![None]
            } else if public_key.algorithm().is_rsa() {
                if rsa_hashes.is_none() {
                    rsa_hashes = Some(rsa_hash_candidates(handle).await);
                }
                rsa_hashes.clone().unwrap_or_default()
            } else {
                vec![None]
            };
            attempted += 1;
            for hash in hashes {
                let result = match &identity {
                    AgentIdentity::PublicKey { key, .. } => {
                        handle
                            .authenticate_publickey_with(username, key.clone(), hash, &mut agent)
                            .await
                    }
                    AgentIdentity::Certificate { certificate, .. } => {
                        handle
                            .authenticate_certificate_with(
                                username,
                                certificate.clone(),
                                hash,
                                &mut agent,
                            )
                            .await
                    }
                }
                .map_err(|error| CoreError::ssh("agent authentication", error.to_string()))?;
                if result.success() {
                    return Ok(());
                }
            }
        }
        if attempted == 0 && requested_fingerprint.is_some() {
            Err(CoreError::ssh(
                "agent authentication",
                "the requested identity fingerprint is unavailable",
            ))
        } else {
            Err(CoreError::ssh(
                "agent authentication",
                format!("server rejected {attempted} candidate identities"),
            ))
        }
    };
    tokio::time::timeout(AUTH_TIMEOUT, operation)
        .await
        .map_err(|_| CoreError::ssh("agent authentication", "timed out"))?
}

async fn execute_command(
    handle: &Handle<ClientHandler>,
    command: String,
    timeout: Duration,
) -> CoreResult<SshCommandOutput> {
    let started = std::time::Instant::now();
    let command_for_timeout = command.clone();
    let execution = async {
        let mut channel = handle
            .channel_open_session()
            .await
            .map_err(|error| CoreError::ssh("open command channel", error.to_string()))?;
        channel
            .exec(true, command.as_str())
            .await
            .map_err(|error| CoreError::ssh("execute command", error.to_string()))?;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_code = None;
        while let Some(message) = channel.wait().await {
            if let Err(error) =
                collect_command_message(message, &mut stdout, &mut stderr, &mut exit_code)
            {
                let _ = channel.close().await;
                return Err(error);
            }
        }
        let mut output = String::from_utf8_lossy(&stdout).into_owned();
        if !stderr.is_empty() {
            if !output.is_empty() && !output.ends_with('\n') {
                output.push('\n');
            }
            output.push_str(&String::from_utf8_lossy(&stderr));
        }
        Ok(SshCommandOutput {
            command,
            output,
            exit_code,
            duration_ms: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
            timed_out: false,
        })
    };
    match tokio::time::timeout(timeout, execution).await {
        Ok(result) => result,
        Err(_) => Ok(SshCommandOutput {
            command: command_for_timeout,
            output: "command timed out".to_owned(),
            exit_code: None,
            duration_ms: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
            timed_out: true,
        }),
    }
}

async fn execute_sensitive_command(
    handle: &Handle<ClientHandler>,
    command: Zeroizing<String>,
    stdin: Zeroizing<Vec<u8>>,
    timeout: Duration,
    limits: SshSensitiveCommandLimits,
) -> CoreResult<SshSensitiveCommandOutput> {
    let started = std::time::Instant::now();
    let execution =
        async {
            let channel = handle.channel_open_session().await.map_err(|error| {
                CoreError::ssh("open sensitive command channel", error.to_string())
            })?;
            let mut channel = SensitiveChannelCloseGuard::new(channel);
            channel
                .channel()
                .exec(true, command.as_str())
                .await
                .map_err(|error| CoreError::ssh("execute sensitive command", error.to_string()))?;
            if !stdin.is_empty() {
                channel
                    .channel()
                    .data_bytes(Bytes::from_owner(stdin))
                    .await
                    .map_err(|error| {
                        CoreError::ssh("write sensitive command stdin", error.to_string())
                    })?;
            }
            channel.channel().eof().await.map_err(|error| {
                CoreError::ssh("finish sensitive command stdin", error.to_string())
            })?;
            let mut stdout = Zeroizing::new(Vec::new());
            let mut stderr = Zeroizing::new(Vec::new());
            let mut exit_code = None;
            while let Some(message) = channel.channel().wait().await {
                if let Err(error) = collect_sensitive_command_message(
                    message,
                    &mut stdout,
                    &mut stderr,
                    &mut exit_code,
                    limits,
                ) {
                    let _ = channel.channel().close().await;
                    return Err(error);
                }
            }
            Ok(SshSensitiveCommandOutput {
                stdout,
                stderr,
                exit_code,
                duration_ms: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
            })
        };
    tokio::time::timeout(timeout, execution)
        .await
        .map_err(|_| CoreError::ssh("execute sensitive command", "operation timed out"))?
}

/// russh's plain `Channel` has no Drop cleanup. Keep ownership behind a guard
/// so cancellation, timeout, or a dropped response still emits a best-effort
/// SSH Close instead of leaving the remote client process detached.
struct SensitiveChannelCloseGuard(Option<russh::Channel<Msg>>);

impl SensitiveChannelCloseGuard {
    fn new(channel: russh::Channel<Msg>) -> Self {
        Self(Some(channel))
    }

    fn channel(&mut self) -> &mut russh::Channel<Msg> {
        self.0
            .as_mut()
            .expect("sensitive channel guard always owns its channel")
    }
}

impl Drop for SensitiveChannelCloseGuard {
    fn drop(&mut self) {
        let Some(channel) = self.0.take() else {
            return;
        };
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = channel.close().await;
            });
        }
    }
}

fn collect_sensitive_command_message(
    message: ChannelMsg,
    stdout: &mut Vec<u8>,
    stderr: &mut Vec<u8>,
    exit_code: &mut Option<i32>,
    limits: SshSensitiveCommandLimits,
) -> CoreResult<()> {
    match message {
        ChannelMsg::Data { data } => append_sensitive_output(
            stdout,
            &data,
            limits.stdout_bytes,
            "sensitive command stdout",
        )?,
        ChannelMsg::ExtendedData { data, ext: 1 } => append_sensitive_output(
            stderr,
            &data,
            limits.stderr_bytes,
            "sensitive command stderr",
        )?,
        ChannelMsg::ExtendedData { ext, .. } => {
            return Err(CoreError::ssh(
                "sensitive command extended data",
                format!("unexpected extended-data stream {ext}"),
            ));
        }
        ChannelMsg::ExitStatus { exit_status } => {
            *exit_code = i32::try_from(exit_status).ok();
        }
        _ => {}
    }
    Ok(())
}

fn append_sensitive_output(
    stream: &mut Vec<u8>,
    data: &[u8],
    limit: usize,
    subject: &'static str,
) -> CoreResult<()> {
    let total = stream
        .len()
        .checked_add(data.len())
        .ok_or_else(|| CoreError::ssh(subject, "output length overflow"))?;
    if total > limit {
        return Err(CoreError::ssh(
            subject,
            format!("output exceeded the {limit}-byte limit"),
        ));
    }
    stream.extend_from_slice(data);
    Ok(())
}

fn collect_command_message(
    message: ChannelMsg,
    stdout: &mut Vec<u8>,
    stderr: &mut Vec<u8>,
    exit_code: &mut Option<i32>,
) -> CoreResult<()> {
    match message {
        ChannelMsg::Data { data } => {
            append_bounded_output(stdout, stderr, &data, false, MAX_COMMAND_OUTPUT_BYTES)?
        }
        ChannelMsg::ExtendedData { data, ext: 1 } => {
            append_bounded_output(stdout, stderr, &data, true, MAX_COMMAND_OUTPUT_BYTES)?
        }
        ChannelMsg::ExitStatus { exit_status } => {
            *exit_code = i32::try_from(exit_status).ok();
        }
        _ => {}
    }
    Ok(())
}

fn append_bounded_output(
    stdout: &mut Vec<u8>,
    stderr: &mut Vec<u8>,
    data: &[u8],
    is_stderr: bool,
    limit: usize,
) -> CoreResult<()> {
    let current = stdout
        .len()
        .checked_add(stderr.len())
        .ok_or_else(|| CoreError::ssh("execute command", "output length overflow"))?;
    let total = current
        .checked_add(data.len())
        .ok_or_else(|| CoreError::ssh("execute command", "output length overflow"))?;
    if total > limit {
        return Err(CoreError::ssh(
            "execute command",
            format!("combined stdout/stderr exceeded the {limit}-byte limit"),
        ));
    }
    if is_stderr {
        stderr.extend_from_slice(data);
    } else {
        stdout.extend_from_slice(data);
    }
    Ok(())
}

async fn open_sftp(handle: &Handle<ClientHandler>) -> CoreResult<SftpSession> {
    let channel = handle
        .channel_open_session()
        .await
        .map_err(|error| CoreError::ssh("open SFTP channel", error.to_string()))?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|error| CoreError::ssh("request SFTP subsystem", error.to_string()))?;
    SftpSession::new(channel.into_stream())
        .await
        .map_err(|error| CoreError::ssh(SFTP_HANDSHAKE_OPERATION, error.to_string()))
}

async fn sftp_request(
    handle: &Handle<ClientHandler>,
    request: SftpRequest,
) -> CoreResult<SftpResponse> {
    let sftp = open_sftp(handle).await?;
    match request {
        SftpRequest::Canonicalize { path } => sftp
            .canonicalize(path)
            .await
            .map(SftpResponse::Path)
            .map_err(|error| CoreError::ssh("canonicalize SFTP path", error.to_string())),
        SftpRequest::List {
            path,
            maximum_entries,
        } => {
            let directory = sftp
                .read_dir(path.as_str())
                .await
                .map_err(|error| CoreError::ssh("list SFTP directory", error.to_string()))?;
            let mut entries = Vec::new();
            for entry in directory {
                if entries.len() >= maximum_entries {
                    return Err(CoreError::validation(
                        "SFTP directory",
                        format!("contains more than {maximum_entries} entries"),
                    ));
                }
                entries.push(SftpRawEntry {
                    name: entry.file_name(),
                    path: entry.path(),
                    metadata: raw_metadata(entry.metadata()),
                });
            }
            Ok(SftpResponse::Entries(entries))
        }
        SftpRequest::Metadata {
            path,
            follow_symlink,
        } => {
            let metadata = if follow_symlink {
                sftp.metadata(path).await
            } else {
                sftp.symlink_metadata(path).await
            }
            .map_err(|error| CoreError::ssh("inspect SFTP path", error.to_string()))?;
            Ok(SftpResponse::Metadata(raw_metadata(metadata)))
        }
        SftpRequest::Exists { path } => {
            let exists = sftp
                .try_exists(path.as_str())
                .await
                .map_err(|error| CoreError::ssh("inspect SFTP path", error.to_string()))?
                || sftp.symlink_metadata(path).await.is_ok();
            Ok(SftpResponse::Exists(exists))
        }
        SftpRequest::Read {
            path,
            maximum_bytes,
        } => {
            let metadata = sftp
                .symlink_metadata(path.as_str())
                .await
                .map_err(|error| CoreError::ssh("inspect SFTP file", error.to_string()))?;
            if !metadata.is_regular() || metadata.is_symlink() {
                return Err(CoreError::validation(
                    "SFTP read path",
                    "must be a regular non-symlink file",
                ));
            }
            if metadata.len() > maximum_bytes {
                return Err(CoreError::validation(
                    "SFTP file",
                    format!("exceeds the {maximum_bytes}-byte read limit"),
                ));
            }
            let bytes = read_sftp_bounded(&sftp, &path, maximum_bytes).await?;
            Ok(SftpResponse::Bytes(bytes))
        }
        SftpRequest::WriteNew {
            path,
            content,
            mode,
        } => {
            ensure_sftp_absent(&sftp, &path).await?;
            let mut file = sftp
                .open_with_flags(
                    path.as_str(),
                    OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
                )
                .await
                .map_err(|error| CoreError::ssh("create SFTP file", error.to_string()))?;
            if let Err(error) = file.write_all(&content).await {
                let _ = file.close().await;
                let _ = sftp.remove_file(path.as_str()).await;
                return Err(CoreError::ssh("write SFTP file", error.to_string()));
            }
            if let Some(mode) = mode
                && let Err(error) = file
                    .set_metadata(russh_sftp::protocol::FileAttributes {
                        permissions: Some(mode),
                        ..Default::default()
                    })
                    .await
            {
                let _ = file.close().await;
                let _ = sftp.remove_file(path.as_str()).await;
                return Err(CoreError::ssh(
                    "set new SFTP file permissions",
                    error.to_string(),
                ));
            }
            if let Err(error) = file.sync_all().await {
                let _ = file.close().await;
                let _ = sftp.remove_file(path.as_str()).await;
                return Err(CoreError::ssh("sync SFTP file", error.to_string()));
            }
            if let Err(error) = file.close().await {
                let _ = sftp.remove_file(path.as_str()).await;
                return Err(CoreError::ssh("close SFTP file", error.to_string()));
            }
            Ok(SftpResponse::Transfer {
                bytes: content.len() as u64,
            })
        }
        SftpRequest::UploadNew {
            local_path,
            remote_path,
            maximum_bytes,
            cancel,
        } => {
            if cancel.is_cancelled() {
                return Err(CoreError::validation("SFTP transfer", TRANSFER_CANCELLED));
            }
            ensure_sftp_absent(&sftp, &remote_path).await?;
            let metadata = tokio::fs::metadata(&local_path)
                .await
                .map_err(|source| CoreError::io("inspect staged upload", &local_path, source))?;
            if !metadata.is_file() || metadata.len() > maximum_bytes {
                return Err(CoreError::validation(
                    "staged upload",
                    format!("must be a regular file no larger than {maximum_bytes} bytes"),
                ));
            }
            let mut local = tokio::fs::File::open(&local_path)
                .await
                .map_err(|source| CoreError::io("open staged upload", &local_path, source))?;
            let mut remote = sftp
                .open_with_flags(
                    remote_path.as_str(),
                    OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
                )
                .await
                .map_err(|error| CoreError::ssh("create uploaded file", error.to_string()))?;
            let mut limited = (&mut local).take(maximum_bytes.saturating_add(1));
            let copied = match copy_cancellable(&mut limited, &mut remote, &cancel).await {
                Ok(copied) => copied,
                Err(stop) => {
                    let _ = remote.close().await;
                    let _ = sftp.remove_file(remote_path.as_str()).await;
                    return Err(stop.into_error("upload file"));
                }
            };
            if copied > maximum_bytes {
                let _ = remote.close().await;
                let _ = sftp.remove_file(remote_path.as_str()).await;
                return Err(CoreError::validation(
                    "staged upload",
                    format!("grew beyond the {maximum_bytes}-byte transfer limit while uploading"),
                ));
            }
            if copied != metadata.len() {
                let _ = remote.close().await;
                let _ = sftp.remove_file(remote_path.as_str()).await;
                return Err(CoreError::ssh(
                    "upload file",
                    "copied byte count did not match the staged file",
                ));
            }
            if let Err(error) = remote.sync_all().await {
                let _ = remote.close().await;
                let _ = sftp.remove_file(remote_path.as_str()).await;
                return Err(CoreError::ssh("sync uploaded file", error.to_string()));
            }
            if let Err(error) = remote.close().await {
                let _ = sftp.remove_file(remote_path.as_str()).await;
                return Err(CoreError::ssh("close uploaded file", error.to_string()));
            }
            Ok(SftpResponse::Transfer { bytes: copied })
        }
        SftpRequest::CollectFileEvidence {
            remote_path,
            destination,
            progress,
        } => crate::file_evidence::collect_sftp_file(&sftp, &remote_path, destination, progress)
            .await
            .map(SftpResponse::FileEvidence),
        SftpRequest::DownloadNew {
            remote_path,
            local_path,
            maximum_bytes,
            cancel,
        } => {
            if cancel.is_cancelled() {
                return Err(CoreError::validation("SFTP transfer", TRANSFER_CANCELLED));
            }
            if tokio::fs::try_exists(&local_path)
                .await
                .map_err(|source| CoreError::io("inspect download target", &local_path, source))?
            {
                return Err(CoreError::validation(
                    "download target",
                    "refuses to overwrite an existing local path",
                ));
            }
            let metadata = sftp
                .symlink_metadata(remote_path.as_str())
                .await
                .map_err(|error| CoreError::ssh("inspect download source", error.to_string()))?;
            if !metadata.is_regular() || metadata.is_symlink() || metadata.len() > maximum_bytes {
                return Err(CoreError::validation(
                    "download source",
                    format!("must be a regular file no larger than {maximum_bytes} bytes"),
                ));
            }
            let _parent = local_path.parent().ok_or_else(|| {
                CoreError::validation("download target", "must have a parent directory")
            })?;
            let _file_name = local_path
                .file_name()
                .ok_or_else(|| CoreError::validation("download target", "must have a file name"))?;
            // The file it creates removes itself unless the download finishes,
            // even when this request is dropped half-way.
            download_sftp_file(
                &sftp,
                &remote_path,
                &local_path,
                maximum_bytes,
                metadata.len(),
                &cancel,
            )
            .await
            .map(|bytes| SftpResponse::Transfer { bytes })
        }
        SftpRequest::CreateDirectory { path } => {
            ensure_sftp_absent(&sftp, &path).await?;
            sftp.create_dir(path)
                .await
                .map_err(|error| CoreError::ssh("create SFTP directory", error.to_string()))?;
            Ok(SftpResponse::Unit)
        }
        SftpRequest::Rename {
            from,
            to,
            require_destination_absent,
        } => {
            if require_destination_absent {
                ensure_sftp_absent(&sftp, &to).await?;
            }
            sftp.rename(from, to)
                .await
                .map_err(|error| CoreError::ssh("rename SFTP path", error.to_string()))?;
            Ok(SftpResponse::Unit)
        }
        SftpRequest::MoveToBackup {
            path,
            backup_directory,
            backup_path,
            expected_sha256,
            maximum_bytes,
        } => {
            if let Some(expected_sha256) = expected_sha256 {
                let metadata = sftp
                    .symlink_metadata(path.as_str())
                    .await
                    .map_err(|error| {
                        CoreError::ssh("inspect SFTP remove target", error.to_string())
                    })?;
                if metadata.is_symlink() || !metadata.is_regular() || metadata.len() > maximum_bytes
                {
                    return Err(CoreError::validation(
                        "SFTP remove target",
                        format!(
                            "must be a regular non-symlink file no larger than {maximum_bytes} bytes"
                        ),
                    ));
                }
                let current = read_sftp_bounded(&sftp, &path, maximum_bytes).await?;
                let actual_sha256 = sha256_bytes(&current);
                if actual_sha256 != expected_sha256 {
                    return Err(CoreError::validation(
                        "SFTP remove target",
                        "file content changed after the operation was planned",
                    ));
                }
            }
            let created_directory = match sftp.symlink_metadata(backup_directory.as_str()).await {
                Ok(metadata) if metadata.is_dir() && !metadata.is_symlink() => false,
                Ok(_) => {
                    return Err(CoreError::validation(
                        "SFTP backup namespace",
                        "existing path is not a non-symlink directory",
                    ));
                }
                Err(_) => {
                    sftp.create_dir(backup_directory.as_str())
                        .await
                        .map_err(|error| {
                            CoreError::ssh("create SFTP backup namespace", error.to_string())
                        })?;
                    true
                }
            };
            // Whether or not this call made the directory, it must not be one
            // anybody else can walk into: a directory left open inside a web
            // root is how a removed file stays reachable.
            narrow_sftp_mode(&sftp, backup_directory.as_str(), BACKUP_DIRECTORY_MODE).await;
            let move_result = async {
                ensure_sftp_absent(&sftp, &backup_path).await?;
                sftp.rename(path, backup_path.clone())
                    .await
                    .map_err(|error| CoreError::ssh("move SFTP path to backup", error.to_string()))
            }
            .await;
            if move_result.is_err() && created_directory {
                let _ = sftp.remove_dir(backup_directory.as_str()).await;
            }
            move_result?;
            // The file that was just set aside keeps whatever mode it had —
            // often world-readable, sometimes executable. It is not in service
            // any more and nothing should be able to read or run it.
            narrow_sftp_mode(&sftp, backup_path.as_str(), BACKUP_FILE_MODE).await;
            Ok(SftpResponse::Unit)
        }
        SftpRequest::Remove { path, directory } => {
            let result = if directory {
                sftp.remove_dir(path).await
            } else {
                sftp.remove_file(path).await
            };
            result.map_err(|error| CoreError::ssh("remove SFTP path", error.to_string()))?;
            Ok(SftpResponse::Unit)
        }
        SftpRequest::Chmod { path, mode } => {
            let mut metadata = sftp
                .symlink_metadata(path.as_str())
                .await
                .map_err(|error| CoreError::ssh("inspect SFTP permissions", error.to_string()))?;
            if metadata.is_symlink() {
                return Err(CoreError::validation(
                    "SFTP chmod path",
                    "refuses to chmod a symbolic link",
                ));
            }
            let file_type = metadata.permissions.unwrap_or_default() & !0o7777;
            metadata.size = None;
            metadata.uid = None;
            metadata.gid = None;
            metadata.atime = None;
            metadata.mtime = None;
            metadata.permissions = Some(file_type | mode);
            sftp.set_metadata(path, metadata)
                .await
                .map_err(|error| CoreError::ssh("chmod SFTP path", error.to_string()))?;
            Ok(SftpResponse::Unit)
        }
        SftpRequest::AtomicWrite {
            path,
            backup_directory,
            backup_path,
            content,
            maximum_bytes,
            expected_sha256,
            expected_canonical_path,
        } => atomic_write_sftp(
            &sftp,
            path,
            backup_directory,
            backup_path,
            content,
            maximum_bytes,
            SftpAtomicWriteExpectations {
                sha256: expected_sha256.as_deref(),
                canonical_path: expected_canonical_path.as_deref(),
            },
        )
        .await
        .map(SftpResponse::AtomicWrite),
    }
}

fn raw_metadata(metadata: russh_sftp::client::fs::Metadata) -> SftpRawMetadata {
    SftpRawMetadata {
        size: metadata.len(),
        permissions: metadata.permissions,
        uid: metadata.uid,
        gid: metadata.gid,
        modified_unix_seconds: metadata.mtime,
        is_file: metadata.is_regular(),
        is_directory: metadata.is_dir(),
        is_symlink: metadata.is_symlink(),
    }
}

/// Narrows an existing path's permissions, keeping its file type bits.
///
/// Used on the backup of a removed file, where the mode is half of what makes
/// the removal a removal. Best effort by design: a machine whose SFTP server
/// will not set permissions should still let the operator delete things, and
/// the caller's own verification is what decides whether the removal stands.
async fn narrow_sftp_mode(sftp: &SftpSession, path: &str, mode: u32) -> bool {
    let Ok(mut metadata) = sftp.symlink_metadata(path).await else {
        return false;
    };
    if metadata.is_symlink() {
        return false;
    }
    let file_type = metadata.permissions.unwrap_or_default() & !0o7777;
    metadata.size = None;
    metadata.uid = None;
    metadata.gid = None;
    metadata.atime = None;
    metadata.mtime = None;
    metadata.permissions = Some(file_type | mode);
    sftp.set_metadata(path.to_string(), metadata).await.is_ok()
}

async fn ensure_sftp_absent(sftp: &SftpSession, path: &str) -> CoreResult<()> {
    if sftp
        .try_exists(path)
        .await
        .map_err(|error| CoreError::ssh("inspect SFTP destination", error.to_string()))?
        || sftp.symlink_metadata(path).await.is_ok()
    {
        return Err(CoreError::validation(
            "SFTP destination",
            "path already exists and will not be overwritten",
        ));
    }
    Ok(())
}

async fn read_sftp_bounded(
    sftp: &SftpSession,
    path: &str,
    maximum_bytes: u64,
) -> CoreResult<Vec<u8>> {
    let file = sftp
        .open(path)
        .await
        .map_err(|error| CoreError::ssh("open SFTP file", error.to_string()))?;
    let mut limited = file.take(maximum_bytes.saturating_add(1));
    let mut content = Vec::new();
    limited
        .read_to_end(&mut content)
        .await
        .map_err(|error| CoreError::ssh("read SFTP file", error.to_string()))?;
    if content.len() as u64 > maximum_bytes {
        return Err(CoreError::validation(
            "SFTP file",
            format!("exceeds the {maximum_bytes}-byte read limit"),
        ));
    }
    Ok(content)
}

async fn download_sftp_file(
    sftp: &SftpSession,
    remote_path: &str,
    destination: &Path,
    maximum_bytes: u64,
    expected_bytes: u64,
    cancel: &SftpTransferCancel,
) -> CoreResult<u64> {
    let mut remote = sftp
        .open(remote_path)
        .await
        .map_err(|error| CoreError::ssh("open download source", error.to_string()))?
        .take(maximum_bytes.saturating_add(1));
    let mut options = tokio::fs::OpenOptions::new();
    options.create_new(true).write(true);
    let mut local = options
        .open(destination)
        .await
        .map_err(|source| CoreError::io("create download file", destination, source))?;
    // Only now is the file ours to remove: create_new refused anything that
    // was already there.
    let mut partial = PartialDownload {
        path: destination,
        finished: false,
    };
    let copied = copy_cancellable(&mut remote, &mut local, cancel)
        .await
        .map_err(|stop| match stop {
            CopyStop::Io(source) => CoreError::io("write downloaded file", destination, source),
            stop => stop.into_error("download file"),
        })?;
    if copied > maximum_bytes || copied != expected_bytes {
        return Err(CoreError::ssh(
            "download file",
            "copied byte count did not match bounded remote metadata",
        ));
    }
    local
        .sync_all()
        .await
        .map_err(|source| CoreError::io("sync downloaded file", destination, source))?;
    partial.finished = true;
    Ok(copied)
}

/// A download's own local file, removed unless the download finished —
/// including when the request is dropped half-way because its caller stopped
/// waiting, where no error path would run.
struct PartialDownload<'a> {
    path: &'a Path,
    finished: bool,
}

impl Drop for PartialDownload<'_> {
    fn drop(&mut self) {
        if !self.finished {
            let _ = std::fs::remove_file(self.path);
        }
    }
}

const TRANSFER_CHUNK_BYTES: usize = 256 * 1024;

enum CopyStop {
    Cancelled,
    Io(std::io::Error),
}

impl CopyStop {
    fn into_error(self, operation: &'static str) -> CoreError {
        match self {
            Self::Cancelled => CoreError::validation("SFTP transfer", TRANSFER_CANCELLED),
            Self::Io(error) => CoreError::ssh(operation, error.to_string()),
        }
    }
}

/// Copies like `tokio::io::copy`, but stops as soon as the transfer is
/// cancelled, even while a read or write is waiting on the network.
async fn copy_cancellable<R, W>(
    reader: &mut R,
    writer: &mut W,
    cancel: &SftpTransferCancel,
) -> Result<u64, CopyStop>
where
    R: tokio::io::AsyncRead + Unpin + ?Sized,
    W: tokio::io::AsyncWrite + Unpin + ?Sized,
{
    let mut buffer = vec![0_u8; TRANSFER_CHUNK_BYTES];
    let mut copied = 0_u64;
    loop {
        if cancel.is_cancelled() {
            return Err(CopyStop::Cancelled);
        }
        let read = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(CopyStop::Cancelled),
            read = reader.read(&mut buffer) => read.map_err(CopyStop::Io)?,
        };
        if read == 0 {
            break;
        }
        tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(CopyStop::Cancelled),
            written = writer.write_all(&buffer[..read]) => written.map_err(CopyStop::Io)?,
        }
        copied = copied.saturating_add(read as u64);
    }
    writer.flush().await.map_err(CopyStop::Io)?;
    Ok(copied)
}

struct SftpAtomicWriteExpectations<'a> {
    sha256: Option<&'a str>,
    canonical_path: Option<&'a str>,
}

async fn atomic_write_sftp(
    sftp: &SftpSession,
    path: String,
    backup_directory: String,
    backup_path: String,
    content: Vec<u8>,
    maximum_bytes: u64,
    expected: SftpAtomicWriteExpectations<'_>,
) -> CoreResult<SftpAtomicWriteReceipt> {
    if content.len() as u64 > maximum_bytes {
        return Err(CoreError::validation(
            "SFTP editor content",
            format!("exceeds the {maximum_bytes}-byte edit limit"),
        ));
    }
    ensure_sftp_canonical_path(sftp, &path, expected.canonical_path).await?;
    let metadata = sftp
        .symlink_metadata(path.as_str())
        .await
        .map_err(|error| CoreError::ssh("inspect atomic editor target", error.to_string()))?;
    if metadata.is_symlink() || !metadata.is_regular() || metadata.len() > maximum_bytes {
        return Err(CoreError::validation(
            "SFTP editor target",
            format!("must be a regular non-symlink file no larger than {maximum_bytes} bytes"),
        ));
    }
    if let Some(expected_sha256) = expected.sha256 {
        let current = read_sftp_bounded(sftp, &path, maximum_bytes).await?;
        if sha256_bytes(&current) != expected_sha256 {
            return Err(CoreError::validation(
                "SFTP editor target",
                "file content changed after the operation was planned",
            ));
        }
    }
    match sftp.symlink_metadata(backup_directory.as_str()).await {
        Ok(directory) if directory.is_dir() && !directory.is_symlink() => {}
        Ok(_) => {
            return Err(CoreError::validation(
                "SFTP backup namespace",
                "existing path is not a non-symlink directory",
            ));
        }
        Err(_) => sftp
            .create_dir(backup_directory.as_str())
            .await
            .map_err(|error| CoreError::ssh("create SFTP backup namespace", error.to_string()))?,
    }
    ensure_sftp_absent(sftp, &backup_path).await?;
    let temporary = format!("{path}.lovelyres-tmp-{}", uuid::Uuid::new_v4());
    ensure_sftp_absent(sftp, &temporary).await?;
    let mut temporary_file = sftp
        .open_with_flags(
            temporary.as_str(),
            OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
        )
        .await
        .map_err(|error| {
            CoreError::ssh("create atomic editor temporary file", error.to_string())
        })?;
    if let Err(error) = temporary_file.write_all(&content).await {
        let _ = sftp.remove_file(temporary.as_str()).await;
        return Err(CoreError::ssh(
            "write atomic editor temporary file",
            error.to_string(),
        ));
    }
    let preserved = russh_sftp::protocol::FileAttributes {
        uid: metadata.uid,
        gid: metadata.gid,
        permissions: metadata.permissions,
        ..Default::default()
    };
    if let Err(error) = temporary_file.set_metadata(preserved).await {
        let _ = sftp.remove_file(temporary.as_str()).await;
        return Err(CoreError::ssh(
            "preserve atomic editor metadata",
            error.to_string(),
        ));
    }
    if let Err(error) = temporary_file.sync_all().await {
        let _ = sftp.remove_file(temporary.as_str()).await;
        return Err(CoreError::ssh(
            "sync atomic editor temporary file",
            error.to_string(),
        ));
    }
    if let Err(error) = temporary_file.close().await {
        let _ = sftp.remove_file(temporary.as_str()).await;
        return Err(CoreError::ssh(
            "close atomic editor temporary file",
            error.to_string(),
        ));
    }
    if let Err(error) = ensure_sftp_canonical_path(sftp, &path, expected.canonical_path).await {
        let _ = sftp.remove_file(temporary.as_str()).await;
        return Err(error);
    }
    sftp.rename(path.as_str(), backup_path.as_str())
        .await
        .map_err(|error| CoreError::ssh("create atomic editor backup", error.to_string()))?;
    if let Some(expected_sha256) = expected.sha256 {
        let backup_matches = read_sftp_bounded(sftp, &backup_path, maximum_bytes)
            .await
            .is_ok_and(|bytes| sha256_bytes(&bytes) == expected_sha256);
        if !backup_matches {
            let restore = sftp.rename(backup_path.as_str(), path.as_str()).await;
            let _ = sftp.remove_file(temporary.as_str()).await;
            if restore.is_err() {
                return Ok(partial_atomic_write_receipt(
                    &path,
                    &backup_path,
                    metadata.permissions,
                ));
            }
            return Err(CoreError::validation(
                "SFTP editor target",
                format!(
                    "file content changed before the atomic rename; concurrent bytes were preserved by restore={}",
                    restore.is_ok()
                ),
            ));
        }
    }
    if let Err(error) = ensure_sftp_absent(sftp, &path).await {
        let restore = sftp.rename(backup_path.as_str(), path.as_str()).await;
        let _ = sftp.remove_file(temporary.as_str()).await;
        if restore.is_err() {
            return Ok(partial_atomic_write_receipt(
                &path,
                &backup_path,
                metadata.permissions,
            ));
        }
        return Err(CoreError::validation(
            "SFTP editor target",
            format!(
                "destination was recreated during atomic replacement: {error}; concurrent bytes restore {}",
                if restore.is_ok() {
                    "succeeded"
                } else {
                    "failed"
                }
            ),
        ));
    }
    if let Err(error) = sftp.rename(temporary.as_str(), path.as_str()).await {
        let restore = sftp.rename(backup_path.as_str(), path.as_str()).await;
        let _ = sftp.remove_file(temporary.as_str()).await;
        if restore.is_err() {
            return Ok(partial_atomic_write_receipt(
                &path,
                &backup_path,
                metadata.permissions,
            ));
        }
        return Err(CoreError::ssh(
            "install atomic editor file",
            format!(
                "{error}; original restore {}",
                if restore.is_ok() {
                    "succeeded"
                } else {
                    "failed"
                }
            ),
        ));
    }
    if let Err(error) = ensure_sftp_canonical_path(sftp, &path, expected.canonical_path).await {
        let _ = sftp.remove_file(path.as_str()).await;
        let restore = sftp.rename(backup_path.as_str(), path.as_str()).await;
        if restore.is_err() {
            return Ok(partial_atomic_write_receipt(
                &path,
                &backup_path,
                metadata.permissions,
            ));
        }
        return Err(CoreError::validation(
            "SFTP editor target",
            format!(
                "canonical path changed during atomic replacement: {error}; original restore {}",
                if restore.is_ok() {
                    "succeeded"
                } else {
                    "failed"
                }
            ),
        ));
    }
    let verified = read_sftp_bounded(sftp, &path, maximum_bytes).await;
    if !matches!(verified, Ok(ref bytes) if bytes == &content) {
        let _ = sftp.remove_file(path.as_str()).await;
        let restore = sftp.rename(backup_path.as_str(), path.as_str()).await;
        if restore.is_err() {
            return Ok(partial_atomic_write_receipt(
                &path,
                &backup_path,
                metadata.permissions,
            ));
        }
        return Err(CoreError::ssh(
            "verify atomic editor file",
            format!(
                "read-back mismatch; original restore {}",
                if restore.is_ok() {
                    "succeeded"
                } else {
                    "failed"
                }
            ),
        ));
    }
    Ok(SftpAtomicWriteReceipt {
        path,
        backup_path,
        bytes_written: content.len() as u64,
        previous_permissions: metadata.permissions,
        installed: true,
    })
}

fn partial_atomic_write_receipt(
    path: &str,
    backup_path: &str,
    previous_permissions: Option<u32>,
) -> SftpAtomicWriteReceipt {
    SftpAtomicWriteReceipt {
        path: path.to_owned(),
        backup_path: backup_path.to_owned(),
        bytes_written: 0,
        previous_permissions,
        installed: false,
    }
}

async fn ensure_sftp_canonical_path(
    sftp: &SftpSession,
    path: &str,
    expected: Option<&str>,
) -> CoreResult<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let canonical = sftp
        .canonicalize(path)
        .await
        .map_err(|error| CoreError::ssh("canonicalize atomic editor target", error.to_string()))?;
    if canonical != expected {
        return Err(CoreError::validation(
            "SFTP editor target",
            "canonical path changed after the operation was planned",
        ));
    }
    Ok(())
}

async fn open_terminal(
    handle: &Handle<ClientHandler>,
    terminal_id: String,
    launch: TerminalLaunch,
    columns: u16,
    rows: u16,
    cancellation: CancellationToken,
) -> CoreResult<(SshTerminalSession, TerminalCloseHandle)> {
    let channel = handle
        .channel_open_session()
        .await
        .map_err(|error| CoreError::ssh("open terminal channel", error.to_string()))?;
    channel
        .request_pty(
            true,
            "xterm-256color",
            u32::from(columns),
            u32::from(rows),
            0,
            0,
            &[],
        )
        .await
        .map_err(|error| CoreError::ssh("request PTY", error.to_string()))?;
    if let Some(command) = launch.exec_command() {
        channel
            .exec(true, command.into_bytes())
            .await
            .map_err(|error| CoreError::ssh("request PTY exec", error.to_string()))?;
    } else {
        channel
            .request_shell(true)
            .await
            .map_err(|error| CoreError::ssh("request shell", error.to_string()))?;
    }
    let (events_tx, events) = terminal_event_channel(EventChannelDefaults::default().terminal)?;
    let (control, control_rx) = mpsc::channel(TERMINAL_CONTROL_CAPACITY);
    let (close, close_rx) = watch::channel(false);
    let close = TerminalCloseHandle { close };
    tokio::spawn(terminal_pump(
        terminal_id.clone(),
        channel,
        control_rx,
        close_rx,
        cancellation,
        events_tx,
    ));
    Ok((
        SshTerminalSession {
            terminal_id,
            control,
            close: close.clone(),
            events,
        },
        close,
    ))
}

async fn terminal_pump(
    terminal_id: String,
    mut channel: russh::Channel<Msg>,
    mut controls: mpsc::Receiver<TerminalControl>,
    mut close: watch::Receiver<bool>,
    mut cancellation: CancellationToken,
    events: TerminalEventSender,
) {
    let mut sequence = 0_u64;
    let mut emitted_exit = false;
    let mut eof_seen = false;
    'pump: loop {
        tokio::select! {
            biased;
            changed = close.changed() => {
                if changed.is_err() || *close.borrow() {
                    break;
                }
            }
            _ = cancellation.cancelled() => break,
            control = controls.recv() => {
                let Some(control) = control else {
                    break;
                };
                let result = match control {
                    TerminalControl::Input(input) => {
                        let operation = channel.data(input.as_slice());
                        tokio::pin!(operation);
                        tokio::select! {
                            biased;
                            _ = close.changed() => break 'pump,
                            _ = cancellation.cancelled() => break 'pump,
                            result = &mut operation => result,
                        }
                    }
                    TerminalControl::FinalInput(input) => {
                        let _ = tokio::time::timeout(
                            Duration::from_secs(2),
                            channel.data(input.as_slice()),
                        )
                        .await;
                        break 'pump;
                    }
                    TerminalControl::Resize { columns, rows } => {
                        let operation = channel.window_change(
                            u32::from(columns),
                            u32::from(rows),
                            0,
                            0,
                        );
                        tokio::pin!(operation);
                        tokio::select! {
                            biased;
                            _ = close.changed() => break 'pump,
                            _ = cancellation.cancelled() => break 'pump,
                            result = &mut operation => result,
                        }
                    }
                };
                if let Err(error) = result {
                    sequence = sequence.saturating_add(1);
                    let _ = send_terminal_event_interruptibly(
                        &events,
                        TerminalEvent {
                            session_id: terminal_id.clone(),
                            sequence,
                            kind: TerminalEventKind::Failed { message: error.to_string() },
                        },
                        &mut close,
                        &mut cancellation,
                    ).await;
                    break;
                }
            }
            message = channel.wait() => {
                let kind = match message {
                    Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                        Some(TerminalEventKind::Output(data.to_vec()))
                    }
                    Some(ChannelMsg::ExitStatus { exit_status }) => {
                        emitted_exit = true;
                        Some(TerminalEventKind::Exited {
                            exit_code: i32::try_from(exit_status).ok(),
                        })
                    }
                    // OpenSSH sends EOF before the exit status. Stopping at the
                    // EOF lost the status, so a command that failed (tcpdump
                    // refusing its filter) read as one that ended normally.
                    Some(ChannelMsg::Eof) if !emitted_exit => {
                        eof_seen = true;
                        None
                    }
                    Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => break,
                    _ => None,
                };
                if let Some(kind) = kind {
                    sequence = sequence.saturating_add(1);
                    if !send_terminal_event_interruptibly(
                        &events,
                        TerminalEvent {
                            session_id: terminal_id.clone(),
                            sequence,
                            kind,
                        },
                        &mut close,
                        &mut cancellation,
                    ).await {
                        break;
                    }
                }
                // Both halves of the end have arrived; the close adds nothing.
                if eof_seen && emitted_exit {
                    break;
                }
            }
        }
    }
    // Final bytes still queued when a close request won the race above go out
    // first: the SSH channel keeps them in order ahead of its EOF and close.
    let final_input =
        std::iter::from_fn(|| controls.try_recv().ok()).find_map(|control| match control {
            TerminalControl::FinalInput(bytes) => Some(bytes),
            TerminalControl::Input(_) | TerminalControl::Resize { .. } => None,
        });
    let _ = tokio::time::timeout(Duration::from_millis(250), async {
        if let Some(bytes) = &final_input {
            let _ = channel.data(bytes.as_slice()).await;
        }
        let _ = channel.eof().await;
        let _ = channel.close().await;
    })
    .await;
    if !emitted_exit {
        sequence = sequence.saturating_add(1);
        let _ = events.try_send(TerminalEvent {
            session_id: terminal_id,
            sequence,
            kind: TerminalEventKind::Exited { exit_code: None },
        });
    }
    events.close();
}

async fn send_terminal_event_interruptibly(
    events: &TerminalEventSender,
    event: TerminalEvent,
    close: &mut watch::Receiver<bool>,
    cancellation: &mut CancellationToken,
) -> bool {
    if *close.borrow() || cancellation.is_cancelled() {
        return false;
    }
    tokio::select! {
        biased;
        _ = close.changed() => false,
        _ = cancellation.cancelled() => false,
        result = events.send(event) => result.is_ok(),
    }
}

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
            host: host.to_owned(),
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
        let verification = verify_or_learn_host_key(
            &self.host,
            self.port,
            server_public_key,
            &self.known_hosts_path,
            self.expected_host_key_fingerprint.as_deref(),
        );
        let accepted = matches!(
            verification,
            HostKeyVerification::Trusted { .. } | HostKeyVerification::Learned { .. }
        );
        match self.verification.lock() {
            Ok(mut state) => *state = verification,
            Err(poisoned) => *poisoned.into_inner() = verification,
        }
        Ok(accepted)
    }
}

fn verify_or_learn_host_key(
    host: &str,
    port: u16,
    public_key: &PublicKey,
    known_hosts_path: &Path,
    expected: Option<&str>,
) -> HostKeyVerification {
    let observed = fingerprint(public_key);
    let lock = KNOWN_HOSTS_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = match lock.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let known = russh::keys::check_known_hosts_path(host, port, public_key, known_hosts_path);
    if let Some(expected) = expected {
        if expected != observed {
            return HostKeyVerification::Mismatch {
                expected: expected.to_owned(),
                observed,
            };
        }
        return match known {
            Ok(false) => match russh::keys::known_hosts::learn_known_hosts_path(
                host,
                port,
                public_key,
                known_hosts_path,
            )
            .map_err(|error| error.to_string())
            .and_then(|_| set_known_hosts_permissions(known_hosts_path))
            {
                Ok(()) => HostKeyVerification::Learned {
                    fingerprint: observed,
                },
                Err(error) => HostKeyVerification::Error(error),
            },
            Ok(true) | Err(russh::keys::Error::KeyChanged { .. }) => HostKeyVerification::Trusted {
                fingerprint: observed,
            },
            Err(error) => HostKeyVerification::Error(error.to_string()),
        };
    }
    match known {
        Ok(true) => HostKeyVerification::Trusted {
            fingerprint: observed,
        },
        Ok(false) => HostKeyVerification::Unknown {
            fingerprint: observed,
        },
        Err(russh::keys::Error::KeyChanged { .. }) => {
            let expected =
                russh::keys::known_hosts::known_host_keys_path(host, port, known_hosts_path)
                    .ok()
                    .and_then(|keys| keys.first().map(|(_, key)| fingerprint(key)))
                    .unwrap_or_else(|| "unknown".to_owned());
            HostKeyVerification::Mismatch { expected, observed }
        }
        Err(error) => HostKeyVerification::Error(error.to_string()),
    }
}

fn set_known_hosts_permissions(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn fingerprint(public_key: &PublicKey) -> String {
    public_key
        .fingerprint(russh::keys::HashAlg::Sha256)
        .to_string()
}

fn verification_state(state: &Arc<Mutex<HostKeyVerification>>) -> HostKeyVerification {
    match state.lock() {
        Ok(state) => state.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}

fn confirmed_fingerprint(
    role: SshHostRole,
    host: &str,
    port: u16,
    username: &str,
    verification: &Arc<Mutex<HostKeyVerification>>,
) -> CoreResult<String> {
    match verification_state(verification) {
        HostKeyVerification::Trusted { fingerprint }
        | HostKeyVerification::Learned { fingerprint } => Ok(fingerprint),
        HostKeyVerification::Unknown { fingerprint } => {
            Err(CoreError::SshHostKeyConfirmationRequired {
                role,
                host: host.to_owned(),
                port,
                username: username.to_owned(),
                fingerprint,
            })
        }
        HostKeyVerification::Mismatch { expected, observed } => Err(CoreError::SshHostKeyChanged {
            role,
            host: host.to_owned(),
            port,
            expected,
            observed,
        }),
        HostKeyVerification::Error(message) => {
            Err(CoreError::ssh("host-key verification", message))
        }
        HostKeyVerification::Pending => Err(CoreError::ssh(
            "host-key verification",
            "server did not provide a verifiable host key",
        )),
    }
}

fn map_connect_error(
    role: SshHostRole,
    host: &str,
    port: u16,
    username: &str,
    verification: &Arc<Mutex<HostKeyVerification>>,
    error: russh::Error,
) -> CoreError {
    match confirmed_fingerprint(role, host, port, username, verification) {
        Err(CoreError::SshHostKeyConfirmationRequired { fingerprint, .. }) => {
            CoreError::SshHostKeyConfirmationRequired {
                role,
                host: host.to_owned(),
                port,
                username: username.to_owned(),
                fingerprint,
            }
        }
        Err(CoreError::SshHostKeyChanged {
            expected, observed, ..
        }) => CoreError::SshHostKeyChanged {
            role,
            host: host.to_owned(),
            port,
            expected,
            observed,
        },
        Err(CoreError::Ssh { message, .. }) => {
            // A still-pending verification means the host-key callback never
            // ran, so the transport error is the real cause. Reporting a host
            // key problem instead sends the operator after the wrong thing.
            if matches!(
                verification_state(verification),
                HostKeyVerification::Pending
            ) {
                CoreError::ssh("connect", error.to_string())
            } else {
                CoreError::ssh("connect", message)
            }
        }
        _ => CoreError::ssh("connect", error.to_string()),
    }
}

#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct TestSessionHarness {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
    entered_count: std::sync::atomic::AtomicUsize,
    cancelled_count: std::sync::atomic::AtomicUsize,
    disconnected: std::sync::atomic::AtomicBool,
    execute_output: Mutex<Option<String>>,
    execute_outputs: Mutex<std::collections::VecDeque<String>>,
    execute_commands: Mutex<Vec<String>>,
    sftp_immediate: std::sync::atomic::AtomicBool,
    sftp_files: Mutex<HashMap<String, Vec<u8>>>,
    sftp_modes: Mutex<HashMap<String, u32>>,
    sftp_directories: Mutex<std::collections::HashSet<String>>,
    sftp_symlinks: Mutex<std::collections::HashSet<String>>,
    sftp_list_count: std::sync::atomic::AtomicUsize,
    terminal_launches: Mutex<Vec<String>>,
    terminal_closed: Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(test)]
impl TestSessionHarness {
    pub(crate) fn execute_commands(&self) -> Vec<String> {
        self.execute_commands
            .lock()
            .expect("test command log")
            .clone()
    }

    pub(crate) fn set_execute_output(&self, output: impl Into<String>) {
        *self
            .execute_output
            .lock()
            .expect("test execute output lock") = Some(output.into());
    }

    pub(crate) fn set_execute_outputs(&self, outputs: impl IntoIterator<Item = impl Into<String>>) {
        *self
            .execute_outputs
            .lock()
            .expect("test execute outputs lock") = outputs.into_iter().map(Into::into).collect();
    }

    pub(crate) fn set_sftp_immediate(&self, immediate: bool) {
        self.sftp_immediate
            .store(immediate, std::sync::atomic::Ordering::SeqCst);
    }

    pub(crate) fn set_sftp_file(&self, path: impl Into<String>, content: impl Into<Vec<u8>>) {
        let path = path.into();
        self.sftp_directories
            .lock()
            .expect("test SFTP directories lock")
            .remove(&path);
        self.sftp_symlinks
            .lock()
            .expect("test SFTP symlinks lock")
            .remove(&path);
        self.sftp_files
            .lock()
            .expect("test SFTP files lock")
            .insert(path.clone(), content.into());
        self.sftp_modes
            .lock()
            .expect("test SFTP modes lock")
            .entry(path)
            .or_insert(0o600);
    }

    pub(crate) fn set_sftp_mode(&self, path: impl Into<String>, mode: u32) {
        self.sftp_modes
            .lock()
            .expect("test SFTP modes lock")
            .insert(path.into(), mode);
    }

    pub(crate) fn set_sftp_directory(&self, path: impl Into<String>) {
        let path = path.into();
        self.sftp_files
            .lock()
            .expect("test SFTP files lock")
            .remove(&path);
        self.sftp_symlinks
            .lock()
            .expect("test SFTP symlinks lock")
            .remove(&path);
        self.sftp_modes
            .lock()
            .expect("test SFTP modes lock")
            .insert(path.clone(), 0o755);
        self.sftp_directories
            .lock()
            .expect("test SFTP directories lock")
            .insert(path);
    }

    pub(crate) fn set_sftp_symlink(&self, path: impl Into<String>) {
        let path = path.into();
        self.sftp_files
            .lock()
            .expect("test SFTP files lock")
            .remove(&path);
        self.sftp_directories
            .lock()
            .expect("test SFTP directories lock")
            .remove(&path);
        self.sftp_symlinks
            .lock()
            .expect("test SFTP symlinks lock")
            .insert(path);
    }

    pub(crate) fn sftp_list_count(&self) -> usize {
        self.sftp_list_count
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    pub(crate) fn sftp_mode(&self, path: &str) -> Option<u32> {
        self.sftp_modes
            .lock()
            .expect("test SFTP modes lock")
            .get(path)
            .copied()
    }

    /// Every file path the machine currently holds, sorted.
    ///
    /// Lets a test go looking for something whose name it cannot predict — a
    /// backup, for instance, which is named after a fresh identifier.
    pub(crate) fn sftp_file(&self, path: &str) -> Option<Vec<u8>> {
        self.sftp_files
            .lock()
            .expect("test SFTP files lock")
            .get(path)
            .cloned()
    }

    pub(crate) fn sftp_paths(&self) -> Vec<String> {
        let mut paths: Vec<String> = self
            .sftp_files
            .lock()
            .expect("test SFTP files lock")
            .keys()
            .cloned()
            .collect();
        paths.sort();
        paths
    }

    pub(crate) fn terminal_launches(&self) -> Vec<String> {
        self.terminal_launches
            .lock()
            .expect("test terminal launches lock")
            .clone()
    }

    pub(crate) fn terminal_closed(&self) -> bool {
        self.terminal_closed
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    async fn hold_operation(&self) {
        let mut guard = TestOperationGuard {
            harness: self,
            completed: false,
        };
        // Subscribe before announcing arrival. notify_waiters only wakes tasks
        // that are already waiting, so a release landing between the two would
        // strand this operation and make every test using the harness flaky.
        let mut released = Box::pin(self.release.notified());
        released.as_mut().enable();
        self.entered_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.entered.notify_waiters();
        released.await;
        guard.completed = true;
    }

    pub(crate) async fn wait_for_entered(&self, expected: usize) {
        while self.entered_count.load(std::sync::atomic::Ordering::SeqCst) < expected {
            let notified = self.entered.notified();
            if self.entered_count.load(std::sync::atomic::Ordering::SeqCst) >= expected {
                break;
            }
            notified.await;
        }
    }

    pub(crate) fn release_operations(&self) {
        self.release.notify_waiters();
    }

    async fn execute(&self, command: String) -> CoreResult<SshCommandOutput> {
        self.execute_commands
            .lock()
            .expect("test command log")
            .push(command.clone());
        let started = std::time::Instant::now();
        if let Some(output) = self
            .execute_outputs
            .lock()
            .expect("test execute outputs lock")
            .pop_front()
        {
            // A scripted output may start with `<exit N>` to end with status N.
            let (output, exit_code) = output
                .strip_prefix("<exit ")
                .and_then(|rest| rest.split_once('>'))
                .and_then(|(code, rest)| Some((rest.to_owned(), code.parse::<i32>().ok()?)))
                .unwrap_or((output, 0));
            return Ok(SshCommandOutput {
                command,
                output,
                exit_code: Some(exit_code),
                duration_ms: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
                timed_out: false,
            });
        }
        if let Some(output) = self
            .execute_output
            .lock()
            .expect("test execute output lock")
            .clone()
        {
            return Ok(SshCommandOutput {
                command,
                output,
                exit_code: Some(0),
                duration_ms: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
                timed_out: false,
            });
        }
        self.hold_operation().await;
        Ok(SshCommandOutput {
            command,
            output: "test operation released".to_owned(),
            exit_code: Some(0),
            duration_ms: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
            timed_out: false,
        })
    }

    async fn execute_sensitive(
        &self,
        _command: Zeroizing<String>,
        _stdin: Zeroizing<Vec<u8>>,
        limits: SshSensitiveCommandLimits,
    ) -> CoreResult<SshSensitiveCommandOutput> {
        let started = std::time::Instant::now();
        let output = if let Some(output) = self
            .execute_outputs
            .lock()
            .expect("test execute outputs lock")
            .pop_front()
        {
            output
        } else if let Some(output) = self
            .execute_output
            .lock()
            .expect("test execute output lock")
            .clone()
        {
            output
        } else {
            self.hold_operation().await;
            "test operation released".to_owned()
        };
        let mut stdout = Zeroizing::new(Vec::new());
        append_sensitive_output(
            &mut stdout,
            output.as_bytes(),
            limits.stdout_bytes,
            "sensitive command stdout",
        )?;
        Ok(SshSensitiveCommandOutput {
            stdout,
            stderr: Zeroizing::new(Vec::new()),
            exit_code: Some(0),
            duration_ms: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
        })
    }

    async fn sftp(&self, request: SftpRequest) -> CoreResult<SftpResponse> {
        if !self
            .sftp_immediate
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            self.hold_operation().await;
        }
        Ok(match request {
            SftpRequest::Canonicalize { path } => SftpResponse::Path(path),
            SftpRequest::List { .. } => {
                self.sftp_list_count
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                SftpResponse::Entries(Vec::new())
            }
            SftpRequest::Metadata { path, .. } => {
                let is_directory = self
                    .sftp_directories
                    .lock()
                    .expect("test SFTP directories lock")
                    .contains(&path);
                let is_symlink = self
                    .sftp_symlinks
                    .lock()
                    .expect("test SFTP symlinks lock")
                    .contains(&path);
                SftpResponse::Metadata(SftpRawMetadata {
                    size: self
                        .sftp_files
                        .lock()
                        .expect("test SFTP files lock")
                        .get(&path)
                        .map_or(0, |content| content.len() as u64),
                    permissions: Some(
                        self.sftp_modes
                            .lock()
                            .expect("test SFTP modes lock")
                            .get(&path)
                            .copied()
                            .unwrap_or(if is_directory { 0o755 } else { 0o600 }),
                    ),
                    uid: None,
                    gid: None,
                    modified_unix_seconds: None,
                    is_file: !is_directory && !is_symlink,
                    is_directory,
                    is_symlink,
                })
            }
            SftpRequest::Exists { path } => SftpResponse::Exists(
                self.sftp_files
                    .lock()
                    .expect("test SFTP files lock")
                    .contains_key(&path),
            ),
            SftpRequest::Read { path, .. } => SftpResponse::Bytes(
                self.sftp_files
                    .lock()
                    .expect("test SFTP files lock")
                    .get(&path)
                    .cloned()
                    .unwrap_or_default(),
            ),
            SftpRequest::WriteNew {
                path,
                content,
                mode,
            } => {
                let mut files = self.sftp_files.lock().expect("test SFTP files lock");
                if files.contains_key(&path) {
                    return Err(CoreError::validation(
                        "test SFTP new file",
                        "path already exists",
                    ));
                }
                files.insert(path.clone(), content.clone());
                self.sftp_modes
                    .lock()
                    .expect("test SFTP modes lock")
                    .insert(path, mode.unwrap_or(0o600));
                SftpResponse::Transfer {
                    bytes: content.len() as u64,
                }
            }
            // A switch already thrown answers the way the real copy does.
            SftpRequest::UploadNew { cancel, .. } | SftpRequest::DownloadNew { cancel, .. }
                if cancel.is_cancelled() =>
            {
                return Err(CoreError::validation("SFTP transfer", TRANSFER_CANCELLED));
            }
            SftpRequest::UploadNew { local_path, .. } => SftpResponse::Transfer {
                bytes: std::fs::metadata(local_path)
                    .expect("test upload source metadata")
                    .len(),
            },
            SftpRequest::DownloadNew { .. } => SftpResponse::Transfer { bytes: 0 },
            SftpRequest::CollectFileEvidence { .. } => {
                return Err(CoreError::validation(
                    "test evidence collection",
                    "requires a real SFTP server",
                ));
            }
            SftpRequest::AtomicWrite {
                path,
                backup_path,
                content,
                expected_sha256,
                expected_canonical_path,
                ..
            } => {
                let mut files = self.sftp_files.lock().expect("test SFTP files lock");
                if expected_canonical_path
                    .as_deref()
                    .is_some_and(|expected| expected != path)
                {
                    return Err(CoreError::validation(
                        "test SFTP editor target",
                        "canonical path changed after the operation was planned",
                    ));
                }
                if let Some(expected) = expected_sha256 {
                    let actual = files
                        .get(&path)
                        .map_or_else(|| sha256_bytes(&[]), |current| sha256_bytes(current));
                    if actual != expected {
                        return Err(CoreError::validation(
                            "test SFTP editor target",
                            "file content changed after the operation was planned",
                        ));
                    }
                }
                if let Some(original) = files.remove(&path) {
                    files.insert(backup_path.clone(), original);
                }
                files.insert(path.clone(), content.clone());
                SftpResponse::AtomicWrite(SftpAtomicWriteReceipt {
                    path,
                    backup_path,
                    bytes_written: content.len() as u64,
                    previous_permissions: Some(0o600),
                    installed: true,
                })
            }
            SftpRequest::MoveToBackup {
                path,
                backup_directory,
                backup_path,
                expected_sha256,
                ..
            } => {
                let mut files = self.sftp_files.lock().expect("test SFTP files lock");
                if let Some(expected) = expected_sha256 {
                    let current = files.get(&path).ok_or_else(|| {
                        CoreError::validation("test SFTP remove target", "file is absent")
                    })?;
                    if sha256_bytes(current) != expected {
                        return Err(CoreError::validation(
                            "test SFTP remove target",
                            "file content changed after the operation was planned",
                        ));
                    }
                }
                if let Some(original) = files.remove(&path) {
                    // The real transport narrows both of these after the move;
                    // recording them here is what lets a test see it happen.
                    let mut modes = self.sftp_modes.lock().expect("test SFTP modes lock");
                    modes.insert(backup_directory, BACKUP_DIRECTORY_MODE);
                    modes.insert(backup_path.clone(), BACKUP_FILE_MODE);
                    files.insert(backup_path, original);
                }
                SftpResponse::Unit
            }
            SftpRequest::Chmod { path, mode } => {
                self.sftp_modes
                    .lock()
                    .expect("test SFTP modes lock")
                    .insert(path, mode);
                SftpResponse::Unit
            }
            // Renaming used to be the one request this double accepted without
            // doing anything, which made undoing a removal look like it worked
            // whether or not the file came back.
            SftpRequest::Rename {
                from,
                to,
                require_destination_absent,
            } => {
                let mut files = self.sftp_files.lock().expect("test SFTP files lock");
                if require_destination_absent && files.contains_key(&to) {
                    return Err(CoreError::validation(
                        "test SFTP destination",
                        "path already exists and will not be overwritten",
                    ));
                }
                if let Some(content) = files.remove(&from) {
                    files.insert(to.clone(), content);
                    let mut modes = self.sftp_modes.lock().expect("test SFTP modes lock");
                    if let Some(mode) = modes.remove(&from) {
                        modes.insert(to, mode);
                    }
                }
                SftpResponse::Unit
            }
            SftpRequest::CreateDirectory { .. } | SftpRequest::Remove { .. } => SftpResponse::Unit,
        })
    }

    async fn open_terminal(
        &self,
        terminal_id: String,
        launch: TerminalLaunch,
        _columns: u16,
        _rows: u16,
        mut cancellation: CancellationToken,
    ) -> CoreResult<(SshTerminalSession, TerminalCloseHandle)> {
        self.terminal_launches
            .lock()
            .expect("test terminal launches lock")
            .push(
                launch
                    .exec_command()
                    .unwrap_or_else(|| "<login-shell>".to_owned()),
            );
        let (events_tx, events) = terminal_event_channel(1)?;
        let (control, control_rx) = mpsc::channel(TERMINAL_CONTROL_CAPACITY);
        let (close, mut close_rx) = watch::channel(false);
        let close = TerminalCloseHandle { close };
        let terminal_closed = self.terminal_closed.clone();
        tokio::spawn(async move {
            let _control_rx = control_rx;
            tokio::select! {
                biased;
                _ = close_rx.changed() => {}
                _ = cancellation.cancelled() => {}
            }
            terminal_closed.store(true, std::sync::atomic::Ordering::SeqCst);
            events_tx.close();
        });
        Ok((
            SshTerminalSession {
                terminal_id,
                control,
                close: close.clone(),
                events,
            },
            close,
        ))
    }

    async fn disconnect(&self) -> CoreResult<()> {
        self.disconnected
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.release.notify_waiters();
        Ok(())
    }
}

#[cfg(test)]
struct TestOperationGuard<'a> {
    harness: &'a TestSessionHarness,
    completed: bool,
}

#[cfg(test)]
impl Drop for TestOperationGuard<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.harness
                .cancelled_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
mod tests {
    /// What these tests bound is "does not hang", not "is quick". A hundred
    /// milliseconds is a coin toss on a loaded machine, and the blocked cases
    /// below are held open indefinitely, so a wider bound still fails at once
    /// when the property is actually broken.
    const RESPONSIVE_BOUND: Duration = Duration::from_secs(2);

    use std::collections::BTreeSet;
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::connections::ConnectionSecretChanges;
    use crate::crypto::CryptoVault;
    use crate::target::TargetIdentity;

    #[tokio::test]
    async fn a_transfer_copies_everything_until_it_is_cancelled() {
        let source = vec![7_u8; TRANSFER_CHUNK_BYTES * 3 + 11];
        let mut written = Vec::new();
        let copied = copy_cancellable(
            &mut source.as_slice(),
            &mut written,
            &SftpTransferCancel::new(),
        )
        .await
        .unwrap_or_else(|_| panic!("an uncancelled copy finishes"));
        assert_eq!(copied, source.len() as u64);
        assert_eq!(written, source);

        // A read stuck on the network still stops: the other end of this pipe
        // never writes anything.
        let (_quiet, mut stalled) = tokio::io::duplex(64);
        let cancel = SftpTransferCancel::new();
        let switch = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            switch.cancel();
        });
        let mut sink = Vec::new();
        let stopped = tokio::time::timeout(
            RESPONSIVE_BOUND,
            copy_cancellable(&mut stalled, &mut sink, &cancel),
        )
        .await
        .expect("a cancelled copy does not hang");
        assert!(matches!(stopped, Err(CopyStop::Cancelled)));
        assert!(cancel.is_cancelled());
    }

    #[test]
    fn a_download_file_is_kept_only_when_the_download_finished() {
        let directory =
            std::env::temp_dir().join(format!("lovelyhawk-partial-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let unfinished = directory.join("half.bin");
        std::fs::write(&unfinished, b"half").unwrap();
        drop(PartialDownload {
            path: &unfinished,
            finished: false,
        });
        assert!(!unfinished.exists(), "a half file was left behind");

        let finished = directory.join("whole.bin");
        std::fs::write(&finished, b"whole").unwrap();
        drop(PartialDownload {
            path: &finished,
            finished: true,
        });
        assert!(finished.exists());
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn actor_status(session_id: &str, connection_id: &str) -> SshConnectionStatus {
        SshConnectionStatus {
            session_id: session_id.to_owned(),
            connection_id: connection_id.to_owned(),
            host: format!("{connection_id}.test"),
            port: 22,
            username: "operator".to_owned(),
            host_key_fingerprint: "SHA256:test".to_owned(),
            connected_at: Utc::now(),
        }
    }

    fn test_router() -> (
        mpsc::Sender<WorkerCommand>,
        watch::Sender<bool>,
        tokio::task::JoinHandle<()>,
    ) {
        let (commands, receiver) = mpsc::channel(SSH_COMMAND_CAPACITY);
        let (shutdown, shutdown_rx) = watch::channel(false);
        let router = tokio::spawn(router_loop(
            receiver,
            shutdown_rx,
            PathBuf::from("unused-test-known-hosts"),
        ));
        (commands, shutdown, router)
    }

    async fn install_test_session(
        commands: &mpsc::Sender<WorkerCommand>,
        status: SshConnectionStatus,
        harness: Arc<TestSessionHarness>,
    ) {
        let (reply, response) = oneshot::channel();
        commands
            .send(WorkerCommand::InstallTestSession {
                status,
                harness,
                reply,
            })
            .await
            .unwrap();
        response.await.unwrap();
    }

    async fn stop_test_router(shutdown: watch::Sender<bool>, router: tokio::task::JoinHandle<()>) {
        shutdown.send_replace(true);
        tokio::time::timeout(Duration::from_secs(2), router)
            .await
            .expect("router shutdown must be bounded")
            .unwrap();
    }

    fn test_key(encoded: &str) -> PublicKey {
        russh::keys::parse_public_key_base64(encoded).unwrap()
    }

    #[test]
    fn command_collection_keeps_exit_status_that_arrives_after_eof() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_code = None;

        collect_command_message(ChannelMsg::Eof, &mut stdout, &mut stderr, &mut exit_code).unwrap();
        collect_command_message(
            ChannelMsg::ExitStatus { exit_status: 0 },
            &mut stdout,
            &mut stderr,
            &mut exit_code,
        )
        .unwrap();

        assert_eq!(exit_code, Some(0));

        let mut omitted_exit_code = None;
        collect_command_message(
            ChannelMsg::Eof,
            &mut stdout,
            &mut stderr,
            &mut omitted_exit_code,
        )
        .unwrap();
        collect_command_message(
            ChannelMsg::Close,
            &mut stdout,
            &mut stderr,
            &mut omitted_exit_code,
        )
        .unwrap();
        assert_eq!(omitted_exit_code, None);
    }

    #[test]
    fn confirmation_cannot_override_persisted_fingerprint() {
        let result = merge_confirmation(
            "host key",
            Some("SHA256:persisted".to_owned()),
            Some("SHA256:attacker".to_owned()),
        );
        assert!(result.is_err());
    }

    #[test]
    fn keyboard_interactive_authorization_is_bounded_and_debug_redacted() {
        let mut authorization = SshConnectAuthorization::default();
        authorization
            .push_keyboard_interactive_response(
                SshHostRole::Target,
                SecretValue::new("target-mfa-never-log"),
            )
            .unwrap();
        authorization
            .push_keyboard_interactive_response(
                SshHostRole::JumpHost,
                SecretValue::new("jump-mfa-never-log"),
            )
            .unwrap();
        assert_eq!(
            authorization.keyboard_interactive_response_count(SshHostRole::Target),
            1
        );
        assert_eq!(
            authorization.keyboard_interactive_response_count(SshHostRole::JumpHost),
            1
        );
        let debug = format!("{authorization:?}");
        assert!(!debug.contains("target-mfa-never-log"));
        assert!(!debug.contains("jump-mfa-never-log"));
        assert!(
            authorization
                .push_keyboard_interactive_response(
                    SshHostRole::Target,
                    SecretValue::new("x".repeat(MAX_KEYBOARD_INTERACTIVE_RESPONSE_BYTES + 1)),
                )
                .is_err()
        );
        let count = authorization.keyboard_interactive_response_count(SshHostRole::Target);
        assert!(
            authorization
                .extend_keyboard_interactive_responses(
                    SshHostRole::Target,
                    vec![
                        SecretValue::new("valid-but-must-not-stick"),
                        SecretValue::new("x".repeat(MAX_KEYBOARD_INTERACTIVE_RESPONSE_BYTES + 1),),
                    ],
                )
                .is_err()
        );
        assert_eq!(
            authorization.keyboard_interactive_response_count(SshHostRole::Target),
            count
        );
    }

    #[tokio::test]
    async fn probe_completion_disconnects_both_handles_without_registering_a_session() {
        let target = Arc::new(TestSessionHarness::default());
        let jump = Arc::new(TestSessionHarness::default());
        let status = actor_status("probe-session", "unsaved-probe");

        let result = finish_probe_connection(
            status.clone(),
            SessionHandle::Test(target.clone()),
            Some(SessionHandle::Test(jump.clone())),
        )
        .await
        .unwrap();

        assert_eq!(result.connection_id, status.connection_id);
        assert_eq!(result.host, status.host);
        assert_eq!(result.host_key_fingerprint, status.host_key_fingerprint);
        assert!(target.disconnected.load(Ordering::SeqCst));
        assert!(jump.disconnected.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn keyboard_interactive_preflight_ignores_unrelated_stale_key_paths() {
        let authentication = Authentication::materialize(
            SshAuthMethod::KeyboardInteractive,
            None,
            Some(PathBuf::from("relative-stale-private-key")),
            None,
            Some(PathBuf::from("relative-stale-certificate")),
            None,
            Vec::new(),
        )
        .await
        .unwrap();
        assert_eq!(authentication.method, SshAuthMethod::KeyboardInteractive);
        assert!(authentication.private_key.is_none());
        assert!(authentication.certificate.is_none());
    }

    #[tokio::test]
    async fn jump_host_materialization_keeps_its_own_key_passphrase_redacted() {
        let root = std::env::temp_dir().join(format!(
            "lovelyres-jump-key-passphrase-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let key_path = root.join("id_ed25519");
        std::fs::write(&key_path, "test-private-key-material").unwrap();

        let request = JumpHostRequest::materialize(
            JumpHostConfig {
                host: "jump.test".to_owned(),
                port: 22,
                username: "operator".to_owned(),
                auth_method: SshAuthMethod::PublicKey,
                private_key_path: Some(key_path),
                certificate_path: None,
                agent_identity_fingerprint: None,
                host_key_fingerprint: None,
            },
            None,
            Some(SecretValue::new("jump-key-passphrase")),
            None,
            Vec::new(),
        )
        .await
        .unwrap();

        assert_eq!(
            request
                .authentication
                .private_key_passphrase
                .as_ref()
                .unwrap()
                .expose(),
            "jump-key-passphrase"
        );
        assert!(!format!("{request:?}").contains("jump-key-passphrase"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn keyboard_interactive_challenge_is_typed_and_rejects_malformed_server_text() {
        let challenge = keyboard_interactive_challenge(
            KeyboardInteractiveEndpoint {
                role: SshHostRole::Target,
                host: "host.test",
                port: 22,
                username: "operator",
            },
            "Verification".to_owned(),
            "Enter the current one-time code".to_owned(),
            vec![Prompt {
                prompt: "OTP: ".to_owned(),
                echo: false,
            }],
            1,
        )
        .unwrap();
        assert_eq!(challenge.role, SshHostRole::Target);
        assert_eq!(challenge.prompts.len(), 1);
        assert!(!challenge.prompts[0].echo);
        assert_eq!(challenge.supplied_responses, 1);
        assert!(!format!("{challenge}").contains("one-time code"));

        assert!(
            keyboard_interactive_challenge(
                KeyboardInteractiveEndpoint {
                    role: SshHostRole::JumpHost,
                    host: "jump.test",
                    port: 22,
                    username: "operator",
                },
                "bad\0name".to_owned(),
                String::new(),
                Vec::new(),
                0,
            )
            .is_err()
        );
        assert!(
            keyboard_interactive_challenge(
                KeyboardInteractiveEndpoint {
                    role: SshHostRole::Target,
                    host: "host.test",
                    port: 22,
                    username: "operator",
                },
                String::new(),
                String::new(),
                (0..=MAX_KEYBOARD_INTERACTIVE_PROMPTS)
                    .map(|_| Prompt {
                        prompt: "OTP: ".to_owned(),
                        echo: false,
                    })
                    .collect(),
                0,
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn raw_ipv6_literal_resolution_preserves_port() {
        let addresses = resolve_ssh_addresses("::1", 2222).await.unwrap();
        assert!(addresses.iter().any(|address| {
            address.is_ipv6() && address.ip().is_loopback() && address.port() == 2222
        }));
    }

    /// The in-process signer must hand back exactly what an agent would: the
    /// data it was given, followed by the encoded signature as one
    /// length-prefixed blob — or the server sees a malformed login. RSA's
    /// hash choice is exercised end to end against real OpenSSH (see
    /// docs/SSH_COMPATIBILITY.md); this pins the wire shape.
    #[tokio::test]
    async fn the_in_process_signer_appends_a_signature_the_public_key_verifies() {
        use russh::keys::signature::Verifier;
        use russh::keys::ssh_encoding::Decode as _;
        use russh::keys::ssh_key::{Signature, private::Ed25519Keypair};

        let key = Arc::new(russh::keys::PrivateKey::from(Ed25519Keypair::from_seed(
            &[7; 32],
        )));
        let identity = AgentIdentity::PublicKey {
            key: key.public_key().clone(),
            comment: String::new(),
        };
        let data = b"session identifier and userauth request".to_vec();
        let mut signer = InProcessSigner(key.clone());
        let signed = russh::Signer::auth_sign(&mut signer, &identity, None, data.clone())
            .await
            .unwrap();
        assert!(signed.starts_with(&data));
        let mut rest = &signed[data.len()..];
        let blob = Vec::<u8>::decode(&mut rest).unwrap();
        assert!(rest.is_empty(), "nothing may follow the signature blob");
        let signature = Signature::decode(&mut blob.as_slice()).unwrap();
        assert!(Verifier::verify(key.public_key(), &data, &signature).is_ok());
        assert!(Verifier::verify(key.public_key(), b"other data", &signature).is_err());
    }

    #[test]
    fn typed_completion_ranges_are_utf8_safe_and_path_parts_are_data_only() {
        let input = "cat 目录/证据";
        let word = completion_word(input, input.len()).unwrap();
        assert_eq!(word.value, "目录/证据");
        assert_eq!(&input[word.start..word.end], word.value);
        assert!(!word.first_word);
        assert!(completion_word(input, input.len() - 1).is_err());

        let (directory, visible, prefix) = completion_path_parts("/tmp/a';touch PWNED;'/ev");
        assert_eq!(directory, "/tmp/a';touch PWNED;'");
        assert_eq!(visible, "/tmp/a';touch PWNED;'/");
        assert_eq!(prefix, "ev");
        assert_eq!(
            crate::shell_escape::shq(directory),
            "'/tmp/a'\\'';touch PWNED;'\\'''"
        );

        let trailing_space = completion_word("cat ", 4).unwrap();
        assert!(!trailing_space.first_word);
        assert_eq!(completion_path_parts(trailing_space.value), (".", "", ""));
    }

    #[test]
    fn typed_completion_and_environment_parsers_are_bounded() {
        let candidates =
            parse_completion_candidates("ls\nls\nless\nnot-matching\nline-with-escape\x1b\n", "l");
        assert_eq!(candidates, vec!["less", "ls"]);

        let environment = parse_bash_environment(
            "shell=/bin/bash\nversion=5.2.15\ncompletion=1\nhistory=1\nuntrusted=x\n",
        );
        assert_eq!(environment.shell, "/bin/bash");
        assert_eq!(environment.version, "5.2.15");
        assert!(environment.supports_completion);
        assert!(environment.supports_history);
    }

    #[test]
    fn host_key_errors_retain_role_when_endpoint_tuples_match() {
        let endpoint = ("same-host.test", 22, "operator");
        let unknown = Arc::new(Mutex::new(HostKeyVerification::Unknown {
            fingerprint: "SHA256:unknown".to_owned(),
        }));
        let error = confirmed_fingerprint(
            SshHostRole::JumpHost,
            endpoint.0,
            endpoint.1,
            endpoint.2,
            &unknown,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            CoreError::SshHostKeyConfirmationRequired {
                role: SshHostRole::JumpHost,
                ..
            }
        ));

        let mismatch = Arc::new(Mutex::new(HostKeyVerification::Mismatch {
            expected: "SHA256:expected".to_owned(),
            observed: "SHA256:observed".to_owned(),
        }));
        let error = confirmed_fingerprint(
            SshHostRole::Target,
            endpoint.0,
            endpoint.1,
            endpoint.2,
            &mismatch,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            CoreError::SshHostKeyChanged {
                role: SshHostRole::Target,
                ..
            }
        ));
        assert_eq!(
            serde_json::to_string(&SshHostRole::JumpHost).unwrap(),
            "\"jump-host\""
        );
    }

    #[test]
    fn known_hosts_requires_confirmation_then_rejects_changed_key() {
        let root = std::env::temp_dir().join(format!("lovelyres-ssh-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("known_hosts");
        let first =
            test_key("AAAAC3NzaC1lZDI1NTE5AAAAICedOftBqa5SQSqiTx/tQmrF+cLcZiHBfahFrT35ij2k");
        let changed =
            test_key("AAAAC3NzaC1lZDI1NTE5AAAAIBUK45WEpPFiPgQwZr/mEV8e2wCqgRZ8nT6Q5r/1KrZ5");
        let unknown = verify_or_learn_host_key("host.test", 22, &first, &path, None);
        let first_fingerprint = match unknown {
            HostKeyVerification::Unknown { fingerprint } => fingerprint,
            other => panic!("unexpected result: {other:?}"),
        };
        assert!(matches!(
            verify_or_learn_host_key("host.test", 22, &first, &path, Some(&first_fingerprint)),
            HostKeyVerification::Learned { .. }
        ));
        let changed_fingerprint = fingerprint(&changed);
        assert!(matches!(
            verify_or_learn_host_key("host.test", 22, &first, &path, Some(&changed_fingerprint)),
            HostKeyVerification::Mismatch { .. }
        ));
        assert!(matches!(
            verify_or_learn_host_key("host.test", 22, &changed, &path, Some(&first_fingerprint)),
            HostKeyVerification::Mismatch { .. }
        ));
        assert!(matches!(
            verify_or_learn_host_key("host.test", 22, &changed, &path, Some(&changed_fingerprint)),
            HostKeyVerification::Trusted { .. }
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn terminal_controls_validate_sizes_and_preserve_cross_type_order() {
        let (control, mut control_rx) = mpsc::channel(3);
        let (close, mut close_rx) = watch::channel(false);
        let (events_tx, events) = terminal_event_channel(1).unwrap();
        events_tx.close();
        let terminal = SshTerminalSession {
            terminal_id: "t1".to_owned(),
            control,
            close: TerminalCloseHandle { close },
            events,
        };
        assert!(terminal.resize(0, 24).await.is_err());
        terminal.write_input(vec![1]).await.unwrap();
        terminal.resize(120, 40).await.unwrap();
        terminal.write_input(vec![2, 3]).await.unwrap();
        assert!(matches!(
            control_rx.recv().await,
            Some(TerminalControl::Input(bytes)) if bytes == vec![1]
        ));
        assert!(matches!(
            control_rx.recv().await,
            Some(TerminalControl::Resize {
                columns: 120,
                rows: 40
            })
        ));
        assert!(matches!(
            control_rx.recv().await,
            Some(TerminalControl::Input(bytes)) if bytes == vec![2, 3]
        ));
        drop(terminal);
        close_rx.changed().await.unwrap();
        assert!(*close_rx.borrow());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn router_stays_responsive_and_disconnect_cancels_cross_session_work() {
        let (commands, shutdown, router) = test_router();
        let harness_a = Arc::new(TestSessionHarness::default());
        let harness_b = Arc::new(TestSessionHarness::default());
        install_test_session(
            &commands,
            actor_status("session-a", "connection-a"),
            harness_a.clone(),
        )
        .await;
        install_test_session(
            &commands,
            actor_status("session-b", "connection-b"),
            harness_b.clone(),
        )
        .await;

        let (execute_reply, execute_response) = oneshot::channel();
        commands
            .send(WorkerCommand::Execute {
                session_id: "session-a".to_owned(),
                expected_connection_id: Some("connection-a".to_owned()),
                command: "hang execute".to_owned(),
                timeout: Duration::from_secs(60),
                reply: execute_reply,
            })
            .await
            .unwrap();
        let (sftp_reply, sftp_response) = oneshot::channel();
        commands
            .send(WorkerCommand::Sftp {
                session_id: "session-a".to_owned(),
                expected_connection_id: "connection-a".to_owned(),
                request: Box::new(SftpRequest::List {
                    path: "/".to_owned(),
                    maximum_entries: 1,
                }),
                reply: sftp_reply,
            })
            .await
            .unwrap();
        harness_a.wait_for_entered(2).await;

        let (list_reply, list_response) = oneshot::channel();
        commands
            .send(WorkerCommand::ListSessions { reply: list_reply })
            .await
            .unwrap();
        let listed = tokio::time::timeout(RESPONSIVE_BOUND, list_response)
            .await
            .expect("session A work must not block listing")
            .unwrap();
        assert_eq!(listed.len(), 2);

        let (disconnect_b_reply, disconnect_b_response) = oneshot::channel();
        commands
            .send(WorkerCommand::Disconnect {
                session_id: "session-b".to_owned(),
                reply: disconnect_b_reply,
            })
            .await
            .unwrap();
        tokio::time::timeout(RESPONSIVE_BOUND, disconnect_b_response)
            .await
            .expect("session A work must not block session B disconnect")
            .unwrap()
            .unwrap();

        let (disconnect_a_reply, disconnect_a_response) = oneshot::channel();
        commands
            .send(WorkerCommand::Disconnect {
                session_id: "session-a".to_owned(),
                reply: disconnect_a_reply,
            })
            .await
            .unwrap();
        tokio::time::timeout(RESPONSIVE_BOUND, disconnect_a_response)
            .await
            .expect("session disconnect must be bounded")
            .unwrap()
            .unwrap();
        assert!(matches!(
            execute_response.await.unwrap(),
            Err(CoreError::OperationCancelled { .. })
        ));
        assert!(matches!(
            sftp_response.await.unwrap(),
            Err(CoreError::OperationCancelled { .. })
        ));
        assert!(harness_a.cancelled_count.load(Ordering::SeqCst) >= 2);
        assert!(harness_b.disconnected.load(Ordering::SeqCst));
        stop_test_router(shutdown, router).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ingress_and_each_session_have_hard_capacity_limits() {
        let (ingress, _receiver) = mpsc::channel(1);
        let (first_reply, _first_response) = oneshot::channel();
        ingress
            .try_send(WorkerCommand::ListSessions { reply: first_reply })
            .unwrap();
        let (overflow_reply, _overflow_response) = oneshot::channel();
        assert!(matches!(
            ingress.try_send(WorkerCommand::ListSessions {
                reply: overflow_reply
            }),
            Err(mpsc::error::TrySendError::Full(_))
        ));

        let (commands, shutdown, router) = test_router();
        let harness = Arc::new(TestSessionHarness::default());
        install_test_session(
            &commands,
            actor_status("bounded", "connection-a"),
            harness.clone(),
        )
        .await;
        let mut responses = Vec::new();
        for index in 0..=SESSION_OPERATION_CAPACITY {
            let (reply, response) = oneshot::channel();
            commands
                .send(WorkerCommand::Execute {
                    session_id: "bounded".to_owned(),
                    expected_connection_id: Some("connection-a".to_owned()),
                    command: format!("hang {index}"),
                    timeout: Duration::from_secs(60),
                    reply,
                })
                .await
                .unwrap();
            responses.push(response);
        }
        let overflow = responses.pop().unwrap();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), overflow)
                .await
                .unwrap()
                .unwrap(),
            Err(CoreError::Ssh {
                operation: "runtime",
                ..
            })
        ));
        harness
            .wait_for_entered(SESSION_OPERATION_CONCURRENCY)
            .await;
        tokio::task::yield_now().await;
        assert_eq!(
            harness.entered_count.load(Ordering::SeqCst),
            SESSION_OPERATION_CONCURRENCY
        );

        let (reply, response) = oneshot::channel();
        commands
            .send(WorkerCommand::Disconnect {
                session_id: "bounded".to_owned(),
                reply,
            })
            .await
            .unwrap();
        response.await.unwrap().unwrap();
        drop(responses);
        stop_test_router(shutdown, router).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropped_response_cancels_work_and_disconnect_still_cleans_up() {
        let (commands, shutdown, router) = test_router();
        let harness = Arc::new(TestSessionHarness::default());
        install_test_session(
            &commands,
            actor_status("abandoned", "connection-a"),
            harness.clone(),
        )
        .await;

        let (reply, response) = oneshot::channel();
        commands
            .send(WorkerCommand::Execute {
                session_id: "abandoned".to_owned(),
                expected_connection_id: Some("connection-a".to_owned()),
                command: "hang".to_owned(),
                timeout: Duration::from_secs(60),
                reply,
            })
            .await
            .unwrap();
        harness.wait_for_entered(1).await;
        drop(response);
        tokio::time::timeout(RESPONSIVE_BOUND, async {
            while harness.cancelled_count.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropping a response must cancel its operation");

        let (disconnect_reply, disconnect_response) = oneshot::channel();
        commands
            .send(WorkerCommand::Disconnect {
                session_id: "abandoned".to_owned(),
                reply: disconnect_reply,
            })
            .await
            .unwrap();
        drop(disconnect_response);
        tokio::time::timeout(RESPONSIVE_BOUND, async {
            while !harness.disconnected.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("abandoned disconnect responses must still clean up the session");
        stop_test_router(shutdown, router).await;
    }

    #[tokio::test]
    async fn saturated_terminal_events_cannot_block_close() {
        let (events, receiver) = terminal_event_channel(1).unwrap();
        events
            .send(TerminalEvent {
                session_id: "terminal".to_owned(),
                sequence: 1,
                kind: TerminalEventKind::Bell,
            })
            .await
            .unwrap();
        let (close, mut close_rx) = watch::channel(false);
        let (_cancel, mut cancellation) = cancellation_pair();
        let blocked = tokio::spawn(async move {
            send_terminal_event_interruptibly(
                &events,
                TerminalEvent {
                    session_id: "terminal".to_owned(),
                    sequence: 2,
                    kind: TerminalEventKind::Bell,
                },
                &mut close_rx,
                &mut cancellation,
            )
            .await
        });
        tokio::task::yield_now().await;
        close.send_replace(true);
        assert!(
            !tokio::time::timeout(RESPONSIVE_BOUND, blocked)
                .await
                .expect("close must interrupt a saturated event send")
                .unwrap()
        );
        assert_eq!(receiver.len(), 1);

        let harness = TestSessionHarness::default();
        let (_session_cancel, cancellation) = cancellation_pair();
        let (terminal, _close) = harness
            .open_terminal(
                "bounded-input".to_owned(),
                TerminalLaunch::LoginShell,
                80,
                24,
                cancellation,
            )
            .await
            .unwrap();
        let terminal = Arc::new(terminal);
        for _ in 0..TERMINAL_CONTROL_CAPACITY {
            terminal.write_input(vec![b'x']).await.unwrap();
        }
        let blocked_terminal = terminal.clone();
        let blocked_input =
            tokio::spawn(async move { blocked_terminal.write_input(vec![b'y']).await });
        tokio::task::yield_now().await;
        terminal.close().await.unwrap();
        assert!(
            tokio::time::timeout(RESPONSIVE_BOUND, blocked_input)
                .await
                .expect("close must interrupt blocked terminal input")
                .unwrap()
                .is_err()
        );
    }

    #[tokio::test]
    async fn actor_and_guarded_bindings_reject_cross_connection_pairs() {
        let status = actor_status("session-a", "connection-a");
        let wrong_guard = TargetGuard {
            identity: TargetIdentity::new("connection-b").unwrap(),
            generation: 7,
        };
        assert!(BoundSshSession::from_status(wrong_guard, &status, "SSH session binding").is_err());

        let (commands, shutdown, router) = test_router();
        let harness = Arc::new(TestSessionHarness::default());
        install_test_session(&commands, status, harness.clone()).await;
        let (reply, response) = oneshot::channel();
        commands
            .send(WorkerCommand::OpenTerminal {
                session_id: "session-a".to_owned(),
                expected_connection_id: Some("connection-b".to_owned()),
                terminal_id: "terminal".to_owned(),
                launch: TerminalLaunch::LoginShell,
                columns: 80,
                rows: 24,
                reply,
            })
            .await
            .unwrap();
        assert!(matches!(
            response.await.unwrap(),
            Err(CoreError::Validation {
                subject: "SSH session binding",
                ..
            })
        ));
        assert_eq!(harness.entered_count.load(Ordering::SeqCst), 0);

        let (reply, response) = oneshot::channel();
        commands
            .send(WorkerCommand::ExecuteSensitive {
                session_id: "session-a".to_owned(),
                expected_connection_id: "connection-b".to_owned(),
                command: Zeroizing::new("printf secret".to_owned()),
                stdin: Zeroizing::new(Vec::new()),
                timeout: Duration::from_secs(1),
                limits: SshSensitiveCommandLimits::new(32, 32).unwrap(),
                reply,
            })
            .await
            .unwrap();
        assert!(matches!(
            response.await.unwrap(),
            Err(CoreError::Validation {
                subject: "sensitive SSH session binding",
                ..
            })
        ));
        assert_eq!(harness.entered_count.load(Ordering::SeqCst), 0);
        stop_test_router(shutdown, router).await;
    }

    #[test]
    fn worker_shutdown_and_service_drop_are_bounded() {
        let (commands, receiver) = mpsc::channel(SSH_COMMAND_CAPACITY);
        let (shutdown, shutdown_rx) = watch::channel(false);
        let (done, finished) = std::sync::mpsc::channel();
        let worker = thread::spawn(move || {
            run_worker(
                receiver,
                shutdown_rx,
                PathBuf::from("unused-test-known-hosts"),
            );
            let _ = done.send(());
        });
        let harness = Arc::new(TestSessionHarness::default());
        let (install_reply, install_response) = oneshot::channel();
        commands
            .blocking_send(WorkerCommand::InstallTestSession {
                status: actor_status("shutdown", "connection-a"),
                harness: harness.clone(),
                reply: install_reply,
            })
            .unwrap();
        install_response.blocking_recv().unwrap();
        let (execute_reply, _execute_response) = oneshot::channel();
        commands
            .blocking_send(WorkerCommand::Execute {
                session_id: "shutdown".to_owned(),
                expected_connection_id: Some("connection-a".to_owned()),
                command: "hang".to_owned(),
                timeout: Duration::from_secs(60),
                reply: execute_reply,
            })
            .unwrap();
        let entered_deadline = std::time::Instant::now() + Duration::from_secs(1);
        while harness.entered_count.load(Ordering::SeqCst) == 0 {
            assert!(std::time::Instant::now() < entered_deadline);
            thread::yield_now();
        }
        shutdown.send_replace(true);
        finished
            .recv_timeout(Duration::from_secs(2))
            .expect("worker shutdown must be bounded");
        worker.join().unwrap();

        let (commands, _receiver) = mpsc::channel(1);
        let (shutdown, shutdown_rx) = watch::channel(false);
        let (release, released) = std::sync::mpsc::channel();
        let detached = thread::spawn(move || {
            let _ = released.recv();
        });
        let inner = SshServiceInner {
            commands,
            shutdown,
            worker: Mutex::new(Some(detached)),
        };
        let started = std::time::Instant::now();
        drop(inner);
        assert!(started.elapsed() < Duration::from_millis(100));
        assert!(*shutdown_rx.borrow());
        release.send(()).unwrap();
    }

    #[test]
    fn runtime_ids_reject_controls() {
        assert!(validate_runtime_id("id", "ok-1").is_ok());
        assert!(validate_runtime_id("id", "bad\nid").is_err());
        assert!(validate_runtime_id("id", "").is_err());
    }

    #[test]
    fn command_output_limit_counts_stdout_and_stderr_together() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        append_bounded_output(&mut stdout, &mut stderr, b"123", false, 5).unwrap();
        append_bounded_output(&mut stdout, &mut stderr, b"45", true, 5).unwrap();
        assert_eq!(stdout, b"123");
        assert_eq!(stderr, b"45");
        assert!(append_bounded_output(&mut stdout, &mut stderr, b"6", false, 5).is_err());
        assert_eq!(stdout, b"123");
        assert_eq!(stderr, b"45");
    }

    #[test]
    fn sensitive_command_output_is_split_bounded_and_debug_redacted() {
        assert!(SshSensitiveCommandLimits::new(0, 1).is_err());
        assert!(SshSensitiveCommandLimits::new(MAX_SENSITIVE_COMMAND_STREAM_BYTES + 1, 1).is_err());

        let mut stream = Vec::new();
        append_sensitive_output(&mut stream, b"secret", 6, "test stream").unwrap();
        assert!(append_sensitive_output(&mut stream, b"!", 6, "test stream").is_err());
        assert_eq!(stream, b"secret");

        let output = SshSensitiveCommandOutput {
            stdout: Zeroizing::new(b"DontLeakStdout".to_vec()),
            stderr: Zeroizing::new(b"DontLeakStderr".to_vec()),
            exit_code: Some(0),
            duration_ms: 7,
        };
        let debug = format!("{output:?}");
        assert!(!debug.contains("DontLeak"));
        assert!(debug.contains("stdout_bytes"));
        assert!(debug.contains("stderr_bytes"));

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_code = None;
        let error = collect_sensitive_command_message(
            ChannelMsg::ExtendedData {
                data: Bytes::from_static(b"DontLeakExtendedData"),
                ext: 2,
            },
            &mut stdout,
            &mut stderr,
            &mut exit_code,
            SshSensitiveCommandLimits::new(32, 32).unwrap(),
        )
        .unwrap_err();
        assert!(stdout.is_empty());
        assert!(stderr.is_empty());
        assert!(!format!("{error:?}").contains("DontLeak"));
    }

    #[test]
    fn connect_preflight_does_not_require_an_external_tokio_runtime() {
        let root =
            std::env::temp_dir().join(format!("lovelyres-ssh-runtime-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let store = PortableStore::prepare(root.clone()).unwrap();
        let crypto = Arc::new(CryptoVault::load(&store).unwrap());
        let connections = ConnectionRepository::new(store.clone(), crypto);
        connections
            .upsert(
                ConnectionConfig {
                    id: "no-password".to_owned(),
                    name: "No password".to_owned(),
                    host: "127.0.0.1".to_owned(),
                    port: 22,
                    username: "root".to_owned(),
                    auth_method: SshAuthMethod::Password,
                    private_key_path: None,
                    certificate_path: None,
                    agent_identity_fingerprint: None,
                    jump_host: None,
                    tags: BTreeSet::new(),
                    notes: None,
                    environment: None,
                    role: None,
                    group: None,
                    host_key_fingerprint: None,
                },
                ConnectionSecretChanges::default(),
            )
            .unwrap();
        let service = SshService::new(store, connections).unwrap();
        let error = futures::executor::block_on(
            service.connect("no-password", HostKeyConfirmations::default()),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            CoreError::Validation {
                subject: "SSH password",
                ..
            }
        ));
        drop(service);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn post_connect_repository_failure_disconnects_registered_session() {
        let root =
            std::env::temp_dir().join(format!("lovelyres-ssh-finalize-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let store = PortableStore::prepare(root.clone()).unwrap();
        let crypto = Arc::new(CryptoVault::load(&store).unwrap());
        let connections = ConnectionRepository::new(store.clone(), crypto);
        let original = ConnectionConfig {
            id: "connection-a".to_owned(),
            name: "Connection A".to_owned(),
            host: "old-endpoint.test".to_owned(),
            port: 22,
            username: "operator".to_owned(),
            auth_method: SshAuthMethod::Password,
            private_key_path: None,
            certificate_path: None,
            agent_identity_fingerprint: None,
            jump_host: None,
            tags: BTreeSet::new(),
            notes: None,
            environment: None,
            role: None,
            group: None,
            host_key_fingerprint: None,
        };
        connections
            .upsert(original.clone(), ConnectionSecretChanges::default())
            .unwrap();
        let service = SshService::new(store, connections.clone()).unwrap();
        let harness = Arc::new(TestSessionHarness::default());
        let status = actor_status("finalize-session", "connection-a");
        let (reply, response) = oneshot::channel();
        service
            .send(WorkerCommand::InstallTestSession {
                status: status.clone(),
                harness: harness.clone(),
                reply,
            })
            .unwrap();
        response.await.unwrap();

        let mut concurrently_edited = original;
        concurrently_edited.host = "new-endpoint.test".to_owned();
        connections
            .upsert(concurrently_edited, ConnectionSecretChanges::default())
            .unwrap();
        let error = service
            .finalize_connected_status(
                "connection-a",
                "old-endpoint.test",
                22,
                "operator",
                None,
                &status,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            CoreError::Validation {
                subject: "SSH connection endpoint",
                ..
            }
        ));
        assert!(service.list_sessions().await.unwrap().is_empty());
        assert!(harness.disconnected.load(Ordering::SeqCst));
        drop(service);
        let _ = std::fs::remove_dir_all(root);
    }

    // Release-VM contract: these helpers deliberately panic when a fixture is missing.
    // Ignored tests must never turn a missing compatibility environment into a pass.
    fn live_required(name: &str) -> String {
        std::env::var(name)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| {
                panic!(
                    "{name} is required; run ignored SSH contracts only against the disposable OpenSSH release-gate VM"
                )
            })
    }

    fn live_optional(name: &str) -> Option<String> {
        std::env::var(name)
            .ok()
            .filter(|value| !value.trim().is_empty())
    }

    #[derive(Clone)]
    struct LiveEndpoint {
        host: String,
        port: u16,
        username: String,
        password: String,
        fingerprint: String,
    }

    impl LiveEndpoint {
        fn from_prefix(prefix: &str) -> Self {
            let required = |suffix: &str| live_required(&format!("{prefix}_{suffix}"));
            let port_name = format!("{prefix}_PORT");
            let port = required("PORT")
                .parse::<u16>()
                .unwrap_or_else(|_| panic!("{port_name} must be a non-zero u16"));
            assert_ne!(port, 0, "{port_name} must be a non-zero u16");
            Self {
                host: required("HOST"),
                port,
                username: required("USERNAME"),
                password: required("PASSWORD"),
                fingerprint: required("HOST_KEY"),
            }
        }

        fn connection(&self, id: &str, auth_method: SshAuthMethod) -> ConnectionConfig {
            ConnectionConfig {
                id: id.to_owned(),
                name: format!("Release VM {id}"),
                host: self.host.clone(),
                port: self.port,
                username: self.username.clone(),
                auth_method,
                private_key_path: None,
                certificate_path: None,
                agent_identity_fingerprint: None,
                jump_host: None,
                tags: BTreeSet::new(),
                notes: Some("disposable release-gate VM only".to_owned()),
                environment: Some("release-vm".to_owned()),
                role: Some("compatibility-contract".to_owned()),
                group: None,
                host_key_fingerprint: Some(self.fingerprint.clone()),
            }
        }
    }

    fn live_service(
        label: &str,
    ) -> CoreResult<(PathBuf, PortableStore, ConnectionRepository, SshService)> {
        let root = std::env::temp_dir().join(format!("lovelyres-{label}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root)
            .map_err(|source| CoreError::io("create live SSH test root", &root, source))?;
        let store = PortableStore::prepare(root.clone())?;
        let crypto = Arc::new(CryptoVault::load(&store)?);
        let connections = ConnectionRepository::new(store.clone(), crypto);
        let ssh = SshService::new(store.clone(), connections.clone())?;
        Ok((root, store, connections, ssh))
    }

    fn upsert_live_connection(
        connections: &ConnectionRepository,
        config: ConnectionConfig,
        password: Option<&str>,
        key_passphrase: Option<&str>,
        jump_password: Option<&str>,
    ) -> CoreResult<()> {
        use crate::connections::SecretChange;

        let secret = |value: Option<&str>| match value {
            Some(value) => SecretChange::Replace(SecretValue::new(value.to_owned())),
            None => SecretChange::Keep,
        };
        connections.upsert(
            config,
            ConnectionSecretChanges {
                password: secret(password),
                key_passphrase: secret(key_passphrase),
                jump_host_password: secret(jump_password),
                jump_host_key_passphrase: secret(None),
            },
        )?;
        Ok(())
    }

    async fn assert_live_exec_and_optional_pty(
        ssh: &SshService,
        connection_id: &str,
        exercise_pty: bool,
    ) -> CoreResult<()> {
        use crate::target::TargetContext;

        let status = ssh
            .connect(connection_id, HostKeyConfirmations::default())
            .await?;
        let target = TargetContext::new();
        let guard = target.activate(TargetIdentity::new(connection_id)?)?;
        let bound = ssh.bind_session(guard, &status.session_id).await?;
        let marker = format!("lovelyres-exec-{connection_id}");
        let result: CoreResult<()> = async {
            let output = ssh
                .execute_bound(
                    &bound,
                    format!("printf '%s\\n' {}", crate::shell_escape::shq(&marker)),
                    Duration::from_secs(10),
                )
                .await?;
            if output.timed_out || output.exit_code != Some(0) || !output.output.contains(&marker) {
                return Err(CoreError::ssh(
                    "release VM exec contract",
                    format!("{connection_id} did not return its exec marker"),
                ));
            }
            let failure = ssh
                .execute_bound(&bound, "sh -c 'exit 7'".to_owned(), Duration::from_secs(10))
                .await?;
            if failure.timed_out || failure.exit_code != Some(7) {
                return Err(CoreError::ssh(
                    "release VM exec contract",
                    format!("{connection_id} did not preserve a non-zero exit status"),
                ));
            }

            if exercise_pty {
                let terminal_marker = format!("lovelyres-pty-{connection_id}");
                let terminal = ssh
                    .open_terminal_bound(&bound, format!("release-vm-{connection_id}"), 80, 24)
                    .await?;
                terminal.resize(100, 30).await?;
                terminal
                    .write_input(
                        format!(
                            "printf '%s\\n' {}; exit\n",
                            crate::shell_escape::shq(&terminal_marker)
                        )
                        .into_bytes(),
                    )
                    .await?;
                tokio::time::timeout(Duration::from_secs(15), async {
                    let mut observed = Vec::new();
                    loop {
                        match terminal.recv().await?.kind {
                            TerminalEventKind::Output(bytes) => observed.extend_from_slice(&bytes),
                            TerminalEventKind::Exited { .. }
                                if String::from_utf8_lossy(&observed)
                                    .contains(&terminal_marker) =>
                            {
                                return Ok(());
                            }
                            TerminalEventKind::Exited { .. } => {
                                return Err(CoreError::ssh(
                                    "release VM PTY contract",
                                    "PTY exited without the expected marker",
                                ));
                            }
                            TerminalEventKind::Failed { message } => {
                                return Err(CoreError::ssh("release VM PTY contract", message));
                            }
                            _ => {}
                        }
                    }
                })
                .await
                .map_err(|_| CoreError::ssh("release VM PTY contract", "timed out"))??;
                terminal.close().await?;
            }
            Ok(())
        }
        .await;
        let disconnect = ssh.disconnect(&status.session_id).await;
        result?;
        disconnect
    }

    /// Release VM matrix contract.
    ///
    /// Required target variables: `LOVELYHAWK_TEST_SSH_{HOST,PORT,USERNAME,PASSWORD,HOST_KEY}`,
    /// `LOVELYHAWK_TEST_SSH_KEY_PATH`, `LOVELYHAWK_TEST_SSH_AGENT_IDENTITY_FINGERPRINT`, and
    /// `LOVELYHAWK_TEST_SSH_JUMP_{HOST,PORT,USERNAME,PASSWORD,HOST_KEY}`. The private key may use
    /// `LOVELYHAWK_TEST_SSH_KEY_PASSPHRASE`. The agent identity must already be loaded in the
    /// test process' OpenSSH agent. All accounts and hosts must be disposable fixtures.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "release gate: requires password/key/agent/jump OpenSSH fixtures"]
    async fn live_openssh_end_to_end_contract() -> CoreResult<()> {
        let endpoint = LiveEndpoint::from_prefix("LOVELYHAWK_TEST_SSH");
        let jump = LiveEndpoint::from_prefix("LOVELYHAWK_TEST_SSH_JUMP");
        let private_key_path = PathBuf::from(live_required("LOVELYHAWK_TEST_SSH_KEY_PATH"));
        assert!(
            private_key_path.is_absolute(),
            "LOVELYHAWK_TEST_SSH_KEY_PATH must be absolute"
        );
        let key_passphrase = live_optional("LOVELYHAWK_TEST_SSH_KEY_PASSPHRASE");
        let agent_fingerprint = live_required("LOVELYHAWK_TEST_SSH_AGENT_IDENTITY_FINGERPRINT");
        let (local_root, _store, connections, ssh) = live_service("openssh-matrix")?;

        let password = endpoint.connection("live-password", SshAuthMethod::Password);
        upsert_live_connection(&connections, password, Some(&endpoint.password), None, None)?;

        let mut public_key = endpoint.connection("live-public-key", SshAuthMethod::PublicKey);
        public_key.private_key_path = Some(private_key_path);
        upsert_live_connection(
            &connections,
            public_key,
            None,
            key_passphrase.as_deref(),
            None,
        )?;

        let mut agent = endpoint.connection("live-agent", SshAuthMethod::Agent);
        agent.agent_identity_fingerprint = Some(agent_fingerprint);
        upsert_live_connection(&connections, agent, None, None, None)?;

        let mut through_jump = endpoint.connection("live-jump", SshAuthMethod::Password);
        through_jump.jump_host = Some(JumpHostConfig {
            host: jump.host,
            port: jump.port,
            username: jump.username,
            auth_method: SshAuthMethod::Password,
            private_key_path: None,
            certificate_path: None,
            agent_identity_fingerprint: None,
            host_key_fingerprint: Some(jump.fingerprint),
        });
        upsert_live_connection(
            &connections,
            through_jump,
            Some(&endpoint.password),
            None,
            Some(&jump.password),
        )?;

        assert_live_exec_and_optional_pty(&ssh, "live-password", true).await?;
        assert_live_exec_and_optional_pty(&ssh, "live-public-key", false).await?;
        assert_live_exec_and_optional_pty(&ssh, "live-agent", false).await?;
        assert_live_exec_and_optional_pty(&ssh, "live-jump", false).await?;
        assert!(ssh.list_sessions().await?.is_empty());
        drop(ssh);
        let _ = std::fs::remove_dir_all(local_root);
        Ok(())
    }

    /// One agent connection: identities and sign requests, the two messages
    /// a login uses. Unlike russh's own agent server, which always signs RSA
    /// with SHA-1, this honours the rsa-sha2-256/512 flags the way OpenSSH's
    /// agent (and Windows') does — so it tests the client, not a weaker agent.
    #[cfg(windows)]
    async fn serve_test_agent_connection<S>(
        mut stream: S,
        keys: Arc<Vec<Arc<russh::keys::PrivateKey>>>,
    ) -> std::io::Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        use russh::keys::HashAlg;
        use russh::keys::signature::Signer as _;
        use russh::keys::ssh_encoding::{Decode as _, Encode as _};
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        const FAILURE: u8 = 5;
        const REQUEST_IDENTITIES: u8 = 11;
        const IDENTITIES_ANSWER: u8 = 12;
        const SIGN_REQUEST: u8 = 13;
        const SIGN_RESPONSE: u8 = 14;
        const RSA_SHA2_256: u32 = 2;
        const RSA_SHA2_512: u32 = 4;
        loop {
            let length = match stream.read_u32().await {
                Ok(length) => length as usize,
                Err(_) => return Ok(()),
            };
            let mut body = vec![0; length];
            stream.read_exact(&mut body).await?;
            let mut reply = Vec::new();
            match body.split_first() {
                Some((&REQUEST_IDENTITIES, _)) => {
                    reply.push(IDENTITIES_ANSWER);
                    (keys.len() as u32).encode(&mut reply).unwrap();
                    for key in keys.iter() {
                        key.public_key()
                            .to_bytes()
                            .unwrap()
                            .as_slice()
                            .encode(&mut reply)
                            .unwrap();
                        "lovelyhawk-test".encode(&mut reply).unwrap();
                    }
                }
                Some((&SIGN_REQUEST, mut rest)) => {
                    let blob = Vec::<u8>::decode(&mut rest).unwrap();
                    let data = Vec::<u8>::decode(&mut rest).unwrap();
                    let flags = u32::decode(&mut rest).unwrap();
                    let key = keys
                        .iter()
                        .find(|key| key.public_key().to_bytes().unwrap() == blob);
                    match key {
                        Some(key) => {
                            let hash = if !key.algorithm().is_rsa() {
                                None
                            } else if flags & RSA_SHA2_512 != 0 {
                                Some(HashAlg::Sha512)
                            } else if flags & RSA_SHA2_256 != 0 {
                                Some(HashAlg::Sha256)
                            } else {
                                None
                            };
                            let signature = PrivateKeyWithHashAlg::new(key.clone(), hash)
                                .try_sign(&data)
                                .unwrap();
                            reply.push(SIGN_RESPONSE);
                            signature
                                .encode_vec()
                                .unwrap()
                                .as_slice()
                                .encode(&mut reply)
                                .unwrap();
                        }
                        None => reply.push(FAILURE),
                    }
                }
                _ => reply.push(FAILURE),
            }
            stream.write_u32(reply.len() as u32).await?;
            stream.write_all(&reply).await?;
        }
    }

    /// Serves an SSH agent holding `keys` on the pipe the client looks for,
    /// for as long as the returned task runs. The pipe must be free: a real
    /// agent already listening would answer instead, and the test would no
    /// longer know which keys it holds.
    #[cfg(windows)]
    fn host_test_agent(
        keys: Vec<russh::keys::PrivateKey>,
    ) -> CoreResult<tokio::task::JoinHandle<()>> {
        use tokio::net::windows::named_pipe::ServerOptions;
        const PIPE: &str = r"\\.\pipe\openssh-ssh-agent";
        let mut server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(PIPE)
            .map_err(|error| {
                CoreError::ssh(
                    "test agent",
                    format!("{PIPE} is already served by another agent: {error}"),
                )
            })?;
        let keys = Arc::new(keys.into_iter().map(Arc::new).collect::<Vec<_>>());
        Ok(tokio::spawn(async move {
            loop {
                if server.connect().await.is_err() {
                    return;
                }
                let connected = server;
                server = match ServerOptions::new().create(PIPE) {
                    Ok(next) => next,
                    Err(_) => return,
                };
                tokio::spawn(serve_test_agent_connection(connected, keys.clone()));
            }
        }))
    }

    /// Every way the connection editor offers to log in, against one real
    /// OpenSSH target and a bastion in front of it.
    ///
    /// Uses the `LOVELYHAWK_TEST_SSH_*` and `LOVELYHAWK_TEST_SSH_JUMP_*`
    /// endpoints of the end-to-end contract, plus
    /// `LOVELYHAWK_TEST_SSH_MATRIX_DIR` holding `id_ed25519` (protected by
    /// `LOVELYHAWK_TEST_SSH_MATRIX_KEY_PASSPHRASE`), `id_ecdsa`, `id_rsa`,
    /// `cert_ed25519` and `cert_rsa` with their `-cert.pub` (signed by a CA in
    /// the target's TrustedUserCAKeys, the keys themselves not authorised),
    /// and `agent_ed25519` / `agent_rsa` (authorised; on Windows the test
    /// serves its own agent with them on the OpenSSH pipe).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "release gate: requires the disposable login-method lab (key, certificate, agent, jump)"]
    async fn live_openssh_every_login_method() -> CoreResult<()> {
        let endpoint = LiveEndpoint::from_prefix("LOVELYHAWK_TEST_SSH");
        let jump = LiveEndpoint::from_prefix("LOVELYHAWK_TEST_SSH_JUMP");
        let dir = PathBuf::from(live_required("LOVELYHAWK_TEST_SSH_MATRIX_DIR"));
        assert!(
            dir.is_absolute(),
            "LOVELYHAWK_TEST_SSH_MATRIX_DIR must be absolute"
        );
        let passphrase = live_required("LOVELYHAWK_TEST_SSH_MATRIX_KEY_PASSPHRASE");
        let (local_root, _store, connections, ssh) = live_service("openssh-login-methods")?;

        let read_key = |name: &str| -> russh::keys::PrivateKey {
            let text = std::fs::read_to_string(dir.join(name)).expect("matrix key is readable");
            russh::keys::decode_secret_key(&text, None).expect("matrix agent key decodes")
        };
        let agent_keys = [read_key("agent_ed25519"), read_key("agent_rsa")];
        let agent_fingerprints = agent_keys
            .iter()
            .map(|key| fingerprint(key.public_key()))
            .collect::<Vec<_>>();
        #[cfg(windows)]
        let agent_task = host_test_agent(agent_keys.to_vec())?;

        let mut cases: Vec<(&str, bool)> = Vec::new();
        let password = endpoint.connection("m-password", SshAuthMethod::Password);
        upsert_live_connection(&connections, password, Some(&endpoint.password), None, None)?;
        cases.push(("m-password", true));

        for (id, file, key_passphrase) in [
            (
                "m-ed25519-passphrase",
                "id_ed25519",
                Some(passphrase.as_str()),
            ),
            ("m-ecdsa", "id_ecdsa", None),
            ("m-rsa", "id_rsa", None),
        ] {
            let mut config = endpoint.connection(id, SshAuthMethod::PublicKey);
            config.private_key_path = Some(dir.join(file));
            upsert_live_connection(&connections, config, None, key_passphrase, None)?;
            cases.push((id, false));
        }
        let certificate = |endpoint: &LiveEndpoint, id: &str, file: &str| {
            let mut config = endpoint.connection(id, SshAuthMethod::Certificate);
            config.private_key_path = Some(dir.join(file));
            config.certificate_path = Some(dir.join(format!("{file}-cert.pub")));
            config
        };
        upsert_live_connection(
            &connections,
            certificate(&endpoint, "m-cert-ed25519", "cert_ed25519"),
            None,
            None,
            None,
        )?;
        cases.push(("m-cert-ed25519", false));
        // An RSA certificate against OpenSSH 8.8+: refused, and saying why.
        upsert_live_connection(
            &connections,
            certificate(&endpoint, "m-cert-rsa-modern", "cert_rsa"),
            None,
            None,
            None,
        )?;
        // …and against an OpenSSH that still takes ssh-rsa-cert-v01: accepted.
        let legacy = live_optional("LOVELYHAWK_TEST_SSH_LEGACY_HOST")
            .map(|_| LiveEndpoint::from_prefix("LOVELYHAWK_TEST_SSH_LEGACY"));
        if let Some(legacy) = &legacy {
            upsert_live_connection(
                &connections,
                certificate(legacy, "m-cert-rsa-legacy", "cert_rsa"),
                None,
                None,
                None,
            )?;
            cases.push(("m-cert-rsa-legacy", false));
        }
        for (id, fingerprint) in [
            ("m-agent-ed25519", &agent_fingerprints[0]),
            ("m-agent-rsa", &agent_fingerprints[1]),
        ] {
            let mut config = endpoint.connection(id, SshAuthMethod::Agent);
            config.agent_identity_fingerprint = Some(fingerprint.clone());
            upsert_live_connection(&connections, config, None, None, None)?;
            cases.push((id, false));
        }
        let mut through_jump = endpoint.connection("m-jump", SshAuthMethod::Password);
        through_jump.jump_host = Some(JumpHostConfig {
            host: jump.host,
            port: jump.port,
            username: jump.username,
            auth_method: SshAuthMethod::Password,
            private_key_path: None,
            certificate_path: None,
            agent_identity_fingerprint: None,
            host_key_fingerprint: Some(jump.fingerprint),
        });
        upsert_live_connection(
            &connections,
            through_jump,
            Some(&endpoint.password),
            None,
            Some(&jump.password),
        )?;
        cases.push(("m-jump", true));

        let mut failures = Vec::new();
        for (id, pty) in cases {
            if let Err(error) = assert_live_exec_and_optional_pty(&ssh, id, pty).await {
                failures.push(format!("{id}: {error}"));
            } else {
                println!("login method ok: {id}");
            }
        }
        match ssh
            .connect("m-cert-rsa-modern", HostKeyConfirmations::default())
            .await
        {
            Ok(status) => {
                let _ = ssh.disconnect(&status.session_id).await;
                failures.push(
                    "m-cert-rsa-modern: OpenSSH 8.8+ accepted a SHA-1 RSA certificate".to_owned(),
                );
            }
            Err(error) if error.to_string().contains("SHA-1") => {
                println!("login method refused as expected: m-cert-rsa-modern ({error})");
            }
            Err(error) => failures.push(format!("m-cert-rsa-modern: unexplained refusal: {error}")),
        }
        if legacy.is_none() {
            println!("login method not run: m-cert-rsa-legacy (no LOVELYHAWK_TEST_SSH_LEGACY_*)");
        }
        #[cfg(windows)]
        agent_task.abort();
        assert!(ssh.list_sessions().await?.is_empty());
        drop(ssh);
        let _ = std::fs::remove_dir_all(local_root);
        assert!(
            failures.is_empty(),
            "login methods that failed:\n{}",
            failures.join("\n")
        );
        Ok(())
    }

    /// Release VM keyboard-interactive/MFA contract.
    ///
    /// Required variables are `LOVELYHAWK_TEST_SSH_MFA_{HOST,PORT,USERNAME,HOST_KEY}` and
    /// `LOVELYHAWK_TEST_SSH_MFA_RESPONSES_JSON`. The latter is a JSON string array in exact
    /// server prompt order. The account and every supplied factor must be disposable.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "release gate: requires a real OpenSSH keyboard-interactive/MFA account"]
    async fn live_openssh_keyboard_interactive_contract() -> CoreResult<()> {
        let required = |suffix: &str| live_required(&format!("LOVELYHAWK_TEST_SSH_MFA_{suffix}"));
        let port = required("PORT")
            .parse::<u16>()
            .expect("LOVELYHAWK_TEST_SSH_MFA_PORT must be a non-zero u16");
        assert_ne!(port, 0, "LOVELYHAWK_TEST_SSH_MFA_PORT must be non-zero");
        let config = ConnectionConfig {
            id: "live-keyboard-interactive".to_owned(),
            name: "Release VM keyboard-interactive".to_owned(),
            host: required("HOST"),
            port,
            username: required("USERNAME"),
            auth_method: SshAuthMethod::KeyboardInteractive,
            private_key_path: None,
            certificate_path: None,
            agent_identity_fingerprint: None,
            jump_host: None,
            tags: BTreeSet::new(),
            notes: Some("disposable MFA release-gate VM only".to_owned()),
            environment: Some("release-vm".to_owned()),
            role: Some("compatibility-contract".to_owned()),
            group: None,
            host_key_fingerprint: Some(required("HOST_KEY")),
        };
        let responses_json = SecretValue::new(required("RESPONSES_JSON"));
        let responses = serde_json::from_str::<Vec<String>>(responses_json.expose())
            .expect("LOVELYHAWK_TEST_SSH_MFA_RESPONSES_JSON must be a JSON string array");
        assert!(
            !responses.is_empty() && responses.len() <= MAX_KEYBOARD_INTERACTIVE_RESPONSES,
            "MFA response fixture must contain 1..=32 responses"
        );

        let (local_root, _store, connections, ssh) = live_service("openssh-mfa")?;
        upsert_live_connection(&connections, config, None, None, None)?;
        let mut authorization = SshConnectAuthorization::default();
        authorization.extend_keyboard_interactive_responses(
            SshHostRole::Target,
            responses.into_iter().map(SecretValue::new).collect(),
        )?;
        let status = ssh
            .connect_authorized("live-keyboard-interactive", authorization)
            .await?;
        let target = crate::target::TargetContext::new();
        let guard = target.activate(TargetIdentity::new("live-keyboard-interactive")?)?;
        let bound = ssh.bind_session(guard, &status.session_id).await?;
        let marker = "lovelyres-keyboard-interactive-ok";
        let output = ssh
            .execute_bound(
                &bound,
                format!("printf '%s\\n' {}", crate::shell_escape::shq(marker)),
                Duration::from_secs(10),
            )
            .await?;
        let result = if output.exit_code == Some(0) && output.output.contains(marker) {
            Ok(())
        } else {
            Err(CoreError::ssh(
                "release VM keyboard-interactive contract",
                "connected account did not return its exec marker",
            ))
        };
        let disconnect = ssh.disconnect(&status.session_id).await;
        result?;
        disconnect?;
        drop(ssh);
        let _ = std::fs::remove_dir_all(local_root);
        Ok(())
    }

    /// Release VM disconnect contract.
    ///
    /// Besides the direct target variables, the harness must provide absolute, initially absent
    /// `LOVELYHAWK_TEST_DISCONNECT_{READY,OBSERVED,RESUME}_FILE` paths. It watches `READY`, cuts
    /// the existing transport, waits for `OBSERVED`, restores the same host/key, then writes the
    /// run token into `RESUME`. This test verifies bounded detection, bounded service shutdown,
    /// and a real post-restart reconnect.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "release gate: requires an externally interrupted and restarted OpenSSH VM"]
    async fn live_openssh_disconnect_shutdown_and_reconnect_contract() -> CoreResult<()> {
        let endpoint = LiveEndpoint::from_prefix("LOVELYHAWK_TEST_SSH");
        let ready = PathBuf::from(live_required("LOVELYHAWK_TEST_DISCONNECT_READY_FILE"));
        let observed = PathBuf::from(live_required("LOVELYHAWK_TEST_DISCONNECT_OBSERVED_FILE"));
        let resume = PathBuf::from(live_required("LOVELYHAWK_TEST_DISCONNECT_RESUME_FILE"));
        for (name, path) in [
            ("LOVELYHAWK_TEST_DISCONNECT_READY_FILE", &ready),
            ("LOVELYHAWK_TEST_DISCONNECT_OBSERVED_FILE", &observed),
            ("LOVELYHAWK_TEST_DISCONNECT_RESUME_FILE", &resume),
        ] {
            assert!(path.is_absolute(), "{name} must be absolute");
            assert!(!path.exists(), "{name} must be absent before the test");
            assert!(
                path.parent().is_some_and(Path::is_dir),
                "{name} parent directory must exist"
            );
        }
        let disconnect_bound = live_optional("LOVELYHAWK_TEST_DISCONNECT_BOUND_SECS")
            .unwrap_or_else(|| "20".to_owned())
            .parse::<u64>()
            .expect("LOVELYHAWK_TEST_DISCONNECT_BOUND_SECS must be a positive integer");
        let restart_bound = live_optional("LOVELYHAWK_TEST_DISCONNECT_RESTART_SECS")
            .unwrap_or_else(|| "60".to_owned())
            .parse::<u64>()
            .expect("LOVELYHAWK_TEST_DISCONNECT_RESTART_SECS must be a positive integer");
        assert!(disconnect_bound > 0 && restart_bound > 0);

        let (local_root, _store, connections, ssh) = live_service("openssh-disconnect")?;
        let config = endpoint.connection("live-disconnect", SshAuthMethod::Password);
        upsert_live_connection(&connections, config, Some(&endpoint.password), None, None)?;
        let status = ssh
            .connect("live-disconnect", HostKeyConfirmations::default())
            .await?;
        let target = crate::target::TargetContext::new();
        let guard = target.activate(TargetIdentity::new("live-disconnect")?)?;
        let bound = ssh.bind_session(guard, &status.session_id).await?;
        let run_token = uuid::Uuid::new_v4().to_string();
        std::fs::write(&ready, &run_token)
            .map_err(|source| CoreError::io("write disconnect ready token", &ready, source))?;

        let interrupted = tokio::time::timeout(
            Duration::from_secs(disconnect_bound),
            ssh.execute_bound(
                &bound,
                "printf 'lovelyres-disconnect-start\\n'; sleep 120; printf 'must-not-finish\\n'"
                    .to_owned(),
                Duration::from_secs(180),
            ),
        )
        .await
        .map_err(|_| {
            CoreError::ssh(
                "release VM disconnect contract",
                "external transport loss was not observed within the configured bound",
            )
        })?;
        if let Ok(output) = interrupted
            && !output.timed_out
            && output.exit_code == Some(0)
        {
            return Err(CoreError::ssh(
                "release VM disconnect contract",
                "the interrupted command unexpectedly completed successfully",
            ));
        }
        let _disconnect_result =
            tokio::time::timeout(Duration::from_secs(5), ssh.disconnect(&status.session_id))
                .await
                .map_err(|_| {
                    CoreError::ssh(
                        "release VM disconnect contract",
                        "disconnect bookkeeping exceeded five seconds",
                    )
                })?;
        assert!(ssh.list_sessions().await?.is_empty());
        std::fs::write(&observed, &run_token).map_err(|source| {
            CoreError::io("write disconnect observed token", &observed, source)
        })?;

        tokio::time::timeout(Duration::from_secs(restart_bound), async {
            loop {
                if std::fs::read_to_string(&resume).ok().as_deref() == Some(run_token.as_str()) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .map_err(|_| {
            CoreError::ssh(
                "release VM reconnect contract",
                "harness did not restore the VM and echo the run token in time",
            )
        })?;

        let reconnect = ssh
            .connect("live-disconnect", HostKeyConfirmations::default())
            .await?;
        let target = crate::target::TargetContext::new();
        let guard = target.activate(TargetIdentity::new("live-disconnect")?)?;
        let rebound = ssh.bind_session(guard, &reconnect.session_id).await?;
        let output = ssh
            .execute_bound(
                &rebound,
                "printf 'lovelyres-reconnected\\n'".to_owned(),
                Duration::from_secs(10),
            )
            .await?;
        if output.timed_out
            || output.exit_code != Some(0)
            || !output.output.contains("lovelyres-reconnected")
        {
            return Err(CoreError::ssh(
                "release VM reconnect contract",
                "reconnected session did not execute the probe",
            ));
        }
        drop(rebound);
        let shutdown_started = std::time::Instant::now();
        drop(ssh);
        assert!(
            shutdown_started.elapsed() < Duration::from_millis(100),
            "dropping a live SSH service must not block the caller"
        );
        tokio::time::sleep(Duration::from_millis(750)).await;
        for marker in [&ready, &observed, &resume] {
            let _ = std::fs::remove_file(marker);
        }
        let _ = std::fs::remove_dir_all(local_root);
        Ok(())
    }

    /// Release VM host-key rotation contract. The stale pin must be different from the real
    /// `LOVELYHAWK_TEST_SSH_HOST_KEY`; the structured rejection must expose both values and the
    /// repository must retain the stale pin rather than silently trusting the observed key.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "release gate: requires a real OpenSSH endpoint and a deliberately stale pin"]
    async fn live_openssh_stale_host_key_fails_closed_without_repinning() -> CoreResult<()> {
        let endpoint = LiveEndpoint::from_prefix("LOVELYHAWK_TEST_SSH");
        let stale = live_required("LOVELYHAWK_TEST_SSH_STALE_HOST_KEY");
        assert_ne!(
            stale, endpoint.fingerprint,
            "LOVELYHAWK_TEST_SSH_STALE_HOST_KEY must differ from the live host key"
        );
        let (local_root, _store, connections, ssh) = live_service("openssh-stale-key")?;
        let mut config = endpoint.connection("live-stale-key", SshAuthMethod::Password);
        config.host_key_fingerprint = Some(stale.clone());
        upsert_live_connection(&connections, config, Some(&endpoint.password), None, None)?;

        let error = ssh
            .connect("live-stale-key", HostKeyConfirmations::default())
            .await
            .expect_err("a stale host-key pin must reject the live server");
        match error {
            CoreError::SshHostKeyChanged {
                role,
                host,
                port,
                expected,
                observed,
            } => {
                assert_eq!(role, SshHostRole::Target);
                assert_eq!(host, endpoint.host);
                assert_eq!(port, endpoint.port);
                assert_eq!(expected, stale);
                assert_eq!(observed, endpoint.fingerprint);
            }
            other => panic!("expected structured host-key change rejection, got {other:?}"),
        }
        assert!(ssh.list_sessions().await?.is_empty());
        let persisted = connections
            .get("live-stale-key")?
            .expect("stale-key fixture must remain present");
        assert_eq!(
            persisted.config.host_key_fingerprint.as_deref(),
            Some(stale.as_str())
        );
        drop(ssh);
        let _ = std::fs::remove_dir_all(local_root);
        Ok(())
    }

    /// Release VM restricted-account contract. The separate
    /// `LOVELYHAWK_TEST_RESTRICTED_SSH_{HOST,PORT,USERNAME,PASSWORD,HOST_KEY}` account must
    /// authenticate but force/reject exec requests with a non-zero status. It must never run the
    /// requested unique payload.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "release gate: requires a forced-command/restricted OpenSSH account"]
    async fn live_openssh_restricted_account_fails_closed() -> CoreResult<()> {
        let endpoint = LiveEndpoint::from_prefix("LOVELYHAWK_TEST_RESTRICTED_SSH");
        let (local_root, _store, connections, ssh) = live_service("openssh-restricted")?;
        let config = endpoint.connection("live-restricted", SshAuthMethod::Password);
        upsert_live_connection(&connections, config, Some(&endpoint.password), None, None)?;
        let status = ssh
            .connect("live-restricted", HostKeyConfirmations::default())
            .await?;
        let target = crate::target::TargetContext::new();
        let guard = target.activate(TargetIdentity::new("live-restricted")?)?;
        let bound = ssh.bind_session(guard, &status.session_id).await?;
        let forbidden_marker = format!("lovelyres-must-not-run-{}", uuid::Uuid::new_v4());
        let result = ssh
            .execute_bound(
                &bound,
                format!(
                    "printf '%s' {}",
                    crate::shell_escape::shq(&forbidden_marker)
                ),
                Duration::from_secs(10),
            )
            .await;
        if let Ok(output) = result {
            assert!(
                !output.output.contains(&forbidden_marker),
                "restricted account executed the caller-supplied payload"
            );
            assert!(
                output.timed_out || output.exit_code != Some(0),
                "restricted account must return a failing receipt"
            );
        }
        ssh.disconnect(&status.session_id).await?;
        assert!(ssh.list_sessions().await?.is_empty());
        drop(ssh);
        let _ = std::fs::remove_dir_all(local_root);
        Ok(())
    }
}
