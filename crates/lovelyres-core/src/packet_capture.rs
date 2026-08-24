//! Target-bound packet capture with bounded live events and verifiable PCAP evidence.

use std::{io::Read, path::Path, sync::Arc, time::Duration};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::domain::CommandRunner;
use crate::events::{
    EventChannelDefaults, PacketCaptureEvent, PacketCaptureEventKind, PacketCaptureEventReceiver,
    PacketCaptureEventSender, TerminalEventKind, TerminalTransport, packet_capture_event_channel,
};
use crate::path_guard::PathGuard;
use crate::sftp::{RemotePath, SftpService};
use crate::shell_escape::shq;
use crate::ssh::{
    BoundSshSession, PacketCapturePtyRequest, SshCommandOutput, SshService, SshTerminalSession,
};
use crate::target::{TargetContext, TargetGuard};
use crate::{CoreError, CoreResult};

pub const MAX_PCAP_CAPTURE_SECONDS: u32 = 300;
pub const MAX_PCAP_PACKET_COUNT: u32 = 100_000;
pub const MAX_PCAP_EVIDENCE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const PCAP_RESULT_MARKER: &str = "LOVELYRES_PCAP_V1";
const PCAP_REMOTE_PREFIX: &str = "/tmp/lovelyres-pcap-";
const MAX_PACKET_LINE_BYTES: usize = 16 * 1024;
const MAX_INTERFACE_OUTPUT_BYTES: usize = 256 * 1024;
const LIVE_CAPTURE_GRACE_SECONDS: u64 = 15;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PacketEntry {
    pub id: usize,
    pub timestamp: String,
    pub protocol: String,
    pub src: String,
    pub dst: String,
    pub length: String,
    pub info: String,
    pub raw: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkInterface {
    pub name: String,
    pub index: u32,
    pub mac: Option<String>,
    pub ips: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PcapCaptureRequest {
    pub interface: String,
    pub filter: Option<String>,
    pub packet_limit: Option<u32>,
    pub duration_seconds: u32,
}

impl PcapCaptureRequest {
    pub fn validate(&self) -> CoreResult<()> {
        validate_interface(&self.interface)?;
        validate_filter(self.filter.as_deref())?;
        if !(1..=MAX_PCAP_CAPTURE_SECONDS).contains(&self.duration_seconds) {
            return Err(CoreError::validation(
                "PCAP duration",
                format!("must be 1..={MAX_PCAP_CAPTURE_SECONDS} seconds"),
            ));
        }
        if self
            .packet_limit
            .is_some_and(|count| count == 0 || count > MAX_PCAP_PACKET_COUNT)
        {
            return Err(CoreError::validation(
                "PCAP packet limit",
                format!("must be 1..={MAX_PCAP_PACKET_COUNT}"),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PcapCapturePlan {
    pub request: PcapCaptureRequest,
    pub remote_path: String,
    pub command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemotePcapMetadata {
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiedPcapArtifact {
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemotePcapArtifact {
    pub capture_id: String,
    pub request: PcapCaptureRequest,
    pub remote_path: String,
    pub metadata: RemotePcapMetadata,
    pub captured_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PcapEvidenceReceipt {
    pub capture_id: String,
    pub local_path: std::path::PathBuf,
    pub request: PcapCaptureRequest,
    pub size_bytes: u64,
    pub sha256: String,
    pub captured_at: DateTime<Utc>,
    pub remote_cleanup_verified: bool,
}

#[derive(Debug)]
pub struct LivePacketCapture {
    capture_id: String,
    target: TargetGuard,
    terminal: Arc<SshTerminalSession>,
    events: PacketCaptureEventReceiver,
}

impl LivePacketCapture {
    pub fn capture_id(&self) -> &str {
        &self.capture_id
    }

    pub fn target(&self) -> &TargetGuard {
        &self.target
    }

    pub fn events(&self) -> &PacketCaptureEventReceiver {
        &self.events
    }

    pub async fn recv(&self) -> CoreResult<PacketCaptureEvent> {
        self.events.recv().await
    }

    pub async fn stop(&self) -> CoreResult<()> {
        self.terminal.close().await
    }

    pub fn request_stop(&self) {
        self.terminal.request_close();
    }
}

impl Drop for LivePacketCapture {
    fn drop(&mut self) {
        self.terminal.request_close();
    }
}

#[derive(Debug, Clone)]
pub struct PacketCaptureService {
    ssh: SshService,
    target: Arc<TargetContext>,
}

impl PacketCaptureService {
    pub fn new(ssh: SshService, target: Arc<TargetContext>) -> Self {
        Self { ssh, target }
    }

    pub fn plan(request: PcapCaptureRequest) -> CoreResult<PcapCapturePlan> {
        request.validate()?;
        let remote_path = new_remote_pcap_path();
        let command = generate_pcap_evidence_command(&request, &remote_path)?;
        Ok(PcapCapturePlan {
            request,
            remote_path,
            command,
        })
    }

    pub fn capture_with_runner(
        runner: &dyn CommandRunner,
        plan: &PcapCapturePlan,
    ) -> CoreResult<RemotePcapMetadata> {
        plan.request.validate()?;
        if !is_managed_remote_pcap_path(&plan.remote_path) {
            return Err(CoreError::validation(
                "remote PCAP path",
                "path is outside the LovelyRes-managed namespace",
            ));
        }
        let output = runner.run(&plan.command)?;
        let stdout = output.into_stdout("packet capture")?;
        parse_pcap_evidence_output(&stdout)
    }

    /// Verify SFTP-downloaded evidence before it is accepted into a case.
    pub fn verify_download(
        bytes: &[u8],
        remote: &RemotePcapMetadata,
    ) -> CoreResult<VerifiedPcapArtifact> {
        let actual_size = u64::try_from(bytes.len()).map_err(|_| {
            CoreError::validation("PCAP artifact", "local artifact length does not fit u64")
        })?;
        let actual_hash = format!("{:x}", Sha256::digest(bytes));
        if actual_size != remote.size_bytes || actual_hash != remote.sha256 {
            return Err(CoreError::validation(
                "PCAP evidence integrity",
                format!(
                    "expected {} bytes/{}, got {} bytes/{}",
                    remote.size_bytes, remote.sha256, actual_size, actual_hash
                ),
            ));
        }
        Ok(VerifiedPcapArtifact {
            size_bytes: actual_size,
            sha256: actual_hash,
        })
    }

    pub fn verify_downloaded_file(
        path: &Path,
        remote: &RemotePcapMetadata,
    ) -> CoreResult<VerifiedPcapArtifact> {
        let mut file = std::fs::File::open(path)
            .map_err(|source| CoreError::io("open downloaded PCAP", path, source))?;
        let metadata = file
            .metadata()
            .map_err(|source| CoreError::io("inspect downloaded PCAP", path, source))?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_PCAP_EVIDENCE_BYTES {
            return Err(CoreError::validation(
                "downloaded PCAP",
                format!("must be a regular file of 1..={MAX_PCAP_EVIDENCE_BYTES} bytes"),
            ));
        }
        if metadata.len() != remote.size_bytes {
            return Err(CoreError::validation(
                "PCAP evidence integrity",
                format!(
                    "expected {} bytes, downloaded {} bytes",
                    remote.size_bytes,
                    metadata.len()
                ),
            ));
        }
        let mut digest = Sha256::new();
        let mut bytes_read = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = file
                .read(&mut buffer)
                .map_err(|source| CoreError::io("hash downloaded PCAP", path, source))?;
            if count == 0 {
                break;
            }
            bytes_read = bytes_read.saturating_add(count as u64);
            if bytes_read > MAX_PCAP_EVIDENCE_BYTES {
                return Err(CoreError::validation(
                    "downloaded PCAP",
                    "file grew beyond the evidence limit while hashing",
                ));
            }
            digest.update(&buffer[..count]);
        }
        let actual_hash = format!("{:x}", digest.finalize());
        if bytes_read != remote.size_bytes || actual_hash != remote.sha256 {
            return Err(CoreError::validation(
                "PCAP evidence integrity",
                format!(
                    "expected {} bytes/{}, got {} bytes/{}",
                    remote.size_bytes, remote.sha256, bytes_read, actual_hash
                ),
            ));
        }
        Ok(VerifiedPcapArtifact {
            size_bytes: bytes_read,
            sha256: actual_hash,
        })
    }

    pub fn cleanup_command(remote_path: &str) -> CoreResult<String> {
        if !is_managed_remote_pcap_path(remote_path) {
            return Err(CoreError::validation(
                "remote PCAP path",
                "refuses to remove an unmanaged path",
            ));
        }
        Ok(format!("rm -f -- {}", shq(remote_path)))
    }

    pub async fn list_interfaces(
        &self,
        session: &BoundSshSession,
    ) -> CoreResult<Vec<NetworkInterface>> {
        self.target.validate(session.target())?;
        let output = self
            .ssh
            .execute_bound(
                session,
                generate_list_interfaces_command().to_owned(),
                Duration::from_secs(15),
            )
            .await?;
        self.target.validate(session.target())?;
        validate_ssh_output("network interfaces", &output, MAX_INTERFACE_OUTPUT_BYTES)?;
        parse_network_interfaces(&output.output)
    }

    pub async fn start_live(
        &self,
        session: &BoundSshSession,
        request: PcapCaptureRequest,
    ) -> CoreResult<LivePacketCapture> {
        request.validate()?;
        self.target.validate(session.target())?;
        let capture_id = format!("pcap-{}", uuid::Uuid::new_v4().simple());
        let command = generate_live_capture_command(&request)?;
        let terminal = Arc::new(
            self.ssh
                .open_packet_capture_bound(
                    session,
                    PacketCapturePtyRequest::new(capture_id.clone(), command)?,
                )
                .await?,
        );
        if let Err(error) = self.target.validate(session.target()) {
            terminal.request_close();
            return Err(error);
        }
        let (sender, events) =
            packet_capture_event_channel(EventChannelDefaults::default().packet_capture)?;
        let pump_terminal = terminal.clone();
        let pump_target = self.target.clone();
        let guard = session.target().clone();
        let pump_capture_id = capture_id.clone();
        let interface = request.interface.clone();
        tokio::spawn(async move {
            pump_live_capture(
                pump_capture_id,
                interface,
                guard,
                pump_target,
                pump_terminal,
                sender,
            )
            .await;
        });
        Ok(LivePacketCapture {
            capture_id,
            target: session.target().clone(),
            terminal,
            events,
        })
    }

    pub async fn capture_evidence_remote(
        &self,
        session: &BoundSshSession,
        request: PcapCaptureRequest,
    ) -> CoreResult<RemotePcapArtifact> {
        let plan = Self::plan(request)?;
        self.target.validate(session.target())?;
        let timeout = Duration::from_secs(
            u64::from(plan.request.duration_seconds) + LIVE_CAPTURE_GRACE_SECONDS,
        );
        let output = self
            .ssh
            .execute_bound(session, plan.command.clone(), timeout)
            .await?;
        if let Err(error) = self.target.validate(session.target()) {
            let _ = self
                .cleanup_remote_artifact(session, &plan.remote_path)
                .await;
            return Err(error);
        }
        if let Err(error) = validate_ssh_output("PCAP evidence capture", &output, 64 * 1024) {
            let _ = self
                .cleanup_remote_artifact(session, &plan.remote_path)
                .await;
            return Err(error);
        }
        let metadata = match parse_pcap_evidence_output(&output.output) {
            Ok(metadata) => metadata,
            Err(error) => {
                let _ = self
                    .cleanup_remote_artifact(session, &plan.remote_path)
                    .await;
                return Err(error);
            }
        };
        Ok(RemotePcapArtifact {
            capture_id: format!("pcap-evidence-{}", uuid::Uuid::new_v4().simple()),
            request: plan.request,
            remote_path: plan.remote_path,
            metadata,
            captured_at: Utc::now(),
        })
    }

    pub async fn cleanup_remote(
        &self,
        session: &BoundSshSession,
        remote_path: &str,
    ) -> CoreResult<()> {
        self.target.validate(session.target())?;
        self.cleanup_remote_artifact(session, remote_path).await?;
        self.target.validate(session.target())?;
        Ok(())
    }

    pub async fn capture_evidence_to_path(
        &self,
        sftp: &SftpService,
        paths: &PathGuard,
        session: &BoundSshSession,
        request: PcapCaptureRequest,
        selected_target: &Path,
    ) -> CoreResult<PcapEvidenceReceipt> {
        let artifact = self.capture_evidence_remote(session, request).await?;
        let remote_path = RemotePath::new(artifact.remote_path.clone())?;
        let sftp_session = match sftp
            .bind_session(session.target().clone(), session.session_id())
            .await
        {
            Ok(session) => session,
            Err(error) => {
                let _ = self
                    .cleanup_remote_artifact(session, &artifact.remote_path)
                    .await;
                return Err(error);
            }
        };
        let transfer = sftp
            .download_new(&sftp_session, paths, &remote_path, selected_target)
            .await;
        let receipt = match transfer {
            Ok(receipt) => receipt,
            Err(error) => {
                let _ = self
                    .cleanup_remote_artifact(session, &artifact.remote_path)
                    .await;
                return Err(error);
            }
        };
        let Some(local_path) = receipt.local_path else {
            let _ = self
                .cleanup_remote_artifact(session, &artifact.remote_path)
                .await;
            return Err(CoreError::validation(
                "PCAP evidence download",
                "download completed without a local path",
            ));
        };
        let verified = match Self::verify_downloaded_file(&local_path, &artifact.metadata) {
            Ok(verified) => verified,
            Err(error) => {
                let _ = std::fs::remove_file(&local_path);
                let _ = self
                    .cleanup_remote_artifact(session, &artifact.remote_path)
                    .await;
                return Err(error);
            }
        };
        let remote_cleanup_verified = self
            .cleanup_remote_artifact(session, &artifact.remote_path)
            .await
            .is_ok();
        if let Err(error) = self.target.validate(session.target()) {
            let _ = std::fs::remove_file(&local_path);
            return Err(error);
        }
        Ok(PcapEvidenceReceipt {
            capture_id: artifact.capture_id,
            local_path,
            request: artifact.request,
            size_bytes: verified.size_bytes,
            sha256: verified.sha256,
            captured_at: artifact.captured_at,
            remote_cleanup_verified,
        })
    }

    async fn cleanup_remote_artifact(
        &self,
        session: &BoundSshSession,
        remote_path: &str,
    ) -> CoreResult<()> {
        let command = Self::cleanup_command(remote_path)?;
        let output = self
            .ssh
            .execute_bound(session, command, Duration::from_secs(15))
            .await?;
        validate_ssh_output("PCAP cleanup", &output, 64 * 1024)
    }
}

fn validate_ssh_output(
    subject: &'static str,
    output: &SshCommandOutput,
    maximum_bytes: usize,
) -> CoreResult<()> {
    if output.timed_out || output.exit_code.is_some_and(|code| code != 0) {
        return Err(CoreError::validation(
            subject,
            format!(
                "remote command failed (exit={:?}, timed_out={})",
                output.exit_code, output.timed_out
            ),
        ));
    }
    if output.output.len() > maximum_bytes {
        return Err(CoreError::validation(
            subject,
            format!("remote output exceeds {maximum_bytes} bytes"),
        ));
    }
    Ok(())
}

fn parse_network_interfaces(output: &str) -> CoreResult<Vec<NetworkInterface>> {
    let mut interfaces = Vec::<NetworkInterface>::new();
    for line in output.lines().take(256) {
        let mut fields = line.splitn(3, '|');
        let Some(index) = fields.next().and_then(|value| value.parse::<u32>().ok()) else {
            continue;
        };
        let Some(name) = fields.next() else {
            continue;
        };
        let Some(ip) = fields.next().filter(|value| value.len() <= 128) else {
            continue;
        };
        if validate_interface(name).is_err() || ip.contains(['\0', '\n', '\r', '|']) {
            continue;
        }
        if let Some(existing) = interfaces
            .iter_mut()
            .find(|interface| interface.index == index && interface.name == name)
        {
            if !existing.ips.iter().any(|value| value == ip) && existing.ips.len() < 16 {
                existing.ips.push(ip.to_owned());
            }
        } else if interfaces.len() < 128 {
            interfaces.push(NetworkInterface {
                name: name.to_owned(),
                index,
                mac: None,
                ips: vec![ip.to_owned()],
            });
        }
    }
    interfaces.sort_by(|left, right| {
        left.index
            .cmp(&right.index)
            .then_with(|| left.name.cmp(&right.name))
    });
    if interfaces.is_empty() {
        return Err(CoreError::validation(
            "network interfaces",
            "remote interface probe returned no valid rows",
        ));
    }
    Ok(interfaces)
}

async fn pump_live_capture(
    capture_id: String,
    interface: String,
    guard: TargetGuard,
    target: Arc<TargetContext>,
    terminal: Arc<SshTerminalSession>,
    sender: PacketCaptureEventSender,
) {
    let mut sequence = 0_u64;
    if !send_capture_event(
        &sender,
        &capture_id,
        &mut sequence,
        PacketCaptureEventKind::Started { interface },
    )
    .await
    {
        terminal.request_close();
        return;
    }
    let mut pending = Vec::new();
    let mut packet_id = 0_usize;
    let mut bytes = 0_u64;
    loop {
        if let Err(error) = target.validate(&guard) {
            terminal.request_close();
            let _ = send_capture_event(
                &sender,
                &capture_id,
                &mut sequence,
                PacketCaptureEventKind::Failed {
                    message: format!("capture target changed: {error}"),
                },
            )
            .await;
            break;
        }
        match terminal.recv().await {
            Ok(event) => match event.kind {
                TerminalEventKind::Output(chunk) => {
                    pending.extend_from_slice(&chunk);
                    for line in drain_capture_lines(&mut pending, false) {
                        let kind = if is_tcpdump_info(&line) {
                            PacketCaptureEventKind::Info { message: line }
                        } else {
                            packet_id = packet_id.saturating_add(1);
                            let packet = parse_tcpdump_line(&line, packet_id);
                            bytes = bytes
                                .saturating_add(packet.length.parse::<u64>().unwrap_or_default());
                            PacketCaptureEventKind::Data(packet)
                        };
                        if !send_capture_event(&sender, &capture_id, &mut sequence, kind).await {
                            terminal.request_close();
                            return;
                        }
                    }
                    if !send_capture_event(
                        &sender,
                        &capture_id,
                        &mut sequence,
                        PacketCaptureEventKind::Progress {
                            packets: packet_id as u64,
                            bytes,
                        },
                    )
                    .await
                    {
                        terminal.request_close();
                        return;
                    }
                }
                TerminalEventKind::Exited { exit_code } => {
                    for line in drain_capture_lines(&mut pending, true) {
                        if is_tcpdump_info(&line) {
                            let _ = send_capture_event(
                                &sender,
                                &capture_id,
                                &mut sequence,
                                PacketCaptureEventKind::Info { message: line },
                            )
                            .await;
                        } else {
                            packet_id = packet_id.saturating_add(1);
                            let packet = parse_tcpdump_line(&line, packet_id);
                            bytes = bytes
                                .saturating_add(packet.length.parse::<u64>().unwrap_or_default());
                            let _ = send_capture_event(
                                &sender,
                                &capture_id,
                                &mut sequence,
                                PacketCaptureEventKind::Data(packet),
                            )
                            .await;
                        }
                    }
                    if exit_code.is_some_and(|code| !matches!(code, 0 | 124 | 130)) {
                        let _ = send_capture_event(
                            &sender,
                            &capture_id,
                            &mut sequence,
                            PacketCaptureEventKind::Failed {
                                message: format!("tcpdump exited with status {exit_code:?}"),
                            },
                        )
                        .await;
                    }
                    let _ = send_capture_event(
                        &sender,
                        &capture_id,
                        &mut sequence,
                        PacketCaptureEventKind::Stopped,
                    )
                    .await;
                    break;
                }
                TerminalEventKind::Failed { message } => {
                    let _ = send_capture_event(
                        &sender,
                        &capture_id,
                        &mut sequence,
                        PacketCaptureEventKind::Failed {
                            message: truncate_utf8_bytes(&message, 4_096),
                        },
                    )
                    .await;
                    break;
                }
                TerminalEventKind::TitleChanged(_) | TerminalEventKind::Bell => {}
            },
            Err(error) => {
                if !matches!(error, CoreError::ChannelClosed { .. }) {
                    let _ = send_capture_event(
                        &sender,
                        &capture_id,
                        &mut sequence,
                        PacketCaptureEventKind::Failed {
                            message: format!("capture stream failed: {error}"),
                        },
                    )
                    .await;
                }
                break;
            }
        }
    }
    sender.close();
}

async fn send_capture_event(
    sender: &PacketCaptureEventSender,
    capture_id: &str,
    sequence: &mut u64,
    kind: PacketCaptureEventKind,
) -> bool {
    *sequence = sequence.saturating_add(1);
    sender
        .send(PacketCaptureEvent {
            capture_id: capture_id.to_owned(),
            sequence: *sequence,
            observed_at: Utc::now(),
            kind,
        })
        .await
        .is_ok()
}

fn drain_capture_lines(pending: &mut Vec<u8>, flush: bool) -> Vec<String> {
    let mut lines = Vec::new();
    while let Some(position) = pending.iter().position(|byte| *byte == b'\n') {
        let mut bytes = pending.drain(..=position).collect::<Vec<_>>();
        while bytes
            .last()
            .is_some_and(|byte| matches!(*byte, b'\n' | b'\r'))
        {
            bytes.pop();
        }
        if !bytes.is_empty() {
            lines.push(truncate_utf8_bytes(
                &String::from_utf8_lossy(&bytes),
                MAX_PACKET_LINE_BYTES,
            ));
        }
    }
    if pending.len() > MAX_PACKET_LINE_BYTES || (flush && !pending.is_empty()) {
        lines.push(truncate_utf8_bytes(
            &String::from_utf8_lossy(pending),
            MAX_PACKET_LINE_BYTES,
        ));
        pending.clear();
    }
    lines
}

fn is_tcpdump_info(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.starts_with("tcpdump:")
        || lower.contains("packets captured")
        || lower.contains("packets received by filter")
        || lower.contains("packets dropped by kernel")
}

fn truncate_utf8_bytes(value: &str, maximum: usize) -> String {
    if value.len() <= maximum {
        return value.to_owned();
    }
    let mut end = maximum;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    let mut truncated = value[..end].to_owned();
    truncated.push('…');
    truncated
}

fn validate_interface(interface: &str) -> CoreResult<()> {
    if interface.is_empty()
        || interface.len() > 64
        || !interface
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:@-".contains(&byte))
    {
        return Err(CoreError::validation(
            "network interface",
            "contains invalid characters or exceeds 64 bytes",
        ));
    }
    Ok(())
}

fn validate_filter(filter: Option<&str>) -> CoreResult<Option<String>> {
    let Some(filter) = filter.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if filter.len() > 2_048 || filter.contains(['\0', '\n', '\r']) {
        return Err(CoreError::validation(
            "BPF filter",
            "must be at most 2048 bytes and contain no line controls",
        ));
    }
    Ok(Some(filter.to_owned()))
}

pub fn new_remote_pcap_path() -> String {
    format!("{PCAP_REMOTE_PREFIX}{}.pcap", uuid::Uuid::new_v4())
}

pub fn is_managed_remote_pcap_path(path: &str) -> bool {
    path.strip_prefix(PCAP_REMOTE_PREFIX)
        .and_then(|value| value.strip_suffix(".pcap"))
        .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok())
}

pub fn generate_pcap_evidence_command(
    request: &PcapCaptureRequest,
    remote_path: &str,
) -> CoreResult<String> {
    request.validate()?;
    let filter = validate_filter(request.filter.as_deref())?;
    if !is_managed_remote_pcap_path(remote_path) {
        return Err(CoreError::validation(
            "remote PCAP path",
            "path is outside the LovelyRes-managed namespace",
        ));
    }
    let remote = shq(remote_path);
    let count_arg = request
        .packet_limit
        .map(|count| format!(" -c {count}"))
        .unwrap_or_default();
    let filter_arg = filter
        .as_deref()
        .map(|value| format!(" {}", shq(value)))
        .unwrap_or_default();
    Ok(format!(
        "set -u\n\
umask 077\n\
command -v tcpdump >/dev/null 2>&1 || {{ echo 'tcpdump unavailable' >&2; exit 127; }}\n\
command -v timeout >/dev/null 2>&1 || {{ echo 'timeout unavailable' >&2; exit 127; }}\n\
command -v sha256sum >/dev/null 2>&1 || {{ echo 'sha256sum unavailable' >&2; exit 127; }}\n\
pcap_runner='tcpdump'\n\
pcap_needs_chown=0\n\
if [ \"$(id -u)\" -ne 0 ]; then\n\
  command -v sudo >/dev/null 2>&1 || {{ echo 'capture requires root or sudo' >&2; exit 126; }}\n\
  sudo -n true >/dev/null 2>&1 || {{ echo 'capture requires non-interactive sudo' >&2; exit 126; }}\n\
  pcap_runner='sudo -n tcpdump'\n\
  pcap_needs_chown=1\n\
fi\n\
rm -f -- {remote}\n\
capture_rc=0\n\
timeout --signal=INT --kill-after=5s {duration}s $pcap_runner -nn -U -i {interface}{count_arg} -w {remote}{filter_arg} >/dev/null 2>&1 || capture_rc=$?\n\
case \"$capture_rc\" in\n\
  0|124|130) ;;\n\
  *) if [ \"$pcap_needs_chown\" -eq 1 ]; then sudo -n rm -f -- {remote}; else rm -f -- {remote}; fi; exit \"$capture_rc\" ;;\n\
esac\n\
if [ \"$pcap_needs_chown\" -eq 1 ]; then sudo -n chown -- \"$(id -u):$(id -g)\" {remote}; fi\n\
test -s {remote} || {{ rm -f -- {remote}; echo 'no PCAP data generated' >&2; exit 1; }}\n\
pcap_size=$(wc -c < {remote})\n\
pcap_hash=$(sha256sum {remote} | awk '{{print $1}}')\n\
printf '{PCAP_RESULT_MARKER}\\t%s\\t%s\\n' \"$pcap_size\" \"$pcap_hash\"",
        duration = request.duration_seconds,
        interface = shq(&request.interface),
    ))
}

pub fn parse_pcap_evidence_output(output: &str) -> CoreResult<RemotePcapMetadata> {
    let line = output
        .lines()
        .rev()
        .find(|line| line.starts_with(PCAP_RESULT_MARKER))
        .ok_or_else(|| CoreError::validation("PCAP metadata", "result marker is missing"))?;
    let mut parts = line.split('\t');
    if parts.next() != Some(PCAP_RESULT_MARKER) {
        return Err(CoreError::validation("PCAP metadata", "invalid marker"));
    }
    let size_bytes = parts
        .next()
        .ok_or_else(|| CoreError::validation("PCAP metadata", "file size is missing"))?
        .parse::<u64>()
        .map_err(|_| CoreError::validation("PCAP metadata", "file size is invalid"))?;
    if size_bytes == 0 || size_bytes > MAX_PCAP_EVIDENCE_BYTES {
        return Err(CoreError::validation(
            "PCAP metadata",
            format!("file size must be 1..={MAX_PCAP_EVIDENCE_BYTES} bytes"),
        ));
    }
    let sha256 = parts
        .next()
        .map(str::trim)
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| CoreError::validation("PCAP metadata", "SHA-256 is invalid"))?
        .to_ascii_lowercase();
    if parts.next().is_some() {
        return Err(CoreError::validation(
            "PCAP metadata",
            "unexpected extra fields",
        ));
    }
    Ok(RemotePcapMetadata { size_bytes, sha256 })
}

pub fn parse_tcpdump_line(line: &str, id: usize) -> PacketEntry {
    let bounded = truncate_utf8_bytes(line, MAX_PACKET_LINE_BYTES);
    let line = bounded.as_str();
    let parts: Vec<_> = line.split_whitespace().collect();
    let mut entry = PacketEntry {
        id,
        timestamp: String::new(),
        protocol: "OTHER".to_owned(),
        src: String::new(),
        dst: String::new(),
        length: String::new(),
        info: line.to_owned(),
        raw: line.to_owned(),
    };
    if parts.len() < 4 {
        return entry;
    }
    let (timestamp, offset) = if parts[0].contains('-') && parts[1].contains(':') {
        (format!("{} {}", parts[0], parts[1]), 2)
    } else {
        (parts[0].to_owned(), 1)
    };
    entry.timestamp = timestamp;
    if parts.len() <= offset {
        return entry;
    }
    let token = parts[offset];
    if matches!(token, "IP" | "IP6") {
        entry.protocol = token.to_owned();
        if let Some(relative_arrow) = parts[offset..].iter().position(|part| *part == ">") {
            let arrow = offset + relative_arrow;
            if arrow > offset + 1 {
                entry.src = parts[offset + 1..arrow].join(" ");
            }
            if arrow + 1 < parts.len() {
                entry.dst = parts[arrow + 1].trim_end_matches(':').to_owned();
                if arrow + 2 < parts.len() {
                    entry.info = parts[arrow + 2..].join(" ");
                }
            }
            if let Some(protocol) =
                infer_protocol(&entry.src).or_else(|| infer_protocol(&entry.dst))
            {
                entry.protocol = protocol.to_owned();
            }
        }
    } else if token.starts_with("ARP") {
        entry.protocol = "ARP".to_owned();
        entry.info = parts[offset..].join(" ");
    } else {
        entry.protocol = token.trim_end_matches(',').to_owned();
        entry.info = parts[offset..].join(" ");
    }
    entry.length = extract_length(&entry.info);
    entry
}

fn infer_protocol(address: &str) -> Option<&'static str> {
    let port = address.rsplit_once('.')?.1.parse::<u16>().ok()?;
    match port {
        80 | 8000 | 8080 | 8888 => Some("HTTP"),
        443 | 8443 => Some("HTTPS"),
        53 => Some("DNS"),
        22 => Some("SSH"),
        21 => Some("FTP"),
        25 | 465 | 587 => Some("SMTP"),
        110 | 995 => Some("POP3"),
        143 | 993 => Some("IMAP"),
        3306 => Some("MySQL"),
        5432 => Some("PgSQL"),
        6379 => Some("Redis"),
        27017 => Some("MongoDB"),
        _ => None,
    }
}

fn extract_length(info: &str) -> String {
    info.split_whitespace()
        .collect::<Vec<_>>()
        .windows(2)
        .find_map(|pair| {
            if matches!(pair[0], "length" | "len") {
                pair[1]
                    .trim_end_matches(',')
                    .parse::<u64>()
                    .ok()
                    .map(|value| value.to_string())
            } else {
                None
            }
        })
        .unwrap_or_default()
}

pub fn generate_tcpdump_command(request: &PcapCaptureRequest) -> CoreResult<String> {
    request.validate()?;
    let mut command = format!("tcpdump -nne -l -tttt -v -i {}", shq(&request.interface));
    if let Some(count) = request.packet_limit {
        command.push_str(&format!(" -c {count}"));
    }
    if let Some(filter) = validate_filter(request.filter.as_deref())? {
        command.push(' ');
        command.push_str(&shq(&filter));
    }
    Ok(command)
}

pub fn generate_live_capture_command(request: &PcapCaptureRequest) -> CoreResult<String> {
    request.validate()?;
    let count_arg = request
        .packet_limit
        .map(|count| format!(" -c {count}"))
        .unwrap_or_default();
    let filter_arg = validate_filter(request.filter.as_deref())?
        .map(|filter| format!(" {}", shq(&filter)))
        .unwrap_or_default();
    Ok(format!(
        "set -u; command -v tcpdump >/dev/null 2>&1 || {{ echo 'tcpdump unavailable' >&2; exit 127; }}; \
command -v timeout >/dev/null 2>&1 || {{ echo 'timeout unavailable' >&2; exit 127; }}; \
pcap_runner='tcpdump'; if [ \"$(id -u)\" -ne 0 ]; then \
command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1 || {{ echo 'capture requires root or non-interactive sudo' >&2; exit 126; }}; \
pcap_runner='sudo -n tcpdump'; fi; \
timeout --signal=INT --kill-after=5s {duration}s $pcap_runner -nne -l -tttt -v -i {interface}{count_arg}{filter_arg} 2>&1",
        duration = request.duration_seconds,
        interface = shq(&request.interface),
    ))
}

pub fn generate_list_interfaces_command() -> &'static str {
    "ip -o addr show 2>/dev/null | awk '{gsub(/:$/, \"\", $1); print $1 \"|\" $2 \"|\" $4}' | head -256"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> PcapCaptureRequest {
        PcapCaptureRequest {
            interface: "eth0".to_owned(),
            filter: Some("tcp port 443; id".to_owned()),
            packet_limit: Some(500),
            duration_seconds: 15,
        }
    }

    #[test]
    fn evidence_command_is_bounded_and_shell_quoted() {
        let path = "/tmp/lovelyres-pcap-123e4567-e89b-12d3-a456-426614174000.pcap";
        let command = generate_pcap_evidence_command(&request(), path).unwrap();
        assert!(command.contains("timeout --signal=INT --kill-after=5s 15s"));
        assert!(command.contains("sudo -n true"));
        assert!(command.contains("-c 500"));
        assert!(command.contains("'tcp port 443; id'"));
        assert!(command.contains(PCAP_RESULT_MARKER));
    }

    #[test]
    fn rejects_unmanaged_paths_and_unbounded_inputs() {
        let mut invalid = request();
        invalid.interface = "eth0; id".to_owned();
        assert!(PacketCaptureService::plan(invalid).is_err());
        invalid = request();
        invalid.packet_limit = Some(MAX_PCAP_PACKET_COUNT + 1);
        assert!(PacketCaptureService::plan(invalid).is_err());
        invalid = request();
        invalid.duration_seconds = MAX_PCAP_CAPTURE_SECONDS + 1;
        assert!(PacketCaptureService::plan(invalid).is_err());
        assert!(generate_pcap_evidence_command(&request(), "/tmp/user-chosen.pcap").is_err());
    }

    #[test]
    fn exact_marker_and_local_sha256_are_required() {
        let bytes = b"pcap bytes";
        let hash = format!("{:x}", Sha256::digest(bytes));
        let metadata = parse_pcap_evidence_output(&format!(
            "noise\n{PCAP_RESULT_MARKER}\t{}\t{hash}\n",
            bytes.len()
        ))
        .unwrap();
        let verified = PacketCaptureService::verify_download(bytes, &metadata).unwrap();
        assert_eq!(verified.sha256, hash);
        assert!(PacketCaptureService::verify_download(b"tampered", &metadata).is_err());
        assert!(parse_pcap_evidence_output("LOVELYRES_PCAP_V1\t24\tnot-a-hash").is_err());
        assert!(
            parse_pcap_evidence_output(&format!(
                "{PCAP_RESULT_MARKER}\t{}\t{}",
                MAX_PCAP_EVIDENCE_BYTES + 1,
                "ab".repeat(32)
            ))
            .is_err()
        );

        let path =
            std::env::temp_dir().join(format!("lovelyres-pcap-test-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, bytes).unwrap();
        let verified = PacketCaptureService::verify_downloaded_file(&path, &metadata).unwrap();
        assert_eq!(verified.sha256, hash);
        std::fs::write(&path, b"tampered").unwrap();
        assert!(PacketCaptureService::verify_downloaded_file(&path, &metadata).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn parses_tcpdump_application_protocol_and_length() {
        let entry = parse_tcpdump_line(
            "2026-08-11 10:00:00.123 IP 10.0.0.2.443 > 10.0.0.3.51000: Flags [P.], length 42",
            7,
        );
        assert_eq!(entry.id, 7);
        assert_eq!(entry.protocol, "HTTPS");
        assert_eq!(entry.length, "42");
    }

    #[test]
    fn live_command_is_bounded_quoted_and_time_limited() {
        let command = generate_live_capture_command(&request()).unwrap();
        assert!(command.contains("timeout --signal=INT --kill-after=5s 15s"));
        assert!(command.contains("sudo -n true"));
        assert!(command.contains("-c 500"));
        assert!(command.contains("'tcp port 443; id'"));
        assert!(!command.contains("eth0;"));
    }

    #[test]
    fn interface_probe_is_typed_grouped_and_rejects_hostile_rows() {
        let rows = "1|lo|127.0.0.1/8\n2|eth0|10.0.0.2/24\n2|eth0|fe80::1/64\n3|bad;id|1.2.3.4/32\n";
        let parsed = parse_network_interfaces(rows).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[1].name, "eth0");
        assert_eq!(parsed[1].ips, ["10.0.0.2/24", "fe80::1/64"]);
    }

    #[test]
    fn split_live_lines_are_reassembled_and_utf8_bounded() {
        let mut pending = b"2026 IP 10.0.0.1.22 > ".to_vec();
        assert!(drain_capture_lines(&mut pending, false).is_empty());
        pending.extend_from_slice(b"10.0.0.2.42: length 4\r\n");
        let lines = drain_capture_lines(&mut pending, false);
        assert_eq!(lines, ["2026 IP 10.0.0.1.22 > 10.0.0.2.42: length 4"]);
        pending.extend(std::iter::repeat_n(b'x', MAX_PACKET_LINE_BYTES + 10));
        let bounded = drain_capture_lines(&mut pending, false);
        assert_eq!(bounded.len(), 1);
        assert!(bounded[0].ends_with('…'));
    }
}
