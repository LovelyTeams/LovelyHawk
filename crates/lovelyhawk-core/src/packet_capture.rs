//! Target-bound packet capture with bounded live events and verifiable PCAP evidence.

use std::{io::Read, path::Path, sync::Arc, time::Duration};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::domain::CommandRunner;
use crate::events::{
    EventChannelDefaults, PacketCaptureEvent, PacketCaptureEventKind, PacketCaptureEventReceiver,
    PacketCaptureEventSender, TerminalEventKind, packet_capture_event_channel,
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
const PCAP_FAILURE_MARKER: &str = "LOVELYHAWK_PCAP_FAILURE_V1";
const MAX_TCPDUMP_FAILURE_BYTES: usize = 400;
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

    /// Interrupts tcpdump through its PTY and closes the session; the capture
    /// command's trap then ends tcpdump and its timer on the host.
    pub async fn stop(&self) -> CoreResult<()> {
        self.terminal.interrupt_and_close();
        Ok(())
    }

    pub fn request_stop(&self) {
        self.terminal.interrupt_and_close();
    }
}

impl Drop for LivePacketCapture {
    fn drop(&mut self) {
        self.terminal.interrupt_and_close();
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
                "path is outside the LovelyHawk-managed namespace",
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

    /// Stop a capture still writing its managed file, then remove the file.
    ///
    /// Dropping the SSH command does not end it on the target: `timeout` and
    /// tcpdump run on until the time limit. The path carries a fresh UUID, so
    /// a process whose command line names it is this capture's own — the
    /// timeout, sudo and tcpdump around it — and nothing else's.
    pub fn stop_command(remote_path: &str) -> CoreResult<String> {
        if !is_managed_remote_pcap_path(remote_path) {
            return Err(CoreError::validation(
                "remote PCAP path",
                "refuses to stop or remove an unmanaged path",
            ));
        }
        let remote = shq(remote_path);
        Ok(format!(
            "set -u\n\
pcap_self=$$\n\
for pcap_proc in /proc/[0-9]*; do\n\
  pcap_pid=${{pcap_proc#/proc/}}\n\
  [ \"$pcap_pid\" = \"$pcap_self\" ] && continue\n\
  case \"$(tr '\\000' ' ' < \"$pcap_proc/cmdline\" 2>/dev/null)\" in\n\
    *{remote}*) kill -INT \"$pcap_pid\" 2>/dev/null || sudo -n kill -INT \"$pcap_pid\" 2>/dev/null ;;\n\
  esac\n\
done\n\
sleep 1\n\
rm -f -- {remote} 2>/dev/null || sudo -n rm -f -- {remote} 2>/dev/null\n\
test ! -e {remote}"
        ))
    }

    /// The capture this connection gave up on: stopped on the target and its
    /// file removed, checked by its absence.
    pub async fn stop_and_cleanup_remote(
        &self,
        session: &BoundSshSession,
        remote_path: &str,
    ) -> CoreResult<()> {
        let command = Self::stop_command(remote_path)?;
        self.target.validate(session.target())?;
        let output = self
            .ssh
            .execute_bound(session, command, Duration::from_secs(20))
            .await?;
        self.target.validate(session.target())?;
        validate_ssh_output("PCAP stop", &output, 64 * 1024)
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

    /// Run a planned capture to its managed file on the target.
    ///
    /// The plan is made first so the caller knows the file's path before the
    /// capture starts and can remove it if it gives up waiting. A capture that
    /// produced no file says why, and leaves nothing behind.
    pub async fn capture_planned(
        &self,
        session: &BoundSshSession,
        plan: &PcapCapturePlan,
    ) -> CoreResult<Result<RemotePcapMetadata, PcapEvidenceFailure>> {
        if !is_managed_remote_pcap_path(&plan.remote_path) {
            return Err(CoreError::validation(
                "remote PCAP path",
                "path is outside the LovelyHawk-managed namespace",
            ));
        }
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
        if output.output.len() > 64 * 1024 {
            let _ = self
                .cleanup_remote_artifact(session, &plan.remote_path)
                .await;
            return Err(CoreError::validation(
                "PCAP evidence capture",
                "remote output exceeds 65536 bytes",
            ));
        }
        if output.timed_out || output.exit_code.is_some_and(|code| code != 0) {
            let _ = self
                .cleanup_remote_artifact(session, &plan.remote_path)
                .await;
            return Ok(Err(if output.timed_out {
                PcapEvidenceFailure::Failed
            } else {
                parse_pcap_evidence_failure(&output.output)
            }));
        }
        match parse_pcap_evidence_output(&output.output) {
            Ok(metadata) => Ok(Ok(metadata)),
            Err(_) => {
                let _ = self
                    .cleanup_remote_artifact(session, &plan.remote_path)
                    .await;
                Ok(Err(PcapEvidenceFailure::Failed))
            }
        }
    }

    pub async fn capture_evidence_remote(
        &self,
        session: &BoundSshSession,
        request: PcapCaptureRequest,
    ) -> CoreResult<RemotePcapArtifact> {
        let plan = Self::plan(request)?;
        let metadata = self
            .capture_planned(session, &plan)
            .await?
            .map_err(|failure| {
                // The kind only: tcpdump's own line is the target's text.
                let kind = match failure {
                    PcapEvidenceFailure::Preflight(_) => "preflight",
                    PcapEvidenceFailure::Tcpdump(_) => "tcpdump error",
                    PcapEvidenceFailure::Empty => "empty",
                    PcapEvidenceFailure::Failed => "failed",
                };
                CoreError::validation(
                    "PCAP evidence capture",
                    format!("capture produced no file ({kind})"),
                )
            })?;
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
            .download_new(
                &sftp_session,
                paths,
                &remote_path,
                selected_target,
                &crate::sftp::SftpTransferCancel::new(),
            )
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
                        // A machine that cannot capture says so before it tries.
                        // That answer ends the capture rather than joining the
                        // packets, because it is not one.
                        if let Some(reason) = capture_preflight_failure(&line) {
                            send_capture_event(
                                &sender,
                                &capture_id,
                                &mut sequence,
                                PacketCaptureEventKind::Failed {
                                    message: reason.to_owned(),
                                },
                            )
                            .await;
                            terminal.request_close();
                            return;
                        }
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
                    if exit_code.is_some_and(|code| !matches!(code, 0 | 124 | 129 | 130 | 143)) {
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

/// Why a machine could not start capturing, said in the operator's words.
///
/// The command checks its own prerequisites and writes one of these lines
/// before doing anything. They used to arrive merged with the packet stream —
/// the live command ends `2>&1` — so "tcpdump unavailable" was parsed as a
/// packet and shown in the packet list, protocol `OTHER`, while the capture
/// reported itself as running. An operator then watched an empty table fill up
/// with nothing, on a machine that was never going to produce a packet.
///
/// The sentence is chosen here from a fixed list rather than passed through:
/// the machine's own text is not what the window shows.
const CAPTURE_PREFLIGHT_REASONS: &[(&str, &str)] = &[
    (
        "tcpdump unavailable",
        "这台机器上没有 tcpdump，抓不了包。装上它再来，或者换一台机器抓。",
    ),
    (
        "timeout unavailable",
        "这台机器上没有 timeout 命令，没法给抓包设时限，所以没有开始。",
    ),
    (
        "sha256sum unavailable",
        "这台机器上没有 sha256sum，没法在目标上核对抓包文件的摘要，所以没有开始。",
    ),
    (
        "capture requires root or non-interactive sudo",
        "抓包要 root 或者能免密码的 sudo，这个账号两样都没有。换个账号连，或者给它配上 sudo。",
    ),
    (
        "capture requires root or sudo",
        "抓包要 root 或者能免密码的 sudo，这个账号两样都没有。换个账号连，或者给它配上 sudo。",
    ),
    (
        "capture requires non-interactive sudo",
        "这个账号的 sudo 需要输密码，抓包用不了。给它配上免密码的 sudo 再试。",
    ),
];

fn capture_preflight_failure(line: &str) -> Option<&'static str> {
    let line = line.trim();
    CAPTURE_PREFLIGHT_REASONS
        .iter()
        .find(|(written, _)| *written == line)
        .map(|(_, reason)| *reason)
}

/// Whether a failure message is one of ours, and so safe to show as written.
///
/// The boundary refuses to echo a capture's failure text, and it is right to:
/// the rest of what a capture prints is `tcpdump`'s own stderr on a machine
/// that may be compromised. These sentences are the exception because they
/// never came from the machine — [`capture_preflight_failure`] chose them —
/// and this is how the other side can tell the difference without trusting the
/// text in front of it.
pub fn known_capture_failure(message: &str) -> Option<&'static str> {
    CAPTURE_PREFLIGHT_REASONS
        .iter()
        .find(|(_, reason)| *reason == message)
        .map(|(_, reason)| *reason)
}

fn is_tcpdump_info(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.starts_with("tcpdump:")
        // Without -v, tcpdump 4.99 prints its start line without the prefix,
        // and the RHEL family's build reports giving up root the same way.
        || lower.starts_with("listening on ")
        || lower.starts_with("dropped privs to ")
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
            "path is outside the LovelyHawk-managed namespace",
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
pcap_log=$(timeout -s INT -k 5 {duration} $pcap_runner -nn -U -i {interface}{count_arg} -w {remote}{filter_arg} 2>&1 >/dev/null) || capture_rc=$?\n\
case \"$capture_rc\" in\n\
  0|124|130) ;;\n\
  *) if [ \"$pcap_needs_chown\" -eq 1 ]; then sudo -n rm -f -- {remote}; else rm -f -- {remote}; fi\n\
     pcap_last=$(printf '%s\\n' \"$pcap_log\" | grep -v -e 'listening on' -e 'packets captured' -e 'packets received' -e 'packets dropped' | tail -n 1 | tr '\\t\\r' '  ' | cut -c 1-400)\n\
     printf '{PCAP_FAILURE_MARKER}\\ttcpdump\\t%s\\n' \"$pcap_last\"\n\
     exit \"$capture_rc\" ;;\n\
esac\n\
if [ \"$pcap_needs_chown\" -eq 1 ]; then sudo -n chown -- \"$(id -u):$(id -g)\" {remote}; fi\n\
test -s {remote} || {{ rm -f -- {remote}; printf '{PCAP_FAILURE_MARKER}\\tempty\\t\\n'; exit 1; }}\n\
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

/// Why a capture to a file produced no file.
///
/// The preflight sentences are chosen from [`CAPTURE_PREFLIGHT_REASONS`]; the
/// tcpdump line is the machine's own text, bounded and stripped of controls,
/// to be shown as plain text and never interpreted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcapEvidenceFailure {
    Preflight(&'static str),
    Tcpdump(String),
    Empty,
    Failed,
}

pub fn parse_pcap_evidence_failure(output: &str) -> PcapEvidenceFailure {
    if let Some(reason) = output.lines().find_map(capture_preflight_failure) {
        return PcapEvidenceFailure::Preflight(reason);
    }
    let Some(line) = output
        .lines()
        .rev()
        .find_map(|line| line.strip_prefix(PCAP_FAILURE_MARKER)?.strip_prefix('\t'))
    else {
        return PcapEvidenceFailure::Failed;
    };
    let (kind, text) = line.split_once('\t').unwrap_or((line, ""));
    match kind {
        "empty" => PcapEvidenceFailure::Empty,
        "tcpdump" => {
            let text: String = text
                .chars()
                .map(|c| if c.is_control() { ' ' } else { c })
                .collect();
            let text = truncate_utf8_bytes(text.trim(), MAX_TCPDUMP_FAILURE_BYTES);
            if text.is_empty() {
                PcapEvidenceFailure::Failed
            } else {
                PcapEvidenceFailure::Tcpdump(text)
            }
        }
        _ => PcapEvidenceFailure::Failed,
    }
}

/// What the capture behind a kept PCAP file was, recorded beside its bytes so
/// the file can be read later without this program. Named like the rest of
/// the manifest it sits in.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PcapEvidenceContext {
    pub tool: String,
    pub interface: String,
    pub filter: Option<String>,
    pub packet_limit: Option<u32>,
    pub duration_seconds: u32,
    pub capture_started_at: DateTime<Utc>,
    pub capture_finished_at: DateTime<Utc>,
    pub target_bytes: u64,
    pub target_sha256: String,
    pub target_temporary_path: String,
    pub target_temporary_removed: bool,
    pub limitations: String,
}

pub const PCAP_EVIDENCE_LIMITATIONS: &str = "tcpdump 以 -nn -U -w 把所选接口上、符合过滤条件的数据包写入目标机上的临时文件，到时长或包数上限即停止；目标机上计算的 SHA-256 与两次 SFTP 读取及本地回读一致。文件只包含内核在这段时间交给 tcpdump 的数据包，内核丢包与未匹配过滤条件的流量不在其中，不代表这段时间的全部网络活动。抓包期间 tcpdump 需要 root 或免密码 sudo。";

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
            if let Some(protocol) = infer_protocol(&entry.src)
                .or_else(|| infer_protocol(&entry.dst))
                .or_else(|| transport_protocol(&entry.info))
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

/// The transport named by the start of tcpdump's one-line summary, when no
/// well-known port says more: `ICMP echo request, …`, `UDP, length 13`,
/// `Flags [S], …` (TCP prints its flags first).
fn transport_protocol(info: &str) -> Option<&'static str> {
    if info.starts_with("ICMP6") {
        Some("ICMPv6")
    } else if info.starts_with("ICMP") {
        Some("ICMP")
    } else if info.starts_with("UDP") {
        Some("UDP")
    } else if info.starts_with("Flags [") {
        Some("TCP")
    } else {
        None
    }
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
    let mut command = format!("tcpdump -nn -l -tttt -i {}", shq(&request.interface));
    if let Some(count) = request.packet_limit {
        command.push_str(&format!(" -c {count}"));
    }
    if let Some(filter) = validate_filter(request.filter.as_deref())? {
        command.push(' ');
        command.push_str(&shq(&filter));
    }
    Ok(command)
}

/// The live capture, run in a PTY whose closing is how 停止抓包 and leaving
/// the page end it.
///
/// tcpdump runs as a job of this shell rather than under timeout(1): GNU
/// timeout moves itself and its child into a process group of their own, out
/// of reach of a hangup sent to the terminal's foreground group; and BusyBox
/// timeout does not take `--signal=`/`--kill-after=` at all, so every capture
/// on Alpine failed. Here
/// a non-interactive shell keeps its jobs in its own process group, so the
/// hangup reaches tcpdump directly, the trap stops it on HUP/INT/TERM, and a
/// timer job sends TERM when the duration is up. tcpdump ends on TERM with
/// its own exit status.
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
pcap_runner='tcpdump'; if [ \"$(id -u)\" -ne 0 ]; then \
command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1 || {{ echo 'capture requires root or non-interactive sudo' >&2; exit 126; }}; \
pcap_runner='sudo -n tcpdump'; fi; \
$pcap_runner -nn -l -tttt -i {interface}{count_arg}{filter_arg} 2>&1 & pcap_pid=$!; \
( trap 'kill \"$pcap_sleep\" 2>/dev/null; exit 0' TERM; sleep {duration} & pcap_sleep=$!; wait \"$pcap_sleep\" && kill -TERM \"$pcap_pid\" 2>/dev/null ) & pcap_timer=$!; \
trap 'kill -TERM \"$pcap_pid\" \"$pcap_timer\" 2>/dev/null; exit 129' HUP INT TERM; \
wait \"$pcap_pid\"; pcap_rc=$?; kill -TERM \"$pcap_timer\" 2>/dev/null; exit \"$pcap_rc\"",
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

    /// A machine that cannot capture must say so instead of producing a packet.
    ///
    /// The live command ends `2>&1`, so its own preflight complaints arrive on
    /// the same stream as the packets. "tcpdump unavailable" was parsed as one:
    /// protocol `OTHER`, empty source and destination, sitting in the packet
    /// list while the capture called itself running. Nothing was hidden, but
    /// the one line that mattered was dressed as the thing it was telling you
    /// would never arrive.
    #[test]
    fn a_machine_that_cannot_capture_says_why_instead_of_faking_a_packet() {
        // Every line the command can write about itself is recognised, and the
        // sentence comes from here rather than from the machine.
        for (line, expected) in [
            ("tcpdump unavailable", "没有 tcpdump"),
            ("timeout unavailable", "没有 timeout"),
            ("capture requires root or non-interactive sudo", "root"),
            ("capture requires non-interactive sudo", "免密码"),
        ] {
            let reason = capture_preflight_failure(line)
                .unwrap_or_else(|| panic!("{line} is not recognised"));
            assert!(reason.contains(expected), "{line} -> {reason}");
            // Trailing whitespace from the terminal must not stop it matching.
            assert_eq!(
                capture_preflight_failure(&format!("{line}\r")),
                Some(reason)
            );
        }
        // A real packet line, and a tcpdump banner, are not preflight failures.
        for ordinary in [
            "2026-09-04 06:54:21.479663 IP 10.0.0.1.443 > 10.0.0.2.51234: Flags [P.]",
            "tcpdump: listening on eth0, link-type EN10MB",
            "5 packets captured",
            "",
        ] {
            assert_eq!(capture_preflight_failure(ordinary), None, "{ordinary}");
        }
        // Both spellings of the sudo complaint exist in the two commands, and
        // both have to be understood — the live path and the file path word it
        // differently.
        assert!(capture_preflight_failure("capture requires root or sudo").is_some());

        // The commands still ask those questions before they capture, so the
        // lines this function knows are lines it can actually receive. The
        // live command keeps its own time and needs no timeout(1).
        let live = generate_live_capture_command(&request()).unwrap();
        assert!(live.contains("tcpdump unavailable"));
        assert!(!live.contains("timeout"));
        let evidence = generate_pcap_evidence_command(&request(), &new_remote_pcap_path()).unwrap();
        for expected in ["tcpdump unavailable", "timeout unavailable"] {
            assert!(
                evidence.contains(expected),
                "{expected} missing from {evidence}"
            );
        }
    }

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
        // Short options: BusyBox timeout (Alpine) has no --signal=/--kill-after=.
        assert!(command.contains("timeout -s INT -k 5 15 "));
        assert!(!command.contains("--signal") && !command.contains("--kill-after"));
        assert!(command.contains("sudo -n true"));
        assert!(command.contains("-c 500"));
        assert!(command.contains("'tcp port 443; id'"));
        assert!(command.contains(PCAP_RESULT_MARKER));
        // tcpdump's complaint is kept for the failure line, not thrown away,
        // and nothing it said reaches the success marker.
        assert!(command.contains("2>&1 >/dev/null) || capture_rc=$?"));
        assert!(command.contains(&format!("{PCAP_FAILURE_MARKER}\\ttcpdump\\t%s")));
        assert!(command.contains(&format!("{PCAP_FAILURE_MARKER}\\tempty")));
        assert!(command.contains("cut -c 1-400"));
    }

    #[test]
    fn stopping_a_capture_touches_only_its_own_processes_and_file() {
        let path = "/tmp/lovelyres-pcap-123e4567-e89b-12d3-a456-426614174000.pcap";
        let command = PacketCaptureService::stop_command(path).unwrap();
        // Matched by the whole quoted path, never by a pattern a name could widen.
        assert!(command.contains(&format!("*{}*)", shq(path))));
        assert!(command.contains("[ \"$pcap_pid\" = \"$pcap_self\" ] && continue"));
        assert!(command.contains("kill -INT"));
        assert!(!command.contains("pkill") && !command.contains("killall"));
        assert!(command.ends_with(&format!("test ! -e {}", shq(path))));
        for unmanaged in [
            "/tmp/x.pcap",
            "/",
            "/tmp/lovelyres-pcap-*.pcap",
            "/tmp/lovelyres-pcap-.pcap",
        ] {
            assert!(
                PacketCaptureService::stop_command(unmanaged).is_err(),
                "{unmanaged}"
            );
        }
    }

    #[test]
    fn a_capture_that_wrote_no_file_says_why() {
        assert_eq!(
            parse_pcap_evidence_failure("tcpdump unavailable\n"),
            PcapEvidenceFailure::Preflight(
                "这台机器上没有 tcpdump，抓不了包。装上它再来，或者换一台机器抓。"
            )
        );
        assert_eq!(
            parse_pcap_evidence_failure("sha256sum unavailable\n"),
            PcapEvidenceFailure::Preflight(
                "这台机器上没有 sha256sum，没法在目标上核对抓包文件的摘要，所以没有开始。"
            )
        );
        assert_eq!(
            parse_pcap_evidence_failure("capture requires non-interactive sudo\n"),
            PcapEvidenceFailure::Preflight(
                "这个账号的 sudo 需要输密码，抓包用不了。给它配上免密码的 sudo 再试。"
            )
        );
        assert_eq!(
            parse_pcap_evidence_failure(&format!(
                "{PCAP_FAILURE_MARKER}\ttcpdump\ttcpdump: syntax error in filter expression: syntax error\n"
            )),
            PcapEvidenceFailure::Tcpdump(
                "tcpdump: syntax error in filter expression: syntax error".to_owned()
            )
        );
        // The machine's text is shown as text: controls flattened, bounded.
        match parse_pcap_evidence_failure(&format!(
            "{PCAP_FAILURE_MARKER}\ttcpdump\t\u{1b}[31mred\u{7}{}\n",
            "长".repeat(400)
        )) {
            PcapEvidenceFailure::Tcpdump(text) => {
                assert!(!text.chars().any(char::is_control), "{text:?}");
                assert!(text.len() <= MAX_TCPDUMP_FAILURE_BYTES + '…'.len_utf8());
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            parse_pcap_evidence_failure(&format!("{PCAP_FAILURE_MARKER}\tempty\t\n")),
            PcapEvidenceFailure::Empty
        );
        for unknown in [
            "",
            "exit 1",
            &format!("{PCAP_FAILURE_MARKER}\ttcpdump\t\n"),
            &format!("{PCAP_FAILURE_MARKER}\tsomething-else\tx\n"),
            "LOVELYHAWK_PCAP_FAILURE_V1x\ttcpdump\tforged prefix",
        ] {
            assert_eq!(
                parse_pcap_evidence_failure(unknown),
                PcapEvidenceFailure::Failed,
                "{unknown:?}"
            );
        }
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

    /// tcpdump's own lines, as 4.99 prints them without -v: never packets.
    #[test]
    fn tcpdump_status_lines_are_not_packets() {
        for line in [
            "tcpdump: verbose output suppressed, use -v[v]... for full protocol decode",
            "listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes",
            // Rocky, Alma: printed before the first packet, no prefix.
            "dropped privs to tcpdump",
            "6 packets captured",
            "6 packets received by filter",
            "0 packets dropped by kernel",
        ] {
            assert!(is_tcpdump_info(line), "{line}");
        }
        assert!(!is_tcpdump_info(
            "2026-10-11 06:10:41.818757 IP 172.17.0.13 > 172.17.0.1: ICMP echo request, id 1, seq 1, length 64"
        ));
    }

    /// Lines as tcpdump 4.99 prints them with the live command's flags, taken
    /// from a capture on a lab host: one line per packet, transport named.
    #[test]
    fn one_line_tcpdump_output_parses_into_whole_packets() {
        for (line, protocol, src, dst, length) in [
            (
                "2026-10-11 06:10:41.818757 IP 172.17.0.13 > 172.17.0.1: ICMP echo request, id 1, seq 1, length 64",
                "ICMP",
                "172.17.0.13",
                "172.17.0.1",
                "64",
            ),
            (
                "2026-10-11 06:10:41.819243 IP 172.17.0.13.45678 > 172.17.0.1.40404: UDP, length 13",
                "UDP",
                "172.17.0.13.45678",
                "172.17.0.1.40404",
                "13",
            ),
            (
                "2026-10-11 06:10:42.000001 IP 172.17.0.13.51000 > 172.17.0.1.9999: Flags [S], seq 1, win 64240, length 0",
                "TCP",
                "172.17.0.13.51000",
                "172.17.0.1.9999",
                "0",
            ),
            (
                "2026-10-11 06:10:42.000002 IP6 fe80::1 > ff02::1: ICMP6, router advertisement, length 56",
                "ICMPv6",
                "fe80::1",
                "ff02::1",
                "56",
            ),
        ] {
            let entry = parse_tcpdump_line(line, 1);
            assert_eq!(
                entry.timestamp.len(),
                "2026-10-11 06:10:41.818757".len(),
                "{line}"
            );
            assert_eq!(
                (
                    entry.protocol.as_str(),
                    entry.src.as_str(),
                    entry.dst.as_str(),
                    entry.length.as_str()
                ),
                (protocol, src, dst, length),
                "{line}"
            );
        }
        // The flags that print the link header and IP options split a packet
        // over two lines, which this parser cannot join; the command must not
        // ask for them.
        for command in [
            generate_live_capture_command(&request()).unwrap(),
            generate_tcpdump_command(&request()).unwrap(),
        ] {
            assert!(command.contains(" -nn -l -tttt -i "), "{command}");
            assert!(
                !command.contains("-nne") && !command.contains("-tttt -v"),
                "{command}"
            );
        }
    }

    #[test]
    fn live_command_is_bounded_quoted_and_time_limited() {
        let command = generate_live_capture_command(&request()).unwrap();
        // tcpdump is a job of the shell, so a hangup from the closed PTY
        // reaches it; the timer sends TERM at the duration; the trap stops
        // both on HUP/INT/TERM; the shell exits with tcpdump's status.
        assert!(command.contains("2>&1 & pcap_pid=$!;"));
        assert!(command.contains("sleep 15 & pcap_sleep=$!;"));
        assert!(command.contains("wait \"$pcap_sleep\" && kill -TERM \"$pcap_pid\""));
        assert!(command.contains(
            "trap 'kill -TERM \"$pcap_pid\" \"$pcap_timer\" 2>/dev/null; exit 129' HUP INT TERM;"
        ));
        assert!(command.ends_with("wait \"$pcap_pid\"; pcap_rc=$?; kill -TERM \"$pcap_timer\" 2>/dev/null; exit \"$pcap_rc\""));
        assert!(!command.contains("timeout"));
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
