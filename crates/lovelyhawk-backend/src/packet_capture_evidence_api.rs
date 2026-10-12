//! A packet capture kept as evidence. tcpdump writes a managed file on the
//! target; that file is collected like any other file evidence (two SFTP reads
//! and a local read-back) and must match the digest the target computed; then
//! the file on the target is removed. The local directory is the host's folder
//! dialog result and never a page input, and the page names the interface only
//! by the handle the live capture surface gave it.
use crate::{
    packet_capture_live_api::{PacketCaptureLiveApi, PacketCaptureStartInput},
    ssh_api::SshApi,
};
use lovelyhawk_core::{
    BackendServices,
    file_evidence::{
        FILE_EVIDENCE_DEADLINE, FileEvidenceBundle, FileEvidenceProgress, FileEvidenceSource,
        MAX_FILE_EVIDENCE_BYTES,
    },
    investigation::{AddEvidence, EvidenceKind, MAX_EVIDENCE, MAX_TIMELINE},
    packet_capture::{
        PCAP_EVIDENCE_LIMITATIONS, PacketCaptureService, PcapEvidenceContext, PcapEvidenceFailure,
    },
    path_guard::PathGuard,
    sftp::RemotePath,
    ssh::BoundSshSession,
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

const MAX_JOBS: usize = 4;
const RETENTION: Duration = Duration::from_secs(20 * 60);
const SAMPLE_FILE: &str = "capture.pcap";

const CAPTURING: &str =
    "正在目标上抓包，到设定时长或包数上限就停。抓包文件先写在目标的 /tmp 里，读回本机后删除。";
const COLLECTING: &str = "抓包已结束，正在把文件读回本机并核对摘要。";
const COMPLETED: &str = "抓包文件和清单已保存。目标上算出的 SHA-256 与两次读取、本地回读一致，已关联到本次开始时的案件；处置报告可包含这条证据。";
const SAVED_UNLINKED: &str = "抓包文件和清单已完整保存，但案件记录写入失败或案件已关闭。请保留该目录；这条证据尚未进入报告。";
const CANCELLED: &str = "已取消。正在停止目标上的这次 tcpdump 并删除它的临时文件；所选目录里没有 manifest.json 的文件不能算作留证。";
const TCPDUMP_REFUSED: &str =
    "tcpdump 没有完成这次抓包，目标上没有留下文件。下面是 tcpdump 自己的说法。";
const EMPTY: &str = "tcpdump 结束了，但没有写出抓包文件，目标上没有留下任何东西。";
const FAILED: &str = "抓包没有完成，目标上没有留下可用的文件。请检查连接后再试。";
const INTERRUPTED: &str =
    "抓包没有完成：连接中断、目标已切换或命令超时。目标上的临时文件已尝试删除。";
const TOO_LARGE: &str = "抓到的文件超过 512 MB 的留证上限，已在目标上删除。请缩短时长、加过滤条件或降低包数上限后再抓。";
const NOT_VERIFIED: &str = "抓包文件没有通过留证校验或读取超时：读取期间文件有变化、权限不足、连接中断或本机空间不足。所选目录里的字节不能算作留证。";
const MISMATCH: &str =
    "读回的字节与目标上算出的 SHA-256 不一致，没有登记为证据。所选目录里的字节不能算作留证。";
const MANIFEST_FAILED: &str =
    "抓包文件已下载，但证据清单写入失败。请检查本机空间和目录权限；尚未登记为案件证据。";

#[derive(Deserialize)]
#[serde(
    tag = "action",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum PacketCaptureEvidenceRequest {
    Begin {
        binding_handle: String,
        interface_handle: String,
        input: PacketCaptureStartInput,
        selected_directory: PathBuf,
    },
    Poll {
        binding_handle: String,
        job_handle: String,
    },
    Cancel {
        binding_handle: String,
        job_handle: String,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PacketCaptureEvidenceDto {
    job_handle: String,
    interface: String,
    duration_seconds: u32,
    packet_limit: Option<u32>,
    filtered: bool,
    target_label: String,
    folder_name: String,
    case_title: String,
    state: &'static str,
    copied_bytes: u64,
    verified_bytes: u64,
    total_bytes: u64,
    sha256: Option<String>,
    detail: &'static str,
    /// tcpdump's own last line when it refused, as plain text from the target.
    tcpdump_line: Option<String>,
    /// What became of the file on the target: "pending" while it may still be
    /// there, "removed", "left" when removing it failed, "none" when no file
    /// was kept.
    temporary_file: &'static str,
}

struct Job {
    binding_handle: String,
    session: BoundSshSession,
    remote_path: String,
    progress: FileEvidenceProgress,
    dto: PacketCaptureEvidenceDto,
    abort: Option<tokio::task::AbortHandle>,
    created: Instant,
}

impl Drop for Job {
    fn drop(&mut self) {
        if let Some(abort) = &self.abort {
            abort.abort();
        }
    }
}

impl Job {
    fn snapshot(&self) -> PacketCaptureEvidenceDto {
        let mut dto = self.dto.clone();
        // The later phase first, so verified never reads ahead of copied.
        dto.verified_bytes = self.progress.verified_bytes();
        dto.copied_bytes = self.progress.copied_bytes();
        if dto.total_bytes == 0 {
            dto.total_bytes = self.progress.total_bytes();
        }
        dto
    }

    fn running(&self) -> bool {
        matches!(self.dto.state, "capturing" | "collecting")
    }
}

#[derive(Clone)]
pub(crate) struct PacketCaptureEvidenceApi {
    services: BackendServices,
    ssh_api: Arc<SshApi>,
    jobs: Arc<Mutex<HashMap<String, Job>>>,
}

impl std::fmt::Debug for PacketCaptureEvidenceApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketCaptureEvidenceApi")
            .field("jobs", &self.jobs.lock().len())
            .finish()
    }
}

#[derive(Debug)]
pub(crate) enum PacketCaptureEvidenceError {
    Invalid,
    Stale,
    Busy,
    Capacity,
    CaseCapacity,
    Unavailable,
}

impl PacketCaptureEvidenceApi {
    pub(crate) fn new(services: BackendServices, ssh_api: Arc<SshApi>) -> Self {
        Self {
            services,
            ssh_api,
            jobs: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Jobs end with their connection. A capture still writing on the target
    /// then stops at its own time limit; its file cannot be removed without
    /// the connection, which the page says before a capture starts.
    pub(crate) fn close_binding(&self, binding: &str) {
        self.jobs
            .lock()
            .retain(|_, job| job.binding_handle != binding);
    }

    pub(crate) async fn dispatch(
        &self,
        request: PacketCaptureEvidenceRequest,
        live: &PacketCaptureLiveApi,
    ) -> Result<PacketCaptureEvidenceDto, PacketCaptureEvidenceError> {
        self.jobs
            .lock()
            .retain(|_, job| job.running() || job.created.elapsed() < RETENTION);
        match request {
            PacketCaptureEvidenceRequest::Begin {
                binding_handle,
                interface_handle,
                input,
                selected_directory,
            } => {
                self.begin(
                    live,
                    &binding_handle,
                    &interface_handle,
                    input,
                    selected_directory,
                )
                .await
            }
            PacketCaptureEvidenceRequest::Poll {
                binding_handle,
                job_handle,
            } => self.poll(&binding_handle, &job_handle, false),
            PacketCaptureEvidenceRequest::Cancel {
                binding_handle,
                job_handle,
            } => self.poll(&binding_handle, &job_handle, true),
        }
    }

    fn binding_current(&self, handle: &str, session: &BoundSshSession) -> bool {
        self.services.target().validate(session.target()).is_ok()
            && self
                .ssh_api
                .binding_session_clone(handle)
                .is_ok_and(|current| &current == session)
    }

    fn poll(
        &self,
        binding: &str,
        handle: &str,
        cancel: bool,
    ) -> Result<PacketCaptureEvidenceDto, PacketCaptureEvidenceError> {
        if !valid_handle(binding) || !valid_handle(handle) {
            return Err(PacketCaptureEvidenceError::Invalid);
        }
        let mut jobs = self.jobs.lock();
        let job = jobs
            .get_mut(handle)
            .filter(|job| job.binding_handle == binding)
            .ok_or(PacketCaptureEvidenceError::Stale)?;
        if !self.binding_current(binding, &job.session) {
            return Err(PacketCaptureEvidenceError::Stale);
        }
        if cancel && job.running() {
            if let Some(abort) = job.abort.take() {
                abort.abort();
            }
            job.dto.state = "cancelled";
            job.dto.detail = CANCELLED;
            job.dto.temporary_file = "pending";
            let services = self.services.clone();
            let session = job.session.clone();
            let path = job.remote_path.clone();
            let jobs = self.jobs.clone();
            let id = handle.to_owned();
            tokio::spawn(async move {
                let removed = services
                    .packet_capture()
                    .stop_and_cleanup_remote(&session, &path)
                    .await
                    .is_ok();
                if let Some(job) = jobs
                    .lock()
                    .get_mut(&id)
                    .filter(|job| job.dto.state == "cancelled")
                {
                    job.dto.temporary_file = if removed { "removed" } else { "left" };
                }
            });
        }
        Ok(job.snapshot())
    }

    async fn begin(
        &self,
        live: &PacketCaptureLiveApi,
        binding_handle: &str,
        interface_handle: &str,
        input: PacketCaptureStartInput,
        directory: PathBuf,
    ) -> Result<PacketCaptureEvidenceDto, PacketCaptureEvidenceError> {
        if !valid_handle(binding_handle)
            || !valid_handle(interface_handle)
            || !directory.is_absolute()
            || directory.as_os_str().len() > 32768
        {
            return Err(PacketCaptureEvidenceError::Invalid);
        }
        let (binding, interface) = live
            .resolve_evidence_interface(binding_handle, interface_handle)
            .map_err(|_| PacketCaptureEvidenceError::Stale)?;
        let request = input
            .into_request(interface.clone())
            .map_err(|_| PacketCaptureEvidenceError::Invalid)?;
        let plan =
            PacketCaptureService::plan(request).map_err(|_| PacketCaptureEvidenceError::Invalid)?;
        let sftp_session = self
            .services
            .sftp()
            .bind_session(binding.target().clone(), binding.session_id())
            .await
            .map_err(|_| PacketCaptureEvidenceError::Stale)?;
        let status = self
            .services
            .ssh()
            .list_sessions()
            .await
            .map_err(|_| PacketCaptureEvidenceError::Stale)?
            .into_iter()
            .find(|s| {
                s.session_id == binding.session_id() && s.connection_id == binding.connection_id()
            })
            .ok_or(PacketCaptureEvidenceError::Stale)?;
        let source = FileEvidenceSource::from_session(&sftp_session, &status)
            .map_err(|_| PacketCaptureEvidenceError::Stale)?;
        let host = if status.host.contains(':') {
            format!("[{}]", status.host)
        } else {
            status.host.clone()
        };
        let target_label = format!("{}@{}:{}", status.username, host, status.port);
        if target_label.len() > 1024 {
            return Err(PacketCaptureEvidenceError::Unavailable);
        }
        if !self.binding_current(binding_handle, &binding) {
            return Err(PacketCaptureEvidenceError::Stale);
        }
        let mut jobs = self.jobs.lock();
        if jobs
            .values()
            .any(|job| job.binding_handle == binding_handle && job.running())
        {
            return Err(PacketCaptureEvidenceError::Busy);
        }
        // A finished job for this connection is replaced only by another
        // explicit folder choice, never by a poll or a late completion.
        jobs.retain(|_, job| job.binding_handle != binding_handle);
        if jobs.len() >= MAX_JOBS {
            return Err(PacketCaptureEvidenceError::Capacity);
        }
        let identity = binding.target().identity.clone();
        let incident = self
            .services
            .investigation()
            .cases()
            .ensure_active(
                &identity,
                Some(format!(
                    "{} 的应急案件",
                    target_label.chars().take(80).collect::<String>()
                )),
            )
            .map_err(|error| match error {
                lovelyhawk_core::CoreError::Validation {
                    subject: "case capacity",
                    ..
                } => PacketCaptureEvidenceError::CaseCapacity,
                _ => PacketCaptureEvidenceError::Unavailable,
            })?;
        if incident.evidence.len() >= MAX_EVIDENCE || incident.timeline.len() >= MAX_TIMELINE {
            return Err(PacketCaptureEvidenceError::Capacity);
        }
        let reservation = self
            .services
            .investigation()
            .cases()
            .reserve_collection(&identity, &incident.id)
            .map_err(|_| PacketCaptureEvidenceError::Unavailable)?;
        let paths = PathGuard::for_store(self.services.store(), [])
            .map_err(|_| PacketCaptureEvidenceError::Unavailable)?;
        let mut bundle = FileEvidenceBundle::create_with_sample(&paths, &directory, SAMPLE_FILE)
            .map_err(|_| PacketCaptureEvidenceError::Unavailable)?;
        let destination = bundle
            .take_destination()
            .map_err(|_| PacketCaptureEvidenceError::Unavailable)?;
        let remote = RemotePath::new(plan.remote_path.clone())
            .map_err(|_| PacketCaptureEvidenceError::Unavailable)?;
        let id = uuid::Uuid::new_v4().to_string();
        let progress = FileEvidenceProgress::default();
        let dto = PacketCaptureEvidenceDto {
            job_handle: id.clone(),
            interface,
            duration_seconds: plan.request.duration_seconds,
            packet_limit: plan.request.packet_limit,
            filtered: plan.request.filter.is_some(),
            target_label,
            folder_name: bundle.folder_name().to_owned(),
            case_title: incident.title.clone(),
            state: "capturing",
            copied_bytes: 0,
            verified_bytes: 0,
            total_bytes: 0,
            sha256: None,
            detail: CAPTURING,
            tcpdump_line: None,
            temporary_file: "pending",
        };
        jobs.insert(
            id.clone(),
            Job {
                binding_handle: binding_handle.to_owned(),
                session: binding.clone(),
                remote_path: plan.remote_path.clone(),
                progress: progress.clone(),
                dto: dto.clone(),
                abort: None,
                created: Instant::now(),
            },
        );
        let api = self.clone();
        let job_id = id.clone();
        let incident_id = incident.id.clone();
        let task = tokio::spawn(async move {
            let _collection_reservation = reservation;
            let capture_started_at = chrono::Utc::now();
            let metadata = match api
                .services
                .packet_capture()
                .capture_planned(&binding, &plan)
                .await
            {
                Ok(Ok(metadata)) => metadata,
                Ok(Err(failure)) => {
                    let (detail, line) = match failure {
                        PcapEvidenceFailure::Preflight(reason) => (reason, None),
                        PcapEvidenceFailure::Tcpdump(line) => (TCPDUMP_REFUSED, Some(line)),
                        PcapEvidenceFailure::Empty => (EMPTY, None),
                        PcapEvidenceFailure::Failed => (FAILED, None),
                    };
                    api.fail(&job_id, detail, line, "none");
                    return;
                }
                Err(_) => {
                    api.fail(&job_id, INTERRUPTED, None, "none");
                    return;
                }
            };
            let capture_finished_at = chrono::Utc::now();
            let too_large = metadata.size_bytes > MAX_FILE_EVIDENCE_BYTES;
            {
                let mut jobs = api.jobs.lock();
                let Some(job) = jobs
                    .get_mut(&job_id)
                    .filter(|job| job.dto.state == "capturing")
                else {
                    return;
                };
                // An oversized file is reported by its own sentence; its size is
                // beyond what the page accepts as a byte count.
                if !too_large {
                    job.dto.total_bytes = metadata.size_bytes;
                    job.dto.state = "collecting";
                    job.dto.detail = COLLECTING;
                }
            }
            if too_large {
                let removed = api
                    .services
                    .packet_capture()
                    .cleanup_remote(&binding, &plan.remote_path)
                    .await
                    .is_ok();
                api.fail(
                    &job_id,
                    TOO_LARGE,
                    None,
                    if removed { "removed" } else { "left" },
                );
                return;
            }
            let collected = tokio::time::timeout(
                FILE_EVIDENCE_DEADLINE,
                api.services.sftp().collect_file_evidence(
                    &sftp_session,
                    &remote,
                    destination,
                    progress,
                ),
            )
            .await;
            let removed = api
                .services
                .packet_capture()
                .cleanup_remote(&binding, &plan.remote_path)
                .await
                .is_ok();
            // No await after this point: once a cancel has been answered a late
            // task cannot publish a manifest or a case record.
            let mut jobs = api.jobs.lock();
            let Some(job) = jobs
                .get_mut(&job_id)
                .filter(|job| job.dto.state == "collecting")
            else {
                return;
            };
            job.dto.temporary_file = if removed { "removed" } else { "left" };
            if !api.binding_current(&job.binding_handle, &job.session) {
                return;
            }
            let Ok(Ok(proof)) = collected else {
                job.dto.state = "failed";
                job.dto.detail = NOT_VERIFIED;
                return;
            };
            if proof.sha256 != metadata.sha256 || proof.bytes != metadata.size_bytes {
                job.dto.state = "failed";
                job.dto.detail = MISMATCH;
                return;
            }
            let sha256 = proof.sha256.clone();
            let context = PcapEvidenceContext {
                tool: "tcpdump".to_owned(),
                interface: plan.request.interface.clone(),
                filter: plan.request.filter.clone(),
                packet_limit: plan.request.packet_limit,
                duration_seconds: plan.request.duration_seconds,
                capture_started_at,
                capture_finished_at,
                target_bytes: metadata.size_bytes,
                target_sha256: metadata.sha256.clone(),
                target_temporary_path: plan.remote_path.clone(),
                target_temporary_removed: removed,
                limitations: PCAP_EVIDENCE_LIMITATIONS.to_owned(),
            };
            let preview = format!(
                "来源主机：{}\n接口：{}\n过滤条件：{}\n时长上限：{} 秒；包数上限：{}\n抓包开始（UTC）：{}\n抓包结束（UTC）：{}\n字节：{}\n方法：tcpdump 写入目标临时文件，目标上的 SHA-256 与两次 SFTP 读取及本地回读一致；临时文件{}。完整参数与限制见同目录 manifest.json。",
                job.dto.target_label,
                context.interface,
                context.filter.as_deref().unwrap_or("无"),
                context.duration_seconds,
                context
                    .packet_limit
                    .map_or_else(|| "不限".to_owned(), |count| count.to_string()),
                capture_started_at.to_rfc3339(),
                capture_finished_at.to_rfc3339(),
                proof.bytes,
                if removed { "已删除" } else { "未能删除" },
            );
            if bundle
                .finish_with_capture(source, &incident_id, proof, Some(context))
                .is_err()
            {
                job.dto.state = "failed";
                job.dto.detail = MANIFEST_FAILED;
                return;
            }
            job.dto.sha256 = Some(sha256.clone());
            let evidence = api.services.investigation().cases().add_evidence_to_case(
                &identity,
                &incident_id,
                AddEvidence {
                    kind: EvidenceKind::Pcap,
                    label: "抓包留证".to_owned(),
                    source: "packet-capture-evidence".to_owned(),
                    preview,
                    locator: Some(bundle.sample_locator()),
                    external_sha256: Some(sha256),
                },
            );
            if evidence.is_ok() {
                job.dto.state = "completed";
                job.dto.detail = COMPLETED;
            } else {
                job.dto.state = "saved-unlinked";
                job.dto.detail = SAVED_UNLINKED;
            }
        });
        if let Some(job) = jobs.get_mut(&id) {
            job.abort = Some(task.abort_handle());
        }
        Ok(dto)
    }

    fn fail(
        &self,
        job_id: &str,
        detail: &'static str,
        tcpdump_line: Option<String>,
        temporary_file: &'static str,
    ) {
        let mut jobs = self.jobs.lock();
        if let Some(job) = jobs.get_mut(job_id).filter(|job| job.running()) {
            job.dto.state = "failed";
            job.dto.detail = detail;
            job.dto.tcpdump_line = tcpdump_line;
            job.dto.temporary_file = temporary_file;
        }
    }
}

fn valid_handle(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}
