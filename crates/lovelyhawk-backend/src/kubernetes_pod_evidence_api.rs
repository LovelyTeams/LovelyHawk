//! A file inside a pod kept as case evidence. The pod is the list row's and
//! the container one of its own; the file is copied by `kubectl exec cat` to
//! a managed temporary file on the SSH host, checked against the length and
//! SHA-256 taken inside the pod before and after the copy, then collected like
//! any other file evidence (two SFTP reads and a local read-back), and the
//! temporary file is removed. The local directory is the host's folder dialog
//! result and never a page input.
use crate::{kubernetes_read_api::KubernetesReadApi, ssh_api::SshApi};
use lovelyhawk_core::{
    BackendServices, CoreError,
    docker::ContainerFilePath,
    file_evidence::{
        FILE_EVIDENCE_DEADLINE, FileEvidenceBundle, FileEvidenceProgress, FileEvidenceSource,
        MAX_FILE_EVIDENCE_BYTES,
    },
    investigation::{AddEvidence, EvidenceKind, MAX_EVIDENCE, MAX_TIMELINE},
    kubernetes::{POD_FILE_EVIDENCE_LIMITATIONS, PodFileEvidenceContext, new_pod_file_stage_path},
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
const SAMPLE_FILE: &str = "pod-file.bin";

const COPYING: &str = "正在把 Pod 里的文件复制到 SSH 主机的临时文件（/tmp），复制前后在 Pod 里各核对一次长度和 SHA-256。";
const COLLECTING: &str = "已复制到 SSH 主机，正在读回本机并核对摘要。";
const COMPLETED: &str = "文件和清单已保存。Pod 里复制前后的 SHA-256 与主机上的副本、两次读取和本地回读一致，已关联到本次开始时的案件；处置报告可包含这条证据。";
const SAVED_UNLINKED: &str =
    "文件和清单已完整保存，但案件记录写入失败或案件已关闭。请保留该目录；这条证据尚未进入报告。";
const CANCELLED: &str = "已取消。正在结束复制并删除 SSH 主机上的临时文件；所选目录里没有 manifest.json 的文件不能算作留证。";
const MISSING: &str = "这个文件不存在，没有复制。";
const NOT_REGULAR: &str = "这不是普通文件（可能是符号链接、目录或设备），不能留证。";
const TOO_LARGE: &str = "文件超过 512 MB 的留证上限，没有复制。";
const CHANGED: &str = "复制期间文件有变化，或复制出的字节与 Pod 里的不一致，没有留证。";
const EXEC_FORBIDDEN: &str = "当前账号没有在这个 Pod 里执行命令（pods/exec）的权限，无法复制文件。";
const FORBIDDEN: &str = "集群拒绝了当前账号读取这个 Pod（权限不足），没有复制。";
const POD_GONE: &str =
    "这个 Pod 已不是列表里那个运行中的 Pod，或所选容器没有在运行，请刷新列表后再试。";
const COPY_FAILED: &str = "没能把文件复制到 SSH 主机：容器里可能没有 cat 或 sha256sum、主机 /tmp 不可写、主机上没有 sha256sum，或连接中断。";
const NOT_VERIFIED: &str = "主机上的副本没有通过留证校验或读取超时：读取期间文件有变化、权限不足、连接中断或本机空间不足。所选目录里的字节不能算作留证。";
const MISMATCH: &str =
    "读回的字节与 Pod 里核对的 SHA-256 不一致，没有登记为证据。所选目录里的字节不能算作留证。";
const MANIFEST_FAILED: &str =
    "文件已下载，但证据清单写入失败。请检查本机空间和目录权限；尚未登记为案件证据。";

#[derive(Deserialize)]
#[serde(
    tag = "action",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum PodFileEvidenceRequest {
    Begin {
        binding_handle: String,
        snapshot_handle: String,
        row_handle: String,
        container: Option<String>,
        path: String,
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
pub(crate) struct PodFileEvidenceDto {
    job_handle: String,
    /// `namespace/name`, as listed.
    pod: String,
    /// The container chosen; null for the pod's default one.
    container: Option<String>,
    path: String,
    target_label: String,
    folder_name: String,
    case_title: String,
    state: &'static str,
    copied_bytes: u64,
    verified_bytes: u64,
    total_bytes: u64,
    sha256: Option<String>,
    detail: &'static str,
    /// What became of the copy on the SSH host: "pending" while it may still
    /// be there, "removed", "left" when removing it failed, "none" when no
    /// copy was made.
    temporary_file: &'static str,
}

struct Job {
    binding_handle: String,
    session: BoundSshSession,
    host_path: String,
    progress: FileEvidenceProgress,
    dto: PodFileEvidenceDto,
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
    fn snapshot(&self) -> PodFileEvidenceDto {
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
        matches!(self.dto.state, "copying" | "collecting")
    }
}

#[derive(Clone)]
pub(crate) struct PodFileEvidenceApi {
    services: BackendServices,
    ssh_api: Arc<SshApi>,
    read: Arc<KubernetesReadApi>,
    jobs: Arc<Mutex<HashMap<String, Job>>>,
}

impl std::fmt::Debug for PodFileEvidenceApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PodFileEvidenceApi")
            .field("jobs", &self.jobs.lock().len())
            .finish()
    }
}

#[derive(Debug)]
pub(crate) enum PodFileEvidenceError {
    Invalid,
    Stale,
    Busy,
    Capacity,
    CaseCapacity,
    Unavailable,
}

impl PodFileEvidenceApi {
    pub(crate) fn new(
        services: BackendServices,
        ssh_api: Arc<SshApi>,
        read: Arc<KubernetesReadApi>,
    ) -> Self {
        Self {
            services,
            ssh_api,
            read,
            jobs: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Jobs end with their connection; a copy still running on the host stops
    /// with the connection's commands.
    pub(crate) fn close_binding(&self, binding: &str) {
        self.jobs
            .lock()
            .retain(|_, job| job.binding_handle != binding);
    }

    pub(crate) async fn dispatch(
        &self,
        request: PodFileEvidenceRequest,
    ) -> Result<PodFileEvidenceDto, PodFileEvidenceError> {
        self.jobs
            .lock()
            .retain(|_, job| job.running() || job.created.elapsed() < RETENTION);
        match request {
            PodFileEvidenceRequest::Begin {
                binding_handle,
                snapshot_handle,
                row_handle,
                container,
                path,
                selected_directory,
            } => {
                self.begin(
                    &binding_handle,
                    &snapshot_handle,
                    &row_handle,
                    container,
                    &path,
                    selected_directory,
                )
                .await
            }
            PodFileEvidenceRequest::Poll {
                binding_handle,
                job_handle,
            } => self.poll(&binding_handle, &job_handle, false),
            PodFileEvidenceRequest::Cancel {
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
    ) -> Result<PodFileEvidenceDto, PodFileEvidenceError> {
        if !valid_handle(binding) || !valid_handle(handle) {
            return Err(PodFileEvidenceError::Invalid);
        }
        let mut jobs = self.jobs.lock();
        let job = jobs
            .get_mut(handle)
            .filter(|job| job.binding_handle == binding)
            .ok_or(PodFileEvidenceError::Stale)?;
        if !self.binding_current(binding, &job.session) {
            return Err(PodFileEvidenceError::Stale);
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
            let path = job.host_path.clone();
            let jobs = self.jobs.clone();
            let id = handle.to_owned();
            tokio::spawn(async move {
                let removed = services
                    .kubernetes()
                    .remove_pod_file_stage(&session, &path)
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
        binding_handle: &str,
        snapshot_handle: &str,
        row_handle: &str,
        container: Option<String>,
        path: &str,
        directory: PathBuf,
    ) -> Result<PodFileEvidenceDto, PodFileEvidenceError> {
        if !valid_handle(binding_handle)
            || !valid_handle(snapshot_handle)
            || !valid_handle(row_handle)
            || !directory.is_absolute()
            || directory.as_os_str().len() > 32768
        {
            return Err(PodFileEvidenceError::Invalid);
        }
        let path = ContainerFilePath::new(path).map_err(|_| PodFileEvidenceError::Invalid)?;
        let (binding, pod) = self
            .read
            .resolve_pod_for_terminal(binding_handle, snapshot_handle, row_handle)
            .map_err(|_| PodFileEvidenceError::Stale)?;
        // A name that is not one of this pod's containers is refused before
        // anything runs; the core checks it again before each step.
        if container
            .as_deref()
            .is_some_and(|name| pod.container(name).is_none())
        {
            return Err(PodFileEvidenceError::Stale);
        }
        let sftp_session = self
            .services
            .sftp()
            .bind_session(binding.target().clone(), binding.session_id())
            .await
            .map_err(|_| PodFileEvidenceError::Stale)?;
        let status = self
            .services
            .ssh()
            .list_sessions()
            .await
            .map_err(|_| PodFileEvidenceError::Stale)?
            .into_iter()
            .find(|s| {
                s.session_id == binding.session_id() && s.connection_id == binding.connection_id()
            })
            .ok_or(PodFileEvidenceError::Stale)?;
        let source = FileEvidenceSource::from_session(&sftp_session, &status)
            .map_err(|_| PodFileEvidenceError::Stale)?;
        let host = if status.host.contains(':') {
            format!("[{}]", status.host)
        } else {
            status.host.clone()
        };
        let target_label = format!("{}@{}:{}", status.username, host, status.port);
        if target_label.len() > 1024 {
            return Err(PodFileEvidenceError::Unavailable);
        }
        if !self.binding_current(binding_handle, &binding) {
            return Err(PodFileEvidenceError::Stale);
        }
        let mut jobs = self.jobs.lock();
        if jobs
            .values()
            .any(|job| job.binding_handle == binding_handle && job.running())
        {
            return Err(PodFileEvidenceError::Busy);
        }
        // A finished job for this connection is replaced only by another
        // explicit folder choice, never by a poll or a late completion.
        jobs.retain(|_, job| job.binding_handle != binding_handle);
        if jobs.len() >= MAX_JOBS {
            return Err(PodFileEvidenceError::Capacity);
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
                CoreError::Validation {
                    subject: "case capacity",
                    ..
                } => PodFileEvidenceError::CaseCapacity,
                _ => PodFileEvidenceError::Unavailable,
            })?;
        if incident.evidence.len() >= MAX_EVIDENCE || incident.timeline.len() >= MAX_TIMELINE {
            return Err(PodFileEvidenceError::Capacity);
        }
        let reservation = self
            .services
            .investigation()
            .cases()
            .reserve_collection(&identity, &incident.id)
            .map_err(|_| PodFileEvidenceError::Unavailable)?;
        let paths = PathGuard::for_store(self.services.store(), [])
            .map_err(|_| PodFileEvidenceError::Unavailable)?;
        let mut bundle = FileEvidenceBundle::create_with_sample(&paths, &directory, SAMPLE_FILE)
            .map_err(|_| PodFileEvidenceError::Unavailable)?;
        let destination = bundle
            .take_destination()
            .map_err(|_| PodFileEvidenceError::Unavailable)?;
        let host_path = new_pod_file_stage_path();
        let remote =
            RemotePath::new(host_path.clone()).map_err(|_| PodFileEvidenceError::Unavailable)?;
        let id = uuid::Uuid::new_v4().to_string();
        let progress = FileEvidenceProgress::default();
        let dto = PodFileEvidenceDto {
            job_handle: id.clone(),
            pod: format!("{}/{}", pod.namespace, pod.name),
            container: container.clone(),
            path: path.as_str().to_owned(),
            target_label,
            folder_name: bundle.folder_name().to_owned(),
            case_title: incident.title.clone(),
            state: "copying",
            copied_bytes: 0,
            verified_bytes: 0,
            total_bytes: 0,
            sha256: None,
            detail: COPYING,
            temporary_file: "pending",
        };
        jobs.insert(
            id.clone(),
            Job {
                binding_handle: binding_handle.to_owned(),
                session: binding.clone(),
                host_path: host_path.clone(),
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
            let kubernetes = api.services.kubernetes();
            let staged = kubernetes
                .stage_pod_file(
                    &binding,
                    &pod,
                    container.as_deref(),
                    &path,
                    &host_path,
                    MAX_FILE_EVIDENCE_BYTES,
                )
                .await;
            let stage = match staged {
                Ok(stage) => stage,
                Err(error) => {
                    // The core removed its copy before answering, or never
                    // made one; what is left is checked once more.
                    let removed = kubernetes
                        .remove_pod_file_stage(&binding, &host_path)
                        .await
                        .is_ok();
                    api.fail(
                        &job_id,
                        stage_failure(&error),
                        if removed { "none" } else { "left" },
                    );
                    return;
                }
            };
            {
                let mut jobs = api.jobs.lock();
                let Some(job) = jobs
                    .get_mut(&job_id)
                    .filter(|job| job.dto.state == "copying")
                else {
                    return;
                };
                job.dto.total_bytes = stage.bytes;
                job.dto.state = "collecting";
                job.dto.detail = COLLECTING;
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
            let removed = kubernetes
                .remove_pod_file_stage(&binding, &host_path)
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
            if proof.sha256 != stage.sha256 || proof.bytes != stage.bytes {
                job.dto.state = "failed";
                job.dto.detail = MISMATCH;
                return;
            }
            let sha256 = proof.sha256.clone();
            let context = PodFileEvidenceContext {
                tool: "kubectl exec cat".to_owned(),
                kube_context: stage.context.clone(),
                namespace: pod.namespace.clone(),
                pod: pod.name.clone(),
                pod_uid: stage.pod_uid.clone(),
                container: stage.container.clone(),
                path: path.as_str().to_owned(),
                copied_at: stage.copied_at,
                pod_bytes: stage.bytes,
                pod_sha256: stage.sha256.clone(),
                host_temporary_path: host_path.clone(),
                host_temporary_removed: removed,
                limitations: POD_FILE_EVIDENCE_LIMITATIONS.to_owned(),
            };
            let preview = format!(
                "来源主机：{}\nPod：{}/{}（UID {}）\n容器：{}\n路径：{}\nkubeconfig 上下文：{}\n复制时间（UTC）：{}\n字节：{}\n方法：kubectl exec 把原始字节复制到 SSH 主机的临时文件，Pod 里复制前后的 SHA-256 与主机副本、两次 SFTP 读取及本地回读一致；临时文件{}。完整参数与限制见同目录 manifest.json。",
                job.dto.target_label,
                context.namespace,
                context.pod,
                context.pod_uid,
                context.container.as_deref().unwrap_or("默认容器"),
                context.path,
                if context.kube_context.is_empty() {
                    "（未读到）"
                } else {
                    context.kube_context.as_str()
                },
                context.copied_at.to_rfc3339(),
                proof.bytes,
                if removed { "已删除" } else { "未能删除" },
            );
            if bundle
                .finish_with_pod_file(source, &incident_id, proof, context)
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
                    kind: EvidenceKind::Path,
                    label: "Pod 文件留证".to_owned(),
                    source: "kubernetes-pod-file-evidence".to_owned(),
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

    fn fail(&self, job_id: &str, detail: &'static str, temporary_file: &'static str) {
        let mut jobs = self.jobs.lock();
        if let Some(job) = jobs.get_mut(job_id).filter(|job| job.running()) {
            job.dto.state = "failed";
            job.dto.detail = detail;
            job.dto.temporary_file = temporary_file;
        }
    }
}

/// Which of its fixed sentences a copy that did not happen gets. The core's
/// own words stay in the log; the page reads one of these.
fn stage_failure(error: &CoreError) -> &'static str {
    let CoreError::Validation { subject, message } = error else {
        return COPY_FAILED;
    };
    match *subject {
        "Kubernetes pod exec" => EXEC_FORBIDDEN,
        "Kubernetes permission" => FORBIDDEN,
        "Kubernetes pod shell" | "Kubernetes pod container" | "Kubernetes container name" => {
            POD_GONE
        }
        "Kubernetes pod file" if message.contains("不存在") => MISSING,
        "Kubernetes pod file" if message.contains("不是普通文件") => NOT_REGULAR,
        "Kubernetes pod file" if message.contains("上限") => TOO_LARGE,
        "Kubernetes pod file" if message.contains("变") => CHANGED,
        _ => COPY_FAILED,
    }
}

fn valid_handle(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invalid(subject: &'static str, message: &str) -> CoreError {
        CoreError::Validation {
            subject,
            message: message.to_owned(),
        }
    }

    #[test]
    fn each_copy_that_did_not_happen_says_which_reason_it_was() {
        for (error, expected) in [
            (invalid("Kubernetes pod exec", "x"), EXEC_FORBIDDEN),
            (invalid("Kubernetes permission", "x"), FORBIDDEN),
            (invalid("Kubernetes pod shell", "x"), POD_GONE),
            (invalid("Kubernetes pod container", "没有在运行"), POD_GONE),
            (invalid("Kubernetes pod file", "这个文件不存在"), MISSING),
            (
                invalid("Kubernetes pod file", "这不是普通文件（可能是符号链接）"),
                NOT_REGULAR,
            ),
            (
                invalid(
                    "Kubernetes pod file",
                    "文件有 9 字节，超过了留证上限 1 字节",
                ),
                TOO_LARGE,
            ),
            (invalid("Kubernetes pod file", "复制期间文件变了"), CHANGED),
            (invalid("Kubernetes command", "HOSTILE"), COPY_FAILED),
            (CoreError::NoActiveTarget, COPY_FAILED),
        ] {
            assert_eq!(stage_failure(&error), expected, "{error:?}");
        }
    }
}
