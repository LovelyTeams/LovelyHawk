//! File evidence collection accepts only a path capability. The local directory
//! is an internal main-process native-dialog result and never a renderer input.
use crate::emergency_path_api::{EmergencyPathApi, PathScope};
use lovelyhawk_core::{
    BackendServices,
    file_evidence::{
        FILE_EVIDENCE_DEADLINE, FileEvidenceBundle, FileEvidenceProgress, FileEvidenceSource,
    },
    investigation::{AddEvidence, EvidenceKind, MAX_EVIDENCE, MAX_TIMELINE},
    path_guard::PathGuard,
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

#[derive(Deserialize)]
#[serde(
    tag = "action",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum FileEvidenceRequest {
    Begin {
        binding_handle: String,
        path_handle: String,
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
pub(crate) struct FileEvidenceDto {
    job_handle: String,
    path_handle: String,
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
}

struct Job {
    scope: PathScope,
    progress: FileEvidenceProgress,
    dto: FileEvidenceDto,
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

#[derive(Clone)]
pub(crate) struct FileEvidenceApi {
    services: BackendServices,
    paths: EmergencyPathApi,
    jobs: Arc<Mutex<HashMap<String, Job>>>,
}
impl std::fmt::Debug for FileEvidenceApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileEvidenceApi")
            .field("jobs", &self.jobs.lock().len())
            .finish()
    }
}

#[derive(Debug)]
pub(crate) enum FileEvidenceError {
    Invalid,
    Stale,
    Busy,
    Capacity,
    CaseCapacity,
    Unavailable,
}

impl FileEvidenceApi {
    pub(crate) fn new(services: BackendServices, paths: EmergencyPathApi) -> Self {
        Self {
            services,
            paths,
            jobs: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub(crate) fn close_binding(&self, binding: &str) {
        self.jobs
            .lock()
            .retain(|_, job| job.scope.binding_handle != binding);
    }

    pub(crate) async fn dispatch(
        &self,
        request: FileEvidenceRequest,
    ) -> Result<FileEvidenceDto, FileEvidenceError> {
        self.jobs
            .lock()
            .retain(|_, job| job.created.elapsed() < RETENTION);
        match request {
            FileEvidenceRequest::Begin {
                binding_handle,
                path_handle,
                selected_directory,
            } => {
                self.begin(&binding_handle, &path_handle, selected_directory)
                    .await
            }
            FileEvidenceRequest::Poll {
                binding_handle,
                job_handle,
            } => self.poll(&binding_handle, &job_handle, false),
            FileEvidenceRequest::Cancel {
                binding_handle,
                job_handle,
            } => self.poll(&binding_handle, &job_handle, true),
        }
    }

    fn poll(
        &self,
        binding: &str,
        handle: &str,
        cancel: bool,
    ) -> Result<FileEvidenceDto, FileEvidenceError> {
        if !valid_handle(binding) || !valid_handle(handle) {
            return Err(FileEvidenceError::Invalid);
        }
        let mut jobs = self.jobs.lock();
        let job = jobs
            .get_mut(handle)
            .filter(|job| job.scope.binding_handle == binding)
            .ok_or(FileEvidenceError::Stale)?;
        self.paths
            .validate_binding(&job.scope)
            .map_err(|_| FileEvidenceError::Stale)?;
        if cancel && job.dto.state == "collecting" {
            if let Some(abort) = job.abort.take() {
                abort.abort();
            }
            job.dto.state = "cancelled";
            job.dto.detail = "已取消采集。所选目录可能保留不完整的 sample.bin；没有有效清单的文件不能算作已完成留证。";
        }
        Ok(job.snapshot())
    }

    async fn begin(
        &self,
        binding: &str,
        handle: &str,
        directory: PathBuf,
    ) -> Result<FileEvidenceDto, FileEvidenceError> {
        if !valid_handle(binding)
            || !valid_handle(handle)
            || !directory.is_absolute()
            || directory.as_os_str().len() > 32768
        {
            return Err(FileEvidenceError::Invalid);
        }
        let (scope, path) = self
            .paths
            .resolve_evidence_path(binding, handle)
            .map_err(|_| FileEvidenceError::Stale)?;
        let session = self
            .paths
            .bind_sftp(&scope)
            .await
            .map_err(|_| FileEvidenceError::Stale)?;
        let status = self
            .services
            .ssh()
            .list_sessions()
            .await
            .map_err(|_| FileEvidenceError::Stale)?
            .into_iter()
            .find(|s| s.session_id == scope.session_id && s.connection_id == scope.connection_id)
            .ok_or(FileEvidenceError::Stale)?;
        let source = FileEvidenceSource::from_session(&session, &status)
            .map_err(|_| FileEvidenceError::Stale)?;
        let host = if status.host.contains(':') {
            format!("[{}]", status.host)
        } else {
            status.host.clone()
        };
        let target_label = format!("{}@{}:{}", status.username, host, status.port);
        if target_label.len() > 1024 {
            return Err(FileEvidenceError::Unavailable);
        }
        self.paths
            .validate_binding(&scope)
            .map_err(|_| FileEvidenceError::Stale)?;
        let mut jobs = self.jobs.lock();
        if jobs
            .values()
            .any(|job| job.scope.binding_handle == binding && job.dto.state == "collecting")
        {
            return Err(FileEvidenceError::Busy);
        }
        // Completed jobs for this binding can be replaced only by another explicit
        // native-directory selection, never by polling or a late completion.
        jobs.retain(|_, job| job.scope.binding_handle != binding);
        if jobs.len() >= MAX_JOBS {
            return Err(FileEvidenceError::Capacity);
        }
        let cases = self.services.investigation().cases();
        let incident = cases
            .ensure_active(
                &scope.target.identity,
                Some(format!(
                    "{} 的应急案件",
                    target_label.chars().take(80).collect::<String>()
                )),
            )
            .map_err(|error| match error {
                lovelyhawk_core::CoreError::Validation {
                    subject: "case capacity",
                    ..
                } => FileEvidenceError::CaseCapacity,
                _ => FileEvidenceError::Unavailable,
            })?;
        if incident.evidence.len() >= MAX_EVIDENCE || incident.timeline.len() >= MAX_TIMELINE {
            return Err(FileEvidenceError::Capacity);
        }
        let reservation = self
            .services
            .investigation()
            .cases()
            .reserve_collection(&scope.target.identity, &incident.id)
            .map_err(|_| FileEvidenceError::Unavailable)?;
        let paths = PathGuard::for_store(self.services.store(), [])
            .map_err(|_| FileEvidenceError::Unavailable)?;
        let mut bundle = FileEvidenceBundle::create(&paths, &directory)
            .map_err(|_| FileEvidenceError::Unavailable)?;
        let destination = bundle
            .take_destination()
            .map_err(|_| FileEvidenceError::Unavailable)?;
        let id = uuid::Uuid::new_v4().to_string();
        let progress = FileEvidenceProgress::default();
        let dto = FileEvidenceDto {
            job_handle: id.clone(),
            path_handle: handle.to_owned(),
            path: path.as_str().to_owned(),
            target_label,
            folder_name: bundle.folder_name().to_owned(),
            case_title: incident.title.clone(),
            state: "collecting",
            copied_bytes: 0,
            verified_bytes: 0,
            total_bytes: 0,
            sha256: None,
            detail: "正在保存原始字节并核对远端与本地摘要。读取可能更新文件访问时间。",
        };
        jobs.insert(
            id.clone(),
            Job {
                scope: scope.clone(),
                progress: progress.clone(),
                dto: dto.clone(),
                abort: None,
                created: Instant::now(),
            },
        );
        let api = self.clone();
        let job_id = id.clone();
        let task = tokio::spawn(async move {
            let _collection_reservation = reservation;
            let result = tokio::time::timeout(
                FILE_EVIDENCE_DEADLINE,
                api.services
                    .sftp()
                    .collect_file_evidence(&session, &path, destination, progress),
            )
            .await;
            // Serialize finish with cancellation. No await after this point: once
            // cancellation reports success a late task cannot publish a manifest.
            let mut jobs = api.jobs.lock();
            let Some(job) = jobs
                .get_mut(&job_id)
                .filter(|j| j.scope == scope && j.dto.state == "collecting")
            else {
                return;
            };
            if api.paths.validate_binding(&scope).is_err() {
                return;
            }
            let Ok(Ok(proof)) = result else {
                job.dto.state = "failed";
                job.dto.detail = "采集未通过校验或已超时。请检查文件是否变化、读取权限、连接与本机空间；本目录保留的字节不能算作已完成留证。";
                return;
            };
            let sha256 = proof.sha256.clone();
            let preview = format!(
                "来源主机：{}\n来源文件：{}\n字节：{}\n采集完成（UTC）：{}\n方法：两次远端读取与本地回读一致；读取可能更新访问时间，不等同于原子快照。完整属性与限制见同目录 manifest.json。",
                job.dto.target_label,
                path.as_str(),
                proof.bytes,
                proof.completed_at.to_rfc3339()
            );
            if bundle.finish(source, &incident.id, proof).is_err() {
                job.dto.state = "failed";
                job.dto.detail = "原始字节已下载，但证据清单写入失败。请检查本机空间和目录权限；尚未登记为案件证据。";
                return;
            }
            job.dto.sha256 = Some(sha256.clone());
            let evidence = api.services.investigation().cases().add_evidence_to_case(
                &scope.target.identity,
                &incident.id,
                AddEvidence {
                    kind: EvidenceKind::Path,
                    label: "文件留证".to_owned(),
                    source: "emergency-file-collection".to_owned(),
                    preview,
                    locator: Some(bundle.sample_locator()),
                    external_sha256: Some(sha256),
                },
            );
            if evidence.is_ok() {
                job.dto.state = "completed";
                job.dto.detail = "原始文件与清单已保存，三次摘要一致，已关联到本次采集开始时的案件；处置报告可包含这条证据。";
            } else {
                job.dto.state = "saved-unlinked";
                job.dto.detail = "原始文件与清单已完整保存，但案件记录写入失败或案件已关闭。请保留该目录；本次证据尚未进入报告。";
            }
        });
        if let Some(job) = jobs.get_mut(&id) {
            job.abort = Some(task.abort_handle());
        }
        Ok(dto)
    }
}

impl Job {
    fn snapshot(&self) -> FileEvidenceDto {
        let mut dto = self.dto.clone();
        // Read the later phase first. Otherwise a context switch between loads
        // could produce a DTO with verified > copied despite a valid transfer.
        dto.verified_bytes = self.progress.verified_bytes();
        dto.copied_bytes = self.progress.copied_bytes();
        dto.total_bytes = self.progress.total_bytes();
        dto
    }
}
fn valid_handle(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}
