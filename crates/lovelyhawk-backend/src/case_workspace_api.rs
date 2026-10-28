//! Local case intents scoped to the live SSH binding. No target strings,
//! commands, hashes, evidence paths or operation receipts are accepted as input.
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use lovelyhawk_core::{
    BackendServices, CoreError,
    investigation::{
        AddEvidence, CaseStatus, EvidenceHashScope, EvidenceKind, IncidentCase, IocType,
    },
    ssh::BoundSshSession,
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    disposal_report_api::{DisposalReportApi, DisposalReportSnapshotDto},
    ssh_api::SshApi,
};

const PAGE_SIZE: usize = 25;
const SNAPSHOT_TTL: Duration = Duration::from_secs(300);
const MAX_SNAPSHOTS: usize = 4;
const MAX_SNAPSHOT_BYTES: usize = 32 * 1024 * 1024;
const MAX_CACHE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(
    tag = "action",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum CaseWorkspaceRequest {
    List {
        binding_handle: String,
    },
    Create {
        binding_handle: String,
        title: String,
        mutation_id: String,
    },
    Select {
        binding_handle: String,
        case_id: String,
    },
    View {
        binding_handle: String,
        case_id: String,
    },
    Items {
        binding_handle: String,
        snapshot_handle: String,
        section: CaseSection,
        query: String,
        offset: usize,
    },
    Note {
        binding_handle: String,
        case_id: String,
        title: String,
        content: String,
    },
    Ioc {
        binding_handle: String,
        case_id: String,
        ioc_type: IocType,
        value: String,
    },
    AttachNote {
        binding_handle: String,
        case_id: String,
        note_id: String,
        revision: String,
    },
    Report {
        binding_handle: String,
        snapshot_handle: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CaseSection {
    Evidence,
    Iocs,
    Timeline,
}

#[derive(Debug, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub(crate) enum CaseWorkspaceResult {
    List {
        cases: Vec<CaseSummary>,
        active_case_id: Option<String>,
        total_cases: usize,
    },
    View {
        snapshot_handle: String,
        incident: CaseSummary,
    },
    Items {
        snapshot_handle: String,
        section: CaseSection,
        query: String,
        offset: usize,
        total: usize,
        has_more: bool,
        items: Vec<CaseEntry>,
    },
    Changed {
        case_id: String,
        message: &'static str,
    },
    Report {
        report: DisposalReportSnapshotDto,
    },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CaseSummary {
    id: String,
    title: String,
    status: CaseStatus,
    created_at: i64,
    updated_at: i64,
    evidence_count: usize,
    ioc_count: usize,
    timeline_count: usize,
}
impl From<&IncidentCase> for CaseSummary {
    fn from(case: &IncidentCase) -> Self {
        Self {
            id: case.id.clone(),
            title: case.title.clone(),
            status: case.status,
            created_at: case.created_at,
            updated_at: case.updated_at,
            evidence_count: case.evidence.len(),
            ioc_count: case.iocs.len(),
            timeline_count: case.timeline.len(),
        }
    }
}
impl From<&lovelyhawk_core::investigation::CaseLibraryRecord> for CaseSummary {
    fn from(record: &lovelyhawk_core::investigation::CaseLibraryRecord) -> Self {
        Self {
            id: record.case_id.clone(),
            title: record.title.clone(),
            status: record.status,
            created_at: record.created_at,
            updated_at: record.updated_at,
            evidence_count: record.evidence_count,
            ioc_count: record.ioc_count,
            timeline_count: record.timeline_count,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CaseEntry {
    id: String,
    category: String,
    title: String,
    text: String,
    source: String,
    locator: Option<String>,
    sha256: Option<String>,
    hash_scope: Option<EvidenceHashScope>,
    timestamp: i64,
    evidence_id: Option<String>,
    ioc_id: Option<String>,
    operation_id: Option<String>,
}

struct Snapshot {
    session: BoundSshSession,
    binding: String,
    case: Arc<IncidentCase>,
    bytes: usize,
    expires: Instant,
}
pub(crate) struct CaseWorkspaceApi {
    services: BackendServices,
    ssh: Arc<SshApi>,
    snapshots: Mutex<HashMap<String, Snapshot>>,
}
impl std::fmt::Debug for CaseWorkspaceApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaseWorkspaceApi")
            .field("snapshots", &self.snapshots.lock().len())
            .finish()
    }
}
#[derive(Debug)]
pub(crate) enum CaseWorkspaceError {
    Invalid,
    Stale,
    Capacity,
    TimelineCapacity,
    EvidenceCapacity,
    IocCapacity,
    NoteChanged,
    NoteTooLarge,
    Unavailable,
    ReportUnavailable,
}
impl From<CoreError> for CaseWorkspaceError {
    fn from(error: CoreError) -> Self {
        match error {
            CoreError::Validation {
                subject: "case capacity",
                ..
            } => Self::Capacity,
            CoreError::Validation {
                subject: "case timeline capacity",
                ..
            } => Self::TimelineCapacity,
            CoreError::Validation {
                subject: "case evidence capacity",
                ..
            } => Self::EvidenceCapacity,
            CoreError::Validation {
                subject: "case IOC capacity",
                ..
            } => Self::IocCapacity,
            CoreError::Validation {
                subject: "note revision",
                ..
            } => Self::NoteChanged,
            CoreError::Validation {
                subject: "case note content",
                ..
            } => Self::NoteTooLarge,
            _ => Self::Unavailable,
        }
    }
}

impl CaseWorkspaceApi {
    pub(crate) fn new(services: BackendServices, ssh: Arc<SshApi>) -> Self {
        Self {
            services,
            ssh,
            snapshots: Mutex::new(HashMap::new()),
        }
    }
    pub(crate) fn close_binding(&self, binding: &str) {
        self.snapshots
            .lock()
            .retain(|_, item| item.binding != binding);
    }
    fn session(&self, binding: &str) -> Result<BoundSshSession, CaseWorkspaceError> {
        if !handle(binding) {
            return Err(CaseWorkspaceError::Invalid);
        }
        let session = self
            .ssh
            .binding_session_clone(binding)
            .map_err(|_| CaseWorkspaceError::Stale)?;
        self.services
            .target()
            .validate(session.target())
            .map_err(|_| CaseWorkspaceError::Stale)?;
        Ok(session)
    }
    fn snapshot(
        &self,
        binding: &str,
        session: &BoundSshSession,
        handle: &str,
    ) -> Result<Arc<IncidentCase>, CaseWorkspaceError> {
        let mut snapshots = self.snapshots.lock();
        snapshots.retain(|_, item| item.expires > Instant::now());
        snapshots
            .get(handle)
            .filter(|item| item.binding == binding && &item.session == session)
            .map(|item| Arc::clone(&item.case))
            .ok_or(CaseWorkspaceError::Stale)
    }
    pub(crate) fn dispatch(
        &self,
        request: CaseWorkspaceRequest,
        reports: &DisposalReportApi,
    ) -> Result<CaseWorkspaceResult, CaseWorkspaceError> {
        request.validate()?;
        let binding = request.binding().to_owned();
        let session = self.session(&binding)?;
        let target = &session.target().identity;
        let cases = self.services.investigation().cases();
        let result = match request {
            CaseWorkspaceRequest::List { .. } => {
                let overview = cases.overview(target)?;
                CaseWorkspaceResult::List {
                    cases: overview.cases.iter().map(CaseSummary::from).collect(),
                    active_case_id: overview.active_case_id,
                    total_cases: overview.total_cases,
                }
            }
            CaseWorkspaceRequest::Create {
                title, mutation_id, ..
            } => {
                let case = cases.create_idempotent(target, title, &mutation_id)?;
                CaseWorkspaceResult::Changed {
                    case_id: case.id,
                    message: "案件已创建。可在列表中核对当前归档案件。",
                }
            }
            CaseWorkspaceRequest::Select { case_id, .. } => {
                cases.select(target, &case_id)?;
                CaseWorkspaceResult::Changed {
                    case_id,
                    message: "已设为当前案件。之后开始的采集将归入此案，进行中的采集保持原归属。",
                }
            }
            CaseWorkspaceRequest::View { case_id, .. } => {
                let case = cases.export(target, &case_id)?.incident_case;
                let bytes = serde_json::to_vec(&case)
                    .map_err(|_| CaseWorkspaceError::Unavailable)?
                    .len();
                if bytes > MAX_SNAPSHOT_BYTES {
                    return Err(CaseWorkspaceError::Unavailable);
                }
                let incident = CaseSummary::from(&case);
                let snapshot_handle = Uuid::new_v4().to_string();
                let mut snapshots = self.snapshots.lock();
                snapshots
                    .retain(|_, item| item.expires > Instant::now() && item.binding != binding);
                if snapshots.len() >= MAX_SNAPSHOTS
                    || snapshots
                        .values()
                        .map(|item| item.bytes)
                        .sum::<usize>()
                        .saturating_add(bytes)
                        > MAX_CACHE_BYTES
                {
                    return Err(CaseWorkspaceError::Unavailable);
                }
                snapshots.insert(
                    snapshot_handle.clone(),
                    Snapshot {
                        session: session.clone(),
                        binding: binding.clone(),
                        case: Arc::new(case),
                        bytes,
                        expires: Instant::now() + SNAPSHOT_TTL,
                    },
                );
                CaseWorkspaceResult::View {
                    snapshot_handle,
                    incident,
                }
            }
            CaseWorkspaceRequest::Items {
                snapshot_handle,
                section,
                query,
                offset,
                ..
            } => {
                let case = self.snapshot(&binding, &session, &snapshot_handle)?;
                page(&case, snapshot_handle, section, query, offset)
            }
            CaseWorkspaceRequest::Note {
                case_id,
                title,
                content,
                ..
            } => {
                cases.add_evidence_to_case(
                    target,
                    &case_id,
                    AddEvidence {
                        kind: EvidenceKind::Note,
                        label: title,
                        source: "case-workspace-manual".to_owned(),
                        preview: content,
                        locator: None,
                        external_sha256: None,
                    },
                )?;
                CaseWorkspaceResult::Changed {
                    case_id,
                    message: "调查记录已保存为证据，并加入时间线。相同内容重复提交只保留一份。",
                }
            }
            CaseWorkspaceRequest::Ioc {
                case_id,
                ioc_type,
                value,
                ..
            } => {
                cases.add_ioc_to_case(
                    target,
                    &case_id,
                    ioc_type,
                    value,
                    "case-workspace-manual".to_owned(),
                )?;
                CaseWorkspaceResult::Changed {
                    case_id,
                    message: "调查线索已加入案件。手工记录的线索不代表已证实入侵。",
                }
            }
            CaseWorkspaceRequest::AttachNote {
                case_id,
                note_id,
                revision,
                ..
            } => {
                cases.attach_note_to_case(target, &case_id, &note_id, &revision)?;
                CaseWorkspaceResult::Changed {
                    case_id,
                    message: "已将所选版本的笔记保存为案件证据。之后修改笔记不会改变此快照。",
                }
            }
            CaseWorkspaceRequest::Report {
                snapshot_handle, ..
            } => {
                let case = self.snapshot(&binding, &session, &snapshot_handle)?;
                CaseWorkspaceResult::Report {
                    report: reports
                        .generate_for_case(&binding, (*case).clone())
                        .map_err(|_| CaseWorkspaceError::ReportUnavailable)?,
                }
            }
        };
        if self.session(&binding)? != session {
            return Err(CaseWorkspaceError::Stale);
        }
        Ok(result)
    }
}

pub(crate) fn page(
    case: &IncidentCase,
    snapshot_handle: String,
    section: CaseSection,
    query: String,
    offset: usize,
) -> CaseWorkspaceResult {
    let search = query.trim().to_lowercase();
    let entries: Vec<CaseEntry> = match section {
        CaseSection::Evidence => case
            .evidence
            .iter()
            .map(|item| CaseEntry {
                id: item.id.clone(),
                category: enum_text(item.kind),
                title: item.label.clone(),
                text: item.preview.clone(),
                source: item.source.clone(),
                locator: item.locator.clone(),
                sha256: Some(item.sha256.clone()),
                hash_scope: Some(item.hash_scope),
                timestamp: item.collected_at,
                evidence_id: None,
                ioc_id: None,
                operation_id: None,
            })
            .collect(),
        CaseSection::Iocs => case
            .iocs
            .iter()
            .map(|item| CaseEntry {
                id: item.id.clone(),
                category: enum_text(item.ioc_type),
                title: item.value.clone(),
                text: String::new(),
                source: item.source.clone(),
                locator: None,
                sha256: None,
                hash_scope: None,
                timestamp: item.added_at,
                evidence_id: None,
                ioc_id: None,
                operation_id: None,
            })
            .collect(),
        CaseSection::Timeline => case
            .timeline
            .iter()
            .map(|item| CaseEntry {
                id: item.id.clone(),
                category: enum_text(item.event_type),
                title: item.title.clone(),
                text: item.detail.clone().unwrap_or_default(),
                source: item.source.clone(),
                locator: None,
                sha256: None,
                hash_scope: None,
                timestamp: item.timestamp,
                evidence_id: item.evidence_id.clone(),
                ioc_id: item.ioc_id.clone(),
                operation_id: item.operation_id.clone(),
            })
            .collect(),
    };
    let filtered: Vec<_> = entries
        .into_iter()
        .filter(|entry| {
            [
                &entry.id,
                &entry.title,
                &entry.text,
                &entry.source,
                entry.locator.as_deref().unwrap_or_default(),
                entry.sha256.as_deref().unwrap_or_default(),
            ]
            .iter()
            .any(|value| value.to_lowercase().contains(&search))
        })
        .collect();
    let total = filtered.len();
    let items: Vec<_> = filtered.into_iter().skip(offset).take(PAGE_SIZE).collect();
    CaseWorkspaceResult::Items {
        snapshot_handle,
        section,
        query,
        offset,
        total,
        has_more: offset.saturating_add(items.len()) < total,
        items,
    }
}
fn enum_text(value: impl Serialize) -> String {
    // These three core enums serialize only to closed kebab-case strings.
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}
fn handle(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}
fn id(value: &str) -> bool {
    !value.trim().is_empty() && value.chars().count() <= 128 && !value.chars().any(char::is_control)
}
fn text(value: &str, maximum: usize, empty: bool) -> bool {
    (empty || !value.trim().is_empty()) && value.chars().count() <= maximum
}

impl CaseWorkspaceRequest {
    fn binding(&self) -> &str {
        match self {
            Self::List { binding_handle }
            | Self::Create { binding_handle, .. }
            | Self::Select { binding_handle, .. }
            | Self::View { binding_handle, .. }
            | Self::Items { binding_handle, .. }
            | Self::Note { binding_handle, .. }
            | Self::Ioc { binding_handle, .. }
            | Self::AttachNote { binding_handle, .. }
            | Self::Report { binding_handle, .. } => binding_handle,
        }
    }
    fn validate(&self) -> Result<(), CaseWorkspaceError> {
        let valid = handle(self.binding())
            && match self {
                Self::List { .. } => true,
                Self::Create {
                    title, mutation_id, ..
                } => {
                    text(title, 160, false)
                        && (16..=64).contains(&mutation_id.len())
                        && mutation_id.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
                        })
                }
                Self::Select { case_id, .. } | Self::View { case_id, .. } => id(case_id),
                Self::Items {
                    snapshot_handle,
                    query,
                    offset,
                    ..
                } => handle(snapshot_handle) && text(query, 256, true) && *offset <= 1000,
                Self::Note {
                    case_id,
                    title,
                    content,
                    ..
                } => id(case_id) && text(title, 256, false) && text(content, 4096, false),
                Self::Ioc { case_id, value, .. } => id(case_id) && text(value, 2048, false),
                Self::AttachNote {
                    case_id,
                    note_id,
                    revision,
                    ..
                } => {
                    id(case_id)
                        && id(note_id)
                        && revision.len() == 64
                        && revision
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                }
                Self::Report {
                    snapshot_handle, ..
                } => handle(snapshot_handle),
            };
        if valid {
            Ok(())
        } else {
            Err(CaseWorkspaceError::Invalid)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lovelyhawk_core::{investigation::EvidenceArtifact, target::TargetIdentity};

    #[test]
    fn snapshot_pages_search_full_provenance_keep_raw_text_and_never_expose_target() {
        let target = TargetIdentity::new("private-target-identity").unwrap();
        let case = IncidentCase {
            id: "case".into(),
            title: "case".into(),
            status: CaseStatus::Open,
            target: target.clone(),
            created_at: 1,
            updated_at: 2,
            iocs: vec![],
            timeline: vec![],
            evidence: (0..31)
                .map(|i| EvidenceArtifact {
                    id: format!("evidence-{i}"),
                    kind: EvidenceKind::Path,
                    label: format!("file-{i}"),
                    source: "real-sftp".into(),
                    locator: Some(format!("collection-{i}/sample.bin")),
                    preview: "<script>literal</script>".into(),
                    sha256: "a0".repeat(32),
                    hash_scope: EvidenceHashScope::ExternalArtifact,
                    collected_at: 1,
                    target: target.clone(),
                })
                .collect(),
        };
        let first = serde_json::to_value(page(
            &case,
            "snapshot".into(),
            CaseSection::Evidence,
            "".into(),
            0,
        ))
        .unwrap();
        assert_eq!(first["items"].as_array().unwrap().len(), 25);
        assert_eq!(first["total"], 31);
        assert_eq!(first["hasMore"], true);
        assert_eq!(first["items"][0]["text"], "<script>literal</script>");
        assert!(!first.to_string().contains("private-target-identity"));
        let second = serde_json::to_value(page(
            &case,
            "snapshot".into(),
            CaseSection::Evidence,
            "".into(),
            25,
        ))
        .unwrap();
        assert_eq!(second["items"].as_array().unwrap().len(), 6);
        assert_eq!(second["hasMore"], false);
        let search = serde_json::to_value(page(
            &case,
            "snapshot".into(),
            CaseSection::Evidence,
            "COLLECTION-30/".into(),
            0,
        ))
        .unwrap();
        assert_eq!(search["total"], 1);
        assert_eq!(search["items"][0]["id"], "evidence-30");
        assert_eq!(search["items"][0]["hashScope"], "external-artifact");
        let empty = serde_json::to_value(page(
            &case,
            "snapshot".into(),
            CaseSection::Evidence,
            "".into(),
            1000,
        ))
        .unwrap();
        assert_eq!(empty["items"].as_array().unwrap().len(), 0);
        assert_eq!(empty["hasMore"], false);
    }
}
