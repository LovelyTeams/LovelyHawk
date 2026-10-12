//! Local case library and immutable, verified archive versions. The portable
//! index changes only after a complete archive copy has been read back.
use super::*;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, Write},
    path::{Path, PathBuf},
};

pub const MAX_CASE_ARCHIVES: usize = 200;
pub const MAX_CASE_EXPORT_BYTES: usize = 32 * 1024 * 1024;
const ARCHIVE_DIRECTORY: &str = "case-archives";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaseLibraryLocation {
    Working,
    Archived,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseLibraryRecord {
    pub key: String,
    pub location: CaseLibraryLocation,
    pub case_id: String,
    pub target: TargetIdentity,
    pub title: String,
    pub status: CaseStatus,
    pub created_at: i64,
    pub updated_at: i64,
    pub evidence_count: usize,
    pub ioc_count: usize,
    pub timeline_count: usize,
    pub archived_at: Option<i64>,
    pub case_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CaseArchiveIndex {
    pub record: CaseLibraryRecord,
    archive_id: String,
    file_sha256: String,
}

#[derive(Debug, Clone)]
pub struct CaseLibrarySnapshot {
    pub record: CaseLibraryRecord,
    pub export: IncidentCaseExport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseArchivePlan {
    operation: OperationPlan,
    expected: CaseLibraryRecord,
    archive_id: String,
    archiving: bool,
    was_current: bool,
}
impl CaseArchivePlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }
    pub fn record(&self) -> &CaseLibraryRecord {
        &self.expected
    }
    pub fn is_archiving(&self) -> bool {
        self.archiving
    }
}

#[derive(Debug, Default)]
pub(super) struct CaseActivityRegistry(BTreeMap<String, usize>);
impl CaseActivityRegistry {
    pub(super) fn ensure_idle(&self, case_id: &str) -> CoreResult<()> {
        if self.0.get(case_id).copied().unwrap_or(0) != 0 {
            return Err(validation(
                "case activity",
                "file evidence is still collecting for this case",
            ));
        }
        Ok(())
    }
}
pub(super) fn activity_for(store: &PortableStore) -> Arc<Mutex<CaseActivityRegistry>> {
    static REGISTRY: OnceLock<Mutex<BTreeMap<PathBuf, Weak<Mutex<CaseActivityRegistry>>>>> =
        OnceLock::new();
    let root = fs::canonicalize(store.root()).unwrap_or_else(|_| store.root().to_owned());
    let mut registry = REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new())).lock();
    registry.retain(|_, item| item.strong_count() > 0);
    if let Some(existing) = registry.get(&root).and_then(Weak::upgrade) {
        return existing;
    }
    let activity = Arc::new(Mutex::new(CaseActivityRegistry::default()));
    registry.insert(root, Arc::downgrade(&activity));
    activity
}

/// Hold for the whole asynchronous file collection, including its final case
/// write. Archiving checks this under the same repository transaction lock.
#[derive(Debug)]
pub struct CaseCollectionReservation {
    registry: Arc<Mutex<CaseActivityRegistry>>,
    case_id: String,
}
impl Drop for CaseCollectionReservation {
    fn drop(&mut self) {
        let mut registry = self.registry.lock();
        if let Some(count) = registry.0.get_mut(&self.case_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                registry.0.remove(&self.case_id);
            }
        }
    }
}

impl IncidentCaseRepository {
    pub fn reserve_collection(
        &self,
        target: &TargetIdentity,
        case_id: &str,
    ) -> CoreResult<CaseCollectionReservation> {
        validate_target(target)?;
        validate_lookup_id(case_id)?;
        let _transaction = self.context.transaction.lock();
        let document = load_cases(&self.context.store)?;
        open_case(&document, target, case_id)?;
        let mut registry = self.context.case_activity.lock();
        if registry.0.values().sum::<usize>() >= 32 {
            return Err(validation("case activity", "too many case collections"));
        }
        *registry.0.entry(case_id.to_owned()).or_default() += 1;
        Ok(CaseCollectionReservation {
            registry: Arc::clone(&self.context.case_activity),
            case_id: case_id.to_owned(),
        })
    }

    pub fn library(&self) -> CoreResult<Vec<CaseLibraryRecord>> {
        let _transaction = self.context.transaction.lock();
        let document = load_cases(&self.context.store)?;
        let mut records = document
            .cases
            .iter()
            .map(working_record)
            .collect::<CoreResult<Vec<_>>>()?;
        records.extend(document.archives.into_iter().map(|entry| entry.record));
        records.sort_by(|left, right| {
            right
                .archived_at
                .unwrap_or(right.updated_at)
                .cmp(&left.archived_at.unwrap_or(left.updated_at))
                .then_with(|| left.key.cmp(&right.key))
        });
        Ok(records)
    }

    pub fn library_open(&self, key: &str) -> CoreResult<CaseLibrarySnapshot> {
        let _transaction = self.context.transaction.lock();
        let document = load_cases(&self.context.store)?;
        self.open_locked(&document, key)
    }

    fn open_locked(&self, document: &CasesDocument, key: &str) -> CoreResult<CaseLibrarySnapshot> {
        if let Some(case_id) = key.strip_prefix("working:") {
            validate_lookup_id(case_id)?;
            let case = document
                .cases
                .iter()
                .find(|item| item.id == case_id)
                .ok_or_else(|| not_found("local incident case", "[selected]"))?;
            Ok(CaseLibrarySnapshot {
                record: working_record(case)?,
                export: export_case(case.clone(), valid_now(self.context.clock.as_ref())?),
            })
        } else if let Some(archive_id) = key.strip_prefix("archive:") {
            validate_archive_id(archive_id)?;
            let index = document
                .archives
                .iter()
                .find(|item| item.archive_id == archive_id)
                .ok_or_else(|| not_found("local case archive", "[selected]"))?;
            let export = read_archive(&self.context.store, index)?;
            Ok(CaseLibrarySnapshot {
                record: index.record.clone(),
                export,
            })
        } else {
            Err(validation(
                "case library key",
                "unknown local case location",
            ))
        }
    }

    pub fn plan_archive(
        &self,
        key: &str,
        expected_case_sha256: &str,
        archiving: bool,
    ) -> CoreResult<CaseArchivePlan> {
        let _transaction = self.context.transaction.lock();
        let document = load_cases(&self.context.store)?;
        let snapshot = self.open_locked(&document, key)?;
        let record = snapshot.record;
        if record.case_sha256 != expected_case_sha256
            || archiving != (record.location == CaseLibraryLocation::Working)
        {
            return Err(validation(
                "case archive stale",
                "selected case changed; review the current version",
            ));
        }
        self.check_transfer(&document, &record, archiving)?;
        let was_current = document
            .active_case_by_target
            .get(record.target.as_str())
            .is_some_and(|id| id == &record.case_id);
        let summary = if archiving {
            format!(
                "归档案件“{}”：完整保留 {} 条证据、{} 条线索、{} 条时间线，核对归档副本后从活动列表移出。原始留证文件不移动；可从本机案件库恢复。{}",
                record.title,
                record.evidence_count,
                record.ioc_count,
                record.timeline_count,
                if was_current {
                    "此案是当前归档案件，移出后后续采集将另建案件。"
                } else {
                    "其他案件的采集归属不变。"
                }
            )
        } else {
            format!(
                "恢复归档案件“{}”：将此版本的 {} 条证据、{} 条线索、{} 条时间线放回活动列表。保留归档原件，不覆盖同编号活动案件，也不自动设为当前采集案件。",
                record.title, record.evidence_count, record.ioc_count, record.timeline_count
            )
        };
        let mut operation =
            OperationPlan::new(self.context.local_guard.clone(), summary, true, None)?;
        operation
            .metadata
            .insert("case-id".into(), record.case_id.clone());
        operation
            .metadata
            .insert("case-revision".into(), record.case_sha256.clone());
        let archive_id = if archiving {
            Uuid::new_v4().to_string()
        } else {
            key.strip_prefix("archive:").unwrap_or_default().to_owned()
        };
        Ok(CaseArchivePlan {
            operation,
            expected: record,
            archive_id,
            archiving,
            was_current,
        })
    }

    fn check_transfer(
        &self,
        document: &CasesDocument,
        record: &CaseLibraryRecord,
        archiving: bool,
    ) -> CoreResult<()> {
        if self
            .context
            .case_activity
            .lock()
            .0
            .get(&record.case_id)
            .copied()
            .unwrap_or(0)
            != 0
        {
            return Err(validation(
                "case activity",
                "file evidence is still collecting for this case",
            ));
        }
        if archiving && document.archives.len() >= MAX_CASE_ARCHIVES {
            return Err(validation(
                "case archive capacity",
                "200 archive versions already exist; nothing was removed",
            ));
        }
        if !archiving {
            if document.cases.len() >= MAX_CASES {
                return Err(validation(
                    "case capacity",
                    "working case list is full; archive another case first",
                ));
            }
            if document.cases.iter().any(|case| case.id == record.case_id) {
                return Err(validation(
                    "case archive conflict",
                    "a working case with this identity already exists",
                ));
            }
        }
        Ok(())
    }

    pub async fn execute_archive_plan(
        &self,
        plan: CaseArchivePlan,
        confirmation: DangerousConfirmation,
        journal: &dyn OperationJournal,
    ) -> CoreResult<InvestigationOperationOutcome> {
        let operation_id = plan.operation.id.clone();
        let executor = ArchiveExecutor {
            repository: self.clone(),
            plan: plan.clone(),
        };
        let verification = run_local_destructive_operation(
            self.context.as_ref(),
            plan.operation,
            confirmation,
            &executor,
            journal,
        )
        .await?;
        Ok(InvestigationOperationOutcome {
            operation_id,
            affected_records: 1,
            verification,
        })
    }

    fn transfer(&self, plan: &CaseArchivePlan) -> CoreResult<()> {
        let _transaction = self.context.transaction.lock();
        let mut document = load_cases(&self.context.store)?;
        let snapshot = self.open_locked(&document, &plan.expected.key)?;
        if snapshot.record != plan.expected {
            return Err(validation(
                "case archive stale",
                "case changed after the reviewed plan",
            ));
        }
        self.check_transfer(&document, &snapshot.record, plan.archiving)?;
        let current = document
            .active_case_by_target
            .get(snapshot.record.target.as_str())
            .is_some_and(|id| id == &snapshot.record.case_id);
        if plan.archiving && current != plan.was_current {
            return Err(validation(
                "case archive stale",
                "case selection changed after the reviewed plan",
            ));
        }
        if plan.archiving {
            let bytes = encode_export(&snapshot.export)?;
            let directory = archive_directory(&self.context.store, true)?;
            let path = directory.join(format!("{}.json", plan.archive_id));
            let file_sha256 = write_verified_new(&path, &bytes)?;
            let mut record = snapshot.record;
            record.key = format!("archive:{}", plan.archive_id);
            record.location = CaseLibraryLocation::Archived;
            record.archived_at = Some(snapshot.export.exported_at_millis);
            let index = CaseArchiveIndex {
                record,
                archive_id: plan.archive_id.clone(),
                file_sha256,
            };
            // Read by the final managed name and validate the manifest before the
            // index can stop referring to the original working case.
            read_archive(&self.context.store, &index)?;
            document
                .cases
                .retain(|case| case.id != plan.expected.case_id);
            if current {
                document
                    .active_case_by_target
                    .remove(plan.expected.target.as_str());
            }
            document.archives.insert(0, index);
        } else {
            // Keeping the immutable archive version makes restoration reversible
            // and preserves the original even if the reopened case is edited.
            document.cases.insert(0, snapshot.export.incident_case);
        }
        write_cases(&self.context.store, &document)
    }

    pub fn export_library_snapshot(
        &self,
        snapshot: &CaseLibrarySnapshot,
        selected: &Path,
    ) -> CoreResult<(String, u64, String)> {
        validate_export(&snapshot.export)?;
        if case_revision(&snapshot.export.incident_case)? != snapshot.record.case_sha256 {
            return Err(validation(
                "case archive integrity",
                "snapshot digest does not match case",
            ));
        }
        let paths = crate::path_guard::PathGuard::for_store(&self.context.store, [])?;
        let destination = paths.ensure_safe_download_target(selected)?;
        if destination.extension().and_then(|s| s.to_str()) != Some("json") {
            return Err(validation(
                "case export destination",
                "select a new JSON file",
            ));
        }
        let parent = destination
            .parent()
            .ok_or_else(|| validation("case export destination", "missing parent"))?;
        if !parent.is_dir() {
            return Err(validation(
                "case export destination",
                "select an existing directory",
            ));
        }
        let name = destination
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| validation("case export name", "invalid filename"))?
            .to_owned();
        if name.chars().count() > 1024
            || name.chars().any(char::is_control)
            || name.contains(['/', '\\', ':'])
        {
            return Err(validation(
                "case export name",
                "select a plain JSON filename",
            ));
        }
        let bytes = encode_export(&snapshot.export)?;
        let digest = write_verified_new(&destination, &bytes)?;
        Ok((name, bytes.len() as u64, digest))
    }
}

#[derive(Debug)]
struct ArchiveExecutor {
    repository: IncidentCaseRepository,
    plan: CaseArchivePlan,
}
#[async_trait]
impl OperationExecutor for ArchiveExecutor {
    async fn execute(&self, _: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        self.repository.transfer(&self.plan)?;
        Ok(ExecutionReceipt {
            summary: if self.plan.archiving {
                "archived one verified local case version"
            } else {
                "restored one local case without changing collection selection"
            }
            .into(),
            restore_token: None,
        })
    }
    async fn verify(
        &self,
        _: &OperationPlan,
        _: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        let key = if self.plan.archiving {
            format!("archive:{}", self.plan.archive_id)
        } else {
            format!("working:{}", self.plan.expected.case_id)
        };
        let snapshot = self.repository.library_open(&key)?;
        let digest_matches = snapshot.record.case_sha256 == self.plan.expected.case_sha256;
        let presence_matches = !self.plan.archiving
            || !self.repository.library()?.iter().any(|item| {
                item.location == CaseLibraryLocation::Working
                    && item.case_id == self.plan.expected.case_id
            });
        Ok(VerificationResult {
            passed: digest_matches && presence_matches,
            detail: "核对案件内容摘要和本机索引位置；原始留证文件未被移动或删除。".into(),
        })
    }
    async fn restore(&self, _: &OperationPlan, _: &ExecutionReceipt) -> CoreResult<()> {
        Err(CoreError::Unsupported {
            feature: "automatic case archive reversal; use a newly reviewed library plan",
        })
    }
}

pub(super) fn working_record(case: &IncidentCase) -> CoreResult<CaseLibraryRecord> {
    Ok(CaseLibraryRecord {
        key: format!("working:{}", case.id),
        location: CaseLibraryLocation::Working,
        case_id: case.id.clone(),
        target: case.target.clone(),
        title: case.title.clone(),
        status: case.status,
        created_at: case.created_at,
        updated_at: case.updated_at,
        evidence_count: case.evidence.len(),
        ioc_count: case.iocs.len(),
        timeline_count: case.timeline.len(),
        archived_at: None,
        case_sha256: case_revision(case)?,
    })
}
pub(super) fn case_revision(case: &IncidentCase) -> CoreResult<String> {
    let bytes = serde_json::to_vec(case).map_err(|source| CoreError::Encode {
        subject: "case revision",
        source,
    })?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
fn export_case(case: IncidentCase, exported_at_millis: i64) -> IncidentCaseExport {
    IncidentCaseExport {
        schema: INCIDENT_CASE_SCHEMA_ID.to_owned(),
        exported_at_millis,
        manifest: CaseExportManifest {
            case_id: case.id.clone(),
            target: case.target.clone(),
            evidence_count: case.evidence.len(),
            ioc_count: case.iocs.len(),
            evidence_hashes: case
                .evidence
                .iter()
                .map(|item| EvidenceHashManifest {
                    id: item.id.clone(),
                    sha256: item.sha256.clone(),
                    hash_scope: item.hash_scope,
                })
                .collect(),
        },
        incident_case: case,
    }
}
fn validate_export(export: &IncidentCaseExport) -> CoreResult<()> {
    validate_timestamp(export.exported_at_millis)?;
    validate_cases(&CasesDocument {
        cases: vec![export.incident_case.clone()],
        ..CasesDocument::default()
    })?;
    if *export != export_case(export.incident_case.clone(), export.exported_at_millis) {
        return Err(validation(
            "case archive integrity",
            "case export manifest does not match its contents",
        ));
    }
    Ok(())
}
fn encode_export(export: &IncidentCaseExport) -> CoreResult<Vec<u8>> {
    validate_export(export)?;
    let bytes = serde_json::to_vec_pretty(export).map_err(|source| CoreError::Encode {
        subject: "case export",
        source,
    })?;
    if bytes.len() > MAX_CASE_EXPORT_BYTES {
        return Err(validation(
            "case archive size",
            "case export exceeds 32 MiB; original records are preserved",
        ));
    }
    Ok(bytes)
}
fn archive_directory(store: &PortableStore, create: bool) -> CoreResult<PathBuf> {
    let root = fs::canonicalize(store.root())
        .map_err(|e| CoreError::io("resolve case data root", store.root(), e))?;
    let directory = root.join(ARCHIVE_DIRECTORY);
    if create && !directory.exists() {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(&directory)
            .map_err(|e| CoreError::io("create case archive directory", &directory, e))?;
    }
    require_directory(&directory)?;
    Ok(directory)
}
fn require_directory(directory: &Path) -> CoreResult<()> {
    let metadata = fs::symlink_metadata(directory)
        .map_err(|e| CoreError::io("inspect case archive directory", directory, e))?;
    if !metadata.is_dir()
        || metadata.is_symlink()
        || fs::canonicalize(directory)
            .map_err(|e| CoreError::io("resolve case archive directory", directory, e))?
            != directory
    {
        return Err(validation(
            "case archive path",
            "archive directory was redirected",
        ));
    }
    Ok(())
}
fn write_verified_new(path: &Path, bytes: &[u8]) -> CoreResult<String> {
    let parent = path
        .parent()
        .ok_or_else(|| validation("case archive path", "missing parent"))?;
    require_directory(parent)?;
    let mut options = OpenOptions::new();
    options.create_new(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| CoreError::io("create case archive", path, e))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .and_then(|()| file.rewind())
        .map_err(|e| CoreError::io("write case archive", path, e))?;
    let mut actual = Vec::new();
    file.take(MAX_CASE_EXPORT_BYTES as u64 + 1)
        .read_to_end(&mut actual)
        .map_err(|e| CoreError::io("verify case archive", path, e))?;
    if actual != bytes {
        return Err(validation(
            "case archive integrity",
            "saved archive bytes did not match",
        ));
    }
    require_directory(parent)?;
    if fs::symlink_metadata(path)
        .map_err(|e| CoreError::io("inspect case archive", path, e))?
        .is_symlink()
        || fs::canonicalize(path).map_err(|e| CoreError::io("resolve case archive", path, e))?
            != path
    {
        return Err(validation(
            "case archive path",
            "saved archive path was redirected",
        ));
    }
    let mut named_bytes = Vec::new();
    File::open(path)
        .map_err(|e| CoreError::io("reopen case archive", path, e))?
        .take(MAX_CASE_EXPORT_BYTES as u64 + 1)
        .read_to_end(&mut named_bytes)
        .map_err(|e| CoreError::io("verify named case archive", path, e))?;
    if named_bytes != bytes {
        return Err(validation(
            "case archive integrity",
            "saved archive name no longer refers to the verified bytes",
        ));
    }
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
fn read_archive(store: &PortableStore, index: &CaseArchiveIndex) -> CoreResult<IncidentCaseExport> {
    let directory = archive_directory(store, false)?;
    let path = directory.join(format!("{}.json", index.archive_id));
    let metadata =
        fs::symlink_metadata(&path).map_err(|e| CoreError::io("inspect case archive", &path, e))?;
    if !metadata.is_file() || metadata.is_symlink() || metadata.len() > MAX_CASE_EXPORT_BYTES as u64
    {
        return Err(validation(
            "case archive integrity",
            "archive is not a bounded regular file",
        ));
    }
    let file = File::open(&path).map_err(|e| CoreError::io("open case archive", &path, e))?;
    let mut bytes = Vec::new();
    file.take(MAX_CASE_EXPORT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| CoreError::io("read case archive", &path, e))?;
    if bytes.len() > MAX_CASE_EXPORT_BYTES
        || format!("{:x}", Sha256::digest(&bytes)) != index.file_sha256
    {
        return Err(validation(
            "case archive integrity",
            "archive content digest changed",
        ));
    }
    require_directory(&directory)?;
    if fs::canonicalize(&path).map_err(|e| CoreError::io("resolve case archive", &path, e))? != path
    {
        return Err(validation(
            "case archive path",
            "archive file was redirected",
        ));
    }
    let export: IncidentCaseExport =
        serde_json::from_slice(&bytes).map_err(|source| CoreError::Decode {
            subject: "case archive",
            source,
        })?;
    validate_export(&export)?;
    let mut expected = working_record(&export.incident_case)?;
    expected.key = index.record.key.clone();
    expected.location = CaseLibraryLocation::Archived;
    expected.archived_at = Some(export.exported_at_millis);
    if expected != index.record {
        return Err(validation(
            "case archive integrity",
            "archive index does not match its document",
        ));
    }
    Ok(export)
}
fn validate_archive_id(value: &str) -> CoreResult<()> {
    if Uuid::parse_str(value)
        .ok()
        .is_none_or(|id| id.to_string() != value)
    {
        return Err(validation("case archive id", "invalid archive identity"));
    }
    Ok(())
}
pub(super) fn validate_index(document: &CasesDocument) -> CoreResult<()> {
    if document.archives.len() > MAX_CASE_ARCHIVES {
        return Err(validation(
            "case archive capacity",
            "too many archived case versions",
        ));
    }
    let mut seen = BTreeSet::new();
    for index in &document.archives {
        validate_archive_id(&index.archive_id)?;
        let record = &index.record;
        validate_lookup_id(&record.case_id)?;
        validate_target(&record.target)?;
        required_trimmed_ref("case archive title", &record.title, 160)?;
        validate_timestamp(record.created_at)?;
        validate_timestamp(record.updated_at)?;
        normalize_sha256(&record.case_sha256)?;
        normalize_sha256(&index.file_sha256)?;
        if !seen.insert(index.archive_id.as_str())
            || record.location != CaseLibraryLocation::Archived
            || record.key != format!("archive:{}", index.archive_id)
            || record.archived_at.is_none_or(|value| value < 0)
            || record.evidence_count > MAX_EVIDENCE
            || record.ioc_count > MAX_IOCS
            || record.timeline_count > MAX_TIMELINE
        {
            return Err(validation(
                "case archive index",
                "invalid archived case summary",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operations::PortableOperationJournal;

    struct Root(PathBuf);
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn fixture() -> (
        Root,
        PortableStore,
        InvestigationRepositories,
        TargetIdentity,
    ) {
        let root =
            Root(std::env::temp_dir().join(format!("lovelyres-case-archive-{}", Uuid::new_v4())));
        let store = PortableStore::prepare(root.0.clone()).unwrap();
        let repositories = InvestigationRepositories::new(store.clone());
        (
            root,
            store,
            repositories,
            TargetIdentity::new("test-host").unwrap(),
        )
    }
    fn record(case: &IncidentCase) -> AddEvidence {
        AddEvidence {
            kind: EvidenceKind::Note,
            label: "留存记录".into(),
            source: "test".into(),
            preview: format!("{} <script>literal evidence</script>", case.id),
            locator: None,
            external_sha256: None,
        }
    }
    async fn archive(
        repositories: &InvestigationRepositories,
        store: &PortableStore,
        key: &str,
    ) -> CaseLibraryRecord {
        let before = repositories.cases().library_open(key).unwrap();
        let plan = repositories
            .cases()
            .plan_archive(key, &before.record.case_sha256, true)
            .unwrap();
        let confirmed = DangerousConfirmation::approve(plan.definition());
        assert!(
            repositories
                .cases()
                .execute_archive_plan(
                    plan,
                    confirmed,
                    &PortableOperationJournal::new(store.clone())
                )
                .await
                .unwrap()
                .verification
                .passed
        );
        repositories
            .cases()
            .library()
            .unwrap()
            .into_iter()
            .find(|item| {
                item.location == CaseLibraryLocation::Archived
                    && item.case_id == before.record.case_id
            })
            .unwrap()
    }

    #[tokio::test]
    async fn archive_frees_a_working_slot_preserving_evidence_and_creation_receipt() {
        let (_root, store, repos, target) = fixture();
        let first = repos
            .cases()
            .create_idempotent(&target, "第一个案件".into(), "archive-create-retry-001")
            .unwrap();
        repos
            .cases()
            .add_evidence_to_case(&target, &first.id, record(&first))
            .unwrap();
        for i in 1..MAX_CASES {
            repos
                .cases()
                .create(&target, Some(format!("case-{i}")))
                .unwrap();
        }
        let original = repos
            .cases()
            .export(&target, &first.id)
            .unwrap()
            .incident_case;
        let current = repos.cases().active(&target).unwrap().unwrap().id;
        let archived = archive(&repos, &store, &format!("working:{}", first.id)).await;
        assert_eq!(
            repos.cases().overview(&target).unwrap().total_cases,
            MAX_CASES - 1
        );
        assert_eq!(repos.cases().active(&target).unwrap().unwrap().id, current);
        let reloaded = InvestigationRepositories::new(store.clone());
        assert_eq!(
            reloaded
                .cases()
                .library_open(&archived.key)
                .unwrap()
                .export
                .incident_case,
            original
        );
        assert!(
            reloaded
                .cases()
                .create_idempotent(&target, "第一个案件".into(), "archive-create-retry-001")
                .is_err()
        );
        repos
            .cases()
            .create(&target, Some("新调查".into()))
            .unwrap();
        assert_eq!(
            repos.cases().overview(&target).unwrap().total_cases,
            MAX_CASES
        );
    }

    #[tokio::test]
    async fn restore_keeps_original_archive_and_does_not_select_or_overwrite_working_case() {
        let (_root, store, repos, target) = fixture();
        let case = repos.cases().create(&target, Some("调查".into())).unwrap();
        repos
            .cases()
            .add_evidence_to_case(&target, &case.id, record(&case))
            .unwrap();
        let archived = archive(&repos, &store, &format!("working:{}", case.id)).await;
        assert!(repos.cases().active(&target).unwrap().is_none());
        let other = repos
            .cases()
            .create(&target, Some("继续调查".into()))
            .unwrap();
        let original = repos.cases().library_open(&archived.key).unwrap();
        let plan = repos
            .cases()
            .plan_archive(&archived.key, &archived.case_sha256, false)
            .unwrap();
        let confirmed = DangerousConfirmation::approve(plan.definition());
        repos
            .cases()
            .execute_archive_plan(
                plan,
                confirmed,
                &PortableOperationJournal::new(store.clone()),
            )
            .await
            .unwrap();
        assert_eq!(repos.cases().active(&target).unwrap().unwrap().id, other.id);
        assert_eq!(
            repos
                .cases()
                .export(&target, &case.id)
                .unwrap()
                .incident_case,
            original.export.incident_case
        );
        assert_eq!(
            repos.cases().library_open(&archived.key).unwrap().export,
            original.export
        );
        assert!(
            repos
                .cases()
                .plan_archive(&archived.key, &archived.case_sha256, false)
                .is_err()
        );
    }

    #[tokio::test]
    async fn collection_reservation_and_changed_evidence_block_archive_before_any_removal() {
        let (_root, store, repos, target) = fixture();
        let case = repos.cases().create(&target, None).unwrap();
        let key = format!("working:{}", case.id);
        let initial = repos.cases().library_open(&key).unwrap();
        let plan = repos
            .cases()
            .plan_archive(&key, &initial.record.case_sha256, true)
            .unwrap();
        let another_repository = InvestigationRepositories::new(store.clone());
        let reservation = another_repository
            .cases()
            .reserve_collection(&target, &case.id)
            .unwrap();
        let approval = DangerousConfirmation::approve(plan.definition());
        assert!(
            repos
                .cases()
                .execute_archive_plan(
                    plan,
                    approval,
                    &PortableOperationJournal::new(store.clone())
                )
                .await
                .is_err()
        );
        assert!(!store.root().join(ARCHIVE_DIRECTORY).exists());
        drop(reservation);
        let plan = repos
            .cases()
            .plan_archive(&key, &initial.record.case_sha256, true)
            .unwrap();
        repos
            .cases()
            .add_evidence_to_case(&target, &case.id, record(&case))
            .unwrap();
        let approval = DangerousConfirmation::approve(plan.definition());
        assert!(
            repos
                .cases()
                .execute_archive_plan(
                    plan,
                    approval,
                    &PortableOperationJournal::new(store.clone())
                )
                .await
                .is_err()
        );
        assert_eq!(
            repos
                .cases()
                .library_open(&key)
                .unwrap()
                .export
                .incident_case
                .evidence
                .len(),
            1
        );
        assert!(!store.root().join(ARCHIVE_DIRECTORY).exists());
    }

    #[tokio::test]
    async fn archive_requires_exact_confirmation_and_rejects_tampered_copy_on_restore() {
        let (_root, store, repos, target) = fixture();
        let case = repos.cases().create(&target, None).unwrap();
        let key = format!("working:{}", case.id);
        let initial = repos.cases().library_open(&key).unwrap();
        let plan = repos
            .cases()
            .plan_archive(&key, &initial.record.case_sha256, true)
            .unwrap();
        let other = repos
            .cases()
            .plan_archive(&key, &initial.record.case_sha256, true)
            .unwrap();
        let journal = PortableOperationJournal::new(store.clone());
        assert!(
            repos
                .cases()
                .execute_archive_plan(
                    plan,
                    DangerousConfirmation::approve(other.definition()),
                    &journal
                )
                .await
                .is_err()
        );
        assert!(journal.entries().unwrap().is_empty());
        let archived = archive(&repos, &store, &key).await;
        let index = load_cases(&store).unwrap().archives.remove(0);
        let path = archive_directory(&store, false)
            .unwrap()
            .join(format!("{}.json", index.archive_id));
        OpenOptions::new()
            .append(true)
            .open(path)
            .unwrap()
            .write_all(b" ")
            .unwrap();
        assert!(repos.cases().library_open(&archived.key).is_err());
        assert!(
            repos
                .cases()
                .plan_archive(&archived.key, &archived.case_sha256, false)
                .is_err()
        );
        assert!(repos.cases().list_for_target(&target).unwrap().is_empty());
        assert_eq!(repos.cases().library().unwrap().len(), 1);
    }

    #[test]
    fn native_export_preserves_exact_snapshot_and_refuses_overwrite_or_forged_manifest() {
        let (root, _store, repos, target) = fixture();
        let case = repos.cases().create(&target, None).unwrap();
        repos
            .cases()
            .add_evidence_to_case(&target, &case.id, record(&case))
            .unwrap();
        let snapshot = repos
            .cases()
            .library_open(&format!("working:{}", case.id))
            .unwrap();
        let path = root.0.join("export.json");
        let (_, count, digest) = repos
            .cases()
            .export_library_snapshot(&snapshot, &path)
            .unwrap();
        let bytes = fs::read(&path).unwrap();
        assert_eq!(count, bytes.len() as u64);
        assert_eq!(digest, format!("{:x}", Sha256::digest(&bytes)));
        assert_eq!(
            serde_json::from_slice::<IncidentCaseExport>(&bytes).unwrap(),
            snapshot.export
        );
        assert!(
            repos
                .cases()
                .export_library_snapshot(&snapshot, &path)
                .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), bytes);
        let mut forged = snapshot;
        forged.export.manifest.evidence_count = 0;
        assert!(
            repos
                .cases()
                .export_library_snapshot(&forged, &root.0.join("forged.json"))
                .is_err()
        );
        assert!(!root.0.join("forged.json").exists());
    }
}
