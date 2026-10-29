//! Target-bound file-integrity baselines and reversible quarantine operations.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    CoreError, CoreResult, PortableStore,
    operations::{
        DangerousConfirmation, ExecutionReceipt, OperationExecutor, OperationPlan, OperationState,
        PlannedOperation, PortableOperationJournal, VerificationResult,
    },
    shell_escape::shq,
    ssh::{BoundSshSession, SshCommandOutput, SshService},
    store::StoreFile,
    target::{TargetContext, TargetGuard, TargetIdentity},
};

const REMOTE_ROOT: &str = "/tmp/.lovelyres_fim";
const MAXIMUM_PATHS: usize = 16;
const MAXIMUM_PATH_BYTES: usize = 4_096;
const MAXIMUM_DIFF_ENTRIES: usize = 5_000;
const MAXIMUM_DIFF_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const BASELINE_TIMEOUT: Duration = Duration::from_secs(600);
const MUTATION_TIMEOUT: Duration = Duration::from_secs(60);

pub const INTEGRITY_PRESETS: [(&str, &str, bool); 6] = [
    ("/var/www（Web 根目录）", "/var/www", true),
    ("/usr/bin", "/usr/bin", true),
    ("/usr/sbin", "/usr/sbin", true),
    ("/bin", "/bin", true),
    ("/etc", "/etc", false),
    ("/usr/local/bin", "/usr/local/bin", false),
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IntegrityBaseline {
    pub id: String,
    pub target: TargetIdentity,
    pub created_at: DateTime<Utc>,
    pub paths: Vec<String>,
    pub remote_manifest: String,
    pub file_count: usize,
    pub manifest_sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IntegrityDiffKind {
    Added,
    Removed,
    Modified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IntegritySeverity {
    High,
    Medium,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IntegrityDiffEntry {
    pub path: String,
    pub kind: IntegrityDiffKind,
    pub severity: IntegritySeverity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntegrityDiff {
    pub baseline_id: String,
    pub entries: Vec<IntegrityDiffEntry>,
    pub added: usize,
    pub removed: usize,
    pub modified: usize,
    pub truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntegrityQuarantinePlan {
    operation: OperationPlan,
    baseline_id: String,
    original_path: String,
    quarantine_path: String,
    execute_command: String,
    verify_command: String,
    restore_command: String,
}

impl IntegrityQuarantinePlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn original_path(&self) -> &str {
        &self.original_path
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntegrityQuarantineOutcome {
    pub operation_id: String,
    pub verified: bool,
    pub verification_detail: String,
    pub restored_after_failed_verification: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct IntegrityDocument {
    baselines: Vec<IntegrityBaseline>,
}

#[derive(Clone, Debug)]
struct IntegrityRepository {
    store: PortableStore,
    transaction: Arc<Mutex<()>>,
}

impl IntegrityRepository {
    fn new(store: PortableStore) -> Self {
        Self {
            store,
            transaction: Arc::new(Mutex::new(())),
        }
    }

    fn list(&self, target: &TargetIdentity) -> CoreResult<Vec<IntegrityBaseline>> {
        let _guard = self.transaction.lock();
        let mut baselines = self
            .store
            .read_or_default::<IntegrityDocument>(StoreFile::Integrity)?
            .baselines
            .into_iter()
            .filter(|baseline| &baseline.target == target)
            .collect::<Vec<_>>();
        baselines.sort_by_key(|left| std::cmp::Reverse(left.created_at));
        Ok(baselines)
    }

    fn find(&self, target: &TargetIdentity, id: &str) -> CoreResult<IntegrityBaseline> {
        validate_runtime_id("integrity baseline id", id)?;
        self.list(target)?
            .into_iter()
            .find(|baseline| baseline.id == id)
            .ok_or_else(|| CoreError::NotFound {
                entity: "integrity baseline",
                id: id.to_owned(),
            })
    }

    fn insert(&self, baseline: IntegrityBaseline) -> CoreResult<()> {
        let _guard = self.transaction.lock();
        let mut document = self
            .store
            .read_or_default::<IntegrityDocument>(StoreFile::Integrity)?;
        if document.baselines.iter().any(|item| item.id == baseline.id) {
            return Err(CoreError::validation(
                "integrity baseline",
                "baseline id already exists",
            ));
        }
        document.baselines.push(baseline);
        self.store.write(StoreFile::Integrity, &document)
    }
}

#[derive(Clone, Debug)]
pub struct IntegrityService {
    ssh: SshService,
    target: Arc<TargetContext>,
    repository: IntegrityRepository,
}

impl IntegrityService {
    pub fn new(ssh: SshService, target: Arc<TargetContext>, store: PortableStore) -> Self {
        Self {
            ssh,
            target,
            repository: IntegrityRepository::new(store),
        }
    }

    pub fn list(&self, target: &TargetGuard) -> CoreResult<Vec<IntegrityBaseline>> {
        self.target.validate(target)?;
        self.repository.list(&target.identity)
    }

    pub async fn create_baseline(
        &self,
        session: &BoundSshSession,
        paths: Vec<String>,
    ) -> CoreResult<IntegrityBaseline> {
        let paths = normalize_paths(paths)?;
        self.target.validate(session.target())?;
        let id = Uuid::new_v4().to_string();
        let remote_manifest = format!("{REMOTE_ROOT}/baseline-{id}.manifest");
        let temporary = format!("{REMOTE_ROOT}/.baseline-{id}.tmp");
        let command = build_create_command(&paths, &temporary, &remote_manifest);
        let output = self
            .ssh
            .execute_bound(session, command, BASELINE_TIMEOUT)
            .await?;
        let parsed = parse_create_output(successful_output("create integrity baseline", output)?)?;

        if let Err(error) = self.target.validate(session.target()) {
            self.cleanup_owned_remote(session, &remote_manifest).await;
            return Err(error);
        }

        let baseline = IntegrityBaseline {
            id,
            target: session.target().identity.clone(),
            created_at: Utc::now(),
            paths,
            remote_manifest,
            file_count: parsed.0,
            manifest_sha256: parsed.1,
        };
        if let Err(error) = self.repository.insert(baseline.clone()) {
            self.cleanup_owned_remote(session, &baseline.remote_manifest)
                .await;
            return Err(error);
        }
        Ok(baseline)
    }

    pub async fn compare(
        &self,
        session: &BoundSshSession,
        baseline_id: &str,
    ) -> CoreResult<IntegrityDiff> {
        self.target.validate(session.target())?;
        let baseline = self
            .repository
            .find(&session.target().identity, baseline_id)?;
        validate_owned_manifest(&baseline.remote_manifest, &baseline.id)?;
        validate_sha256(&baseline.manifest_sha256)?;
        let temporary = format!("{REMOTE_ROOT}/.compare-{}.tmp", Uuid::new_v4());
        let command = build_compare_command(&baseline, &temporary);
        let output = self
            .ssh
            .execute_bound(session, command, BASELINE_TIMEOUT)
            .await?;
        let output = successful_output("compare integrity baseline", output)?;
        if output.len() > MAXIMUM_DIFF_OUTPUT_BYTES {
            return Err(CoreError::validation(
                "integrity diff",
                format!("output exceeds {MAXIMUM_DIFF_OUTPUT_BYTES} bytes"),
            ));
        }
        let diff = parse_diff_output(&baseline.id, &output)?;
        self.target.validate(session.target())?;
        Ok(diff)
    }

    pub async fn plan_quarantine(
        &self,
        session: &BoundSshSession,
        baseline_id: &str,
        path: &str,
    ) -> CoreResult<IntegrityQuarantinePlan> {
        let path = validate_remote_file_path(path)?.to_owned();
        let diff = self.compare(session, baseline_id).await?;
        if !diff.entries.iter().any(|entry| {
            entry.path == path
                && matches!(
                    entry.kind,
                    IntegrityDiffKind::Added | IntegrityDiffKind::Modified
                )
        }) {
            return Err(CoreError::validation(
                "integrity quarantine",
                "path is not an added or modified file in the current comparison",
            ));
        }
        let quarantine_path = format!("{REMOTE_ROOT}/quarantine/{}", Uuid::new_v4());
        let execute_command = format!(
            "umask 077; mkdir -p {root} && [ -f {path} ] && [ ! -L {path} ] && [ ! -e {quarantine} ] && mv -- {path} {quarantine}",
            root = shq(&format!("{REMOTE_ROOT}/quarantine")),
            path = shq(&path),
            quarantine = shq(&quarantine_path),
        );
        let verify_command = format!(
            "[ ! -e {path} ] && [ -f {quarantine} ] && [ ! -L {quarantine} ] && printf 'QUARANTINE_OK\\n'",
            path = shq(&path),
            quarantine = shq(&quarantine_path),
        );
        let restore_command = format!(
            "[ ! -e {path} ] && [ -f {quarantine} ] && mv -- {quarantine} {path} && [ -f {path} ] && printf 'RESTORE_OK\\n'",
            path = shq(&path),
            quarantine = shq(&quarantine_path),
        );
        let mut operation = OperationPlan::new(
            session.target().clone(),
            format!("隔离可疑文件 {path}"),
            true,
            Some(format!("将隔离副本恢复到 {path}")),
        )?;
        operation
            .metadata
            .insert("baseline_id".to_owned(), baseline_id.to_owned());
        operation.metadata.insert("path".to_owned(), path.clone());
        operation
            .metadata
            .insert("quarantine_path".to_owned(), quarantine_path.clone());
        Ok(IntegrityQuarantinePlan {
            operation,
            baseline_id: baseline_id.to_owned(),
            original_path: path,
            quarantine_path,
            execute_command,
            verify_command,
            restore_command,
        })
    }

    pub async fn execute_quarantine(
        &self,
        session: &BoundSshSession,
        plan: IntegrityQuarantinePlan,
        confirmation: DangerousConfirmation,
        journal: &PortableOperationJournal,
    ) -> CoreResult<IntegrityQuarantineOutcome> {
        self.target.validate(session.target())?;
        if plan.operation.target != *session.target() {
            return Err(CoreError::validation(
                "integrity quarantine target",
                "plan is not bound to this SSH target epoch",
            ));
        }
        let mut operation = PlannedOperation::plan(plan.operation.clone());
        operation.confirm(confirmation)?;
        let executor = IntegrityQuarantineExecutor {
            service: self,
            session,
            plan: &plan,
        };
        if let Err(error) = operation.execute(&self.target, &executor).await {
            if operation.state() == OperationState::StaleAfterExecution {
                operation.journal(journal)?;
            }
            return Err(error);
        }
        operation.journal(journal)?;
        let verification = match operation.verify(&self.target, &executor, journal).await {
            Ok(verification) => verification,
            Err(error) => {
                if operation.state() == OperationState::VerificationFailed
                    && let Err(restore_error) =
                        operation.restore(&self.target, &executor, journal).await
                {
                    return Err(CoreError::validation(
                        "integrity quarantine recovery",
                        format!(
                            "verification failed ({error}); automatic restore also failed ({restore_error})"
                        ),
                    ));
                }
                return Err(error);
            }
        };
        let mut restored = false;
        if !verification.passed {
            operation.restore(&self.target, &executor, journal).await?;
            restored = true;
        }
        Ok(IntegrityQuarantineOutcome {
            operation_id: plan.operation.id,
            verified: verification.passed,
            verification_detail: verification.detail,
            restored_after_failed_verification: restored,
        })
    }

    async fn execute_operation_command(
        &self,
        session: &BoundSshSession,
        command: String,
        subject: &'static str,
    ) -> CoreResult<String> {
        let output = self
            .ssh
            .execute_bound(session, command, MUTATION_TIMEOUT)
            .await?;
        successful_output(subject, output)
    }

    async fn cleanup_owned_remote(&self, session: &BoundSshSession, path: &str) {
        if !path.starts_with(&format!("{REMOTE_ROOT}/baseline-")) {
            return;
        }
        let _ = self
            .ssh
            .execute_bound(
                session,
                format!("rm -f -- {}", shq(path)),
                Duration::from_secs(15),
            )
            .await;
    }
}

#[derive(Debug)]
struct IntegrityQuarantineExecutor<'a> {
    service: &'a IntegrityService,
    session: &'a BoundSshSession,
    plan: &'a IntegrityQuarantinePlan,
}

impl IntegrityQuarantineExecutor<'_> {
    fn ensure_plan(&self, definition: &OperationPlan) -> CoreResult<()> {
        if definition.id != self.plan.operation.id
            || definition.target != self.plan.operation.target
            || definition.metadata.get("baseline_id") != Some(&self.plan.baseline_id)
            || definition.metadata.get("path") != Some(&self.plan.original_path)
            || definition.metadata.get("quarantine_path") != Some(&self.plan.quarantine_path)
        {
            return Err(CoreError::validation(
                "integrity quarantine plan",
                "executor is bound to a different immutable plan",
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl OperationExecutor for IntegrityQuarantineExecutor<'_> {
    async fn execute(&self, definition: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        self.ensure_plan(definition)?;
        let output = self
            .service
            .execute_operation_command(
                self.session,
                self.plan.execute_command.clone(),
                "quarantine integrity finding",
            )
            .await?;
        Ok(ExecutionReceipt {
            summary: if output.trim().is_empty() {
                format!("moved {} into managed quarantine", self.plan.original_path)
            } else {
                output.chars().take(512).collect()
            },
            restore_token: None,
        })
    }

    async fn verify(
        &self,
        definition: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        self.ensure_plan(definition)?;
        let output = self
            .service
            .execute_operation_command(
                self.session,
                self.plan.verify_command.clone(),
                "verify quarantined file",
            )
            .await?;
        Ok(VerificationResult {
            passed: output.lines().any(|line| line == "QUARANTINE_OK"),
            detail: output.chars().take(512).collect(),
        })
    }

    async fn restore(
        &self,
        definition: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<()> {
        self.ensure_plan(definition)?;
        let output = self
            .service
            .execute_operation_command(
                self.session,
                self.plan.restore_command.clone(),
                "restore quarantined file",
            )
            .await?;
        if !output.lines().any(|line| line == "RESTORE_OK") {
            return Err(CoreError::validation(
                "integrity restore verification",
                "restore marker was not observed",
            ));
        }
        Ok(())
    }
}

fn normalize_paths(paths: Vec<String>) -> CoreResult<Vec<String>> {
    if paths.is_empty() || paths.len() > MAXIMUM_PATHS {
        return Err(CoreError::validation(
            "integrity paths",
            format!("select between 1 and {MAXIMUM_PATHS} paths"),
        ));
    }
    let mut normalized = BTreeSet::new();
    for path in paths {
        let path = validate_remote_path_root(path.trim())?;
        normalized.insert(path.to_owned());
    }
    Ok(normalized.into_iter().collect())
}

fn validate_remote_path_root(path: &str) -> CoreResult<&str> {
    if path.len() < 2
        || path.len() > MAXIMUM_PATH_BYTES
        || !path.starts_with('/')
        || path.chars().any(char::is_control)
        || path.split('/').any(|component| component == "..")
        || path == REMOTE_ROOT
        || path.starts_with(&format!("{REMOTE_ROOT}/"))
    {
        return Err(CoreError::validation(
            "integrity path",
            "must be an absolute control-free path outside the LovelyHawk managed namespace",
        ));
    }
    if path == "/" {
        Ok(path)
    } else {
        Ok(path.trim_end_matches('/'))
    }
}

fn validate_remote_file_path(path: &str) -> CoreResult<&str> {
    validate_remote_path_root(path)
}

fn validate_runtime_id(subject: &'static str, value: &str) -> CoreResult<()> {
    if Uuid::parse_str(value).is_err() {
        return Err(CoreError::validation(subject, "must be a UUID"));
    }
    Ok(())
}

fn validate_sha256(value: &str) -> CoreResult<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CoreError::validation(
            "integrity manifest digest",
            "must be a 64-character SHA-256 digest",
        ));
    }
    Ok(())
}

fn validate_owned_manifest(path: &str, id: &str) -> CoreResult<()> {
    validate_runtime_id("integrity baseline id", id)?;
    let expected = format!("{REMOTE_ROOT}/baseline-{id}.manifest");
    if path != expected {
        return Err(CoreError::validation(
            "integrity manifest path",
            "stored path is outside the managed baseline namespace",
        ));
    }
    Ok(())
}

fn scan_pipeline(paths: &[String]) -> String {
    let path_arguments = paths
        .iter()
        .map(|path| shq(path))
        .collect::<Vec<_>>()
        .join(" ");
    let worker = r#"for lr_file do
lr_hash=$(sha256sum -- "$lr_file" 2>/dev/null | awk '{print $1}') || continue
lr_path=$(printf %s "$lr_file" | base64 | tr -d '\n')
case "$lr_hash" in (*[!0-9a-fA-F]*|'') continue;; esac
printf '%s|%s\n' "$lr_hash" "$lr_path"
done"#;
    format!(
        "find {path_arguments} -type f -exec /bin/sh -c {worker} lovelyres-fim {{}} + 2>/dev/null | LC_ALL=C sort",
        worker = shq(worker),
    )
}

fn build_create_command(paths: &[String], temporary: &str, destination: &str) -> String {
    let scan = scan_pipeline(paths);
    format!(
        "set -eu; umask 077; mkdir -p {root}; lr_tmp={temporary}; trap 'rm -f -- \"$lr_tmp\"' 0 1 2 15; {scan} > \"$lr_tmp\"; [ -s \"$lr_tmp\" ] || [ -f \"$lr_tmp\" ]; mv -- \"$lr_tmp\" {destination}; trap - 0 1 2 15; lr_count=$(wc -l < {destination}); lr_hash=$(sha256sum -- {destination} | awk '{{print $1}}'); printf 'LR_FIM_V1|%s|%s\\n' \"$lr_count\" \"$lr_hash\"",
        root = shq(REMOTE_ROOT),
        temporary = shq(temporary),
        destination = shq(destination),
    )
}

fn build_compare_command(baseline: &IntegrityBaseline, temporary: &str) -> String {
    let scan = scan_pipeline(&baseline.paths);
    format!(
        "set -eu; lr_base={baseline}; lr_tmp={temporary}; trap 'rm -f -- \"$lr_tmp\"' 0 1 2 15; [ -f \"$lr_base\" ]; lr_hash=$(sha256sum -- \"$lr_base\" | awk '{{print $1}}'); [ \"$lr_hash\" = {expected} ]; {scan} > \"$lr_tmp\"; printf 'LR_FIM_DIFF_V1\\n===ADDED===\\n'; comm -13 \"$lr_base\" \"$lr_tmp\" | head -n {limit}; printf '===REMOVED===\\n'; comm -23 \"$lr_base\" \"$lr_tmp\" | head -n {limit}",
        baseline = shq(&baseline.remote_manifest),
        temporary = shq(temporary),
        expected = shq(&baseline.manifest_sha256),
        limit = MAXIMUM_DIFF_ENTRIES + 1,
    )
}

fn successful_output(subject: &'static str, output: SshCommandOutput) -> CoreResult<String> {
    if output.timed_out {
        return Err(CoreError::ssh(subject, "remote command timed out"));
    }
    if output.exit_code != Some(0) {
        return Err(CoreError::ssh(
            subject,
            format!(
                "remote command exited with {:?}: {}",
                output.exit_code,
                output.output.chars().take(1_024).collect::<String>()
            ),
        ));
    }
    Ok(output.output)
}

fn parse_create_output(output: String) -> CoreResult<(usize, String)> {
    let line = output
        .lines()
        .rev()
        .find(|line| line.starts_with("LR_FIM_V1|"))
        .ok_or_else(|| CoreError::validation("integrity baseline", "missing result marker"))?;
    let mut fields = line.split('|');
    if fields.next() != Some("LR_FIM_V1") {
        return Err(CoreError::validation(
            "integrity baseline",
            "invalid result marker",
        ));
    }
    let count = fields
        .next()
        .and_then(|field| field.parse::<usize>().ok())
        .ok_or_else(|| CoreError::validation("integrity baseline", "invalid file count"))?;
    let digest = fields
        .next()
        .filter(|_| fields.next().is_none())
        .ok_or_else(|| CoreError::validation("integrity baseline", "invalid result fields"))?
        .to_ascii_lowercase();
    validate_sha256(&digest)?;
    Ok((count, digest))
}

fn parse_manifest_line(line: &str) -> CoreResult<(String, String)> {
    let (digest, encoded_path) = line.split_once('|').ok_or_else(|| {
        CoreError::validation("integrity manifest entry", "missing field separator")
    })?;
    validate_sha256(digest)?;
    let bytes = STANDARD.decode(encoded_path).map_err(|_| {
        CoreError::validation("integrity manifest entry", "path is not valid base64")
    })?;
    if bytes.len() > MAXIMUM_PATH_BYTES {
        return Err(CoreError::validation(
            "integrity manifest entry",
            "decoded path is too long",
        ));
    }
    let path = String::from_utf8(bytes)
        .map_err(|_| CoreError::validation("integrity manifest entry", "path is not UTF-8"))?;
    validate_remote_file_path(&path)?;
    Ok((digest.to_ascii_lowercase(), path))
}

fn parse_diff_output(baseline_id: &str, output: &str) -> CoreResult<IntegrityDiff> {
    if !output.lines().any(|line| line == "LR_FIM_DIFF_V1") {
        return Err(CoreError::validation(
            "integrity diff",
            "missing result marker",
        ));
    }
    let mut mode = None;
    let mut added = BTreeMap::<String, String>::new();
    let mut removed = BTreeMap::<String, String>::new();
    let mut added_seen = 0usize;
    let mut removed_seen = 0usize;
    for line in output.lines() {
        match line {
            "LR_FIM_DIFF_V1" => continue,
            "===ADDED===" => {
                mode = Some(IntegrityDiffKind::Added);
                continue;
            }
            "===REMOVED===" => {
                mode = Some(IntegrityDiffKind::Removed);
                continue;
            }
            "" => continue,
            _ => {}
        }
        let Some(kind) = mode else {
            continue;
        };
        let (digest, path) = parse_manifest_line(line)?;
        match kind {
            IntegrityDiffKind::Added => {
                added_seen += 1;
                if added.len() < MAXIMUM_DIFF_ENTRIES {
                    added.insert(path, digest);
                }
            }
            IntegrityDiffKind::Removed => {
                removed_seen += 1;
                if removed.len() < MAXIMUM_DIFF_ENTRIES {
                    removed.insert(path, digest);
                }
            }
            IntegrityDiffKind::Modified => unreachable!(),
        }
    }

    let mut paths = added
        .keys()
        .chain(removed.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut entries = Vec::with_capacity(paths.len());
    for path in paths.iter() {
        let kind = match (added.get(path), removed.get(path)) {
            (Some(after), Some(before)) if after != before => IntegrityDiffKind::Modified,
            (Some(_), None) => IntegrityDiffKind::Added,
            (None, Some(_)) => IntegrityDiffKind::Removed,
            (Some(_), Some(_)) => continue,
            (None, None) => unreachable!(),
        };
        entries.push(IntegrityDiffEntry {
            severity: classify_severity(path, kind),
            path: path.clone(),
            kind,
        });
    }
    paths.clear();
    entries.sort_by(|left, right| {
        severity_rank(left.severity)
            .cmp(&severity_rank(right.severity))
            .then_with(|| left.path.cmp(&right.path))
    });
    let added_count = entries
        .iter()
        .filter(|entry| entry.kind == IntegrityDiffKind::Added)
        .count();
    let removed_count = entries
        .iter()
        .filter(|entry| entry.kind == IntegrityDiffKind::Removed)
        .count();
    let modified_count = entries
        .iter()
        .filter(|entry| entry.kind == IntegrityDiffKind::Modified)
        .count();
    Ok(IntegrityDiff {
        baseline_id: baseline_id.to_owned(),
        entries,
        added: added_count,
        removed: removed_count,
        modified: modified_count,
        truncated: added_seen > MAXIMUM_DIFF_ENTRIES || removed_seen > MAXIMUM_DIFF_ENTRIES,
    })
}

fn classify_severity(path: &str, kind: IntegrityDiffKind) -> IntegritySeverity {
    let web = ["/www/", "/html/", "/webapps/", "/htdocs/", "/public_html/"]
        .iter()
        .any(|segment| path.contains(segment));
    let executable = ["/bin/", "/sbin/"]
        .iter()
        .any(|segment| path.contains(segment));
    if (web || executable) && kind != IntegrityDiffKind::Removed {
        IntegritySeverity::High
    } else {
        IntegritySeverity::Medium
    }
}

const fn severity_rank(severity: IntegritySeverity) -> u8 {
    match severity {
        IntegritySeverity::High => 0,
        IntegritySeverity::Medium => 1,
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use chrono::Utc;

    use super::*;
    use crate::{
        BackendServices,
        ssh::{SshConnectionStatus, TestSessionHarness},
    };

    #[derive(Debug)]
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("lovelyres-integrity-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn encoded(path: &str, digest: char) -> String {
        format!(
            "{}|{}",
            digest.to_string().repeat(64),
            STANDARD.encode(path)
        )
    }

    #[test]
    fn paths_are_deduplicated_and_shell_quoted_without_opening_the_managed_namespace() {
        let paths = normalize_paths(vec![
            "/var/www/a b".to_owned(),
            "/etc".to_owned(),
            "/etc".to_owned(),
        ])
        .unwrap();
        assert_eq!(paths, vec!["/etc", "/var/www/a b"]);
        let command = build_create_command(
            &paths,
            "/tmp/.lovelyres_fim/.baseline-x.tmp",
            "/tmp/.lovelyres_fim/baseline-x.manifest",
        );
        assert!(command.contains("'/var/www/a b'"));
        assert!(command.contains("base64"));
        for hostile in [
            "relative",
            "/etc/../tmp",
            "/tmp/.lovelyres_fim",
            "/tmp/.lovelyres_fim/evil",
            "/var/www\n===REMOVED===",
        ] {
            assert!(normalize_paths(vec![hostile.to_owned()]).is_err());
        }
    }

    #[test]
    fn parses_added_removed_modified_and_high_risk_paths() {
        let output = format!(
            "LR_FIM_DIFF_V1\n===ADDED===\n{}\n{}\n===REMOVED===\n{}\n{}\n",
            encoded("/var/www/html/shell.php", 'a'),
            encoded("/etc/new.conf", 'b'),
            encoded("/var/www/html/shell.php", 'c'),
            encoded("/usr/bin/removed", 'd'),
        );
        let diff = parse_diff_output("baseline", &output).unwrap();
        assert_eq!(diff.added, 1);
        assert_eq!(diff.modified, 1);
        assert_eq!(diff.removed, 1);
        assert_eq!(diff.entries[0].path, "/var/www/html/shell.php");
        assert_eq!(diff.entries[0].severity, IntegritySeverity::High);
    }

    #[test]
    fn manifest_parser_rejects_control_characters_even_when_base64_encoded() {
        let hostile = "/var/www/a\n===REMOVED===\n<script>.php";
        let line = encoded(hostile, 'e');
        assert!(parse_manifest_line(&line).is_err());
    }

    #[test]
    fn malformed_or_non_absolute_manifest_paths_are_rejected() {
        assert!(parse_manifest_line(&format!("{}|%%%", "a".repeat(64))).is_err());
        assert!(parse_manifest_line(&encoded("relative", 'a')).is_err());
        assert!(parse_manifest_line("short|L2V0Yw==").is_err());
    }

    #[test]
    fn create_result_requires_exact_count_and_sha256() {
        let parsed =
            parse_create_output(format!("noise\nLR_FIM_V1|12|{}\n", "A".repeat(64))).unwrap();
        assert_eq!(parsed.0, 12);
        assert_eq!(parsed.1, "a".repeat(64));
        assert!(parse_create_output("LR_FIM_V1|x|bad".to_owned()).is_err());
    }

    #[tokio::test]
    async fn created_baseline_is_portable_and_bound_to_stable_target_identity() {
        let root = TestRoot::new();
        let services =
            BackendServices::new(PortableStore::prepare(root.0.clone()).unwrap()).unwrap();
        let identity = TargetIdentity::new("connection-a").unwrap();
        let guard = services.activate_target(identity.clone()).unwrap();
        let status = SshConnectionStatus {
            session_id: "session-a".to_owned(),
            connection_id: "connection-a".to_owned(),
            host: "host-a.test".to_owned(),
            port: 22,
            username: "operator".to_owned(),
            host_key_fingerprint: "SHA256:test".to_owned(),
            connected_at: Utc::now(),
        };
        let session = BoundSshSession::from_status(guard.clone(), &status, "test session").unwrap();
        let harness = Arc::new(TestSessionHarness::default());
        harness.set_execute_output(format!("LR_FIM_V1|2|{}", "a".repeat(64)));
        services
            .ssh()
            .install_test_session(status, harness)
            .await
            .unwrap();

        let baseline = services
            .integrity()
            .create_baseline(&session, vec!["/etc".to_owned(), "/var/www".to_owned()])
            .await
            .unwrap();
        assert_eq!(baseline.file_count, 2);
        assert_eq!(
            services.integrity().list(&guard).unwrap(),
            vec![baseline.clone()]
        );
        assert!(root.0.join("data").join("integrity.json").is_file());

        let replacement = services.activate_target(identity).unwrap();
        assert!(services.integrity().list(&guard).is_err());
        assert_eq!(
            services.integrity().list(&replacement).unwrap(),
            vec![baseline]
        );
    }

    #[tokio::test]
    async fn quarantine_requires_exact_plan_then_journals_and_verifies() {
        let root = TestRoot::new();
        let services =
            BackendServices::new(PortableStore::prepare(root.0.clone()).unwrap()).unwrap();
        let guard = services
            .activate_target(TargetIdentity::new("connection-a").unwrap())
            .unwrap();
        let status = SshConnectionStatus {
            session_id: "session-a".to_owned(),
            connection_id: "connection-a".to_owned(),
            host: "host-a.test".to_owned(),
            port: 22,
            username: "operator".to_owned(),
            host_key_fingerprint: "SHA256:test".to_owned(),
            connected_at: Utc::now(),
        };
        let session = BoundSshSession::from_status(guard, &status, "test session").unwrap();
        let harness = Arc::new(TestSessionHarness::default());
        harness.set_execute_output(format!("LR_FIM_V1|1|{}", "a".repeat(64)));
        services
            .ssh()
            .install_test_session(status, harness.clone())
            .await
            .unwrap();
        let baseline = services
            .integrity()
            .create_baseline(&session, vec!["/var/www".to_owned()])
            .await
            .unwrap();

        harness.set_execute_output(format!(
            "LR_FIM_DIFF_V1\n===ADDED===\n{}\n===REMOVED===\n",
            encoded("/var/www/html/shell.php", 'b')
        ));
        let wrong_plan = services
            .integrity()
            .plan_quarantine(&session, &baseline.id, "/var/www/html/shell.php")
            .await
            .unwrap();
        let exact_plan = services
            .integrity()
            .plan_quarantine(&session, &baseline.id, "/var/www/html/shell.php")
            .await
            .unwrap();
        let wrong_confirmation = DangerousConfirmation::approve(wrong_plan.definition());
        assert!(
            services
                .integrity()
                .execute_quarantine(
                    &session,
                    exact_plan,
                    wrong_confirmation,
                    services.operation_journal(),
                )
                .await
                .is_err()
        );
        assert!(services.operation_journal().entries().unwrap().is_empty());

        let exact_plan = services
            .integrity()
            .plan_quarantine(&session, &baseline.id, "/var/www/html/shell.php")
            .await
            .unwrap();
        let confirmation = DangerousConfirmation::approve(exact_plan.definition());
        harness.set_execute_output("QUARANTINE_OK\n");
        let outcome = services
            .integrity()
            .execute_quarantine(
                &session,
                exact_plan,
                confirmation,
                services.operation_journal(),
            )
            .await
            .unwrap();
        assert!(outcome.verified);
        let entries = services.operation_journal().entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].phase, crate::operations::JournalPhase::Executed);
        assert_eq!(
            entries[1].phase,
            crate::operations::JournalPhase::VerificationPassed
        );
    }
}
