//! Target-bound Java discovery and verified JAR class replacement.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    CoreError, CoreResult, PortableStore,
    operations::{
        DangerousConfirmation, ExecutionReceipt, OperationExecutor, OperationJournal,
        OperationPlan, OperationState, PlannedOperation, PortableOperationJournal,
        VerificationResult,
    },
    path_guard::PathGuard,
    sftp::{MAX_TRANSFER_BYTES, RemotePath},
    shell_escape::shq,
    ssh::{BoundSshSession, SftpRequest, SftpResponse, SshCommandOutput, SshService},
    store::StoreFile,
    target::{TargetContext, TargetGuard, TargetIdentity},
};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_CLASS_BYTES: u64 = 16 * 1024 * 1024;
const MAX_PROCESSES: usize = 50;
const MAX_CLASS_ENTRIES: usize = 500;
const MAX_OPEN_JARS: usize = 256;
const MAX_HISTORY: usize = 256;
/// Where a root login keeps the original JARs it replaced; older records
/// name this folder, so it keeps its name.
const JAVA_ROOT: &str = "/var/lib/lovelyres-java-updates";
/// Where any other login keeps them: a folder of its own home. An ordinary
/// account cannot create anything under /var/lib, and its backups are its own.
const JAVA_HOME_BACKUP_DIR: &str = ".lovelyhawk-java-updates";
const ENV_MARKER: &str = "LOVELYRES_JAVA_ENV_V1";
const JAR_MARKER: &str = "LOVELYRES_JAVA_JAR_V1";
const ENTRY_MARKER: &str = "LOVELYRES_JAVA_ENTRY_V1";
const STAGE_MARKER: &str = "LOVELYRES_JAVA_STAGE_READY_V1";
const APPLY_MARKER: &str = "LOVELYRES_JAVA_APPLIED_V1";
/// Printed when the rebuilt JAR cannot get the original owner and mode back
/// (an ordinary login cannot give a file to another account): nothing was
/// swapped in.
const OWNER_REFUSED_MARKER: &str = "LOVELYHAWK_JAVA_OWNER_REFUSED_V1";
const VERIFY_MARKER: &str = "LOVELYRES_JAVA_VERIFIED_V1";
const RESTORE_MARKER: &str = "LOVELYRES_JAVA_RESTORED_V1";
const REAPPLY_MARKER: &str = "LOVELYRES_JAVA_REAPPLIED_V1";

/// Shell function printing the absolute path of a JDK tool, or nothing.
///
/// A command run over SSH reads no login profile, so a JDK put on PATH by
/// /etc/profile or by a container image's own environment is invisible to
/// `command -v`, although the JVMs on the host were started from it. When the
/// tool is not on PATH it is looked for beside the `java` a running JVM was
/// started from (the kernel's /proc/<pid>/exe, not its command line). Such a
/// tool is only used when it, its bin directory and the JDK home are owned by
/// root or the login user and writable by no one else: a JVM started from a
/// directory another account can write must not decide what this command runs.
const JDK_TOOL_FUNCTION: &str = r#"jdk_tool() {
  found="$(command -v "$1" 2>/dev/null || true)"
  case "$found" in /*) printf '%s\n' "$found"; return 0 ;; esac
  me="$(id -u)"
  ps -eo pid=,comm= 2>/dev/null | awk '$2 == "java" || $2 ~ /\/java$/ { print $1 }' | head -n 64 | while read -r pid; do
    readlink -- "/proc/$pid/exe" 2>/dev/null || true
  done | sed -n 's#^\(/..*\)/bin/java$#\1#p' | sort -u | while IFS= read -r home; do
    tool="$home/bin/$1"
    test -f "$tool" && test -x "$tool" && test ! -L "$tool" || continue
    trusted=1
    for item in "$tool" "$home/bin" "$home"; do
      owner="$(stat -c %u -- "$item" 2>/dev/null)" || { trusted=0; break; }
      mode="$(stat -c %A -- "$item" 2>/dev/null)" || { trusted=0; break; }
      case "$owner" in 0|"$me") ;; *) trusted=0 ;; esac
      case "$mode" in ?????w*|????????w*) trusted=0 ;; esac
    done
    if [ "$trusted" -eq 1 ]; then printf '%s\n' "$tool"; break; fi
  done
}"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum JavaTool {
    Java,
    Jar,
    Jcmd,
    Jstack,
    Jmap,
    Jstat,
    Javap,
}

impl JavaTool {
    pub const ALL: [Self; 7] = [
        Self::Java,
        Self::Jar,
        Self::Jcmd,
        Self::Jstack,
        Self::Jmap,
        Self::Jstat,
        Self::Javap,
    ];

    pub const fn command(self) -> &'static str {
        match self {
            Self::Java => "java",
            Self::Jar => "jar",
            Self::Jcmd => "jcmd",
            Self::Jstack => "jstack",
            Self::Jmap => "jmap",
            Self::Jstat => "jstat",
            Self::Javap => "javap",
        }
    }

    fn parse(value: &str) -> CoreResult<Self> {
        Self::ALL
            .into_iter()
            .find(|tool| tool.command() == value)
            .ok_or_else(|| CoreError::validation("Java tool", "unknown tool marker"))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JavaProcess {
    pub pid: u32,
    pub user: String,
    pub cpu_percent: f32,
    pub memory_percent: f32,
    pub elapsed_seconds: u64,
    pub command: String,
    /// The .jar files the process holds open, read from /proc/<pid>/fd: the
    /// JARs it really loads, including those a wildcard classpath or an
    /// application server's own class loaders open. `None` when this login
    /// may not read the process's open files.
    #[serde(default)]
    pub open_jars: Option<Vec<RemotePath>>,
    /// More JARs were open than were listed, or some had names that cannot be
    /// used safely and were left out.
    #[serde(default)]
    pub open_jars_incomplete: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JavaEnvironment {
    pub target: TargetGuard,
    pub version: Option<String>,
    pub tools: BTreeMap<JavaTool, bool>,
    pub processes: Vec<JavaProcess>,
    pub captured_at: DateTime<Utc>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct JarEntryPath(String);

impl fmt::Debug for JarEntryPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("JarEntryPath")
            .field(&self.0)
            .finish()
    }
}

impl JarEntryPath {
    pub fn new(value: impl Into<String>) -> CoreResult<Self> {
        let value = value.into().trim().replace('\\', "/");
        if value.is_empty()
            || value.len() > 1_024
            || value.starts_with('/')
            || !value.ends_with(".class")
            || value.chars().any(char::is_control)
        {
            return Err(CoreError::validation(
                "JAR class entry",
                "must be a relative .class path no longer than 1024 bytes",
            ));
        }
        for component in value.split('/') {
            if component.is_empty()
                || matches!(component, "." | "..")
                || !component.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$' | b'-' | b'.')
                })
            {
                return Err(CoreError::validation(
                    "JAR class entry",
                    "contains an invalid archive component",
                ));
            }
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for JarEntryPath {
    type Error = CoreError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<JarEntryPath> for String {
    fn from(value: JarEntryPath) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JavaJarInspection {
    pub target: TargetGuard,
    pub jar_path: RemotePath,
    pub size: u64,
    pub sha256: String,
    pub class_count: usize,
    pub class_entries: Vec<JarEntryPath>,
    pub truncated: bool,
    pub captured_at: DateTime<Utc>,
}

pub struct StagedClassArtifact {
    path: PathBuf,
    bytes: u64,
    sha256: String,
}

impl fmt::Debug for StagedClassArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StagedClassArtifact")
            .field("bytes", &self.bytes)
            .field("sha256", &self.sha256)
            .finish_non_exhaustive()
    }
}

impl StagedClassArtifact {
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

impl Drop for StagedClassArtifact {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum JavaUpdateState {
    Applied,
    Restored,
}

impl JavaUpdateState {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Applied => "已应用",
            Self::Restored => "已恢复",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JavaUpdateRecord {
    pub id: String,
    pub operation_id: String,
    pub last_operation_id: String,
    pub target: TargetIdentity,
    pub jar_path: RemotePath,
    pub entry_path: JarEntryPath,
    pub remote_root: RemotePath,
    pub before_jar_sha256: String,
    pub before_entry_sha256: String,
    pub source_sha256: String,
    pub applied_jar_sha256: String,
    pub backup_sha256: String,
    pub digest: String,
    pub state: JavaUpdateState,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct JavaJarUpdatePlan {
    operation: OperationPlan,
    update_id: String,
    jar_path: RemotePath,
    entry_path: JarEntryPath,
    remote_root: RemotePath,
    candidate_path: RemotePath,
    paths: PathGuard,
    artifact: StagedClassArtifact,
    before_jar_sha256: String,
    before_entry_sha256: String,
}

impl fmt::Debug for JavaJarUpdatePlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JavaJarUpdatePlan")
            .field("operation", &self.operation)
            .field("update_id", &self.update_id)
            .field("jar_path", &self.jar_path)
            .field("entry_path", &self.entry_path)
            .field("remote_root", &self.remote_root)
            .field("candidate_path", &self.candidate_path)
            .field("artifact", &self.artifact)
            .field("before_jar_sha256", &self.before_jar_sha256)
            .field("before_entry_sha256", &self.before_entry_sha256)
            .finish()
    }
}

impl JavaJarUpdatePlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn jar_path(&self) -> &RemotePath {
        &self.jar_path
    }

    pub fn entry_path(&self) -> &JarEntryPath {
        &self.entry_path
    }

    pub fn source_sha256(&self) -> &str {
        self.artifact.sha256()
    }
}

#[derive(Debug, Clone)]
pub struct JavaRestorePlan {
    operation: OperationPlan,
    record: JavaUpdateRecord,
}

impl JavaRestorePlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn record(&self) -> &JavaUpdateRecord {
        &self.record
    }
}

#[derive(Debug, Clone)]
pub struct JavaOperationOutcome {
    pub record: JavaUpdateRecord,
    pub verification: VerificationResult,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct StoredJavaHistory {
    updates: Vec<JavaUpdateRecord>,
}

#[derive(Debug, Clone)]
pub struct JavaService {
    ssh: SshService,
    target: Arc<TargetContext>,
    store: PortableStore,
    journal: PortableOperationJournal,
    lock: Arc<Mutex<()>>,
}

impl JavaService {
    pub fn new(
        ssh: SshService,
        target: Arc<TargetContext>,
        store: PortableStore,
        journal: PortableOperationJournal,
    ) -> Self {
        Self {
            ssh,
            target,
            store,
            journal,
            lock: Arc::new(Mutex::new(())),
        }
    }

    pub async fn scan_environment(&self, session: &BoundSshSession) -> CoreResult<JavaEnvironment> {
        self.target.validate(session.target())?;
        let output = successful_marker(
            "scan Java environment",
            self.ssh
                .execute_bound(session, environment_command(), COMMAND_TIMEOUT)
                .await?,
            ENV_MARKER,
        )?;
        let parsed = parse_environment(&output)?;
        self.target.validate(session.target())?;
        Ok(JavaEnvironment {
            target: session.target().clone(),
            version: parsed.version,
            tools: parsed.tools,
            processes: parsed.processes,
            captured_at: Utc::now(),
        })
    }

    pub async fn inspect_jar(
        &self,
        session: &BoundSshSession,
        jar_path: RemotePath,
    ) -> CoreResult<JavaJarInspection> {
        validate_jar_path(&jar_path)?;
        self.target.validate(session.target())?;
        let output = successful_marker(
            "inspect Java archive",
            self.ssh
                .execute_bound(session, inspect_jar_command(&jar_path), COMMAND_TIMEOUT)
                .await?,
            JAR_MARKER,
        )?;
        let (size, sha256, class_count, class_entries) = parse_jar_inspection(&output)?;
        self.target.validate(session.target())?;
        Ok(JavaJarInspection {
            target: session.target().clone(),
            jar_path,
            size,
            sha256,
            class_count,
            truncated: class_count > class_entries.len(),
            class_entries,
            captured_at: Utc::now(),
        })
    }

    pub fn stage_class_file(
        &self,
        paths: &PathGuard,
        selected: &Path,
    ) -> CoreResult<StagedClassArtifact> {
        let staged = paths.stage_native_selected_upload(selected, MAX_CLASS_BYTES)?;
        let result = inspect_staged_class(paths, &staged);
        if result.is_err() {
            let _ = fs::remove_file(&staged);
        }
        let (bytes, sha256) = result?;
        Ok(StagedClassArtifact {
            path: staged,
            bytes,
            sha256,
        })
    }

    pub async fn plan_jar_update(
        &self,
        session: &BoundSshSession,
        paths: &PathGuard,
        jar_path: RemotePath,
        entry_path: JarEntryPath,
        artifact: StagedClassArtifact,
    ) -> CoreResult<JavaJarUpdatePlan> {
        validate_jar_path(&jar_path)?;
        paths.ensure_managed_upload_source(&artifact.path)?;
        let (bytes, sha256) = inspect_staged_class(paths, &artifact.path)?;
        if bytes != artifact.bytes || sha256 != artifact.sha256 {
            return Err(CoreError::validation(
                "staged Java class",
                "artifact changed after it was authorized",
            ));
        }
        self.target.validate(session.target())?;
        let output = successful_marker(
            "inspect JAR class entry",
            self.ssh
                .execute_bound(
                    session,
                    inspect_entry_command(&jar_path, &entry_path),
                    COMMAND_TIMEOUT,
                )
                .await?,
            ENTRY_MARKER,
        )?;
        let (before_jar_sha256, before_entry_sha256) = parse_entry_inspection(&output)?;
        let login = parse_login(&output)?;
        self.target.validate(session.target())?;

        let update_id = Uuid::new_v4().to_string();
        let remote_root = remote_root_for(&login, &update_id)?;
        let candidate_path = candidate_path(&jar_path, &update_id)?;
        let mut operation = OperationPlan::new(
            session.target().clone(),
            format!(
                "替换 {} 中的 {}（SHA-256 {}）",
                jar_path.as_str(),
                entry_path.as_str(),
                artifact.sha256
            ),
            true,
            Some("从受管原始 JAR 备份原子恢复，并校验 SHA-256".to_owned()),
        )?;
        operation
            .metadata
            .insert("source".to_owned(), "java-jar-update".to_owned());
        operation
            .metadata
            .insert("update_id".to_owned(), update_id.clone());
        operation
            .metadata
            .insert("jar_sha256".to_owned(), before_jar_sha256.clone());
        operation
            .metadata
            .insert("class_sha256".to_owned(), artifact.sha256.clone());
        Ok(JavaJarUpdatePlan {
            operation,
            update_id,
            jar_path,
            entry_path,
            remote_root,
            candidate_path,
            paths: paths.clone(),
            artifact,
            before_jar_sha256,
            before_entry_sha256,
        })
    }

    pub async fn execute_jar_update(
        &self,
        session: &BoundSshSession,
        plan: JavaJarUpdatePlan,
        confirmation: DangerousConfirmation,
    ) -> CoreResult<JavaOperationOutcome> {
        validate_update_plan(session, &plan)?;
        let executor = JarUpdateExecutor {
            service: self,
            session,
            plan: &plan,
        };
        let verification = run_planned_operation(
            &self.target,
            &self.journal,
            plan.operation.clone(),
            confirmation,
            &executor,
        )
        .await?;
        if !verification.passed {
            return Err(CoreError::validation(
                "Java update verification",
                "JAR or class hash did not match; the original archive was restored when safe",
            ));
        }
        Ok(JavaOperationOutcome {
            record: self.record_by_id(session.target(), &plan.update_id)?,
            verification,
        })
    }

    pub fn list_history(&self, target: &TargetGuard) -> CoreResult<Vec<JavaUpdateRecord>> {
        self.target.validate(target)?;
        let _guard = self.lock.lock();
        let mut records = self
            .store
            .read_or_default::<StoredJavaHistory>(StoreFile::Java)?
            .updates
            .into_iter()
            .filter(|record| record.target == target.identity)
            .collect::<Vec<_>>();
        for record in &records {
            validate_record(record)?;
        }
        records.sort_by(|left, right| right.created_at.cmp(&left.created_at));
        Ok(records)
    }

    pub fn plan_restore(
        &self,
        session: &BoundSshSession,
        record_id: &str,
    ) -> CoreResult<JavaRestorePlan> {
        self.target.validate(session.target())?;
        let record = self.record_by_id(session.target(), record_id)?;
        if record.state != JavaUpdateState::Applied {
            return Err(CoreError::validation(
                "Java update restore",
                "only an applied update can be restored",
            ));
        }
        let mut operation = OperationPlan::new(
            session.target().clone(),
            format!(
                "恢复 {} 中的 {}",
                record.jar_path.as_str(),
                record.entry_path.as_str()
            ),
            true,
            Some("从受管已应用 JAR 副本重新应用本次更新".to_owned()),
        )?;
        operation
            .metadata
            .insert("source".to_owned(), "java-jar-restore".to_owned());
        operation
            .metadata
            .insert("record_id".to_owned(), record.id.clone());
        operation
            .metadata
            .insert("digest".to_owned(), record.digest.clone());
        Ok(JavaRestorePlan { operation, record })
    }

    pub async fn execute_restore(
        &self,
        session: &BoundSshSession,
        plan: JavaRestorePlan,
        confirmation: DangerousConfirmation,
    ) -> CoreResult<JavaOperationOutcome> {
        validate_restore_plan(session, &plan)?;
        let executor = JavaRestoreExecutor {
            service: self,
            session,
            plan: &plan,
        };
        let verification = run_planned_operation(
            &self.target,
            &self.journal,
            plan.operation.clone(),
            confirmation,
            &executor,
        )
        .await?;
        if !verification.passed {
            return Err(CoreError::validation(
                "Java restore verification",
                "restored JAR hash did not match the original archive",
            ));
        }
        Ok(JavaOperationOutcome {
            record: self.record_by_id(session.target(), &plan.record.id)?,
            verification,
        })
    }

    fn insert_record(&self, record: JavaUpdateRecord) -> CoreResult<()> {
        validate_record(&record)?;
        let _guard = self.lock.lock();
        let mut stored = self
            .store
            .read_or_default::<StoredJavaHistory>(StoreFile::Java)?;
        if stored.updates.iter().any(|item| item.id == record.id) {
            return Err(CoreError::validation(
                "Java update record",
                "record identity already exists",
            ));
        }
        stored.updates.push(record);
        if stored.updates.len() > MAX_HISTORY {
            stored.updates.sort_by_key(|item| item.created_at);
            stored.updates.drain(..stored.updates.len() - MAX_HISTORY);
        }
        self.store.write(StoreFile::Java, &stored)
    }

    fn record_by_id(&self, target: &TargetGuard, record_id: &str) -> CoreResult<JavaUpdateRecord> {
        validate_uuid("Java update record id", record_id)?;
        let _guard = self.lock.lock();
        let record = self
            .store
            .read_or_default::<StoredJavaHistory>(StoreFile::Java)?
            .updates
            .into_iter()
            .find(|record| record.id == record_id && record.target == target.identity)
            .ok_or_else(|| CoreError::NotFound {
                entity: "Java update record",
                id: record_id.to_owned(),
            })?;
        validate_record(&record)?;
        Ok(record)
    }

    fn transition_record(
        &self,
        record_id: &str,
        target: &TargetIdentity,
        expected: JavaUpdateState,
        next: JavaUpdateState,
        operation_id: &str,
    ) -> CoreResult<JavaUpdateRecord> {
        validate_uuid("Java update record id", record_id)?;
        validate_uuid("Java update operation id", operation_id)?;
        let _guard = self.lock.lock();
        let mut stored = self
            .store
            .read_or_default::<StoredJavaHistory>(StoreFile::Java)?;
        let record = stored
            .updates
            .iter_mut()
            .find(|record| record.id == record_id && &record.target == target)
            .ok_or_else(|| CoreError::NotFound {
                entity: "Java update record",
                id: record_id.to_owned(),
            })?;
        validate_record(record)?;
        if record.state != expected {
            return Err(CoreError::validation(
                "Java update record state",
                format!(
                    "expected {}, found {}",
                    expected.label(),
                    record.state.label()
                ),
            ));
        }
        record.state = next;
        record.last_operation_id = operation_id.to_owned();
        record.updated_at = Utc::now();
        let result = record.clone();
        self.store.write(StoreFile::Java, &stored)?;
        Ok(result)
    }

    async fn cleanup_remote(&self, session: &BoundSshSession, root: &RemotePath) {
        let Ok(source) = root.child("new.class") else {
            return;
        };
        let _ = self
            .ssh
            .execute_bound(
                session,
                format!(
                    "rm -f -- {} 2>/dev/null || true; rmdir -- {} 2>/dev/null || true",
                    shq(source.as_str()),
                    shq(root.as_str())
                ),
                Duration::from_secs(15),
            )
            .await;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UpdateReceipt {
    before_jar_sha256: String,
    before_entry_sha256: String,
    source_sha256: String,
    applied_jar_sha256: String,
    backup_sha256: String,
}

#[derive(Debug)]
struct JarUpdateExecutor<'a> {
    service: &'a JavaService,
    session: &'a BoundSshSession,
    plan: &'a JavaJarUpdatePlan,
}

#[async_trait]
impl OperationExecutor for JarUpdateExecutor<'_> {
    async fn execute(&self, definition: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        ensure_same_plan(definition, &self.plan.operation, "Java JAR update")?;
        let (bytes, sha256) = inspect_staged_class(&self.plan.paths, &self.plan.artifact.path)?;
        if bytes != self.plan.artifact.bytes || sha256 != self.plan.artifact.sha256 {
            return Err(CoreError::validation(
                "staged Java class",
                "artifact changed after the update plan was confirmed",
            ));
        }
        self.service.target.validate(self.session.target())?;
        let stage = self
            .service
            .ssh
            .execute_bound(
                self.session,
                prepare_remote_stage_command(self.plan)?,
                COMMAND_TIMEOUT,
            )
            .await;
        if let Err(error) = self.service.target.validate(self.session.target()) {
            self.service
                .cleanup_remote(self.session, &self.plan.remote_root)
                .await;
            return Err(error);
        }
        if let Err(error) = stage.and_then(|output| {
            successful_marker("prepare Java update staging", output, STAGE_MARKER)
        }) {
            self.service
                .cleanup_remote(self.session, &self.plan.remote_root)
                .await;
            return Err(error);
        }

        let remote_class = self.plan.remote_root.child("new.class")?;
        let upload = self
            .service
            .ssh
            .sftp(
                self.session.session_id(),
                self.session.connection_id(),
                SftpRequest::UploadNew {
                    local_path: self.plan.artifact.path.clone(),
                    remote_path: remote_class.as_str().to_owned(),
                    maximum_bytes: MAX_CLASS_BYTES.min(MAX_TRANSFER_BYTES),
                    // A class file is small and its upload is not offered for
                    // cancelling; the switch is never thrown.
                    cancel: crate::ssh::SftpTransferCancel::new(),
                },
            )
            .await;
        if let Err(error) = self.service.target.validate(self.session.target()) {
            self.service
                .cleanup_remote(self.session, &self.plan.remote_root)
                .await;
            return Err(error);
        }
        match upload {
            Err(error) => {
                self.service
                    .cleanup_remote(self.session, &self.plan.remote_root)
                    .await;
                return Err(error);
            }
            Ok(SftpResponse::Transfer { bytes }) if bytes == self.plan.artifact.bytes => {}
            Ok(SftpResponse::Transfer { bytes }) => {
                self.service
                    .cleanup_remote(self.session, &self.plan.remote_root)
                    .await;
                return Err(CoreError::validation(
                    "Java class upload",
                    format!(
                        "uploaded {bytes} bytes, expected {}",
                        self.plan.artifact.bytes
                    ),
                ));
            }
            Ok(response) => {
                self.service
                    .cleanup_remote(self.session, &self.plan.remote_root)
                    .await;
                return Err(CoreError::validation(
                    "Java class upload",
                    format!("unexpected SFTP response: {}", response.kind()),
                ));
            }
        }

        let applied = self
            .service
            .ssh
            .execute_bound(
                self.session,
                apply_update_command(self.plan)?,
                COMMAND_TIMEOUT,
            )
            .await?;
        // The script prints this only right before giving up, ahead of the swap.
        if applied
            .output
            .lines()
            .any(|line| line.trim() == OWNER_REFUSED_MARKER)
        {
            // Nothing was swapped in, so the copy of the original kept for a
            // restore is not needed either.
            self.service
                .cleanup_remote(self.session, &self.plan.remote_root)
                .await;
            return Err(CoreError::validation(
                "Java JAR owner",
                "the rebuilt JAR could not be given the original owner and mode, so nothing was swapped in",
            ));
        }
        let output = successful_marker("apply Java JAR update", applied, APPLY_MARKER)?;
        let receipt = parse_update_receipt(&output)?;
        validate_receipt_for_plan(&receipt, self.plan)?;
        let now = Utc::now();
        let record = JavaUpdateRecord {
            id: self.plan.update_id.clone(),
            operation_id: self.plan.operation.id.clone(),
            last_operation_id: self.plan.operation.id.clone(),
            target: self.session.target().identity.clone(),
            jar_path: self.plan.jar_path.clone(),
            entry_path: self.plan.entry_path.clone(),
            remote_root: self.plan.remote_root.clone(),
            before_jar_sha256: receipt.before_jar_sha256.clone(),
            before_entry_sha256: receipt.before_entry_sha256.clone(),
            source_sha256: receipt.source_sha256.clone(),
            applied_jar_sha256: receipt.applied_jar_sha256.clone(),
            backup_sha256: receipt.backup_sha256.clone(),
            digest: record_digest(
                &self.session.target().identity,
                &self.plan.update_id,
                &self.plan.jar_path,
                &self.plan.entry_path,
                &self.plan.remote_root,
                &receipt,
            )?,
            state: JavaUpdateState::Applied,
            created_at: now,
            updated_at: now,
        };
        if let Err(error) = self.service.insert_record(record) {
            let _ = self
                .service
                .ssh
                .execute_bound(
                    self.session,
                    restore_command_for_plan(self.plan, &receipt)?,
                    COMMAND_TIMEOUT,
                )
                .await;
            return Err(error);
        }
        Ok(ExecutionReceipt {
            summary: format!(
                "replaced {} in {}; managed backup {}",
                self.plan.entry_path.as_str(),
                self.plan.jar_path.as_str(),
                self.plan.remote_root.as_str()
            ),
            restore_token: Some(serde_json::to_string(&receipt).map_err(|source| {
                CoreError::Encode {
                    subject: "Java update receipt",
                    source,
                }
            })?),
        })
    }

    async fn verify(
        &self,
        definition: &OperationPlan,
        receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        ensure_same_plan(definition, &self.plan.operation, "Java JAR update")?;
        let receipt = decode_receipt(receipt)?;
        validate_receipt_for_plan(&receipt, self.plan)?;
        let output = successful_marker(
            "verify Java JAR update",
            self.service
                .ssh
                .execute_bound(
                    self.session,
                    verify_update_command(self.plan, &receipt)?,
                    COMMAND_TIMEOUT,
                )
                .await?,
            VERIFY_MARKER,
        )?;
        let verified = parse_verify_receipt(&output)?;
        Ok(VerificationResult {
            passed: verified == receipt,
            detail: if verified == receipt {
                format!(
                    "class and archive SHA-256 verified for {}",
                    self.plan.entry_path.as_str()
                )
            } else {
                "remote Java update evidence differed from the immutable plan".to_owned()
            },
        })
    }

    async fn restore(
        &self,
        definition: &OperationPlan,
        receipt: &ExecutionReceipt,
    ) -> CoreResult<()> {
        ensure_same_plan(definition, &self.plan.operation, "Java JAR update")?;
        let receipt = decode_receipt(receipt)?;
        successful_marker(
            "restore failed Java JAR update",
            self.service
                .ssh
                .execute_bound(
                    self.session,
                    restore_command_for_plan(self.plan, &receipt)?,
                    COMMAND_TIMEOUT,
                )
                .await?,
            RESTORE_MARKER,
        )?;
        self.service.transition_record(
            &self.plan.update_id,
            &self.session.target().identity,
            JavaUpdateState::Applied,
            JavaUpdateState::Restored,
            &self.plan.operation.id,
        )?;
        Ok(())
    }
}

#[derive(Debug)]
struct JavaRestoreExecutor<'a> {
    service: &'a JavaService,
    session: &'a BoundSshSession,
    plan: &'a JavaRestorePlan,
}

#[async_trait]
impl OperationExecutor for JavaRestoreExecutor<'_> {
    async fn execute(&self, definition: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        ensure_same_plan(definition, &self.plan.operation, "Java JAR restore")?;
        successful_marker(
            "restore Java update history",
            self.service
                .ssh
                .execute_bound(
                    self.session,
                    restore_command_for_record(&self.plan.record)?,
                    COMMAND_TIMEOUT,
                )
                .await?,
            RESTORE_MARKER,
        )?;
        self.service.transition_record(
            &self.plan.record.id,
            &self.plan.record.target,
            JavaUpdateState::Applied,
            JavaUpdateState::Restored,
            &self.plan.operation.id,
        )?;
        Ok(ExecutionReceipt {
            summary: format!(
                "restored original JAR from {}",
                self.plan.record.remote_root.as_str()
            ),
            restore_token: Some(self.plan.record.id.clone()),
        })
    }

    async fn verify(
        &self,
        definition: &OperationPlan,
        _: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        ensure_same_plan(definition, &self.plan.operation, "Java JAR restore")?;
        let output = successful_marker(
            "verify restored Java JAR",
            self.service
                .ssh
                .execute_bound(
                    self.session,
                    verify_restored_command(&self.plan.record)?,
                    COMMAND_TIMEOUT,
                )
                .await?,
            VERIFY_MARKER,
        )?;
        let actual = output
            .lines()
            .find_map(|line| line.strip_prefix("RESTORED\t"))
            .ok_or_else(|| {
                CoreError::validation("Java restore verification", "missing hash evidence")
            })?;
        validate_sha256("restored JAR hash", actual)?;
        Ok(VerificationResult {
            passed: actual == self.plan.record.before_jar_sha256,
            detail: if actual == self.plan.record.before_jar_sha256 {
                "original JAR SHA-256 restored".to_owned()
            } else {
                "restored JAR SHA-256 differed from history".to_owned()
            },
        })
    }

    async fn restore(&self, definition: &OperationPlan, _: &ExecutionReceipt) -> CoreResult<()> {
        ensure_same_plan(definition, &self.plan.operation, "Java JAR restore")?;
        successful_marker(
            "reapply Java update after failed restore",
            self.service
                .ssh
                .execute_bound(
                    self.session,
                    reapply_command(&self.plan.record)?,
                    COMMAND_TIMEOUT,
                )
                .await?,
            REAPPLY_MARKER,
        )?;
        self.service.transition_record(
            &self.plan.record.id,
            &self.plan.record.target,
            JavaUpdateState::Restored,
            JavaUpdateState::Applied,
            &self.plan.operation.id,
        )?;
        Ok(())
    }
}

async fn run_planned_operation(
    target: &TargetContext,
    journal: &dyn OperationJournal,
    definition: OperationPlan,
    confirmation: DangerousConfirmation,
    executor: &dyn OperationExecutor,
) -> CoreResult<VerificationResult> {
    let mut operation = PlannedOperation::plan(definition);
    operation.confirm(confirmation)?;
    let execution = operation.execute(target, executor).await;
    if matches!(
        operation.state(),
        OperationState::Executed | OperationState::StaleAfterExecution
    ) {
        operation.journal(journal)?;
    }
    execution?;
    let verification = operation.verify(target, executor, journal).await;
    match verification {
        Ok(result) if result.passed => Ok(result),
        Ok(result) => {
            operation.restore(target, executor, journal).await?;
            Ok(result)
        }
        Err(error) => {
            if matches!(operation.state(), OperationState::VerificationFailed) {
                let _ = operation.restore(target, executor, journal).await;
            }
            Err(error)
        }
    }
}

/// JVMs that exited but were never reaped (state Z) run nothing and are left
/// out by their state, never by their command text, which a process can set.
///
/// For each JVM listed, the .jar files it holds open come from the links in
/// /proc/<pid>/fd (`FDS <pid> 0` when this login may not read them): the
/// command line names only the launcher JARs of an application server or a
/// wildcard classpath, while the JVM keeps every JAR it loads from open.
fn environment_command() -> String {
    format!(
        r#"set -eu
{JDK_TOOL_FUNCTION}
printf '%s\n' '{ENV_MARKER}'
for tool in java jar jcmd jstack jmap jstat javap; do
  if [ -n "$(jdk_tool "$tool" || true)" ]; then printf 'TOOL\t%s\t1\n' "$tool"; else printf 'TOOL\t%s\t0\n' "$tool"; fi
done
java_tool="$(jdk_tool java || true)"
if [ -n "$java_tool" ]; then
  "$java_tool" -version 2>&1 | sed -n '1{{s/[[:space:]]\+/ /g;s/^/VERSION\t/p;q;}}'
fi
procs="$(ps -eo stat=,pid=,user=,pcpu=,pmem=,etimes=,comm=,args= 2>/dev/null | awk '
  $1 !~ /^Z/ && ($7 == "java" || $7 ~ /\/java$/) {{
    command=$0; sub(/^[[:space:]]*[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]*/, "", command);
    gsub(/[\t\r\n]/, " ", command);
    if (length(command) > 512) command=substr(command, 1, 512);
    printf "PROC\t%s\t%s\t%s\t%s\t%s\t%s\n", $2, $3, $4, $5, $6, command;
    count++; if (count >= {MAX_PROCESSES}) exit;
  }}' || true)"
if [ -n "$procs" ]; then printf '%s\n' "$procs"; fi
for pid in $(printf '%s\n' "$procs" | awk -F '\t' '$1 == "PROC" {{ print $2 }}'); do
  if fds="$(ls -l -- "/proc/$pid/fd" 2>/dev/null)"; then
    printf 'FDS\t%s\t1\n' "$pid"
    printf '%s\n' "$fds" | sed -n 's#^.* -> \(/.*\.[jJ][aA][rR]\)$#\1#p' | sort -u | awk -v pid="$pid" '
      NR <= {MAX_OPEN_JARS} {{ printf "OPEN\t%s\t%s\n", pid, $0 }}
      NR == {MAX_OPEN_JARS} + 1 {{ printf "OPENMORE\t%s\n", pid }}'
  else
    printf 'FDS\t%s\t0\n' "$pid"
  fi
done"#
    )
}

fn inspect_jar_command(jar_path: &RemotePath) -> String {
    let jar = shq(jar_path.as_str());
    format!(
        r#"set -eu
jar_path={jar}
test -f "$jar_path" && test ! -L "$jar_path"
{JDK_TOOL_FUNCTION}
jar_tool="$(jdk_tool jar || true)"
test -n "$jar_tool"
command -v sha256sum >/dev/null 2>&1
printf '%s\n' '{JAR_MARKER}'
printf 'META\t%s\t%s\n' "$(stat -c %s -- "$jar_path")" "$(sha256sum -- "$jar_path" | awk '{{print $1}}')"
"$jar_tool" tf "$jar_path" | awk '
  /\.class$/ {{
    count++;
    if (count <= {MAX_CLASS_ENTRIES}) print "CLASS\t" $0;
  }}
  END {{ print "COUNT\t" (count + 0); }}'"#
    )
}

fn inspect_entry_command(jar_path: &RemotePath, entry_path: &JarEntryPath) -> String {
    let jar = shq(jar_path.as_str());
    let entry = shq(entry_path.as_str());
    format!(
        r#"set -eu
jar_path={jar}
entry={entry}
test -f "$jar_path" && test ! -L "$jar_path"
{JDK_TOOL_FUNCTION}
jar_tool="$(jdk_tool jar || true)"
test -n "$jar_tool"
command -v sha256sum >/dev/null 2>&1
"$jar_tool" tf "$jar_path" | grep -F -x -- "$entry" >/dev/null
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
(cd "$work" && "$jar_tool" xf "$jar_path" "$entry")
test -f "$work/$entry" && test ! -L "$work/$entry"
printf '%s\n' '{ENTRY_MARKER}'
printf 'ENTRY\t%s\t%s\n' "$(sha256sum -- "$jar_path" | awk '{{print $1}}')" "$(sha256sum -- "$work/$entry" | awk '{{print $1}}')"
printf 'LOGIN\t%s\t%s\n' "$(id -u)" "${{HOME:-}}""#
    )
}

fn prepare_remote_stage_command(plan: &JavaJarUpdatePlan) -> CoreResult<String> {
    let root = shq(plan.remote_root.as_str());
    let base = plan.remote_root.parent()?;
    Ok(format!(
        r#"set -eu
umask 077
base={}
root={root}
if [ -e "$base" ] || [ -L "$base" ]; then
  test -d "$base" && test ! -L "$base"
  test "$(stat -c %u -- "$base")" = "$(id -u)"
  chmod 0700 -- "$base"
else
  mkdir -m 0700 -- "$base"
fi
test ! -e "$root" && test ! -L "$root"
mkdir -m 0700 -- "$root"
printf '%s\n' '{STAGE_MARKER}'"#,
        shq(base.as_str())
    ))
}

fn apply_update_command(plan: &JavaJarUpdatePlan) -> CoreResult<String> {
    validate_update_paths(plan)?;
    let backup = plan.remote_root.child("original.jar")?;
    let applied = plan.remote_root.child("applied.jar")?;
    let source = plan.remote_root.child("new.class")?;
    let work = plan.remote_root.child("work")?;
    let verify = plan.remote_root.child("verify")?;
    let entry_parent = entry_parent(&plan.entry_path);
    let staged_entry_parent = if entry_parent.is_empty() {
        work.clone()
    } else {
        RemotePath::new(format!("{}/{entry_parent}", work.as_str()))?
    };
    let staged_entry = RemotePath::new(format!("{}/{}", work.as_str(), plan.entry_path.as_str()))?;
    let verify_entry =
        RemotePath::new(format!("{}/{}", verify.as_str(), plan.entry_path.as_str()))?;
    let rollback = plan
        .jar_path
        .parent()?
        .child(&format!(".lovelyres-java-{}.rollback", plan.update_id))?;

    Ok(format!(
        r#"set -eu
umask 077
jar_path={jar}
entry={entry}
root={root}
source={source}
backup={backup}
applied={applied}
candidate={candidate}
rollback={rollback}
work={work}
verify={verify}
committed=0
cleanup() {{
  status=$?
  trap - EXIT HUP INT TERM
  rm -f -- "$candidate" "$rollback"
  if [ "$status" -ne 0 ] && [ "$committed" -eq 1 ] && [ -f "$backup" ] && [ ! -L "$backup" ]; then
    cp -a -- "$backup" "$rollback" && mv -f -- "$rollback" "$jar_path" || true
  fi
  exit "$status"
}}
trap cleanup EXIT HUP INT TERM
test -f "$jar_path" && test ! -L "$jar_path"
test -f "$source" && test ! -L "$source"
test ! -e "$backup" && test ! -L "$backup"
test ! -e "$applied" && test ! -L "$applied"
test ! -e "$candidate" && test ! -L "$candidate"
{jdk_tool_function}
jar_tool="$(jdk_tool jar || true)"
test -n "$jar_tool"
command -v sha256sum >/dev/null 2>&1
actual_before="$(sha256sum -- "$jar_path" | awk '{{print $1}}')"
test "$actual_before" = {before_jar}
actual_source="$(sha256sum -- "$source" | awk '{{print $1}}')"
test "$actual_source" = {source_hash}
cp -a -- "$jar_path" "$backup"
backup_hash="$(sha256sum -- "$backup" | awk '{{print $1}}')"
test "$backup_hash" = "$actual_before"
cp -a -- "$jar_path" "$candidate"
mkdir -p -m 0700 -- {staged_parent}
cp -- "$source" {staged_entry}
(cd "$work" && "$jar_tool" uf "$candidate" "$entry")
# jar writes the updated archive as a new file under this umask and owner; the
# account the application runs as must still be able to read it, so it gets
# the original's owner and mode back, or nothing is swapped in. An ordinary
# login cannot give a file to another account; that is said, not guessed.
if ! chown -- "$(stat -c %u:%g -- "$jar_path")" "$candidate" \
  || ! chmod -- "$(stat -c %a -- "$jar_path")" "$candidate" \
  || ! test "$(stat -c '%u:%g %a' -- "$candidate")" = "$(stat -c '%u:%g %a' -- "$jar_path")"; then
  # Nothing was swapped in: the copy kept for a restore is not needed.
  rm -rf -- "$work"
  rm -f -- "$backup" "$source"
  rmdir -- "$root" 2>/dev/null || true
  printf '%s\n' '{OWNER_REFUSED_MARKER}'
  exit 3
fi
mkdir -m 0700 -- "$verify"
(cd "$verify" && "$jar_tool" xf "$candidate" "$entry")
test -f {verify_entry} && test ! -L {verify_entry}
entry_hash="$(sha256sum -- {verify_entry} | awk '{{print $1}}')"
test "$entry_hash" = "$actual_source"
mv -f -- "$candidate" "$jar_path"
committed=1
applied_hash="$(sha256sum -- "$jar_path" | awk '{{print $1}}')"
cp -a -- "$jar_path" "$applied"
test "$(sha256sum -- "$applied" | awk '{{print $1}}')" = "$applied_hash"
printf '%s\n' '{APPLY_MARKER}'
printf 'EVIDENCE\t%s\t%s\t%s\t%s\t%s\n' "$actual_before" {before_entry} "$actual_source" "$applied_hash" "$backup_hash"
trap - EXIT HUP INT TERM
rm -f -- "$candidate" "$rollback""#,
        jar = shq(plan.jar_path.as_str()),
        entry = shq(plan.entry_path.as_str()),
        root = shq(plan.remote_root.as_str()),
        source = shq(source.as_str()),
        backup = shq(backup.as_str()),
        applied = shq(applied.as_str()),
        candidate = shq(plan.candidate_path.as_str()),
        rollback = shq(rollback.as_str()),
        work = shq(work.as_str()),
        verify = shq(verify.as_str()),
        before_jar = shq(&plan.before_jar_sha256),
        source_hash = shq(plan.artifact.sha256()),
        staged_parent = shq(staged_entry_parent.as_str()),
        staged_entry = shq(staged_entry.as_str()),
        verify_entry = shq(verify_entry.as_str()),
        before_entry = shq(&plan.before_entry_sha256),
        jdk_tool_function = JDK_TOOL_FUNCTION,
    ))
}

fn verify_update_command(plan: &JavaJarUpdatePlan, receipt: &UpdateReceipt) -> CoreResult<String> {
    validate_update_paths(plan)?;
    validate_receipt(receipt)?;
    let backup = plan.remote_root.child("original.jar")?;
    let applied = plan.remote_root.child("applied.jar")?;
    let verify = plan.remote_root.child("verify-current")?;
    let verify_entry =
        RemotePath::new(format!("{}/{}", verify.as_str(), plan.entry_path.as_str()))?;
    Ok(format!(
        r#"set -eu
jar_path={jar}
entry={entry}
backup={backup}
applied={applied}
verify={verify}
test -f "$jar_path" && test ! -L "$jar_path"
test -f "$backup" && test ! -L "$backup"
test -f "$applied" && test ! -L "$applied"
test "$(sha256sum -- "$jar_path" | awk '{{print $1}}')" = {applied_hash}
test "$(sha256sum -- "$backup" | awk '{{print $1}}')" = {backup_hash}
test "$(sha256sum -- "$applied" | awk '{{print $1}}')" = {applied_hash}
test "$(stat -c '%u:%g %a' -- "$jar_path")" = "$(stat -c '%u:%g %a' -- "$backup")"
{jdk_tool_function}
jar_tool="$(jdk_tool jar || true)"
test -n "$jar_tool"
rm -r -- "$verify" 2>/dev/null || true
mkdir -m 0700 -- "$verify"
(cd "$verify" && "$jar_tool" xf "$jar_path" "$entry")
test -f {verify_entry} && test ! -L {verify_entry}
test "$(sha256sum -- {verify_entry} | awk '{{print $1}}')" = {source_hash}
printf '%s\n' '{VERIFY_MARKER}'
printf 'EVIDENCE\t%s\t%s\t%s\t%s\t%s\n' {before_jar} {before_entry} {source_hash} {applied_hash} {backup_hash}"#,
        jar = shq(plan.jar_path.as_str()),
        entry = shq(plan.entry_path.as_str()),
        backup = shq(backup.as_str()),
        applied = shq(applied.as_str()),
        verify = shq(verify.as_str()),
        verify_entry = shq(verify_entry.as_str()),
        before_jar = shq(&receipt.before_jar_sha256),
        before_entry = shq(&receipt.before_entry_sha256),
        source_hash = shq(&receipt.source_sha256),
        applied_hash = shq(&receipt.applied_jar_sha256),
        backup_hash = shq(&receipt.backup_sha256),
        jdk_tool_function = JDK_TOOL_FUNCTION,
    ))
}

fn restore_command_for_plan(
    plan: &JavaJarUpdatePlan,
    receipt: &UpdateReceipt,
) -> CoreResult<String> {
    validate_receipt_for_plan(receipt, plan)?;
    restore_command(
        &plan.jar_path,
        &plan.remote_root,
        &plan.update_id,
        &receipt.applied_jar_sha256,
        &receipt.before_jar_sha256,
        &receipt.backup_sha256,
        RESTORE_MARKER,
    )
}

fn restore_command_for_record(record: &JavaUpdateRecord) -> CoreResult<String> {
    validate_record(record)?;
    restore_command(
        &record.jar_path,
        &record.remote_root,
        &record.id,
        &record.applied_jar_sha256,
        &record.before_jar_sha256,
        &record.backup_sha256,
        RESTORE_MARKER,
    )
}

fn restore_command(
    jar_path: &RemotePath,
    remote_root: &RemotePath,
    update_id: &str,
    expected_current: &str,
    expected_original: &str,
    expected_backup: &str,
    marker: &str,
) -> CoreResult<String> {
    validate_uuid("Java update id", update_id)?;
    validate_sha256("current JAR hash", expected_current)?;
    validate_sha256("original JAR hash", expected_original)?;
    validate_sha256("backup JAR hash", expected_backup)?;
    let backup = remote_root.child("original.jar")?;
    let temporary = jar_path
        .parent()?
        .child(&format!(".lovelyres-java-{update_id}.restore"))?;
    Ok(format!(
        r#"set -eu
jar_path={jar}
backup={backup}
temporary={temporary}
test -f "$jar_path" && test ! -L "$jar_path"
test -f "$backup" && test ! -L "$backup"
test "$(sha256sum -- "$jar_path" | awk '{{print $1}}')" = {expected_current}
test "$(sha256sum -- "$backup" | awk '{{print $1}}')" = {expected_backup}
test ! -e "$temporary" && test ! -L "$temporary"
cp -a -- "$backup" "$temporary"
test "$(sha256sum -- "$temporary" | awk '{{print $1}}')" = {expected_original}
mv -f -- "$temporary" "$jar_path"
test "$(sha256sum -- "$jar_path" | awk '{{print $1}}')" = {expected_original}
printf '%s\n' {marker}"#,
        jar = shq(jar_path.as_str()),
        backup = shq(backup.as_str()),
        temporary = shq(temporary.as_str()),
        expected_current = shq(expected_current),
        expected_backup = shq(expected_backup),
        expected_original = shq(expected_original),
        marker = shq(marker),
    ))
}

fn verify_restored_command(record: &JavaUpdateRecord) -> CoreResult<String> {
    validate_record(record)?;
    let backup = record.remote_root.child("original.jar")?;
    Ok(format!(
        r#"set -eu
jar_path={jar}
backup={backup}
test -f "$jar_path" && test ! -L "$jar_path"
actual="$(sha256sum -- "$jar_path" | awk '{{print $1}}')"
test "$actual" = {expected}
test "$(stat -c '%u:%g %a' -- "$jar_path")" = "$(stat -c '%u:%g %a' -- "$backup")"
printf '%s\n' '{VERIFY_MARKER}'
printf 'RESTORED\t%s\n' "$actual""#,
        jar = shq(record.jar_path.as_str()),
        backup = shq(backup.as_str()),
        expected = shq(&record.before_jar_sha256),
    ))
}

fn reapply_command(record: &JavaUpdateRecord) -> CoreResult<String> {
    validate_record(record)?;
    let applied = record.remote_root.child("applied.jar")?;
    let temporary = record
        .jar_path
        .parent()?
        .child(&format!(".lovelyres-java-{}.reapply", record.id))?;
    Ok(format!(
        r#"set -eu
jar_path={jar}
applied={applied}
temporary={temporary}
test -f "$jar_path" && test ! -L "$jar_path"
test -f "$applied" && test ! -L "$applied"
test "$(sha256sum -- "$jar_path" | awk '{{print $1}}')" = {before}
test "$(sha256sum -- "$applied" | awk '{{print $1}}')" = {after}
test ! -e "$temporary" && test ! -L "$temporary"
cp -a -- "$applied" "$temporary"
mv -f -- "$temporary" "$jar_path"
test "$(sha256sum -- "$jar_path" | awk '{{print $1}}')" = {after}
printf '%s\n' '{REAPPLY_MARKER}'"#,
        jar = shq(record.jar_path.as_str()),
        applied = shq(applied.as_str()),
        temporary = shq(temporary.as_str()),
        before = shq(&record.before_jar_sha256),
        after = shq(&record.applied_jar_sha256),
    ))
}

struct ParsedEnvironment {
    version: Option<String>,
    tools: BTreeMap<JavaTool, bool>,
    processes: Vec<JavaProcess>,
}

/// A PID the open-file rows refer to; it must be one listed before them.
fn listed_pid(value: &str, pids: &BTreeSet<u32>) -> CoreResult<u32> {
    value
        .parse::<u32>()
        .ok()
        .filter(|pid| pids.contains(pid))
        .ok_or_else(|| CoreError::validation("Java open files", "unknown process"))
}

fn listed_process(processes: &mut [JavaProcess], pid: u32) -> CoreResult<&mut JavaProcess> {
    processes
        .iter_mut()
        .find(|process| process.pid == pid)
        .ok_or_else(|| CoreError::validation("Java open files", "unknown process"))
}

fn parse_environment(output: &str) -> CoreResult<ParsedEnvironment> {
    let mut version = None;
    let mut tools = BTreeMap::new();
    let mut processes = Vec::new();
    let mut pids = BTreeSet::new();
    let mut open_files_reported = BTreeSet::new();
    for line in output.lines() {
        if let Some(value) = line.strip_prefix("VERSION\t") {
            let value = bounded_remote_text("Java version", value, 256)?;
            if version.replace(value).is_some() {
                return Err(CoreError::validation(
                    "Java environment",
                    "duplicate version",
                ));
            }
        } else if let Some(value) = line.strip_prefix("TOOL\t") {
            let mut fields = value.split('\t');
            let tool = JavaTool::parse(fields.next().unwrap_or_default())?;
            let available = match fields.next() {
                Some("1") => true,
                Some("0") => false,
                _ => return Err(CoreError::validation("Java tool", "invalid availability")),
            };
            if fields.next().is_some() || tools.insert(tool, available).is_some() {
                return Err(CoreError::validation(
                    "Java tool",
                    "duplicate or extra field",
                ));
            }
        } else if let Some(value) = line.strip_prefix("PROC\t") {
            if processes.len() >= MAX_PROCESSES {
                return Err(CoreError::validation(
                    "Java processes",
                    "too many process rows",
                ));
            }
            let fields = value.splitn(6, '\t').collect::<Vec<_>>();
            if fields.len() != 6 {
                return Err(CoreError::validation("Java process", "invalid field count"));
            }
            let pid = fields[0]
                .parse::<u32>()
                .map_err(|_| CoreError::validation("Java PID", "must be an integer"))?;
            if pid <= 1 || !pids.insert(pid) {
                return Err(CoreError::validation(
                    "Java PID",
                    "must be unique and greater than one",
                ));
            }
            let user = bounded_remote_text("Java process user", fields[1], 128)?;
            let cpu_percent = parse_percent("Java process CPU", fields[2])?;
            let memory_percent = parse_percent("Java process memory", fields[3])?;
            let elapsed_seconds = fields[4]
                .parse::<u64>()
                .map_err(|_| CoreError::validation("Java process elapsed time", "invalid value"))?;
            let command = bounded_remote_text("Java process command", fields[5], 512)?;
            processes.push(JavaProcess {
                pid,
                user,
                cpu_percent,
                memory_percent,
                elapsed_seconds,
                command,
                open_jars: None,
                open_jars_incomplete: false,
            });
        } else if let Some(value) = line.strip_prefix("FDS\t") {
            let (pid, readable) = value
                .split_once('\t')
                .ok_or_else(|| CoreError::validation("Java open files", "invalid field count"))?;
            let pid = listed_pid(pid, &pids)?;
            if !open_files_reported.insert(pid) {
                return Err(CoreError::validation(
                    "Java open files",
                    "duplicate process",
                ));
            }
            let process = listed_process(&mut processes, pid)?;
            process.open_jars = match readable {
                "1" => Some(Vec::new()),
                "0" => None,
                _ => return Err(CoreError::validation("Java open files", "invalid state")),
            };
        } else if let Some(value) = line.strip_prefix("OPEN\t") {
            let (pid, path) = value
                .split_once('\t')
                .ok_or_else(|| CoreError::validation("Java open JAR", "invalid field count"))?;
            let process = listed_process(&mut processes, listed_pid(pid, &pids)?)?;
            let Some(open) = process.open_jars.as_mut() else {
                return Err(CoreError::validation(
                    "Java open JAR",
                    "listed for a process whose open files were not read",
                ));
            };
            if open.len() >= MAX_OPEN_JARS {
                return Err(CoreError::validation("Java open JAR", "too many rows"));
            }
            // A name that is not a plain absolute .jar path is left out and
            // the list is marked incomplete, rather than the whole scan failing.
            match RemotePath::new(path.to_owned()) {
                Ok(path) if validate_jar_path(&path).is_ok() && !open.contains(&path) => {
                    open.push(path)
                }
                _ => process.open_jars_incomplete = true,
            }
        } else if let Some(pid) = line.strip_prefix("OPENMORE\t") {
            let process = listed_process(&mut processes, listed_pid(pid, &pids)?)?;
            if process.open_jars.is_none() {
                return Err(CoreError::validation(
                    "Java open JAR",
                    "listed for a process whose open files were not read",
                ));
            }
            process.open_jars_incomplete = true;
        }
    }
    if !JavaTool::ALL
        .into_iter()
        .all(|tool| tools.contains_key(&tool))
    {
        return Err(CoreError::validation(
            "Java environment",
            "incomplete tool inventory",
        ));
    }
    Ok(ParsedEnvironment {
        version,
        tools,
        processes,
    })
}

fn parse_jar_inspection(output: &str) -> CoreResult<(u64, String, usize, Vec<JarEntryPath>)> {
    let mut metadata = None;
    let mut count = None;
    let mut entries = Vec::new();
    let mut unique = BTreeSet::new();
    for line in output.lines() {
        if let Some(value) = line.strip_prefix("META\t") {
            let fields = value.split('\t').collect::<Vec<_>>();
            if fields.len() != 2 || metadata.is_some() {
                return Err(CoreError::validation("JAR inspection", "invalid metadata"));
            }
            let size = fields[0]
                .parse::<u64>()
                .map_err(|_| CoreError::validation("JAR size", "invalid value"))?;
            validate_sha256("JAR SHA-256", fields[1])?;
            metadata = Some((size, fields[1].to_owned()));
        } else if let Some(value) = line.strip_prefix("CLASS\t") {
            if entries.len() >= MAX_CLASS_ENTRIES {
                return Err(CoreError::validation(
                    "JAR inspection",
                    "too many emitted entries",
                ));
            }
            let entry = JarEntryPath::new(value)?;
            if !unique.insert(entry.clone()) {
                return Err(CoreError::validation(
                    "JAR inspection",
                    "duplicate class entry",
                ));
            }
            entries.push(entry);
        } else if let Some(value) = line.strip_prefix("COUNT\t") {
            if count.is_some() {
                return Err(CoreError::validation(
                    "JAR inspection",
                    "duplicate class count",
                ));
            }
            count = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| CoreError::validation("JAR class count", "invalid value"))?,
            );
        }
    }
    let (size, sha256) =
        metadata.ok_or_else(|| CoreError::validation("JAR inspection", "missing metadata"))?;
    let count =
        count.ok_or_else(|| CoreError::validation("JAR inspection", "missing class count"))?;
    if count < entries.len() {
        return Err(CoreError::validation(
            "JAR inspection",
            "class count is smaller than emitted entries",
        ));
    }
    Ok((size, sha256, count, entries))
}

fn parse_entry_inspection(output: &str) -> CoreResult<(String, String)> {
    let evidence = output
        .lines()
        .find_map(|line| line.strip_prefix("ENTRY\t"))
        .ok_or_else(|| CoreError::validation("JAR entry inspection", "missing hash evidence"))?;
    let fields = evidence.split('\t').collect::<Vec<_>>();
    if fields.len() != 2 {
        return Err(CoreError::validation(
            "JAR entry inspection",
            "invalid hash field count",
        ));
    }
    validate_sha256("JAR SHA-256", fields[0])?;
    validate_sha256("JAR entry SHA-256", fields[1])?;
    Ok((fields[0].to_owned(), fields[1].to_owned()))
}

fn parse_update_receipt(output: &str) -> CoreResult<UpdateReceipt> {
    let evidence = output
        .lines()
        .find_map(|line| line.strip_prefix("EVIDENCE\t"))
        .ok_or_else(|| CoreError::validation("Java update receipt", "missing hash evidence"))?;
    let fields = evidence.split('\t').collect::<Vec<_>>();
    if fields.len() != 5 {
        return Err(CoreError::validation(
            "Java update receipt",
            "invalid hash field count",
        ));
    }
    let receipt = UpdateReceipt {
        before_jar_sha256: fields[0].to_owned(),
        before_entry_sha256: fields[1].to_owned(),
        source_sha256: fields[2].to_owned(),
        applied_jar_sha256: fields[3].to_owned(),
        backup_sha256: fields[4].to_owned(),
    };
    validate_receipt(&receipt)?;
    Ok(receipt)
}

fn parse_verify_receipt(output: &str) -> CoreResult<UpdateReceipt> {
    parse_update_receipt(output)
}

fn decode_receipt(receipt: &ExecutionReceipt) -> CoreResult<UpdateReceipt> {
    let receipt = serde_json::from_str::<UpdateReceipt>(
        receipt
            .restore_token
            .as_deref()
            .ok_or_else(|| CoreError::validation("Java update receipt", "missing evidence"))?,
    )
    .map_err(|source| CoreError::Decode {
        subject: "Java update receipt",
        source,
    })?;
    validate_receipt(&receipt)?;
    Ok(receipt)
}

fn inspect_staged_class(paths: &PathGuard, path: &Path) -> CoreResult<(u64, String)> {
    let path = paths.ensure_managed_upload_source(path)?;
    let metadata = fs::metadata(&path)
        .map_err(|source| CoreError::io("inspect staged Java class", &path, source))?;
    if !metadata.is_file() || metadata.len() < 8 || metadata.len() > MAX_CLASS_BYTES {
        return Err(CoreError::validation(
            "staged Java class",
            format!("must be an 8..={MAX_CLASS_BYTES} byte regular file"),
        ));
    }
    let mut file = fs::File::open(&path)
        .map_err(|source| CoreError::io("open staged Java class", &path, source))?;
    let mut digest = Sha256::new();
    let mut header = [0_u8; 4];
    file.read_exact(&mut header)
        .map_err(|source| CoreError::io("read staged Java class header", &path, source))?;
    if header != [0xCA, 0xFE, 0xBA, 0xBE] {
        return Err(CoreError::validation(
            "staged Java class",
            "missing CAFEBABE class-file magic",
        ));
    }
    digest.update(header);
    let copied = std::io::copy(&mut file, &mut digest)
        .map_err(|source| CoreError::io("hash staged Java class", &path, source))?;
    if copied + 4 != metadata.len() {
        return Err(CoreError::validation(
            "staged Java class",
            "file changed while it was being hashed",
        ));
    }
    Ok((metadata.len(), format!("{:x}", digest.finalize())))
}

fn parse_percent(subject: &'static str, value: &str) -> CoreResult<f32> {
    let value = value
        .parse::<f32>()
        .map_err(|_| CoreError::validation(subject, "invalid percentage"))?;
    if !value.is_finite() || !(0.0..=100_000.0).contains(&value) {
        return Err(CoreError::validation(
            subject,
            "percentage is outside bounds",
        ));
    }
    Ok(value)
}

fn bounded_remote_text(subject: &'static str, value: &str, maximum: usize) -> CoreResult<String> {
    if value.is_empty()
        || value.len() > maximum
        || value
            .chars()
            .any(|character| matches!(character, '\0' | '\r' | '\n' | '\t'))
    {
        return Err(CoreError::validation(subject, "invalid remote text"));
    }
    Ok(value.to_owned())
}

fn validate_jar_path(path: &RemotePath) -> CoreResult<()> {
    if !path.file_name()?.to_ascii_lowercase().ends_with(".jar") {
        return Err(CoreError::validation(
            "Java archive path",
            "must identify a .jar file",
        ));
    }
    Ok(())
}

fn entry_parent(entry: &JarEntryPath) -> &str {
    entry
        .as_str()
        .rsplit_once('/')
        .map_or("", |(parent, _)| parent)
}

/// The account a plan runs as, read with the JAR it is made for.
#[derive(Debug, Clone, PartialEq, Eq)]
struct JavaLogin {
    uid: u32,
    home: String,
}

fn parse_login(output: &str) -> CoreResult<JavaLogin> {
    let evidence = output
        .lines()
        .find_map(|line| line.strip_prefix("LOGIN\t"))
        .ok_or_else(|| CoreError::validation("Java login", "missing account evidence"))?;
    let (uid, home) = evidence
        .split_once('\t')
        .ok_or_else(|| CoreError::validation("Java login", "invalid account field count"))?;
    let uid = uid
        .parse::<u32>()
        .map_err(|_| CoreError::validation("Java login", "account id is not a number"))?;
    Ok(JavaLogin {
        uid,
        home: home.to_owned(),
    })
}

/// Where this login keeps the original JARs it replaces: root's shared
/// folder, or a folder in the account's own home. An account without a home
/// of its own has nowhere to keep them, so it replaces nothing.
fn backup_base(login: &JavaLogin) -> CoreResult<RemotePath> {
    if login.uid == 0 {
        return RemotePath::new(JAVA_ROOT);
    }
    let home = RemotePath::new(login.home.as_str()).map_err(|_| {
        CoreError::validation(
            "Java backup folder",
            "the login has no usable home folder to keep the original JAR in",
        )
    })?;
    if home.as_str() == "/" {
        return Err(CoreError::validation(
            "Java backup folder",
            "the login has no home folder of its own to keep the original JAR in",
        ));
    }
    home.child(JAVA_HOME_BACKUP_DIR)
}

fn remote_root_for(login: &JavaLogin, update_id: &str) -> CoreResult<RemotePath> {
    validate_uuid("Java update id", update_id)?;
    backup_base(login)?.child(update_id)
}

/// Whether a backup folder is one this module makes: this update's own
/// folder in root's shared folder or in a home folder's backup folder.
fn is_managed_remote_root(root: &RemotePath, update_id: &str) -> CoreResult<bool> {
    validate_uuid("Java update id", update_id)?;
    if root.file_name()? != update_id {
        return Ok(false);
    }
    let base = root.parent()?;
    Ok(base.as_str() == JAVA_ROOT
        || (base.file_name()? == JAVA_HOME_BACKUP_DIR && base.parent()?.as_str() != "/"))
}

fn candidate_path(jar_path: &RemotePath, update_id: &str) -> CoreResult<RemotePath> {
    validate_uuid("Java update id", update_id)?;
    jar_path
        .parent()?
        .child(&format!(".lovelyres-java-{update_id}.candidate"))
}

fn validate_update_paths(plan: &JavaJarUpdatePlan) -> CoreResult<()> {
    validate_uuid("Java update id", &plan.update_id)?;
    validate_jar_path(&plan.jar_path)?;
    if !is_managed_remote_root(&plan.remote_root, &plan.update_id)?
        || plan.candidate_path != candidate_path(&plan.jar_path, &plan.update_id)?
    {
        return Err(CoreError::validation(
            "Java update paths",
            "managed paths are not canonical",
        ));
    }
    Ok(())
}

fn validate_update_plan(session: &BoundSshSession, plan: &JavaJarUpdatePlan) -> CoreResult<()> {
    validate_update_paths(plan)?;
    if plan.operation.target != *session.target() {
        return Err(CoreError::validation(
            "Java update plan",
            "plan target does not match the bound SSH session",
        ));
    }
    if plan.operation.metadata.get("update_id") != Some(&plan.update_id)
        || plan.operation.metadata.get("jar_sha256") != Some(&plan.before_jar_sha256)
        || plan.operation.metadata.get("class_sha256") != Some(&plan.artifact.sha256)
    {
        return Err(CoreError::validation(
            "Java update plan",
            "immutable metadata does not match the typed plan",
        ));
    }
    validate_sha256("JAR SHA-256", &plan.before_jar_sha256)?;
    validate_sha256("JAR entry SHA-256", &plan.before_entry_sha256)?;
    validate_sha256("class SHA-256", &plan.artifact.sha256)
}

fn validate_restore_plan(session: &BoundSshSession, plan: &JavaRestorePlan) -> CoreResult<()> {
    validate_record(&plan.record)?;
    if plan.operation.target != *session.target()
        || plan.record.target != session.target().identity
        || plan.operation.metadata.get("record_id") != Some(&plan.record.id)
        || plan.operation.metadata.get("digest") != Some(&plan.record.digest)
        || plan.record.state != JavaUpdateState::Applied
    {
        return Err(CoreError::validation(
            "Java restore plan",
            "plan is stale or belongs to a different target/record",
        ));
    }
    Ok(())
}

fn validate_receipt(receipt: &UpdateReceipt) -> CoreResult<()> {
    validate_sha256("original JAR SHA-256", &receipt.before_jar_sha256)?;
    validate_sha256("original entry SHA-256", &receipt.before_entry_sha256)?;
    validate_sha256("source class SHA-256", &receipt.source_sha256)?;
    validate_sha256("applied JAR SHA-256", &receipt.applied_jar_sha256)?;
    validate_sha256("backup JAR SHA-256", &receipt.backup_sha256)?;
    if receipt.before_jar_sha256 != receipt.backup_sha256 {
        return Err(CoreError::validation(
            "Java update receipt",
            "backup hash differs from the planned original JAR",
        ));
    }
    Ok(())
}

fn validate_receipt_for_plan(receipt: &UpdateReceipt, plan: &JavaJarUpdatePlan) -> CoreResult<()> {
    validate_receipt(receipt)?;
    if receipt.before_jar_sha256 != plan.before_jar_sha256
        || receipt.before_entry_sha256 != plan.before_entry_sha256
        || receipt.source_sha256 != plan.artifact.sha256
    {
        return Err(CoreError::validation(
            "Java update receipt",
            "remote evidence differs from the immutable plan",
        ));
    }
    Ok(())
}

fn validate_record(record: &JavaUpdateRecord) -> CoreResult<()> {
    validate_uuid("Java update record id", &record.id)?;
    validate_uuid("Java update operation id", &record.operation_id)?;
    validate_uuid("Java update last operation id", &record.last_operation_id)?;
    validate_jar_path(&record.jar_path)?;
    if !is_managed_remote_root(&record.remote_root, &record.id)? {
        return Err(CoreError::validation(
            "Java update record",
            "remote root is outside the managed namespace",
        ));
    }
    let receipt = UpdateReceipt {
        before_jar_sha256: record.before_jar_sha256.clone(),
        before_entry_sha256: record.before_entry_sha256.clone(),
        source_sha256: record.source_sha256.clone(),
        applied_jar_sha256: record.applied_jar_sha256.clone(),
        backup_sha256: record.backup_sha256.clone(),
    };
    validate_receipt(&receipt)?;
    let digest = record_digest(
        &record.target,
        &record.id,
        &record.jar_path,
        &record.entry_path,
        &record.remote_root,
        &receipt,
    )?;
    if digest != record.digest {
        return Err(CoreError::validation(
            "Java update record",
            "record digest mismatch",
        ));
    }
    Ok(())
}

fn record_digest(
    target: &TargetIdentity,
    id: &str,
    jar_path: &RemotePath,
    entry_path: &JarEntryPath,
    remote_root: &RemotePath,
    receipt: &UpdateReceipt,
) -> CoreResult<String> {
    validate_uuid("Java update id", id)?;
    validate_receipt(receipt)?;
    let encoded = serde_json::to_vec(&(target, id, jar_path, entry_path, remote_root, receipt))
        .map_err(|source| CoreError::Encode {
            subject: "Java update record digest",
            source,
        })?;
    Ok(format!("{:x}", Sha256::digest(encoded)))
}

fn ensure_same_plan(
    actual: &OperationPlan,
    expected: &OperationPlan,
    subject: &'static str,
) -> CoreResult<()> {
    if actual.id != expected.id || actual.target != expected.target {
        return Err(CoreError::validation(
            subject,
            "executor received a different immutable plan",
        ));
    }
    Ok(())
}

fn validate_uuid(subject: &'static str, value: &str) -> CoreResult<Uuid> {
    Uuid::parse_str(value).map_err(|_| CoreError::validation(subject, "must be a canonical UUID"))
}

fn validate_sha256(subject: &'static str, value: &str) -> CoreResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CoreError::validation(
            subject,
            "must be lowercase SHA-256 hex",
        ));
    }
    Ok(())
}

fn successful_output(subject: &'static str, output: SshCommandOutput) -> CoreResult<String> {
    if output.timed_out || output.exit_code != Some(0) {
        return Err(CoreError::ssh(
            subject,
            format!(
                "remote command failed (exit {:?}, timed_out={}): {}",
                output.exit_code,
                output.timed_out,
                compact_output(&output.output)
            ),
        ));
    }
    Ok(output.output)
}

fn successful_marker(
    subject: &'static str,
    output: SshCommandOutput,
    marker: &str,
) -> CoreResult<String> {
    let output = successful_output(subject, output)?;
    if !output.lines().any(|line| line.trim() == marker) {
        return Err(CoreError::validation(subject, "missing completion marker"));
    }
    Ok(output)
}

fn compact_output(output: &str) -> String {
    let mut output = output.replace(['\r', '\n'], " ");
    if output.len() > 512 {
        let mut end = 512;
        while !output.is_char_boundary(end) {
            end -= 1;
        }
        output.truncate(end);
        output.push('…');
    }
    output
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, sync::Arc};

    use super::*;
    use crate::{
        BackendServices,
        ssh::{SshConnectionStatus, TestSessionHarness},
    };

    #[derive(Debug)]
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("lovelyres-java-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    async fn fixture() -> (
        TestRoot,
        BackendServices,
        BoundSshSession,
        Arc<TestSessionHarness>,
    ) {
        let temp = TestRoot::new();
        let store = PortableStore::prepare(temp.0.clone()).unwrap();
        let services = BackendServices::new(store).unwrap();
        let identity = TargetIdentity::new("java-target").unwrap();
        let guard = services.activate_target(identity.clone()).unwrap();
        let status = SshConnectionStatus {
            session_id: "java-session".to_owned(),
            connection_id: identity.as_str().to_owned(),
            host: "192.0.2.40".to_owned(),
            port: 22,
            username: "root".to_owned(),
            host_key_fingerprint: "SHA256:java".to_owned(),
            connected_at: Utc::now(),
        };
        let harness = Arc::new(TestSessionHarness::default());
        services
            .ssh()
            .install_test_session(status, harness.clone())
            .await
            .unwrap();
        let session = services
            .ssh()
            .bind_session(guard, "java-session")
            .await
            .unwrap();
        (temp, services, session, harness)
    }

    fn class_bytes(seed: u8) -> Vec<u8> {
        let mut bytes = vec![0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 61];
        bytes.extend(std::iter::repeat_n(seed, 32));
        bytes
    }

    fn write_selected(root: &TestRoot, name: &str, bytes: &[u8]) -> PathBuf {
        let path = root.0.join(name);
        fs::write(&path, bytes).unwrap();
        path
    }

    fn hash(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn entry_output(before_jar: &str, before_entry: &str) -> String {
        format!("{ENTRY_MARKER}\nENTRY\t{before_jar}\t{before_entry}\nLOGIN\t0\t/root\n")
    }

    fn root_login() -> JavaLogin {
        JavaLogin {
            uid: 0,
            home: "/root".to_owned(),
        }
    }

    #[test]
    fn an_ordinary_login_keeps_backups_in_its_own_home_and_root_in_the_shared_folder() {
        let id = Uuid::new_v4().to_string();
        let ops = JavaLogin {
            uid: 1000,
            home: "/home/ops".to_owned(),
        };
        assert_eq!(
            remote_root_for(&root_login(), &id).unwrap().as_str(),
            format!("{JAVA_ROOT}/{id}")
        );
        let own = remote_root_for(&ops, &id).unwrap();
        assert_eq!(
            own.as_str(),
            format!("/home/ops/{JAVA_HOME_BACKUP_DIR}/{id}")
        );
        assert!(is_managed_remote_root(&own, &id).unwrap());
        assert!(
            is_managed_remote_root(&remote_root_for(&root_login(), &id).unwrap(), &id).unwrap()
        );
        // An account without a home of its own replaces nothing.
        for home in [
            "/",
            "",
            "relative/home",
            "/home/../root",
            "/home/ops/",
            "/home/o\tps",
        ] {
            assert!(
                remote_root_for(
                    &JavaLogin {
                        uid: 1000,
                        home: home.to_owned()
                    },
                    &id
                )
                .is_err(),
                "{home:?}"
            );
        }
        // Only this update's own folder in one of the two places is managed.
        let other = Uuid::new_v4().to_string();
        for root in [
            format!("/tmp/{id}"),
            format!("/home/ops/other/{id}"),
            format!("/{JAVA_HOME_BACKUP_DIR}/{id}"),
            format!("/home/ops/{JAVA_HOME_BACKUP_DIR}/{other}"),
            format!("{JAVA_ROOT}/{other}"),
        ] {
            assert!(
                !is_managed_remote_root(&RemotePath::new(root.clone()).unwrap(), &id).unwrap(),
                "{root}"
            );
        }
        // The account is read with the JAR; nothing else stands in for it.
        assert_eq!(
            parse_login(&format!("{ENTRY_MARKER}\nLOGIN\t1000\t/home/ops\n")).unwrap(),
            ops
        );
        assert!(parse_login(&format!("{ENTRY_MARKER}\n")).is_err());
        assert!(parse_login("LOGIN\tops\t/home/ops\n").is_err());
        assert!(parse_login("LOGIN\t1000\n").is_err());
    }

    fn evidence_output(marker: &str, receipt: &UpdateReceipt) -> String {
        format!(
            "{marker}\nEVIDENCE\t{}\t{}\t{}\t{}\t{}\n",
            receipt.before_jar_sha256,
            receipt.before_entry_sha256,
            receipt.source_sha256,
            receipt.applied_jar_sha256,
            receipt.backup_sha256
        )
    }

    #[test]
    fn legacy_archive_contract_is_closed_and_traversal_safe() {
        assert!(JarEntryPath::new("../evil.class").is_err());
        assert!(JarEntryPath::new("/absolute/Evil.class").is_err());
        assert!(JarEntryPath::new("config/application.yml").is_err());
        assert!(JarEntryPath::new("com/example/App.class;id").is_err());
        assert_eq!(
            JarEntryPath::new("BOOT-INF/classes/com/example/App$Inner.class")
                .unwrap()
                .as_str(),
            "BOOT-INF/classes/com/example/App$Inner.class"
        );
        assert!(validate_jar_path(&RemotePath::new("/opt/app.bin").unwrap()).is_err());
        validate_jar_path(&RemotePath::new("/opt/app's/service.jar").unwrap()).unwrap();
    }

    #[test]
    fn staged_class_requires_magic_and_managed_identity() {
        let temp = TestRoot::new();
        let store = PortableStore::prepare(temp.0.clone()).unwrap();
        let services = BackendServices::new(store).unwrap();
        let paths = services.path_guard([]).unwrap();
        let invalid = write_selected(&temp, "invalid.class", b"not a class");
        assert!(services.java().stage_class_file(&paths, &invalid).is_err());

        let valid = write_selected(&temp, "valid.class", &class_bytes(7));
        let artifact = services.java().stage_class_file(&paths, &valid).unwrap();
        assert_eq!(artifact.bytes(), 40);
        validate_sha256("artifact", artifact.sha256()).unwrap();
        assert!(artifact.path.starts_with(paths.managed_upload_root()));
        let staged = artifact.path.clone();
        drop(artifact);
        assert!(!staged.exists());
    }

    #[test]
    fn parsers_reject_incomplete_or_hostile_remote_rows() {
        let mut environment = format!("{ENV_MARKER}\nVERSION\topenjdk 17.0.11\n");
        for tool in JavaTool::ALL {
            environment.push_str(&format!("TOOL\t{}\t1\n", tool.command()));
        }
        environment.push_str("PROC\t42\tapp\t1.5\t2.0\t60\tjava -jar /opt/app.jar\n");
        let parsed = parse_environment(&environment).unwrap();
        assert_eq!(parsed.processes[0].pid, 42);
        assert_eq!(parsed.tools.len(), JavaTool::ALL.len());
        assert!(parse_environment("PROC\t42\tapp\t1\t2\t3\tjava").is_err());
        assert_eq!(parsed.processes[0].open_jars, None);

        // The JARs a JVM holds open: listed ones are kept, a name that cannot
        // be used is left out and the list marked incomplete.
        let mut open = environment.clone();
        open.push_str("PROC\t43\ttomcat\t0.5\t9.0\t600\tjava -classpath /usr/local/tomcat/bin/bootstrap.jar org.apache.catalina.startup.Bootstrap start\n");
        open.push_str("FDS\t42\t0\nFDS\t43\t1\n");
        open.push_str("OPEN\t43\t/usr/local/tomcat/webapps/shop/WEB-INF/lib/shop-core.jar\n");
        open.push_str("OPEN\t43\t/usr/local/tomcat/lib/../evil.jar\n");
        let parsed = parse_environment(&open).unwrap();
        assert_eq!(parsed.processes[0].open_jars, None);
        let tomcat = &parsed.processes[1];
        assert_eq!(
            tomcat.open_jars.as_deref().unwrap(),
            [
                RemotePath::new("/usr/local/tomcat/webapps/shop/WEB-INF/lib/shop-core.jar")
                    .unwrap()
            ]
        );
        assert!(tomcat.open_jars_incomplete);
        let more = parse_environment(&format!("{open}OPENMORE\t43\n")).unwrap();
        assert!(more.processes[1].open_jars_incomplete);
        let complete = format!("{environment}FDS\t42\t1\nOPEN\t42\t/opt/app.jar\n");
        let parsed = parse_environment(&complete).unwrap();
        assert!(!parsed.processes[0].open_jars_incomplete);
        assert_eq!(
            parsed.processes[0].open_jars.as_ref().map(Vec::len),
            Some(1)
        );
        for hostile in [
            // A process never listed, one reported twice, open files of an unreadable one.
            format!("{environment}FDS\t99\t1\n"),
            format!("{environment}FDS\t42\t1\nFDS\t42\t1\n"),
            format!("{environment}FDS\t42\t0\nOPEN\t42\t/opt/app.jar\n"),
            format!("{environment}OPEN\t42\t/opt/app.jar\n"),
            format!("{environment}FDS\t42\t0\nOPENMORE\t42\n"),
            format!("{environment}FDS\t42\tyes\n"),
        ] {
            assert!(parse_environment(&hostile).is_err(), "{hostile}");
        }
        let mut flood = format!("{environment}FDS\t42\t1\n");
        for index in 0..=MAX_OPEN_JARS {
            flood.push_str(&format!("OPEN\t42\t/opt/lib/{index}.jar\n"));
        }
        assert!(parse_environment(&flood).is_err());

        let jar = format!(
            "{JAR_MARKER}\nMETA\t1024\t{}\nCLASS\tcom/example/App.class\nCOUNT\t1\n",
            hash(1)
        );
        let (_, _, count, entries) = parse_jar_inspection(&jar).unwrap();
        assert_eq!(count, 1);
        assert_eq!(entries[0].as_str(), "com/example/App.class");
        let hostile = format!(
            "{JAR_MARKER}\nMETA\t1024\t{}\nCLASS\t../evil.class\nCOUNT\t1\n",
            hash(1)
        );
        assert!(parse_jar_inspection(&hostile).is_err());
    }

    #[tokio::test]
    async fn environment_and_jar_reads_are_target_bound() {
        let (_temp, services, session, harness) = fixture().await;
        let mut environment = format!("{ENV_MARKER}\nVERSION\topenjdk 17\n");
        for tool in JavaTool::ALL {
            environment.push_str(&format!("TOOL\t{}\t1\n", tool.command()));
        }
        environment.push_str("PROC\t77\troot\t0.1\t1.2\t90\tjava -jar /opt/app.jar\n");
        harness.set_execute_output(environment);
        let scan = services.java().scan_environment(&session).await.unwrap();
        assert_eq!(scan.processes.len(), 1);

        harness.set_execute_output(format!(
            "{JAR_MARKER}\nMETA\t2048\t{}\nCLASS\tcom/example/App.class\nCOUNT\t1\n",
            hash(2)
        ));
        let inspection = services
            .java()
            .inspect_jar(&session, RemotePath::new("/opt/app.jar").unwrap())
            .await
            .unwrap();
        assert_eq!(inspection.class_count, 1);
        services
            .target()
            .activate(TargetIdentity::new("replacement").unwrap())
            .unwrap();
        assert!(services.java().scan_environment(&session).await.is_err());
    }

    #[tokio::test]
    async fn wrong_confirmation_has_zero_effect_then_update_is_verified_and_journaled() {
        let (temp, services, session, harness) = fixture().await;
        let paths = services.path_guard([]).unwrap();
        let selected_a = write_selected(&temp, "a.class", &class_bytes(1));
        let selected_b = write_selected(&temp, "b.class", &class_bytes(2));
        let artifact_a = services
            .java()
            .stage_class_file(&paths, &selected_a)
            .unwrap();
        let artifact_b = services
            .java()
            .stage_class_file(&paths, &selected_b)
            .unwrap();
        let before_jar = hash(0x11);
        let before_entry = hash(0x22);
        harness.set_execute_outputs([
            entry_output(&before_jar, &before_entry),
            entry_output(&before_jar, &before_entry),
        ]);
        let first = services
            .java()
            .plan_jar_update(
                &session,
                &paths,
                RemotePath::new("/opt/app.jar").unwrap(),
                JarEntryPath::new("com/example/App.class").unwrap(),
                artifact_a,
            )
            .await
            .unwrap();
        let second = services
            .java()
            .plan_jar_update(
                &session,
                &paths,
                RemotePath::new("/opt/app.jar").unwrap(),
                JarEntryPath::new("com/example/App.class").unwrap(),
                artifact_b,
            )
            .await
            .unwrap();
        let wrong = DangerousConfirmation::approve(first.definition());
        let error = services
            .java()
            .execute_jar_update(&session, second, wrong)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("different operation"));
        assert!(
            services
                .java()
                .list_history(session.target())
                .unwrap()
                .is_empty()
        );

        let selected = write_selected(&temp, "apply.class", &class_bytes(3));
        let artifact = services.java().stage_class_file(&paths, &selected).unwrap();
        let source_sha = artifact.sha256().to_owned();
        harness.set_execute_output(entry_output(&before_jar, &before_entry));
        let plan = services
            .java()
            .plan_jar_update(
                &session,
                &paths,
                RemotePath::new("/opt/app.jar").unwrap(),
                JarEntryPath::new("com/example/App.class").unwrap(),
                artifact,
            )
            .await
            .unwrap();
        let operation_id = plan.definition().id.clone();
        let confirmation = DangerousConfirmation::approve(plan.definition());
        let receipt = UpdateReceipt {
            before_jar_sha256: before_jar.clone(),
            before_entry_sha256: before_entry,
            source_sha256: source_sha,
            applied_jar_sha256: hash(0x33),
            backup_sha256: before_jar,
        };
        harness.set_execute_output("");
        harness.set_execute_outputs([
            format!("{STAGE_MARKER}\n"),
            evidence_output(APPLY_MARKER, &receipt),
            evidence_output(VERIFY_MARKER, &receipt),
        ]);
        harness.set_sftp_immediate(true);
        let outcome = services
            .java()
            .execute_jar_update(&session, plan, confirmation)
            .await
            .unwrap();
        assert_eq!(outcome.record.state, JavaUpdateState::Applied);
        assert!(outcome.verification.passed);
        assert!(
            services
                .operation_journal()
                .entries()
                .unwrap()
                .iter()
                .any(|entry| entry.operation_id == operation_id)
        );
    }

    #[tokio::test]
    async fn a_jar_another_account_owns_is_not_swapped_in_and_says_why() {
        let (temp, services, session, harness) = fixture().await;
        let paths = services.path_guard([]).unwrap();
        let selected = write_selected(&temp, "owner.class", &class_bytes(5));
        let artifact = services.java().stage_class_file(&paths, &selected).unwrap();
        harness.set_execute_output(entry_output(&hash(0x71), &hash(0x72)));
        let plan = services
            .java()
            .plan_jar_update(
                &session,
                &paths,
                RemotePath::new("/home/ops/shared/other.jar").unwrap(),
                JarEntryPath::new("lh/probe/Probe.class").unwrap(),
                artifact,
            )
            .await
            .unwrap();
        let root = plan.remote_root.clone();
        let confirmation = DangerousConfirmation::approve(plan.definition());
        harness.set_execute_output("");
        harness.set_execute_outputs([
            format!("{STAGE_MARKER}\n"),
            format!("chown: changing ownership: Operation not permitted\n{OWNER_REFUSED_MARKER}\n"),
        ]);
        harness.set_sftp_immediate(true);
        let error = services
            .java()
            .execute_jar_update(&session, plan, confirmation)
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                CoreError::Validation {
                    subject: "Java JAR owner",
                    ..
                }
            ),
            "{error}"
        );
        // No record: there is nothing to restore.
        assert!(
            services
                .java()
                .list_history(session.target())
                .unwrap()
                .is_empty()
        );
        // The refusal comes before the swap, and lets go of the backup by
        // its exact paths, never the managed folder recursively.
        let commands = harness.execute_commands();
        let apply = commands
            .iter()
            .find(|command| command.contains(OWNER_REFUSED_MARKER))
            .unwrap();
        let refused = apply.find(OWNER_REFUSED_MARKER).unwrap();
        let refusal = &apply[apply.find("if ! chown").unwrap()..refused];
        assert!(refused < apply.find("mv -f -- \"$candidate\" \"$jar_path\"").unwrap());
        assert!(refusal.contains("rm -f -- \"$backup\" \"$source\""));
        assert!(!refusal.contains("rm -rf -- \"$root\""));
        assert!(
            commands
                .iter()
                .any(|command| command.starts_with("rm -f -- ") && command.contains(root.as_str()))
        );
    }

    #[tokio::test]
    async fn history_restore_is_a_second_exact_operation() {
        let (temp, services, session, harness) = fixture().await;
        let paths = services.path_guard([]).unwrap();
        let selected = write_selected(&temp, "restore.class", &class_bytes(4));
        let artifact = services.java().stage_class_file(&paths, &selected).unwrap();
        let receipt = UpdateReceipt {
            before_jar_sha256: hash(0x41),
            before_entry_sha256: hash(0x42),
            source_sha256: artifact.sha256().to_owned(),
            applied_jar_sha256: hash(0x43),
            backup_sha256: hash(0x41),
        };
        harness.set_execute_output(entry_output(
            &receipt.before_jar_sha256,
            &receipt.before_entry_sha256,
        ));
        let update = services
            .java()
            .plan_jar_update(
                &session,
                &paths,
                RemotePath::new("/srv/service.jar").unwrap(),
                JarEntryPath::new("WEB-INF/classes/app/Main.class").unwrap(),
                artifact,
            )
            .await
            .unwrap();
        harness.set_execute_output("");
        harness.set_execute_outputs([
            format!("{STAGE_MARKER}\n"),
            evidence_output(APPLY_MARKER, &receipt),
            evidence_output(VERIFY_MARKER, &receipt),
        ]);
        harness.set_sftp_immediate(true);
        let confirmation = DangerousConfirmation::approve(update.definition());
        let applied = services
            .java()
            .execute_jar_update(&session, update, confirmation)
            .await
            .unwrap();

        let restore = services
            .java()
            .plan_restore(&session, &applied.record.id)
            .unwrap();
        harness.set_execute_outputs([
            format!("{RESTORE_MARKER}\n"),
            format!("{VERIFY_MARKER}\nRESTORED\t{}\n", receipt.before_jar_sha256),
        ]);
        let confirmation = DangerousConfirmation::approve(restore.definition());
        let restored = services
            .java()
            .execute_restore(&session, restore, confirmation)
            .await
            .unwrap();
        assert_eq!(restored.record.state, JavaUpdateState::Restored);
        assert!(restored.verification.passed);
    }

    #[test]
    fn tampered_history_cannot_reach_restore_builder() {
        let id = Uuid::new_v4().to_string();
        let target = TargetIdentity::new("target").unwrap();
        let jar = RemotePath::new("/opt/app.jar").unwrap();
        let entry = JarEntryPath::new("com/example/App.class").unwrap();
        let root = remote_root_for(&root_login(), &id).unwrap();
        let receipt = UpdateReceipt {
            before_jar_sha256: hash(0x51),
            before_entry_sha256: hash(0x52),
            source_sha256: hash(0x53),
            applied_jar_sha256: hash(0x54),
            backup_sha256: hash(0x51),
        };
        let mut record = JavaUpdateRecord {
            id: id.clone(),
            operation_id: Uuid::new_v4().to_string(),
            last_operation_id: Uuid::new_v4().to_string(),
            target: target.clone(),
            jar_path: jar.clone(),
            entry_path: entry.clone(),
            remote_root: root.clone(),
            before_jar_sha256: receipt.before_jar_sha256.clone(),
            before_entry_sha256: receipt.before_entry_sha256.clone(),
            source_sha256: receipt.source_sha256.clone(),
            applied_jar_sha256: receipt.applied_jar_sha256.clone(),
            backup_sha256: receipt.backup_sha256.clone(),
            digest: record_digest(&target, &id, &jar, &entry, &root, &receipt).unwrap(),
            state: JavaUpdateState::Applied,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert!(restore_command_for_record(&record).is_ok());
        record.remote_root = RemotePath::new("/tmp/attacker").unwrap();
        assert!(restore_command_for_record(&record).is_err());
        record.remote_root = root;
        record.backup_sha256 = format!("{};id", hash(0x51));
        assert!(restore_command_for_record(&record).is_err());
    }

    #[test]
    fn command_builders_quote_remote_paths_and_use_managed_namespaces() {
        let temp = TestRoot::new();
        let target = TargetGuard {
            identity: TargetIdentity::new("target").unwrap(),
            generation: 1,
        };
        let paths = PathGuard::new(temp.0.join("staging"), []).unwrap();
        let staged = paths.stage_upload(&class_bytes(9)).unwrap();
        let (bytes, sha256) = inspect_staged_class(&paths, &staged).unwrap();
        let id = Uuid::new_v4().to_string();
        let jar_path = RemotePath::new("/opt/app's/service.jar").unwrap();
        let entry_path = JarEntryPath::new("BOOT-INF/classes/app/Main.class").unwrap();
        let mut operation =
            OperationPlan::new(target, "test", true, Some("restore".to_owned())).unwrap();
        operation
            .metadata
            .insert("update_id".to_owned(), id.clone());
        operation
            .metadata
            .insert("jar_sha256".to_owned(), hash(0x61));
        operation
            .metadata
            .insert("class_sha256".to_owned(), sha256.clone());
        let mut plan = JavaJarUpdatePlan {
            operation,
            update_id: id.clone(),
            jar_path: jar_path.clone(),
            entry_path,
            remote_root: remote_root_for(&root_login(), &id).unwrap(),
            candidate_path: candidate_path(&jar_path, &id).unwrap(),
            paths,
            artifact: StagedClassArtifact {
                path: staged,
                bytes,
                sha256,
            },
            before_jar_sha256: hash(0x61),
            before_entry_sha256: hash(0x62),
        };
        // Root stages under its shared folder; an ordinary login under its own
        // home, never under the folder only root can create.
        assert!(
            prepare_remote_stage_command(&plan)
                .unwrap()
                .contains(&format!("base='{JAVA_ROOT}'"))
        );
        let own_root = remote_root_for(
            &JavaLogin {
                uid: 1000,
                home: "/home/ops".to_owned(),
            },
            &id,
        )
        .unwrap();
        let shared_root = std::mem::replace(&mut plan.remote_root, own_root);
        let own_stage = prepare_remote_stage_command(&plan).unwrap();
        assert!(own_stage.contains(&format!("base='/home/ops/{JAVA_HOME_BACKUP_DIR}'")));
        assert!(!own_stage.contains(JAVA_ROOT));
        assert!(apply_update_command(&plan).is_ok());
        plan.remote_root = shared_root;
        let command = apply_update_command(&plan).unwrap();
        assert!(command.contains("'/opt/app'\\''s/service.jar'"));
        assert!(command.contains(JAVA_ROOT));
        assert!(command.contains("\"$jar_tool\" uf \"$candidate\" \"$entry\""));
        // jar writes a fresh file: the original owner and mode go back on it
        // before the swap, and the swap does not happen if they cannot.
        let rewrite = command.find("\"$jar_tool\" uf").unwrap();
        let owner = command
            .find("chown -- \"$(stat -c %u:%g -- \"$jar_path\")\" \"$candidate\"")
            .unwrap();
        let mode = command
            .find("chmod -- \"$(stat -c %a -- \"$jar_path\")\" \"$candidate\"")
            .unwrap();
        let checked = command
            .find("test \"$(stat -c '%u:%g %a' -- \"$candidate\")\" = \"$(stat -c '%u:%g %a' -- \"$jar_path\")\"")
            .unwrap();
        let swap = command
            .find("mv -f -- \"$candidate\" \"$jar_path\"")
            .unwrap();
        assert!(rewrite < owner && owner < mode && mode < checked && checked < swap);
        assert!(!command.contains("curl"));
        assert!(!command.contains("wget"));

        // Every command that runs jar finds it the same way, and never runs a
        // bare `jar` from whatever PATH happens to be.
        let receipt = UpdateReceipt {
            before_jar_sha256: hash(0x61),
            before_entry_sha256: hash(0x62),
            source_sha256: plan.artifact.sha256().to_owned(),
            applied_jar_sha256: hash(0x63),
            backup_sha256: hash(0x61),
        };
        // The independent read-back compares owner and mode with the backup too.
        assert!(verify_update_command(&plan, &receipt)
            .unwrap()
            .contains("test \"$(stat -c '%u:%g %a' -- \"$jar_path\")\" = \"$(stat -c '%u:%g %a' -- \"$backup\")\""));
        for command in [
            inspect_jar_command(&jar_path),
            inspect_entry_command(&plan.jar_path, &plan.entry_path),
            command,
            verify_update_command(&plan, &receipt).unwrap(),
        ] {
            assert!(command.contains(JDK_TOOL_FUNCTION));
            assert!(
                command.contains("jar_tool=\"$(jdk_tool jar || true)\"\ntest -n \"$jar_tool\"")
            );
            assert!(!command.contains("&& jar ") && !command.contains("\njar "));
        }
        let environment = environment_command();
        assert!(environment.contains(JDK_TOOL_FUNCTION));
        assert!(environment.contains("ps -eo stat=,pid=,"));
        assert!(environment.contains("$1 !~ /^Z/ && ($7 == \"java\""));
        assert!(!environment.contains("defunct"));
    }

    #[test]
    fn jdk_tools_off_path_come_only_from_a_jdk_no_one_else_can_write() {
        let function = JDK_TOOL_FUNCTION;
        // PATH first, then the binary the kernel says a running JVM is, never its command line.
        assert!(
            function.find("command -v \"$1\"").unwrap() < function.find("/proc/$pid/exe").unwrap()
        );
        assert!(!function.contains("cmdline") && !function.contains("args="));
        // A deleted or renamed binary ("... (deleted)") does not match.
        assert!(function.contains(r"s#^\(/..*\)/bin/java$#\1#p"));
        // The tool, its bin directory and the JDK home are each checked for owner and mode.
        assert!(function.contains("for item in \"$tool\" \"$home/bin\" \"$home\"; do"));
        assert!(function.contains("case \"$owner\" in 0|\"$me\") ;; *) trusted=0 ;; esac"));
        assert!(function.contains("case \"$mode\" in ?????w*|????????w*) trusted=0 ;; esac"));
        assert!(function.contains("test ! -L \"$tool\""));
        // An unreadable owner or mode is a refusal, not a pass.
        assert_eq!(function.matches("|| { trusted=0; break; }").count(), 2);
    }

    #[test]
    fn java_history_has_a_dedicated_portable_file() {
        assert_eq!(StoreFile::Java.file_name(), "java-history.json");
    }
}
