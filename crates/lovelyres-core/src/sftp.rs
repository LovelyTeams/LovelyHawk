//! Typed SFTP surface and destructive-operation lifecycle.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::operations::{
    DangerousConfirmation, ExecutionReceipt, OperationExecutor, OperationPlan, OperationState,
    PlannedOperation, PortableOperationJournal, VerificationResult,
};
use crate::path_guard::PathGuard;
use crate::shell_escape::shq;
#[cfg(test)]
use crate::ssh::SshConnectionStatus;
use crate::ssh::{
    BoundSshSession, SftpAtomicWriteReceipt, SftpRawEntry, SftpRawMetadata, SftpRequest,
    SftpResponse, SshService,
};
use crate::target::{TargetContext, TargetGuard};
use crate::{CoreError, CoreResult};

pub const MAX_EDIT_BYTES: u64 = 2 * 1024 * 1024;
pub const MAX_TRANSFER_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub const MAX_DIRECTORY_ENTRIES: usize = 50_000;
pub const MAX_DIRECTORY_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
const MAX_ARCHIVE_MANIFEST_BYTES: usize = 8 * 1024 * 1024;
const EXTRACT_RECEIPT_NAME: &str = ".lovelyres-extract-receipt";
const EXTRACT_SOURCE_NAME: &str = ".lovelyres-extract-source";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RemotePath(String);

impl RemotePath {
    pub fn new(value: impl Into<String>) -> CoreResult<Self> {
        let value = value.into();
        if !value.starts_with('/') {
            return Err(CoreError::validation(
                "remote path",
                "must be an absolute POSIX path",
            ));
        }
        if value.len() > 4096
            || value.contains('\\')
            || value.chars().any(char::is_control)
            || (value.len() > 1 && value.ends_with('/'))
        {
            return Err(CoreError::validation(
                "remote path",
                "must be at most 4096 bytes with no controls, backslashes, or trailing slash",
            ));
        }
        if value != "/"
            && value[1..]
                .split('/')
                .any(|component| component.is_empty() || matches!(component, "." | ".."))
        {
            return Err(CoreError::validation(
                "remote path",
                "must not contain empty, current-directory, or parent-directory components",
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn parent(&self) -> CoreResult<Self> {
        let split = self.0.rfind('/').ok_or_else(|| {
            CoreError::validation("remote path", "absolute path has no parent separator")
        })?;
        if split == 0 {
            Self::new("/")
        } else {
            Self::new(self.0[..split].to_owned())
        }
    }

    pub fn file_name(&self) -> CoreResult<&str> {
        let name = self.0.rsplit('/').next().unwrap_or_default();
        if name.is_empty() {
            return Err(CoreError::validation(
                "remote path",
                "root cannot be used for this operation",
            ));
        }
        Ok(name)
    }

    pub fn child(&self, name: &str) -> CoreResult<Self> {
        if name.is_empty() || name.contains('/') || name.chars().any(char::is_control) {
            return Err(CoreError::validation(
                "remote child name",
                "must be one non-empty path component",
            ));
        }
        if self.0 == "/" {
            Self::new(format!("/{name}"))
        } else {
            Self::new(format!("{}/{name}", self.0))
        }
    }

    fn backup_location(&self) -> CoreResult<(Self, Self)> {
        let parent = self.parent()?;
        let namespace = parent.child(".lovelyres-backups")?;
        let backup = namespace.child(&format!("{}-{}", Uuid::new_v4(), self.file_name()?))?;
        Ok((namespace, backup))
    }
}

impl TryFrom<String> for RemotePath {
    type Error = CoreError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<RemotePath> for String {
    fn from(value: RemotePath) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SftpFileKind {
    File,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SftpMetadata {
    pub size: u64,
    pub permissions: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub modified_at: Option<DateTime<Utc>>,
    pub kind: SftpFileKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SftpEntry {
    pub name: String,
    pub path: RemotePath,
    pub metadata: SftpMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SftpLocation {
    pub target: TargetGuard,
    pub path: RemotePath,
}

impl SftpLocation {
    pub fn new(target: TargetGuard, path: RemotePath) -> Self {
        Self { target, path }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SftpTransferReceipt {
    pub remote_path: RemotePath,
    pub local_path: Option<PathBuf>,
    pub bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArchiveFormat {
    Tar,
    TarGzip,
    TarZstd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArchiveExtractionFormat {
    Zip,
    Tar,
    TarGzip,
    TarBzip2,
    TarZstd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ArchiveEntryKind {
    File,
    Directory,
}

#[derive(Clone, Debug)]
struct ArchiveExtractionPlan {
    archive: RemotePath,
    destination: RemotePath,
    format: ArchiveExtractionFormat,
    archive_size: u64,
    archive_sha256: String,
    manifest_sha256: String,
    entry_count: usize,
    receipt_token: String,
}

#[derive(Clone)]
pub enum SftpMutation {
    CreateFile {
        path: RemotePath,
        content: Vec<u8>,
        mode: Option<u32>,
    },
    CreateDirectory {
        path: RemotePath,
    },
    AtomicWrite {
        path: RemotePath,
        content: Vec<u8>,
    },
    AtomicWriteIfMatch {
        path: RemotePath,
        expected_sha256: String,
        expected_canonical_path: Option<RemotePath>,
        backup_directory: Option<RemotePath>,
        content: Vec<u8>,
    },
    Rename {
        from: RemotePath,
        to: RemotePath,
    },
    Chmod {
        path: RemotePath,
        mode: u32,
    },
    ChmodIfMode {
        path: RemotePath,
        expected_mode: u32,
        mode: u32,
    },
    Remove {
        path: RemotePath,
    },
    RemoveFileIfMatch {
        path: RemotePath,
        expected_sha256: String,
    },
    CreateArchive {
        sources: Vec<RemotePath>,
        destination: RemotePath,
        format: ArchiveFormat,
    },
}

impl fmt::Debug for SftpMutation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CreateFile {
                path,
                content,
                mode,
            } => formatter
                .debug_struct("CreateFile")
                .field("path", path)
                .field("content_bytes", &content.len())
                .field("mode", mode)
                .finish(),
            Self::CreateDirectory { path } => formatter
                .debug_tuple("CreateDirectory")
                .field(path)
                .finish(),
            Self::AtomicWrite { path, content } => formatter
                .debug_struct("AtomicWrite")
                .field("path", path)
                .field("content_bytes", &content.len())
                .finish(),
            Self::AtomicWriteIfMatch {
                path,
                expected_sha256,
                expected_canonical_path,
                backup_directory,
                content,
            } => formatter
                .debug_struct("AtomicWriteIfMatch")
                .field("path", path)
                .field("expected_sha256", expected_sha256)
                .field("expected_canonical_path", expected_canonical_path)
                .field("backup_directory", backup_directory)
                .field("content_bytes", &content.len())
                .finish(),
            Self::Rename { from, to } => formatter
                .debug_struct("Rename")
                .field("from", from)
                .field("to", to)
                .finish(),
            Self::Chmod { path, mode } => formatter
                .debug_struct("Chmod")
                .field("path", path)
                .field("mode", &format_args!("{mode:o}"))
                .finish(),
            Self::ChmodIfMode {
                path,
                expected_mode,
                mode,
            } => formatter
                .debug_struct("ChmodIfMode")
                .field("path", path)
                .field("expected_mode", &format_args!("{expected_mode:o}"))
                .field("mode", &format_args!("{mode:o}"))
                .finish(),
            Self::Remove { path } => formatter.debug_tuple("Remove").field(path).finish(),
            Self::RemoveFileIfMatch {
                path,
                expected_sha256,
            } => formatter
                .debug_struct("RemoveFileIfMatch")
                .field("path", path)
                .field("expected_sha256", expected_sha256)
                .finish(),
            Self::CreateArchive {
                sources,
                destination,
                format,
            } => formatter
                .debug_struct("CreateArchive")
                .field("sources", sources)
                .field("destination", destination)
                .field("format", format)
                .finish(),
        }
    }
}

#[derive(Clone)]
enum SftpOperation {
    Mutation(SftpMutation),
    ExtractArchive(ArchiveExtractionPlan),
    UploadStaged {
        paths: PathGuard,
        staged_path: PathBuf,
        remote_path: RemotePath,
        expected_bytes: u64,
    },
}

impl fmt::Debug for SftpOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mutation(mutation) => mutation.fmt(formatter),
            Self::ExtractArchive(plan) => plan.fmt(formatter),
            Self::UploadStaged {
                remote_path,
                expected_bytes,
                ..
            } => formatter
                .debug_struct("UploadStaged")
                .field("remote_path", remote_path)
                .field("expected_bytes", expected_bytes)
                .finish_non_exhaustive(),
        }
    }
}

/// Session token created from actor-owned SSH state and one active target epoch.
/// Private fields prevent callers from pairing a guard for host A with host B's
/// raw session id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundSftpSession {
    ssh: BoundSshSession,
}

impl BoundSftpSession {
    #[cfg(test)]
    fn from_status(target: TargetGuard, status: &SshConnectionStatus) -> CoreResult<Self> {
        Ok(Self {
            ssh: BoundSshSession::from_status(target, status, "SFTP session binding")?,
        })
    }

    fn from_ssh(ssh: BoundSshSession) -> Self {
        Self { ssh }
    }

    pub fn session_id(&self) -> &str {
        self.ssh.session_id()
    }

    pub fn connection_id(&self) -> &str {
        self.ssh.connection_id()
    }

    pub fn target(&self) -> &TargetGuard {
        self.ssh.target()
    }
}

#[derive(Debug, Clone)]
pub struct SftpService {
    ssh: SshService,
    target: Arc<TargetContext>,
    journal: PortableOperationJournal,
}

impl SftpService {
    pub fn new(
        ssh: SshService,
        target: Arc<TargetContext>,
        journal: PortableOperationJournal,
    ) -> Self {
        Self {
            ssh,
            target,
            journal,
        }
    }

    pub async fn bind_session(
        &self,
        target: TargetGuard,
        session_id: &str,
    ) -> CoreResult<BoundSftpSession> {
        self.target.validate(&target)?;
        let session =
            BoundSftpSession::from_ssh(self.ssh.bind_session(target.clone(), session_id).await?);
        self.target.validate(&target)?;
        Ok(session)
    }

    pub async fn list(
        &self,
        session: &BoundSftpSession,
        path: &RemotePath,
    ) -> CoreResult<Vec<SftpEntry>> {
        match self
            .request(
                session,
                SftpRequest::List {
                    path: path.as_str().to_owned(),
                    maximum_entries: MAX_DIRECTORY_ENTRIES,
                },
            )
            .await?
        {
            SftpResponse::Entries(entries) => {
                let output_bytes = entries.iter().try_fold(0_usize, |total, entry| {
                    total
                        .checked_add(entry.name.len())
                        .and_then(|total| total.checked_add(entry.path.len()))
                        .and_then(|total| total.checked_add(64))
                        .ok_or_else(|| {
                            CoreError::validation(
                                "SFTP directory output",
                                "size accounting overflowed",
                            )
                        })
                })?;
                if output_bytes > MAX_DIRECTORY_OUTPUT_BYTES {
                    return Err(CoreError::validation(
                        "SFTP directory output",
                        format!("exceeds the {MAX_DIRECTORY_OUTPUT_BYTES}-byte limit"),
                    ));
                }
                entries
                    .into_iter()
                    .map(|entry| convert_entry(path, entry))
                    .collect()
            }
            response => Err(unexpected_response("list", response)),
        }
    }

    /// Resolve a remote path through the SFTP server's REALPATH operation.
    /// Security-sensitive callers compare this value again immediately before
    /// mutation so ancestor symlink changes cannot silently widen a managed root.
    pub async fn canonicalize(
        &self,
        session: &BoundSftpSession,
        path: &RemotePath,
    ) -> CoreResult<RemotePath> {
        match self
            .request(
                session,
                SftpRequest::Canonicalize {
                    path: path.as_str().to_owned(),
                },
            )
            .await?
        {
            SftpResponse::Path(path) => RemotePath::new(path),
            response => Err(unexpected_response("canonicalize", response)),
        }
    }

    pub async fn metadata(
        &self,
        session: &BoundSftpSession,
        path: &RemotePath,
        follow_symlink: bool,
    ) -> CoreResult<SftpMetadata> {
        self.metadata_raw(session, path, follow_symlink)
            .await
            .map(convert_metadata)
    }

    pub async fn open_directory_terminal(
        &self,
        session: &BoundSftpSession,
        directory: &RemotePath,
        terminal_id: String,
        columns: u16,
        rows: u16,
    ) -> CoreResult<crate::ssh::SshTerminalSession> {
        let metadata = self.metadata(session, directory, false).await?;
        if metadata.kind != SftpFileKind::Directory {
            return Err(CoreError::validation(
                "SFTP directory terminal",
                "the selected remote path is not a directory",
            ));
        }
        self.target.validate(session.target())?;
        let terminal = self
            .ssh
            .open_directory_terminal_bound(
                &session.ssh,
                terminal_id,
                directory.clone(),
                columns,
                rows,
            )
            .await?;
        if let Err(error) = self.target.validate(session.target()) {
            let _ = crate::events::TerminalTransport::close(&terminal).await;
            return Err(error);
        }
        Ok(terminal)
    }

    pub async fn read_file(
        &self,
        session: &BoundSftpSession,
        path: &RemotePath,
    ) -> CoreResult<Vec<u8>> {
        match self
            .request(
                session,
                SftpRequest::Read {
                    path: path.as_str().to_owned(),
                    maximum_bytes: MAX_EDIT_BYTES,
                },
            )
            .await?
        {
            SftpResponse::Bytes(bytes) => Ok(bytes),
            response => Err(unexpected_response("read", response)),
        }
    }

    pub async fn read_text(
        &self,
        session: &BoundSftpSession,
        path: &RemotePath,
    ) -> CoreResult<String> {
        String::from_utf8(self.read_file(session, path).await?).map_err(|error| {
            CoreError::validation(
                "SFTP editor file",
                format!("must be valid UTF-8 text: {error}"),
            )
        })
    }

    pub async fn download_new(
        &self,
        session: &BoundSftpSession,
        paths: &PathGuard,
        remote_path: &RemotePath,
        selected_target: &Path,
    ) -> CoreResult<SftpTransferReceipt> {
        let local_path = paths.ensure_safe_download_target(selected_target)?;
        self.target.validate(session.target())?;
        let response = self
            .ssh
            .sftp(
                session.session_id(),
                session.connection_id(),
                SftpRequest::DownloadNew {
                    remote_path: remote_path.as_str().to_owned(),
                    local_path: local_path.clone(),
                    maximum_bytes: MAX_TRANSFER_BYTES,
                },
            )
            .await;
        if let Err(error) = self.target.validate(session.target()) {
            if matches!(&response, Ok(SftpResponse::Transfer { .. })) {
                let _ = std::fs::remove_file(&local_path);
            }
            return Err(error);
        }
        let bytes = match response? {
            SftpResponse::Transfer { bytes } => bytes,
            response => return Err(unexpected_response("download", response)),
        };
        Ok(SftpTransferReceipt {
            remote_path: remote_path.clone(),
            local_path: Some(local_path),
            bytes,
        })
    }

    pub fn plan(
        &self,
        session: &BoundSftpSession,
        mutation: SftpMutation,
    ) -> CoreResult<SftpPlannedOperation> {
        self.plan_operation(session, SftpOperation::Mutation(mutation))
    }

    pub fn suggested_extraction_destination(archive: &RemotePath) -> CoreResult<RemotePath> {
        let (_, stem) = archive_extraction_format(archive)?;
        archive.parent()?.child(stem)
    }

    /// Build an extraction plan only after the remote archive has produced a
    /// stable, bounded manifest containing regular files and directories.
    pub async fn plan_extract(
        &self,
        session: &BoundSftpSession,
        archive: RemotePath,
        destination: RemotePath,
    ) -> CoreResult<SftpPlannedOperation> {
        self.plan_extract_with_nonce(session, archive, destination, Uuid::new_v4().to_string())
            .await
    }

    async fn plan_extract_with_nonce(
        &self,
        session: &BoundSftpSession,
        archive: RemotePath,
        destination: RemotePath,
        inspection_nonce: String,
    ) -> CoreResult<SftpPlannedOperation> {
        self.target.validate(session.target())?;
        if archive == destination || destination.as_str() == "/" {
            return Err(CoreError::validation(
                "archive extraction destination",
                "must be a new non-root path different from the archive",
            ));
        }
        let (format, _) = archive_extraction_format(&archive)?;
        let metadata = self.metadata(session, &archive, false).await?;
        if metadata.kind != SftpFileKind::File
            || metadata.size == 0
            || metadata.size > MAX_TRANSFER_BYTES
        {
            return Err(CoreError::validation(
                "archive extraction source",
                format!(
                    "must be a non-empty regular file no larger than {MAX_TRANSFER_BYTES} bytes"
                ),
            ));
        }
        if self.exists(session, &destination).await? {
            return Err(CoreError::validation(
                "archive extraction destination",
                "refuses to overwrite an existing remote path",
            ));
        }

        let output = self
            .ssh
            .execute_for_connection(
                session.session_id(),
                session.connection_id(),
                archive_preflight_command(&archive, format, &inspection_nonce),
                Duration::from_secs(300),
            )
            .await?;
        self.target.validate(session.target())?;
        if output.timed_out || output.exit_code != Some(0) {
            return Err(CoreError::ssh(
                "inspect archive manifest",
                bounded_command_error(&output.output),
            ));
        }
        let manifest = parse_archive_preflight(&output.output, &inspection_nonce)?;
        let operation = SftpOperation::ExtractArchive(ArchiveExtractionPlan {
            archive,
            destination,
            format,
            archive_size: metadata.size,
            archive_sha256: manifest.archive_sha256,
            manifest_sha256: manifest.manifest_sha256,
            entry_count: manifest.entry_count,
            receipt_token: Uuid::new_v4().to_string(),
        });
        self.plan_operation(session, operation)
    }

    /// Build a single-use upload plan from a core-managed staging file.
    ///
    /// The source is authorized both now and immediately before dispatch. A
    /// caller cannot put an arbitrary local path into [`SftpMutation`].
    pub fn plan_upload(
        &self,
        session: &BoundSftpSession,
        paths: &PathGuard,
        staged_path: &Path,
        remote_path: RemotePath,
    ) -> CoreResult<SftpPlannedOperation> {
        let staged_path = paths.ensure_managed_upload_source(staged_path)?;
        let metadata = std::fs::metadata(&staged_path)
            .map_err(|source| CoreError::io("inspect staged upload", &staged_path, source))?;
        if !metadata.is_file() || metadata.len() > MAX_TRANSFER_BYTES {
            return Err(CoreError::validation(
                "staged upload",
                format!("must be a regular file no larger than {MAX_TRANSFER_BYTES} bytes"),
            ));
        }
        self.plan_operation(
            session,
            SftpOperation::UploadStaged {
                paths: paths.clone(),
                staged_path,
                remote_path,
                expected_bytes: metadata.len(),
            },
        )
    }

    fn plan_operation(
        &self,
        session: &BoundSftpSession,
        operation: SftpOperation,
    ) -> CoreResult<SftpPlannedOperation> {
        self.target.validate(session.target())?;
        validate_operation(&operation)?;
        let (summary, restore_description) = operation_description(&operation);
        let mut plan =
            OperationPlan::new(session.target().clone(), summary, true, restore_description)?;
        plan.metadata = operation_metadata(&operation);
        let executor = SftpMutationExecutor::new(self.clone(), session.clone(), operation)?;
        Ok(SftpPlannedOperation {
            operation: PlannedOperation::plan(plan),
            executor,
            target: self.target.clone(),
            journal: self.journal.clone(),
        })
    }

    async fn request(
        &self,
        session: &BoundSftpSession,
        request: SftpRequest,
    ) -> CoreResult<SftpResponse> {
        self.target.validate(session.target())?;
        let response = self
            .ssh
            .sftp(session.session_id(), session.connection_id(), request)
            .await;
        self.target.validate(session.target())?;
        response
    }

    /// Dispatch one step of an already preflighted planned operation.
    ///
    /// `PlannedOperation` owns the before/after target checks. Performing a
    /// second post-check here could hide a successful remote side effect from
    /// the outer lifecycle, preventing its stale-execution journal entry.
    async fn operation_request(
        &self,
        session: &BoundSftpSession,
        request: SftpRequest,
    ) -> CoreResult<SftpResponse> {
        self.ssh
            .sftp(session.session_id(), session.connection_id(), request)
            .await
    }

    async fn operation_execute(
        &self,
        session: &BoundSftpSession,
        command: String,
        timeout: Duration,
    ) -> CoreResult<crate::ssh::SshCommandOutput> {
        self.ssh
            .execute_for_connection(
                session.session_id(),
                session.connection_id(),
                command,
                timeout,
            )
            .await
    }

    async fn metadata_raw(
        &self,
        session: &BoundSftpSession,
        path: &RemotePath,
        follow_symlink: bool,
    ) -> CoreResult<SftpRawMetadata> {
        match self
            .request(
                session,
                SftpRequest::Metadata {
                    path: path.as_str().to_owned(),
                    follow_symlink,
                },
            )
            .await?
        {
            SftpResponse::Metadata(metadata) => Ok(metadata),
            response => Err(unexpected_response("metadata", response)),
        }
    }

    pub(crate) async fn exists(
        &self,
        session: &BoundSftpSession,
        path: &RemotePath,
    ) -> CoreResult<bool> {
        match self
            .request(
                session,
                SftpRequest::Exists {
                    path: path.as_str().to_owned(),
                },
            )
            .await?
        {
            SftpResponse::Exists(exists) => Ok(exists),
            response => Err(unexpected_response("exists", response)),
        }
    }

    async fn unit(&self, session: &BoundSftpSession, request: SftpRequest) -> CoreResult<()> {
        expect_unit("mutation", self.request(session, request).await?)
    }

    async fn operation_unit(
        &self,
        session: &BoundSftpSession,
        request: SftpRequest,
    ) -> CoreResult<()> {
        expect_unit("mutation", self.operation_request(session, request).await?)
    }
}

#[derive(Debug)]
pub struct SftpPlannedOperation {
    operation: PlannedOperation,
    executor: SftpMutationExecutor,
    target: Arc<TargetContext>,
    journal: PortableOperationJournal,
}

/// Typed reference to the remote backup reserved by an atomic write plan.
///
/// The backup contains configuration bytes and must never be logged as file
/// content. Callers may persist these validated paths to offer a later guarded
/// restore; the backup path is created only when the atomic write succeeds.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SftpAtomicBackup {
    pub original: RemotePath,
    pub backup: RemotePath,
}

impl SftpPlannedOperation {
    pub fn definition(&self) -> &OperationPlan {
        self.operation.definition()
    }

    pub fn state(&self) -> OperationState {
        self.operation.state()
    }

    pub fn atomic_backup(&self) -> Option<SftpAtomicBackup> {
        let original = match &self.executor.operation {
            SftpOperation::Mutation(SftpMutation::AtomicWrite { path, .. })
            | SftpOperation::Mutation(SftpMutation::AtomicWriteIfMatch { path, .. }) => {
                path.clone()
            }
            _ => return None,
        };
        Some(SftpAtomicBackup {
            original,
            backup: self.executor.backup_path.clone()?,
        })
    }

    pub fn confirm(&mut self, confirmation: DangerousConfirmation) -> CoreResult<()> {
        self.operation.confirm(confirmation)
    }

    pub async fn execute_and_verify(&mut self) -> CoreResult<VerificationResult> {
        if let Err(error) = self.operation.execute(&self.target, &self.executor).await {
            if self.operation.state() == OperationState::StaleAfterExecution {
                self.operation.journal(&self.journal)?;
            }
            return Err(error);
        }
        self.operation.journal(&self.journal)?;
        self.operation
            .verify(&self.target, &self.executor, &self.journal)
            .await
    }

    pub async fn restore(&mut self) -> CoreResult<()> {
        self.operation
            .restore(&self.target, &self.executor, &self.journal)
            .await
    }
}

struct SftpMutationExecutor {
    service: SftpService,
    session: BoundSftpSession,
    operation: SftpOperation,
    backup_directory: Option<RemotePath>,
    backup_path: Option<RemotePath>,
    archive_temporary: Option<RemotePath>,
}

impl fmt::Debug for SftpMutationExecutor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SftpMutationExecutor")
            .field("session", &self.session)
            .field("operation", &self.operation)
            .field("backup_directory", &self.backup_directory)
            .field("backup_path", &self.backup_path)
            .field("archive_temporary", &self.archive_temporary)
            .finish()
    }
}

impl SftpMutationExecutor {
    fn new(
        service: SftpService,
        session: BoundSftpSession,
        operation: SftpOperation,
    ) -> CoreResult<Self> {
        let backup_target = match &operation {
            SftpOperation::Mutation(SftpMutation::AtomicWrite { path, .. })
            | SftpOperation::Mutation(SftpMutation::AtomicWriteIfMatch { path, .. })
            | SftpOperation::Mutation(SftpMutation::Remove { path })
            | SftpOperation::Mutation(SftpMutation::RemoveFileIfMatch { path, .. }) => Some(path),
            _ => None,
        };
        let explicit_backup_directory = match &operation {
            SftpOperation::Mutation(SftpMutation::AtomicWriteIfMatch {
                backup_directory, ..
            }) => backup_directory.clone(),
            _ => None,
        };
        let (backup_directory, backup_path) = match backup_target {
            Some(path) => {
                let (default_directory, default_backup) = path.backup_location()?;
                let (directory, backup) = if let Some(directory) = explicit_backup_directory {
                    let backup =
                        directory.child(&format!("{}-{}", Uuid::new_v4(), path.file_name()?))?;
                    (directory, backup)
                } else {
                    (default_directory, default_backup)
                };
                (Some(directory), Some(backup))
            }
            None => (None, None),
        };
        let archive_temporary = match &operation {
            SftpOperation::Mutation(SftpMutation::CreateArchive { destination, .. }) => Some(
                destination
                    .parent()?
                    .child(&format!(".lovelyres-archive-{}.tmp", Uuid::new_v4()))?,
            ),
            SftpOperation::ExtractArchive(plan) => Some(
                plan.destination
                    .parent()?
                    .child(&format!(".lovelyres-extract-{}.tmp", Uuid::new_v4()))?,
            ),
            _ => None,
        };
        Ok(Self {
            service,
            session,
            operation,
            backup_directory,
            backup_path,
            archive_temporary,
        })
    }

    fn backup(&self) -> CoreResult<(&RemotePath, &RemotePath)> {
        self.backup_directory
            .as_ref()
            .zip(self.backup_path.as_ref())
            .ok_or_else(|| CoreError::validation("SFTP restore", "backup path is unavailable"))
    }

    fn archive_temporary(&self) -> CoreResult<&RemotePath> {
        self.archive_temporary
            .as_ref()
            .ok_or_else(|| CoreError::validation("SFTP archive", "temporary path is unavailable"))
    }
}

impl Drop for SftpMutationExecutor {
    fn drop(&mut self) {
        if let SftpOperation::UploadStaged { staged_path, .. } = &self.operation {
            let _ = std::fs::remove_file(staged_path);
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum RestoreToken {
    AtomicWrite {
        path: RemotePath,
        backup: RemotePath,
        installed: bool,
        installed_sha256: String,
        backup_sha256: Option<String>,
        expected_canonical_path: Option<RemotePath>,
    },
    Rename {
        from: RemotePath,
        to: RemotePath,
    },
    Chmod {
        path: RemotePath,
        previous_mode: u32,
    },
    RemovedToBackup {
        path: RemotePath,
        backup: RemotePath,
    },
    CreatedPath {
        path: RemotePath,
        directory: bool,
    },
    ExtractedDirectory {
        destination: RemotePath,
        receipt_token: String,
        manifest_sha256: String,
        tree_sha256: String,
    },
}

#[async_trait]
impl OperationExecutor for SftpMutationExecutor {
    async fn execute(&self, _plan: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        let token = match &self.operation {
            SftpOperation::Mutation(SftpMutation::CreateFile {
                path,
                content,
                mode,
            }) => {
                let response = self
                    .service
                    .operation_request(
                        &self.session,
                        SftpRequest::WriteNew {
                            path: path.as_str().to_owned(),
                            content: content.clone(),
                            mode: *mode,
                        },
                    )
                    .await?;
                match response {
                    SftpResponse::Transfer { bytes } if bytes == content.len() as u64 => {}
                    SftpResponse::Transfer { .. } => {
                        return Err(CoreError::ssh(
                            "create SFTP file",
                            "worker receipt did not match the operation plan",
                        ));
                    }
                    response => return Err(unexpected_response("create file", response)),
                }
                RestoreToken::CreatedPath {
                    path: path.clone(),
                    directory: false,
                }
            }
            SftpOperation::Mutation(SftpMutation::CreateDirectory { path }) => {
                self.service
                    .operation_unit(
                        &self.session,
                        SftpRequest::CreateDirectory {
                            path: path.as_str().to_owned(),
                        },
                    )
                    .await?;
                RestoreToken::CreatedPath {
                    path: path.clone(),
                    directory: true,
                }
            }
            SftpOperation::Mutation(
                SftpMutation::AtomicWrite { path, content }
                | SftpMutation::AtomicWriteIfMatch { path, content, .. },
            ) => {
                let (backup_directory, backup_path) = self.backup()?;
                let expected_sha256 = match &self.operation {
                    SftpOperation::Mutation(SftpMutation::AtomicWriteIfMatch {
                        expected_sha256,
                        ..
                    }) => Some(expected_sha256.clone()),
                    _ => None,
                };
                let expected_canonical_path = match &self.operation {
                    SftpOperation::Mutation(SftpMutation::AtomicWriteIfMatch {
                        expected_canonical_path,
                        ..
                    }) => expected_canonical_path
                        .as_ref()
                        .map(|path| path.as_str().to_owned()),
                    _ => None,
                };
                let response = self
                    .service
                    .operation_request(
                        &self.session,
                        SftpRequest::AtomicWrite {
                            path: path.as_str().to_owned(),
                            backup_directory: backup_directory.as_str().to_owned(),
                            backup_path: backup_path.as_str().to_owned(),
                            content: content.clone(),
                            maximum_bytes: MAX_EDIT_BYTES,
                            expected_sha256: expected_sha256.clone(),
                            expected_canonical_path,
                        },
                    )
                    .await?;
                let SftpResponse::AtomicWrite(SftpAtomicWriteReceipt {
                    path: receipt_path,
                    backup_path: receipt_backup,
                    bytes_written,
                    previous_permissions,
                    installed,
                }) = response
                else {
                    return Err(unexpected_response("atomic write", response));
                };
                if receipt_path != path.as_str()
                    || receipt_backup != backup_path.as_str()
                    || (installed && bytes_written != content.len() as u64)
                    || (!installed && bytes_written != 0)
                {
                    return Err(CoreError::ssh(
                        "atomic write",
                        "worker receipt did not match the operation plan",
                    ));
                }
                let _ = previous_permissions;
                RestoreToken::AtomicWrite {
                    path: path.clone(),
                    backup: backup_path.clone(),
                    installed,
                    installed_sha256: content_sha256(content),
                    backup_sha256: expected_sha256,
                    expected_canonical_path: match &self.operation {
                        SftpOperation::Mutation(SftpMutation::AtomicWriteIfMatch {
                            expected_canonical_path,
                            ..
                        }) => expected_canonical_path.clone(),
                        _ => None,
                    },
                }
            }
            SftpOperation::Mutation(SftpMutation::Rename { from, to }) => {
                self.service
                    .operation_unit(
                        &self.session,
                        SftpRequest::Rename {
                            from: from.as_str().to_owned(),
                            to: to.as_str().to_owned(),
                            require_destination_absent: true,
                        },
                    )
                    .await?;
                RestoreToken::Rename {
                    from: from.clone(),
                    to: to.clone(),
                }
            }
            SftpOperation::Mutation(
                SftpMutation::Chmod { path, mode }
                | SftpMutation::ChmodIfMode {
                    path,
                    mode,
                    expected_mode: _,
                },
            ) => {
                let metadata = self
                    .service
                    .metadata_raw(&self.session, path, false)
                    .await?;
                let previous_mode = metadata.permissions.ok_or_else(|| {
                    CoreError::validation("SFTP chmod", "server did not report permissions")
                })? & 0o7777;
                if let SftpOperation::Mutation(SftpMutation::ChmodIfMode { expected_mode, .. }) =
                    &self.operation
                    && previous_mode != *expected_mode
                {
                    return Err(CoreError::validation(
                        "SFTP chmod target",
                        format!(
                            "permission bits changed after planning (expected {expected_mode:04o}, found {previous_mode:04o})"
                        ),
                    ));
                }
                self.service
                    .operation_unit(
                        &self.session,
                        SftpRequest::Chmod {
                            path: path.as_str().to_owned(),
                            mode: *mode,
                        },
                    )
                    .await?;
                RestoreToken::Chmod {
                    path: path.clone(),
                    previous_mode,
                }
            }
            SftpOperation::Mutation(
                SftpMutation::Remove { path } | SftpMutation::RemoveFileIfMatch { path, .. },
            ) => {
                let (backup_directory, backup_path) = self.backup()?;
                let expected_sha256 = match &self.operation {
                    SftpOperation::Mutation(SftpMutation::RemoveFileIfMatch {
                        expected_sha256,
                        ..
                    }) => Some(expected_sha256.clone()),
                    _ => None,
                };
                self.service
                    .operation_unit(
                        &self.session,
                        SftpRequest::MoveToBackup {
                            path: path.as_str().to_owned(),
                            backup_directory: backup_directory.as_str().to_owned(),
                            backup_path: backup_path.as_str().to_owned(),
                            expected_sha256,
                            maximum_bytes: MAX_EDIT_BYTES,
                        },
                    )
                    .await?;
                RestoreToken::RemovedToBackup {
                    path: path.clone(),
                    backup: backup_path.clone(),
                }
            }
            SftpOperation::Mutation(SftpMutation::CreateArchive {
                sources,
                destination,
                format,
            }) => {
                if self.service.exists(&self.session, destination).await? {
                    return Err(CoreError::validation(
                        "archive destination",
                        "refuses to overwrite an existing path",
                    ));
                }
                let command =
                    archive_command(sources, self.archive_temporary()?, destination, *format);
                let output = self
                    .service
                    .operation_execute(&self.session, command, Duration::from_secs(3600))
                    .await?;
                if !output.timed_out && output.exit_code == Some(0) {
                    RestoreToken::CreatedPath {
                        path: destination.clone(),
                        directory: false,
                    }
                } else {
                    return Err(CoreError::ssh("create archive", output.output));
                }
            }
            SftpOperation::ExtractArchive(plan) => {
                if self
                    .service
                    .exists(&self.session, &plan.destination)
                    .await?
                {
                    return Err(CoreError::validation(
                        "archive extraction destination",
                        "destination appeared after planning; refuses to overwrite it",
                    ));
                }
                let output = self
                    .service
                    .operation_execute(
                        &self.session,
                        extract_archive_command(plan, self.archive_temporary()?),
                        Duration::from_secs(3600),
                    )
                    .await?;
                if output.timed_out || output.exit_code != Some(0) {
                    return Err(CoreError::ssh(
                        "extract archive",
                        bounded_command_error(&output.output),
                    ));
                }
                let tree_sha256 = parse_extract_success(&output.output, plan)?;
                RestoreToken::ExtractedDirectory {
                    destination: plan.destination.clone(),
                    receipt_token: plan.receipt_token.clone(),
                    manifest_sha256: plan.manifest_sha256.clone(),
                    tree_sha256,
                }
            }
            SftpOperation::UploadStaged {
                paths,
                staged_path,
                remote_path,
                expected_bytes,
            } => {
                let local_path = paths.ensure_managed_upload_source(staged_path)?;
                let metadata = std::fs::metadata(&local_path).map_err(|source| {
                    CoreError::io("inspect staged upload", &local_path, source)
                })?;
                if !metadata.is_file()
                    || metadata.len() != *expected_bytes
                    || metadata.len() > MAX_TRANSFER_BYTES
                {
                    return Err(CoreError::validation(
                        "staged upload",
                        "source changed after planning or exceeds the transfer limit",
                    ));
                }
                let response = self
                    .service
                    .operation_request(
                        &self.session,
                        SftpRequest::UploadNew {
                            local_path,
                            remote_path: remote_path.as_str().to_owned(),
                            maximum_bytes: MAX_TRANSFER_BYTES,
                        },
                    )
                    .await;
                let _cleanup = std::fs::remove_file(staged_path);
                let response = response?;
                match response {
                    SftpResponse::Transfer { bytes } if bytes == *expected_bytes => {}
                    SftpResponse::Transfer { .. } => {
                        return Err(CoreError::ssh(
                            "upload SFTP file",
                            "worker receipt did not match the operation plan",
                        ));
                    }
                    response => return Err(unexpected_response("upload", response)),
                }
                RestoreToken::CreatedPath {
                    path: remote_path.clone(),
                    directory: false,
                }
            }
        };
        Ok(ExecutionReceipt {
            summary: "SFTP mutation completed".to_owned(),
            restore_token: Some(serde_json::to_string(&token).map_err(|source| {
                CoreError::Encode {
                    subject: "SFTP restore token",
                    source,
                }
            })?),
        })
    }

    async fn verify(
        &self,
        _plan: &OperationPlan,
        receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        let (passed, detail) = match &self.operation {
            SftpOperation::Mutation(SftpMutation::CreateFile {
                path,
                content,
                mode,
            }) => {
                let bytes = self.service.read_file(&self.session, path).await?;
                let mode_matches = if let Some(expected_mode) = mode {
                    self.service
                        .metadata_raw(&self.session, path, false)
                        .await?
                        .permissions
                        .is_some_and(|actual| actual & 0o7777 == *expected_mode)
                } else {
                    true
                };
                (
                    bytes == *content && mode_matches,
                    if let Some(mode) = mode {
                        format!("new file read-back matches planned bytes and mode {mode:04o}")
                    } else {
                        "new file read-back matches planned bytes".to_owned()
                    },
                )
            }
            SftpOperation::Mutation(SftpMutation::CreateDirectory { path }) => {
                let metadata = self.service.metadata(&self.session, path, false).await?;
                (
                    metadata.kind == SftpFileKind::Directory,
                    "new path is a directory".to_owned(),
                )
            }
            SftpOperation::Mutation(
                SftpMutation::AtomicWrite { path, content }
                | SftpMutation::AtomicWriteIfMatch { path, content, .. },
            ) => {
                let bytes = self.service.read_file(&self.session, path).await?;
                (
                    bytes == *content,
                    "atomic write read-back matches planned bytes".to_owned(),
                )
            }
            SftpOperation::Mutation(SftpMutation::Rename { from, to }) => {
                let from_exists = self.service.exists(&self.session, from).await?;
                let to_exists = self.service.exists(&self.session, to).await?;
                (
                    !from_exists && to_exists,
                    "rename source is absent and destination exists".to_owned(),
                )
            }
            SftpOperation::Mutation(
                SftpMutation::Chmod { path, mode }
                | SftpMutation::ChmodIfMode {
                    path,
                    mode,
                    expected_mode: _,
                },
            ) => {
                let metadata = self
                    .service
                    .metadata_raw(&self.session, path, false)
                    .await?;
                (
                    metadata
                        .permissions
                        .is_some_and(|value| value & 0o7777 == *mode),
                    format!("remote mode is {:o}", mode),
                )
            }
            SftpOperation::Mutation(
                SftpMutation::Remove { path } | SftpMutation::RemoveFileIfMatch { path, .. },
            ) => {
                let (_, backup) = self.backup()?;
                (
                    !self.service.exists(&self.session, path).await?
                        && self.service.exists(&self.session, backup).await?,
                    "original path is absent and recoverable backup exists".to_owned(),
                )
            }
            SftpOperation::Mutation(SftpMutation::CreateArchive { destination, .. }) => (
                self.service.exists(&self.session, destination).await?,
                "archive destination exists".to_owned(),
            ),
            SftpOperation::ExtractArchive(plan) => {
                let RestoreToken::ExtractedDirectory {
                    destination,
                    receipt_token,
                    manifest_sha256,
                    tree_sha256,
                } = decode_restore_token(receipt)?
                else {
                    return Err(CoreError::validation(
                        "archive extraction receipt",
                        "restore token kind does not match the planned extraction",
                    ));
                };
                if destination != plan.destination
                    || receipt_token != plan.receipt_token
                    || manifest_sha256 != plan.manifest_sha256
                {
                    return Err(CoreError::validation(
                        "archive extraction receipt",
                        "receipt does not match the private extraction plan",
                    ));
                }
                let output = self
                    .service
                    .operation_execute(
                        &self.session,
                        verify_extracted_directory_command(
                            &destination,
                            &receipt_token,
                            &manifest_sha256,
                            &tree_sha256,
                        ),
                        Duration::from_secs(3600),
                    )
                    .await?;
                let verified = !output.timed_out && output.exit_code == Some(0);
                (
                    verified,
                    if verified {
                        format!(
                            "extracted {} validated entries into a new directory",
                            plan.entry_count
                        )
                    } else {
                        "extracted directory no longer matches its validated manifest".to_owned()
                    },
                )
            }
            SftpOperation::UploadStaged {
                remote_path,
                expected_bytes,
                ..
            } => {
                let metadata = self
                    .service
                    .metadata(&self.session, remote_path, false)
                    .await?;
                (
                    metadata.kind == SftpFileKind::File && metadata.size == *expected_bytes,
                    "uploaded path is a regular file with the planned byte length".to_owned(),
                )
            }
        };
        Ok(VerificationResult { passed, detail })
    }

    async fn restore(&self, _plan: &OperationPlan, receipt: &ExecutionReceipt) -> CoreResult<()> {
        let token: RestoreToken = decode_restore_token(receipt)?;
        match token {
            RestoreToken::AtomicWrite {
                path,
                backup,
                installed,
                installed_sha256,
                backup_sha256,
                expected_canonical_path,
            } => {
                if let Some(expected) = expected_canonical_path.as_ref() {
                    let actual = self.service.canonicalize(&self.session, &path).await?;
                    if actual != *expected {
                        return Err(CoreError::validation(
                            "SFTP restore target",
                            "canonical path changed after the guarded write",
                        ));
                    }
                }
                let current = self.service.read_file(&self.session, &path).await?;
                if content_sha256(&current) != installed_sha256 {
                    return Err(CoreError::validation(
                        "SFTP restore target",
                        "file content changed after the guarded write",
                    ));
                }
                let backup_bytes = self.service.read_file(&self.session, &backup).await?;
                if let Some(expected) = backup_sha256.as_deref()
                    && content_sha256(&backup_bytes) != expected
                {
                    return Err(CoreError::validation(
                        "SFTP restore backup",
                        "backup content no longer matches the planned original SHA-256",
                    ));
                }
                if !installed {
                    if self.service.exists(&self.session, &path).await? {
                        return Err(CoreError::validation(
                            "SFTP partial atomic restore",
                            "target path was recreated after a partial write; the preserved backup was not allowed to overwrite it",
                        ));
                    }
                    self.service
                        .unit(
                            &self.session,
                            SftpRequest::Rename {
                                from: backup.as_str().to_owned(),
                                to: path.as_str().to_owned(),
                                require_destination_absent: true,
                            },
                        )
                        .await?;
                    if let Some(expected) = expected_canonical_path.as_ref() {
                        let actual = self.service.canonicalize(&self.session, &path).await?;
                        if actual != *expected {
                            return Err(CoreError::validation(
                                "SFTP partial atomic restore",
                                "restored target canonical path does not match the planned identity",
                            ));
                        }
                    }
                    if let Some(expected) = backup_sha256.as_deref() {
                        let restored = self.service.read_file(&self.session, &path).await?;
                        if content_sha256(&restored) != expected {
                            return Err(CoreError::validation(
                                "SFTP partial atomic restore",
                                "restored target does not match the planned original SHA-256",
                            ));
                        }
                    }
                    return Ok(());
                }
                let displaced_directory = backup.parent()?;
                let displaced_path = displaced_directory.child(&format!(
                    "{}-pre-restore-{}",
                    Uuid::new_v4(),
                    path.file_name()?
                ))?;
                let restored_bytes = backup_bytes.len() as u64;
                let response = self
                    .service
                    .operation_request(
                        &self.session,
                        SftpRequest::AtomicWrite {
                            path: path.as_str().to_owned(),
                            backup_directory: displaced_directory.as_str().to_owned(),
                            backup_path: displaced_path.as_str().to_owned(),
                            content: backup_bytes,
                            maximum_bytes: MAX_EDIT_BYTES,
                            expected_sha256: Some(installed_sha256),
                            expected_canonical_path: expected_canonical_path
                                .as_ref()
                                .map(|expected| expected.as_str().to_owned()),
                        },
                    )
                    .await?;
                let SftpResponse::AtomicWrite(restored) = response else {
                    return Err(unexpected_response("guarded atomic restore", response));
                };
                if restored.path != path.as_str()
                    || restored.backup_path != displaced_path.as_str()
                    || restored.bytes_written != restored_bytes
                {
                    return Err(CoreError::validation(
                        "SFTP guarded restore",
                        "worker receipt did not match the guarded restore request",
                    ));
                }
                if let Some(expected) = expected_canonical_path.as_ref() {
                    let actual = self.service.canonicalize(&self.session, &path).await?;
                    if actual != *expected {
                        return Err(CoreError::validation(
                            "SFTP restored target",
                            "canonical path changed while restoring the guarded write",
                        ));
                    }
                }
                Ok(())
            }
            RestoreToken::Rename { from, to } => {
                self.service
                    .unit(
                        &self.session,
                        SftpRequest::Rename {
                            from: to.as_str().to_owned(),
                            to: from.as_str().to_owned(),
                            require_destination_absent: true,
                        },
                    )
                    .await
            }
            RestoreToken::Chmod {
                path,
                previous_mode,
            } => {
                self.service
                    .unit(
                        &self.session,
                        SftpRequest::Chmod {
                            path: path.as_str().to_owned(),
                            mode: previous_mode,
                        },
                    )
                    .await
            }
            RestoreToken::RemovedToBackup { path, backup } => {
                self.service
                    .unit(
                        &self.session,
                        SftpRequest::Rename {
                            from: backup.as_str().to_owned(),
                            to: path.as_str().to_owned(),
                            require_destination_absent: true,
                        },
                    )
                    .await
            }
            RestoreToken::CreatedPath { path, directory } => {
                self.service
                    .unit(
                        &self.session,
                        SftpRequest::Remove {
                            path: path.as_str().to_owned(),
                            directory,
                        },
                    )
                    .await
            }
            RestoreToken::ExtractedDirectory {
                destination,
                receipt_token,
                manifest_sha256,
                tree_sha256,
            } => {
                let output = self
                    .service
                    .operation_execute(
                        &self.session,
                        restore_extracted_directory_command(
                            &destination,
                            &receipt_token,
                            &manifest_sha256,
                            &tree_sha256,
                        ),
                        Duration::from_secs(3600),
                    )
                    .await?;
                if !output.timed_out && output.exit_code == Some(0) {
                    Ok(())
                } else {
                    Err(CoreError::ssh(
                        "restore archive extraction",
                        bounded_command_error(&output.output),
                    ))
                }
            }
        }
    }
}

fn validate_mutation(mutation: &SftpMutation) -> CoreResult<()> {
    match mutation {
        SftpMutation::CreateFile { path, .. } if path.as_str() == "/" => Err(
            CoreError::validation("SFTP new file", "root already exists"),
        ),
        SftpMutation::CreateFile { content, .. } if content.len() as u64 > MAX_EDIT_BYTES => {
            Err(CoreError::validation(
                "SFTP new file",
                format!("must be no larger than {MAX_EDIT_BYTES} bytes"),
            ))
        }
        SftpMutation::CreateFile {
            mode: Some(mode), ..
        } if *mode > 0o7777 => Err(CoreError::validation(
            "SFTP new file mode",
            "must be between 0000 and 7777 octal",
        )),
        SftpMutation::CreateDirectory { path } if path.as_str() == "/" => Err(
            CoreError::validation("SFTP new directory", "root already exists"),
        ),
        SftpMutation::AtomicWrite { content, .. } if content.len() as u64 > MAX_EDIT_BYTES => {
            Err(CoreError::validation(
                "SFTP editor content",
                format!("must be no larger than {MAX_EDIT_BYTES} bytes"),
            ))
        }
        SftpMutation::AtomicWriteIfMatch {
            path,
            expected_canonical_path: Some(expected),
            ..
        } if path != expected => Err(CoreError::validation(
            "SFTP guarded editor",
            "mutation path must already equal its captured canonical path",
        )),
        SftpMutation::AtomicWriteIfMatch {
            expected_sha256,
            content,
            ..
        } if content.len() as u64 > MAX_EDIT_BYTES || !is_sha256(expected_sha256) => {
            Err(CoreError::validation(
                "SFTP guarded editor",
                format!(
                    "content must be no larger than {MAX_EDIT_BYTES} bytes and expected SHA-256 must be lowercase hexadecimal"
                ),
            ))
        }
        SftpMutation::RemoveFileIfMatch {
            expected_sha256, ..
        } if !is_sha256(expected_sha256) => Err(CoreError::validation(
            "SFTP guarded remove",
            "expected SHA-256 must be lowercase hexadecimal",
        )),
        SftpMutation::Rename { from, to } if from == to => Err(CoreError::validation(
            "SFTP rename",
            "source and destination must differ",
        )),
        SftpMutation::Chmod { mode, .. } if *mode > 0o7777 => Err(CoreError::validation(
            "SFTP mode",
            "must be between 0000 and 7777 octal",
        )),
        SftpMutation::ChmodIfMode {
            expected_mode,
            mode,
            ..
        } if *expected_mode > 0o7777 || *mode > 0o7777 => Err(CoreError::validation(
            "SFTP guarded mode",
            "expected and replacement modes must be between 0000 and 7777 octal",
        )),
        SftpMutation::CreateArchive { sources, .. }
            if sources.is_empty() || sources.len() > 1024 =>
        {
            Err(CoreError::validation(
                "archive sources",
                "must contain between 1 and 1024 paths",
            ))
        }
        SftpMutation::CreateArchive {
            sources,
            destination,
            ..
        } if sources.iter().any(|source| source == destination) => Err(CoreError::validation(
            "archive destination",
            "must differ from every source",
        )),
        _ => Ok(()),
    }
}

fn validate_operation(operation: &SftpOperation) -> CoreResult<()> {
    match operation {
        SftpOperation::Mutation(mutation) => validate_mutation(mutation),
        SftpOperation::ExtractArchive(plan) => validate_extraction_plan(plan),
        SftpOperation::UploadStaged {
            remote_path,
            expected_bytes,
            ..
        } => {
            if remote_path.as_str() == "/" {
                return Err(CoreError::validation(
                    "SFTP upload destination",
                    "root cannot be replaced by an upload",
                ));
            }
            if *expected_bytes > MAX_TRANSFER_BYTES {
                return Err(CoreError::validation(
                    "SFTP upload",
                    format!("must be no larger than {MAX_TRANSFER_BYTES} bytes"),
                ));
            }
            Ok(())
        }
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn content_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn mutation_description(mutation: &SftpMutation) -> (String, Option<String>) {
    match mutation {
        SftpMutation::CreateFile { path, .. } => (
            format!("create new file {}", path.as_str()),
            Some("remove the newly created remote file".to_owned()),
        ),
        SftpMutation::CreateDirectory { path } => (
            format!("create new directory {}", path.as_str()),
            Some("remove the newly created empty remote directory".to_owned()),
        ),
        SftpMutation::AtomicWrite { path, .. } => (
            format!("atomically replace {}", path.as_str()),
            Some("restore the original file from the remote backup namespace".to_owned()),
        ),
        SftpMutation::AtomicWriteIfMatch { path, .. } => (
            format!(
                "atomically replace {} only if its content still matches the captured SHA-256",
                path.as_str()
            ),
            Some("restore the original file from the remote backup namespace".to_owned()),
        ),
        SftpMutation::Rename { from, to } => (
            format!("rename {} to {}", from.as_str(), to.as_str()),
            Some("rename the destination back to the original path".to_owned()),
        ),
        SftpMutation::Chmod { path, mode } => (
            format!("change {} permissions to {:o}", path.as_str(), mode),
            Some("restore the previous permission bits".to_owned()),
        ),
        SftpMutation::ChmodIfMode {
            path,
            expected_mode,
            mode,
        } => (
            format!(
                "change {} permissions from {:04o} to {:04o} only if the captured mode still matches",
                path.as_str(),
                expected_mode,
                mode
            ),
            Some("restore the captured permission bits".to_owned()),
        ),
        SftpMutation::Remove { path } => (
            format!(
                "remove {} into the recoverable backup namespace",
                path.as_str()
            ),
            Some("move the remote backup back to its original path".to_owned()),
        ),
        SftpMutation::RemoveFileIfMatch { path, .. } => (
            format!(
                "move {} into the recoverable backup namespace only if its content still matches the captured SHA-256",
                path.as_str()
            ),
            Some("move the remote backup back to its original path".to_owned()),
        ),
        SftpMutation::CreateArchive { destination, .. } => (
            format!("create archive {}", destination.as_str()),
            Some("remove the newly created archive".to_owned()),
        ),
    }
}

fn operation_description(operation: &SftpOperation) -> (String, Option<String>) {
    match operation {
        SftpOperation::Mutation(mutation) => mutation_description(mutation),
        SftpOperation::ExtractArchive(plan) => (
            format!(
                "extract {} validated entries from {} into new directory {}",
                plan.entry_count,
                plan.archive.as_str(),
                plan.destination.as_str()
            ),
            Some(
                "remove the extracted directory only while its receipt, manifest, and content digest remain unchanged"
                    .to_owned(),
            ),
        ),
        SftpOperation::UploadStaged {
            remote_path,
            expected_bytes,
            ..
        } => (
            format!(
                "upload {expected_bytes} staged bytes to new file {}",
                remote_path.as_str()
            ),
            Some("remove the newly uploaded remote file".to_owned()),
        ),
    }
}

fn mutation_metadata(mutation: &SftpMutation) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    match mutation {
        SftpMutation::CreateFile {
            path,
            content,
            mode,
        } => {
            metadata.insert("action".to_owned(), "create-file".to_owned());
            metadata.insert("path".to_owned(), path.as_str().to_owned());
            metadata.insert("bytes".to_owned(), content.len().to_string());
            if let Some(mode) = mode {
                metadata.insert("mode".to_owned(), format!("{mode:o}"));
            }
        }
        SftpMutation::CreateDirectory { path } => {
            metadata.insert("action".to_owned(), "create-directory".to_owned());
            metadata.insert("path".to_owned(), path.as_str().to_owned());
        }
        SftpMutation::AtomicWrite { path, content } => {
            metadata.insert("action".to_owned(), "atomic-write".to_owned());
            metadata.insert("path".to_owned(), path.as_str().to_owned());
            metadata.insert("bytes".to_owned(), content.len().to_string());
        }
        SftpMutation::AtomicWriteIfMatch {
            path,
            expected_sha256,
            content,
            ..
        } => {
            metadata.insert("action".to_owned(), "atomic-write-if-match".to_owned());
            metadata.insert("path".to_owned(), path.as_str().to_owned());
            metadata.insert("bytes".to_owned(), content.len().to_string());
            metadata.insert("expected-sha256".to_owned(), expected_sha256.clone());
        }
        SftpMutation::Rename { from, to } => {
            metadata.insert("action".to_owned(), "rename".to_owned());
            metadata.insert("from".to_owned(), from.as_str().to_owned());
            metadata.insert("to".to_owned(), to.as_str().to_owned());
        }
        SftpMutation::Chmod { path, mode } => {
            metadata.insert("action".to_owned(), "chmod".to_owned());
            metadata.insert("path".to_owned(), path.as_str().to_owned());
            metadata.insert("mode".to_owned(), format!("{mode:o}"));
        }
        SftpMutation::ChmodIfMode {
            path,
            expected_mode,
            mode,
        } => {
            metadata.insert("action".to_owned(), "chmod-if-mode".to_owned());
            metadata.insert("path".to_owned(), path.as_str().to_owned());
            metadata.insert("expected-mode".to_owned(), format!("{expected_mode:04o}"));
            metadata.insert("mode".to_owned(), format!("{mode:04o}"));
        }
        SftpMutation::Remove { path } => {
            metadata.insert("action".to_owned(), "remove".to_owned());
            metadata.insert("path".to_owned(), path.as_str().to_owned());
        }
        SftpMutation::RemoveFileIfMatch {
            path,
            expected_sha256,
        } => {
            metadata.insert("action".to_owned(), "remove-file-if-match".to_owned());
            metadata.insert("path".to_owned(), path.as_str().to_owned());
            metadata.insert("expected-sha256".to_owned(), expected_sha256.clone());
        }
        SftpMutation::CreateArchive {
            sources,
            destination,
            format,
        } => {
            metadata.insert("action".to_owned(), "create-archive".to_owned());
            metadata.insert("destination".to_owned(), destination.as_str().to_owned());
            metadata.insert("source-count".to_owned(), sources.len().to_string());
            metadata.insert("format".to_owned(), format!("{format:?}"));
        }
    }
    metadata
}

fn operation_metadata(operation: &SftpOperation) -> BTreeMap<String, String> {
    match operation {
        SftpOperation::Mutation(mutation) => mutation_metadata(mutation),
        SftpOperation::ExtractArchive(plan) => BTreeMap::from([
            ("action".to_owned(), "extract-archive".to_owned()),
            ("archive".to_owned(), plan.archive.as_str().to_owned()),
            ("archive-bytes".to_owned(), plan.archive_size.to_string()),
            ("archive-sha256".to_owned(), plan.archive_sha256.clone()),
            (
                "destination".to_owned(),
                plan.destination.as_str().to_owned(),
            ),
            ("entry-count".to_owned(), plan.entry_count.to_string()),
            ("manifest-sha256".to_owned(), plan.manifest_sha256.clone()),
        ]),
        SftpOperation::UploadStaged {
            remote_path,
            expected_bytes,
            ..
        } => BTreeMap::from([
            ("action".to_owned(), "upload-new".to_owned()),
            ("path".to_owned(), remote_path.as_str().to_owned()),
            ("bytes".to_owned(), expected_bytes.to_string()),
        ]),
    }
}

fn archive_command(
    sources: &[RemotePath],
    temporary: &RemotePath,
    destination: &RemotePath,
    format: ArchiveFormat,
) -> String {
    let option = match format {
        ArchiveFormat::Tar => "-cf",
        ArchiveFormat::TarGzip => "-czf",
        ArchiveFormat::TarZstd => "--zstd -cf",
    };
    let sources = sources
        .iter()
        .map(|source| shq(source.as_str()))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "set -eu; tmp={}; dst={}; trap 'rm -f -- \"$tmp\"' EXIT HUP INT TERM; \
         test ! -e \"$dst\"; test ! -e \"$tmp\"; tar {} \"$tmp\" -- {}; \
         test -s \"$tmp\"; mv -- \"$tmp\" \"$dst\"; trap - EXIT HUP INT TERM",
        shq(temporary.as_str()),
        shq(destination.as_str()),
        option,
        sources
    )
}

#[derive(Debug, PartialEq, Eq)]
struct ArchiveManifest {
    archive_sha256: String,
    manifest_sha256: String,
    entry_count: usize,
}

fn archive_extraction_format(archive: &RemotePath) -> CoreResult<(ArchiveExtractionFormat, &str)> {
    let name = archive.file_name()?;
    let lower = name.to_ascii_lowercase();
    let candidates = [
        (".tar.gz", ArchiveExtractionFormat::TarGzip),
        (".tar.bz2", ArchiveExtractionFormat::TarBzip2),
        (".tar.zst", ArchiveExtractionFormat::TarZstd),
        (".tgz", ArchiveExtractionFormat::TarGzip),
        (".tbz2", ArchiveExtractionFormat::TarBzip2),
        (".tzst", ArchiveExtractionFormat::TarZstd),
        (".tar", ArchiveExtractionFormat::Tar),
        (".zip", ArchiveExtractionFormat::Zip),
    ];
    for (suffix, format) in candidates {
        if lower.ends_with(suffix) && name.len() > suffix.len() {
            return Ok((format, &name[..name.len() - suffix.len()]));
        }
    }
    Err(CoreError::validation(
        "archive extraction format",
        "supports .zip, .tar, .tar.gz, .tgz, .tar.bz2, .tbz2, .tar.zst, and .tzst",
    ))
}

fn archive_preflight_command(
    archive: &RemotePath,
    format: ArchiveExtractionFormat,
    nonce: &str,
) -> String {
    let archive = shq(archive.as_str());
    let (names, types) = match format {
        ArchiveExtractionFormat::Zip => (
            "unzip -Z1 \"$archive\" 2>/dev/null".to_owned(),
            "zipinfo -l \"$archive\" 2>/dev/null | awk 'substr($0,1,1) ~ /[-dlcbps]/ { print substr($0,1,1) }'"
                .to_owned(),
        ),
        ArchiveExtractionFormat::Tar
        | ArchiveExtractionFormat::TarGzip
        | ArchiveExtractionFormat::TarBzip2
        | ArchiveExtractionFormat::TarZstd => (
            "tar --absolute-names --quoting-style=escape -tf \"$archive\" 2>/dev/null"
                .to_owned(),
            "tar --absolute-names --quoting-style=escape -tvf \"$archive\" 2>/dev/null | cut -c1"
                .to_owned(),
        ),
    };
    let before_marker = format!("LOVELYRES_{nonce}_ARCHIVE_BEFORE");
    let names_begin = format!("LOVELYRES_{nonce}_NAMES_BEGIN");
    let names_end = format!("LOVELYRES_{nonce}_NAMES_END");
    let types_begin = format!("LOVELYRES_{nonce}_TYPES_BEGIN");
    let types_end = format!("LOVELYRES_{nonce}_TYPES_END");
    let after_marker = format!("LOVELYRES_{nonce}_ARCHIVE_AFTER");
    format!(
        "set -eu; archive={archive}; test -f \"$archive\"; before=$(sha256sum -- \"$archive\" | awk '{{print $1}}'); \
         printf '{before_marker}=%s\\n{names_begin}\\n' \"$before\"; \
         {names}; printf '{names_end}\\n{types_begin}\\n'; \
         {types}; printf '{types_end}\\n'; \
         after=$(sha256sum -- \"$archive\" | awk '{{print $1}}'); \
         printf '{after_marker}=%s\\n' \"$after\"; test \"$before\" = \"$after\""
    )
}

fn parse_archive_preflight(output: &str, nonce: &str) -> CoreResult<ArchiveManifest> {
    if output.len() > MAX_ARCHIVE_MANIFEST_BYTES {
        return Err(CoreError::validation(
            "archive manifest",
            format!("exceeds the {MAX_ARCHIVE_MANIFEST_BYTES}-byte inspection limit"),
        ));
    }
    let before_prefix = format!("LOVELYRES_{nonce}_ARCHIVE_BEFORE=");
    let after_prefix = format!("LOVELYRES_{nonce}_ARCHIVE_AFTER=");
    let before = marker_value(output, &before_prefix)?;
    let after = marker_value(output, &after_prefix)?;
    if !is_sha256(before) || before != after {
        return Err(CoreError::validation(
            "archive manifest",
            "archive changed while its entries were inspected",
        ));
    }
    let names_begin = format!("LOVELYRES_{nonce}_NAMES_BEGIN\n");
    let names_end = format!("LOVELYRES_{nonce}_NAMES_END\n");
    let types_begin = format!("LOVELYRES_{nonce}_TYPES_BEGIN\n");
    let types_end = format!("LOVELYRES_{nonce}_TYPES_END\n");
    let names = marker_section(output, &names_begin, &names_end)?;
    let types = marker_section(output, &types_begin, &types_end)?;
    let names = names.lines().collect::<Vec<_>>();
    let types = types.lines().collect::<Vec<_>>();
    if names.is_empty() || names.len() != types.len() || names.len() > MAX_DIRECTORY_ENTRIES {
        return Err(CoreError::validation(
            "archive manifest",
            format!(
                "must contain 1..={MAX_DIRECTORY_ENTRIES} entries with one trustworthy type per name"
            ),
        ));
    }

    let mut entries = BTreeMap::new();
    for (name, kind) in names.into_iter().zip(types) {
        let kind = match kind.as_bytes() {
            b"-" => ArchiveEntryKind::File,
            b"d" => ArchiveEntryKind::Directory,
            _ => {
                return Err(CoreError::validation(
                    "archive entry type",
                    "symlinks, hard links, devices, sockets, and special files are not allowed",
                ));
            }
        };
        let Some(path) = normalize_archive_entry(name)? else {
            continue;
        };
        insert_archive_entry(&mut entries, &path, kind)?;
    }
    if entries.is_empty() || entries.len() > MAX_DIRECTORY_ENTRIES {
        return Err(CoreError::validation(
            "archive manifest",
            format!("must expand to 1..={MAX_DIRECTORY_ENTRIES} files and directories"),
        ));
    }
    let manifest = archive_manifest_text(&entries);
    if manifest.len() > MAX_ARCHIVE_MANIFEST_BYTES {
        return Err(CoreError::validation(
            "archive manifest",
            format!("expanded manifest exceeds {MAX_ARCHIVE_MANIFEST_BYTES} bytes"),
        ));
    }
    Ok(ArchiveManifest {
        archive_sha256: before.to_owned(),
        manifest_sha256: content_sha256(manifest.as_bytes()),
        entry_count: entries.len(),
    })
}

fn marker_value<'a>(output: &'a str, prefix: &str) -> CoreResult<&'a str> {
    let mut matches = output.lines().filter_map(|line| line.strip_prefix(prefix));
    let value = matches.next().ok_or_else(|| {
        CoreError::validation(
            "archive inspection output",
            format!("missing marker {prefix}"),
        )
    })?;
    if matches.next().is_some() || value.is_empty() {
        return Err(CoreError::validation(
            "archive inspection output",
            format!("marker {prefix} is duplicated or empty"),
        ));
    }
    Ok(value)
}

fn marker_section<'a>(output: &'a str, start: &str, end: &str) -> CoreResult<&'a str> {
    let start_index = output.find(start).ok_or_else(|| {
        CoreError::validation(
            "archive inspection output",
            format!("missing marker {start:?}"),
        )
    })? + start.len();
    let tail = &output[start_index..];
    let end_index = tail.find(end).ok_or_else(|| {
        CoreError::validation(
            "archive inspection output",
            format!("missing marker {end:?}"),
        )
    })?;
    if output[start_index..].matches(start).next().is_some()
        || tail[end_index + end.len()..].contains(end)
    {
        return Err(CoreError::validation(
            "archive inspection output",
            "manifest section markers are duplicated",
        ));
    }
    Ok(&tail[..end_index])
}

fn normalize_archive_entry(name: &str) -> CoreResult<Option<String>> {
    if name.is_empty()
        || name.len() > 4096
        || name.starts_with('/')
        || name.contains('\\')
        || name.chars().any(char::is_control)
    {
        return Err(CoreError::validation(
            "archive entry path",
            "must be relative, bounded, and contain no controls or backslashes",
        ));
    }
    let mut name = name;
    while let Some(stripped) = name.strip_prefix("./") {
        name = stripped;
    }
    name = name.trim_end_matches('/');
    if name.is_empty() || name == "." {
        return Ok(None);
    }
    let components = name.split('/').collect::<Vec<_>>();
    if components.iter().any(|component| {
        component.is_empty()
            || matches!(*component, "." | "..")
            || matches!(*component, EXTRACT_RECEIPT_NAME | EXTRACT_SOURCE_NAME)
    }) {
        return Err(CoreError::validation(
            "archive entry path",
            "contains an empty, dot, parent, or reserved receipt component",
        ));
    }
    Ok(Some(components.join("/")))
}

fn insert_archive_entry(
    entries: &mut BTreeMap<String, ArchiveEntryKind>,
    path: &str,
    kind: ArchiveEntryKind,
) -> CoreResult<()> {
    let mut offset = 0;
    while let Some(index) = path[offset..].find('/') {
        offset += index;
        let parent = &path[..offset];
        match entries.get(parent) {
            Some(ArchiveEntryKind::File) => {
                return Err(CoreError::validation(
                    "archive manifest",
                    format!("file {parent:?} is also used as a parent directory"),
                ));
            }
            Some(ArchiveEntryKind::Directory) => {}
            None => {
                entries.insert(parent.to_owned(), ArchiveEntryKind::Directory);
            }
        }
        offset += 1;
    }
    match entries.get(path) {
        Some(existing) if *existing != kind => Err(CoreError::validation(
            "archive manifest",
            format!("entry {path:?} has conflicting file types"),
        )),
        Some(ArchiveEntryKind::File) => Err(CoreError::validation(
            "archive manifest",
            format!("file {path:?} occurs more than once"),
        )),
        Some(ArchiveEntryKind::Directory) => Ok(()),
        None => {
            entries.insert(path.to_owned(), kind);
            Ok(())
        }
    }
}

fn archive_manifest_text(entries: &BTreeMap<String, ArchiveEntryKind>) -> String {
    let mut lines = entries
        .iter()
        .map(|(path, kind)| {
            let prefix = match kind {
                ArchiveEntryKind::File => 'f',
                ArchiveEntryKind::Directory => 'd',
            };
            format!("{prefix}\t{path}\n")
        })
        .collect::<Vec<_>>();
    lines.sort_unstable();
    lines.concat()
}

fn validate_extraction_plan(plan: &ArchiveExtractionPlan) -> CoreResult<()> {
    let (format, _) = archive_extraction_format(&plan.archive)?;
    if format != plan.format
        || plan.archive == plan.destination
        || plan.destination.as_str() == "/"
        || plan.archive_size == 0
        || plan.archive_size > MAX_TRANSFER_BYTES
        || !is_sha256(&plan.archive_sha256)
        || !is_sha256(&plan.manifest_sha256)
        || plan.entry_count == 0
        || plan.entry_count > MAX_DIRECTORY_ENTRIES
        || Uuid::parse_str(&plan.receipt_token).is_err()
    {
        return Err(CoreError::validation(
            "archive extraction plan",
            "private plan fields are inconsistent or out of bounds",
        ));
    }
    Ok(())
}

fn shell_tree_digests(directory: &str, marker: &str) -> String {
    format!(
        "manifest=$(find \"{directory}\" -mindepth 1 ! -path \"{directory}/{marker}\" -print | \
         while IFS= read -r p; do rel=${{p#\"{directory}/\"}}; \
         if test ! -L \"$p\" && test -d \"$p\"; then printf 'd\\t%s\\n' \"$rel\"; \
         elif test ! -L \"$p\" && test -f \"$p\"; then printf 'f\\t%s\\n' \"$rel\"; \
         else printf 'x\\t%s\\n' \"$rel\"; fi; done | LC_ALL=C sort | sha256sum | awk '{{print $1}}'); \
         tree=$(find \"{directory}\" -mindepth 1 ! -path \"{directory}/{marker}\" -print | \
         while IFS= read -r p; do rel=${{p#\"{directory}/\"}}; \
         if test ! -L \"$p\" && test -d \"$p\"; then printf 'd\\t-\\t%s\\n' \"$rel\"; \
         elif test ! -L \"$p\" && test -f \"$p\"; then sum=$(sha256sum -- \"$p\" | awk '{{print $1}}'); printf 'f\\t%s\\t%s\\n' \"$sum\" \"$rel\"; \
         else printf 'x\\t-\\t%s\\n' \"$rel\"; fi; done | LC_ALL=C sort | sha256sum | awk '{{print $1}}')"
    )
}

fn extract_archive_command(plan: &ArchiveExtractionPlan, temporary: &RemotePath) -> String {
    let extract = match plan.format {
        ArchiveExtractionFormat::Zip => "unzip -n -q \"$archive\" -d \"$stage\"".to_owned(),
        ArchiveExtractionFormat::Tar => tar_extract_command("-xf"),
        ArchiveExtractionFormat::TarGzip => tar_extract_command("-xzf"),
        ArchiveExtractionFormat::TarBzip2 => tar_extract_command("-xjf"),
        ArchiveExtractionFormat::TarZstd => tar_extract_command("--zstd -xf"),
    };
    let digests = shell_tree_digests("$stage", EXTRACT_RECEIPT_NAME);
    format!(
        "set -eu; archive={}; destination={}; stage={}; marker={}; source_name={}; \
         expected_size={}; expected_archive={}; expected_manifest={}; token={}; \
         mkdir -m 700 -- \"$stage\"; trap 'rm -rf -- \"$stage\"' EXIT HUP INT TERM; \
         test -f \"$archive\"; test ! -e \"$destination\"; head -c \"$expected_size\" -- \"$archive\" > \"$stage/$source_name\"; \
         archive=\"$stage/$source_name\"; actual_size=$(wc -c < \"$archive\"); test \"$actual_size\" = \"$expected_size\"; \
         actual_archive=$(sha256sum -- \"$archive\" | awk '{{print $1}}'); test \"$actual_archive\" = \"$expected_archive\"; \
         {extract}; rm -f -- \"$archive\"; {digests}; test \"$manifest\" = \"$expected_manifest\"; \
         printf '%s\\n%s\\n%s\\n' \"$token\" \"$manifest\" \"$tree\" > \"$stage/$marker\"; chmod 600 -- \"$stage/$marker\"; \
         test ! -e \"$destination\"; mv -- \"$stage\" \"$destination\"; trap - EXIT HUP INT TERM; \
         printf 'LOVELYRES_EXTRACT_OK=%s:%s\\n' \"$manifest\" \"$tree\"",
        shq(plan.archive.as_str()),
        shq(plan.destination.as_str()),
        shq(temporary.as_str()),
        shq(EXTRACT_RECEIPT_NAME),
        shq(EXTRACT_SOURCE_NAME),
        plan.archive_size,
        shq(&plan.archive_sha256),
        shq(&plan.manifest_sha256),
        shq(&plan.receipt_token),
    )
}

fn tar_extract_command(option: &str) -> String {
    format!(
        "tar {option} \"$archive\" --directory=\"$stage\" --keep-old-files --no-same-owner --no-same-permissions --delay-directory-restore"
    )
}

fn parse_extract_success(output: &str, plan: &ArchiveExtractionPlan) -> CoreResult<String> {
    let value = marker_value(output, "LOVELYRES_EXTRACT_OK=")?;
    let (manifest, tree) = value.split_once(':').ok_or_else(|| {
        CoreError::validation("archive extraction receipt", "success marker is malformed")
    })?;
    if manifest != plan.manifest_sha256 || !is_sha256(tree) {
        return Err(CoreError::validation(
            "archive extraction receipt",
            "success marker does not match the private extraction plan",
        ));
    }
    Ok(tree.to_owned())
}

fn verify_extracted_directory_command(
    destination: &RemotePath,
    receipt_token: &str,
    manifest_sha256: &str,
    tree_sha256: &str,
) -> String {
    extracted_directory_guard_command(destination, receipt_token, manifest_sha256, tree_sha256)
}

fn restore_extracted_directory_command(
    destination: &RemotePath,
    receipt_token: &str,
    manifest_sha256: &str,
    tree_sha256: &str,
) -> String {
    let first_digests = shell_tree_digests("$destination", EXTRACT_RECEIPT_NAME);
    let second_digests = shell_tree_digests("$quarantine", EXTRACT_RECEIPT_NAME);
    let quarantine = format!(
        "{}.lovelyres-restore-{}",
        destination.as_str(),
        Uuid::new_v4()
    );
    format!(
        "set -eu; destination={}; quarantine={}; marker={}; token={}; expected_manifest={}; expected_tree={}; \
         test -d \"$destination\"; test ! -L \"$destination\"; test ! -e \"$quarantine\"; \
         expected_receipt=$(printf '%s\\n%s\\n%s' \"$token\" \"$expected_manifest\" \"$expected_tree\"); \
         actual_receipt=$(cat -- \"$destination/$marker\"); test \"$actual_receipt\" = \"$expected_receipt\"; \
         {first_digests}; test \"$manifest\" = \"$expected_manifest\"; test \"$tree\" = \"$expected_tree\"; \
         mv -- \"$destination\" \"$quarantine\"; \
         trap 'if test -e \"$quarantine\" && test ! -e \"$destination\"; then mv -- \"$quarantine\" \"$destination\"; fi' EXIT HUP INT TERM; \
         actual_receipt=$(cat -- \"$quarantine/$marker\"); test \"$actual_receipt\" = \"$expected_receipt\"; \
         {second_digests}; test \"$manifest\" = \"$expected_manifest\"; test \"$tree\" = \"$expected_tree\"; \
         rm -rf -- \"$quarantine\"; trap - EXIT HUP INT TERM",
        shq(destination.as_str()),
        shq(&quarantine),
        shq(EXTRACT_RECEIPT_NAME),
        shq(receipt_token),
        shq(manifest_sha256),
        shq(tree_sha256),
    )
}

fn extracted_directory_guard_command(
    destination: &RemotePath,
    receipt_token: &str,
    manifest_sha256: &str,
    tree_sha256: &str,
) -> String {
    let digests = shell_tree_digests("$destination", EXTRACT_RECEIPT_NAME);
    format!(
        "set -eu; destination={}; marker={}; token={}; expected_manifest={}; expected_tree={}; \
         test -d \"$destination\"; test ! -L \"$destination\"; \
         expected_receipt=$(printf '%s\\n%s\\n%s' \"$token\" \"$expected_manifest\" \"$expected_tree\"); \
         actual_receipt=$(cat -- \"$destination/$marker\"); test \"$actual_receipt\" = \"$expected_receipt\"; \
         {digests}; test \"$manifest\" = \"$expected_manifest\"; test \"$tree\" = \"$expected_tree\"",
        shq(destination.as_str()),
        shq(EXTRACT_RECEIPT_NAME),
        shq(receipt_token),
        shq(manifest_sha256),
        shq(tree_sha256),
    )
}

fn decode_restore_token(receipt: &ExecutionReceipt) -> CoreResult<RestoreToken> {
    let encoded = receipt
        .restore_token
        .as_deref()
        .ok_or_else(|| CoreError::validation("SFTP restore", "operation has no restore token"))?;
    serde_json::from_str(encoded).map_err(|source| CoreError::Decode {
        subject: "SFTP restore token",
        source,
    })
}

fn bounded_command_error(output: &str) -> String {
    const LIMIT: usize = 8192;
    let mut end = output.len().min(LIMIT);
    while !output.is_char_boundary(end) {
        end -= 1;
    }
    let suffix = if end < output.len() { "…" } else { "" };
    format!("{}{suffix}", output[..end].trim())
}

fn convert_entry(parent: &RemotePath, raw: SftpRawEntry) -> CoreResult<SftpEntry> {
    if raw.name.is_empty() || raw.name.contains('/') || raw.name.chars().any(char::is_control) {
        return Err(CoreError::validation(
            "SFTP entry name",
            "server returned an invalid path component",
        ));
    }
    let expected = parent.child(&raw.name)?;
    let returned = RemotePath::new(raw.path)?;
    if returned != expected {
        return Err(CoreError::validation(
            "SFTP entry path",
            "server returned a path outside the directory being listed",
        ));
    }
    Ok(SftpEntry {
        name: raw.name,
        path: returned,
        metadata: convert_metadata(raw.metadata),
    })
}

fn convert_metadata(raw: SftpRawMetadata) -> SftpMetadata {
    let kind = if raw.is_symlink {
        SftpFileKind::Symlink
    } else if raw.is_directory {
        SftpFileKind::Directory
    } else if raw.is_file {
        SftpFileKind::File
    } else {
        SftpFileKind::Other
    };
    SftpMetadata {
        size: raw.size,
        permissions: raw.permissions,
        uid: raw.uid,
        gid: raw.gid,
        modified_at: raw
            .modified_unix_seconds
            .and_then(|seconds| DateTime::from_timestamp(i64::from(seconds), 0)),
        kind,
    }
}

fn expect_unit(operation: &'static str, response: SftpResponse) -> CoreResult<()> {
    match response {
        SftpResponse::Unit => Ok(()),
        response => Err(unexpected_response(operation, response)),
    }
}

fn unexpected_response(operation: &'static str, response: SftpResponse) -> CoreError {
    CoreError::ssh(
        operation,
        format!(
            "dedicated SSH runtime returned an unexpected {} response",
            response.kind()
        ),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::connections::{
        ConnectionConfig, ConnectionRepository, ConnectionSecretChanges, SecretChange,
        SshAuthMethod,
    };
    use crate::crypto::{CryptoVault, SecretValue};
    use crate::operations::JournalPhase;
    use crate::ssh::{HostKeyConfirmations, TestSessionHarness};
    use crate::target::TargetIdentity;
    use crate::{BackendServices, PortableStore};

    fn status(session_id: &str, connection_id: &str) -> SshConnectionStatus {
        SshConnectionStatus {
            session_id: session_id.to_owned(),
            connection_id: connection_id.to_owned(),
            host: "host.test".to_owned(),
            port: 22,
            username: "root".to_owned(),
            host_key_fingerprint: "SHA256:test".to_owned(),
            connected_at: Utc::now(),
        }
    }

    async fn guarded_chmod_fixture() -> (
        PathBuf,
        BackendServices,
        BoundSftpSession,
        Arc<TestSessionHarness>,
    ) {
        let root = std::env::temp_dir().join(format!(
            "lovelyres-sftp-guarded-chmod-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let services = BackendServices::new(PortableStore::prepare(root.clone()).unwrap()).unwrap();
        let identity = TargetIdentity::new("sftp-guarded-chmod-target").unwrap();
        let guard = services.activate_target(identity.clone()).unwrap();
        let status = status("sftp-guarded-chmod-session", identity.as_str());
        let harness = Arc::new(TestSessionHarness::default());
        harness.set_sftp_immediate(true);
        services
            .ssh()
            .install_test_session(status, harness.clone())
            .await
            .unwrap();
        let session = services
            .sftp()
            .bind_session(guard, "sftp-guarded-chmod-session")
            .await
            .unwrap();
        (root, services, session, harness)
    }

    #[test]
    fn remote_paths_are_absolute_and_traversal_free() {
        for valid in ["/", "/etc/ssh/sshd_config", "/tmp/中文 文件.txt"] {
            assert!(RemotePath::new(valid).is_ok(), "{valid}");
        }
        for invalid in [
            "relative",
            "/etc/../shadow",
            "/tmp//file",
            "/tmp/./file",
            "/tmp/file/",
            "/tmp\\file",
            "/tmp/file\nname",
        ] {
            assert!(RemotePath::new(invalid).is_err(), "{invalid}");
        }
    }

    #[tokio::test]
    async fn directory_terminal_quotes_the_path_and_refuses_files_or_stale_targets() {
        let (root, services, session, harness) = guarded_chmod_fixture().await;
        let directory = RemotePath::new("/tmp/a'; touch pwned; echo '").unwrap();
        harness.set_sftp_directory(directory.as_str());

        let terminal = services
            .sftp()
            .open_directory_terminal(
                &session,
                &directory,
                "sftp-directory-terminal".to_owned(),
                120,
                40,
            )
            .await
            .unwrap();
        assert_eq!(
            harness.terminal_launches(),
            vec![format!(
                "cd -- {} && exec \"${{SHELL:-/bin/sh}}\" -l",
                shq(directory.as_str())
            )]
        );

        let file = RemotePath::new("/tmp/evidence.txt").unwrap();
        harness.set_sftp_file(file.as_str(), b"evidence".to_vec());
        let error = services
            .sftp()
            .open_directory_terminal(&session, &file, "sftp-file-terminal".to_owned(), 80, 24)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("not a directory"));
        assert_eq!(harness.terminal_launches().len(), 1);

        services
            .activate_target(TargetIdentity::new("host-b").unwrap())
            .unwrap();
        let error = services
            .sftp()
            .open_directory_terminal(
                &session,
                &directory,
                "sftp-stale-terminal".to_owned(),
                80,
                24,
            )
            .await
            .unwrap_err();
        assert!(matches!(error, CoreError::TargetChanged { .. }));
        assert_eq!(harness.terminal_launches().len(), 1);

        crate::events::TerminalTransport::close(&terminal)
            .await
            .unwrap();
        drop(terminal);
        drop(services);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn backup_namespace_is_sibling_scoped_and_unique() {
        let path = RemotePath::new("/etc/ssh/sshd_config").unwrap();
        let (directory, backup) = path.backup_location().unwrap();
        assert_eq!(directory.as_str(), "/etc/ssh/.lovelyres-backups");
        assert!(backup.as_str().starts_with("/etc/ssh/.lovelyres-backups/"));
        assert!(backup.as_str().ends_with("-sshd_config"));
    }

    #[test]
    fn edit_limit_and_modes_are_validated_before_planning() {
        let path = RemotePath::new("/tmp/file").unwrap();
        assert!(
            validate_mutation(&SftpMutation::AtomicWrite {
                path: path.clone(),
                content: vec![0; MAX_EDIT_BYTES as usize + 1],
            })
            .is_err()
        );
        assert!(
            validate_mutation(&SftpMutation::Chmod {
                path: path.clone(),
                mode: 0o10000,
            })
            .is_err()
        );
        assert!(
            validate_mutation(&SftpMutation::ChmodIfMode {
                path: path.clone(),
                expected_mode: 0o10000,
                mode: 0o600,
            })
            .is_err()
        );
        assert!(
            validate_mutation(&SftpMutation::CreateFile {
                path: path.clone(),
                content: Vec::new(),
                mode: Some(0o10000),
            })
            .is_err()
        );
        let managed = SftpMutation::CreateFile {
            path,
            content: b"managed\n".to_vec(),
            mode: Some(0o644),
        };
        assert!(validate_mutation(&managed).is_ok());
        assert_eq!(
            mutation_metadata(&managed).get("mode").map(String::as_str),
            Some("644")
        );
    }

    #[tokio::test]
    async fn guarded_chmod_rejects_a_mode_changed_after_planning_without_side_effects() {
        let (root, services, session, harness) = guarded_chmod_fixture().await;
        let path = RemotePath::new("/etc/passwd").unwrap();
        harness.set_sftp_file(path.as_str(), b"root:x:0:0".to_vec());
        harness.set_sftp_mode(path.as_str(), 0o666);
        let mut operation = services
            .sftp()
            .plan(
                &session,
                SftpMutation::ChmodIfMode {
                    path: path.clone(),
                    expected_mode: 0o666,
                    mode: 0o644,
                },
            )
            .unwrap();
        operation
            .confirm(DangerousConfirmation::approve(operation.definition()))
            .unwrap();

        harness.set_sftp_mode(path.as_str(), 0o640);
        let error = operation.execute_and_verify().await.unwrap_err();
        assert!(error.to_string().contains("changed after planning"));
        assert_eq!(harness.sftp_mode(path.as_str()), Some(0o640));
        assert!(services.operation_journal().entries().unwrap().is_empty());

        drop(operation);
        drop(services);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn guarded_chmod_is_journaled_verified_and_restorable() {
        let (root, services, session, harness) = guarded_chmod_fixture().await;
        let path = RemotePath::new("/etc/passwd").unwrap();
        harness.set_sftp_file(path.as_str(), b"root:x:0:0".to_vec());
        harness.set_sftp_mode(path.as_str(), 0o666);
        let mut operation = services
            .sftp()
            .plan(
                &session,
                SftpMutation::ChmodIfMode {
                    path: path.clone(),
                    expected_mode: 0o666,
                    mode: 0o644,
                },
            )
            .unwrap();
        let operation_id = operation.definition().id.clone();
        assert_eq!(
            operation.definition().metadata.get("expected-mode"),
            Some(&"0666".to_owned())
        );
        operation
            .confirm(DangerousConfirmation::approve(operation.definition()))
            .unwrap();
        assert!(operation.execute_and_verify().await.unwrap().passed);
        assert_eq!(harness.sftp_mode(path.as_str()), Some(0o644));

        operation.restore().await.unwrap();
        assert_eq!(harness.sftp_mode(path.as_str()), Some(0o666));
        let entries = services.operation_journal().entries().unwrap();
        assert!(entries.iter().any(|entry| {
            entry.operation_id == operation_id && entry.phase == JournalPhase::VerificationPassed
        }));
        assert!(entries.iter().any(|entry| {
            entry.operation_id == operation_id && entry.phase == JournalPhase::Restored
        }));

        drop(operation);
        drop(services);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn guarded_atomic_restore_requires_the_installed_hash_and_preserves_concurrent_bytes() {
        let (root, services, session, harness) = guarded_chmod_fixture().await;
        let path = RemotePath::new("/etc/nginx/nginx.conf").unwrap();
        let backup_directory = RemotePath::new("/etc/nginx/.lovelyres-backups").unwrap();
        harness.set_sftp_file(path.as_str(), b"worker_processes 1;\n".to_vec());

        let make_plan = || {
            services.sftp().plan(
                &session,
                SftpMutation::AtomicWriteIfMatch {
                    path: path.clone(),
                    expected_sha256: content_sha256(b"worker_processes 1;\n"),
                    expected_canonical_path: Some(path.clone()),
                    backup_directory: Some(backup_directory.clone()),
                    content: b"worker_processes auto;\n".to_vec(),
                },
            )
        };

        let mut restored = make_plan().unwrap();
        restored
            .confirm(DangerousConfirmation::approve(restored.definition()))
            .unwrap();
        assert!(restored.execute_and_verify().await.unwrap().passed);
        restored.restore().await.unwrap();
        assert_eq!(
            services.sftp().read_file(&session, &path).await.unwrap(),
            b"worker_processes 1;\n"
        );

        let mut raced = make_plan().unwrap();
        raced
            .confirm(DangerousConfirmation::approve(raced.definition()))
            .unwrap();
        assert!(raced.execute_and_verify().await.unwrap().passed);
        harness.set_sftp_file(path.as_str(), b"concurrent administrator edit\n".to_vec());
        assert!(raced.restore().await.is_err());
        assert_eq!(
            services.sftp().read_file(&session, &path).await.unwrap(),
            b"concurrent administrator edit\n"
        );

        drop(raced);
        drop(restored);
        drop(services);
        let _ = std::fs::remove_dir_all(root);
    }

    fn preflight_output(nonce: &str, hash: &str, names: &[&str], types: &[&str]) -> String {
        format!(
            "LOVELYRES_{nonce}_ARCHIVE_BEFORE={hash}\nLOVELYRES_{nonce}_NAMES_BEGIN\n{}\nLOVELYRES_{nonce}_NAMES_END\nLOVELYRES_{nonce}_TYPES_BEGIN\n{}\nLOVELYRES_{nonce}_TYPES_END\nLOVELYRES_{nonce}_ARCHIVE_AFTER={hash}\n",
            names.join("\n"),
            types.join("\n")
        )
    }

    #[test]
    fn archive_manifest_normalizes_directories_and_has_a_stable_digest() {
        let nonce = "00000000-0000-0000-0000-000000000001";
        let hash = "11".repeat(32);
        let parsed = parse_archive_preflight(
            &preflight_output(nonce, &hash, &["a/report.txt", "z-evidence/"], &["-", "d"]),
            nonce,
        )
        .unwrap();
        assert_eq!(parsed.archive_sha256, hash);
        assert_eq!(parsed.entry_count, 3);
        assert_eq!(
            parsed.manifest_sha256,
            content_sha256(b"d\ta\nd\tz-evidence\nf\ta/report.txt\n")
        );
    }

    #[test]
    fn archive_manifest_rejects_traversal_links_duplicates_and_reserved_receipts() {
        let nonce = "00000000-0000-0000-0000-000000000002";
        let hash = "22".repeat(32);
        for (names, types) in [
            (vec!["../shadow"], vec!["-"]),
            (vec!["safe/link"], vec!["l"]),
            (vec!["safe/file", "safe/file"], vec!["-", "-"]),
            (vec!["safe/.lovelyres-extract-receipt"], vec!["-"]),
            (vec!["safe\\file"], vec!["-"]),
        ] {
            let output = preflight_output(nonce, &hash, &names, &types);
            assert!(
                parse_archive_preflight(&output, nonce).is_err(),
                "{names:?}"
            );
        }
    }

    #[test]
    fn archive_format_and_destination_are_derived_without_overwriting() {
        for (path, expected) in [
            ("/tmp/case.zip", "/tmp/case"),
            ("/tmp/case.tar", "/tmp/case"),
            ("/tmp/case.tar.gz", "/tmp/case"),
            ("/tmp/case.tgz", "/tmp/case"),
            ("/tmp/case.tar.bz2", "/tmp/case"),
            ("/tmp/case.tar.zst", "/tmp/case"),
        ] {
            assert_eq!(
                SftpService::suggested_extraction_destination(&RemotePath::new(path).unwrap())
                    .unwrap()
                    .as_str(),
                expected
            );
        }
        assert!(
            SftpService::suggested_extraction_destination(
                &RemotePath::new("/tmp/case.rar").unwrap()
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn extraction_plan_is_built_only_from_a_stable_remote_manifest() {
        let (root, services, session, harness) = guarded_chmod_fixture().await;
        let archive = RemotePath::new("/tmp/case.tar.gz").unwrap();
        let destination = RemotePath::new("/tmp/case").unwrap();
        let nonce = "00000000-0000-0000-0000-000000000003";
        let hash = "33".repeat(32);
        harness.set_sftp_file(archive.as_str(), b"archive".to_vec());
        harness.set_execute_output(preflight_output(
            nonce,
            &hash,
            &["case/", "case/report.txt"],
            &["d", "-"],
        ));

        let operation = services
            .sftp()
            .plan_extract_with_nonce(
                &session,
                archive.clone(),
                destination.clone(),
                nonce.to_owned(),
            )
            .await
            .unwrap();
        assert_eq!(
            operation.definition().metadata.get("archive-sha256"),
            Some(&hash)
        );
        assert_eq!(
            operation.definition().metadata.get("archive-bytes"),
            Some(&"7".to_owned())
        );
        assert_eq!(
            operation.definition().metadata.get("entry-count"),
            Some(&"2".to_owned())
        );
        assert!(operation.definition().dangerous);
        assert!(operation.definition().restore_description.is_some());

        drop(operation);
        drop(services);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn extraction_requires_confirmation_and_journals_verify_and_restore() {
        let (root, services, session, harness) = guarded_chmod_fixture().await;
        let archive = RemotePath::new("/tmp/case.zip").unwrap();
        let destination = RemotePath::new("/tmp/case").unwrap();
        let nonce = "00000000-0000-0000-0000-000000000004";
        let archive_hash = "66".repeat(32);
        let manifest_sha256 = content_sha256(b"d\tcase\nf\tcase/report.txt\n");
        let tree_sha256 = "77".repeat(32);
        harness.set_sftp_file(archive.as_str(), b"archive".to_vec());
        harness.set_execute_outputs([
            preflight_output(
                nonce,
                &archive_hash,
                &["case/", "case/report.txt"],
                &["d", "-"],
            ),
            format!("LOVELYRES_EXTRACT_OK={manifest_sha256}:{tree_sha256}\n"),
            String::new(),
            String::new(),
        ]);

        let mut operation = services
            .sftp()
            .plan_extract_with_nonce(&session, archive, destination, nonce.to_owned())
            .await
            .unwrap();
        assert!(operation.execute_and_verify().await.is_err());
        operation
            .confirm(DangerousConfirmation::approve(operation.definition()))
            .unwrap();
        assert!(operation.execute_and_verify().await.unwrap().passed);
        operation.restore().await.unwrap();

        let entries = services.operation_journal().entries().unwrap();
        assert!(
            entries
                .iter()
                .any(|entry| entry.phase == JournalPhase::VerificationPassed)
        );
        assert!(
            entries
                .iter()
                .any(|entry| entry.phase == JournalPhase::Restored)
        );

        drop(operation);
        drop(services);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn extraction_command_quotes_paths_and_checks_before_atomic_publish() {
        let plan = ArchiveExtractionPlan {
            archive: RemotePath::new("/tmp/a'; touch pwned; echo '.tar").unwrap(),
            destination: RemotePath::new("/tmp/result'; touch pwned; echo '").unwrap(),
            format: ArchiveExtractionFormat::Tar,
            archive_size: 1024,
            archive_sha256: "44".repeat(32),
            manifest_sha256: "55".repeat(32),
            entry_count: 1,
            receipt_token: Uuid::new_v4().to_string(),
        };
        let command = extract_archive_command(
            &plan,
            &RemotePath::new("/tmp/.lovelyres-extract-test.tmp").unwrap(),
        );
        assert!(command.contains("'\\''"));
        assert!(command.contains("test ! -e \"$destination\""));
        assert!(command.contains("head -c \"$expected_size\""));
        assert!(command.contains("test \"$actual_size\" = \"$expected_size\""));
        assert!(command.contains("test \"$manifest\" = \"$expected_manifest\""));
        assert!(command.contains("mv -- \"$stage\" \"$destination\""));
        assert!(!command.contains("archive=/tmp/a';"));

        let restore = restore_extracted_directory_command(
            &plan.destination,
            &plan.receipt_token,
            &plan.manifest_sha256,
            &"77".repeat(32),
        );
        assert!(restore.contains("mv -- \"$destination\" \"$quarantine\""));
        assert!(restore.contains("mv -- \"$quarantine\" \"$destination\""));
        assert!(restore.matches("actual_receipt=$(cat").count() >= 2);
        assert!(restore.contains("rm -rf -- \"$quarantine\""));
    }

    #[test]
    fn archive_command_quotes_every_remote_path() {
        let command = archive_command(
            &[RemotePath::new("/tmp/a'; touch /tmp/pwned; echo '").unwrap()],
            &RemotePath::new("/tmp/.lovelyres-archive-test.tmp").unwrap(),
            &RemotePath::new("/tmp/evidence.tar.gz").unwrap(),
            ArchiveFormat::TarGzip,
        );
        assert!(command.contains("'\\''"));
        assert!(command.contains("trap 'rm -f"));
        assert!(!command.contains("-- /tmp/a';"));
    }

    #[test]
    fn listed_entry_must_be_the_named_child_of_the_requested_directory() {
        let metadata = SftpRawMetadata {
            size: 1,
            permissions: Some(0o600),
            uid: Some(0),
            gid: Some(0),
            modified_unix_seconds: None,
            is_file: true,
            is_directory: false,
            is_symlink: false,
        };
        let parent = RemotePath::new("/tmp/evidence").unwrap();
        assert!(
            convert_entry(
                &parent,
                SftpRawEntry {
                    name: "item.txt".to_owned(),
                    path: "/tmp/evidence/item.txt".to_owned(),
                    metadata: metadata.clone(),
                }
            )
            .is_ok()
        );
        assert!(
            convert_entry(
                &parent,
                SftpRawEntry {
                    name: "item.txt".to_owned(),
                    path: "/etc/shadow".to_owned(),
                    metadata,
                }
            )
            .is_err()
        );
    }

    #[test]
    fn remote_mutations_have_no_public_raw_service_method() {
        let source = include_str!("sftp.rs")
            .split("\n#[cfg(test)]\nmod tests")
            .next()
            .unwrap();
        for forbidden in [
            "pub async fn create_file(",
            "pub async fn create_directory(",
            "pub async fn upload_staged(",
            "pub async fn atomic_write(",
            "pub async fn rename(",
            "pub async fn chmod(",
            "pub async fn remove(",
            "pub async fn create_archive(",
            "pub async fn extract_archive(",
        ] {
            assert!(!source.contains(forbidden), "found raw method {forbidden}");
        }
    }

    #[test]
    fn mutation_executor_defers_post_target_check_to_planned_operation() {
        let source = include_str!("sftp.rs");
        let execute = source
            .split("impl OperationExecutor for SftpMutationExecutor")
            .nth(1)
            .unwrap()
            .split("async fn verify")
            .next()
            .unwrap();
        assert!(execute.contains("operation_request("));
        assert!(execute.contains("operation_unit("));
        assert!(execute.contains("operation_execute("));
        assert!(!execute.contains(".request("));
        assert!(!execute.contains(".unit("));
        assert!(!execute.contains(".execute("));
    }

    #[test]
    fn destructive_variants_are_always_marked_dangerous() {
        let target = crate::target::TargetContext::new();
        let guard = target
            .activate(crate::target::TargetIdentity::new("host-a").unwrap())
            .unwrap();
        let (summary, restore) = mutation_description(&SftpMutation::Remove {
            path: RemotePath::new("/tmp/evidence").unwrap(),
        });
        let plan = OperationPlan::new(guard, summary, true, restore).unwrap();
        assert!(plan.dangerous);
        assert!(plan.restore_description.is_some());
    }

    #[test]
    fn bound_session_rejects_cross_target_pairing() {
        let target = TargetContext::new();
        let guard_a = target
            .activate(crate::target::TargetIdentity::new("connection-a").unwrap())
            .unwrap();
        assert!(
            BoundSftpSession::from_status(guard_a.clone(), &status("session-b", "connection-b"))
                .is_err()
        );
        let bound =
            BoundSftpSession::from_status(guard_a, &status("session-a", "connection-a")).unwrap();
        assert_eq!(bound.connection_id(), "connection-a");
        assert_eq!(bound.session_id(), "session-a");
    }

    #[test]
    fn sftp_mutation_cannot_reach_worker_without_confirmation() {
        let root =
            std::env::temp_dir().join(format!("lovelyres-sftp-plan-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let store = PortableStore::prepare(root.clone()).unwrap();
        let connections =
            ConnectionRepository::new(store.clone(), Arc::new(CryptoVault::load(&store).unwrap()));
        let ssh = SshService::new(store.clone(), connections).unwrap();
        let target = Arc::new(TargetContext::new());
        let journal = PortableOperationJournal::new(store);
        let service = SftpService::new(ssh, target.clone(), journal);
        let guard = target
            .activate(crate::target::TargetIdentity::new("host-a").unwrap())
            .unwrap();
        let session =
            BoundSftpSession::from_status(guard, &status("missing-session", "host-a")).unwrap();
        let mut operation = service
            .plan(
                &session,
                SftpMutation::Remove {
                    path: RemotePath::new("/tmp/evidence").unwrap(),
                },
            )
            .unwrap();
        let error = futures::executor::block_on(operation.execute_and_verify()).unwrap_err();
        assert!(matches!(error, CoreError::ConfirmationRequired { .. }));
        drop(operation);
        drop(service);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn overwrite_plan_requires_exact_confirmation_and_does_not_journal_early() {
        let root =
            std::env::temp_dir().join(format!("lovelyres-sftp-overwrite-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let store = PortableStore::prepare(root.clone()).unwrap();
        let connections =
            ConnectionRepository::new(store.clone(), Arc::new(CryptoVault::load(&store).unwrap()));
        let ssh = SshService::new(store.clone(), connections).unwrap();
        let target = Arc::new(TargetContext::new());
        let journal = PortableOperationJournal::new(store);
        let service = SftpService::new(ssh, target.clone(), journal.clone());
        let guard = target
            .activate(TargetIdentity::new("host-a").unwrap())
            .unwrap();
        let session =
            BoundSftpSession::from_status(guard, &status("missing-session", "host-a")).unwrap();
        let mut operation = service
            .plan(
                &session,
                SftpMutation::AtomicWrite {
                    path: RemotePath::new("/tmp/evidence.txt").unwrap(),
                    content: b"replacement".to_vec(),
                },
            )
            .unwrap();
        let atomic_backup = operation
            .atomic_backup()
            .expect("atomic writes reserve a typed durable backup path");
        assert_eq!(atomic_backup.original.as_str(), "/tmp/evidence.txt");
        assert_eq!(
            atomic_backup.backup.parent().unwrap().as_str(),
            "/tmp/.lovelyres-backups"
        );
        assert!(operation.definition().dangerous);
        assert!(operation.definition().restore_description.is_some());
        assert!(matches!(
            futures::executor::block_on(operation.execute_and_verify()),
            Err(CoreError::ConfirmationRequired { .. })
        ));
        assert!(journal.entries().unwrap().is_empty());
        drop(operation);
        drop(service);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn cancelled_upload_plan_removes_its_single_use_staging_file() {
        let root =
            std::env::temp_dir().join(format!("lovelyres-sftp-upload-plan-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let store = PortableStore::prepare(root.clone()).unwrap();
        let connections =
            ConnectionRepository::new(store.clone(), Arc::new(CryptoVault::load(&store).unwrap()));
        let ssh = SshService::new(store.clone(), connections).unwrap();
        let target = Arc::new(TargetContext::new());
        let service = SftpService::new(
            ssh,
            target.clone(),
            PortableOperationJournal::new(store.clone()),
        );
        let guard = target
            .activate(TargetIdentity::new("host-a").unwrap())
            .unwrap();
        let session =
            BoundSftpSession::from_status(guard, &status("missing-session", "host-a")).unwrap();
        let paths = PathGuard::for_store(&store, []).unwrap();
        let staged = paths.stage_upload(b"evidence").unwrap();
        let operation = service
            .plan_upload(
                &session,
                &paths,
                &staged,
                RemotePath::new("/tmp/evidence.bin").unwrap(),
            )
            .unwrap();
        assert!(staged.exists());
        drop(operation);
        assert!(!staged.exists());
        drop(service);
        let _ = std::fs::remove_dir_all(root);
    }

    /// Release VM SFTP contract.
    ///
    /// Requires `LOVELYRES_TEST_SSH_{HOST,PORT,USERNAME,PASSWORD,HOST_KEY}` and an existing,
    /// writable `LOVELYRES_TEST_SFTP_REMOTE_ROOT`. The test creates one UUID-named child below
    /// that root, exercises real bind/list/create/read/atomic-write/rename/chmod/archive/extract
    /// and restore traffic, then removes only that dedicated child. Missing fixtures are failures,
    /// never skips; the test remains ignored so the default suite never reaches the network.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "release gate: requires a real OpenSSH VM with SFTP and a disposable remote root"]
    async fn live_sftp_crud_atomic_restore_archive_matrix() -> CoreResult<()> {
        fn required(name: &str) -> String {
            std::env::var(name)
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| {
                    panic!(
                        "{name} is required; run this ignored test only against the disposable SFTP release-gate VM"
                    )
                })
        }

        let host = required("LOVELYRES_TEST_SSH_HOST");
        let port = required("LOVELYRES_TEST_SSH_PORT")
            .parse::<u16>()
            .expect("LOVELYRES_TEST_SSH_PORT must be a non-zero u16");
        assert_ne!(port, 0, "LOVELYRES_TEST_SSH_PORT must be non-zero");
        let username = required("LOVELYRES_TEST_SSH_USERNAME");
        let password = required("LOVELYRES_TEST_SSH_PASSWORD");
        let fingerprint = required("LOVELYRES_TEST_SSH_HOST_KEY");
        let remote_parent = RemotePath::new(required("LOVELYRES_TEST_SFTP_REMOTE_ROOT"))?;
        assert_ne!(
            remote_parent.as_str(),
            "/",
            "LOVELYRES_TEST_SFTP_REMOTE_ROOT must be a dedicated writable directory, not /"
        );
        let remote_root = remote_parent.child(&format!("lovelyres-sftp-{}", Uuid::new_v4()))?;
        let remote_file = remote_root.child("probe.txt")?;
        let renamed_file = remote_root.child("renamed.txt")?;
        let archive_file = remote_root.child("probe.tar")?;
        let extracted_directory = remote_root.child("probe-extracted")?;
        let extracted_modification = extracted_directory.child("post-extract.txt")?;

        let local_root =
            std::env::temp_dir().join(format!("lovelyres-sftp-contract-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&local_root)
            .map_err(|source| CoreError::io("create live SFTP test root", &local_root, source))?;
        let store = PortableStore::prepare(local_root.clone())?;
        let crypto = Arc::new(CryptoVault::load(&store)?);
        let connections = ConnectionRepository::new(store.clone(), crypto);
        let connection_id = "live-sftp-contract";
        connections.upsert(
            ConnectionConfig {
                id: connection_id.to_owned(),
                name: "Release VM SFTP contract".to_owned(),
                host,
                port,
                username,
                auth_method: SshAuthMethod::Password,
                private_key_path: None,
                certificate_path: None,
                agent_identity_fingerprint: None,
                jump_host: None,
                tags: BTreeSet::new(),
                notes: Some("disposable release-gate VM only".to_owned()),
                environment: Some("release-vm".to_owned()),
                role: Some("sftp-contract".to_owned()),
                group: None,
                host_key_fingerprint: Some(fingerprint),
            },
            ConnectionSecretChanges {
                password: SecretChange::Replace(SecretValue::new(password)),
                ..ConnectionSecretChanges::default()
            },
        )?;

        let ssh = SshService::new(store.clone(), connections)?;
        let status = ssh
            .connect(connection_id, HostKeyConfirmations::default())
            .await?;
        let target = Arc::new(TargetContext::new());
        let guard = target.activate(TargetIdentity::new(connection_id)?)?;
        let bound_ssh = ssh.bind_session(guard.clone(), &status.session_id).await?;
        let sftp = SftpService::new(
            ssh.clone(),
            target.clone(),
            PortableOperationJournal::new(store),
        );
        let bound_sftp = sftp.bind_session(guard, &status.session_id).await?;

        let matrix_result: CoreResult<()> = async {
            let mut create_root = sftp.plan(
                &bound_sftp,
                SftpMutation::CreateDirectory {
                    path: remote_root.clone(),
                },
            )?;
            create_root.confirm(DangerousConfirmation::approve(create_root.definition()))?;
            assert!(create_root.execute_and_verify().await?.passed);
            let _initial_listing = sftp.list(&bound_sftp, &remote_root).await?;
            let mut create_file = sftp.plan(
                &bound_sftp,
                SftpMutation::CreateFile {
                    path: remote_file.clone(),
                    content: b"original".to_vec(),
                    mode: None,
                },
            )?;
            create_file.confirm(DangerousConfirmation::approve(create_file.definition()))?;
            assert!(create_file.execute_and_verify().await?.passed);
            assert_eq!(
                sftp.read_file(&bound_sftp, &remote_file).await?,
                b"original"
            );
            let entries = sftp.list(&bound_sftp, &remote_root).await?;
            assert!(entries.iter().any(|entry| entry.path == remote_file));

            let original_mode = sftp
                .metadata(&bound_sftp, &remote_file, false)
                .await?
                .permissions
                .expect("OpenSSH SFTP must report POSIX permission bits")
                & 0o7777;

            let mut atomic = sftp.plan(
                &bound_sftp,
                SftpMutation::AtomicWriteIfMatch {
                    path: remote_file.clone(),
                    expected_sha256: content_sha256(b"original"),
                    expected_canonical_path: None,
                    backup_directory: None,
                    content: b"updated".to_vec(),
                },
            )?;
            atomic.confirm(DangerousConfirmation::approve(atomic.definition()))?;
            assert!(atomic.execute_and_verify().await?.passed);
            assert_eq!(sftp.read_file(&bound_sftp, &remote_file).await?, b"updated");
            atomic.restore().await?;
            assert_eq!(
                sftp.read_file(&bound_sftp, &remote_file).await?,
                b"original"
            );

            let mut rename = sftp.plan(
                &bound_sftp,
                SftpMutation::Rename {
                    from: remote_file.clone(),
                    to: renamed_file.clone(),
                },
            )?;
            rename.confirm(DangerousConfirmation::approve(rename.definition()))?;
            assert!(rename.execute_and_verify().await?.passed);
            assert_eq!(
                sftp.read_file(&bound_sftp, &renamed_file).await?,
                b"original"
            );
            rename.restore().await?;
            assert_eq!(
                sftp.read_file(&bound_sftp, &remote_file).await?,
                b"original"
            );

            let changed_mode = if original_mode == 0o640 { 0o600 } else { 0o640 };
            let mut chmod = sftp.plan(
                &bound_sftp,
                SftpMutation::Chmod {
                    path: remote_file.clone(),
                    mode: changed_mode,
                },
            )?;
            chmod.confirm(DangerousConfirmation::approve(chmod.definition()))?;
            assert!(chmod.execute_and_verify().await?.passed);
            chmod.restore().await?;
            assert_eq!(
                sftp.metadata(&bound_sftp, &remote_file, false)
                    .await?
                    .permissions
                    .expect("restored file must report permission bits")
                    & 0o7777,
                original_mode
            );

            let mut archive = sftp.plan(
                &bound_sftp,
                SftpMutation::CreateArchive {
                    sources: vec![remote_file.clone()],
                    destination: archive_file.clone(),
                    format: ArchiveFormat::Tar,
                },
            )?;
            archive.confirm(DangerousConfirmation::approve(archive.definition()))?;
            assert!(archive.execute_and_verify().await?.passed);
            let archive_metadata = sftp.metadata(&bound_sftp, &archive_file, false).await?;
            assert_eq!(archive_metadata.kind, SftpFileKind::File);
            assert!(archive_metadata.size > 0);

            let mut extraction = sftp
                .plan_extract(
                    &bound_sftp,
                    archive_file.clone(),
                    extracted_directory.clone(),
                )
                .await?;
            extraction.confirm(DangerousConfirmation::approve(extraction.definition()))?;
            assert!(extraction.execute_and_verify().await?.passed);
            assert_eq!(
                sftp.metadata(&bound_sftp, &extracted_directory, false)
                    .await?
                    .kind,
                SftpFileKind::Directory
            );
            let mut modification = sftp.plan(
                &bound_sftp,
                SftpMutation::CreateFile {
                    path: extracted_modification.clone(),
                    content: b"post-extract modification".to_vec(),
                    mode: Some(0o600),
                },
            )?;
            modification.confirm(DangerousConfirmation::approve(modification.definition()))?;
            assert!(modification.execute_and_verify().await?.passed);
            assert!(extraction.restore().await.is_err());
            assert!(sftp.exists(&bound_sftp, &extracted_directory).await?);
            assert!(sftp.exists(&bound_sftp, &extracted_modification).await?);
            modification.restore().await?;
            extraction.restore().await?;
            assert!(!sftp.exists(&bound_sftp, &extracted_directory).await?);

            archive.restore().await?;
            assert!(!sftp.exists(&bound_sftp, &archive_file).await?);
            Ok(())
        }
        .await;

        let quoted_root = shq(remote_root.as_str());
        let cleanup_result = ssh
            .execute_bound(
                &bound_ssh,
                format!("rm -rf -- {quoted_root} && test ! -e {quoted_root}"),
                Duration::from_secs(15),
            )
            .await;
        let disconnect_result = ssh.disconnect(&status.session_id).await;
        matrix_result?;
        let cleanup = cleanup_result?;
        if cleanup.timed_out || cleanup.exit_code != Some(0) {
            return Err(CoreError::ssh(
                "release VM SFTP cleanup",
                "dedicated remote test directory was not removed",
            ));
        }
        disconnect_result?;
        drop(sftp);
        drop(ssh);
        let _ = std::fs::remove_dir_all(local_root);
        Ok(())
    }
}
