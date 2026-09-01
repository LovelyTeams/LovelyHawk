//! Typed SSH connection persistence with redacted public views.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::crypto::{CryptoVault, SecretValue, is_encrypted};
use crate::operations::{
    DangerousConfirmation, ExecutionReceipt, OperationExecutor, OperationJournal, OperationPlan,
    OperationState, PlannedOperation, VerificationResult,
};
use crate::shell_escape::is_valid_username;
use crate::store::StoreFile;
use crate::target::{TargetContext, TargetGuard, TargetIdentity};
use crate::{CoreError, CoreResult, PortableStore};

const CONNECTION_EXPORT_FORMAT: &str = "lovelyres-connections";
const CONNECTION_EXPORT_SCHEMA_VERSION: u32 = 1;
const MAX_CONNECTION_IMPORT_BYTES: usize = 2 * 1024 * 1024;
const MAX_CONNECTION_IMPORT_ENTRIES: usize = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SshAuthMethod {
    Password,
    KeyboardInteractive,
    PublicKey,
    Agent,
    Certificate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JumpHostConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_method: SshAuthMethod,
    pub private_key_path: Option<PathBuf>,
    pub certificate_path: Option<PathBuf>,
    pub agent_identity_fingerprint: Option<String>,
    pub host_key_fingerprint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionConfig {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_method: SshAuthMethod,
    pub private_key_path: Option<PathBuf>,
    pub certificate_path: Option<PathBuf>,
    pub agent_identity_fingerprint: Option<String>,
    pub jump_host: Option<JumpHostConfig>,
    pub tags: BTreeSet<String>,
    pub notes: Option<String>,
    pub environment: Option<String>,
    pub role: Option<String>,
    pub group: Option<String>,
    pub host_key_fingerprint: Option<String>,
}

impl ConnectionConfig {
    pub fn validate(&self) -> CoreResult<()> {
        validate_id(&self.id)?;
        validate_label("connection name", &self.name, 256)?;
        validate_host(&self.host)?;
        if self.port == 0 {
            return Err(CoreError::validation("SSH port", "must be non-zero"));
        }
        if !is_valid_username(&self.username) {
            return Err(CoreError::validation(
                "SSH username",
                "must be a valid Linux account name",
            ));
        }
        if let Some(jump) = &self.jump_host {
            validate_host(&jump.host)?;
            if jump.port == 0 || !is_valid_username(&jump.username) {
                return Err(CoreError::validation(
                    "jump host",
                    "port and username must be valid",
                ));
            }
        }
        for tag in &self.tags {
            validate_label("connection tag", tag, 64)?;
        }
        Ok(())
    }
}

/// Credential-free object returned to the native UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionView {
    pub config: ConnectionConfig,
    pub has_password: bool,
    pub has_key_passphrase: bool,
    pub jump_host_has_password: bool,
    pub jump_host_has_key_passphrase: bool,
    pub last_connected_at: Option<DateTime<Utc>>,
}

/// A write-only secret change. Its debug representation remains redacted.
#[derive(Debug)]
pub enum SecretChange {
    Keep,
    Replace(SecretValue),
    Remove,
}

#[derive(Debug)]
pub struct ConnectionSecretChanges {
    pub password: SecretChange,
    pub key_passphrase: SecretChange,
    pub jump_host_password: SecretChange,
    pub jump_host_key_passphrase: SecretChange,
}

impl Default for ConnectionSecretChanges {
    fn default() -> Self {
        Self {
            password: SecretChange::Keep,
            key_passphrase: SecretChange::Keep,
            jump_host_password: SecretChange::Keep,
            jump_host_key_passphrase: SecretChange::Keep,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredConnection {
    config: ConnectionConfig,
    encrypted_password: Option<String>,
    encrypted_key_passphrase: Option<String>,
    encrypted_jump_host_password: Option<String>,
    encrypted_jump_host_key_passphrase: Option<String>,
    last_connected_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct StoredConnections {
    connections: Vec<StoredConnection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectionExportDocument {
    format: String,
    schema_version: u32,
    exported_at: DateTime<Utc>,
    connections: Vec<ConnectionExportEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectionExportEntry {
    name: String,
    host: String,
    port: u16,
    username: String,
    auth_method: SshAuthMethod,
    private_key_path: Option<PathBuf>,
    certificate_path: Option<PathBuf>,
    agent_identity_fingerprint: Option<String>,
    jump_host: Option<ConnectionExportJumpHost>,
    tags: BTreeSet<String>,
    notes: Option<String>,
    environment: Option<String>,
    role: Option<String>,
    group: Option<String>,
    host_key_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectionExportJumpHost {
    host: String,
    port: u16,
    username: String,
    auth_method: SshAuthMethod,
    private_key_path: Option<PathBuf>,
    certificate_path: Option<PathBuf>,
    agent_identity_fingerprint: Option<String>,
    host_key_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionImportSummary {
    pub imported: usize,
    pub skipped_existing: usize,
    pub skipped_duplicate: usize,
}

#[derive(Debug)]
#[allow(dead_code)] // handed to the russh service when that domain is extracted
pub(crate) struct ResolvedConnection {
    pub config: ConnectionConfig,
    pub password: Option<SecretValue>,
    pub key_passphrase: Option<SecretValue>,
    pub jump_host_password: Option<SecretValue>,
    pub jump_host_key_passphrase: Option<SecretValue>,
}

/// Immutable, process-local credentials for testing an unsaved connection.
///
/// Secrets remain sealed with the portable vault between authentication
/// attempts so host-key and keyboard-interactive retries never require the UI
/// to retain plaintext values.
#[derive(Clone)]
pub struct ConnectionProbePlan {
    stored: StoredConnection,
    crypto: Arc<CryptoVault>,
    base_execution_digest: Option<String>,
}

impl fmt::Debug for ConnectionProbePlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionProbePlan")
            .field("connection_id", &self.stored.config.id)
            .field("host", &self.stored.config.host)
            .field("port", &self.stored.config.port)
            .field("username", &self.stored.config.username)
            .finish_non_exhaustive()
    }
}

impl ConnectionProbePlan {
    pub fn connection_id(&self) -> &str {
        &self.stored.config.id
    }

    pub fn config(&self) -> &ConnectionConfig {
        &self.stored.config
    }

    pub(crate) fn resolve_for_backend(&self) -> CoreResult<ResolvedConnection> {
        resolve_stored(&self.crypto, self.stored.clone())
    }

    pub(crate) fn with_verified_host_keys(
        mut self,
        target_fingerprint: &str,
        jump_host_fingerprint: Option<&str>,
    ) -> CoreResult<Self> {
        validate_host_key_fingerprint(target_fingerprint)?;
        if self
            .stored
            .config
            .host_key_fingerprint
            .as_deref()
            .is_some_and(|expected| expected != target_fingerprint)
        {
            return Err(CoreError::validation(
                "SSH connection probe",
                "the observed target host key does not match the probe plan",
            ));
        }
        self.stored.config.host_key_fingerprint = Some(target_fingerprint.to_owned());
        if let Some(fingerprint) = jump_host_fingerprint {
            validate_host_key_fingerprint(fingerprint)?;
            let jump = self.stored.config.jump_host.as_mut().ok_or_else(|| {
                CoreError::validation(
                    "SSH connection probe",
                    "a jump-host fingerprint was supplied for a plan without a jump host",
                )
            })?;
            if jump
                .host_key_fingerprint
                .as_deref()
                .is_some_and(|expected| expected != fingerprint)
            {
                return Err(CoreError::validation(
                    "SSH connection probe",
                    "the observed jump-host key does not match the probe plan",
                ));
            }
            jump.host_key_fingerprint = Some(fingerprint.to_owned());
        }
        Ok(self)
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionRepository {
    store: PortableStore,
    crypto: Arc<CryptoVault>,
    lock: Arc<Mutex<()>>,
    local_target: Arc<TargetContext>,
    local_guard: TargetGuard,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionDeletePlan {
    connection_id: String,
    connection_name: String,
    snapshot_digest: String,
    operation: OperationPlan,
}

impl ConnectionDeletePlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }

    pub fn connection_name(&self) -> &str {
        &self.connection_name
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionDeleteOutcome {
    pub operation_id: String,
    pub verification: VerificationResult,
}

#[derive(Debug)]
struct ConnectionDeleteExecutor {
    repository: ConnectionRepository,
    connection_id: String,
    snapshot_digest: String,
}

#[async_trait]
impl OperationExecutor for ConnectionDeleteExecutor {
    async fn execute(&self, _plan: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        self.repository
            .remove_if_unchanged(&self.connection_id, &self.snapshot_digest)?;
        Ok(ExecutionReceipt {
            summary: "permanently deleted one portable SSH connection and its stored credentials"
                .to_owned(),
            restore_token: None,
        })
    }

    async fn verify(
        &self,
        _plan: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        let absent = self.repository.get(&self.connection_id)?.is_none();
        Ok(VerificationResult {
            passed: absent,
            detail: if absent {
                "verified that the portable SSH connection no longer exists".to_owned()
            } else {
                "the portable SSH connection still exists after deletion".to_owned()
            },
        })
    }

    async fn restore(&self, _plan: &OperationPlan, _receipt: &ExecutionReceipt) -> CoreResult<()> {
        Err(CoreError::Unsupported {
            feature: "restoring a permanently deleted SSH connection",
        })
    }
}

impl ConnectionRepository {
    pub fn new(store: PortableStore, crypto: Arc<CryptoVault>) -> Self {
        let local_target = Arc::new(TargetContext::new());
        let local_identity = TargetIdentity::new("portable-connections")
            .expect("the static portable connection target identity is valid");
        let local_guard = local_target
            .activate(local_identity)
            .expect("a fresh local target generation is available");
        Self {
            store,
            crypto,
            lock: Arc::new(Mutex::new(())),
            local_target,
            local_guard,
        }
    }

    pub fn list(&self) -> CoreResult<Vec<ConnectionView>> {
        let _guard = self.lock.lock();
        Ok(self
            .load_locked()?
            .connections
            .into_iter()
            .map(ConnectionView::from)
            .collect())
    }

    pub fn get(&self, id: &str) -> CoreResult<Option<ConnectionView>> {
        let _guard = self.lock.lock();
        Ok(self
            .load_locked()?
            .connections
            .into_iter()
            .find(|connection| connection.config.id == id)
            .map(ConnectionView::from))
    }

    pub fn write_new_export(&self, destination: &Path) -> CoreResult<usize> {
        validate_connection_document_path(destination, "connection export destination")?;
        let entries = {
            let _guard = self.lock.lock();
            let stored = self.load_locked()?;
            if stored.connections.len() > MAX_CONNECTION_IMPORT_ENTRIES {
                return Err(CoreError::validation(
                    "connection export",
                    format!(
                        "contains {} connections; the maximum is {MAX_CONNECTION_IMPORT_ENTRIES}",
                        stored.connections.len()
                    ),
                ));
            }
            stored
                .connections
                .iter()
                .map(|connection| ConnectionExportEntry::from(&connection.config))
                .collect::<Vec<_>>()
        };
        for entry in &entries {
            entry.validate()?;
        }
        let count = entries.len();
        let document = ConnectionExportDocument {
            format: CONNECTION_EXPORT_FORMAT.to_owned(),
            schema_version: CONNECTION_EXPORT_SCHEMA_VERSION,
            exported_at: Utc::now(),
            connections: entries,
        };
        let bytes = serde_json::to_vec_pretty(&document).map_err(|source| CoreError::Encode {
            subject: "SSH connection export",
            source,
        })?;
        if bytes.len() > MAX_CONNECTION_IMPORT_BYTES {
            return Err(CoreError::validation(
                "connection export",
                format!(
                    "encoded document is {} bytes; the maximum is {MAX_CONNECTION_IMPORT_BYTES}",
                    bytes.len()
                ),
            ));
        }

        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(destination)
            .map_err(|source| CoreError::io("create SSH connection export", destination, source))?;
        let write_result = (|| {
            file.write_all(&bytes).map_err(|source| {
                CoreError::io("write SSH connection export", destination, source)
            })?;
            file.flush().map_err(|source| {
                CoreError::io("flush SSH connection export", destination, source)
            })?;
            file.sync_all()
                .map_err(|source| CoreError::io("sync SSH connection export", destination, source))
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(destination);
        }
        write_result.map(|()| count)
    }

    pub fn import_file(&self, source: &Path) -> CoreResult<ConnectionImportSummary> {
        validate_connection_document_path(source, "connection import source")?;
        let mut file = File::open(source)
            .map_err(|error| CoreError::io("open SSH connection import", source, error))?;
        let metadata = file
            .metadata()
            .map_err(|error| CoreError::io("inspect SSH connection import", source, error))?;
        if !metadata.is_file() {
            return Err(CoreError::validation(
                "connection import source",
                "must be a regular JSON file",
            ));
        }
        if metadata.len() > MAX_CONNECTION_IMPORT_BYTES as u64 {
            return Err(CoreError::validation(
                "connection import source",
                format!(
                    "file is {} bytes; the maximum is {MAX_CONNECTION_IMPORT_BYTES}",
                    metadata.len()
                ),
            ));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        Read::by_ref(&mut file)
            .take((MAX_CONNECTION_IMPORT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| CoreError::io("read SSH connection import", source, error))?;
        if bytes.len() > MAX_CONNECTION_IMPORT_BYTES {
            return Err(CoreError::validation(
                "connection import source",
                format!("file exceeds the {MAX_CONNECTION_IMPORT_BYTES}-byte limit"),
            ));
        }
        let document: ConnectionExportDocument =
            serde_json::from_slice(&bytes).map_err(|source| CoreError::Decode {
                subject: "SSH connection import",
                source,
            })?;
        if document.format != CONNECTION_EXPORT_FORMAT {
            return Err(CoreError::validation(
                "connection import format",
                format!(
                    "expected {CONNECTION_EXPORT_FORMAT}, got {}",
                    document.format
                ),
            ));
        }
        if document.schema_version != CONNECTION_EXPORT_SCHEMA_VERSION {
            return Err(CoreError::UnsupportedSchema {
                document: "SSH connection import",
                expected: CONNECTION_EXPORT_SCHEMA_VERSION,
                actual: document.schema_version,
            });
        }
        if document.connections.len() > MAX_CONNECTION_IMPORT_ENTRIES {
            return Err(CoreError::validation(
                "connection import",
                format!(
                    "contains {} connections; the maximum is {MAX_CONNECTION_IMPORT_ENTRIES}",
                    document.connections.len()
                ),
            ));
        }
        for entry in &document.connections {
            entry.validate()?;
        }

        let _guard = self.lock.lock();
        let mut stored = self.load_locked()?;
        let existing_endpoints = stored
            .connections
            .iter()
            .map(|connection| ConnectionEndpoint::from(&connection.config))
            .collect::<BTreeSet<_>>();
        let mut imported_endpoints = BTreeSet::new();
        let mut ids = stored
            .connections
            .iter()
            .map(|connection| connection.config.id.clone())
            .collect::<BTreeSet<_>>();
        let mut summary = ConnectionImportSummary {
            imported: 0,
            skipped_existing: 0,
            skipped_duplicate: 0,
        };
        for entry in document.connections {
            let endpoint = ConnectionEndpoint::from(&entry);
            if existing_endpoints.contains(&endpoint) {
                summary.skipped_existing += 1;
                continue;
            }
            if !imported_endpoints.insert(endpoint) {
                summary.skipped_duplicate += 1;
                continue;
            }
            let id = next_connection_id(&mut ids);
            stored.connections.push(StoredConnection {
                config: entry.into_config(id),
                encrypted_password: None,
                encrypted_key_passphrase: None,
                encrypted_jump_host_password: None,
                encrypted_jump_host_key_passphrase: None,
                last_connected_at: None,
            });
            summary.imported += 1;
        }
        if summary.imported > 0 {
            stored
                .connections
                .sort_by(|left, right| left.config.name.cmp(&right.config.name));
            self.store.write(StoreFile::Connections, &stored)?;
        }
        Ok(summary)
    }

    pub fn upsert(
        &self,
        config: ConnectionConfig,
        changes: ConnectionSecretChanges,
    ) -> CoreResult<ConnectionView> {
        config.validate()?;
        let _guard = self.lock.lock();
        let mut stored = self.load_locked()?;
        let existing_index = stored
            .connections
            .iter()
            .position(|connection| connection.config.id == config.id);
        let existing = existing_index.map(|index| stored.connections.remove(index));
        let connection = connection_with_changes(&self.crypto, existing, config, changes)?;
        let view = ConnectionView::from(connection.clone());
        stored.connections.push(connection);
        stored
            .connections
            .sort_by(|left, right| left.config.name.cmp(&right.config.name));
        self.store.write(StoreFile::Connections, &stored)?;
        Ok(view)
    }

    /// Builds an immutable test snapshot without writing the connection store.
    pub fn prepare_probe(
        &self,
        config: ConnectionConfig,
        changes: ConnectionSecretChanges,
    ) -> CoreResult<ConnectionProbePlan> {
        config.validate()?;
        let _guard = self.lock.lock();
        let existing = self
            .load_locked()?
            .connections
            .into_iter()
            .find(|connection| connection.config.id == config.id);
        let base_execution_digest = existing
            .as_ref()
            .map(connection_execution_digest)
            .transpose()?;
        let stored = connection_with_changes(&self.crypto, existing, config, changes)?;
        Ok(ConnectionProbePlan {
            stored,
            crypto: self.crypto.clone(),
            base_execution_digest,
        })
    }

    /// Commits exactly the successfully tested snapshot. A concurrent edit,
    /// deletion, or colliding new ID invalidates the plan instead of merging it.
    pub fn commit_probe(&self, mut plan: ConnectionProbePlan) -> CoreResult<ConnectionView> {
        plan.stored.config.validate()?;
        let _guard = self.lock.lock();
        let mut stored = self.load_locked()?;
        let existing_index = stored
            .connections
            .iter()
            .position(|connection| connection.config.id == plan.stored.config.id);
        match (plan.base_execution_digest.as_deref(), existing_index) {
            (None, None) => {}
            (Some(expected), Some(index))
                if connection_execution_digest(&stored.connections[index])? == expected =>
            {
                plan.stored.last_connected_at = stored.connections[index].last_connected_at;
                stored.connections.remove(index);
            }
            _ => {
                return Err(CoreError::validation(
                    "SSH connection probe",
                    "the saved connection changed after it was tested; test the current draft again",
                ));
            }
        }
        let view = ConnectionView::from(plan.stored.clone());
        stored.connections.push(plan.stored);
        stored
            .connections
            .sort_by(|left, right| left.config.name.cmp(&right.config.name));
        self.store.write(StoreFile::Connections, &stored)?;
        Ok(view)
    }

    pub fn plan_delete(&self, id: &str) -> CoreResult<ConnectionDeletePlan> {
        let (connection, snapshot_digest) = self.snapshot_for_delete(id)?;
        let mut operation = OperationPlan::new(
            self.local_guard.clone(),
            format!(
                "永久删除 SSH 连接“{}”及其已保存凭据；此操作不可恢复。",
                connection.config.name
            ),
            true,
            None,
        )?;
        operation
            .metadata
            .insert("connection-id".to_owned(), connection.config.id.clone());
        operation.metadata.insert(
            "connection-snapshot-sha256".to_owned(),
            snapshot_digest.clone(),
        );
        Ok(ConnectionDeletePlan {
            connection_id: connection.config.id,
            connection_name: connection.config.name,
            snapshot_digest,
            operation,
        })
    }

    pub async fn execute_delete(
        &self,
        plan: ConnectionDeletePlan,
        confirmation: DangerousConfirmation,
        journal: &dyn OperationJournal,
    ) -> CoreResult<ConnectionDeleteOutcome> {
        let operation_id = plan.operation.id.clone();
        let executor = ConnectionDeleteExecutor {
            repository: self.clone(),
            connection_id: plan.connection_id,
            snapshot_digest: plan.snapshot_digest,
        };
        let mut operation = PlannedOperation::plan(plan.operation);
        operation.confirm(confirmation)?;
        if let Err(error) = operation
            .execute(self.local_target.as_ref(), &executor)
            .await
        {
            if operation.state() == OperationState::StaleAfterExecution {
                operation.journal(journal)?;
            }
            return Err(error);
        }
        operation.journal(journal)?;
        let verification = operation
            .verify(self.local_target.as_ref(), &executor, journal)
            .await?;
        if !verification.passed {
            return Err(CoreError::Validation {
                subject: "connection delete verification",
                message: verification.detail,
            });
        }
        Ok(ConnectionDeleteOutcome {
            operation_id,
            verification,
        })
    }

    fn remove_if_unchanged(&self, id: &str, expected_digest: &str) -> CoreResult<()> {
        let _guard = self.lock.lock();
        let mut stored = self.load_locked()?;
        let index = stored
            .connections
            .iter()
            .position(|connection| connection.config.id == id)
            .ok_or_else(|| CoreError::NotFound {
                entity: "connection",
                id: id.to_owned(),
            })?;
        if connection_snapshot_digest(&stored.connections[index])? != expected_digest {
            return Err(CoreError::validation(
                "connection delete plan",
                "the connection changed after confirmation was requested; create a new plan",
            ));
        }
        stored.connections.remove(index);
        self.store.write(StoreFile::Connections, &stored)?;
        Ok(())
    }

    fn snapshot_for_delete(&self, id: &str) -> CoreResult<(ConnectionView, String)> {
        let _guard = self.lock.lock();
        let stored = self
            .load_locked()?
            .connections
            .into_iter()
            .find(|connection| connection.config.id == id)
            .ok_or_else(|| CoreError::NotFound {
                entity: "connection",
                id: id.to_owned(),
            })?;
        let digest = connection_snapshot_digest(&stored)?;
        Ok((ConnectionView::from(stored), digest))
    }

    pub fn mark_connected(&self, id: &str, connected_at: DateTime<Utc>) -> CoreResult<()> {
        let _guard = self.lock.lock();
        let mut stored = self.load_locked()?;
        let connection = stored
            .connections
            .iter_mut()
            .find(|connection| connection.config.id == id)
            .ok_or_else(|| CoreError::NotFound {
                entity: "connection",
                id: id.to_owned(),
            })?;
        connection.last_connected_at = Some(connected_at);
        self.store.write(StoreFile::Connections, &stored)
    }

    pub(crate) fn compare_and_set_host_key_fingerprint(
        &self,
        id: &str,
        expected_host: &str,
        expected_port: u16,
        expected_username: &str,
        expected: Option<&str>,
        observed: &str,
    ) -> CoreResult<()> {
        validate_host_key_fingerprint(observed)?;
        let _guard = self.lock.lock();
        let mut stored = self.load_locked()?;
        let connection = stored
            .connections
            .iter_mut()
            .find(|connection| connection.config.id == id)
            .ok_or_else(|| CoreError::NotFound {
                entity: "connection",
                id: id.to_owned(),
            })?;
        if connection.config.host != expected_host
            || connection.config.port != expected_port
            || connection.config.username != expected_username
        {
            return Err(CoreError::validation(
                "SSH connection endpoint",
                "host, port, or username changed while the connection was in flight",
            ));
        }
        let current = connection.config.host_key_fingerprint.as_deref();
        if current == Some(observed) {
            return Ok(());
        }
        if current != expected {
            return Err(CoreError::validation(
                "SSH host key trust record",
                "connection was edited while host-key confirmation was in flight",
            ));
        }
        connection.config.host_key_fingerprint = Some(observed.to_owned());
        self.store.write(StoreFile::Connections, &stored)
    }

    #[allow(dead_code)] // credential resolution remains inaccessible to the UI-facing API
    pub(crate) fn resolve_for_backend(&self, id: &str) -> CoreResult<ResolvedConnection> {
        let _guard = self.lock.lock();
        let stored = self
            .load_locked()?
            .connections
            .into_iter()
            .find(|connection| connection.config.id == id)
            .ok_or_else(|| CoreError::NotFound {
                entity: "connection",
                id: id.to_owned(),
            })?;
        resolve_stored(&self.crypto, stored)
    }

    fn load_locked(&self) -> CoreResult<StoredConnections> {
        let stored = self
            .store
            .read_or_default::<StoredConnections>(StoreFile::Connections)?;
        let mut ids = BTreeSet::new();
        for connection in &stored.connections {
            connection.config.validate()?;
            if !ids.insert(connection.config.id.as_str()) {
                return Err(CoreError::validation(
                    "stored connections",
                    "connection ids must be unique",
                ));
            }
            for encrypted in [
                connection.encrypted_password.as_deref(),
                connection.encrypted_key_passphrase.as_deref(),
                connection.encrypted_jump_host_password.as_deref(),
                connection.encrypted_jump_host_key_passphrase.as_deref(),
            ]
            .into_iter()
            .flatten()
            {
                if !is_encrypted(encrypted) {
                    return Err(CoreError::validation(
                        "stored connection secret",
                        "must use the enc:v1 ciphertext format",
                    ));
                }
            }
        }
        Ok(stored)
    }
}

impl From<StoredConnection> for ConnectionView {
    fn from(stored: StoredConnection) -> Self {
        Self {
            config: stored.config,
            has_password: stored.encrypted_password.is_some(),
            has_key_passphrase: stored.encrypted_key_passphrase.is_some(),
            jump_host_has_password: stored.encrypted_jump_host_password.is_some(),
            jump_host_has_key_passphrase: stored.encrypted_jump_host_key_passphrase.is_some(),
            last_connected_at: stored.last_connected_at,
        }
    }
}

impl From<&ConnectionConfig> for ConnectionExportEntry {
    fn from(config: &ConnectionConfig) -> Self {
        Self {
            name: config.name.clone(),
            host: config.host.clone(),
            port: config.port,
            username: config.username.clone(),
            auth_method: config.auth_method,
            private_key_path: config.private_key_path.clone(),
            certificate_path: config.certificate_path.clone(),
            agent_identity_fingerprint: config.agent_identity_fingerprint.clone(),
            jump_host: config
                .jump_host
                .as_ref()
                .map(ConnectionExportJumpHost::from),
            tags: config.tags.clone(),
            notes: config.notes.clone(),
            environment: config.environment.clone(),
            role: config.role.clone(),
            group: config.group.clone(),
            host_key_fingerprint: config.host_key_fingerprint.clone(),
        }
    }
}

impl ConnectionExportEntry {
    fn into_config(self, id: String) -> ConnectionConfig {
        ConnectionConfig {
            id,
            name: self.name,
            host: self.host,
            port: self.port,
            username: self.username,
            auth_method: self.auth_method,
            private_key_path: self.private_key_path,
            certificate_path: self.certificate_path,
            agent_identity_fingerprint: self.agent_identity_fingerprint,
            jump_host: self.jump_host.map(ConnectionExportJumpHost::into_config),
            tags: self.tags,
            notes: self.notes,
            environment: self.environment,
            role: self.role,
            group: self.group,
            host_key_fingerprint: self.host_key_fingerprint,
        }
    }

    fn validate(&self) -> CoreResult<()> {
        let config = self.clone().into_config("import-validation".to_owned());
        config.validate()?;
        validate_connection_metadata(&config)
    }
}

impl From<&JumpHostConfig> for ConnectionExportJumpHost {
    fn from(config: &JumpHostConfig) -> Self {
        Self {
            host: config.host.clone(),
            port: config.port,
            username: config.username.clone(),
            auth_method: config.auth_method,
            private_key_path: config.private_key_path.clone(),
            certificate_path: config.certificate_path.clone(),
            agent_identity_fingerprint: config.agent_identity_fingerprint.clone(),
            host_key_fingerprint: config.host_key_fingerprint.clone(),
        }
    }
}

impl ConnectionExportJumpHost {
    fn into_config(self) -> JumpHostConfig {
        JumpHostConfig {
            host: self.host,
            port: self.port,
            username: self.username,
            auth_method: self.auth_method,
            private_key_path: self.private_key_path,
            certificate_path: self.certificate_path,
            agent_identity_fingerprint: self.agent_identity_fingerprint,
            host_key_fingerprint: self.host_key_fingerprint,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ConnectionEndpoint {
    host: String,
    port: u16,
    username: String,
}

impl From<&ConnectionConfig> for ConnectionEndpoint {
    fn from(config: &ConnectionConfig) -> Self {
        Self {
            host: config.host.to_ascii_lowercase(),
            port: config.port,
            username: config.username.clone(),
        }
    }
}

impl From<&ConnectionExportEntry> for ConnectionEndpoint {
    fn from(config: &ConnectionExportEntry) -> Self {
        Self {
            host: config.host.to_ascii_lowercase(),
            port: config.port,
            username: config.username.clone(),
        }
    }
}

fn next_connection_id(ids: &mut BTreeSet<String>) -> String {
    loop {
        let id = Uuid::new_v4().to_string();
        if ids.insert(id.clone()) {
            return id;
        }
    }
}

fn validate_connection_document_path(path: &Path, subject: &'static str) -> CoreResult<()> {
    if !path.is_absolute() {
        return Err(CoreError::validation(
            subject,
            "must be an absolute path selected by the user",
        ));
    }
    if !path
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
    {
        return Err(CoreError::validation(
            subject,
            "must use the .json extension",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| CoreError::validation(subject, "path has no parent directory"))?;
    if !parent.is_dir() {
        return Err(CoreError::validation(
            subject,
            "parent directory does not exist",
        ));
    }
    Ok(())
}

fn validate_connection_metadata(config: &ConnectionConfig) -> CoreResult<()> {
    validate_optional_path("private key path", config.private_key_path.as_deref())?;
    validate_optional_path("certificate path", config.certificate_path.as_deref())?;
    validate_optional_fingerprint(
        "SSH agent identity fingerprint",
        config.agent_identity_fingerprint.as_deref(),
    )?;
    validate_optional_fingerprint(
        "SSH host key fingerprint",
        config.host_key_fingerprint.as_deref(),
    )?;
    validate_optional_text("connection notes", config.notes.as_deref(), 16 * 1024, true)?;
    validate_optional_text(
        "connection environment",
        config.environment.as_deref(),
        256,
        false,
    )?;
    validate_optional_text("connection role", config.role.as_deref(), 256, false)?;
    validate_optional_text("connection group", config.group.as_deref(), 256, false)?;
    if let Some(jump) = &config.jump_host {
        validate_optional_path(
            "jump-host private key path",
            jump.private_key_path.as_deref(),
        )?;
        validate_optional_path(
            "jump-host certificate path",
            jump.certificate_path.as_deref(),
        )?;
        validate_optional_fingerprint(
            "jump-host agent identity fingerprint",
            jump.agent_identity_fingerprint.as_deref(),
        )?;
        validate_optional_fingerprint(
            "jump-host key fingerprint",
            jump.host_key_fingerprint.as_deref(),
        )?;
    }
    Ok(())
}

fn validate_optional_path(subject: &'static str, path: Option<&Path>) -> CoreResult<()> {
    let Some(path) = path else {
        return Ok(());
    };
    let value = path.to_string_lossy();
    if value.is_empty() || value.len() > 4_096 || value.contains('\0') {
        return Err(CoreError::validation(
            subject,
            "must be non-empty, at most 4096 bytes, and contain no NUL",
        ));
    }
    Ok(())
}

fn validate_optional_fingerprint(subject: &'static str, value: Option<&str>) -> CoreResult<()> {
    let Some(value) = value else {
        return Ok(());
    };
    validate_host_key_fingerprint(value)
        .map_err(|_| CoreError::validation(subject, "must use the SHA256: OpenSSH representation"))
}

fn validate_optional_text(
    subject: &'static str,
    value: Option<&str>,
    maximum: usize,
    multiline: bool,
) -> CoreResult<()> {
    let Some(value) = value else {
        return Ok(());
    };
    let has_forbidden_control = value.chars().any(|character| {
        character.is_control() && !(multiline && matches!(character, '\n' | '\r' | '\t'))
    });
    if value.len() > maximum || has_forbidden_control {
        return Err(CoreError::validation(
            subject,
            format!("must be at most {maximum} bytes and contain no unsupported controls"),
        ));
    }
    Ok(())
}

fn connection_snapshot_digest(connection: &StoredConnection) -> CoreResult<String> {
    let bytes = serde_json::to_vec(connection).map_err(|source| CoreError::Encode {
        subject: "connection delete snapshot",
        source,
    })?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn connection_execution_digest(connection: &StoredConnection) -> CoreResult<String> {
    let bytes = serde_json::to_vec(&(
        &connection.config,
        &connection.encrypted_password,
        &connection.encrypted_key_passphrase,
        &connection.encrypted_jump_host_password,
        &connection.encrypted_jump_host_key_passphrase,
    ))
    .map_err(|source| CoreError::Encode {
        subject: "connection execution snapshot",
        source,
    })?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn connection_with_changes(
    crypto: &CryptoVault,
    existing: Option<StoredConnection>,
    config: ConnectionConfig,
    changes: ConnectionSecretChanges,
) -> CoreResult<StoredConnection> {
    let mut connection = existing.unwrap_or_else(|| StoredConnection {
        config: config.clone(),
        encrypted_password: None,
        encrypted_key_passphrase: None,
        encrypted_jump_host_password: None,
        encrypted_jump_host_key_passphrase: None,
        last_connected_at: None,
    });
    connection.config = config;
    connection.encrypted_password =
        apply_secret_change(crypto, changes.password, connection.encrypted_password)?;
    connection.encrypted_key_passphrase = apply_secret_change(
        crypto,
        changes.key_passphrase,
        connection.encrypted_key_passphrase,
    )?;
    connection.encrypted_jump_host_password = apply_secret_change(
        crypto,
        changes.jump_host_password,
        connection.encrypted_jump_host_password,
    )?;
    connection.encrypted_jump_host_key_passphrase = apply_secret_change(
        crypto,
        changes.jump_host_key_passphrase,
        connection.encrypted_jump_host_key_passphrase,
    )?;
    Ok(connection)
}

fn resolve_stored(
    crypto: &CryptoVault,
    stored: StoredConnection,
) -> CoreResult<ResolvedConnection> {
    Ok(ResolvedConnection {
        config: stored.config,
        password: open_optional(crypto, stored.encrypted_password.as_deref())?,
        key_passphrase: open_optional(crypto, stored.encrypted_key_passphrase.as_deref())?,
        jump_host_password: open_optional(crypto, stored.encrypted_jump_host_password.as_deref())?,
        jump_host_key_passphrase: open_optional(
            crypto,
            stored.encrypted_jump_host_key_passphrase.as_deref(),
        )?,
    })
}

fn apply_secret_change(
    crypto: &CryptoVault,
    change: SecretChange,
    existing: Option<String>,
) -> CoreResult<Option<String>> {
    match change {
        SecretChange::Keep => Ok(existing),
        SecretChange::Remove => Ok(None),
        SecretChange::Replace(secret) if secret.is_empty() => Err(CoreError::validation(
            "connection secret",
            "must not be empty; use Remove to clear it",
        )),
        SecretChange::Replace(secret) => crypto.seal(&secret).map(Some),
    }
}

#[allow(dead_code)]
fn open_optional(crypto: &CryptoVault, encrypted: Option<&str>) -> CoreResult<Option<SecretValue>> {
    encrypted.map(|value| crypto.open(value)).transpose()
}

fn validate_id(value: &str) -> CoreResult<()> {
    if value.trim().is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(CoreError::validation(
            "connection id",
            "must be non-empty, at most 128 bytes, and contain no control characters",
        ));
    }
    Ok(())
}

fn validate_label(subject: &'static str, value: &str, maximum: usize) -> CoreResult<()> {
    if value.trim().is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(CoreError::validation(
            subject,
            format!("must be non-empty, at most {maximum} bytes, and contain no controls"),
        ));
    }
    Ok(())
}

fn validate_host(value: &str) -> CoreResult<()> {
    let valid = !value.is_empty()
        && value.len() <= 253
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'[' | b']')
        });
    if !valid {
        return Err(CoreError::validation(
            "SSH host",
            "must be an IP literal or ASCII hostname without whitespace or shell metacharacters",
        ));
    }
    Ok(())
}

fn validate_host_key_fingerprint(value: &str) -> CoreResult<()> {
    if !value.starts_with("SHA256:") || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(CoreError::validation(
            "SSH host key fingerprint",
            "must use the SHA256: OpenSSH representation",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use uuid::Uuid;

    use crate::operations::PortableOperationJournal;

    use super::*;

    #[derive(Debug)]
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("lovelyres-connections-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn config() -> ConnectionConfig {
        ConnectionConfig {
            id: "server-1".to_owned(),
            name: "Incident host".to_owned(),
            host: "10.0.0.8".to_owned(),
            port: 22,
            username: "root".to_owned(),
            auth_method: SshAuthMethod::Password,
            private_key_path: None,
            certificate_path: None,
            agent_identity_fingerprint: None,
            jump_host: None,
            tags: BTreeSet::from(["critical".to_owned()]),
            notes: None,
            environment: Some("competition".to_owned()),
            role: None,
            group: None,
            host_key_fingerprint: Some("SHA256:test".to_owned()),
        }
    }

    fn repository() -> (TestRoot, PortableStore, ConnectionRepository) {
        let root = TestRoot::new();
        let store = PortableStore::prepare(root.0.clone()).unwrap();
        let crypto = Arc::new(CryptoVault::load(&store).unwrap());
        let repository = ConnectionRepository::new(store.clone(), crypto);
        (root, store, repository)
    }

    #[test]
    fn public_views_never_contain_plaintext_or_ciphertext() {
        let (_root, store, repository) = repository();
        let view = repository
            .upsert(
                config(),
                ConnectionSecretChanges {
                    password: SecretChange::Replace(SecretValue::new("hunter2")),
                    ..ConnectionSecretChanges::default()
                },
            )
            .unwrap();
        assert!(view.has_password);
        assert!(!format!("{view:?}").contains("hunter2"));
        let raw = fs::read_to_string(store.path_for(StoreFile::Connections)).unwrap();
        assert!(!raw.contains("hunter2"));
        assert!(raw.contains("enc:v1:"));

        let resolved = repository.resolve_for_backend("server-1").unwrap();
        assert_eq!(resolved.password.unwrap().expose(), "hunter2");
    }

    #[test]
    fn probe_plan_reuses_sealed_secrets_without_persisting_the_draft() {
        let (_root, store, repository) = repository();
        repository
            .upsert(
                config(),
                ConnectionSecretChanges {
                    password: SecretChange::Replace(SecretValue::new("stored-password")),
                    key_passphrase: SecretChange::Replace(SecretValue::new("old-passphrase")),
                    ..ConnectionSecretChanges::default()
                },
            )
            .unwrap();
        let before = fs::read(store.path_for(StoreFile::Connections)).unwrap();

        let mut draft = config();
        draft.name = "Unsaved test draft".to_owned();
        draft.host = "10.0.0.9".to_owned();
        draft.host_key_fingerprint = None;
        let plan = repository
            .prepare_probe(
                draft.clone(),
                ConnectionSecretChanges {
                    password: SecretChange::Keep,
                    key_passphrase: SecretChange::Replace(SecretValue::new("draft-passphrase")),
                    jump_host_password: SecretChange::Remove,
                    jump_host_key_passphrase: SecretChange::Keep,
                },
            )
            .unwrap();

        assert_eq!(plan.connection_id(), "server-1");
        assert!(!format!("{plan:?}").contains("stored-password"));
        assert!(!format!("{plan:?}").contains("draft-passphrase"));
        for _ in 0..2 {
            let resolved = plan.resolve_for_backend().unwrap();
            assert_eq!(resolved.config, draft);
            assert_eq!(resolved.password.unwrap().expose(), "stored-password");
            assert_eq!(
                resolved.key_passphrase.unwrap().expose(),
                "draft-passphrase"
            );
            assert!(resolved.jump_host_password.is_none());
        }
        assert_eq!(
            repository.get("server-1").unwrap().unwrap().config,
            config()
        );
        assert_eq!(
            fs::read(store.path_for(StoreFile::Connections)).unwrap(),
            before
        );

        let concurrent_connected_at = Utc::now();
        repository
            .mark_connected("server-1", concurrent_connected_at)
            .unwrap();
        let plan = plan
            .with_verified_host_keys("SHA256:tested-probe", None)
            .unwrap();
        let mut verified_draft = draft;
        verified_draft.host_key_fingerprint = Some("SHA256:tested-probe".to_owned());
        let saved = repository.commit_probe(plan.clone()).unwrap();
        assert_eq!(saved.config, verified_draft);
        assert_eq!(saved.last_connected_at, Some(concurrent_connected_at));
        let resolved = repository.resolve_for_backend("server-1").unwrap();
        assert_eq!(resolved.password.unwrap().expose(), "stored-password");
        assert_eq!(
            resolved.key_passphrase.unwrap().expose(),
            "draft-passphrase"
        );
        let committed = fs::read(store.path_for(StoreFile::Connections)).unwrap();
        assert!(repository.commit_probe(plan).is_err());
        assert_eq!(
            fs::read(store.path_for(StoreFile::Connections)).unwrap(),
            committed
        );
    }

    #[test]
    fn non_secret_update_preserves_stored_secret_and_remove_clears_it() {
        let (_root, _store, repository) = repository();
        repository
            .upsert(
                config(),
                ConnectionSecretChanges {
                    password: SecretChange::Replace(SecretValue::new("secret")),
                    ..ConnectionSecretChanges::default()
                },
            )
            .unwrap();
        let mut changed = config();
        changed.name = "Renamed".to_owned();
        assert!(
            repository
                .upsert(changed.clone(), ConnectionSecretChanges::default())
                .unwrap()
                .has_password
        );
        assert!(
            !repository
                .upsert(
                    changed,
                    ConnectionSecretChanges {
                        password: SecretChange::Remove,
                        ..ConnectionSecretChanges::default()
                    },
                )
                .unwrap()
                .has_password
        );
    }

    #[test]
    fn rejects_shell_shaped_hosts_and_usernames() {
        let mut invalid = config();
        invalid.host = "host; rm -rf /".to_owned();
        assert!(invalid.validate().is_err());
        invalid = config();
        invalid.username = "root;id".to_owned();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn host_key_patch_preserves_concurrent_non_security_edits() {
        let (_root, _store, repository) = repository();
        repository
            .upsert(config(), ConnectionSecretChanges::default())
            .unwrap();

        let mut concurrently_edited = config();
        concurrently_edited.name = "Edited while connecting".to_owned();
        concurrently_edited.tags.insert("new-tag".to_owned());
        repository
            .upsert(concurrently_edited, ConnectionSecretChanges::default())
            .unwrap();

        repository
            .compare_and_set_host_key_fingerprint(
                "server-1",
                "10.0.0.8",
                22,
                "root",
                Some("SHA256:test"),
                "SHA256:observed",
            )
            .unwrap();
        let view = repository.get("server-1").unwrap().unwrap();
        assert_eq!(view.config.name, "Edited while connecting");
        assert!(view.config.tags.contains("new-tag"));
        assert_eq!(
            view.config.host_key_fingerprint.as_deref(),
            Some("SHA256:observed")
        );
    }

    #[test]
    fn host_key_patch_rejects_a_concurrent_pin_change() {
        let (_root, _store, repository) = repository();
        repository
            .upsert(config(), ConnectionSecretChanges::default())
            .unwrap();
        let mut concurrently_edited = config();
        concurrently_edited.host_key_fingerprint = Some("SHA256:other".to_owned());
        repository
            .upsert(concurrently_edited, ConnectionSecretChanges::default())
            .unwrap();

        assert!(
            repository
                .compare_and_set_host_key_fingerprint(
                    "server-1",
                    "10.0.0.8",
                    22,
                    "root",
                    Some("SHA256:test"),
                    "SHA256:test",
                )
                .is_err()
        );
        assert_eq!(
            repository
                .get("server-1")
                .unwrap()
                .unwrap()
                .config
                .host_key_fingerprint
                .as_deref(),
            Some("SHA256:other")
        );
    }

    #[test]
    fn host_key_patch_rejects_a_concurrent_endpoint_change() {
        let (_root, _store, repository) = repository();
        repository
            .upsert(config(), ConnectionSecretChanges::default())
            .unwrap();
        let mut concurrently_edited = config();
        concurrently_edited.host = "10.0.0.9".to_owned();
        repository
            .upsert(concurrently_edited, ConnectionSecretChanges::default())
            .unwrap();

        assert!(
            repository
                .compare_and_set_host_key_fingerprint(
                    "server-1",
                    "10.0.0.8",
                    22,
                    "root",
                    Some("SHA256:test"),
                    "SHA256:test",
                )
                .is_err()
        );
        assert_eq!(
            repository.get("server-1").unwrap().unwrap().config.host,
            "10.0.0.9"
        );
    }

    #[tokio::test]
    async fn connection_delete_requires_the_exact_plan_and_journals_verification() {
        let (_root, store, repository) = repository();
        repository
            .upsert(
                config(),
                ConnectionSecretChanges {
                    password: SecretChange::Replace(SecretValue::new("secret")),
                    ..ConnectionSecretChanges::default()
                },
            )
            .unwrap();
        let plan = repository.plan_delete("server-1").unwrap();
        let wrong_plan = repository.plan_delete("server-1").unwrap();
        let journal = PortableOperationJournal::new(store.clone());
        let before = fs::read(store.path_for(StoreFile::Connections)).unwrap();

        let error = repository
            .execute_delete(
                plan,
                DangerousConfirmation::approve(wrong_plan.definition()),
                &journal,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("different operation"));
        assert_eq!(
            fs::read(store.path_for(StoreFile::Connections)).unwrap(),
            before
        );
        assert!(journal.entries().unwrap().is_empty());

        let plan = repository.plan_delete("server-1").unwrap();
        let confirmation = DangerousConfirmation::approve(plan.definition());
        let outcome = repository
            .execute_delete(plan, confirmation, &journal)
            .await
            .unwrap();
        assert!(outcome.verification.passed);
        assert!(repository.get("server-1").unwrap().is_none());
        let entries = journal.entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].operation_id, outcome.operation_id);
        assert_eq!(entries[1].operation_id, outcome.operation_id);
    }

    #[tokio::test]
    async fn connection_delete_plan_rejects_a_concurrent_edit() {
        let (_root, store, repository) = repository();
        repository
            .upsert(config(), ConnectionSecretChanges::default())
            .unwrap();
        let plan = repository.plan_delete("server-1").unwrap();
        let confirmation = DangerousConfirmation::approve(plan.definition());

        let mut edited = config();
        edited.name = "Changed after confirmation opened".to_owned();
        repository
            .upsert(edited, ConnectionSecretChanges::default())
            .unwrap();
        let journal = PortableOperationJournal::new(store);
        let error = repository
            .execute_delete(plan, confirmation, &journal)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("changed after confirmation"));
        assert_eq!(
            repository.get("server-1").unwrap().unwrap().config.name,
            "Changed after confirmation opened"
        );
        assert!(journal.entries().unwrap().is_empty());

        let plan = repository.plan_delete("server-1").unwrap();
        let confirmation = DangerousConfirmation::approve(plan.definition());
        let same_public_config = repository.get("server-1").unwrap().unwrap().config;
        repository
            .upsert(
                same_public_config,
                ConnectionSecretChanges {
                    password: SecretChange::Replace(SecretValue::new("new secret")),
                    ..ConnectionSecretChanges::default()
                },
            )
            .unwrap();
        let error = repository
            .execute_delete(plan, confirmation, &journal)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("changed after confirmation"));
        assert!(repository.get("server-1").unwrap().unwrap().has_password);
        assert!(journal.entries().unwrap().is_empty());
    }

    #[test]
    fn jump_host_key_passphrase_is_stored_separately_and_stays_redacted() {
        let (root, store, repository) = repository();
        let mut connection = config();
        connection.jump_host = Some(JumpHostConfig {
            host: "jump.example.test".to_owned(),
            port: 22,
            username: "bastion".to_owned(),
            auth_method: SshAuthMethod::PublicKey,
            private_key_path: Some(root.0.join("jump-ed25519")),
            certificate_path: None,
            agent_identity_fingerprint: None,
            host_key_fingerprint: Some("SHA256:jump".to_owned()),
        });
        let view = repository
            .upsert(
                connection,
                ConnectionSecretChanges {
                    jump_host_key_passphrase: SecretChange::Replace(SecretValue::new(
                        "jump-key-secret",
                    )),
                    ..ConnectionSecretChanges::default()
                },
            )
            .unwrap();
        assert!(view.jump_host_has_key_passphrase);
        assert!(!view.jump_host_has_password);
        assert!(!format!("{view:?}").contains("jump-key-secret"));
        let resolved = repository.resolve_for_backend("server-1").unwrap();
        assert_eq!(
            resolved.jump_host_key_passphrase.unwrap().expose(),
            "jump-key-secret"
        );
        assert!(resolved.jump_host_password.is_none());
        let raw = fs::read_to_string(store.path_for(StoreFile::Connections)).unwrap();
        assert!(!raw.contains("jump-key-secret"));
        assert!(raw.contains("encrypted_jump_host_key_passphrase"));
        assert!(raw.contains("enc:v1:"));
    }

    #[test]
    fn export_omits_every_secret_and_import_assigns_a_fresh_identity() {
        let (source_root, _source_store, source) = repository();
        source
            .upsert(
                config(),
                ConnectionSecretChanges {
                    password: SecretChange::Replace(SecretValue::new("password-never-export")),
                    key_passphrase: SecretChange::Replace(SecretValue::new(
                        "key-passphrase-never-export",
                    )),
                    jump_host_password: SecretChange::Replace(SecretValue::new(
                        "jump-password-never-export",
                    )),
                    jump_host_key_passphrase: SecretChange::Replace(SecretValue::new(
                        "jump-key-passphrase-never-export",
                    )),
                },
            )
            .unwrap();
        let export_path = source_root.0.join("connections.json");
        assert_eq!(source.write_new_export(&export_path).unwrap(), 1);
        let exported = fs::read_to_string(&export_path).unwrap();
        for forbidden in [
            "password-never-export",
            "key-passphrase-never-export",
            "jump-password-never-export",
            "jump-key-passphrase-never-export",
            "enc:v1:",
            "encrypted_password",
            "last_connected_at",
            "\"id\"",
        ] {
            assert!(!exported.contains(forbidden), "leaked field {forbidden}");
        }
        assert!(exported.contains(CONNECTION_EXPORT_FORMAT));
        assert!(exported.contains("SHA256:test"));

        let (_target_root, _target_store, target) = repository();
        let summary = target.import_file(&export_path).unwrap();
        assert_eq!(summary.imported, 1);
        assert_eq!(summary.skipped_existing, 0);
        assert_eq!(summary.skipped_duplicate, 0);
        let imported = target.list().unwrap().pop().unwrap();
        assert_ne!(imported.config.id, "server-1");
        assert_eq!(
            imported.config.host_key_fingerprint.as_deref(),
            Some("SHA256:test")
        );
        assert!(!imported.has_password);
        assert!(!imported.has_key_passphrase);
        assert!(!imported.jump_host_has_password);
        assert!(!imported.jump_host_has_key_passphrase);

        let repeated = target.import_file(&export_path).unwrap();
        assert_eq!(repeated.imported, 0);
        assert_eq!(repeated.skipped_existing, 1);
        assert_eq!(target.list().unwrap().len(), 1);
    }

    #[test]
    fn import_rejects_secret_fields_and_invalid_batches_without_partial_writes() {
        let (source_root, _source_store, source) = repository();
        source
            .upsert(config(), ConnectionSecretChanges::default())
            .unwrap();
        let clean_path = source_root.0.join("clean.json");
        source.write_new_export(&clean_path).unwrap();
        let clean: serde_json::Value =
            serde_json::from_slice(&fs::read(&clean_path).unwrap()).unwrap();

        let (target_root, target_store, target) = repository();
        let mut existing = config();
        existing.id = "existing-target".to_owned();
        existing.host = "10.0.0.99".to_owned();
        target
            .upsert(existing, ConnectionSecretChanges::default())
            .unwrap();
        let before = fs::read(target_store.path_for(StoreFile::Connections)).unwrap();

        let mut injected = clean.clone();
        injected["connections"][0]["encrypted_password"] =
            serde_json::Value::String("enc:v1:attacker-controlled".to_owned());
        let injected_path = target_root.0.join("secret-field.json");
        fs::write(
            &injected_path,
            serde_json::to_vec_pretty(&injected).unwrap(),
        )
        .unwrap();
        assert!(target.import_file(&injected_path).is_err());
        assert_eq!(
            fs::read(target_store.path_for(StoreFile::Connections)).unwrap(),
            before
        );

        let mut invalid_batch = clean;
        let mut invalid = invalid_batch["connections"][0].clone();
        invalid["name"] = serde_json::Value::String("Invalid second entry".to_owned());
        invalid["host"] = serde_json::Value::String("host; touch /tmp/pwned".to_owned());
        invalid_batch["connections"]
            .as_array_mut()
            .unwrap()
            .push(invalid);
        let invalid_path = target_root.0.join("invalid-batch.json");
        fs::write(
            &invalid_path,
            serde_json::to_vec_pretty(&invalid_batch).unwrap(),
        )
        .unwrap();
        assert!(target.import_file(&invalid_path).is_err());
        assert_eq!(
            fs::read(target_store.path_for(StoreFile::Connections)).unwrap(),
            before
        );
        assert_eq!(target.list().unwrap().len(), 1);
    }

    #[test]
    fn import_deduplicates_endpoints_and_export_never_overwrites() {
        let (source_root, _source_store, source) = repository();
        source
            .upsert(config(), ConnectionSecretChanges::default())
            .unwrap();
        let export_path = source_root.0.join("connections.json");
        source.write_new_export(&export_path).unwrap();
        let original = fs::read(&export_path).unwrap();
        assert!(source.write_new_export(&export_path).is_err());
        assert_eq!(fs::read(&export_path).unwrap(), original);

        let mut duplicated: serde_json::Value = serde_json::from_slice(&original).unwrap();
        let mut second = duplicated["connections"][0].clone();
        second["name"] = serde_json::Value::String("Same endpoint, another label".to_owned());
        duplicated["connections"]
            .as_array_mut()
            .unwrap()
            .push(second);
        let duplicate_path = source_root.0.join("duplicates.json");
        fs::write(
            &duplicate_path,
            serde_json::to_vec_pretty(&duplicated).unwrap(),
        )
        .unwrap();

        let (_target_root, _target_store, target) = repository();
        let summary = target.import_file(&duplicate_path).unwrap();
        assert_eq!(summary.imported, 1);
        assert_eq!(summary.skipped_existing, 0);
        assert_eq!(summary.skipped_duplicate, 1);
        assert_eq!(target.list().unwrap().len(), 1);

        let oversized_path = source_root.0.join("oversized.json");
        fs::write(&oversized_path, vec![b'x'; MAX_CONNECTION_IMPORT_BYTES + 1]).unwrap();
        assert!(target.import_file(&oversized_path).is_err());
        assert_eq!(target.list().unwrap().len(), 1);
    }
}
