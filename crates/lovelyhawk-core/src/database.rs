//! Target-bound database inspection and planned administration.

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    future::Future,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use chrono::Utc;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{CryptoVault, SecretValue};
use crate::database_config::DatabaseConfigProduct;
use crate::database_config_inventory::{
    DatabaseConfigInventoryDocument, DatabaseConfigInventoryQueryPlan,
    DatabaseConfigInventorySurface, MAX_DATABASE_CONFIG_INVENTORY_TSV_BYTES,
    database_config_inventory_query_plan,
};
use crate::database_config_runtime::{
    DatabaseConfigRuntimeDocument, DatabaseConfigRuntimeEdition, DatabaseConfigRuntimeIdentity,
    DatabaseConfigRuntimeIdentityPlan, DatabaseConfigRuntimeQueryPlan,
    MAX_DATABASE_CONFIG_RUNTIME_IDENTITY_TSV_BYTES, MAX_DATABASE_CONFIG_RUNTIME_TSV_BYTES,
    database_config_runtime_identity_plan, database_config_runtime_query_plan,
};
use crate::domain::{CommandRunner, bounded_text};
use crate::operations::{
    DangerousConfirmation, ExecutionReceipt, OperationExecutor, OperationPlan, OperationState,
    PlannedOperation, PortableOperationJournal, VerificationResult,
};
use crate::postgresql_native::{NativeRuntimeRequest, PostgresqlTlsMode, PostgresqlTlsSettings};
use crate::shell_escape::{escape_sql_literal, is_valid_sql_ident, shq};
use crate::ssh::{
    BoundSshSession, SshCommandOutput, SshSensitiveCommandLimits, SshSensitiveCommandOutput,
    SshService,
};
use crate::store::StoreFile;
use crate::target::{TargetContext, TargetGuard, TargetIdentity};
use crate::{CoreError, CoreResult, PortableStore};

const MAX_SQL_BYTES: usize = 1_048_576;
const MAX_RESULT_ROWS: usize = 10_000;
const MAX_RESULT_CELL_CHARS: usize = 16_384;
const MAX_DATABASE_ITEMS: usize = 10_000;
const QUERY_TIMEOUT: Duration = Duration::from_secs(45);
const INSPECTION_TIMEOUT: Duration = Duration::from_secs(25);
const RUNTIME_IDENTITY_TIMEOUT: Duration = Duration::from_secs(10);
const INVENTORY_TIMEOUT: Duration = Duration::from_secs(25);
const RUNTIME_STDERR_BYTES: usize = 16 * 1024;
pub const MAX_DATABASE_PROFILES: usize = 256;
const MAX_PROFILE_STORE_BYTES: usize = 8 * 1024 * 1024;
const MAX_PROFILE_PASSWORD_BYTES: usize = 16 * 1024;
const MUTATION_TIMEOUT: Duration = Duration::from_secs(120);
const BACKUP_TIMEOUT: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DatabaseEngine {
    Mysql,
    Postgresql,
    Redis,
    Mongo,
    Dm,
    Kingbase,
}

impl DatabaseEngine {
    pub const ALL: [Self; 4] = [Self::Mysql, Self::Postgresql, Self::Redis, Self::Mongo];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Mysql => "MySQL / MariaDB",
            Self::Postgresql => "PostgreSQL",
            Self::Redis => "Redis",
            Self::Mongo => "MongoDB",
            Self::Dm => "DM (达梦)",
            Self::Kingbase => "KingBase",
        }
    }

    pub const fn default_port(self) -> u16 {
        match self {
            Self::Mysql => 3306,
            Self::Postgresql => 5432,
            Self::Redis => 6379,
            Self::Mongo => 27017,
            Self::Dm => 5236,
            Self::Kingbase => 54321,
        }
    }

    pub const fn supports_client(self) -> bool {
        matches!(
            self,
            Self::Mysql | Self::Postgresql | Self::Redis | Self::Mongo
        )
    }

    const fn service_names(self) -> &'static [&'static str] {
        match self {
            Self::Mysql => &["mysql", "mysqld", "mariadb"],
            Self::Postgresql => &["postgresql"],
            Self::Redis => &["redis", "redis-server"],
            Self::Mongo => &["mongod", "mongodb"],
            Self::Dm => &["DmServiceDMSERVER"],
            Self::Kingbase => &["kingbase"],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DatabaseConnection {
    pub engine: DatabaseEngine,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub database: Option<String>,
}

impl DatabaseConnection {
    pub fn validate(&self) -> CoreResult<()> {
        if self.host.is_empty()
            || self.host.len() > 253
            || !self.host.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'.' | b'-' | b'_' | b':' | b'[' | b']')
            })
        {
            return Err(CoreError::validation(
                "database host",
                "must be an ASCII hostname or IP literal",
            ));
        }
        if self.port == 0 {
            return Err(CoreError::validation("database port", "must be non-zero"));
        }
        if let Some(username) = &self.username {
            bounded_text("database username", username, 128)?;
        }
        if let Some(database) = &self.database {
            bounded_text("database name", database, 128)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DatabaseProfileConfig {
    pub id: String,
    pub name: String,
    pub connection: DatabaseConnection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postgresql_tls: Option<PostgresqlTlsSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_connection_id: Option<String>,
}

impl DatabaseProfileConfig {
    pub fn new(name: impl Into<String>, engine: DatabaseEngine) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.into(),
            postgresql_tls: None,
            ssh_connection_id: None,
            connection: DatabaseConnection {
                engine,
                host: "127.0.0.1".to_owned(),
                port: engine.default_port(),
                username: (!matches!(engine, DatabaseEngine::Redis)).then(|| {
                    if engine == DatabaseEngine::Postgresql {
                        "postgres"
                    } else {
                        "root"
                    }
                    .to_owned()
                }),
                database: None,
            },
        }
    }

    pub fn validate(&self) -> CoreResult<()> {
        validate_profile_id(&self.id)?;
        if let Some(id) = &self.ssh_connection_id {
            validate_profile_id(id)?;
        }
        bounded_text("database profile name", self.name.trim(), 256)?;
        if !self.connection.engine.supports_client() {
            return Err(CoreError::Unsupported {
                feature: "database client profiles for detection-only engines",
            });
        }
        self.connection.validate()?;
        if let Some(tls) = &self.postgresql_tls {
            tls.validate(&self.connection)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DatabaseProfileView {
    pub config: DatabaseProfileConfig,
    pub has_password: bool,
}

/// A portable configuration revision. The digest includes its encrypted
/// credential, but neither plaintext nor the digest is a renderer capability.
#[derive(Clone)]
pub struct DatabaseProfileSnapshot {
    view: DatabaseProfileView,
    digest: String,
}

impl std::fmt::Debug for DatabaseProfileSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatabaseProfileSnapshot")
            .field("has_password", &self.view.has_password)
            .finish_non_exhaustive()
    }
}

impl DatabaseProfileSnapshot {
    pub fn view(&self) -> &DatabaseProfileView {
        &self.view
    }

    pub fn same_revision(&self, other: &Self) -> bool {
        self.view.config.id == other.view.config.id && self.digest == other.digest
    }
}

enum ProfileExpectation<'a> {
    LegacyUpsert,
    Absent,
    Unchanged(&'a DatabaseProfileSnapshot),
}

#[derive(Debug)]
pub enum DatabaseSecretChange {
    Keep,
    Replace(SecretValue),
    Remove,
}

#[derive(Debug)]
pub struct DatabaseProfileChanges {
    pub password: DatabaseSecretChange,
}

impl Default for DatabaseProfileChanges {
    fn default() -> Self {
        Self {
            password: DatabaseSecretChange::Keep,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredDatabaseProfile {
    config: DatabaseProfileConfig,
    encrypted_password: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct StoredDatabaseProfiles {
    profiles: Vec<StoredDatabaseProfile>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DatabaseRuntimeStatus {
    Running,
    Stopped,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DetectedDatabase {
    pub engine: DatabaseEngine,
    pub name: String,
    pub version: String,
    pub status: DatabaseRuntimeStatus,
    pub port: u16,
    pub data_directory: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DatabaseTable {
    pub name: String,
    pub row_count: Option<u64>,
    pub size: Option<String>,
    pub engine: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DatabaseColumn {
    pub name: String,
    pub data_type: String,
    pub nullable: bool,
    pub primary_key: bool,
    pub default_value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DatabaseUser {
    pub username: String,
    pub host: String,
    pub privileges: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DatabaseStats {
    pub uptime: String,
    pub total_connections: u64,
    pub active_connections: u64,
    pub total_size: String,
    pub slow_queries: u64,
    pub extra: BTreeMap<String, String>,
}

#[derive(Clone)]
pub struct DatabaseRuntimeParametersSnapshot {
    target: TargetGuard,
    profile_id: String,
    profile_snapshot_digest: String,
    identity_plan_id: &'static str,
    query_plan_id: &'static str,
    identity: DatabaseConfigRuntimeIdentity,
    document: DatabaseConfigRuntimeDocument,
    postgresql_tls_mode: Option<PostgresqlTlsMode>,
    notice_count: usize,
    postgresql_observation: Option<crate::postgresql_observation::PostgresqlObservation>,
    postgresql_host_process: Option<crate::postgresql_process::PostgresqlHostInspection>,
    postgresql_access: Option<crate::postgresql_access::PostgresqlAccessReview>,
}

impl std::fmt::Debug for DatabaseRuntimeParametersSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DatabaseRuntimeParametersSnapshot")
            .field("target", &self.target)
            .field("profile_id", &self.profile_id)
            .field("identity_plan_id", &self.identity_plan_id)
            .field("query_plan_id", &self.query_plan_id)
            .field("identity", &self.identity)
            .field("document", &self.document)
            .finish()
    }
}

impl DatabaseRuntimeParametersSnapshot {
    pub const fn postgresql_access(
        &self,
    ) -> Option<&crate::postgresql_access::PostgresqlAccessReview> {
        self.postgresql_access.as_ref()
    }
    pub const fn postgresql_host_process(
        &self,
    ) -> Option<&crate::postgresql_process::PostgresqlHostInspection> {
        self.postgresql_host_process.as_ref()
    }
    pub const fn target(&self) -> &TargetGuard {
        &self.target
    }

    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub const fn identity_plan_id(&self) -> &'static str {
        self.identity_plan_id
    }

    pub const fn query_plan_id(&self) -> &'static str {
        self.query_plan_id
    }

    pub const fn product(&self) -> DatabaseConfigProduct {
        self.identity.product()
    }

    pub const fn edition(&self) -> DatabaseConfigRuntimeEdition {
        self.identity.edition()
    }

    pub const fn version(&self) -> crate::database_config_schema::DatabaseConfigVersion {
        self.identity.version()
    }

    pub const fn document(&self) -> &DatabaseConfigRuntimeDocument {
        &self.document
    }

    pub const fn postgresql_tls_mode(&self) -> Option<PostgresqlTlsMode> {
        self.postgresql_tls_mode
    }
    pub const fn notice_count(&self) -> usize {
        self.notice_count
    }
    pub fn postgresql_observation(
        &self,
    ) -> Option<&crate::postgresql_observation::PostgresqlObservation> {
        self.postgresql_observation.as_ref()
    }
}

#[derive(Clone)]
pub struct DatabaseConfigInventorySnapshot {
    target: TargetGuard,
    profile_id: String,
    profile_snapshot_digest: String,
    identity_plan_id: &'static str,
    query_plan_id: &'static str,
    identity: DatabaseConfigRuntimeIdentity,
    document: DatabaseConfigInventoryDocument,
}

impl std::fmt::Debug for DatabaseConfigInventorySnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DatabaseConfigInventorySnapshot")
            .field("target", &self.target)
            .field("profile_id", &self.profile_id)
            .field("identity_plan_id", &self.identity_plan_id)
            .field("query_plan_id", &self.query_plan_id)
            .field("identity", &self.identity)
            .field("document", &self.document)
            .finish()
    }
}

impl DatabaseConfigInventorySnapshot {
    pub const fn target(&self) -> &TargetGuard {
        &self.target
    }

    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub const fn identity_plan_id(&self) -> &'static str {
        self.identity_plan_id
    }

    pub const fn query_plan_id(&self) -> &'static str {
        self.query_plan_id
    }

    pub const fn identity(&self) -> DatabaseConfigRuntimeIdentity {
        self.identity
    }

    pub const fn product(&self) -> DatabaseConfigProduct {
        self.identity.product()
    }

    pub const fn edition(&self) -> DatabaseConfigRuntimeEdition {
        self.identity.edition()
    }

    pub const fn document(&self) -> &DatabaseConfigInventoryDocument {
        &self.document
    }
}

/// Write-only credentials. Debug output is redacted by `SecretValue`.
#[derive(Debug)]
pub struct DatabaseCredentials {
    password: Option<SecretValue>,
}

impl DatabaseCredentials {
    pub fn none() -> Self {
        Self { password: None }
    }

    pub fn password(password: SecretValue) -> Self {
        Self {
            password: Some(password),
        }
    }
}

#[derive(Debug)]
struct ResolvedDatabaseProfile {
    ssh_connection_id: Option<String>,
    connection: DatabaseConnection,
    credentials: DatabaseCredentials,
    postgresql_tls: Option<PostgresqlTlsSettings>,
}

fn validate_profile_session(
    profile: &ResolvedDatabaseProfile,
    session: &BoundSshSession,
) -> CoreResult<()> {
    if profile
        .ssh_connection_id
        .as_deref()
        .is_some_and(|id| id != session.connection_id())
    {
        return Err(CoreError::validation(
            "database profile target",
            "profile belongs to a different SSH connection",
        ));
    }
    Ok(())
}

struct DatabaseRuntimeWireCommand {
    command: Zeroizing<String>,
    stdin: Zeroizing<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct DatabaseProfileRepository {
    store: PortableStore,
    crypto: Arc<CryptoVault>,
    lock: Arc<Mutex<()>>,
    local_target: Arc<TargetContext>,
    local_guard: TargetGuard,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseProfileDeletePlan {
    profile_id: String,
    snapshot_digest: String,
    operation: OperationPlan,
}

impl DatabaseProfileDeletePlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseProfileDeleteOutcome {
    pub operation_id: String,
    pub verification: VerificationResult,
}

impl DatabaseProfileRepository {
    fn new(store: PortableStore, crypto: Arc<CryptoVault>) -> Self {
        let local_target = Arc::new(TargetContext::new());
        let local_guard = local_target
            .activate(
                TargetIdentity::new("portable-database-profiles")
                    .expect("static database profile target identity is valid"),
            )
            .expect("fresh database profile target generation is available");
        Self {
            store,
            crypto,
            lock: Arc::new(Mutex::new(())),
            local_target,
            local_guard,
        }
    }

    fn list(&self) -> CoreResult<Vec<DatabaseProfileView>> {
        Ok(self
            .snapshots()?
            .into_iter()
            .map(|snapshot| snapshot.view)
            .collect())
    }

    fn snapshots(&self) -> CoreResult<Vec<DatabaseProfileSnapshot>> {
        let _guard = self.lock.lock();
        self.load_locked()?
            .profiles
            .into_iter()
            .map(|profile| {
                Ok(DatabaseProfileSnapshot {
                    digest: profile_digest(&profile)?,
                    view: DatabaseProfileView {
                        has_password: profile.encrypted_password.is_some(),
                        config: profile.config,
                    },
                })
            })
            .collect()
    }

    fn upsert(
        &self,
        config: DatabaseProfileConfig,
        changes: DatabaseProfileChanges,
    ) -> CoreResult<DatabaseProfileView> {
        self.upsert_checked(config, changes, ProfileExpectation::LegacyUpsert)
            .map(|snapshot| snapshot.view)
    }

    fn upsert_checked(
        &self,
        config: DatabaseProfileConfig,
        changes: DatabaseProfileChanges,
        expected: ProfileExpectation<'_>,
    ) -> CoreResult<DatabaseProfileSnapshot> {
        config.validate()?;
        if let DatabaseSecretChange::Replace(secret) = &changes.password
            && (secret.expose().len() > MAX_PROFILE_PASSWORD_BYTES
                || secret.expose().contains('\0'))
        {
            return Err(CoreError::validation(
                "database profile password",
                "password exceeds its limit or contains NUL",
            ));
        }
        let _guard = self.lock.lock();
        let mut stored = self.load_locked()?;
        let index = stored
            .profiles
            .iter()
            .position(|profile| profile.config.id == config.id);
        match expected {
            ProfileExpectation::Absent if index.is_some() => {
                return Err(CoreError::validation(
                    "database profile conflict",
                    "profile already exists",
                ));
            }
            ProfileExpectation::Unchanged(snapshot) => {
                let existing = index.map(|index| &stored.profiles[index]).ok_or_else(|| {
                    CoreError::validation("database profile conflict", "profile was removed")
                })?;
                if snapshot.view.config.id != config.id
                    || profile_digest(existing)? != snapshot.digest
                {
                    return Err(CoreError::validation(
                        "database profile conflict",
                        "profile changed; reload before saving",
                    ));
                }
            }
            _ => {}
        }
        if index.is_none() && stored.profiles.len() >= MAX_DATABASE_PROFILES {
            return Err(CoreError::validation(
                "database profile capacity",
                "database profile count limit reached",
            ));
        }
        let existing_password = index
            .map(|index| stored.profiles.remove(index).encrypted_password)
            .unwrap_or_default();
        let encrypted_password = match changes.password {
            DatabaseSecretChange::Keep => existing_password,
            DatabaseSecretChange::Replace(secret) => Some(self.crypto.seal(&secret)?),
            DatabaseSecretChange::Remove => None,
        };
        let view = DatabaseProfileView {
            config: config.clone(),
            has_password: encrypted_password.is_some(),
        };
        stored.profiles.push(StoredDatabaseProfile {
            config,
            encrypted_password,
        });
        stored.profiles.sort_by(|left, right| {
            left.config
                .name
                .to_lowercase()
                .cmp(&right.config.name.to_lowercase())
                .then_with(|| left.config.id.cmp(&right.config.id))
        });
        let saved = stored
            .profiles
            .iter()
            .find(|profile| profile.config.id == view.config.id)
            .expect("inserted profile");
        let digest = profile_digest(saved)?;
        self.store
            .write_bounded(StoreFile::Database, &stored, MAX_PROFILE_STORE_BYTES)?;
        Ok(DatabaseProfileSnapshot { view, digest })
    }

    fn resolve(&self, profile_id: &str) -> CoreResult<ResolvedDatabaseProfile> {
        self.resolve_with_digest(profile_id)
            .map(|(profile, _)| profile)
    }

    fn resolve_with_digest(
        &self,
        profile_id: &str,
    ) -> CoreResult<(ResolvedDatabaseProfile, String)> {
        validate_profile_id(profile_id)?;
        let _guard = self.lock.lock();
        let profile = self
            .load_locked()?
            .profiles
            .into_iter()
            .find(|profile| profile.config.id == profile_id)
            .ok_or_else(|| CoreError::validation("database profile", "profile does not exist"))?;
        let digest = profile_digest(&profile)?;
        let password = profile
            .encrypted_password
            .as_deref()
            .map(|encrypted| self.crypto.open(encrypted))
            .transpose()?;
        Ok((
            ResolvedDatabaseProfile {
                ssh_connection_id: profile.config.ssh_connection_id,
                postgresql_tls: profile.config.postgresql_tls,
                connection: profile.config.connection,
                credentials: password
                    .map_or_else(DatabaseCredentials::none, DatabaseCredentials::password),
            },
            digest,
        ))
    }

    fn ensure_snapshot(
        &self,
        profile_id: &str,
        expected_digest: &str,
        subject: &'static str,
    ) -> CoreResult<()> {
        validate_profile_id(profile_id)?;
        let _guard = self.lock.lock();
        let stored = self.load_locked()?;
        let profile = stored
            .profiles
            .iter()
            .find(|profile| profile.config.id == profile_id)
            .ok_or_else(|| CoreError::validation("database profile", "profile does not exist"))?;
        if profile_digest(profile)? != expected_digest {
            return Err(CoreError::validation(
                subject,
                "profile changed while database configuration was being read",
            ));
        }
        Ok(())
    }

    fn plan_delete(
        &self,
        profile_id: &str,
        expected: Option<&str>,
    ) -> CoreResult<DatabaseProfileDeletePlan> {
        validate_profile_id(profile_id)?;
        let _guard = self.lock.lock();
        let profile = self
            .load_locked()?
            .profiles
            .into_iter()
            .find(|profile| profile.config.id == profile_id)
            .ok_or_else(|| CoreError::validation("database profile", "profile does not exist"))?;
        let snapshot_digest = profile_digest(&profile)?;
        if expected.is_some_and(|digest| digest != snapshot_digest) {
            return Err(CoreError::validation(
                "database profile conflict",
                "profile changed; reload before deleting",
            ));
        }
        let operation = OperationPlan::new(
            self.local_guard.clone(),
            format!(
                "永久删除数据库连接“{}”及其已保存凭据；此操作不可恢复。",
                profile.config.name
            ),
            true,
            None,
        )?;
        Ok(DatabaseProfileDeletePlan {
            profile_id: profile.config.id,
            snapshot_digest,
            operation,
        })
    }

    fn remove_if_unchanged(&self, profile_id: &str, digest: &str) -> CoreResult<()> {
        let _guard = self.lock.lock();
        let mut stored = self.load_locked()?;
        let index = stored
            .profiles
            .iter()
            .position(|profile| profile.config.id == profile_id)
            .ok_or_else(|| CoreError::validation("database profile", "profile does not exist"))?;
        if profile_digest(&stored.profiles[index])? != digest {
            return Err(CoreError::validation(
                "database profile deletion",
                "profile changed after confirmation; create a new plan",
            ));
        }
        stored.profiles.remove(index);
        self.store
            .write_bounded(StoreFile::Database, &stored, MAX_PROFILE_STORE_BYTES)
    }

    fn contains(&self, profile_id: &str) -> CoreResult<bool> {
        let _guard = self.lock.lock();
        Ok(self
            .load_locked()?
            .profiles
            .iter()
            .any(|profile| profile.config.id == profile_id))
    }

    fn load_locked(&self) -> CoreResult<StoredDatabaseProfiles> {
        let stored: StoredDatabaseProfiles = self
            .store
            .read_or_default_bounded(StoreFile::Database, MAX_PROFILE_STORE_BYTES)?;
        if stored.profiles.len() > MAX_DATABASE_PROFILES {
            return Err(CoreError::validation(
                "database profile capacity",
                "database profile count limit exceeded",
            ));
        }
        let mut ids = std::collections::HashSet::new();
        for profile in &stored.profiles {
            profile.config.validate()?;
            if !ids.insert(&profile.config.id)
                || profile
                    .encrypted_password
                    .as_ref()
                    .is_some_and(|value| value.len() > 64 * 1024)
            {
                return Err(CoreError::validation(
                    "database profile store",
                    "duplicate profile identity or oversized credential",
                ));
            }
        }
        Ok(stored)
    }
}

#[derive(Debug)]
struct DatabaseProfileDeleteExecutor {
    repository: DatabaseProfileRepository,
    profile_id: String,
    snapshot_digest: String,
}

#[async_trait]
impl OperationExecutor for DatabaseProfileDeleteExecutor {
    async fn execute(&self, _: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        self.repository
            .remove_if_unchanged(&self.profile_id, &self.snapshot_digest)?;
        Ok(ExecutionReceipt {
            summary: "deleted one portable database profile and its encrypted credential"
                .to_owned(),
            restore_token: None,
        })
    }

    async fn verify(
        &self,
        _: &OperationPlan,
        _: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        let removed = !self.repository.contains(&self.profile_id)?;
        Ok(VerificationResult {
            passed: removed,
            detail: if removed {
                "verified that the portable database profile is absent".to_owned()
            } else {
                "database profile remains after deletion".to_owned()
            },
        })
    }

    async fn restore(&self, _: &OperationPlan, _: &ExecutionReceipt) -> CoreResult<()> {
        Err(CoreError::Unsupported {
            feature: "restoring a permanently deleted database profile",
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SqlResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
    pub truncated: bool,
    pub execution_time_ms: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DatabaseStatementKind {
    ReadOnly,
    Mutation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DatabaseMutationRequest {
    pub statement: String,
    pub verification_statement: Option<String>,
    pub verification_contains: Option<String>,
    pub restore_statement: Option<String>,
    pub summary: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DatabaseServiceAction {
    Start,
    Stop,
    Restart,
}

impl DatabaseServiceAction {
    const fn command(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
        }
    }

    const fn expected_running(self) -> bool {
        !matches!(self, Self::Stop)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DatabaseVerificationPolicy {
    ExitSuccess,
    Contains(String),
    ServiceRunning(bool),
}

pub struct DatabaseActionPlan {
    pub operation: OperationPlan,
    execute_command: Zeroizing<String>,
    precondition_command: Option<Zeroizing<String>>,
    precondition_output: Option<String>,
    verification_command: Option<Zeroizing<String>>,
    verification_policy: DatabaseVerificationPolicy,
    restore_command: Option<Zeroizing<String>>,
    timeout: Duration,
}

impl std::fmt::Debug for DatabaseActionPlan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DatabaseActionPlan")
            .field("operation", &self.operation)
            .field("execute_command", &"[REDACTED]")
            .field(
                "precondition_command",
                &self.precondition_command.as_ref().map(|_| "[REDACTED]"),
            )
            .field("precondition_output", &self.precondition_output)
            .field(
                "verification_command",
                &self.verification_command.as_ref().map(|_| "[REDACTED]"),
            )
            .field("verification_policy", &self.verification_policy)
            .field(
                "restore_command",
                &self.restore_command.as_ref().map(|_| "[REDACTED]"),
            )
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl DatabaseActionPlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseActionOutcome {
    pub operation_id: String,
    pub verified: bool,
    pub detail: String,
    pub restored_after_failed_verification: bool,
}

#[derive(Debug, Clone)]
pub struct DatabaseService {
    ssh: SshService,
    target: Arc<TargetContext>,
    profiles: DatabaseProfileRepository,
}

impl DatabaseService {
    pub fn new(
        ssh: SshService,
        target: Arc<TargetContext>,
        store: PortableStore,
        crypto: Arc<CryptoVault>,
    ) -> Self {
        Self {
            ssh,
            target,
            profiles: DatabaseProfileRepository::new(store, crypto),
        }
    }

    pub fn profiles(&self) -> CoreResult<Vec<DatabaseProfileView>> {
        self.profiles.list()
    }

    pub fn profile_snapshots(&self) -> CoreResult<Vec<DatabaseProfileSnapshot>> {
        self.profiles.snapshots()
    }

    pub fn validate_profile_snapshot(&self, snapshot: &DatabaseProfileSnapshot) -> CoreResult<()> {
        self.profiles.ensure_snapshot(
            &snapshot.view.config.id,
            &snapshot.digest,
            "database profile conflict",
        )
    }

    /// None creates a new identity; Some updates exactly the observed revision.
    /// The comparison and write share the repository lock.
    pub fn save_profile_if_unchanged(
        &self,
        config: DatabaseProfileConfig,
        changes: DatabaseProfileChanges,
        expected: Option<&DatabaseProfileSnapshot>,
    ) -> CoreResult<DatabaseProfileSnapshot> {
        self.profiles.upsert_checked(
            config,
            changes,
            expected.map_or(ProfileExpectation::Absent, ProfileExpectation::Unchanged),
        )
    }

    pub fn plan_delete_profile_snapshot(
        &self,
        snapshot: &DatabaseProfileSnapshot,
    ) -> CoreResult<DatabaseProfileDeletePlan> {
        self.profiles
            .plan_delete(&snapshot.view.config.id, Some(&snapshot.digest))
    }

    pub fn upsert_profile(
        &self,
        config: DatabaseProfileConfig,
        changes: DatabaseProfileChanges,
    ) -> CoreResult<DatabaseProfileView> {
        self.profiles.upsert(config, changes)
    }

    pub fn plan_delete_profile(&self, profile_id: &str) -> CoreResult<DatabaseProfileDeletePlan> {
        self.profiles.plan_delete(profile_id, None)
    }

    pub async fn execute_delete_profile(
        &self,
        plan: DatabaseProfileDeletePlan,
        confirmation: DangerousConfirmation,
        journal: &PortableOperationJournal,
    ) -> CoreResult<DatabaseProfileDeleteOutcome> {
        let mut operation = PlannedOperation::plan(plan.operation.clone());
        operation.confirm(confirmation)?;
        let executor = DatabaseProfileDeleteExecutor {
            repository: self.profiles.clone(),
            profile_id: plan.profile_id,
            snapshot_digest: plan.snapshot_digest,
        };
        operation
            .execute(&self.profiles.local_target, &executor)
            .await?;
        operation.journal(journal)?;
        let verification = operation
            .verify(&self.profiles.local_target, &executor, journal)
            .await?;
        Ok(DatabaseProfileDeleteOutcome {
            operation_id: plan.operation.id,
            verification,
        })
    }

    pub async fn detect(&self, session: &BoundSshSession) -> CoreResult<Vec<DetectedDatabase>> {
        let output = self
            .read_command(
                session,
                detection_command(),
                INSPECTION_TIMEOUT,
                "detect databases",
            )
            .await?;
        parse_detection(&output)
    }

    pub async fn test_profile(
        &self,
        session: &BoundSshSession,
        profile_id: &str,
    ) -> CoreResult<()> {
        let profile = self.profiles.resolve(profile_id)?;
        let statement = match profile.connection.engine {
            DatabaseEngine::Mysql | DatabaseEngine::Postgresql => "SELECT 1",
            DatabaseEngine::Redis => "PING",
            DatabaseEngine::Mongo => "db.runCommand({ping:1})",
            DatabaseEngine::Dm | DatabaseEngine::Kingbase => {
                return Err(CoreError::Unsupported {
                    feature: "database client for detection-only engine",
                });
            }
        };
        self.query_resolved(session, &profile, statement).await?;
        Ok(())
    }

    /// Reads the reviewed runtime-parameter surface for one exact upstream
    /// database identity. The caller declares a product, but the remote server
    /// must independently prove its native product, community edition, and
    /// reviewed version before the parameter query is selected.
    ///
    /// Both SQL statements come from the closed runtime-plan registry.
    /// PostgreSQL uses its native protocol over the bound SSH connection;
    /// MySQL/MariaDB still reject password-bearing remote-client profiles.
    /// Remote stdout, stderr and database error details never enter the snapshot.
    pub async fn read_postgresql_runtime_snapshot(
        &self,
        session: &BoundSshSession,
        expected: &DatabaseProfileSnapshot,
    ) -> CoreResult<DatabaseRuntimeParametersSnapshot> {
        let id = &expected.view.config.id;
        let (profile, digest) = self.profiles.resolve_with_digest(id)?;
        if digest != expected.digest {
            return Err(CoreError::validation(
                "database profile conflict",
                "profile changed before reading",
            ));
        }
        validate_profile_session(&profile, session)?;
        validate_runtime_product_engine(
            profile.connection.engine,
            DatabaseConfigProduct::PostgreSql,
        )?;
        self.read_native_postgresql_runtime(session, id, profile, digest)
            .await
    }

    pub async fn read_runtime_parameters(
        &self,
        session: &BoundSshSession,
        profile_id: &str,
        declared_product: DatabaseConfigProduct,
    ) -> CoreResult<DatabaseRuntimeParametersSnapshot> {
        let (profile, profile_digest) = self.profiles.resolve_with_digest(profile_id)?;
        validate_profile_session(&profile, session)?;
        validate_runtime_product_engine(profile.connection.engine, declared_product)?;
        if declared_product == DatabaseConfigProduct::PostgreSql {
            return self
                .read_native_postgresql_runtime(session, profile_id, profile, profile_digest)
                .await;
        }

        let identity_plan =
            database_config_runtime_identity_plan(declared_product).map_err(|error| {
                CoreError::validation("database runtime identity plan", error.to_string())
            })?;
        let identity_command = build_runtime_identity_command(&profile, identity_plan)?;
        let identity_output = self
            .sensitive_raw_command(
                session,
                identity_command,
                RUNTIME_IDENTITY_TIMEOUT,
                MAX_DATABASE_CONFIG_RUNTIME_IDENTITY_TSV_BYTES,
            )
            .await?;
        self.profiles.ensure_snapshot(
            profile_id,
            &profile_digest,
            "database runtime parameters",
        )?;
        let identity_bytes =
            successful_sensitive_database_output("database runtime identity", identity_output)?;
        let identity = identity_plan.parse_tsv(identity_bytes).map_err(|error| {
            CoreError::validation("database runtime identity", error.to_string())
        })?;

        let query_plan =
            database_config_runtime_query_plan(identity.runtime_target()).map_err(|error| {
                CoreError::validation("database runtime query plan", error.to_string())
            })?;
        let query_command = build_runtime_query_command(&profile, query_plan)?;
        let query_output = self
            .sensitive_raw_command(
                session,
                query_command,
                INSPECTION_TIMEOUT,
                MAX_DATABASE_CONFIG_RUNTIME_TSV_BYTES,
            )
            .await?;
        self.profiles.ensure_snapshot(
            profile_id,
            &profile_digest,
            "database runtime parameters",
        )?;
        let query_bytes =
            successful_sensitive_database_output("database runtime parameters", query_output)?;
        let document = query_plan.parse_tsv(query_bytes).map_err(|error| {
            CoreError::validation("database runtime parameters", error.to_string())
        })?;

        // No await follows these checks. A result can therefore only escape
        // for the same target epoch and the same encrypted profile snapshot
        // that authorized both remote reads.
        self.profiles.ensure_snapshot(
            profile_id,
            &profile_digest,
            "database runtime parameters",
        )?;
        self.target.validate(session.target())?;
        Ok(DatabaseRuntimeParametersSnapshot {
            target: session.target().clone(),
            profile_id: profile_id.to_owned(),
            profile_snapshot_digest: profile_digest,
            identity_plan_id: identity_plan.id(),
            query_plan_id: query_plan.id(),
            identity,
            document,
            postgresql_tls_mode: None,
            notice_count: 0,
            postgresql_observation: None,
            postgresql_host_process: None,
            postgresql_access: None,
        })
    }

    async fn read_native_postgresql_runtime(
        &self,
        session: &BoundSshSession,
        profile_id: &str,
        profile: ResolvedDatabaseProfile,
        profile_digest: String,
    ) -> CoreResult<DatabaseRuntimeParametersSnapshot> {
        self.target.validate(session.target())?;
        let request = NativeRuntimeRequest::new(
            profile.connection,
            profile.postgresql_tls.unwrap_or_default(),
            profile.credentials.password,
        )?;
        let pending = self.ssh.read_postgresql_runtime_bound(session, request);
        tokio::pin!(pending);
        let mut target_check = tokio::time::interval(Duration::from_millis(100));
        let result = loop {
            tokio::select! {
                result = &mut pending => break result,
                _ = target_check.tick() => {
                    self.target.validate(session.target())?;
                    self.profiles.ensure_snapshot(profile_id, &profile_digest, "database runtime parameters")?;
                }
            }
        };
        self.target.validate(session.target())?;
        self.profiles.ensure_snapshot(
            profile_id,
            &profile_digest,
            "database runtime parameters",
        )?;
        let read = result?;
        Ok(DatabaseRuntimeParametersSnapshot {
            target: session.target().clone(),
            profile_id: profile_id.to_owned(),
            profile_snapshot_digest: profile_digest,
            identity_plan_id: read.identity_plan_id,
            query_plan_id: read.query_plan_id,
            identity: read.identity,
            document: read.document,
            postgresql_tls_mode: Some(read.tls_mode),
            notice_count: read.notice_count,
            postgresql_observation: Some(read.observation),
            postgresql_host_process: Some(read.host_process),
            postgresql_access: Some(read.access),
        })
    }

    /// Revalidates a completed snapshot immediately before a caller applies it
    /// to page state. This closes the gap between the async method returning
    /// and a frontend consumer processing the result.
    pub fn validate_runtime_parameters_snapshot(
        &self,
        snapshot: &DatabaseRuntimeParametersSnapshot,
    ) -> CoreResult<()> {
        self.target.validate(snapshot.target())?;
        self.profiles.ensure_snapshot(
            snapshot.profile_id(),
            &snapshot.profile_snapshot_digest,
            "database runtime parameters",
        )
    }

    /// Reads one reviewed, read-only plugin or component inventory after the
    /// server proves its exact native product, edition, and supported version.
    /// One closed query returns identity and inventory from the same database
    /// connection. Password
    /// profiles remain unavailable until a native database protocol can keep
    /// credentials outside a remote process and its output channels.
    pub async fn read_database_config_inventory(
        &self,
        session: &BoundSshSession,
        profile_id: &str,
        declared_product: DatabaseConfigProduct,
        surface: DatabaseConfigInventorySurface,
    ) -> CoreResult<DatabaseConfigInventorySnapshot> {
        // Reject unsupported product/surface pairs, including MariaDB
        // components, before any profile can authorize an SSH request.
        let query_plan =
            database_config_inventory_query_plan(declared_product, surface).map_err(|error| {
                CoreError::validation(
                    "database configuration inventory query plan",
                    error.to_string(),
                )
            })?;
        let (profile, profile_digest) = self.profiles.resolve_with_digest(profile_id)?;
        validate_runtime_product_engine(profile.connection.engine, declared_product)?;
        validate_profile_session(&profile, session)?;
        let query_command = build_inventory_query_command(&profile, query_plan)?;
        let query_output = self
            .sensitive_raw_command(
                session,
                query_command,
                INVENTORY_TIMEOUT,
                MAX_DATABASE_CONFIG_INVENTORY_TSV_BYTES,
            )
            .await?;
        self.profiles.ensure_snapshot(
            profile_id,
            &profile_digest,
            "database configuration inventory",
        )?;
        let query_bytes =
            successful_sensitive_database_output("database configuration inventory", query_output)?;
        let (identity, document) = query_plan
            .parse_tsv(query_bytes)
            .map_err(|error| {
                CoreError::validation("database configuration inventory", error.to_string())
            })?
            .into_parts();

        // Nothing awaits after these checks, so neither a stale target epoch
        // nor a changed encrypted profile snapshot can escape as current data.
        self.profiles.ensure_snapshot(
            profile_id,
            &profile_digest,
            "database configuration inventory",
        )?;
        self.target.validate(session.target())?;
        Ok(DatabaseConfigInventorySnapshot {
            target: session.target().clone(),
            profile_id: profile_id.to_owned(),
            profile_snapshot_digest: profile_digest,
            identity_plan_id: query_plan.identity_plan_id(),
            query_plan_id: query_plan.id(),
            identity,
            document,
        })
    }

    /// Revalidates a completed inventory immediately before page-state use.
    pub fn validate_database_config_inventory_snapshot(
        &self,
        snapshot: &DatabaseConfigInventorySnapshot,
    ) -> CoreResult<()> {
        self.target.validate(snapshot.target())?;
        self.profiles.ensure_snapshot(
            snapshot.profile_id(),
            &snapshot.profile_snapshot_digest,
            "database configuration inventory",
        )
    }

    pub async fn query_profile(
        &self,
        session: &BoundSshSession,
        profile_id: &str,
        database: Option<&str>,
        statement: &str,
    ) -> CoreResult<SqlResult> {
        let profile = self.resolve_for_database(profile_id, database)?;
        self.query_resolved(session, &profile, statement).await
    }

    pub fn classify_statement(
        engine: DatabaseEngine,
        statement: &str,
    ) -> CoreResult<DatabaseStatementKind> {
        validate_statement(statement)?;
        Ok(if validate_read_only_statement(engine, statement).is_ok() {
            DatabaseStatementKind::ReadOnly
        } else {
            DatabaseStatementKind::Mutation
        })
    }

    pub async fn sample_table(
        &self,
        session: &BoundSshSession,
        profile_id: &str,
        database: &str,
        table: &str,
        maximum_rows: u16,
    ) -> CoreResult<SqlResult> {
        if maximum_rows == 0 || maximum_rows > 1_000 {
            return Err(CoreError::validation(
                "database sample row limit",
                "must be between 1 and 1000",
            ));
        }
        if !is_valid_sql_ident(database) || !is_valid_sql_ident(table) {
            return Err(CoreError::validation(
                "database sample identifiers",
                "database and table must match the SQL identifier whitelist",
            ));
        }
        let statement = match self.profiles.resolve(profile_id)?.connection.engine {
            DatabaseEngine::Mysql | DatabaseEngine::Postgresql => {
                format!("SELECT * FROM {table} LIMIT {maximum_rows}")
            }
            DatabaseEngine::Mongo => {
                format!("db.{table}.find({{}}).limit({maximum_rows}).forEach(printjson)")
            }
            DatabaseEngine::Redis => {
                return Err(CoreError::Unsupported {
                    feature: "relational table sampling for Redis",
                });
            }
            DatabaseEngine::Dm | DatabaseEngine::Kingbase => {
                return Err(CoreError::Unsupported {
                    feature: "table sampling for detection-only engine",
                });
            }
        };
        self.query_profile(session, profile_id, Some(database), &statement)
            .await
    }

    pub async fn list_databases(
        &self,
        session: &BoundSshSession,
        profile_id: &str,
    ) -> CoreResult<Vec<String>> {
        let profile = self.profiles.resolve(profile_id)?;
        let statement = database_list_statement(profile.connection.engine)?;
        let result = self.query_resolved(session, &profile, statement).await?;
        let mut databases = parse_name_rows(profile.connection.engine, result);
        databases.sort();
        databases.dedup();
        databases.truncate(MAX_DATABASE_ITEMS);
        Ok(databases)
    }

    pub async fn list_tables(
        &self,
        session: &BoundSshSession,
        profile_id: &str,
        database: &str,
    ) -> CoreResult<Vec<DatabaseTable>> {
        let profile = self.resolve_for_database(profile_id, Some(database))?;
        let statement = tables_statement(profile.connection.engine, database)?;
        let result = self.query_resolved(session, &profile, &statement).await?;
        parse_tables(profile.connection.engine, result)
    }

    pub async fn list_columns(
        &self,
        session: &BoundSshSession,
        profile_id: &str,
        database: &str,
        table: &str,
    ) -> CoreResult<Vec<DatabaseColumn>> {
        let profile = self.resolve_for_database(profile_id, Some(database))?;
        let statement = columns_statement(profile.connection.engine, database, table)?;
        let result = self.query_resolved(session, &profile, &statement).await?;
        parse_columns(profile.connection.engine, result)
    }

    pub async fn list_users(
        &self,
        session: &BoundSshSession,
        profile_id: &str,
    ) -> CoreResult<Vec<DatabaseUser>> {
        let profile = self.profiles.resolve(profile_id)?;
        let statement = users_statement(profile.connection.engine)?;
        let result = self.query_resolved(session, &profile, statement).await?;
        parse_users(profile.connection.engine, result)
    }

    pub async fn stats(
        &self,
        session: &BoundSshSession,
        profile_id: &str,
    ) -> CoreResult<DatabaseStats> {
        let profile = self.profiles.resolve(profile_id)?;
        let statements = stats_statements(profile.connection.engine)?;
        let mut results = Vec::with_capacity(statements.len());
        for statement in statements {
            results.push(self.query_resolved(session, &profile, statement).await?);
        }
        parse_stats(profile.connection.engine, &results)
    }

    pub async fn plan_mutation(
        &self,
        session: &BoundSshSession,
        profile_id: &str,
        database: Option<&str>,
        request: &DatabaseMutationRequest,
    ) -> CoreResult<DatabaseActionPlan> {
        self.target.validate(session.target())?;
        let profile = self.resolve_for_database(profile_id, database)?;
        validate_profile_session(&profile, session)?;
        build_mutation_plan(session.target().clone(), &profile, request)
    }

    pub async fn plan_service_action(
        &self,
        session: &BoundSshSession,
        engine: DatabaseEngine,
        action: DatabaseServiceAction,
    ) -> CoreResult<DatabaseActionPlan> {
        self.target.validate(session.target())?;
        let status_command = service_status_command(engine);
        let before = self
            .read_command(
                session,
                status_command.clone(),
                INSPECTION_TIMEOUT,
                "read database service state",
            )
            .await?;
        let before_running = service_is_running(&before);
        let active_service = active_service_name(engine, &before);
        let execute_command = active_service.map_or_else(
            || service_action_command(engine, action),
            |service| single_service_action_command(service, action),
        );
        let restore_command = if before_running == action.expected_running() {
            None
        } else {
            Some(if let Some(service) = active_service {
                single_service_action_command(
                    service,
                    if before_running {
                        DatabaseServiceAction::Start
                    } else {
                        DatabaseServiceAction::Stop
                    },
                )
            } else {
                service_action_command(
                    engine,
                    if before_running {
                        DatabaseServiceAction::Start
                    } else {
                        DatabaseServiceAction::Stop
                    },
                )
            })
        };
        let mut operation = OperationPlan::new(
            session.target().clone(),
            format!("{} {} 数据库服务", action_label(action), engine.label()),
            true,
            restore_command
                .as_ref()
                .map(|_| format!("恢复 {} 服务到确认前状态", engine.label())),
        )?;
        operation
            .metadata
            .insert("database-engine".to_owned(), engine.label().to_owned());
        operation.metadata.insert(
            "service-before-running".to_owned(),
            before_running.to_string(),
        );
        Ok(DatabaseActionPlan {
            operation,
            execute_command: Zeroizing::new(execute_command),
            precondition_command: Some(Zeroizing::new(status_command.clone())),
            precondition_output: Some(normalize_service_state(&before)),
            verification_command: Some(Zeroizing::new(status_command)),
            verification_policy: DatabaseVerificationPolicy::ServiceRunning(
                action.expected_running(),
            ),
            restore_command: restore_command.map(Zeroizing::new),
            timeout: MUTATION_TIMEOUT,
        })
    }

    pub async fn plan_backup(
        &self,
        session: &BoundSshSession,
        profile_id: &str,
        database: &str,
    ) -> CoreResult<DatabaseActionPlan> {
        self.target.validate(session.target())?;
        if !is_valid_sql_ident(database) {
            return Err(CoreError::validation(
                "database backup name",
                "must match the SQL identifier whitelist",
            ));
        }
        let profile = self.resolve_for_database(profile_id, Some(database))?;
        validate_profile_session(&profile, session)?;
        let mut plan = build_backup_plan(session.target().clone(), &profile, database)?;
        if profile.connection.engine == DatabaseEngine::Redis {
            let command = build_command(&profile.connection, &profile.credentials, "LASTSAVE")?;
            let before = self
                .read_command(
                    session,
                    command.clone(),
                    INSPECTION_TIMEOUT,
                    "read Redis persistence marker",
                )
                .await?;
            plan.verification_command = Some(Zeroizing::new(format!(
                "before={}; i=0; while [ $i -lt 20 ]; do current=$({}); [ \"$current\" != \"$before\" ] && printf '%s\\n' \"$current\" && exit 0; i=$((i+1)); sleep 1; done; exit 1",
                shq(before.trim()),
                command
            )));
            plan.verification_policy = DatabaseVerificationPolicy::ExitSuccess;
        }
        Ok(plan)
    }

    pub async fn execute_action(
        &self,
        session: &BoundSshSession,
        action: DatabaseActionPlan,
        confirmation: DangerousConfirmation,
        journal: &PortableOperationJournal,
    ) -> CoreResult<DatabaseActionOutcome> {
        self.target.validate(session.target())?;
        if action.operation.target != *session.target() {
            return Err(CoreError::validation(
                "database operation target",
                "plan is bound to a different SSH target epoch",
            ));
        }
        let mut operation = PlannedOperation::plan(action.operation.clone());
        operation.confirm(confirmation)?;
        let executor = DatabaseRemoteOperationExecutor {
            service: self,
            session,
            action: &action,
        };
        if let Err(error) = operation.execute(&self.target, &executor).await {
            if operation.state() == OperationState::StaleAfterExecution {
                operation.journal(journal)?;
            }
            return Err(error);
        }
        operation.journal(journal)?;
        let verification = operation.verify(&self.target, &executor, journal).await?;
        let mut restored = false;
        if !verification.passed && action.restore_command.is_some() {
            operation.restore(&self.target, &executor, journal).await?;
            restored = true;
        }
        Ok(DatabaseActionOutcome {
            operation_id: action.operation.id,
            verified: verification.passed,
            detail: verification.detail,
            restored_after_failed_verification: restored,
        })
    }

    pub fn query_with_runner(
        runner: &dyn CommandRunner,
        connection: &DatabaseConnection,
        credentials: &DatabaseCredentials,
        statement: &str,
    ) -> CoreResult<SqlResult> {
        validate_read_only_statement(connection.engine, statement)?;
        let command = build_command(connection, credentials, statement)?;
        let stdout = runner.run(&command)?.into_stdout("database query")?;
        Ok(parse_result(connection.engine, &stdout))
    }

    pub fn list_tables_statement(engine: DatabaseEngine, database: &str) -> CoreResult<String> {
        tables_statement(engine, database)
    }

    fn resolve_for_database(
        &self,
        profile_id: &str,
        database: Option<&str>,
    ) -> CoreResult<ResolvedDatabaseProfile> {
        let mut profile = self.profiles.resolve(profile_id)?;
        if let Some(database) = database {
            bounded_text("database name", database, 128)?;
            profile.connection.database = (!database.is_empty()).then(|| database.to_owned());
        }
        Ok(profile)
    }

    async fn query_resolved(
        &self,
        session: &BoundSshSession,
        profile: &ResolvedDatabaseProfile,
        statement: &str,
    ) -> CoreResult<SqlResult> {
        validate_profile_session(profile, session)?;
        validate_read_only_statement(profile.connection.engine, statement)?;
        let command = build_command(&profile.connection, &profile.credentials, statement)?;
        let started = Instant::now();
        let output = self.raw_command(session, command, QUERY_TIMEOUT).await?;
        let stdout = successful_database_output("database query", output)?;
        let mut result = parse_result(profile.connection.engine, &stdout);
        result.execution_time_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        Ok(result)
    }

    async fn read_command(
        &self,
        session: &BoundSshSession,
        command: String,
        timeout: Duration,
        subject: &'static str,
    ) -> CoreResult<String> {
        let output = self.raw_command(session, command, timeout).await?;
        successful_database_output(subject, output)
    }

    async fn raw_command(
        &self,
        session: &BoundSshSession,
        command: impl Into<String>,
        timeout: Duration,
    ) -> CoreResult<SshCommandOutput> {
        guarded_result(&self.target, session.target(), || {
            self.ssh.execute_bound(session, command.into(), timeout)
        })
        .await
    }

    async fn sensitive_raw_command(
        &self,
        session: &BoundSshSession,
        request: DatabaseRuntimeWireCommand,
        timeout: Duration,
        stdout_bytes: usize,
    ) -> CoreResult<SshSensitiveCommandOutput> {
        let limits = SshSensitiveCommandLimits::new(stdout_bytes, RUNTIME_STDERR_BYTES)?;
        guarded_result(&self.target, session.target(), || {
            self.ssh.execute_bound_sensitive(
                session,
                request.command,
                request.stdin,
                timeout,
                limits,
            )
        })
        .await
    }
}

#[derive(Debug)]
struct DatabaseRemoteOperationExecutor<'a> {
    service: &'a DatabaseService,
    session: &'a BoundSshSession,
    action: &'a DatabaseActionPlan,
}

impl DatabaseRemoteOperationExecutor<'_> {
    fn ensure_plan(&self, plan: &OperationPlan) -> CoreResult<()> {
        if plan.id != self.action.operation.id || plan.target != self.action.operation.target {
            return Err(CoreError::validation(
                "database operation",
                "executor is bound to a different immutable plan",
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl OperationExecutor for DatabaseRemoteOperationExecutor<'_> {
    async fn execute(&self, plan: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        self.ensure_plan(plan)?;
        if let (Some(command), Some(expected)) = (
            self.action.precondition_command.as_ref(),
            self.action.precondition_output.as_ref(),
        ) {
            let output = self
                .service
                .read_command(
                    self.session,
                    command.to_string(),
                    INSPECTION_TIMEOUT,
                    "database operation precondition",
                )
                .await?;
            if normalize_service_state(&output) != *expected {
                return Err(CoreError::validation(
                    "database operation precondition",
                    "remote state changed after confirmation; create a new plan",
                ));
            }
        }
        let output = self
            .service
            .raw_command(
                self.session,
                self.action.execute_command.to_string(),
                self.action.timeout,
            )
            .await?;
        let stdout = successful_database_output("database operation", output)?;
        Ok(ExecutionReceipt {
            summary: bounded_output_summary(&stdout),
            restore_token: None,
        })
    }

    async fn verify(
        &self,
        plan: &OperationPlan,
        _: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        self.ensure_plan(plan)?;
        let Some(command) = &self.action.verification_command else {
            return Ok(VerificationResult {
                passed: true,
                detail: "command completed successfully; no additional readback was requested"
                    .to_owned(),
            });
        };
        let output = self
            .service
            .read_command(
                self.session,
                command.to_string(),
                INSPECTION_TIMEOUT,
                "verify database operation",
            )
            .await?;
        let passed = verification_passes(&self.action.verification_policy, &output);
        Ok(VerificationResult {
            passed,
            detail: bounded_output_summary(&output),
        })
    }

    async fn restore(&self, plan: &OperationPlan, _: &ExecutionReceipt) -> CoreResult<()> {
        self.ensure_plan(plan)?;
        let command = self.action.restore_command.as_ref().ok_or_else(|| {
            CoreError::validation("database restore", "operation has no restore command")
        })?;
        let output = self
            .service
            .raw_command(self.session, command.to_string(), MUTATION_TIMEOUT)
            .await?;
        successful_database_output("restore database operation", output)?;
        Ok(())
    }
}

fn validate_profile_id(id: &str) -> CoreResult<()> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(CoreError::validation(
            "database profile id",
            "must be 1-128 ASCII letters, digits, dashes, or underscores",
        ));
    }
    Ok(())
}

fn profile_digest(profile: &StoredDatabaseProfile) -> CoreResult<String> {
    let bytes = serde_json::to_vec(profile).map_err(|source| CoreError::Encode {
        subject: "database profile snapshot",
        source,
    })?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn validate_runtime_product_engine(
    engine: DatabaseEngine,
    product: DatabaseConfigProduct,
) -> CoreResult<()> {
    match (engine, product) {
        (DatabaseEngine::Mysql, DatabaseConfigProduct::MySql | DatabaseConfigProduct::MariaDb)
        | (DatabaseEngine::Postgresql, DatabaseConfigProduct::PostgreSql) => Ok(()),
        (
            _,
            DatabaseConfigProduct::MySql
            | DatabaseConfigProduct::MariaDb
            | DatabaseConfigProduct::PostgreSql,
        ) => Err(CoreError::validation(
            "database runtime product",
            "declared product does not match the saved client protocol",
        )),
        _ => Err(CoreError::Unsupported {
            feature: "runtime parameter discovery for this database product",
        }),
    }
}

fn build_runtime_identity_command(
    profile: &ResolvedDatabaseProfile,
    plan: &'static DatabaseConfigRuntimeIdentityPlan,
) -> CoreResult<DatabaseRuntimeWireCommand> {
    validate_runtime_product_engine(profile.connection.engine, plan.declared_product())?;
    build_runtime_wire_command(
        &profile.connection,
        &profile.credentials,
        plan.declared_product(),
        plan.query(),
    )
}

fn build_runtime_query_command(
    profile: &ResolvedDatabaseProfile,
    plan: &'static DatabaseConfigRuntimeQueryPlan,
) -> CoreResult<DatabaseRuntimeWireCommand> {
    validate_runtime_product_engine(profile.connection.engine, plan.binding().product)?;
    build_runtime_wire_command(
        &profile.connection,
        &profile.credentials,
        plan.binding().product,
        plan.query(),
    )
}

fn build_inventory_query_command(
    profile: &ResolvedDatabaseProfile,
    plan: &'static DatabaseConfigInventoryQueryPlan,
) -> CoreResult<DatabaseRuntimeWireCommand> {
    validate_runtime_product_engine(profile.connection.engine, plan.binding().product)?;
    build_runtime_wire_command(
        &profile.connection,
        &profile.credentials,
        plan.binding().product,
        plan.query(),
    )
}

fn build_runtime_wire_command(
    connection: &DatabaseConnection,
    credentials: &DatabaseCredentials,
    product: DatabaseConfigProduct,
    reviewed_query: &'static str,
) -> CoreResult<DatabaseRuntimeWireCommand> {
    connection.validate()?;
    validate_runtime_product_engine(connection.engine, product)?;
    if credentials.password.is_some() {
        return Err(CoreError::Unsupported {
            feature: "password-authenticated database configuration discovery until a native database protocol is available",
        });
    }
    let mut command = Zeroizing::new(String::with_capacity(reviewed_query.len() + 512));
    let stdin = Zeroizing::new(Vec::new());
    let username = connection.username.as_deref().unwrap_or_default();

    match connection.engine {
        DatabaseEngine::Mysql => {
            command.push_str(
                "unset MYSQL_PWD MYSQL_TEST_LOGIN_FILE MYSQL_HOME MARIADB_HOME \
                 MYSQL_HOST MYSQL_TCP_PORT MYSQL_UNIX_PORT MYSQL_GROUP_SUFFIX \
                 LIBMYSQL_ENABLE_CLEARTEXT_PLUGIN LIBMYSQL_PLUGIN_DIR; \
                 exec mysql --no-defaults ",
            );
            if product == DatabaseConfigProduct::MySql {
                command.push_str("--no-login-paths ");
            }
            command.push_str(
                // `mysql` may be either Oracle's or MariaDB's client even when
                // the server product is MariaDB. Both clients accept an
                // explicit empty password, which prevents an Oracle client
                // from inheriting a password from its implicit login-path file.
                "--password= --protocol=TCP --batch --raw --quick --skip-column-names \
                 --default-character-set=utf8mb4 --connect-timeout=10 --host=",
            );
            push_sensitive_shell_quoted(&mut command, &connection.host);
            write!(&mut *command, " --port={} --user=", connection.port)
                .expect("writing to a String cannot fail");
            push_sensitive_shell_quoted(&mut command, username);
            if let Some(database) = connection.database.as_deref() {
                command.push_str(" --database=");
                push_sensitive_shell_quoted(&mut command, database);
            }
            command.push_str(" --execute=");
            push_sensitive_shell_quoted(&mut command, reviewed_query);
        }
        DatabaseEngine::Postgresql => {
            command.push_str(
                "unset PGPASSWORD; \
                 PGCONNECT_TIMEOUT=10 PGOPTIONS='-c statement_timeout=20000' \
                 exec psql -X --quiet --tuples-only --no-align --field-separator ",
            );
            // A literal tab is required. Passing the two bytes `\\t` would
            // make psql emit a different wire format than the parser accepts.
            push_sensitive_shell_quoted(&mut command, "\t");
            command.push_str(" --pset footer=off --set ON_ERROR_STOP=1 -h ");
            push_sensitive_shell_quoted(&mut command, &connection.host);
            write!(&mut *command, " -p {} -U ", connection.port)
                .expect("writing to a String cannot fail");
            push_sensitive_shell_quoted(&mut command, username);
            if let Some(database) = connection.database.as_deref() {
                command.push_str(" -d ");
                push_sensitive_shell_quoted(&mut command, database);
            }
            command.push_str(" -c ");
            push_sensitive_shell_quoted(&mut command, reviewed_query);
        }
        DatabaseEngine::Redis
        | DatabaseEngine::Mongo
        | DatabaseEngine::Dm
        | DatabaseEngine::Kingbase => {
            return Err(CoreError::Unsupported {
                feature: "runtime parameter wire command for this database engine",
            });
        }
    }
    Ok(DatabaseRuntimeWireCommand { command, stdin })
}

/// Appends one POSIX-sh argument directly into the zeroizing command buffer.
/// This avoids constructing a second, ordinary `String` containing a secret.
fn push_sensitive_shell_quoted(command: &mut String, value: &str) {
    command.push('\'');
    let mut remaining = value;
    while let Some(index) = remaining.find('\'') {
        command.push_str(&remaining[..index]);
        command.push_str("'\\''");
        remaining = &remaining[index + 1..];
    }
    command.push_str(remaining);
    command.push('\'');
}

fn successful_sensitive_database_output(
    subject: &'static str,
    output: SshSensitiveCommandOutput,
) -> CoreResult<Zeroizing<Vec<u8>>> {
    if output.exit_code != Some(0) {
        return Err(CoreError::validation(
            subject,
            "remote command did not exit successfully; sensitive output was discarded",
        ));
    }
    if !output.stderr.is_empty() {
        return Err(CoreError::validation(
            subject,
            "remote command produced unexpected stderr; sensitive output was discarded",
        ));
    }
    Ok(output.stdout)
}

async fn guarded_result<T, F, Fut>(
    target: &TargetContext,
    guard: &TargetGuard,
    operation: F,
) -> CoreResult<T>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = CoreResult<T>>,
{
    target.validate(guard)?;
    let result = operation().await;
    // A failed remote request may race with a target switch just like a
    // successful one. Revalidate before exposing either outcome so an error
    // from the old target cannot overwrite state for the new activation.
    target.validate(guard)?;
    result
}

fn successful_database_output(
    subject: &'static str,
    output: SshCommandOutput,
) -> CoreResult<String> {
    if output.timed_out || output.exit_code != Some(0) {
        return Err(CoreError::validation(
            subject,
            format!(
                "remote command failed (exit={:?}, timed_out={}): {}",
                output.exit_code,
                output.timed_out,
                bounded_output_summary(&output.output)
            ),
        ));
    }
    if output.output.len() > MAX_SQL_BYTES.saturating_mul(16) {
        return Err(CoreError::validation(
            subject,
            "remote database output exceeds the 16 MiB boundary",
        ));
    }
    Ok(output.output)
}

fn verification_passes(policy: &DatabaseVerificationPolicy, output: &str) -> bool {
    match policy {
        DatabaseVerificationPolicy::ExitSuccess => true,
        DatabaseVerificationPolicy::Contains(expected) => output.contains(expected),
        DatabaseVerificationPolicy::ServiceRunning(expected) => {
            service_is_running(output) == *expected
        }
    }
}

fn bounded_output_summary(output: &str) -> String {
    let summary: String = output.trim().chars().take(1_024).collect();
    if summary.is_empty() {
        "command completed successfully".to_owned()
    } else {
        summary
    }
}

fn detection_command() -> String {
    r#"probe() {
  key="$1"; label="$2"; port="$3"; data="$4"; version_cmd="$5"; shift 5
  version=$(sh -c "$version_cmd" 2>/dev/null | head -n 1 | tr '\t\r\n' '   ' | cut -c1-512)
  [ -n "$version" ] || return 0
  status=stopped
  for service in "$@"; do
    [ "$(systemctl is-active "$service" 2>/dev/null || true)" = active ] && status=running && break
  done
  printf 'LRDB\t%s\t%s\t%s\t%s\t%s\t%s\n' "$key" "$status" "$port" "$data" "$label" "$version"
}
probe mysql 'MySQL / MariaDB' 3306 /var/lib/mysql 'mysql --version' mysql mysqld mariadb
probe postgresql PostgreSQL 5432 /var/lib/postgresql 'psql --version' postgresql
probe redis Redis 6379 /var/lib/redis 'redis-server --version' redis redis-server
probe mongo MongoDB 27017 /var/lib/mongodb 'mongod --version' mongod mongodb
probe dm 'DM (达梦)' 5236 /opt/dmdbms/data '/opt/dmdbms/bin/dm_svc_conf print_version' DmServiceDMSERVER
probe kingbase KingBase 54321 /opt/Kingbase/data 'ksql --version' kingbase"#
        .to_owned()
}

fn parse_detection(output: &str) -> CoreResult<Vec<DetectedDatabase>> {
    let mut detected = Vec::new();
    for line in output.lines().take(32) {
        let fields: Vec<_> = line.split('\t').collect();
        if fields.first().copied() != Some("LRDB") || fields.len() != 7 {
            continue;
        }
        let engine = match fields[1] {
            "mysql" => DatabaseEngine::Mysql,
            "postgresql" => DatabaseEngine::Postgresql,
            "redis" => DatabaseEngine::Redis,
            "mongo" => DatabaseEngine::Mongo,
            "dm" => DatabaseEngine::Dm,
            "kingbase" => DatabaseEngine::Kingbase,
            _ => continue,
        };
        let status = match fields[2] {
            "running" => DatabaseRuntimeStatus::Running,
            "stopped" => DatabaseRuntimeStatus::Stopped,
            _ => DatabaseRuntimeStatus::Unknown,
        };
        let port = fields[3]
            .parse::<u16>()
            .map_err(|_| CoreError::validation("database detection", "invalid detected port"))?;
        detected.push(DetectedDatabase {
            engine,
            name: fields[5].chars().take(128).collect(),
            version: fields[6].chars().take(512).collect(),
            status,
            port,
            data_directory: fields[4].chars().take(512).collect(),
        });
    }
    detected.sort_by_key(|database| database.engine.label());
    Ok(detected)
}

fn service_status_command(engine: DatabaseEngine) -> String {
    engine
        .service_names()
        .iter()
        .map(|service| {
            format!(
                "printf '%s\\t%s\\n' {} \"$(systemctl is-active {} 2>/dev/null || true)\"",
                shq(service),
                shq(service)
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn service_action_command(engine: DatabaseEngine, action: DatabaseServiceAction) -> String {
    let commands = engine
        .service_names()
        .iter()
        .map(|service| {
            format!(
                "systemctl {} {} 2>/dev/null",
                action.command(),
                shq(service)
            )
        })
        .collect::<Vec<_>>();
    commands.join(" || ")
}

fn single_service_action_command(service: &str, action: DatabaseServiceAction) -> String {
    format!("systemctl {} {}", action.command(), shq(service))
}

fn service_is_running(output: &str) -> bool {
    output.lines().any(|line| {
        line.split_once('\t')
            .is_some_and(|(_, state)| state.trim() == "active")
    })
}

fn active_service_name(engine: DatabaseEngine, output: &str) -> Option<&'static str> {
    output.lines().find_map(|line| {
        let (service, state) = line.split_once('\t')?;
        (state.trim() == "active")
            .then(|| {
                engine
                    .service_names()
                    .iter()
                    .copied()
                    .find(|candidate| *candidate == service.trim())
            })
            .flatten()
    })
}

fn normalize_service_state(output: &str) -> String {
    let mut states = output
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .map(|(service, state)| format!("{}={}", service.trim(), state.trim()))
        .collect::<Vec<_>>();
    states.sort();
    states.join(";")
}

const fn action_label(action: DatabaseServiceAction) -> &'static str {
    match action {
        DatabaseServiceAction::Start => "启动",
        DatabaseServiceAction::Stop => "停止",
        DatabaseServiceAction::Restart => "重启",
    }
}

fn database_list_statement(engine: DatabaseEngine) -> CoreResult<&'static str> {
    match engine {
        DatabaseEngine::Mysql => Ok("SHOW DATABASES"),
        DatabaseEngine::Postgresql => {
            Ok("SELECT datname FROM pg_database WHERE datistemplate = false ORDER BY datname")
        }
        DatabaseEngine::Redis => Ok("INFO keyspace"),
        DatabaseEngine::Mongo => {
            Ok("db.adminCommand({listDatabases:1}).databases.forEach(d=>print(d.name))")
        }
        DatabaseEngine::Dm | DatabaseEngine::Kingbase => Err(CoreError::Unsupported {
            feature: "database catalog for detection-only engine",
        }),
    }
}

fn tables_statement(engine: DatabaseEngine, database: &str) -> CoreResult<String> {
    if !is_valid_sql_ident(database) {
        return Err(CoreError::validation(
            "database identifier",
            "must match the SQL identifier whitelist",
        ));
    }
    match engine {
        DatabaseEngine::Mysql => Ok(format!(
            "SELECT TABLE_NAME, COALESCE(TABLE_ROWS,0), CONCAT(ROUND((DATA_LENGTH+INDEX_LENGTH)/1024,2),' KB'), COALESCE(ENGINE,'') FROM information_schema.TABLES WHERE TABLE_SCHEMA='{}' ORDER BY TABLE_NAME",
            escape_sql_literal(database)
        )),
        DatabaseEngine::Postgresql => Ok(
            "SELECT c.relname, COALESCE(c.reltuples::bigint,0), pg_size_pretty(pg_total_relation_size(c.oid)), '' FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind='r' AND n.nspname='public' ORDER BY c.relname".to_owned(),
        ),
        DatabaseEngine::Redis => Ok("SCAN 0 COUNT 1000".to_owned()),
        DatabaseEngine::Mongo => Ok("db.getCollectionNames().forEach(print)".to_owned()),
        DatabaseEngine::Dm | DatabaseEngine::Kingbase => Err(CoreError::Unsupported {
            feature: "database tables for detection-only engine",
        }),
    }
}

fn columns_statement(engine: DatabaseEngine, database: &str, table: &str) -> CoreResult<String> {
    if !is_valid_sql_ident(database) || !is_valid_sql_ident(table) {
        return Err(CoreError::validation(
            "database schema identifier",
            "database and table must match the SQL identifier whitelist",
        ));
    }
    match engine {
        DatabaseEngine::Mysql => Ok(format!("DESCRIBE `{database}`.`{table}`")),
        DatabaseEngine::Postgresql => Ok(format!(
            "SELECT c.column_name,c.data_type,c.is_nullable,COALESCE(c.column_default,''),CASE WHEN tc.constraint_type='PRIMARY KEY' THEN 'YES' ELSE 'NO' END FROM information_schema.columns c LEFT JOIN information_schema.key_column_usage kcu ON c.table_schema=kcu.table_schema AND c.table_name=kcu.table_name AND c.column_name=kcu.column_name LEFT JOIN information_schema.table_constraints tc ON kcu.constraint_name=tc.constraint_name AND tc.constraint_type='PRIMARY KEY' WHERE c.table_schema='public' AND c.table_name='{}' ORDER BY c.ordinal_position",
            escape_sql_literal(table)
        )),
        DatabaseEngine::Redis | DatabaseEngine::Mongo => Err(CoreError::Unsupported {
            feature: "relational column inspection for this database engine",
        }),
        DatabaseEngine::Dm | DatabaseEngine::Kingbase => Err(CoreError::Unsupported {
            feature: "database columns for detection-only engine",
        }),
    }
}

fn users_statement(engine: DatabaseEngine) -> CoreResult<&'static str> {
    match engine {
        DatabaseEngine::Mysql => Ok("SELECT user,host FROM mysql.user ORDER BY user,host"),
        DatabaseEngine::Postgresql => Ok(
            "SELECT usename,CASE WHEN usesuper THEN 'SUPERUSER' ELSE 'USER' END FROM pg_user ORDER BY usename",
        ),
        DatabaseEngine::Redis => Ok("ACL LIST"),
        DatabaseEngine::Mongo => Ok(
            "db.getUsers().users.forEach(u=>print(u.user+'|'+(u.roles||[]).map(r=>r.role).join(',')))",
        ),
        DatabaseEngine::Dm | DatabaseEngine::Kingbase => Err(CoreError::Unsupported {
            feature: "database users for detection-only engine",
        }),
    }
}

fn stats_statements(engine: DatabaseEngine) -> CoreResult<Vec<&'static str>> {
    match engine {
        DatabaseEngine::Mysql => Ok(vec![
            "SHOW GLOBAL STATUS WHERE Variable_name IN ('Uptime','Threads_connected','Threads_running','Slow_queries','Connections')",
            "SELECT COALESCE(ROUND(SUM(data_length+index_length)/1024/1024,2),0) AS size_mb FROM information_schema.tables",
        ]),
        DatabaseEngine::Postgresql => Ok(vec![
            "SELECT date_trunc('second',current_timestamp-pg_postmaster_start_time()),(SELECT count(*) FROM pg_stat_activity),(SELECT count(*) FROM pg_stat_activity WHERE state='active'),pg_size_pretty((SELECT sum(pg_database_size(datname)) FROM pg_database))",
        ]),
        DatabaseEngine::Redis => Ok(vec!["INFO"]),
        DatabaseEngine::Mongo => Ok(vec![
            "var s=db.serverStatus(); print(JSON.stringify({uptime:s.uptime,current:s.connections.current,available:s.connections.available,totalCreated:s.connections.totalCreated}))",
        ]),
        DatabaseEngine::Dm | DatabaseEngine::Kingbase => Err(CoreError::Unsupported {
            feature: "database statistics for detection-only engine",
        }),
    }
}

fn parse_name_rows(engine: DatabaseEngine, result: SqlResult) -> Vec<String> {
    let values = result
        .rows
        .into_iter()
        .filter_map(|row| row.into_iter().next())
        .flat_map(|value| {
            if engine == DatabaseEngine::Redis {
                value
                    .lines()
                    .filter_map(|line| line.strip_prefix("db"))
                    .filter_map(|suffix| {
                        suffix
                            .split_once(':')
                            .map(|(number, _)| format!("db{number}"))
                    })
                    .collect::<Vec<_>>()
            } else {
                vec![value]
            }
        })
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if values.is_empty() && engine == DatabaseEngine::Redis {
        vec!["db0".to_owned()]
    } else {
        values
    }
}

fn parse_tables(engine: DatabaseEngine, result: SqlResult) -> CoreResult<Vec<DatabaseTable>> {
    let mut tables = Vec::new();
    for row in result.rows.into_iter().take(MAX_DATABASE_ITEMS) {
        let Some(name) = row
            .first()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        tables.push(DatabaseTable {
            name: name.chars().take(256).collect(),
            row_count: row.get(1).and_then(|value| value.parse().ok()),
            size: row.get(2).filter(|value| !value.is_empty()).cloned(),
            engine: row.get(3).filter(|value| !value.is_empty()).cloned(),
        });
    }
    if engine == DatabaseEngine::Redis {
        for table in &mut tables {
            table.row_count = None;
            table.size = None;
            table.engine = Some("key sample".to_owned());
        }
    }
    Ok(tables)
}

fn parse_columns(engine: DatabaseEngine, result: SqlResult) -> CoreResult<Vec<DatabaseColumn>> {
    let columns = result
        .rows
        .into_iter()
        .take(MAX_DATABASE_ITEMS)
        .filter_map(|row| {
            let name = row.first()?.trim();
            if name.is_empty() {
                return None;
            }
            let column = match engine {
                DatabaseEngine::Mysql => DatabaseColumn {
                    name: name.chars().take(256).collect(),
                    data_type: row.get(1).cloned().unwrap_or_default(),
                    nullable: row.get(2).is_none_or(|value| value == "YES"),
                    primary_key: row.get(3).is_some_and(|value| value == "PRI"),
                    default_value: row
                        .get(4)
                        .filter(|value| !value.is_empty() && value.as_str() != "NULL")
                        .cloned(),
                },
                DatabaseEngine::Postgresql => DatabaseColumn {
                    name: name.chars().take(256).collect(),
                    data_type: row.get(1).cloned().unwrap_or_default(),
                    nullable: row.get(2).is_none_or(|value| value == "YES"),
                    default_value: row.get(3).filter(|value| !value.is_empty()).cloned(),
                    primary_key: row.get(4).is_some_and(|value| value == "YES"),
                },
                _ => return None,
            };
            Some(column)
        })
        .collect();
    Ok(columns)
}

fn parse_users(engine: DatabaseEngine, result: SqlResult) -> CoreResult<Vec<DatabaseUser>> {
    let users = result
        .rows
        .into_iter()
        .take(MAX_DATABASE_ITEMS)
        .filter_map(|row| {
            let first = row.first()?.trim();
            if first.is_empty() {
                return None;
            }
            match engine {
                DatabaseEngine::Mysql => Some(DatabaseUser {
                    username: first.to_owned(),
                    host: row.get(1).cloned().unwrap_or_default(),
                    privileges: Vec::new(),
                }),
                DatabaseEngine::Postgresql => Some(DatabaseUser {
                    username: first.to_owned(),
                    host: "%".to_owned(),
                    privileges: row.get(1).cloned().into_iter().collect(),
                }),
                DatabaseEngine::Redis => {
                    let parts = first.split_whitespace().collect::<Vec<_>>();
                    Some(DatabaseUser {
                        username: parts.get(1).copied().unwrap_or("default").to_owned(),
                        host: "%".to_owned(),
                        privileges: vec![first.to_owned()],
                    })
                }
                DatabaseEngine::Mongo => {
                    let (username, roles) = first.split_once('|').unwrap_or((first, ""));
                    Some(DatabaseUser {
                        username: username.to_owned(),
                        host: "%".to_owned(),
                        privileges: roles
                            .split(',')
                            .map(str::trim)
                            .filter(|role| !role.is_empty())
                            .map(str::to_owned)
                            .collect(),
                    })
                }
                DatabaseEngine::Dm | DatabaseEngine::Kingbase => None,
            }
        })
        .collect();
    Ok(users)
}

fn parse_stats(engine: DatabaseEngine, results: &[SqlResult]) -> CoreResult<DatabaseStats> {
    let first = results
        .first()
        .ok_or_else(|| CoreError::validation("database statistics", "missing statistics result"))?;
    match engine {
        DatabaseEngine::Mysql => {
            let mut stats = DatabaseStats::default();
            for row in &first.rows {
                let Some(key) = row.first().map(String::as_str) else {
                    continue;
                };
                let value = row.get(1).map(String::as_str).unwrap_or_default();
                match key {
                    "Uptime" => stats.uptime = format_duration(value.parse().unwrap_or_default()),
                    "Connections" => stats.total_connections = value.parse().unwrap_or_default(),
                    "Threads_connected" | "Threads_running" => {
                        let parsed = value.parse().unwrap_or_default();
                        if key == "Threads_connected" || stats.active_connections == 0 {
                            stats.active_connections = parsed;
                        }
                    }
                    "Slow_queries" => stats.slow_queries = value.parse().unwrap_or_default(),
                    _ => {
                        stats.extra.insert(key.to_owned(), value.to_owned());
                    }
                }
            }
            stats.total_size = results
                .get(1)
                .and_then(|result| result.rows.first())
                .and_then(|row| row.first())
                .map(|value| format!("{value} MiB"))
                .unwrap_or_else(|| "unknown".to_owned());
            Ok(stats)
        }
        DatabaseEngine::Postgresql => {
            let row = first
                .rows
                .first()
                .ok_or_else(|| CoreError::validation("PostgreSQL statistics", "empty result"))?;
            Ok(DatabaseStats {
                uptime: row.first().cloned().unwrap_or_default(),
                total_connections: row.get(1).and_then(|value| value.parse().ok()).unwrap_or(0),
                active_connections: row.get(2).and_then(|value| value.parse().ok()).unwrap_or(0),
                total_size: row.get(3).cloned().unwrap_or_else(|| "unknown".to_owned()),
                slow_queries: 0,
                extra: BTreeMap::new(),
            })
        }
        DatabaseEngine::Redis => {
            let mut stats = DatabaseStats::default();
            let lines = first
                .rows
                .iter()
                .filter_map(|row| row.first())
                .flat_map(|value| value.lines());
            for line in lines {
                let Some((key, value)) = line.split_once(':') else {
                    continue;
                };
                match key.trim() {
                    "uptime_in_seconds" => {
                        stats.uptime = format_duration(value.trim().parse().unwrap_or_default())
                    }
                    "total_connections_received" => {
                        stats.total_connections = value.trim().parse().unwrap_or_default()
                    }
                    "connected_clients" => {
                        stats.active_connections = value.trim().parse().unwrap_or_default()
                    }
                    "used_memory_human" => stats.total_size = value.trim().to_owned(),
                    "instantaneous_ops_per_sec" | "keyspace_hits" | "keyspace_misses" => {
                        stats
                            .extra
                            .insert(key.trim().to_owned(), value.trim().to_owned());
                    }
                    _ => {}
                }
            }
            if stats.total_size.is_empty() {
                stats.total_size = "unknown".to_owned();
            }
            Ok(stats)
        }
        DatabaseEngine::Mongo => {
            let json = first
                .rows
                .iter()
                .filter_map(|row| row.first())
                .find(|value| value.trim_start().starts_with('{'))
                .ok_or_else(|| {
                    CoreError::validation("MongoDB statistics", "missing JSON result")
                })?;
            let value: serde_json::Value =
                serde_json::from_str(json).map_err(|source| CoreError::Decode {
                    subject: "MongoDB statistics",
                    source,
                })?;
            let uptime = value
                .get("uptime")
                .and_then(|value| value.as_u64())
                .unwrap_or(0);
            let active = value
                .get("current")
                .and_then(|value| value.as_u64())
                .unwrap_or(0);
            let total = value
                .get("totalCreated")
                .and_then(|value| value.as_u64())
                .unwrap_or(active);
            let mut extra = BTreeMap::new();
            if let Some(available) = value.get("available").and_then(|value| value.as_u64()) {
                extra.insert("available_connections".to_owned(), available.to_string());
            }
            Ok(DatabaseStats {
                uptime: format_duration(uptime),
                total_connections: total,
                active_connections: active,
                total_size: "unknown".to_owned(),
                slow_queries: 0,
                extra,
            })
        }
        DatabaseEngine::Dm | DatabaseEngine::Kingbase => Err(CoreError::Unsupported {
            feature: "statistics for detection-only engine",
        }),
    }
}

fn format_duration(seconds: u64) -> String {
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;
    format!("{days}d {hours}h {minutes}m")
}

fn build_mutation_plan(
    target: TargetGuard,
    profile: &ResolvedDatabaseProfile,
    request: &DatabaseMutationRequest,
) -> CoreResult<DatabaseActionPlan> {
    validate_statement(&request.statement)?;
    bounded_text("database mutation summary", &request.summary, 2_048)?;
    if validate_read_only_statement(profile.connection.engine, &request.statement).is_ok() {
        return Err(CoreError::validation(
            "database mutation",
            "read-only statements must use query_profile instead of a dangerous plan",
        ));
    }
    let verification_command = request
        .verification_statement
        .as_deref()
        .map(|statement| {
            validate_read_only_statement(profile.connection.engine, statement)?;
            build_command(&profile.connection, &profile.credentials, statement)
        })
        .transpose()?
        .map(Zeroizing::new);
    if request.verification_contains.is_some() && verification_command.is_none() {
        return Err(CoreError::validation(
            "database verification",
            "verification_contains requires a verification statement",
        ));
    }
    if let Some(expected) = &request.verification_contains {
        bounded_text("database verification text", expected, 4_096)?;
    }
    let restore_command = request
        .restore_statement
        .as_deref()
        .map(|statement| {
            validate_statement(statement)?;
            build_command(&profile.connection, &profile.credentials, statement)
        })
        .transpose()?
        .map(Zeroizing::new);
    let mut operation = OperationPlan::new(
        target,
        request.summary.clone(),
        true,
        restore_command
            .as_ref()
            .map(|_| "执行确认时提供的数据库恢复语句".to_owned()),
    )?;
    operation.metadata.insert(
        "database-engine".to_owned(),
        profile.connection.engine.label().to_owned(),
    );
    if let Some(database) = &profile.connection.database {
        operation
            .metadata
            .insert("database-name".to_owned(), database.clone());
    }
    Ok(DatabaseActionPlan {
        operation,
        execute_command: Zeroizing::new(build_command(
            &profile.connection,
            &profile.credentials,
            &request.statement,
        )?),
        precondition_command: None,
        precondition_output: None,
        verification_command,
        verification_policy: request.verification_contains.clone().map_or(
            DatabaseVerificationPolicy::ExitSuccess,
            DatabaseVerificationPolicy::Contains,
        ),
        restore_command,
        timeout: MUTATION_TIMEOUT,
    })
}

fn build_backup_plan(
    target: TargetGuard,
    profile: &ResolvedDatabaseProfile,
    database: &str,
) -> CoreResult<DatabaseActionPlan> {
    let suffix = format!(
        "{}-{}",
        Utc::now().format("%Y%m%d-%H%M%S"),
        Uuid::new_v4().simple()
    );
    let (execute, verify, policy, artifact) = match profile.connection.engine {
        DatabaseEngine::Mysql => {
            let path = format!("/tmp/lovelyres-{database}-{suffix}.sql");
            (
                format!(
                    "{} > {}",
                    build_dump_command(&profile.connection, &profile.credentials, database)?,
                    shq(&path)
                ),
                format!("test -s {} && sha256sum -- {}", shq(&path), shq(&path)),
                DatabaseVerificationPolicy::ExitSuccess,
                path,
            )
        }
        DatabaseEngine::Postgresql => {
            let path = format!("/tmp/lovelyres-{database}-{suffix}.sql");
            (
                format!(
                    "{} > {}",
                    build_dump_command(&profile.connection, &profile.credentials, database)?,
                    shq(&path)
                ),
                format!("test -s {} && sha256sum -- {}", shq(&path), shq(&path)),
                DatabaseVerificationPolicy::ExitSuccess,
                path,
            )
        }
        DatabaseEngine::Mongo => {
            let path = format!("/tmp/lovelyres-{database}-{suffix}");
            (
                build_dump_command(&profile.connection, &profile.credentials, database)?
                    .replace("__OUTPUT__", &shq(&path)),
                format!(
                    "test -d {} && find {} -type f -size +0c -print -quit",
                    shq(&path),
                    shq(&path)
                ),
                DatabaseVerificationPolicy::ExitSuccess,
                path,
            )
        }
        DatabaseEngine::Redis => {
            let before_command =
                build_command(&profile.connection, &profile.credentials, "LASTSAVE")?;
            (
                build_command(&profile.connection, &profile.credentials, "BGSAVE")?,
                before_command.clone(),
                DatabaseVerificationPolicy::ExitSuccess,
                "Redis configured persistence directory".to_owned(),
            )
        }
        DatabaseEngine::Dm | DatabaseEngine::Kingbase => {
            return Err(CoreError::Unsupported {
                feature: "backup for detection-only database engine",
            });
        }
    };
    let mut operation = OperationPlan::new(
        target,
        format!(
            "备份 {} 数据库 {database} 到远端 {artifact}",
            profile.connection.engine.label()
        ),
        true,
        None,
    )?;
    operation
        .metadata
        .insert("database-backup-artifact".to_owned(), artifact);
    Ok(DatabaseActionPlan {
        operation,
        execute_command: Zeroizing::new(execute),
        precondition_command: None,
        precondition_output: None,
        verification_command: Some(Zeroizing::new(verify)),
        verification_policy: policy,
        restore_command: None,
        timeout: BACKUP_TIMEOUT,
    })
}

fn build_dump_command(
    connection: &DatabaseConnection,
    credentials: &DatabaseCredentials,
    database: &str,
) -> CoreResult<String> {
    connection.validate()?;
    if !is_valid_sql_ident(database) {
        return Err(CoreError::validation(
            "database backup name",
            "must match the SQL identifier whitelist",
        ));
    }
    let password = credentials.password.as_ref().map(SecretValue::expose);
    let username = connection.username.as_deref().unwrap_or_default();
    Ok(match connection.engine {
        DatabaseEngine::Mysql => format!(
            "{}mysqldump --single-transaction --quick -h {} -P {} -u {} -- {}",
            password
                .map(|value| format!("MYSQL_PWD={} ", shq(value)))
                .unwrap_or_default(),
            shq(&connection.host),
            connection.port,
            shq(username),
            shq(database),
        ),
        DatabaseEngine::Postgresql => format!(
            "{}pg_dump -h {} -p {} -U {} -- {}",
            password
                .map(|value| format!("PGPASSWORD={} ", shq(value)))
                .unwrap_or_default(),
            shq(&connection.host),
            connection.port,
            shq(username),
            shq(database),
        ),
        DatabaseEngine::Mongo => format!(
            "mongodump --host {} --port {} {} {} --db {} --out __OUTPUT__",
            shq(&connection.host),
            connection.port,
            if username.is_empty() {
                String::new()
            } else {
                format!("--username {}", shq(username))
            },
            password
                .map(|value| format!("--password {} --authenticationDatabase admin", shq(value)))
                .unwrap_or_default(),
            shq(database),
        ),
        DatabaseEngine::Redis | DatabaseEngine::Dm | DatabaseEngine::Kingbase => {
            return Err(CoreError::Unsupported {
                feature: "dump command for this database engine",
            });
        }
    })
}

fn validate_statement(statement: &str) -> CoreResult<()> {
    if statement.trim().is_empty() || statement.len() > MAX_SQL_BYTES || statement.contains('\0') {
        return Err(CoreError::validation(
            "SQL statement",
            format!("must be non-empty, NUL-free, and at most {MAX_SQL_BYTES} bytes"),
        ));
    }
    Ok(())
}

fn validate_read_only_statement(engine: DatabaseEngine, statement: &str) -> CoreResult<()> {
    validate_statement(statement)?;
    let trimmed = statement.trim().trim_end_matches(';').trim();
    if trimmed.contains(';') || trimmed.starts_with("--") || trimmed.starts_with("/*") {
        return Err(CoreError::validation(
            "read-only query",
            "must contain exactly one uncommented statement",
        ));
    }
    let keyword = trimmed
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    let allowed = match engine {
        DatabaseEngine::Mysql | DatabaseEngine::Postgresql => {
            matches!(keyword.as_str(), "SELECT" | "SHOW" | "DESCRIBE" | "EXPLAIN")
        }
        DatabaseEngine::Redis => matches!(
            keyword.as_str(),
            "GET"
                | "MGET"
                | "SCAN"
                | "HGET"
                | "HGETALL"
                | "INFO"
                | "DBSIZE"
                | "TTL"
                | "TYPE"
                | "PING"
                | "LASTSAVE"
                | "ACL"
        ),
        DatabaseEngine::Mongo => {
            let lower = trimmed.to_ascii_lowercase();
            let command_is_read_only = (!lower.contains(".runcommand(")
                || lower == "db.runcommand({ping:1})")
                && (!lower.contains(".admincommand(") || lower.contains("listdatabases"));
            (lower.starts_with("db.") || lower.starts_with("var s=db.serverstatus(); print("))
                && command_is_read_only
                && ![
                    ".insert",
                    ".update",
                    ".replace",
                    ".delete",
                    ".remove",
                    ".drop",
                    ".create",
                    ".rename",
                    ".findandmodify",
                    ".bulkwrite",
                    ".save(",
                    "$out",
                    "$merge",
                ]
                .iter()
                .any(|forbidden| lower.contains(forbidden))
        }
        DatabaseEngine::Dm | DatabaseEngine::Kingbase => false,
    };
    if !allowed {
        return Err(CoreError::validation(
            "read-only query",
            "statement is not in the read-only command allowlist; use plan_mutation",
        ));
    }
    let upper = format!(" {} ", trimmed.to_ascii_uppercase());
    if upper.contains(" INTO OUTFILE ") || upper.contains(" INTO DUMPFILE ") {
        return Err(CoreError::validation(
            "read-only query",
            "file-writing SELECT variants require plan_mutation",
        ));
    }
    if engine == DatabaseEngine::Redis
        && keyword == "ACL"
        && trimmed
            .split_whitespace()
            .nth(1)
            .is_none_or(|subcommand| !subcommand.eq_ignore_ascii_case("LIST"))
    {
        return Err(CoreError::validation(
            "read-only Redis command",
            "only ACL LIST is accepted by the read-only boundary",
        ));
    }
    Ok(())
}

fn build_command(
    connection: &DatabaseConnection,
    credentials: &DatabaseCredentials,
    statement: &str,
) -> CoreResult<String> {
    connection.validate()?;
    validate_statement(statement)?;
    let host = shq(&connection.host);
    let username = connection.username.as_deref().unwrap_or_default();
    let database = connection.database.as_deref().unwrap_or_default();
    let password = credentials.password.as_ref().map(SecretValue::expose);
    Ok(match connection.engine {
        DatabaseEngine::Mysql => format!(
            "{}mysql --batch --raw -h {host} -P {} -u {} {} -e {}",
            password
                .map(|value| format!("MYSQL_PWD={} ", shq(value)))
                .unwrap_or_default(),
            connection.port,
            shq(username),
            if database.is_empty() {
                String::new()
            } else {
                format!("--database {}", shq(database))
            },
            shq(statement),
        ),
        DatabaseEngine::Postgresql => format!(
            "{}psql -X -v ON_ERROR_STOP=1 -A -F '\\t' -P footer=off -h {host} -p {} -U {} {} -c {}",
            password
                .map(|value| format!("PGPASSWORD={} ", shq(value)))
                .unwrap_or_default(),
            connection.port,
            shq(username),
            if database.is_empty() {
                String::new()
            } else {
                format!("-d {}", shq(database))
            },
            shq(statement),
        ),
        DatabaseEngine::Redis => format!(
            "{}redis-cli --raw -h {host} -p {} {}",
            password
                .map(|value| format!("REDISCLI_AUTH={} ", shq(value)))
                .unwrap_or_default(),
            connection.port,
            statement
                .split_whitespace()
                .map(shq)
                .collect::<Vec<_>>()
                .join(" "),
        ),
        DatabaseEngine::Mongo => format!(
            "mongosh --quiet --host {host} --port {} {} {} {} --eval {}",
            connection.port,
            if username.is_empty() {
                String::new()
            } else {
                format!(
                    "--username {} --authenticationDatabase admin",
                    shq(username)
                )
            },
            password
                .map(|value| format!("--password {}", shq(value)))
                .unwrap_or_default(),
            if database.is_empty() {
                String::new()
            } else {
                shq(database)
            },
            shq(statement),
        ),
        DatabaseEngine::Dm | DatabaseEngine::Kingbase => {
            return Err(CoreError::Unsupported {
                feature: "database client for detection-only engine",
            });
        }
    })
}

fn parse_result(engine: DatabaseEngine, output: &str) -> SqlResult {
    if matches!(engine, DatabaseEngine::Redis | DatabaseEngine::Mongo) {
        let mut rows: Vec<_> = output
            .lines()
            .take(MAX_RESULT_ROWS + 1)
            .map(|line| vec![line.chars().take(MAX_RESULT_CELL_CHARS).collect()])
            .collect();
        let truncated = rows.len() > MAX_RESULT_ROWS;
        rows.truncate(MAX_RESULT_ROWS);
        return SqlResult {
            columns: vec!["value".to_owned()],
            rows,
            truncated,
            execution_time_ms: 0,
        };
    }
    let mut lines = output.lines();
    let columns = lines
        .next()
        .map(|line| {
            line.split('\t')
                .map(|cell| cell.chars().take(MAX_RESULT_CELL_CHARS).collect())
                .collect()
        })
        .unwrap_or_default();
    let mut rows: Vec<_> = lines
        .take(MAX_RESULT_ROWS + 1)
        .map(|line| line.split('\t').map(str::to_owned).collect())
        .collect();
    let truncated = rows.len() > MAX_RESULT_ROWS;
    rows.truncate(MAX_RESULT_ROWS);
    SqlResult {
        columns,
        rows,
        truncated,
        execution_time_ms: 0,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::{Arc, Mutex},
    };

    use super::*;
    use crate::database_config_inventory::{
        DatabaseConfigPluginInventoryRow, DatabaseConfigPluginMaturity, DatabaseConfigPluginStatus,
    };
    use crate::database_config_schema::DatabaseConfigVersion;
    use crate::domain::CommandOutput;
    use crate::{
        BackendServices,
        ssh::{SshConnectionStatus, TestSessionHarness},
        target::{TargetContext, TargetIdentity},
    };
    use chrono::Utc;

    #[derive(Debug)]
    struct StubRunner {
        command: Mutex<Option<String>>,
        output: String,
    }

    impl CommandRunner for StubRunner {
        fn run(&self, command: &str) -> CoreResult<CommandOutput> {
            *self.command.lock().unwrap() = Some(command.to_owned());
            Ok(CommandOutput::success(&self.output))
        }
    }

    fn connection(engine: DatabaseEngine) -> DatabaseConnection {
        DatabaseConnection {
            engine,
            host: "127.0.0.1".to_owned(),
            port: 3306,
            username: Some("root".to_owned()),
            database: Some("incident".to_owned()),
        }
    }

    #[derive(Debug)]
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("lovelyres-database-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    async fn bound_services(
        root: &TestRoot,
    ) -> (BackendServices, BoundSshSession, Arc<TestSessionHarness>) {
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
        services
            .ssh()
            .install_test_session(status, harness.clone())
            .await
            .unwrap();
        (services, session, harness)
    }

    fn save_profile(service: &DatabaseService) -> DatabaseProfileView {
        service
            .upsert_profile(
                DatabaseProfileConfig {
                    ssh_connection_id: None,
                    postgresql_tls: None,
                    id: "mysql-main".to_owned(),
                    name: "MySQL main".to_owned(),
                    connection: connection(DatabaseEngine::Mysql),
                },
                DatabaseProfileChanges {
                    password: DatabaseSecretChange::Replace(SecretValue::new("db-secret")),
                },
            )
            .unwrap()
    }

    fn save_runtime_profile(service: &DatabaseService) -> DatabaseProfileView {
        service
            .upsert_profile(
                DatabaseProfileConfig {
                    ssh_connection_id: None,
                    postgresql_tls: None,
                    id: "mysql-main".to_owned(),
                    name: "MySQL runtime".to_owned(),
                    connection: connection(DatabaseEngine::Mysql),
                },
                DatabaseProfileChanges {
                    password: DatabaseSecretChange::Remove,
                },
            )
            .unwrap()
    }

    fn runtime_hex(value: &str) -> String {
        value
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect()
    }

    fn mysql_identity_wire(version: &str) -> String {
        format!(
            "{}\t{}",
            runtime_hex(version),
            runtime_hex("MySQL Community Server - GPL")
        )
    }

    fn mysql_runtime_wire(name: &str, value: &str) -> String {
        [
            runtime_hex(name),
            runtime_hex(value),
            runtime_hex("global"),
            runtime_hex("vendor-defined"),
            runtime_hex("COMPILED"),
            "-".to_owned(),
            runtime_hex("1"),
            runtime_hex("100000"),
            "-".to_owned(),
        ]
        .join("\t")
    }

    fn inventory_wire_row(cells: &[Option<&str>]) -> String {
        cells
            .iter()
            .map(|cell| cell.map_or_else(|| "-".to_owned(), runtime_hex))
            .collect::<Vec<_>>()
            .join("\t")
    }

    fn plugin_inventory_wire(
        product: DatabaseConfigProduct,
        version: &str,
        rows: &[String],
    ) -> String {
        let identity = match product {
            DatabaseConfigProduct::MySql => inventory_wire_row(&[
                Some("identity_v1"),
                Some(version),
                Some("MySQL Community Server - GPL"),
                None,
                None,
                None,
                None,
            ]),
            DatabaseConfigProduct::MariaDb => inventory_wire_row(&[
                Some("identity_v1"),
                Some(version),
                None,
                None,
                None,
                None,
                None,
            ]),
            _ => unreachable!(),
        };
        let mut wire = format!("{identity}\n");
        if !rows.is_empty() {
            wire.push_str(&rows.join("\n"));
            wire.push('\n');
        }
        wire.push_str("636F6D706C6574655F7631\t-\t-\t-\t-\t-\t-\n");
        wire
    }

    fn component_inventory_wire(version: &str, rows: &[String]) -> String {
        let identity = inventory_wire_row(&[
            Some("identity_v1"),
            Some(version),
            Some("MySQL Community Server - GPL"),
        ]);
        let mut wire = format!("{identity}\n");
        if !rows.is_empty() {
            wire.push_str(&rows.join("\n"));
            wire.push('\n');
        }
        wire.push_str("-\t-\t636F6D706C6574655F7631\n");
        wire
    }

    #[test]
    fn read_only_boundary_rejects_mutation_and_stacked_statements() {
        for statement in [
            "DELETE FROM users",
            "SELECT 1; DROP TABLE users",
            "/* hidden */ DELETE FROM users",
            "SELECT * INTO OUTFILE '/tmp/x' FROM users",
        ] {
            assert!(validate_read_only_statement(DatabaseEngine::Mysql, statement).is_err());
        }
        assert!(
            validate_read_only_statement(DatabaseEngine::Mysql, "SELECT * FROM users;").is_ok()
        );
    }

    #[test]
    fn shell_command_quotes_password_and_sql_payloads() {
        let runner = StubRunner {
            command: Mutex::new(None),
            output: "id\tname\n1\talice".to_owned(),
        };
        let credentials = DatabaseCredentials::password(SecretValue::new("p'ass; id"));
        let result = DatabaseService::query_with_runner(
            &runner,
            &connection(DatabaseEngine::Mysql),
            &credentials,
            "SELECT 'x$(id)' AS name",
        )
        .unwrap();
        assert_eq!(result.columns, ["id", "name"]);
        let command = runner.command.lock().unwrap().clone().unwrap();
        assert!(command.contains("MYSQL_PWD='p'\\''ass; id'"));
        assert!(command.contains("-e 'SELECT '\\''x$(id)'\\'' AS name'"));
    }

    #[test]
    fn runtime_wire_commands_are_closed_headerless_and_shell_quoted() {
        let mysql_profile = ResolvedDatabaseProfile {
            ssh_connection_id: None,
            postgresql_tls: None,
            connection: DatabaseConnection {
                engine: DatabaseEngine::Mysql,
                host: "127.0.0.1".to_owned(),
                port: 3306,
                username: Some("incident-user".to_owned()),
                database: Some("response db".to_owned()),
            },
            credentials: DatabaseCredentials::none(),
        };
        let mysql_plan =
            database_config_runtime_identity_plan(DatabaseConfigProduct::MySql).unwrap();
        let mysql = build_runtime_identity_command(&mysql_profile, mysql_plan).unwrap();
        assert!(
            mysql
                .command
                .starts_with("unset MYSQL_PWD MYSQL_TEST_LOGIN_FILE ")
        );
        assert!(mysql.command.contains("MYSQL_HOME MARIADB_HOME"));
        assert!(mysql.command.contains("LIBMYSQL_ENABLE_CLEARTEXT_PLUGIN"));
        assert!(!mysql.command.contains("MYSQL_PWD="));
        assert!(!mysql.command.contains("LR_DB_PASSWORD"));
        let mysql_options = mysql.command.split_once("exec mysql ").unwrap().1;
        assert!(mysql_options.starts_with("--no-defaults --no-login-paths --password= "));
        assert!(mysql.command.contains("--protocol=TCP"));
        assert!(mysql.command.contains("--skip-column-names"));
        assert!(mysql.command.contains("--database='response db'"));
        assert!(mysql.command.ends_with(&shq(mysql_plan.query())));
        assert!(mysql.stdin.is_empty());

        let mariadb_plan =
            database_config_runtime_identity_plan(DatabaseConfigProduct::MariaDb).unwrap();
        let mariadb = build_runtime_identity_command(&mysql_profile, mariadb_plan).unwrap();
        let mariadb_options = mariadb.command.split_once("exec mysql ").unwrap().1;
        assert!(mariadb_options.starts_with("--no-defaults --password= --protocol=TCP "));
        assert!(!mariadb_options.contains("--no-login-paths"));

        let postgresql_profile = ResolvedDatabaseProfile {
            ssh_connection_id: None,
            postgresql_tls: None,
            connection: DatabaseConnection {
                engine: DatabaseEngine::Postgresql,
                host: "::1".to_owned(),
                port: 5432,
                username: Some("responder".to_owned()),
                database: Some("postgres".to_owned()),
            },
            credentials: DatabaseCredentials::none(),
        };
        let postgresql_plan =
            database_config_runtime_identity_plan(DatabaseConfigProduct::PostgreSql).unwrap();
        let postgresql =
            build_runtime_identity_command(&postgresql_profile, postgresql_plan).unwrap();
        assert!(postgresql.command.starts_with("unset PGPASSWORD; "));
        assert!(!postgresql.command.contains("PGPASSWORD="));
        assert!(postgresql.command.contains("exec psql -X "));
        assert!(postgresql.command.contains("--tuples-only --no-align"));
        assert!(
            postgresql
                .command
                .contains(&format!("--field-separator {}", shq("\t")))
        );
        assert!(!postgresql.command.contains("--field-separator '\\t'"));
        assert!(postgresql.command.contains("--set ON_ERROR_STOP=1"));
        assert!(postgresql.command.ends_with(&shq(postgresql_plan.query())));
        assert!(postgresql.stdin.is_empty());

        let password_profile = ResolvedDatabaseProfile {
            ssh_connection_id: None,
            postgresql_tls: None,
            connection: connection(DatabaseEngine::Mysql),
            credentials: DatabaseCredentials::password(SecretValue::new("do-not-export")),
        };
        let error = build_runtime_identity_command(&password_profile, mysql_plan)
            .err()
            .expect("password-bearing runtime discovery must fail closed");
        assert!(error.to_string().contains("native database protocol"));
        assert!(!format!("{error:?}").contains("do-not-export"));
    }

    #[test]
    fn inventory_wire_command_uses_only_the_reviewed_read_only_query() {
        assert!(INVENTORY_TIMEOUT <= Duration::from_secs(25));
        let profile = ResolvedDatabaseProfile {
            ssh_connection_id: None,
            postgresql_tls: None,
            connection: DatabaseConnection {
                engine: DatabaseEngine::Mysql,
                host: "127.0.0.1".to_owned(),
                port: 3306,
                username: Some("incident-user".to_owned()),
                database: Some("response db".to_owned()),
            },
            credentials: DatabaseCredentials::none(),
        };
        let query_plan = database_config_inventory_query_plan(
            DatabaseConfigProduct::MySql,
            DatabaseConfigInventorySurface::PluginRegistry,
        )
        .unwrap();
        let request = build_inventory_query_command(&profile, query_plan).unwrap();

        assert!(
            request
                .command
                .starts_with("unset MYSQL_PWD MYSQL_TEST_LOGIN_FILE ")
        );
        assert_eq!(request.command.matches("exec mysql").count(), 1);
        assert!(
            request
                .command
                .split_once("exec mysql ")
                .unwrap()
                .1
                .starts_with("--no-defaults --no-login-paths --password= ")
        );
        assert!(request.command.contains("--skip-column-names"));
        assert!(request.command.ends_with(&shq(query_plan.query())));
        assert!(!request.command.contains("MYSQL_PWD="));
        assert_eq!(request.command.matches(" --password=").count(), 1);
        assert!(!request.command.contains(" --defaults-file="));
        assert!(!request.command.contains(" --defaults-extra-file="));
        assert!(!request.command.contains(" --login-path="));
        assert!(!request.command.contains(" --init-command="));
        assert!(!request.command.contains(" > "));
        assert!(request.stdin.is_empty());
        for forbidden in [
            "INSERT",
            "UPDATE",
            "DELETE",
            "ALTER",
            "DROP",
            "TRUNCATE",
            "CALL",
            "INSTALL",
            "UNINSTALL",
        ] {
            assert!(
                !query_plan
                    .query()
                    .split(|character: char| !character.is_ascii_alphanumeric())
                    .any(|token| token.eq_ignore_ascii_case(forbidden)),
                "inventory query unexpectedly contains {forbidden}"
            );
        }

        let mariadb_plan = database_config_inventory_query_plan(
            DatabaseConfigProduct::MariaDb,
            DatabaseConfigInventorySurface::PluginRegistry,
        )
        .unwrap();
        let mariadb_request = build_inventory_query_command(&profile, mariadb_plan).unwrap();
        let mariadb_options = mariadb_request.command.split_once("exec mysql ").unwrap().1;
        assert!(mariadb_options.starts_with("--no-defaults --password= --protocol=TCP "));
        assert!(!mariadb_options.contains("--no-login-paths"));
        assert_eq!(mariadb_options.matches("--password=").count(), 1);
        assert_eq!(mariadb_request.command.matches("exec mysql").count(), 1);
    }

    #[test]
    fn mariadb_wire_is_passwordless_with_either_mysql_client_flavor() {
        let profile = ResolvedDatabaseProfile {
            ssh_connection_id: None,
            postgresql_tls: None,
            connection: DatabaseConnection {
                engine: DatabaseEngine::Mysql,
                host: "127.0.0.1".to_owned(),
                port: 3306,
                username: Some("incident-user".to_owned()),
                database: Some("response".to_owned()),
            },
            credentials: DatabaseCredentials::none(),
        };
        let plan = database_config_inventory_query_plan(
            DatabaseConfigProduct::MariaDb,
            DatabaseConfigInventorySurface::PluginRegistry,
        )
        .unwrap();
        let request = build_inventory_query_command(&profile, plan).unwrap();
        let options = request.command.split_once("exec mysql ").unwrap().1;

        // The executable name does not identify whether the remote binary is
        // Oracle MySQL or MariaDB. This prefix is accepted by both: MariaDB
        // cannot receive MySQL-only `--no-login-paths`, while an Oracle client
        // cannot inherit the password from its implicit login-path file.
        assert!(options.starts_with("--no-defaults --password= --protocol=TCP "));
        assert!(!options.contains("--no-login-paths"));
        assert_eq!(options.matches("--password=").count(), 1);
        assert!(!options.contains("--password='"));
        assert!(!options.contains("--password=\""));
    }

    #[test]
    fn mysql_wire_treats_option_shaped_profile_values_only_as_option_values() {
        let profile = ResolvedDatabaseProfile {
            ssh_connection_id: None,
            postgresql_tls: None,
            connection: DatabaseConnection {
                engine: DatabaseEngine::Mysql,
                host: "127.0.0.1".to_owned(),
                port: 3306,
                username: Some("--defaults-extra-file=/tmp/hostile.cnf".to_owned()),
                database: Some("--init-command=DROP TABLE evidence".to_owned()),
            },
            credentials: DatabaseCredentials::none(),
        };
        let plan = database_config_inventory_query_plan(
            DatabaseConfigProduct::MySql,
            DatabaseConfigInventorySurface::PluginRegistry,
        )
        .unwrap();
        let request = build_inventory_query_command(&profile, plan).unwrap();

        assert!(
            request
                .command
                .contains("--user='--defaults-extra-file=/tmp/hostile.cnf'")
        );
        assert!(
            request
                .command
                .contains("--database='--init-command=DROP TABLE evidence'")
        );
        assert!(!request.command.contains(" --defaults-extra-file="));
        assert!(!request.command.contains(" --init-command="));
        assert_eq!(request.command.matches("exec mysql").count(), 1);
        assert!(request.command.ends_with(&shq(plan.query())));
    }

    #[tokio::test]
    async fn inventory_reads_mysql_plugins_components_and_mariadb_plugins() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        save_runtime_profile(services.database());
        let mysql_plugin = plugin_inventory_wire(
            DatabaseConfigProduct::MySql,
            "8.4.6",
            &[inventory_wire_row(&[
                Some("loaded"),
                Some("InnoDB"),
                Some("ACTIVE"),
                Some("STORAGE ENGINE"),
                None,
                Some("ON"),
                None,
            ])],
        );
        let mysql_component = component_inventory_wire(
            "8.4.6",
            &[inventory_wire_row(&[
                Some("1"),
                Some("1"),
                Some("file://component_validate_password"),
            ])],
        );
        let mariadb_plugin = plugin_inventory_wire(
            DatabaseConfigProduct::MariaDb,
            "11.4.3-MariaDB-log",
            &[inventory_wire_row(&[
                Some("loaded"),
                Some("server_audit"),
                Some("ACTIVE"),
                Some("AUDIT"),
                Some("server_audit.so"),
                Some("ON"),
                Some("Stable"),
            ])],
        );
        harness.set_execute_outputs([mysql_plugin, mysql_component, mariadb_plugin]);

        let plugins = services
            .database()
            .read_database_config_inventory(
                &session,
                "mysql-main",
                DatabaseConfigProduct::MySql,
                DatabaseConfigInventorySurface::PluginRegistry,
            )
            .await
            .unwrap();
        assert_eq!(plugins.product(), DatabaseConfigProduct::MySql);
        assert_eq!(plugins.edition(), DatabaseConfigRuntimeEdition::Community);
        assert_eq!(
            plugins.identity().version(),
            DatabaseConfigVersion::new(8, 4, 6)
        );
        assert_eq!(
            plugins.identity_plan_id(),
            "mysql-native-community-identity-v1"
        );
        assert_eq!(
            plugins.query_plan_id(),
            "mysql-plugin-inventory-composite-read-only-v2"
        );
        let plugin_rows = plugins.document().plugins().unwrap().rows();
        let DatabaseConfigPluginInventoryRow::Loaded(plugin) = &plugin_rows[0] else {
            panic!("expected loaded MySQL plugin")
        };
        assert_eq!(plugin.name().public_value(), Some("InnoDB"));
        assert_eq!(plugin.status(), DatabaseConfigPluginStatus::Active);

        let components = services
            .database()
            .read_database_config_inventory(
                &session,
                "mysql-main",
                DatabaseConfigProduct::MySql,
                DatabaseConfigInventorySurface::ComponentRegistry,
            )
            .await
            .unwrap();
        assert_eq!(
            components.query_plan_id(),
            "mysql-component-inventory-composite-read-only-v2"
        );
        assert_eq!(
            components.document().components().unwrap().rows()[0]
                .urn()
                .public_value(),
            Some("file://component_validate_password")
        );

        let mariadb = services
            .database()
            .read_database_config_inventory(
                &session,
                "mysql-main",
                DatabaseConfigProduct::MariaDb,
                DatabaseConfigInventorySurface::PluginRegistry,
            )
            .await
            .unwrap();
        assert_eq!(mariadb.product(), DatabaseConfigProduct::MariaDb);
        assert_eq!(
            mariadb.query_plan_id(),
            "mariadb-plugin-inventory-composite-read-only-v2"
        );
        let mariadb_rows = mariadb.document().plugins().unwrap().rows();
        let DatabaseConfigPluginInventoryRow::Loaded(plugin) = &mariadb_rows[0] else {
            panic!("expected loaded MariaDB plugin")
        };
        assert_eq!(plugin.name().public_value(), Some("server_audit"));
        assert_eq!(
            plugin.maturity(),
            Some(DatabaseConfigPluginMaturity::Stable)
        );

        for snapshot in [&plugins, &components, &mariadb] {
            services
                .database()
                .validate_database_config_inventory_snapshot(snapshot)
                .unwrap();
        }
        let (_, digest) = services
            .database()
            .profiles
            .resolve_with_digest("mysql-main")
            .unwrap();
        let debug = format!("{plugins:?}{components:?}{mariadb:?}");
        assert!(!debug.contains(&digest));
        assert!(!debug.contains("server_audit.so"));

        let mut changed = services.database().profiles().unwrap()[0].config.clone();
        changed.name = "changed after inventory read".to_owned();
        services
            .database()
            .upsert_profile(changed, DatabaseProfileChanges::default())
            .unwrap();
        assert!(
            services
                .database()
                .validate_database_config_inventory_snapshot(&plugins)
                .is_err()
        );
    }

    #[tokio::test]
    async fn inventory_rejects_mariadb_components_before_any_ssh_request() {
        let root = TestRoot::new();
        let (services, session, _harness) = bound_services(&root).await;
        save_runtime_profile(services.database());

        let result = tokio::time::timeout(
            Duration::from_secs(2),
            services.database().read_database_config_inventory(
                &session,
                "mysql-main",
                DatabaseConfigProduct::MariaDb,
                DatabaseConfigInventorySurface::ComponentRegistry,
            ),
        )
        .await
        .expect("unsupported surface must fail before entering the SSH harness");
        let error = result.unwrap_err();
        assert!(error.to_string().contains("inventory surface"));
    }

    #[tokio::test]
    async fn inventory_rejects_password_profiles_before_the_first_ssh_request() {
        let root = TestRoot::new();
        let (services, session, _harness) = bound_services(&root).await;
        save_profile(services.database());

        let result = tokio::time::timeout(
            Duration::from_secs(2),
            services.database().read_database_config_inventory(
                &session,
                "mysql-main",
                DatabaseConfigProduct::MySql,
                DatabaseConfigInventorySurface::PluginRegistry,
            ),
        )
        .await
        .expect("password profile must fail before entering the SSH harness");
        let error = result.unwrap_err();
        assert!(error.to_string().contains("native database protocol"));
        assert!(!format!("{error:?}").contains("db-secret"));
    }

    #[tokio::test]
    async fn inventory_rejects_profile_change_while_composite_query_is_in_flight() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        let view = save_runtime_profile(services.database());

        let service = services.database().clone();
        let session_for_task = session.clone();
        let read = tokio::spawn(async move {
            service
                .read_database_config_inventory(
                    &session_for_task,
                    "mysql-main",
                    DatabaseConfigProduct::MySql,
                    DatabaseConfigInventorySurface::PluginRegistry,
                )
                .await
        });
        harness.wait_for_entered(1).await;
        let mut changed = view.config;
        changed.name = "changed during composite inventory read".to_owned();
        services
            .database()
            .upsert_profile(changed, DatabaseProfileChanges::default())
            .unwrap();
        harness.release_operations();

        let error = read.await.unwrap().unwrap_err();
        assert!(error.to_string().contains("profile changed"));
    }

    #[tokio::test]
    async fn inventory_rejects_target_change_while_query_is_in_flight() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        save_runtime_profile(services.database());
        let service = services.database().clone();
        let session_for_task = session.clone();
        let read = tokio::spawn(async move {
            service
                .read_database_config_inventory(
                    &session_for_task,
                    "mysql-main",
                    DatabaseConfigProduct::MySql,
                    DatabaseConfigInventorySurface::PluginRegistry,
                )
                .await
        });
        harness.wait_for_entered(1).await;
        services
            .activate_target(TargetIdentity::new("connection-b").unwrap())
            .unwrap();
        harness.release_operations();

        let error = read.await.unwrap().unwrap_err();
        assert!(matches!(error, CoreError::TargetChanged { .. }));
    }

    #[tokio::test]
    async fn inventory_snapshot_revalidation_rejects_a_later_target_switch() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        save_runtime_profile(services.database());
        harness.set_execute_outputs([plugin_inventory_wire(
            DatabaseConfigProduct::MySql,
            "8.4.6",
            &[],
        )]);
        let snapshot = services
            .database()
            .read_database_config_inventory(
                &session,
                "mysql-main",
                DatabaseConfigProduct::MySql,
                DatabaseConfigInventorySurface::PluginRegistry,
            )
            .await
            .unwrap();
        services
            .activate_target(TargetIdentity::new("connection-b").unwrap())
            .unwrap();

        let error = services
            .database()
            .validate_database_config_inventory_snapshot(&snapshot)
            .unwrap_err();
        assert!(matches!(error, CoreError::TargetChanged { .. }));
    }

    #[test]
    fn inventory_sensitive_stderr_is_discarded_without_echoing_secrets() {
        let secret = "stderr-password=NeverEchoThis";
        let output = SshSensitiveCommandOutput {
            stdout: Zeroizing::new(b"hostile stdout".to_vec()),
            stderr: Zeroizing::new(secret.as_bytes().to_vec()),
            exit_code: Some(1),
            duration_ms: 1,
        };
        assert!(!format!("{output:?}").contains(secret));

        let error =
            successful_sensitive_database_output("database configuration inventory", output)
                .unwrap_err();
        assert!(!error.to_string().contains(secret));
        assert!(!format!("{error:?}").contains(secret));
        assert!(!error.to_string().contains("hostile stdout"));
    }

    #[tokio::test]
    async fn runtime_parameters_require_verified_identity_and_discard_raw_wire() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        save_runtime_profile(services.database());
        harness.set_execute_outputs([
            mysql_identity_wire("8.4.6"),
            mysql_runtime_wire("MAX_CONNECTIONS", "151"),
        ]);

        let snapshot = services
            .database()
            .read_runtime_parameters(&session, "mysql-main", DatabaseConfigProduct::MySql)
            .await
            .unwrap();
        assert_eq!(snapshot.product(), DatabaseConfigProduct::MySql);
        assert_eq!(snapshot.edition(), DatabaseConfigRuntimeEdition::Community);
        assert_eq!(
            snapshot.identity_plan_id(),
            "mysql-native-community-identity-v1"
        );
        assert_eq!(snapshot.query_plan_id(), "mysql-8.4-runtime-read-only-v1");
        assert_eq!(snapshot.document().rows().len(), 1);
        assert_eq!(snapshot.document().rows()[0].name(), "MAX_CONNECTIONS");
        assert_eq!(snapshot.document().rows()[0].value().public_value(), None);
        services
            .database()
            .validate_runtime_parameters_snapshot(&snapshot)
            .unwrap();
        let (_, digest) = services
            .database()
            .profiles
            .resolve_with_digest("mysql-main")
            .unwrap();
        let debug = format!("{snapshot:?}");
        assert!(!debug.contains("db-secret"));
        assert!(!debug.contains("151"));
        assert!(!debug.contains(&digest));

        let mut changed = services.database().profiles().unwrap()[0].config.clone();
        changed.name = "changed after runtime read".to_owned();
        services
            .database()
            .upsert_profile(changed, DatabaseProfileChanges::default())
            .unwrap();
        assert!(
            services
                .database()
                .validate_runtime_parameters_snapshot(&snapshot)
                .is_err()
        );
    }

    #[tokio::test]
    async fn runtime_identity_rejects_mysql_mariadb_product_confusion() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        save_runtime_profile(services.database());
        harness.set_execute_output(runtime_hex("8.4.6"));

        let error = services
            .database()
            .read_runtime_parameters(&session, "mysql-main", DatabaseConfigProduct::MariaDb)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("declared database product"));
        assert!(!format!("{error:?}").contains("382E342E36"));
    }

    #[tokio::test]
    async fn runtime_parameter_read_rejects_profile_changes_between_queries() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        let view = save_runtime_profile(services.database());
        harness.set_execute_outputs([mysql_identity_wire("8.4.6")]);

        let service = services.database().clone();
        let session_for_task = session.clone();
        let read = tokio::spawn(async move {
            service
                .read_runtime_parameters(
                    &session_for_task,
                    "mysql-main",
                    DatabaseConfigProduct::MySql,
                )
                .await
        });
        harness.wait_for_entered(1).await;
        let mut changed = view.config;
        changed.name = "changed during runtime read".to_owned();
        services
            .database()
            .upsert_profile(changed, DatabaseProfileChanges::default())
            .unwrap();
        harness.release_operations();

        let error = read.await.unwrap().unwrap_err();
        assert!(error.to_string().contains("profile changed"));
    }

    #[tokio::test]
    async fn runtime_parameter_read_rejects_target_switch_between_queries() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        save_runtime_profile(services.database());
        harness.set_execute_outputs([mysql_identity_wire("8.4.6")]);

        let service = services.database().clone();
        let session_for_task = session.clone();
        let read = tokio::spawn(async move {
            service
                .read_runtime_parameters(
                    &session_for_task,
                    "mysql-main",
                    DatabaseConfigProduct::MySql,
                )
                .await
        });
        harness.wait_for_entered(1).await;
        services
            .activate_target(TargetIdentity::new("connection-b").unwrap())
            .unwrap();
        harness.release_operations();

        let error = read.await.unwrap().unwrap_err();
        assert!(matches!(error, CoreError::TargetChanged { .. }));
    }

    #[test]
    fn identifiers_and_result_rows_are_bounded() {
        assert!(
            DatabaseService::list_tables_statement(
                DatabaseEngine::Mysql,
                "prod; DROP DATABASE prod",
            )
            .is_err()
        );
        let output = (0..=MAX_RESULT_ROWS)
            .map(|index| index.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let result = parse_result(DatabaseEngine::Redis, &output);
        assert!(result.truncated);
        assert_eq!(result.rows.len(), MAX_RESULT_ROWS);
    }

    #[test]
    fn planned_commands_do_not_debug_or_serialize_credentials() {
        let target = TargetContext::new();
        let guard = target
            .activate(TargetIdentity::new("host").unwrap())
            .unwrap();
        let credentials = DatabaseCredentials::password(SecretValue::new("db-super-secret"));
        let plan = build_mutation_plan(
            guard,
            &ResolvedDatabaseProfile {
                ssh_connection_id: None,
                postgresql_tls: None,
                connection: connection(DatabaseEngine::Mysql),
                credentials,
            },
            &DatabaseMutationRequest {
                statement: "DELETE FROM sessions WHERE expired=1".to_owned(),
                verification_statement: Some("SELECT COUNT(*) FROM sessions".to_owned()),
                verification_contains: None,
                restore_statement: None,
                summary: "remove expired sessions".to_owned(),
            },
        )
        .unwrap();
        let debug = format!("{plan:?}");
        assert!(!debug.contains("db-super-secret"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[tokio::test]
    async fn native_snapshot_read_refuses_a_changed_profile_before_any_ssh_work() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        let config = DatabaseProfileConfig::new("original", DatabaseEngine::Postgresql);
        let snapshot = services
            .database()
            .save_profile_if_unchanged(config, DatabaseProfileChanges::default(), None)
            .unwrap();
        let mut changed = snapshot.view().config.clone();
        changed.name = "new revision".into();
        services
            .database()
            .save_profile_if_unchanged(changed, DatabaseProfileChanges::default(), Some(&snapshot))
            .unwrap();
        assert!(
            services
                .database()
                .read_postgresql_runtime_snapshot(&session, &snapshot)
                .await
                .is_err()
        );
        assert!(harness.execute_commands().is_empty());
    }

    #[tokio::test]
    async fn profile_editor_uses_atomic_revision_checks_and_preserves_credentials() {
        let root = TestRoot::new();
        let (services, _, _) = bound_services(&root).await;
        let service = services.database();
        let config = DatabaseProfileConfig::new("Native profile", DatabaseEngine::Postgresql);
        let snapshot = service
            .save_profile_if_unchanged(
                config.clone(),
                DatabaseProfileChanges {
                    password: DatabaseSecretChange::Replace(SecretValue::new(
                        "ProfileRevisionSecretCanary",
                    )),
                },
                None,
            )
            .unwrap();
        assert!(snapshot.view().has_password);
        assert!(!format!("{snapshot:?}").contains("ProfileRevisionSecretCanary"));
        assert!(
            service
                .save_profile_if_unchanged(config.clone(), DatabaseProfileChanges::default(), None)
                .is_err()
        );
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let attempts = ["First editor", "Second editor"].map(|name| {
            let service = service.clone();
            let mut config = config.clone();
            config.name = name.to_owned();
            let snapshot = snapshot.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                service.save_profile_if_unchanged(
                    config,
                    DatabaseProfileChanges::default(),
                    Some(&snapshot),
                )
            })
        });
        let results = attempts.map(|attempt| attempt.join().unwrap());
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        let updated = results.into_iter().find_map(Result::ok).unwrap();
        assert!(!snapshot.same_revision(&updated));
        assert!(service.validate_profile_snapshot(&snapshot).is_err());
        assert!(service.plan_delete_profile_snapshot(&snapshot).is_err());
        assert!(
            service
                .profiles
                .resolve(&config.id)
                .unwrap()
                .credentials
                .password
                .as_ref()
                .unwrap()
                .expose()
                == "ProfileRevisionSecretCanary"
        );
        let before = fs::read(services.store().path_for(StoreFile::Database)).unwrap();
        let mut forged = updated.view().config.clone();
        forged.id = "different-id".to_owned();
        assert!(
            service
                .save_profile_if_unchanged(
                    forged,
                    DatabaseProfileChanges::default(),
                    Some(&updated)
                )
                .is_err()
        );
        assert_eq!(
            fs::read(services.store().path_for(StoreFile::Database)).unwrap(),
            before
        );
        let removed_secret = service
            .save_profile_if_unchanged(
                updated.view().config.clone(),
                DatabaseProfileChanges {
                    password: DatabaseSecretChange::Remove,
                },
                Some(&updated),
            )
            .unwrap();
        assert!(!removed_secret.view().has_password);
        let plan = service
            .plan_delete_profile_snapshot(&removed_secret)
            .unwrap();
        let approval = DangerousConfirmation::approve(plan.definition());
        let outcome = service
            .execute_delete_profile(plan, approval, services.operation_journal())
            .await
            .unwrap();
        assert!(outcome.verification.passed);
        assert!(
            service
                .save_profile_if_unchanged(
                    removed_secret.view().config.clone(),
                    DatabaseProfileChanges::default(),
                    Some(&removed_secret)
                )
                .is_err()
        );
        assert!(service.profile_snapshots().unwrap().is_empty());
    }

    #[tokio::test]
    async fn associated_profile_refuses_a_different_ssh_connection_before_any_command() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        let mut profile = DatabaseProfileConfig::new("Other server", DatabaseEngine::Postgresql);
        profile.ssh_connection_id = Some("connection-b".to_owned());
        services
            .database()
            .save_profile_if_unchanged(profile.clone(), DatabaseProfileChanges::default(), None)
            .unwrap();
        assert!(
            services
                .database()
                .read_runtime_parameters(&session, &profile.id, DatabaseConfigProduct::PostgreSql)
                .await
                .is_err()
        );
        assert!(
            services
                .database()
                .test_profile(&session, &profile.id)
                .await
                .is_err()
        );
        assert!(harness.execute_commands().is_empty());
    }

    #[tokio::test]
    async fn profile_store_bounds_reject_duplicates_and_preserve_existing_bytes() {
        let root = TestRoot::new();
        let (services, _, _) = bound_services(&root).await;
        let config = DatabaseProfileConfig::new("Original profile", DatabaseEngine::Postgresql);
        let snapshot = services
            .database()
            .save_profile_if_unchanged(config.clone(), DatabaseProfileChanges::default(), None)
            .unwrap();
        let original = fs::read(services.store().path_for(StoreFile::Database)).unwrap();
        assert!(
            services
                .database()
                .save_profile_if_unchanged(
                    config.clone(),
                    DatabaseProfileChanges {
                        password: DatabaseSecretChange::Replace(SecretValue::new(
                            "x".repeat(MAX_PROFILE_PASSWORD_BYTES + 1)
                        ))
                    },
                    Some(&snapshot)
                )
                .is_err()
        );
        assert_eq!(
            fs::read(services.store().path_for(StoreFile::Database)).unwrap(),
            original
        );
        let duplicate = StoredDatabaseProfile {
            config,
            encrypted_password: None,
        };
        services
            .store()
            .write(
                StoreFile::Database,
                &StoredDatabaseProfiles {
                    profiles: vec![duplicate.clone(), duplicate],
                },
            )
            .unwrap();
        assert!(services.database().profiles().is_err());
        let profiles = (0..MAX_DATABASE_PROFILES)
            .map(|index| StoredDatabaseProfile {
                config: DatabaseProfileConfig::new(
                    format!("Profile {index}"),
                    DatabaseEngine::Postgresql,
                ),
                encrypted_password: None,
            })
            .collect();
        services
            .store()
            .write(StoreFile::Database, &StoredDatabaseProfiles { profiles })
            .unwrap();
        assert_eq!(
            services.database().profiles().unwrap().len(),
            MAX_DATABASE_PROFILES
        );
        let full = fs::read(services.store().path_for(StoreFile::Database)).unwrap();
        assert!(
            services
                .database()
                .save_profile_if_unchanged(
                    DatabaseProfileConfig::new("One too many", DatabaseEngine::Postgresql),
                    DatabaseProfileChanges::default(),
                    None
                )
                .is_err()
        );
        assert_eq!(
            fs::read(services.store().path_for(StoreFile::Database)).unwrap(),
            full
        );
        let mut padded_valid_json = vec![b' '; MAX_PROFILE_STORE_BYTES + 1 - full.len()];
        padded_valid_json.extend_from_slice(&full);
        fs::write(
            services.store().path_for(StoreFile::Database),
            padded_valid_json,
        )
        .unwrap();
        assert!(services.database().profiles().is_err());
    }

    #[tokio::test]
    async fn portable_profiles_encrypt_credentials_and_delete_with_snapshot_cas() {
        let root = TestRoot::new();
        let services =
            BackendServices::new(PortableStore::prepare(root.0.clone()).unwrap()).unwrap();
        let view = save_profile(services.database());
        assert!(view.has_password);
        let json = fs::read_to_string(services.store().path_for(StoreFile::Database)).unwrap();
        assert!(json.contains("enc:v1:"));
        assert!(!json.contains("db-secret"));
        let plan = services
            .database()
            .plan_delete_profile("mysql-main")
            .unwrap();
        let mut changed = view.config;
        changed.name = "renamed while confirming".to_owned();
        services
            .database()
            .upsert_profile(changed, DatabaseProfileChanges::default())
            .unwrap();
        let confirmation = DangerousConfirmation::approve(plan.definition());
        let error = services
            .database()
            .execute_delete_profile(plan, confirmation, services.operation_journal())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("changed after confirmation"));
        assert_eq!(services.database().profiles().unwrap().len(), 1);
    }

    #[test]
    fn detection_and_catalog_parsers_are_typed_and_bounded() {
        let detected = parse_detection(
            "noise\nLRDB\tmysql\trunning\t3306\t/var/lib/mysql\tMySQL\tmysql 8.4\n\
             LRDB\tdm\tstopped\t5236\t/opt/dmdbms/data\tDM (达梦)\tDM8",
        )
        .unwrap();
        assert_eq!(detected.len(), 2);
        assert_eq!(detected[0].engine, DatabaseEngine::Dm);
        assert_eq!(detected[1].status, DatabaseRuntimeStatus::Running);

        let tables = parse_tables(
            DatabaseEngine::Mysql,
            SqlResult {
                columns: vec![],
                rows: vec![vec![
                    "events".to_owned(),
                    "42".to_owned(),
                    "8 KB".to_owned(),
                    "InnoDB".to_owned(),
                ]],
                truncated: false,
                execution_time_ms: 0,
            },
        )
        .unwrap();
        assert_eq!(tables[0].row_count, Some(42));
        assert_eq!(tables[0].engine.as_deref(), Some("InnoDB"));
    }

    #[tokio::test]
    async fn profile_queries_are_bound_to_the_active_ssh_epoch() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        save_profile(services.database());
        harness.set_execute_output("answer\n1");
        let result = services
            .database()
            .query_profile(&session, "mysql-main", None, "SELECT 1 AS answer")
            .await
            .unwrap();
        assert_eq!(result.columns, ["answer"]);
        assert_eq!(result.rows, [vec!["1".to_owned()]]);

        services
            .activate_target(TargetIdentity::new("connection-b").unwrap())
            .unwrap();
        let error = services
            .database()
            .query_profile(&session, "mysql-main", None, "SELECT 1")
            .await
            .unwrap_err();
        assert!(matches!(error, CoreError::TargetChanged { .. }));
    }

    #[tokio::test]
    async fn failed_database_requests_revalidate_the_target_epoch() {
        let target = TargetContext::new();
        let guard = target
            .activate(TargetIdentity::new("connection-a").unwrap())
            .unwrap();

        let error = guarded_result(&target, &guard, || async {
            target
                .activate(TargetIdentity::new("connection-b").unwrap())
                .unwrap();
            Err::<(), _>(CoreError::validation("database query", "remote failure"))
        })
        .await
        .unwrap_err();

        assert!(matches!(error, CoreError::TargetChanged { .. }));
    }

    #[tokio::test]
    async fn dangerous_sql_uses_exact_plan_confirmation_journal_and_verify() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        save_profile(services.database());
        harness.set_execute_output("verified-count\t0");
        let plan = services
            .database()
            .plan_mutation(
                &session,
                "mysql-main",
                Some("incident"),
                &DatabaseMutationRequest {
                    statement: "DELETE FROM sessions WHERE expired=1".to_owned(),
                    verification_statement: Some(
                        "SELECT 'verified-count', COUNT(*) FROM sessions WHERE expired=1"
                            .to_owned(),
                    ),
                    verification_contains: Some("verified-count\t0".to_owned()),
                    restore_statement: None,
                    summary: "delete expired sessions after incident review".to_owned(),
                },
            )
            .await
            .unwrap();
        let wrong = OperationPlan::new(session.target().clone(), "wrong plan", true, None).unwrap();
        let error = services
            .database()
            .execute_action(
                &session,
                plan,
                DangerousConfirmation::approve(&wrong),
                services.operation_journal(),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, CoreError::Validation { .. }));
        assert!(services.operation_journal().entries().unwrap().is_empty());

        let plan = services
            .database()
            .plan_mutation(
                &session,
                "mysql-main",
                None,
                &DatabaseMutationRequest {
                    statement: "DELETE FROM sessions WHERE expired=1".to_owned(),
                    verification_statement: Some(
                        "SELECT 'verified-count', COUNT(*) FROM sessions WHERE expired=1"
                            .to_owned(),
                    ),
                    verification_contains: Some("verified-count\t0".to_owned()),
                    restore_statement: None,
                    summary: "delete expired sessions after incident review".to_owned(),
                },
            )
            .await
            .unwrap();
        let confirmation = DangerousConfirmation::approve(plan.definition());
        let outcome = services
            .database()
            .execute_action(&session, plan, confirmation, services.operation_journal())
            .await
            .unwrap();
        assert!(outcome.verified);
        let journal = services.operation_journal().entries().unwrap();
        assert_eq!(journal.len(), 2);
    }

    #[test]
    fn mongo_and_redis_read_only_boundaries_reject_mutators() {
        for statement in [
            "db.users.deleteMany({})",
            "db.dropDatabase()",
            "db.items.insertOne({x:1})",
        ] {
            assert!(validate_read_only_statement(DatabaseEngine::Mongo, statement).is_err());
        }
        assert!(validate_read_only_statement(DatabaseEngine::Mongo, "db.users.find({})").is_ok());
        assert!(validate_read_only_statement(DatabaseEngine::Redis, "ACL LIST").is_ok());
        assert!(validate_read_only_statement(DatabaseEngine::Redis, "ACL SETUSER root").is_err());
    }

    #[test]
    fn non_zero_database_command_is_never_reported_as_success() {
        let error = successful_database_output(
            "database query",
            SshCommandOutput {
                command: "redacted".to_owned(),
                output: "FATAL: authentication failed".to_owned(),
                exit_code: Some(2),
                duration_ms: 12,
                timed_out: false,
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("exit=Some(2)"));
    }

    #[test]
    fn service_actions_require_expected_state_readback() {
        let active = "mysql\tinactive\nmariadb\tactive\n";
        let stopped = "mysql\tinactive\nmariadb\tinactive\n";
        assert!(verification_passes(
            &DatabaseVerificationPolicy::ServiceRunning(true),
            active,
        ));
        assert!(!verification_passes(
            &DatabaseVerificationPolicy::ServiceRunning(true),
            stopped,
        ));
        assert!(verification_passes(
            &DatabaseVerificationPolicy::ServiceRunning(false),
            stopped,
        ));
        assert_eq!(
            active_service_name(DatabaseEngine::Mysql, active),
            Some("mariadb")
        );
    }
}
