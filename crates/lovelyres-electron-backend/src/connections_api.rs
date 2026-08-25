//! Typed Electron boundary for portable SSH connections.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use lovelyres_core::connections::{
    ConnectionConfig, ConnectionDeletePlan, ConnectionRepository, ConnectionSecretChanges,
    ConnectionView, JumpHostConfig, SecretChange, SshAuthMethod,
};
use lovelyres_core::crypto::SecretValue;
use lovelyres_core::operations::{DangerousConfirmation, PortableOperationJournal};
use lovelyres_core::{CoreError, CoreResult};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use uuid::Uuid;

const MAX_CONNECTION_RESULTS: usize = 1_000;
const MAX_TAGS: usize = 20;
const MAX_NOTES_BYTES: usize = 16 * 1024;
const MAX_SECRET_BYTES: usize = 16 * 1024;
const MAX_DELETE_PLANS: usize = 32;
const DELETE_PLAN_TTL: Duration = Duration::from_secs(5 * 60);
const DELETE_HANDLE_ATTEMPTS: usize = 8;

#[derive(Debug)]
pub struct ConnectionsApi {
    repository: ConnectionRepository,
    journal: PortableOperationJournal,
    mutation_lock: Mutex<()>,
    delete_plans: Mutex<DeletePlanRegistry>,
}

impl ConnectionsApi {
    pub fn new(repository: ConnectionRepository, journal: PortableOperationJournal) -> Self {
        Self {
            repository,
            journal,
            mutation_lock: Mutex::new(()),
            delete_plans: Mutex::new(DeletePlanRegistry::default()),
        }
    }

    pub fn list_connections(&self) -> CoreResult<Vec<ConnectionSummaryDto>> {
        let connections = self.repository.list()?;
        if connections.len() > MAX_CONNECTION_RESULTS {
            return Err(invalid(
                "Electron connection list",
                format!("contains more than {MAX_CONNECTION_RESULTS} entries"),
            ));
        }
        Ok(connections
            .into_iter()
            .map(ConnectionSummaryDto::from)
            .collect())
    }

    pub fn get_connection(&self, connection_id: &str) -> CoreResult<ConnectionEditViewDto> {
        validate_connection_id(connection_id)?;
        self.repository
            .get(connection_id)?
            .map(ConnectionEditViewDto::from)
            .ok_or_else(|| CoreError::NotFound {
                entity: "connection",
                id: connection_id.to_owned(),
            })
    }

    pub fn create_connection(
        &self,
        input: ConnectionWriteInput,
    ) -> CoreResult<ConnectionEditViewDto> {
        validate_connection_id(&input.connection.id)?;
        let _mutation = self.lock_mutations()?;
        if self.repository.get(&input.connection.id)?.is_some() {
            return Err(invalid(
                "Electron connection create",
                "a connection with this id already exists",
            ));
        }
        let (config, changes) = input.into_core(None)?;
        self.repository
            .upsert(config, changes)
            .map(ConnectionEditViewDto::from)
    }

    pub fn update_connection(
        &self,
        input: ConnectionWriteInput,
    ) -> CoreResult<ConnectionEditViewDto> {
        validate_connection_id(&input.connection.id)?;
        let _mutation = self.lock_mutations()?;
        let existing =
            self.repository
                .get(&input.connection.id)?
                .ok_or_else(|| CoreError::NotFound {
                    entity: "connection",
                    id: input.connection.id.clone(),
                })?;
        let (config, changes) = input.into_core(Some(&existing))?;
        self.repository
            .upsert(config, changes)
            .map(ConnectionEditViewDto::from)
    }

    pub fn plan_connection_delete(
        &self,
        connection_id: &str,
    ) -> CoreResult<ConnectionDeletePromptDto> {
        validate_connection_id(connection_id)?;
        let plan = self.repository.plan_delete(connection_id)?;
        let connection_id = plan.connection_id().to_owned();
        let connection_name = plan.connection_name().to_owned();
        let confirmation_text = plan.definition().summary.clone();
        let handle = self.lock_delete_plans()?.insert(plan, Instant::now())?;
        let prompt = ConnectionDeletePromptDto {
            handle,
            connection_id,
            connection_name,
            confirmation_text,
        };
        Ok(prompt)
    }

    pub async fn confirm_connection_delete(
        &self,
        handle: &str,
    ) -> CoreResult<ConnectionDeleteResultDto> {
        validate_delete_handle(handle)?;
        let plan = self
            .lock_delete_plans()?
            .take(handle, Instant::now())
            .ok_or_else(|| CoreError::NotFound {
                entity: "connection delete plan handle",
                id: "[opaque]".to_owned(),
            })?;

        // The renderer never supplies an operation id or confirmation object. The
        // exact confirmation is constructed only after recovering the in-memory plan.
        let confirmation = DangerousConfirmation::approve(plan.definition());
        let outcome = self
            .repository
            .execute_delete(plan, confirmation, &self.journal)
            .await?;
        Ok(ConnectionDeleteResultDto {
            operation_id: outcome.operation_id,
            verified: outcome.verification.passed,
            verification_detail: outcome.verification.detail,
        })
    }

    pub fn cancel_connection_delete(
        &self,
        handle: &str,
    ) -> CoreResult<ConnectionDeleteCancelledDto> {
        validate_delete_handle(handle)?;
        self.lock_delete_plans()?
            .take(handle, Instant::now())
            .ok_or_else(|| CoreError::NotFound {
                entity: "connection delete plan handle",
                id: "[opaque]".to_owned(),
            })?;
        Ok(ConnectionDeleteCancelledDto { cancelled: true })
    }

    pub fn import_connections(&self, source: &Path) -> CoreResult<ConnectionImportResultDto> {
        let _mutation = self.lock_mutations()?;
        let summary = self.repository.import_file(source)?;
        Ok(ConnectionImportResultDto {
            imported: summary.imported,
            skipped_existing: summary.skipped_existing,
            skipped_duplicate: summary.skipped_duplicate,
        })
    }

    pub fn export_connections(&self, destination: &Path) -> CoreResult<ConnectionExportResultDto> {
        let count = self.repository.write_new_export(destination)?;
        Ok(ConnectionExportResultDto { count })
    }

    fn lock_mutations(&self) -> CoreResult<MutexGuard<'_, ()>> {
        self.mutation_lock.lock().map_err(|_| {
            invalid(
                "Electron connection mutation",
                "internal lock is unavailable",
            )
        })
    }

    fn lock_delete_plans(&self) -> CoreResult<MutexGuard<'_, DeletePlanRegistry>> {
        self.delete_plans.lock().map_err(|_| {
            invalid(
                "Electron connection delete plans",
                "internal registry is unavailable",
            )
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionSummaryDto {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_method: SshAuthMethod,
    pub tags: Vec<String>,
    pub group: Option<String>,
    pub environment: Option<String>,
    pub last_connected_at: Option<String>,
    pub has_password: bool,
    pub has_key_passphrase: bool,
    pub jump_host_has_password: bool,
    pub jump_host_has_key_passphrase: bool,
}

impl From<ConnectionView> for ConnectionSummaryDto {
    fn from(view: ConnectionView) -> Self {
        Self {
            id: view.config.id,
            name: view.config.name,
            host: view.config.host,
            port: view.config.port,
            username: view.config.username,
            auth_method: view.config.auth_method,
            tags: view.config.tags.into_iter().collect(),
            group: view.config.group,
            environment: view.config.environment,
            last_connected_at: view.last_connected_at.map(|value| value.to_rfc3339()),
            has_password: view.has_password,
            has_key_passphrase: view.has_key_passphrase,
            jump_host_has_password: view.jump_host_has_password,
            jump_host_has_key_passphrase: view.jump_host_has_key_passphrase,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionEditViewDto {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_method: SshAuthMethod,
    pub private_key_path: Option<String>,
    pub certificate_path: Option<String>,
    pub agent_identity_fingerprint: Option<String>,
    pub jump_host: Option<JumpHostEditViewDto>,
    pub tags: Vec<String>,
    pub notes: Option<String>,
    pub environment: Option<String>,
    pub role: Option<String>,
    pub group: Option<String>,
    pub host_key_fingerprint: Option<String>,
    pub has_password: bool,
    pub has_key_passphrase: bool,
    pub jump_host_has_password: bool,
    pub jump_host_has_key_passphrase: bool,
    pub last_connected_at: Option<String>,
}

impl From<ConnectionView> for ConnectionEditViewDto {
    fn from(view: ConnectionView) -> Self {
        Self {
            id: view.config.id,
            name: view.config.name,
            host: view.config.host,
            port: view.config.port,
            username: view.config.username,
            auth_method: view.config.auth_method,
            private_key_path: path_text(view.config.private_key_path),
            certificate_path: path_text(view.config.certificate_path),
            agent_identity_fingerprint: view.config.agent_identity_fingerprint,
            jump_host: view.config.jump_host.map(JumpHostEditViewDto::from),
            tags: view.config.tags.into_iter().collect(),
            notes: view.config.notes,
            environment: view.config.environment,
            role: view.config.role,
            group: view.config.group,
            host_key_fingerprint: view.config.host_key_fingerprint,
            has_password: view.has_password,
            has_key_passphrase: view.has_key_passphrase,
            jump_host_has_password: view.jump_host_has_password,
            jump_host_has_key_passphrase: view.jump_host_has_key_passphrase,
            last_connected_at: view.last_connected_at.map(|value| value.to_rfc3339()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JumpHostEditViewDto {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_method: SshAuthMethod,
    pub private_key_path: Option<String>,
    pub certificate_path: Option<String>,
    pub agent_identity_fingerprint: Option<String>,
    pub host_key_fingerprint: Option<String>,
}

impl From<JumpHostConfig> for JumpHostEditViewDto {
    fn from(config: JumpHostConfig) -> Self {
        Self {
            host: config.host,
            port: config.port,
            username: config.username,
            auth_method: config.auth_method,
            private_key_path: path_text(config.private_key_path),
            certificate_path: path_text(config.certificate_path),
            agent_identity_fingerprint: config.agent_identity_fingerprint,
            host_key_fingerprint: config.host_key_fingerprint,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectionWriteInput {
    pub connection: ConnectionDraftInput,
    #[serde(default)]
    pub secrets: ConnectionSecretWrites,
}

impl ConnectionWriteInput {
    pub(crate) fn into_core(
        self,
        existing: Option<&ConnectionView>,
    ) -> CoreResult<(ConnectionConfig, ConnectionSecretChanges)> {
        let Self {
            connection,
            secrets,
        } = self;
        let config = connection.into_core(existing)?;
        let changes = secrets.into_core(&config, existing)?;
        Ok((config, changes))
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectionDraftInput {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_method: SshAuthMethod,
    pub private_key_path: Option<String>,
    pub certificate_path: Option<String>,
    pub agent_identity_fingerprint: Option<String>,
    pub jump_host: Option<JumpHostDraftInput>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub notes: Option<String>,
    pub environment: Option<String>,
    pub role: Option<String>,
    pub group: Option<String>,
}

impl ConnectionDraftInput {
    fn into_core(self, existing: Option<&ConnectionView>) -> CoreResult<ConnectionConfig> {
        self.validate_bounds()?;
        let host_key_fingerprint = existing
            .filter(|view| view.config.host == self.host && view.config.port == self.port)
            .and_then(|view| view.config.host_key_fingerprint.clone());
        let previous_jump = existing.and_then(|view| view.config.jump_host.as_ref());
        let config = ConnectionConfig {
            id: self.id,
            name: self.name,
            host: self.host,
            port: self.port,
            username: self.username,
            auth_method: self.auth_method,
            private_key_path: self.private_key_path.map(PathBuf::from),
            certificate_path: self.certificate_path.map(PathBuf::from),
            agent_identity_fingerprint: self.agent_identity_fingerprint,
            jump_host: self.jump_host.map(|jump| jump.into_core(previous_jump)),
            tags: self.tags.into_iter().collect(),
            notes: self.notes,
            environment: self.environment,
            role: self.role,
            group: self.group,
            host_key_fingerprint,
        };

        // This preflight uses the domain validator. ConnectionRepository::upsert
        // deliberately repeats it at the persistence boundary.
        config.validate()?;
        Ok(config)
    }

    fn validate_bounds(&self) -> CoreResult<()> {
        validate_connection_id(&self.id)?;
        validate_label("Electron connection name", &self.name, 256)?;
        validate_label("Electron SSH host", &self.host, 253)?;
        validate_label("Electron SSH username", &self.username, 32)?;
        if self.port == 0 {
            return Err(invalid("Electron SSH port", "must be non-zero"));
        }
        validate_auth_fields(
            "Electron SSH authentication",
            self.auth_method,
            self.private_key_path.as_deref(),
            self.certificate_path.as_deref(),
            self.agent_identity_fingerprint.as_deref(),
        )?;
        validate_optional_path(
            "Electron private key path",
            self.private_key_path.as_deref(),
        )?;
        validate_optional_path(
            "Electron certificate path",
            self.certificate_path.as_deref(),
        )?;
        validate_optional_fingerprint(
            "Electron agent identity fingerprint",
            self.agent_identity_fingerprint.as_deref(),
        )?;
        if self.tags.len() > MAX_TAGS {
            return Err(invalid(
                "Electron connection tags",
                format!("must contain at most {MAX_TAGS} entries"),
            ));
        }
        let mut unique_tags = BTreeSet::new();
        for tag in &self.tags {
            validate_label("Electron connection tag", tag, 64)?;
            if !unique_tags.insert(tag) {
                return Err(invalid(
                    "Electron connection tags",
                    "must not contain duplicates",
                ));
            }
        }
        validate_optional_text(
            "Electron connection notes",
            self.notes.as_deref(),
            MAX_NOTES_BYTES,
            true,
        )?;
        validate_optional_text(
            "Electron connection environment",
            self.environment.as_deref(),
            256,
            false,
        )?;
        validate_optional_text("Electron connection role", self.role.as_deref(), 256, false)?;
        validate_optional_text(
            "Electron connection group",
            self.group.as_deref(),
            256,
            false,
        )?;
        if let Some(jump) = &self.jump_host {
            jump.validate_bounds()?;
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JumpHostDraftInput {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_method: SshAuthMethod,
    pub private_key_path: Option<String>,
    pub certificate_path: Option<String>,
    pub agent_identity_fingerprint: Option<String>,
}

impl JumpHostDraftInput {
    fn into_core(self, previous: Option<&JumpHostConfig>) -> JumpHostConfig {
        let host_key_fingerprint = previous
            .filter(|jump| jump.host == self.host && jump.port == self.port)
            .and_then(|jump| jump.host_key_fingerprint.clone());
        JumpHostConfig {
            host: self.host,
            port: self.port,
            username: self.username,
            auth_method: self.auth_method,
            private_key_path: self.private_key_path.map(PathBuf::from),
            certificate_path: self.certificate_path.map(PathBuf::from),
            agent_identity_fingerprint: self.agent_identity_fingerprint,
            host_key_fingerprint,
        }
    }

    fn validate_bounds(&self) -> CoreResult<()> {
        validate_label("Electron jump-host address", &self.host, 253)?;
        validate_label("Electron jump-host username", &self.username, 32)?;
        if self.port == 0 {
            return Err(invalid("Electron jump-host port", "must be non-zero"));
        }
        validate_auth_fields(
            "Electron jump-host authentication",
            self.auth_method,
            self.private_key_path.as_deref(),
            self.certificate_path.as_deref(),
            self.agent_identity_fingerprint.as_deref(),
        )?;
        validate_optional_path(
            "Electron jump-host private key path",
            self.private_key_path.as_deref(),
        )?;
        validate_optional_path(
            "Electron jump-host certificate path",
            self.certificate_path.as_deref(),
        )?;
        validate_optional_fingerprint(
            "Electron jump-host agent identity fingerprint",
            self.agent_identity_fingerprint.as_deref(),
        )
    }
}

#[derive(Debug, Deserialize, Default)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectionSecretWrites {
    pub password: SecretWrite,
    pub key_passphrase: SecretWrite,
    pub jump_host_password: SecretWrite,
    pub jump_host_key_passphrase: SecretWrite,
}

impl ConnectionSecretWrites {
    fn into_core(
        self,
        config: &ConnectionConfig,
        existing: Option<&ConnectionView>,
    ) -> CoreResult<ConnectionSecretChanges> {
        let target_scope_unchanged = existing.is_some_and(|view| {
            view.config.host == config.host
                && view.config.port == config.port
                && view.config.username == config.username
                && view.config.auth_method == config.auth_method
        });
        let target_key_scope_unchanged = target_scope_unchanged
            && existing.is_some_and(|view| view.config.private_key_path == config.private_key_path);
        let jump_scope_unchanged = existing
            .and_then(|view| view.config.jump_host.as_ref())
            .zip(config.jump_host.as_ref())
            .is_some_and(|(previous, current)| {
                previous.host == current.host
                    && previous.port == current.port
                    && previous.username == current.username
                    && previous.auth_method == current.auth_method
            });
        let jump_key_scope_unchanged = jump_scope_unchanged
            && existing
                .and_then(|view| view.config.jump_host.as_ref())
                .zip(config.jump_host.as_ref())
                .is_some_and(|(previous, current)| {
                    previous.private_key_path == current.private_key_path
                });
        let password_active = config.auth_method == SshAuthMethod::Password;
        let key_passphrase_active = uses_private_key(config.auth_method);
        let jump_password_active = config
            .jump_host
            .as_ref()
            .is_some_and(|jump| jump.auth_method == SshAuthMethod::Password);
        let jump_key_passphrase_active = config
            .jump_host
            .as_ref()
            .is_some_and(|jump| uses_private_key(jump.auth_method));

        self.password
            .validate_usage("Electron SSH password", password_active)?;
        self.key_passphrase
            .validate_usage("Electron SSH key passphrase", key_passphrase_active)?;
        self.jump_host_password
            .validate_usage("Electron jump-host password", jump_password_active)?;
        self.jump_host_key_passphrase.validate_usage(
            "Electron jump-host key passphrase",
            jump_key_passphrase_active,
        )?;
        if password_active
            && !self.password.will_exist(
                target_scope_unchanged && existing.is_some_and(|view| view.has_password),
            )
        {
            return Err(invalid(
                "Electron SSH password",
                "password authentication requires a stored or replacement password",
            ));
        }
        if jump_password_active
            && !self.jump_host_password.will_exist(
                jump_scope_unchanged && existing.is_some_and(|view| view.jump_host_has_password),
            )
        {
            return Err(invalid(
                "Electron jump-host password",
                "password authentication requires a stored or replacement password",
            ));
        }

        Ok(ConnectionSecretChanges {
            password: self
                .password
                .into_core(password_active, target_scope_unchanged),
            key_passphrase: self
                .key_passphrase
                .into_core(key_passphrase_active, target_key_scope_unchanged),
            jump_host_password: self
                .jump_host_password
                .into_core(jump_password_active, jump_scope_unchanged),
            jump_host_key_passphrase: self
                .jump_host_key_passphrase
                .into_core(jump_key_passphrase_active, jump_key_scope_unchanged),
        })
    }
}

pub struct SecretWrite(SecretWriteKind);

enum SecretWriteKind {
    Keep,
    Remove,
    Replace(SecretValue),
}

impl SecretWrite {
    pub fn keep() -> Self {
        Self(SecretWriteKind::Keep)
    }

    pub fn remove() -> Self {
        Self(SecretWriteKind::Remove)
    }

    pub fn replace(value: String) -> CoreResult<Self> {
        if value.is_empty() || value.len() > MAX_SECRET_BYTES {
            return Err(invalid(
                "Electron connection secret",
                format!("must contain 1..={MAX_SECRET_BYTES} bytes"),
            ));
        }
        Ok(Self(SecretWriteKind::Replace(SecretValue::new(value))))
    }

    fn validate_usage(&self, subject: &'static str, active: bool) -> CoreResult<()> {
        if !active && matches!(self.0, SecretWriteKind::Replace(_)) {
            return Err(invalid(
                subject,
                "cannot replace a secret unused by the selected authentication method",
            ));
        }
        Ok(())
    }

    fn will_exist(&self, stored: bool) -> bool {
        match self.0 {
            SecretWriteKind::Keep => stored,
            SecretWriteKind::Remove => false,
            SecretWriteKind::Replace(_) => true,
        }
    }

    fn into_core(self, active: bool, keep_scope_unchanged: bool) -> SecretChange {
        if !active {
            return SecretChange::Remove;
        }
        match self.0 {
            SecretWriteKind::Keep if keep_scope_unchanged => SecretChange::Keep,
            SecretWriteKind::Keep => SecretChange::Remove,
            SecretWriteKind::Remove => SecretChange::Remove,
            SecretWriteKind::Replace(secret) => SecretChange::Replace(secret),
        }
    }
}

impl Default for SecretWrite {
    fn default() -> Self {
        Self::keep()
    }
}

impl fmt::Debug for SecretWrite {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            SecretWriteKind::Keep => formatter.write_str("SecretWrite::Keep"),
            SecretWriteKind::Remove => formatter.write_str("SecretWrite::Remove"),
            SecretWriteKind::Replace(_) => formatter.write_str("SecretWrite::Replace([REDACTED])"),
        }
    }
}

impl<'de> Deserialize<'de> for SecretWrite {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(
            tag = "action",
            content = "value",
            rename_all = "kebab-case",
            deny_unknown_fields
        )]
        enum WireSecretWrite {
            Keep,
            Remove,
            Replace(String),
        }

        match WireSecretWrite::deserialize(deserializer)? {
            WireSecretWrite::Keep => Ok(Self::keep()),
            WireSecretWrite::Remove => Ok(Self::remove()),
            WireSecretWrite::Replace(value) => Self::replace(value).map_err(D::Error::custom),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionDeletePromptDto {
    pub handle: String,
    pub connection_id: String,
    pub connection_name: String,
    pub confirmation_text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionDeleteResultDto {
    pub operation_id: String,
    pub verified: bool,
    pub verification_detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionDeleteCancelledDto {
    pub cancelled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionImportResultDto {
    pub imported: usize,
    pub skipped_existing: usize,
    pub skipped_duplicate: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConnectionExportResultDto {
    pub count: usize,
}

#[derive(Default)]
struct DeletePlanRegistry {
    plans: HashMap<String, PendingDeletePlan>,
    order: VecDeque<String>,
}

struct PendingDeletePlan {
    plan: ConnectionDeletePlan,
    expires_at: Instant,
}

impl fmt::Debug for DeletePlanRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeletePlanRegistry")
            .field("plan_count", &self.plans.len())
            .finish()
    }
}

impl DeletePlanRegistry {
    fn insert(&mut self, plan: ConnectionDeletePlan, now: Instant) -> CoreResult<String> {
        self.remove_expired(now);
        while self.plans.len() >= MAX_DELETE_PLANS {
            let Some(oldest) = self.order.pop_front() else {
                self.plans.clear();
                break;
            };
            self.plans.remove(&oldest);
        }

        for _ in 0..DELETE_HANDLE_ATTEMPTS {
            let handle = Uuid::new_v4().simple().to_string();
            if self.plans.contains_key(&handle) {
                continue;
            }
            self.order.push_back(handle.clone());
            self.plans.insert(
                handle.clone(),
                PendingDeletePlan {
                    plan,
                    expires_at: now + DELETE_PLAN_TTL,
                },
            );
            return Ok(handle);
        }

        Err(invalid(
            "Electron connection delete handle",
            "could not allocate a unique opaque identifier",
        ))
    }

    fn take(&mut self, handle: &str, now: Instant) -> Option<ConnectionDeletePlan> {
        self.remove_expired(now);
        let pending = self.plans.remove(handle)?;
        self.order.retain(|existing| existing != handle);
        Some(pending.plan)
    }

    fn remove_expired(&mut self, now: Instant) {
        self.plans.retain(|_, pending| pending.expires_at > now);
        self.order.retain(|handle| self.plans.contains_key(handle));
    }
}

fn validate_connection_id(value: &str) -> CoreResult<()> {
    if value.trim().is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(invalid(
            "Electron connection id",
            "must be non-empty, at most 128 bytes, and contain no controls",
        ));
    }
    Ok(())
}

fn validate_delete_handle(value: &str) -> CoreResult<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(invalid(
            "Electron connection delete handle",
            "must be a bounded opaque identifier",
        ));
    }
    Ok(())
}

fn validate_label(subject: &'static str, value: &str, maximum: usize) -> CoreResult<()> {
    if value.trim().is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(invalid(
            subject,
            format!("must be non-empty, at most {maximum} bytes, and contain no controls"),
        ));
    }
    Ok(())
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
        return Err(invalid(
            subject,
            format!("must be at most {maximum} bytes and contain no unsupported controls"),
        ));
    }
    Ok(())
}

fn validate_optional_path(subject: &'static str, value: Option<&str>) -> CoreResult<()> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.is_empty()
        || value.len() > 4_096
        || value.chars().any(char::is_control)
        || !Path::new(value).is_absolute()
    {
        return Err(invalid(
            subject,
            "must be an absolute path of at most 4096 bytes with no controls",
        ));
    }
    Ok(())
}

fn validate_optional_fingerprint(subject: &'static str, value: Option<&str>) -> CoreResult<()> {
    let Some(value) = value else {
        return Ok(());
    };
    if !value.starts_with("SHA256:") || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(invalid(
            subject,
            "must use the bounded SHA256: OpenSSH representation",
        ));
    }
    Ok(())
}

fn validate_auth_fields(
    subject: &'static str,
    method: SshAuthMethod,
    private_key_path: Option<&str>,
    certificate_path: Option<&str>,
    agent_identity_fingerprint: Option<&str>,
) -> CoreResult<()> {
    let valid = match method {
        SshAuthMethod::Password | SshAuthMethod::KeyboardInteractive => {
            private_key_path.is_none()
                && certificate_path.is_none()
                && agent_identity_fingerprint.is_none()
        }
        SshAuthMethod::PublicKey => {
            private_key_path.is_some()
                && certificate_path.is_none()
                && agent_identity_fingerprint.is_none()
        }
        SshAuthMethod::Agent => private_key_path.is_none() && certificate_path.is_none(),
        SshAuthMethod::Certificate => {
            private_key_path.is_some()
                && certificate_path.is_some()
                && agent_identity_fingerprint.is_none()
        }
    };
    if !valid {
        return Err(invalid(
            subject,
            "credential paths and fingerprints must match the selected authentication method",
        ));
    }
    Ok(())
}

fn uses_private_key(method: SshAuthMethod) -> bool {
    matches!(
        method,
        SshAuthMethod::PublicKey | SshAuthMethod::Certificate
    )
}

fn path_text(path: Option<PathBuf>) -> Option<String> {
    path.map(|value| value.to_string_lossy().into_owned())
}

fn invalid(subject: &'static str, message: impl Into<String>) -> CoreError {
    CoreError::Validation {
        subject,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Arc;

    use lovelyres_core::PortableStore;
    use lovelyres_core::crypto::CryptoVault;
    use serde_json::json;
    use uuid::Uuid;

    use super::*;

    #[derive(Debug)]
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "lovelyres-electron-connections-api-{}",
                Uuid::new_v4()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn api() -> (TestRoot, ConnectionsApi) {
        let root = TestRoot::new();
        let store = PortableStore::prepare(root.0.clone()).unwrap();
        let crypto = Arc::new(CryptoVault::load(&store).unwrap());
        let repository = ConnectionRepository::new(store.clone(), crypto);
        let journal = PortableOperationJournal::new(store);
        (root, ConnectionsApi::new(repository, journal))
    }

    fn input(id: &str, password: &str) -> ConnectionWriteInput {
        serde_json::from_value(json!({
            "connection": {
                "id": id,
                "name": "Incident host",
                "host": "10.0.0.8",
                "port": 22,
                "username": "root",
                "authMethod": "password",
                "privateKeyPath": null,
                "certificatePath": null,
                "agentIdentityFingerprint": null,
                "jumpHost": null,
                "tags": ["critical"],
                "notes": "plain text only",
                "environment": "competition",
                "role": null,
                "group": "red-team"
            },
            "secrets": {
                "password": { "action": "replace", "value": password }
            }
        }))
        .unwrap()
    }

    fn key_input(
        id: &str,
        private_key_path: &str,
        passphrase: Option<&str>,
    ) -> ConnectionWriteInput {
        let mut input = input(id, "unused-password");
        input.connection.auth_method = SshAuthMethod::PublicKey;
        input.connection.private_key_path = Some(private_key_path.to_owned());
        input.secrets.password = SecretWrite::remove();
        input.secrets.key_passphrase = match passphrase {
            Some(passphrase) => SecretWrite::replace(passphrase.to_owned()).unwrap(),
            None => SecretWrite::keep(),
        };
        input
    }

    fn input_with_password_jump_host(
        id: &str,
        password: &str,
        jump_password: &str,
    ) -> ConnectionWriteInput {
        let mut input = input(id, password);
        input.connection.jump_host = Some(JumpHostDraftInput {
            host: "10.0.0.9".to_owned(),
            port: 22,
            username: "jump".to_owned(),
            auth_method: SshAuthMethod::Password,
            private_key_path: None,
            certificate_path: None,
            agent_identity_fingerprint: None,
        });
        input.secrets.jump_host_password = SecretWrite::replace(jump_password.to_owned()).unwrap();
        input
    }

    #[test]
    fn secret_inputs_are_write_only_and_debug_redacted() {
        let input = input("server-1", "never-print-this-secret");
        let debug = format!("{input:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("never-print-this-secret"));

        let oversized = "x".repeat(MAX_SECRET_BYTES + 1);
        let encoded = json!({ "action": "replace", "value": oversized });
        assert!(serde_json::from_value::<SecretWrite>(encoded).is_err());
    }

    #[test]
    fn create_list_and_edit_views_never_return_credentials() {
        let (_root, api) = api();
        let saved = api
            .create_connection(input("server-1", "credential-never-returned"))
            .unwrap();
        assert!(saved.has_password);

        let edit_json = serde_json::to_string(&api.get_connection("server-1").unwrap()).unwrap();
        let list_json = serde_json::to_string(&api.list_connections().unwrap()).unwrap();
        for encoded in [edit_json, list_json] {
            assert!(!encoded.contains("credential-never-returned"));
            assert!(!encoded.contains("enc:v1:"));
            assert!(!encoded.contains("password\":"));
        }
    }

    #[test]
    fn boundary_bounds_then_core_rejects_host_metacharacters() {
        let (_root, api) = api();
        let mut input = input("server-1", "password");
        input.connection.host = "server.example;id".to_owned();
        let error = api.create_connection(input).unwrap_err();
        assert!(matches!(
            error,
            CoreError::Validation {
                subject: "SSH host",
                ..
            }
        ));
    }

    #[test]
    fn create_and_update_are_distinct_and_inputs_are_bounded() {
        let (_root, api) = api();
        api.create_connection(input("server-1", "password"))
            .unwrap();
        assert!(
            api.create_connection(input("server-1", "other-password"))
                .is_err()
        );
        assert!(
            api.update_connection(input("missing", "other-password"))
                .is_err()
        );

        let mut updated = input("server-1", "replacement");
        updated.connection.notes = Some("x".repeat(MAX_NOTES_BYTES + 1));
        assert!(api.update_connection(updated).is_err());

        let mut too_many_tags = input("server-2", "password");
        too_many_tags.connection.tags =
            (0..=MAX_TAGS).map(|index| format!("tag-{index}")).collect();
        assert!(api.create_connection(too_many_tags).is_err());
    }

    #[test]
    fn target_password_keep_is_rejected_after_endpoint_scope_changes() {
        let (_root, api) = api();
        api.create_connection(input("server-1", "original-password"))
            .unwrap();
        let mut moved = input("server-1", "discarded-replacement");
        moved.connection.host = "10.0.0.18".to_owned();
        moved.secrets = ConnectionSecretWrites::default();

        let error = api.update_connection(moved).unwrap_err();
        assert!(matches!(
            error,
            CoreError::Validation {
                subject: "Electron SSH password",
                ..
            }
        ));
        assert_eq!(api.get_connection("server-1").unwrap().host, "10.0.0.8");

        let mut explicit = input("server-1", "replacement-password");
        explicit.connection.host = "10.0.0.18".to_owned();
        let saved = api.update_connection(explicit).unwrap();
        assert_eq!(saved.host, "10.0.0.18");
        assert!(saved.has_password);
    }

    #[test]
    fn target_key_passphrase_keep_is_removed_after_private_key_scope_changes() {
        let (root, api) = api();
        let first_key = root.0.join("first-key").to_string_lossy().into_owned();
        let second_key = root.0.join("second-key").to_string_lossy().into_owned();
        let created = api
            .create_connection(key_input(
                "server-1",
                &first_key,
                Some("original-passphrase"),
            ))
            .unwrap();
        assert!(created.has_key_passphrase);

        let same_scope = api
            .update_connection(key_input("server-1", &first_key, None))
            .unwrap();
        assert!(same_scope.has_key_passphrase);

        let changed_scope = api
            .update_connection(key_input("server-1", &second_key, None))
            .unwrap();
        assert_eq!(
            changed_scope.private_key_path.as_deref(),
            Some(second_key.as_str())
        );
        assert!(!changed_scope.has_key_passphrase);
    }

    #[test]
    fn jump_password_keep_is_rejected_after_jump_endpoint_scope_changes() {
        let (_root, api) = api();
        api.create_connection(input_with_password_jump_host(
            "server-1",
            "target-password",
            "jump-password",
        ))
        .unwrap();
        let mut moved = input_with_password_jump_host(
            "server-1",
            "discarded-target-password",
            "discarded-jump-password",
        );
        moved.connection.jump_host.as_mut().unwrap().host = "10.0.0.19".to_owned();
        moved.secrets = ConnectionSecretWrites::default();

        let error = api.update_connection(moved).unwrap_err();
        assert!(matches!(
            error,
            CoreError::Validation {
                subject: "Electron jump-host password",
                ..
            }
        ));
        assert_eq!(
            api.get_connection("server-1")
                .unwrap()
                .jump_host
                .unwrap()
                .host,
            "10.0.0.9"
        );

        let mut explicit = input_with_password_jump_host(
            "server-1",
            "discarded-target-password",
            "replacement-jump-password",
        );
        explicit.connection.jump_host.as_mut().unwrap().host = "10.0.0.19".to_owned();
        explicit.secrets.password = SecretWrite::keep();
        let saved = api.update_connection(explicit).unwrap();
        assert_eq!(saved.jump_host.unwrap().host, "10.0.0.19");
        assert!(saved.jump_host_has_password);
    }

    #[test]
    fn same_scope_keep_preserves_target_and_jump_passwords() {
        let (_root, api) = api();
        api.create_connection(input_with_password_jump_host(
            "server-1",
            "target-password",
            "jump-password",
        ))
        .unwrap();
        let mut metadata_only = input_with_password_jump_host(
            "server-1",
            "discarded-target-password",
            "discarded-jump-password",
        );
        metadata_only.connection.name = "Renamed incident host".to_owned();
        metadata_only.connection.notes = Some("metadata only".to_owned());
        metadata_only.secrets = ConnectionSecretWrites::default();

        let saved = api.update_connection(metadata_only).unwrap();
        assert_eq!(saved.name, "Renamed incident host");
        assert!(saved.has_password);
        assert!(saved.jump_host_has_password);
    }

    #[tokio::test]
    async fn delete_uses_a_one_time_opaque_in_memory_plan() {
        let (_root, api) = api();
        api.create_connection(input("server-1", "delete-me"))
            .unwrap();
        let prompt = api.plan_connection_delete("server-1").unwrap();
        let operation_id = {
            let registry = api.lock_delete_plans().unwrap();
            registry.plans[&prompt.handle].plan.definition().id.clone()
        };
        let encoded = serde_json::to_string(&prompt).unwrap();
        assert_ne!(prompt.handle, operation_id);
        assert!(!encoded.contains(&operation_id));
        assert!(!encoded.contains("metadata"));
        assert!(!encoded.contains("restoreToken"));
        assert!(!encoded.contains("snapshot-sha256"));

        let result = api.confirm_connection_delete(&prompt.handle).await.unwrap();
        assert!(result.verified);
        assert!(api.get_connection("server-1").is_err());
        assert!(api.confirm_connection_delete(&prompt.handle).await.is_err());
        assert!(api.cancel_connection_delete(&prompt.handle).is_err());
        assert!(!api.journal.entries().unwrap().is_empty());
    }

    #[tokio::test]
    async fn cancelled_delete_is_consumed_without_deleting_or_journaling() {
        let (_root, api) = api();
        api.create_connection(input("server-1", "keep-me")).unwrap();
        let prompt = api.plan_connection_delete("server-1").unwrap();
        let journal_entries_before = api.journal.entries().unwrap().len();

        let cancelled = api.cancel_connection_delete(&prompt.handle).unwrap();
        assert!(cancelled.cancelled);
        assert!(api.get_connection("server-1").is_ok());
        assert_eq!(api.journal.entries().unwrap().len(), journal_entries_before);

        assert!(api.cancel_connection_delete(&prompt.handle).is_err());
        assert!(api.confirm_connection_delete(&prompt.handle).await.is_err());
        assert!(api.get_connection("server-1").is_ok());
        assert_eq!(api.journal.entries().unwrap().len(), journal_entries_before);
    }

    #[tokio::test]
    async fn expired_delete_is_cleaned_up_and_fails_closed() {
        let (_root, api) = api();
        api.create_connection(input("server-1", "keep-me")).unwrap();
        let cancel_prompt = api.plan_connection_delete("server-1").unwrap();
        let confirm_prompt = api.plan_connection_delete("server-1").unwrap();
        let journal_entries_before = api.journal.entries().unwrap().len();
        {
            let mut registry = api.lock_delete_plans().unwrap();
            let now = Instant::now();
            registry
                .plans
                .get_mut(&cancel_prompt.handle)
                .unwrap()
                .expires_at = now;
            registry
                .plans
                .get_mut(&confirm_prompt.handle)
                .unwrap()
                .expires_at = now;
        }

        assert!(api.cancel_connection_delete(&cancel_prompt.handle).is_err());
        assert!(
            api.confirm_connection_delete(&confirm_prompt.handle)
                .await
                .is_err()
        );
        assert!(api.get_connection("server-1").is_ok());
        assert_eq!(api.journal.entries().unwrap().len(), journal_entries_before);
        assert!(
            !api.lock_delete_plans()
                .unwrap()
                .plans
                .contains_key(&cancel_prompt.handle)
        );
        assert!(
            !api.lock_delete_plans()
                .unwrap()
                .plans
                .contains_key(&confirm_prompt.handle)
        );
    }

    #[tokio::test]
    async fn stale_delete_plan_is_consumed_and_fails_closed() {
        let (_root, api) = api();
        api.create_connection(input("server-1", "first-password"))
            .unwrap();
        let prompt = api.plan_connection_delete("server-1").unwrap();

        let mut update = input("server-1", "replacement-password");
        update.connection.notes = Some("changed after planning".to_owned());
        api.update_connection(update).unwrap();

        assert!(api.confirm_connection_delete(&prompt.handle).await.is_err());
        assert!(api.get_connection("server-1").is_ok());
        assert!(api.confirm_connection_delete(&prompt.handle).await.is_err());
    }

    #[test]
    fn delete_registry_is_bounded_and_evicts_the_oldest_capability() {
        let (_root, api) = api();
        api.create_connection(input("server-1", "password"))
            .unwrap();
        let started_at = Instant::now();
        let first = api.plan_connection_delete("server-1").unwrap();
        for _ in 1..=MAX_DELETE_PLANS {
            api.plan_connection_delete("server-1").unwrap();
        }
        let registry = api.lock_delete_plans().unwrap();
        assert_eq!(registry.plans.len(), MAX_DELETE_PLANS);
        assert!(!registry.plans.contains_key(&first.handle));
        assert!(registry.plans.values().all(|pending| {
            pending.expires_at > started_at
                && pending.expires_at <= Instant::now() + DELETE_PLAN_TTL
        }));
        drop(registry);

        assert!(api.cancel_connection_delete(&first.handle).is_err());
        assert!(api.get_connection("server-1").is_ok());
    }

    #[test]
    fn import_export_delegates_to_the_bounded_secret_free_core_contract() {
        let (source_root, source) = api();
        source
            .create_connection(input("source-id", "never-export-this-secret"))
            .unwrap();
        let export_path = source_root.0.join("connections.json");

        let exported = source.export_connections(&export_path).unwrap();
        assert_eq!(exported.count, 1);
        let document = fs::read_to_string(&export_path).unwrap();
        assert!(!document.contains("never-export-this-secret"));
        assert!(!document.contains("enc:v1:"));
        assert!(!document.contains("source-id"));
        let original = fs::read(&export_path).unwrap();
        assert!(source.export_connections(&export_path).is_err());
        assert_eq!(fs::read(&export_path).unwrap(), original);

        let (_target_root, target) = api();
        let imported = target.import_connections(&export_path).unwrap();
        assert_eq!(imported.imported, 1);
        assert_eq!(imported.skipped_existing, 0);
        assert_eq!(imported.skipped_duplicate, 0);
        let view = target.list_connections().unwrap().pop().unwrap();
        assert_ne!(view.id, "source-id");
        assert!(!view.has_password);

        let repeated = target.import_connections(&export_path).unwrap();
        assert_eq!(repeated.imported, 0);
        assert_eq!(repeated.skipped_existing, 1);
        assert_eq!(repeated.skipped_duplicate, 0);
    }
}
