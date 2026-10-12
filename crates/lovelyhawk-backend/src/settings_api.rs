//! Secret-safe desktop boundary over the core-owned portable settings store.
//!
//! It accepts no path. API keys enter through one deserialize-only replacement input,
//! move immediately into `SecretValue`, and never appear in response DTOs. Destructive
//! clearing/removal retains the exact core plan behind a bounded single-use handle.

use std::{
    collections::HashMap,
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use lovelyhawk_core::{
    BackendServices, CoreError,
    crypto::SecretValue,
    net_guard::{ProxySettings, ProxyType},
    operations::{DangerousConfirmation, PortableOperationJournal},
    settings::{
        AiApiKeyClearPlan, AiProviderKind, AiProviderRemovalPlan, AiProviderSettings, AppSettings,
        ApplicationLogLevel, Language, SettingsRepository, Theme,
    },
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const MAX_SETTINGS_TEXT_BYTES: usize = 128 * 1024;
const MAX_AI_PROVIDERS: usize = 32;
const MAX_AI_API_KEY_BYTES: usize = 16 * 1024;
const MAX_PENDING_MUTATIONS: usize = 32;
const MAX_MUTATION_HANDLE_BYTES: usize = 128;
const MUTATION_TTL: Duration = Duration::from_secs(120);

#[derive(Clone)]
pub(crate) struct SettingsApi {
    repository: SettingsRepository,
    journal: PortableOperationJournal,
    pending: Arc<Mutex<SettingsMutationRegistry>>,
}

impl fmt::Debug for SettingsApi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SettingsApi")
            .field("repository", &"[PORTABLE]")
            .field("pending_mutations", &self.pending.lock().plans.len())
            .finish()
    }
}

impl SettingsApi {
    pub(crate) fn new(services: &BackendServices) -> Self {
        Self {
            repository: services.settings().clone(),
            journal: services.operation_journal().clone(),
            pending: Arc::new(Mutex::new(SettingsMutationRegistry::default())),
        }
    }

    pub(crate) fn load(&self) -> Result<SettingsSnapshotDto, SettingsApiError> {
        self.repository
            .load()
            .map(SettingsSnapshotDto::from)
            .map_err(SettingsApiError::from)
    }

    pub(crate) fn save(
        &self,
        input: SettingsSaveInput,
    ) -> Result<SettingsSnapshotDto, SettingsApiError> {
        input.validate_boundary()?;
        let SettingsSaveInput {
            theme,
            language,
            auto_connect,
            default_ssh_port,
            terminal_font_size,
            max_log_lines,
            log_level,
            notifications,
            security,
            ui,
            docker,
            ssh,
            ai,
        } = input;
        self.repository
            .update(move |settings| {
                settings.theme = theme;
                settings.language = language;
                settings.auto_connect = auto_connect;
                settings.default_ssh_port = default_ssh_port;
                settings.terminal_font_size = terminal_font_size;
                settings.max_log_lines = max_log_lines;
                settings.log_level = log_level;
                settings.notifications.enabled = notifications.enabled;
                settings.notifications.connection_status = notifications.connection_status;
                settings.notifications.command_completion = notifications.command_completion;
                settings.notifications.error_alerts = notifications.error_alerts;
                settings.security.save_passwords = security.save_passwords;
                settings.security.session_timeout_ms = security.session_timeout_ms;
                settings.security.require_confirmation = security.require_confirmation;
                settings.ui.sidebar_width = ui.sidebar_width;
                settings.ui.show_status_bar = ui.show_status_bar;
                settings.ui.compact_mode = ui.compact_mode;
                settings.ui.animations_enabled = ui.animations_enabled;
                settings.docker.auto_refresh = docker.auto_refresh;
                settings.docker.refresh_interval_ms = docker.refresh_interval_ms;
                settings.docker.show_system_containers = docker.show_system_containers;
                settings.ssh.keep_alive_interval_ms = ssh.keep_alive_interval_ms;
                settings.ssh.connection_timeout_ms = ssh.connection_timeout_ms;
                settings.ssh.max_retries = ssh.max_retries;
                settings.ai.providers = ai
                    .providers
                    .into_iter()
                    .map(AiProviderSettings::from)
                    .collect();
                settings.ai.default_provider_id = ai.default_provider_id;
                settings.ai.proxy = ai.proxy.map(ProxySettings::from);
                Ok(())
            })
            .map(SettingsSnapshotDto::from)
            .map_err(SettingsApiError::from)
    }

    pub(crate) fn replace_ai_api_key(
        &self,
        input: SettingsAiApiKeyReplacementInput,
    ) -> Result<SettingsAiApiKeyReplacementResult, SettingsApiError> {
        input.validate_boundary()?;
        let SettingsAiApiKeyReplacementInput {
            provider_id,
            api_key,
        } = input;
        self.repository
            .set_ai_api_key(&provider_id, Some(SecretValue::new(api_key)))?;
        let has_api_key = self
            .repository
            .load()?
            .ai
            .providers
            .into_iter()
            .find(|provider| provider.id == provider_id)
            .is_some_and(|provider| provider.has_api_key);
        if !has_api_key {
            return Err(SettingsApiError::VerificationFailed);
        }
        Ok(SettingsAiApiKeyReplacementResult {
            provider_id,
            has_api_key: true,
        })
    }

    pub(crate) fn plan_clear_ai_api_key(
        &self,
        provider_id: &str,
    ) -> Result<SettingsMutationProposal, SettingsApiError> {
        validate_provider_id(provider_id)?;
        let plan = self.repository.plan_clear_ai_api_key(provider_id)?;
        self.insert_plan(PendingSettingsMutation::ClearAiApiKey(plan), Instant::now())
    }

    pub(crate) fn plan_remove_ai_provider(
        &self,
        provider_id: &str,
    ) -> Result<SettingsMutationProposal, SettingsApiError> {
        validate_provider_id(provider_id)?;
        let plan = self.repository.plan_remove_ai_provider(provider_id)?;
        self.insert_plan(
            PendingSettingsMutation::RemoveAiProvider(plan),
            Instant::now(),
        )
    }

    pub(crate) async fn confirm_mutation(
        &self,
        handle: &str,
    ) -> Result<SettingsMutationResult, SettingsApiError> {
        validate_mutation_handle(handle)?;
        let entry = self.pending.lock().take(handle, Instant::now())?;
        let (kind, provider_id, outcome) = match entry.mutation {
            PendingSettingsMutation::ClearAiApiKey(plan) => {
                let provider_id = plan.provider_id().to_owned();
                let confirmation = DangerousConfirmation::approve(plan.definition());
                let outcome = self
                    .repository
                    .execute_clear_ai_api_key(plan, confirmation, &self.journal)
                    .await?;
                (SettingsMutationKind::ClearAiApiKey, provider_id, outcome)
            }
            PendingSettingsMutation::RemoveAiProvider(plan) => {
                let provider_id = plan.provider_id().to_owned();
                let confirmation = DangerousConfirmation::approve(plan.definition());
                let outcome = self
                    .repository
                    .execute_remove_ai_provider(plan, confirmation, &self.journal)
                    .await?;
                (SettingsMutationKind::RemoveAiProvider, provider_id, outcome)
            }
        };
        if !outcome.verification.passed {
            return Err(SettingsApiError::VerificationFailed);
        }
        let snapshot = self.repository.load()?;
        let independently_verified = match kind {
            SettingsMutationKind::ClearAiApiKey => snapshot
                .ai
                .providers
                .iter()
                .find(|provider| provider.id == provider_id)
                .is_some_and(|provider| !provider.has_api_key),
            SettingsMutationKind::RemoveAiProvider => snapshot
                .ai
                .providers
                .iter()
                .all(|provider| provider.id != provider_id),
        };
        if !independently_verified {
            return Err(SettingsApiError::VerificationFailed);
        }
        Ok(SettingsMutationResult {
            kind,
            verified: true,
        })
    }

    pub(crate) fn cancel_mutation(
        &self,
        handle: &str,
    ) -> Result<SettingsMutationCancellation, SettingsApiError> {
        validate_mutation_handle(handle)?;
        self.pending.lock().cancel(handle, Instant::now())?;
        Ok(SettingsMutationCancellation { cancelled: true })
    }

    fn insert_plan(
        &self,
        mutation: PendingSettingsMutation,
        now: Instant,
    ) -> Result<SettingsMutationProposal, SettingsApiError> {
        let kind = mutation.kind();
        let summary = mutation.definition().summary.clone();
        let handle = self.pending.lock().insert(mutation, now)?;
        Ok(SettingsMutationProposal {
            handle,
            kind,
            summary,
            expires_in_seconds: MUTATION_TTL.as_secs(),
        })
    }
}

pub(crate) enum SettingsApiError {
    Core(CoreError),
    InvalidInput,
    InvalidHandle,
    InvalidPlan,
    PlanCapacity,
    VerificationFailed,
}

impl fmt::Debug for SettingsApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core(_) => "SettingsApiError::Core([REDACTED])",
            Self::InvalidInput => "SettingsApiError::InvalidInput",
            Self::InvalidHandle => "SettingsApiError::InvalidHandle",
            Self::InvalidPlan => "SettingsApiError::InvalidPlan",
            Self::PlanCapacity => "SettingsApiError::PlanCapacity",
            Self::VerificationFailed => "SettingsApiError::VerificationFailed",
        })
    }
}

impl fmt::Display for SettingsApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the settings operation failed")
    }
}

impl std::error::Error for SettingsApiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Core(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CoreError> for SettingsApiError {
    fn from(error: CoreError) -> Self {
        Self::Core(error)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SettingsAiApiKeyReplacementInput {
    provider_id: String,
    api_key: String,
}

impl SettingsAiApiKeyReplacementInput {
    fn validate_boundary(&self) -> Result<(), SettingsApiError> {
        validate_provider_id(&self.provider_id)?;
        if self.api_key.is_empty()
            || self.api_key.len() > MAX_AI_API_KEY_BYTES
            || self.api_key.chars().any(char::is_control)
        {
            return Err(SettingsApiError::InvalidInput);
        }
        Ok(())
    }
}

impl fmt::Debug for SettingsAiApiKeyReplacementInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "SettingsAiApiKeyReplacementInput { provider_id: [REDACTED], api_key: [REDACTED] }",
        )
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SettingsAiApiKeyReplacementResult {
    provider_id: String,
    has_api_key: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SettingsMutationKind {
    ClearAiApiKey,
    RemoveAiProvider,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SettingsMutationProposal {
    handle: String,
    kind: SettingsMutationKind,
    summary: String,
    expires_in_seconds: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SettingsMutationResult {
    kind: SettingsMutationKind,
    verified: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct SettingsMutationCancellation {
    cancelled: bool,
}

#[derive(Default)]
struct SettingsMutationRegistry {
    plans: HashMap<String, PendingSettingsMutationEntry>,
}

impl fmt::Debug for SettingsMutationRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SettingsMutationRegistry")
            .field("plan_count", &self.plans.len())
            .finish()
    }
}

struct PendingSettingsMutationEntry {
    created_at: Instant,
    mutation: PendingSettingsMutation,
}

enum PendingSettingsMutation {
    ClearAiApiKey(AiApiKeyClearPlan),
    RemoveAiProvider(AiProviderRemovalPlan),
}

impl PendingSettingsMutation {
    fn kind(&self) -> SettingsMutationKind {
        match self {
            Self::ClearAiApiKey(_) => SettingsMutationKind::ClearAiApiKey,
            Self::RemoveAiProvider(_) => SettingsMutationKind::RemoveAiProvider,
        }
    }

    fn definition(&self) -> &lovelyhawk_core::operations::OperationPlan {
        match self {
            Self::ClearAiApiKey(plan) => plan.definition(),
            Self::RemoveAiProvider(plan) => plan.definition(),
        }
    }
}

impl SettingsMutationRegistry {
    fn insert(
        &mut self,
        mutation: PendingSettingsMutation,
        now: Instant,
    ) -> Result<String, SettingsApiError> {
        self.prune(now);
        if self.plans.len() >= MAX_PENDING_MUTATIONS {
            return Err(SettingsApiError::PlanCapacity);
        }
        let handle = (0..8)
            .map(|_| Uuid::new_v4().to_string())
            .find(|candidate| !self.plans.contains_key(candidate))
            .ok_or(SettingsApiError::PlanCapacity)?;
        self.plans.insert(
            handle.clone(),
            PendingSettingsMutationEntry {
                created_at: now,
                mutation,
            },
        );
        Ok(handle)
    }

    fn take(
        &mut self,
        handle: &str,
        now: Instant,
    ) -> Result<PendingSettingsMutationEntry, SettingsApiError> {
        self.prune(now);
        self.plans
            .remove(handle)
            .ok_or(SettingsApiError::InvalidPlan)
    }

    fn cancel(&mut self, handle: &str, now: Instant) -> Result<(), SettingsApiError> {
        self.take(handle, now).map(|_| ())
    }

    fn prune(&mut self, now: Instant) {
        self.plans
            .retain(|_, entry| now.saturating_duration_since(entry.created_at) < MUTATION_TTL);
    }
}

fn validate_provider_id(provider_id: &str) -> Result<(), SettingsApiError> {
    let mut bytes = provider_id.bytes();
    let Some(first) = bytes.next() else {
        return Err(SettingsApiError::InvalidInput);
    };
    if provider_id.len() > 64
        || !first.is_ascii_alphanumeric()
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(SettingsApiError::InvalidInput);
    }
    Ok(())
}

fn validate_mutation_handle(handle: &str) -> Result<(), SettingsApiError> {
    if handle.is_empty()
        || handle.len() > MAX_MUTATION_HANDLE_BYTES
        || !handle
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(SettingsApiError::InvalidHandle);
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SettingsSnapshotDto {
    theme: Theme,
    language: Language,
    auto_connect: bool,
    default_ssh_port: u16,
    terminal_font_size: u16,
    max_log_lines: u32,
    log_level: ApplicationLogLevel,
    notifications: NotificationSettingsDto,
    security: SecuritySettingsDto,
    ui: UiSettingsDto,
    docker: DockerSettingsDto,
    ssh: SshSettingsDto,
    ai: AiSettingsDto,
}

impl From<AppSettings> for SettingsSnapshotDto {
    fn from(settings: AppSettings) -> Self {
        Self {
            theme: settings.theme,
            language: settings.language,
            auto_connect: settings.auto_connect,
            default_ssh_port: settings.default_ssh_port,
            terminal_font_size: settings.terminal_font_size,
            max_log_lines: settings.max_log_lines,
            log_level: settings.log_level,
            notifications: NotificationSettingsDto {
                enabled: settings.notifications.enabled,
                connection_status: settings.notifications.connection_status,
                command_completion: settings.notifications.command_completion,
                error_alerts: settings.notifications.error_alerts,
            },
            security: SecuritySettingsDto {
                save_passwords: settings.security.save_passwords,
                session_timeout_ms: settings.security.session_timeout_ms,
                require_confirmation: settings.security.require_confirmation,
            },
            ui: UiSettingsDto {
                sidebar_width: settings.ui.sidebar_width,
                show_status_bar: settings.ui.show_status_bar,
                compact_mode: settings.ui.compact_mode,
                animations_enabled: settings.ui.animations_enabled,
            },
            docker: DockerSettingsDto {
                auto_refresh: settings.docker.auto_refresh,
                refresh_interval_ms: settings.docker.refresh_interval_ms,
                show_system_containers: settings.docker.show_system_containers,
            },
            ssh: SshSettingsDto {
                keep_alive_interval_ms: settings.ssh.keep_alive_interval_ms,
                connection_timeout_ms: settings.ssh.connection_timeout_ms,
                max_retries: settings.ssh.max_retries,
            },
            ai: AiSettingsDto {
                providers: settings
                    .ai
                    .providers
                    .into_iter()
                    .map(AiProviderDto::from)
                    .collect(),
                default_provider_id: settings.ai.default_provider_id,
                proxy: settings.ai.proxy.map(ProxySettingsDto::from),
            },
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SettingsSaveInput {
    theme: Theme,
    language: Language,
    auto_connect: bool,
    default_ssh_port: u16,
    terminal_font_size: u16,
    max_log_lines: u32,
    log_level: ApplicationLogLevel,
    notifications: NotificationSettingsDto,
    security: SecuritySettingsDto,
    ui: UiSettingsDto,
    docker: DockerSettingsDto,
    ssh: SshSettingsDto,
    ai: AiSettingsInputDto,
}

impl SettingsSaveInput {
    fn validate_boundary(&self) -> Result<(), SettingsApiError> {
        if self.ai.providers.len() > MAX_AI_PROVIDERS {
            return Err(SettingsApiError::InvalidInput);
        }
        let mut total = 0usize;
        for provider in &self.ai.providers {
            for text in [
                provider.id.as_str(),
                provider.label.as_str(),
                provider.endpoint.as_str(),
                provider.model.as_str(),
            ] {
                total = total
                    .checked_add(text.len())
                    .ok_or(SettingsApiError::InvalidInput)?;
            }
        }
        if let Some(proxy) = &self.ai.proxy {
            total = total
                .checked_add(proxy.proxy_url.len())
                .ok_or(SettingsApiError::InvalidInput)?;
        }
        if total > MAX_SETTINGS_TEXT_BYTES {
            return Err(SettingsApiError::InvalidInput);
        }
        Ok(())
    }
}

impl From<SettingsSnapshotDto> for SettingsSaveInput {
    fn from(snapshot: SettingsSnapshotDto) -> Self {
        Self {
            theme: snapshot.theme,
            language: snapshot.language,
            auto_connect: snapshot.auto_connect,
            default_ssh_port: snapshot.default_ssh_port,
            terminal_font_size: snapshot.terminal_font_size,
            max_log_lines: snapshot.max_log_lines,
            log_level: snapshot.log_level,
            notifications: snapshot.notifications,
            security: snapshot.security,
            ui: snapshot.ui,
            docker: snapshot.docker,
            ssh: snapshot.ssh,
            ai: AiSettingsInputDto {
                providers: snapshot
                    .ai
                    .providers
                    .into_iter()
                    .map(AiProviderInputDto::from)
                    .collect(),
                default_provider_id: snapshot.ai.default_provider_id,
                proxy: snapshot.ai.proxy,
            },
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NotificationSettingsDto {
    enabled: bool,
    connection_status: bool,
    command_completion: bool,
    error_alerts: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SecuritySettingsDto {
    save_passwords: bool,
    session_timeout_ms: u32,
    require_confirmation: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UiSettingsDto {
    sidebar_width: u32,
    show_status_bar: bool,
    compact_mode: bool,
    animations_enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DockerSettingsDto {
    auto_refresh: bool,
    refresh_interval_ms: u32,
    show_system_containers: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SshSettingsDto {
    keep_alive_interval_ms: u32,
    connection_timeout_ms: u32,
    max_retries: u8,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AiSettingsDto {
    providers: Vec<AiProviderDto>,
    default_provider_id: Option<String>,
    proxy: Option<ProxySettingsDto>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AiSettingsInputDto {
    providers: Vec<AiProviderInputDto>,
    default_provider_id: Option<String>,
    proxy: Option<ProxySettingsDto>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AiProviderDto {
    id: String,
    label: String,
    kind: AiProviderKind,
    endpoint: String,
    model: String,
    enabled: bool,
    has_api_key: bool,
}

impl From<AiProviderSettings> for AiProviderDto {
    fn from(provider: AiProviderSettings) -> Self {
        Self {
            id: provider.id,
            label: provider.label,
            kind: provider.kind,
            endpoint: provider.endpoint,
            model: provider.model,
            enabled: provider.enabled,
            has_api_key: provider.has_api_key,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AiProviderInputDto {
    id: String,
    label: String,
    kind: AiProviderKind,
    endpoint: String,
    model: String,
    enabled: bool,
}

impl From<AiProviderDto> for AiProviderInputDto {
    fn from(provider: AiProviderDto) -> Self {
        Self {
            id: provider.id,
            label: provider.label,
            kind: provider.kind,
            endpoint: provider.endpoint,
            model: provider.model,
            enabled: provider.enabled,
        }
    }
}

impl From<AiProviderInputDto> for AiProviderSettings {
    fn from(provider: AiProviderInputDto) -> Self {
        Self {
            id: provider.id,
            label: provider.label,
            kind: provider.kind,
            endpoint: provider.endpoint,
            model: provider.model,
            enabled: provider.enabled,
            // Credential presence is derived from the encrypted core map after save.
            has_api_key: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProxySettingsDto {
    proxy_type: ProxyType,
    proxy_url: String,
}

impl From<ProxySettings> for ProxySettingsDto {
    fn from(proxy: ProxySettings) -> Self {
        Self {
            proxy_type: proxy.proxy_type,
            proxy_url: proxy.proxy_url,
        }
    }
}

impl From<ProxySettingsDto> for ProxySettings {
    fn from(proxy: ProxySettingsDto) -> Self {
        Self {
            proxy_type: proxy.proxy_type,
            proxy_url: proxy.proxy_url,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use lovelyhawk_core::{
        PortableStore,
        crypto::SecretValue,
        operations::JournalPhase,
        settings::{AiProviderKind, AiProviderSettings},
    };
    use serde_json::json;
    use uuid::Uuid;

    use super::*;

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("lovelyres-settings-api-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn api() -> (TestRoot, BackendServices, SettingsApi) {
        let root = TestRoot::new();
        let store = PortableStore::prepare(root.0.clone()).unwrap();
        let services = BackendServices::new(store).unwrap();
        let api = SettingsApi::new(&services);
        (root, services, api)
    }

    fn provider(id: &str) -> AiProviderSettings {
        AiProviderSettings {
            id: id.to_owned(),
            label: "Provider".to_owned(),
            kind: AiProviderKind::OpenAiCompatible,
            endpoint: "https://example.test/v1".to_owned(),
            model: "model".to_owned(),
            enabled: true,
            has_api_key: false,
        }
    }

    #[test]
    fn saves_only_through_the_portable_core_repository() {
        let (root, services, api) = api();
        let mut input = SettingsSaveInput::from(api.load().unwrap());
        input.theme = Theme::Dark;
        input.ui.sidebar_width = 360;
        input.default_ssh_port = 2222;

        let saved = api.save(input).unwrap();
        assert_eq!(saved.theme, Theme::Dark);
        assert_eq!(saved.ui.sidebar_width, 360);
        assert_eq!(services.settings().load().unwrap().default_ssh_port, 2222);
        assert!(root.0.join("data").join("settings.json").is_file());
    }

    #[test]
    fn never_serializes_secrets_and_preserves_core_owned_key_state() {
        let (_root, services, api) = api();
        services
            .settings()
            .update(|settings| {
                settings.ai.providers.push(provider("safe-provider"));
                settings.ai.default_provider_id = Some("safe-provider".to_owned());
                Ok(())
            })
            .unwrap();
        services
            .settings()
            .set_ai_api_key(
                "safe-provider",
                Some(SecretValue::new("Bearer-secret-must-not-cross")),
            )
            .unwrap();

        let snapshot = api.load().unwrap();
        assert!(snapshot.ai.providers[0].has_api_key);
        let encoded = serde_json::to_string(&snapshot).unwrap();
        assert!(!encoded.contains("Bearer-secret-must-not-cross"));
        assert!(!encoded.contains("ciphertext"));

        let mut input = SettingsSaveInput::from(snapshot);
        input.ai.providers[0].label = "</div><script>hostile()</script>".to_owned();
        let saved = api.save(input).unwrap();
        assert!(saved.ai.providers[0].has_api_key);
        assert_eq!(
            saved.ai.providers[0].label,
            "</div><script>hostile()</script>"
        );
    }

    #[test]
    fn exact_deserialization_rejects_paths_secrets_and_unknown_nested_fields() {
        let (_root, _services, api) = api();
        let input = SettingsSaveInput::from(api.load().unwrap());
        let mut value = serde_json::to_value(input).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("dataRoot".to_owned(), json!("C:/Users/person/AppData"));
        assert!(serde_json::from_value::<SettingsSaveInput>(value).is_err());

        let mut value = serde_json::to_value(SettingsSaveInput::from(api.load().unwrap())).unwrap();
        value["ai"]["providers"] = json!([{
            "id": "provider-1",
            "label": "Provider",
            "kind": "open-ai-compatible",
            "endpoint": "https://example.test/v1",
            "model": "model",
            "enabled": true,
            "apiKey": "must-not-cross"
        }]);
        assert!(serde_json::from_value::<SettingsSaveInput>(value).is_err());
    }

    #[test]
    fn core_validation_and_destructive_provider_guard_fail_closed() {
        let (_root, services, api) = api();
        services
            .settings()
            .update(|settings| {
                settings.ai.providers.push(provider("existing"));
                Ok(())
            })
            .unwrap();

        let mut invalid = SettingsSaveInput::from(api.load().unwrap());
        invalid.default_ssh_port = 0;
        let error = api.save(invalid).unwrap_err();
        assert_eq!(error.to_string(), "the settings operation failed");
        assert!(!format!("{error:?}").contains("default SSH port"));

        let mut removal = SettingsSaveInput::from(api.load().unwrap());
        removal.ai.providers.clear();
        assert!(api.save(removal).is_err());
        assert_eq!(services.settings().load().unwrap().ai.providers.len(), 1);
    }

    #[test]
    fn api_key_replacement_is_bounded_write_only_and_debug_redacted() {
        let (_root, services, api) = api();
        services
            .settings()
            .update(|settings| {
                settings.ai.providers.push(provider("write-only"));
                Ok(())
            })
            .unwrap();
        let secret = "Bearer-secret-must-never-return";
        let input = serde_json::from_value::<SettingsAiApiKeyReplacementInput>(json!({
            "providerId": "write-only",
            "apiKey": secret,
        }))
        .unwrap();
        assert!(!format!("{input:?}").contains(secret));
        let result = api.replace_ai_api_key(input).unwrap();
        assert_eq!(result.provider_id, "write-only");
        assert!(result.has_api_key);
        let encoded = serde_json::to_string(&result).unwrap();
        assert!(!encoded.contains(secret));
        assert!(
            !serde_json::to_string(&api.load().unwrap())
                .unwrap()
                .contains(secret)
        );

        let control = serde_json::from_value::<SettingsAiApiKeyReplacementInput>(json!({
            "providerId": "write-only",
            "apiKey": "key\r\nHost: metadata",
        }))
        .unwrap();
        assert!(matches!(
            api.replace_ai_api_key(control),
            Err(SettingsApiError::InvalidInput)
        ));
        let oversized = SettingsAiApiKeyReplacementInput {
            provider_id: "write-only".to_owned(),
            api_key: "x".repeat(MAX_AI_API_KEY_BYTES + 1),
        };
        assert!(matches!(
            api.replace_ai_api_key(oversized),
            Err(SettingsApiError::InvalidInput)
        ));
        assert!(
            serde_json::from_value::<SettingsAiApiKeyReplacementInput>(json!({
                "providerId": "write-only",
                "apiKey": "secret",
                "path": "C:/secret.txt",
            }))
            .is_err()
        );
    }

    #[tokio::test]
    async fn mutation_handles_are_single_use_cancellable_ttl_and_capacity_bounded() {
        let (_root, services, api) = api();
        services
            .settings()
            .update(|settings| {
                settings.ai.providers.push(provider("bounded"));
                Ok(())
            })
            .unwrap();
        services
            .settings()
            .set_ai_api_key("bounded", Some(SecretValue::new("secret")))
            .unwrap();

        let cancelled = api.plan_clear_ai_api_key("bounded").unwrap();
        assert!(!cancelled.handle.contains("bounded"));
        assert!(api.cancel_mutation(&cancelled.handle).unwrap().cancelled);
        assert!(matches!(
            api.confirm_mutation(&cancelled.handle).await,
            Err(SettingsApiError::InvalidPlan)
        ));

        let expired = api.plan_clear_ai_api_key("bounded").unwrap();
        assert!(matches!(
            api.pending
                .lock()
                .take(&expired.handle, Instant::now() + MUTATION_TTL),
            Err(SettingsApiError::InvalidPlan)
        ));

        for _ in 0..MAX_PENDING_MUTATIONS {
            api.plan_clear_ai_api_key("bounded").unwrap();
        }
        assert!(matches!(
            api.plan_clear_ai_api_key("bounded"),
            Err(SettingsApiError::PlanCapacity)
        ));
    }

    #[tokio::test]
    async fn clear_and_remove_execute_core_plans_journal_verify_and_preserve_exact_summary() {
        let (_root, services, api) = api();
        services
            .settings()
            .update(|settings| {
                settings.ai.providers.push(provider("one"));
                settings.ai.providers.push(provider("two"));
                settings.ai.default_provider_id = Some("one".to_owned());
                Ok(())
            })
            .unwrap();
        services
            .settings()
            .set_ai_api_key("one", Some(SecretValue::new("one-secret")))
            .unwrap();
        services
            .settings()
            .set_ai_api_key("two", Some(SecretValue::new("two-secret")))
            .unwrap();

        let clear = api.plan_clear_ai_api_key("one").unwrap();
        assert_eq!(
            clear.summary,
            "永久清除 AI 服务商“Provider”的 API Key；此操作不可恢复。"
        );
        let cleared = api.confirm_mutation(&clear.handle).await.unwrap();
        assert_eq!(cleared.kind, SettingsMutationKind::ClearAiApiKey);
        assert!(cleared.verified);
        assert!(!services.settings().load().unwrap().ai.providers[0].has_api_key);
        assert!(matches!(
            api.confirm_mutation(&clear.handle).await,
            Err(SettingsApiError::InvalidPlan)
        ));

        let remove = api.plan_remove_ai_provider("two").unwrap();
        assert_eq!(
            remove.summary,
            "永久删除 AI 服务商“Provider”及其 API Key；此操作不可恢复。"
        );
        let removed = api.confirm_mutation(&remove.handle).await.unwrap();
        assert_eq!(removed.kind, SettingsMutationKind::RemoveAiProvider);
        assert!(removed.verified);
        assert!(
            services
                .settings()
                .load()
                .unwrap()
                .ai
                .providers
                .iter()
                .all(|provider| provider.id != "two")
        );

        let entries = services.operation_journal().entries().unwrap();
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].phase, JournalPhase::Executed);
        assert_eq!(entries[1].phase, JournalPhase::VerificationPassed);
        assert_eq!(entries[2].phase, JournalPhase::Executed);
        assert_eq!(entries[3].phase, JournalPhase::VerificationPassed);
        assert!(entries.iter().all(|entry| {
            !entry.detail.contains("one-secret") && !entry.detail.contains("two-secret")
        }));
    }

    #[tokio::test]
    async fn stale_clear_and_remove_plans_fail_closed_without_journaling() {
        let (_root, services, api) = api();
        services
            .settings()
            .update(|settings| {
                settings.ai.providers.push(provider("stale"));
                Ok(())
            })
            .unwrap();
        services
            .settings()
            .set_ai_api_key("stale", Some(SecretValue::new("first-secret")))
            .unwrap();

        let clear = api.plan_clear_ai_api_key("stale").unwrap();
        services
            .settings()
            .set_ai_api_key("stale", Some(SecretValue::new("replacement-secret")))
            .unwrap();
        assert!(api.confirm_mutation(&clear.handle).await.is_err());
        assert!(services.settings().load().unwrap().ai.providers[0].has_api_key);
        assert!(services.operation_journal().entries().unwrap().is_empty());

        let removal = api.plan_remove_ai_provider("stale").unwrap();
        services
            .settings()
            .update(|settings| {
                settings.ai.providers[0].label = "Changed".to_owned();
                Ok(())
            })
            .unwrap();
        assert!(api.confirm_mutation(&removal.handle).await.is_err());
        assert_eq!(services.settings().load().unwrap().ai.providers.len(), 1);
        assert!(services.operation_journal().entries().unwrap().is_empty());
    }
}
