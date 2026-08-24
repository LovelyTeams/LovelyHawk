//! Typed settings repository with credential-free UI views.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::{CryptoVault, SecretValue, is_encrypted};
use crate::net_guard::{ProxySettings, validate_outbound_url};
use crate::operations::{
    DangerousConfirmation, ExecutionReceipt, OperationExecutor, OperationJournal, OperationPlan,
    OperationState, PlannedOperation, VerificationResult,
};
use crate::store::StoreFile;
use crate::target::{TargetContext, TargetGuard, TargetIdentity};
use crate::{CoreError, CoreResult, PortableStore};

const LOCAL_SETTINGS_TARGET: &str = "portable-workspace:settings";
pub const EMBEDDED_TERMINAL_FONT: &str = "Cascadia Mono";
pub const MAX_AI_PROVIDERS: usize = 32;
const MAX_AI_API_KEY_BYTES: usize = 16_384;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Theme {
    Light,
    Dark,
    Sakura,
    IncidentCanvas,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Language {
    #[serde(rename = "zh-CN")]
    ChineseSimplified,
    #[serde(rename = "en-US")]
    English,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationSettings {
    pub enabled: bool,
    pub connection_status: bool,
    pub command_completion: bool,
    pub error_alerts: bool,
}

impl Default for NotificationSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            connection_status: true,
            command_completion: false,
            error_alerts: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecuritySettings {
    pub save_passwords: bool,
    pub session_timeout_ms: u32,
    pub require_confirmation: bool,
}

impl Default for SecuritySettings {
    fn default() -> Self {
        Self {
            save_passwords: false,
            session_timeout_ms: 86_400_000,
            require_confirmation: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiSettings {
    pub sidebar_width: u32,
    pub show_status_bar: bool,
    pub compact_mode: bool,
    pub animations_enabled: bool,
}

impl Default for UiSettings {
    fn default() -> Self {
        Self {
            sidebar_width: 280,
            show_status_bar: !cfg!(target_os = "windows"),
            compact_mode: false,
            animations_enabled: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DockerSettings {
    pub auto_refresh: bool,
    pub refresh_interval_ms: u32,
    pub show_system_containers: bool,
}

impl Default for DockerSettings {
    fn default() -> Self {
        Self {
            auto_refresh: true,
            refresh_interval_ms: 5_000,
            show_system_containers: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshSettings {
    pub keep_alive_interval_ms: u32,
    /// Zero disables the timeout, matching the existing application's default.
    pub connection_timeout_ms: u32,
    pub max_retries: u8,
}

impl Default for SshSettings {
    fn default() -> Self {
        Self {
            keep_alive_interval_ms: 30_000,
            connection_timeout_ms: 0,
            max_retries: 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AiProviderKind {
    OpenAiCompatible,
    Anthropic,
    Gemini,
}

/// Safe settings view. It intentionally contains no API key or ciphertext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiProviderSettings {
    pub id: String,
    pub label: String,
    pub kind: AiProviderKind,
    pub endpoint: String,
    pub model: String,
    pub enabled: bool,
    pub has_api_key: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AiSettings {
    pub providers: Vec<AiProviderSettings>,
    pub default_provider_id: Option<String>,
    pub proxy: Option<ProxySettings>,
}

/// Stable IDs exported from legacy `secfixData.ts` into the native offline catalog.
pub fn is_security_reference_catalog_id(id: &str) -> bool {
    matches!(
        id,
        "py-sqli"
            | "py-cmdi"
            | "py-ssti"
            | "py-path"
            | "py-pickle"
            | "py-eval"
            | "py-ssrf"
            | "py-upload"
            | "py-xxe"
            | "py-flask-debug"
            | "py-yaml"
            | "php-sqli"
            | "php-cmdi"
            | "php-lfi"
            | "php-upload"
            | "php-deser"
            | "php-xss"
            | "php-disable"
            | "php-backdoor"
            | "php-session"
            | "php-ssrf"
            | "java-sqli"
            | "java-deser"
            | "java-xxe"
            | "java-ssrf"
            | "java-spel"
            | "java-log4j"
            | "java-path"
            | "java-cmdi"
            | "java-fastjson"
            | "js-proto"
            | "js-cmdi"
            | "js-xss"
            | "js-nosqli"
            | "js-path"
            | "js-jwt"
            | "js-ssti"
            | "go-sqli"
            | "go-cmdi"
            | "go-path"
            | "go-ssti"
            | "go-ssrf"
            | "c-bof"
            | "c-fmt"
            | "c-int"
            | "mw-log4j"
            | "mw-fastjson1"
            | "mw-shiro-550"
            | "mw-weblogic-t3"
            | "mw-spring4shell"
            | "mw-tomcat-ajp"
            | "mw-struts2"
            | "mw-druid"
            | "mw-nacos"
            | "mw-redis-unauth"
            | "mw-solr"
            | "mw-xxljob"
            | "mw-jackson"
            | "mw-apache-httpd"
            | "mw-nginx-hardening"
            | "cms-thinkphp5"
            | "cms-thinkphp6"
            | "cms-discuz"
            | "cms-phpmyadmin"
            | "cms-dedecms"
            | "cms-tongda"
            | "cms-laravel-debug"
            | "cms-wordpress"
            | "em-user-clean"
            | "em-cron-clean"
            | "em-ssh-keys"
            | "em-process-hunt"
            | "em-persist-check"
            | "em-network-lock"
            | "em-memshell"
            | "em-webshell-hunt"
            | "sh-ssh"
            | "sh-firewall"
            | "sh-audit"
            | "sh-webshell"
            | "sh-passwd"
            | "sh-rootkit"
            | "sh-network"
            | "sh-persist"
            | "sh-docker"
            | "sh-log"
            | "sh-baseline"
            | "sh-waf-nginx"
            | "sh-waf-apache"
            | "sh-traffic"
            | "sh-flag"
            | "sql-mysql"
            | "sql-mysql-log"
            | "sql-redis"
            | "sql-pg"
            | "k8s-docker-escape"
            | "k8s-docker-forensic"
            | "k8s-docker-harden"
            | "k8s-pod-audit"
            | "k8s-rbac-audit"
            | "k8s-cronjob-audit"
            | "k8s-persistence"
            | "k8s-forensic-timeline"
            | "k8s-network-audit"
            | "k8s-emergency"
            | "k8s-secret-audit"
            | "k8s-container-escape"
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SecurityReferenceSettings {
    #[serde(default)]
    pub favorite_ids: Vec<String>,
}

impl SecurityReferenceSettings {
    fn validate(&self) -> CoreResult<()> {
        if self.favorite_ids.len() > 512 {
            return Err(CoreError::validation(
                "security reference favorites",
                "must contain at most 512 catalog IDs",
            ));
        }
        let mut unique = BTreeSet::new();
        for id in &self.favorite_ids {
            if !is_security_reference_catalog_id(id) {
                return Err(CoreError::validation(
                    "security reference favorite",
                    "must reference a known catalog ID",
                ));
            }
            if !unique.insert(id.as_str()) {
                return Err(CoreError::validation(
                    "security reference favorites",
                    "catalog IDs must be unique",
                ));
            }
        }
        Ok(())
    }
}

/// Runtime diagnostic verbosity persisted with the portable native settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ApplicationLogLevel {
    Debug,
    Warn,
    Error,
    #[default]
    #[serde(other)]
    Info,
}

impl ApplicationLogLevel {
    pub const ALL: [Self; 4] = [Self::Debug, Self::Info, Self::Warn, Self::Error];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

/// Public settings type shared with the native UI. No secret-bearing fields exist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSettings {
    pub theme: Theme,
    pub language: Language,
    pub auto_connect: bool,
    pub default_ssh_port: u16,
    pub terminal_font: String,
    pub terminal_font_size: u16,
    pub max_log_lines: u32,
    #[serde(default)]
    pub log_level: ApplicationLogLevel,
    pub auto_save_interval_ms: u32,
    pub notifications: NotificationSettings,
    pub security: SecuritySettings,
    pub ui: UiSettings,
    pub docker: DockerSettings,
    pub ssh: SshSettings,
    pub ai: AiSettings,
    #[serde(default)]
    pub security_reference: SecurityReferenceSettings,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            theme: Theme::Light,
            language: Language::ChineseSimplified,
            auto_connect: false,
            default_ssh_port: 22,
            terminal_font: "Cascadia Mono".to_owned(),
            terminal_font_size: 14,
            max_log_lines: 1_000,
            log_level: ApplicationLogLevel::Info,
            auto_save_interval_ms: 30_000,
            notifications: NotificationSettings::default(),
            security: SecuritySettings::default(),
            ui: UiSettings::default(),
            docker: DockerSettings::default(),
            ssh: SshSettings::default(),
            ai: AiSettings::default(),
            security_reference: SecurityReferenceSettings::default(),
        }
    }
}

impl AppSettings {
    pub fn validate(&self) -> CoreResult<()> {
        if self.default_ssh_port == 0 {
            return Err(CoreError::validation(
                "default SSH port",
                "must be non-zero",
            ));
        }
        if !(8..=72).contains(&self.terminal_font_size) {
            return Err(CoreError::validation(
                "terminal font size",
                "must be 8..=72",
            ));
        }
        if self.terminal_font != EMBEDDED_TERMINAL_FONT {
            return Err(CoreError::validation(
                "terminal font",
                "must reference the bundled Cascadia Mono font",
            ));
        }
        if !(1..=100_000).contains(&self.max_log_lines) {
            return Err(CoreError::validation(
                "maximum log lines",
                "must be 1..=100000",
            ));
        }
        if !(1_000..=3_600_000).contains(&self.auto_save_interval_ms) {
            return Err(CoreError::validation(
                "auto-save interval",
                "must be 1000..=3600000 ms",
            ));
        }
        if !(60_000..=86_400_000).contains(&self.security.session_timeout_ms) {
            return Err(CoreError::validation(
                "session timeout",
                "must be 60000..=86400000 ms",
            ));
        }
        if !(200..=800).contains(&self.ui.sidebar_width) {
            return Err(CoreError::validation("sidebar width", "must be 200..=800"));
        }
        if !(1_000..=60_000).contains(&self.docker.refresh_interval_ms) {
            return Err(CoreError::validation(
                "Docker refresh interval",
                "must be 1000..=60000 ms",
            ));
        }
        if !(5_000..=300_000).contains(&self.ssh.keep_alive_interval_ms) {
            return Err(CoreError::validation(
                "SSH keep-alive interval",
                "must be 5000..=300000 ms",
            ));
        }
        if self.ssh.connection_timeout_ms != 0
            && !(1_000..=600_000).contains(&self.ssh.connection_timeout_ms)
        {
            return Err(CoreError::validation(
                "SSH connection timeout",
                "must be zero or 1000..=600000 ms",
            ));
        }
        if !(1..=10).contains(&self.ssh.max_retries) {
            return Err(CoreError::validation("SSH retries", "must be 1..=10"));
        }

        if self.ai.providers.len() > MAX_AI_PROVIDERS {
            return Err(CoreError::validation(
                "AI providers",
                "must contain at most 32 providers",
            ));
        }
        let mut provider_ids = BTreeSet::new();
        for provider in &self.ai.providers {
            if !valid_provider_id(&provider.id) {
                return Err(CoreError::validation(
                    "AI provider id",
                    "must be 1..=64 ASCII letters, digits, dots, underscores, or hyphens and start with a letter or digit",
                ));
            }
            if !provider_ids.insert(provider.id.as_str()) {
                return Err(CoreError::validation("AI provider id", "must be unique"));
            }
            if provider.endpoint.len() > 2_048 {
                return Err(CoreError::validation(
                    "AI provider endpoint",
                    "must be at most 2048 bytes",
                ));
            }
            validate_outbound_url(&provider.endpoint)?;
            if provider.model.trim().is_empty()
                || provider.model.len() > 256
                || provider.model.chars().any(char::is_control)
                || provider.label.trim().is_empty()
                || provider.label.len() > 128
                || provider.label.chars().any(char::is_control)
            {
                return Err(CoreError::validation(
                    "AI provider",
                    "label/model must be non-empty, bounded, and contain no control characters",
                ));
            }
        }
        if let Some(default) = &self.ai.default_provider_id
            && !provider_ids.contains(default.as_str())
        {
            return Err(CoreError::validation(
                "default AI provider",
                "must reference a configured provider",
            ));
        }
        if let Some(proxy) = &self.ai.proxy {
            proxy.validate()?;
        }
        self.security_reference.validate()?;
        Ok(())
    }
}

fn valid_provider_id(id: &str) -> bool {
    let mut bytes = id.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    id.len() <= 64
        && first.is_ascii_alphanumeric()
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn ensure_provider_ids_preserved(previous: &AppSettings, next: &AppSettings) -> CoreResult<()> {
    let next_ids: BTreeSet<_> = next
        .ai
        .providers
        .iter()
        .map(|provider| provider.id.as_str())
        .collect();
    if previous
        .ai
        .providers
        .iter()
        .any(|provider| !next_ids.contains(provider.id.as_str()))
    {
        return Err(CoreError::validation(
            "AI provider removal",
            "must use plan_remove_ai_provider and execute_remove_ai_provider",
        ));
    }
    Ok(())
}

fn provider_state_digest(
    provider: &AiProviderSettings,
    encrypted_key: Option<&str>,
    default_provider_id: Option<&str>,
) -> CoreResult<String> {
    let bytes =
        serde_json::to_vec(&(provider, encrypted_key, default_provider_id)).map_err(|source| {
            CoreError::Encode {
                subject: "AI provider removal plan snapshot",
                source,
            }
        })?;
    Ok(sha256_hex(&bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn validate_ai_api_key(secret: &SecretValue) -> CoreResult<()> {
    if secret.is_empty() {
        return Err(CoreError::validation("AI API key", "must not be empty"));
    }
    if secret.expose().len() > MAX_AI_API_KEY_BYTES || secret.expose().chars().any(char::is_control)
    {
        return Err(CoreError::validation(
            "AI API key",
            "must be at most 16384 bytes and contain no control characters",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct StoredSettings {
    settings: AppSettings,
    encrypted_ai_keys: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiProviderRemovalPlan {
    provider_id: String,
    expected_state_digest: String,
    operation: OperationPlan,
}

impl AiProviderRemovalPlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiApiKeyClearPlan {
    provider_id: String,
    expected_key_digest: String,
    operation: OperationPlan,
}

impl AiApiKeyClearPlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsOperationOutcome {
    pub operation_id: String,
    pub verification: VerificationResult,
}

async fn run_settings_destructive_operation(
    repository: &SettingsRepository,
    plan: OperationPlan,
    confirmation: DangerousConfirmation,
    executor: &dyn OperationExecutor,
    journal: &dyn OperationJournal,
) -> CoreResult<VerificationResult> {
    let mut operation = PlannedOperation::plan(plan);
    operation.confirm(confirmation)?;
    if let Err(error) = operation
        .execute(repository.local_target.as_ref(), executor)
        .await
    {
        if operation.state() == OperationState::StaleAfterExecution {
            operation.journal(journal)?;
        }
        return Err(error);
    }
    operation.journal(journal)?;
    let verification = operation
        .verify(repository.local_target.as_ref(), executor, journal)
        .await?;
    if !verification.passed {
        return Err(CoreError::Validation {
            subject: "settings operation verification",
            message: verification.detail,
        });
    }
    Ok(verification)
}

#[derive(Debug)]
struct AiProviderRemovalExecutor {
    repository: SettingsRepository,
    provider_id: String,
    expected_state_digest: String,
}

#[async_trait]
impl OperationExecutor for AiProviderRemovalExecutor {
    async fn execute(&self, _plan: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        self.repository
            .remove_ai_provider_for_operation(&self.provider_id, &self.expected_state_digest)?;
        Ok(ExecutionReceipt {
            summary: "removed one AI provider and its encrypted API key".to_owned(),
            restore_token: None,
        })
    }

    async fn verify(
        &self,
        _plan: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        let absent = self.repository.provider_and_key_absent(&self.provider_id)?;
        Ok(VerificationResult {
            passed: absent,
            detail: if absent {
                "verified that the AI provider and encrypted key are absent".to_owned()
            } else {
                "the AI provider or encrypted key still exists".to_owned()
            },
        })
    }

    async fn restore(&self, _plan: &OperationPlan, _receipt: &ExecutionReceipt) -> CoreResult<()> {
        Err(CoreError::Unsupported {
            feature: "restoring a removed AI provider",
        })
    }
}

#[derive(Debug)]
struct AiApiKeyClearExecutor {
    repository: SettingsRepository,
    provider_id: String,
    expected_key_digest: String,
}

#[async_trait]
impl OperationExecutor for AiApiKeyClearExecutor {
    async fn execute(&self, _plan: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        self.repository
            .clear_ai_key_for_operation(&self.provider_id, &self.expected_key_digest)?;
        Ok(ExecutionReceipt {
            summary: "cleared one encrypted AI API key".to_owned(),
            restore_token: None,
        })
    }

    async fn verify(
        &self,
        _plan: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        let cleared = !self.repository.provider_has_api_key(&self.provider_id)?;
        Ok(VerificationResult {
            passed: cleared,
            detail: if cleared {
                "verified that the encrypted AI API key is absent".to_owned()
            } else {
                "the encrypted AI API key still exists".to_owned()
            },
        })
    }

    async fn restore(&self, _plan: &OperationPlan, _receipt: &ExecutionReceipt) -> CoreResult<()> {
        Err(CoreError::Unsupported {
            feature: "restoring a cleared AI API key",
        })
    }
}

#[derive(Debug, Clone)]
pub struct SettingsRepository {
    store: PortableStore,
    crypto: Arc<CryptoVault>,
    lock: Arc<Mutex<()>>,
    local_target: Arc<TargetContext>,
    local_guard: TargetGuard,
}

impl SettingsRepository {
    pub fn new(store: PortableStore, crypto: Arc<CryptoVault>) -> Self {
        let local_target = Arc::new(TargetContext::new());
        let local_guard = local_target
            .activate(
                TargetIdentity::new(LOCAL_SETTINGS_TARGET)
                    .expect("the built-in local settings target is valid"),
            )
            .expect("a new local settings target can be activated");
        Self {
            store,
            crypto,
            lock: Arc::new(Mutex::new(())),
            local_target,
            local_guard,
        }
    }

    pub fn load(&self) -> CoreResult<AppSettings> {
        let _guard = self.lock.lock();
        self.load_locked().map(Self::safe_view)
    }

    pub fn save(&self, settings: AppSettings) -> CoreResult<()> {
        settings.validate()?;
        let _guard = self.lock.lock();
        let previous = self.load_locked()?;
        ensure_provider_ids_preserved(&previous.settings, &settings)?;
        let provider_ids: BTreeSet<_> = settings
            .ai
            .providers
            .iter()
            .map(|provider| provider.id.as_str())
            .collect();
        let encrypted_ai_keys = previous
            .encrypted_ai_keys
            .into_iter()
            .filter(|(id, _)| provider_ids.contains(id.as_str()))
            .collect();
        self.store.write(
            StoreFile::Settings,
            &StoredSettings {
                settings,
                encrypted_ai_keys,
            },
        )
    }

    /// Atomically updates typed settings without exposing the backing JSON or
    /// dropping concurrent changes made through another repository clone.
    pub fn update(
        &self,
        update: impl FnOnce(&mut AppSettings) -> CoreResult<()>,
    ) -> CoreResult<AppSettings> {
        let _guard = self.lock.lock();
        let mut stored = self.load_locked()?;
        let previous_settings = stored.settings.clone();
        update(&mut stored.settings)?;
        stored.settings.validate()?;
        ensure_provider_ids_preserved(&previous_settings, &stored.settings)?;
        let provider_ids: BTreeSet<_> = stored
            .settings
            .ai
            .providers
            .iter()
            .map(|provider| provider.id.as_str())
            .collect();
        stored
            .encrypted_ai_keys
            .retain(|id, _| provider_ids.contains(id.as_str()));
        self.store.write(StoreFile::Settings, &stored)?;
        Ok(Self::safe_view(stored))
    }

    /// Atomically updates typed settings and optionally writes a new API key.
    /// Existing keys are never exposed and an omitted key update preserves them.
    pub fn update_with_ai_key(
        &self,
        update: impl FnOnce(&mut AppSettings) -> CoreResult<()>,
        api_key: Option<(String, SecretValue)>,
    ) -> CoreResult<AppSettings> {
        if let Some((_, secret)) = &api_key {
            validate_ai_api_key(secret)?;
        }
        let _guard = self.lock.lock();
        let mut stored = self.load_locked()?;
        let previous_settings = stored.settings.clone();
        update(&mut stored.settings)?;
        stored.settings.validate()?;
        ensure_provider_ids_preserved(&previous_settings, &stored.settings)?;
        if let Some((provider_id, secret)) = api_key {
            if !stored
                .settings
                .ai
                .providers
                .iter()
                .any(|provider| provider.id == provider_id)
            {
                return Err(CoreError::NotFound {
                    entity: "AI provider",
                    id: provider_id,
                });
            }
            stored
                .encrypted_ai_keys
                .insert(provider_id, self.crypto.seal(&secret)?);
        }
        self.store.write(StoreFile::Settings, &stored)?;
        Ok(Self::safe_view(stored))
    }

    pub fn set_ai_api_key(&self, provider_id: &str, secret: Option<SecretValue>) -> CoreResult<()> {
        let _guard = self.lock.lock();
        let mut stored = self.load_locked()?;
        if !stored
            .settings
            .ai
            .providers
            .iter()
            .any(|provider| provider.id == provider_id)
        {
            return Err(CoreError::NotFound {
                entity: "AI provider",
                id: provider_id.to_owned(),
            });
        }
        match secret {
            Some(secret) => {
                validate_ai_api_key(&secret)?;
                stored
                    .encrypted_ai_keys
                    .insert(provider_id.to_owned(), self.crypto.seal(&secret)?);
            }
            None => {
                return Err(CoreError::validation(
                    "AI API key clearing",
                    "must use plan_clear_ai_api_key and execute_clear_ai_api_key",
                ));
            }
        }
        self.store.write(StoreFile::Settings, &stored)
    }

    pub fn plan_remove_ai_provider(&self, provider_id: &str) -> CoreResult<AiProviderRemovalPlan> {
        let _guard = self.lock.lock();
        let stored = self.load_locked()?;
        let provider = stored
            .settings
            .ai
            .providers
            .iter()
            .find(|provider| provider.id == provider_id)
            .ok_or_else(|| CoreError::NotFound {
                entity: "AI provider",
                id: provider_id.to_owned(),
            })?;
        let expected_state_digest = provider_state_digest(
            provider,
            stored
                .encrypted_ai_keys
                .get(provider_id)
                .map(String::as_str),
            stored.settings.ai.default_provider_id.as_deref(),
        )?;
        let mut operation = OperationPlan::new(
            self.local_guard.clone(),
            format!(
                "永久删除 AI Provider“{}”及其 API Key；此操作不可恢复。",
                provider.label
            ),
            true,
            None,
        )?;
        operation
            .metadata
            .insert("provider-id".to_owned(), provider.id.clone());
        Ok(AiProviderRemovalPlan {
            provider_id: provider.id.clone(),
            expected_state_digest,
            operation,
        })
    }

    pub async fn execute_remove_ai_provider(
        &self,
        plan: AiProviderRemovalPlan,
        confirmation: DangerousConfirmation,
        journal: &dyn OperationJournal,
    ) -> CoreResult<SettingsOperationOutcome> {
        let operation_id = plan.operation.id.clone();
        let executor = AiProviderRemovalExecutor {
            repository: self.clone(),
            provider_id: plan.provider_id,
            expected_state_digest: plan.expected_state_digest,
        };
        let verification = run_settings_destructive_operation(
            self,
            plan.operation,
            confirmation,
            &executor,
            journal,
        )
        .await?;
        Ok(SettingsOperationOutcome {
            operation_id,
            verification,
        })
    }

    pub fn plan_clear_ai_api_key(&self, provider_id: &str) -> CoreResult<AiApiKeyClearPlan> {
        let _guard = self.lock.lock();
        let stored = self.load_locked()?;
        let provider = stored
            .settings
            .ai
            .providers
            .iter()
            .find(|provider| provider.id == provider_id)
            .ok_or_else(|| CoreError::NotFound {
                entity: "AI provider",
                id: provider_id.to_owned(),
            })?;
        let encrypted_key =
            stored
                .encrypted_ai_keys
                .get(provider_id)
                .ok_or_else(|| CoreError::NotFound {
                    entity: "AI API key",
                    id: provider_id.to_owned(),
                })?;
        let expected_key_digest = sha256_hex(encrypted_key.as_bytes());
        let mut operation = OperationPlan::new(
            self.local_guard.clone(),
            format!(
                "永久清除 AI Provider“{}”的 API Key；此操作不可恢复。",
                provider.label
            ),
            true,
            None,
        )?;
        operation
            .metadata
            .insert("provider-id".to_owned(), provider.id.clone());
        Ok(AiApiKeyClearPlan {
            provider_id: provider.id.clone(),
            expected_key_digest,
            operation,
        })
    }

    pub async fn execute_clear_ai_api_key(
        &self,
        plan: AiApiKeyClearPlan,
        confirmation: DangerousConfirmation,
        journal: &dyn OperationJournal,
    ) -> CoreResult<SettingsOperationOutcome> {
        let operation_id = plan.operation.id.clone();
        let executor = AiApiKeyClearExecutor {
            repository: self.clone(),
            provider_id: plan.provider_id,
            expected_key_digest: plan.expected_key_digest,
        };
        let verification = run_settings_destructive_operation(
            self,
            plan.operation,
            confirmation,
            &executor,
            journal,
        )
        .await?;
        Ok(SettingsOperationOutcome {
            operation_id,
            verification,
        })
    }

    fn remove_ai_provider_for_operation(
        &self,
        provider_id: &str,
        expected_state_digest: &str,
    ) -> CoreResult<()> {
        let _guard = self.lock.lock();
        let mut stored = self.load_locked()?;
        let provider = stored
            .settings
            .ai
            .providers
            .iter()
            .find(|provider| provider.id == provider_id)
            .ok_or_else(|| CoreError::NotFound {
                entity: "AI provider",
                id: provider_id.to_owned(),
            })?;
        let current_digest = provider_state_digest(
            provider,
            stored
                .encrypted_ai_keys
                .get(provider_id)
                .map(String::as_str),
            stored.settings.ai.default_provider_id.as_deref(),
        )?;
        if current_digest != expected_state_digest {
            return Err(CoreError::validation(
                "AI provider removal plan",
                "provider, API key, or default selection changed after confirmation was planned",
            ));
        }
        let previous_len = stored.settings.ai.providers.len();
        stored
            .settings
            .ai
            .providers
            .retain(|provider| provider.id != provider_id);
        if stored.settings.ai.providers.len() == previous_len {
            return Err(CoreError::NotFound {
                entity: "AI provider",
                id: provider_id.to_owned(),
            });
        }
        stored.encrypted_ai_keys.remove(provider_id);
        if stored.settings.ai.default_provider_id.as_deref() == Some(provider_id) {
            stored.settings.ai.default_provider_id = stored
                .settings
                .ai
                .providers
                .first()
                .map(|provider| provider.id.clone());
        }
        stored.settings.validate()?;
        self.store.write(StoreFile::Settings, &stored)
    }

    fn clear_ai_key_for_operation(
        &self,
        provider_id: &str,
        expected_key_digest: &str,
    ) -> CoreResult<()> {
        let _guard = self.lock.lock();
        let mut stored = self.load_locked()?;
        if !stored
            .settings
            .ai
            .providers
            .iter()
            .any(|provider| provider.id == provider_id)
        {
            return Err(CoreError::NotFound {
                entity: "AI provider",
                id: provider_id.to_owned(),
            });
        }
        let encrypted =
            stored
                .encrypted_ai_keys
                .get(provider_id)
                .ok_or_else(|| CoreError::NotFound {
                    entity: "AI API key",
                    id: provider_id.to_owned(),
                })?;
        if sha256_hex(encrypted.as_bytes()) != expected_key_digest {
            return Err(CoreError::validation(
                "AI API key clear plan",
                "API key changed after confirmation was planned",
            ));
        }
        stored.encrypted_ai_keys.remove(provider_id);
        self.store.write(StoreFile::Settings, &stored)
    }

    fn provider_and_key_absent(&self, provider_id: &str) -> CoreResult<bool> {
        let _guard = self.lock.lock();
        let stored = self.load_locked()?;
        Ok(!stored
            .settings
            .ai
            .providers
            .iter()
            .any(|provider| provider.id == provider_id)
            && !stored.encrypted_ai_keys.contains_key(provider_id))
    }

    fn provider_has_api_key(&self, provider_id: &str) -> CoreResult<bool> {
        let _guard = self.lock.lock();
        let stored = self.load_locked()?;
        if !stored
            .settings
            .ai
            .providers
            .iter()
            .any(|provider| provider.id == provider_id)
        {
            return Err(CoreError::NotFound {
                entity: "AI provider",
                id: provider_id.to_owned(),
            });
        }
        Ok(stored.encrypted_ai_keys.contains_key(provider_id))
    }

    fn load_locked(&self) -> CoreResult<StoredSettings> {
        let stored = self
            .store
            .read_or_default::<StoredSettings>(StoreFile::Settings)?;
        stored.settings.validate()?;
        if stored
            .encrypted_ai_keys
            .values()
            .any(|encrypted| !is_encrypted(encrypted))
        {
            return Err(CoreError::validation(
                "stored AI API key",
                "must use the enc:v1 ciphertext format",
            ));
        }
        Ok(stored)
    }

    fn safe_view(mut stored: StoredSettings) -> AppSettings {
        for provider in &mut stored.settings.ai.providers {
            provider.has_api_key = stored.encrypted_ai_keys.contains_key(&provider.id);
        }
        stored.settings
    }

    #[allow(dead_code)] // only AI proxy code, never the UI, may resolve this value
    pub(crate) fn resolve_ai_api_key(&self, provider_id: &str) -> CoreResult<Option<SecretValue>> {
        let _guard = self.lock.lock();
        let stored = self.load_locked()?;
        stored
            .encrypted_ai_keys
            .get(provider_id)
            .map(|encrypted| self.crypto.open(encrypted))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Barrier;
    use std::thread;

    use uuid::Uuid;

    use super::*;
    use crate::crypto::ENC_PREFIX;
    use crate::operations::{DangerousConfirmation, JournalPhase, PortableOperationJournal};

    #[derive(Debug)]
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("lovelyres-settings-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn repository() -> (TestRoot, PortableStore, SettingsRepository) {
        let root = TestRoot::new();
        let store = PortableStore::prepare(root.0.clone()).unwrap();
        let crypto = Arc::new(CryptoVault::load(&store).unwrap());
        let repository = SettingsRepository::new(store.clone(), crypto);
        (root, store, repository)
    }

    fn provider(id: &str) -> AiProviderSettings {
        AiProviderSettings {
            id: id.to_owned(),
            label: format!("Provider {id}"),
            kind: AiProviderKind::OpenAiCompatible,
            endpoint: "http://127.0.0.1:11434/v1/chat/completions".to_owned(),
            model: "qwen".to_owned(),
            enabled: true,
            has_api_key: false,
        }
    }

    fn add_providers(repository: &SettingsRepository, ids: &[&str]) {
        repository
            .update(|settings| {
                settings.ai.providers = ids.iter().map(|id| provider(id)).collect();
                settings.ai.default_provider_id = ids.first().map(|id| (*id).to_owned());
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn default_settings_are_valid_including_disabled_ssh_timeout() {
        AppSettings::default().validate().unwrap();
    }

    #[test]
    fn api_keys_are_encrypted_and_only_presence_reaches_view() {
        let (_root, store, repository) = repository();
        let mut settings = AppSettings::default();
        settings.ai.providers.push(AiProviderSettings {
            id: "local".to_owned(),
            label: "Local model".to_owned(),
            kind: AiProviderKind::OpenAiCompatible,
            endpoint: "http://127.0.0.1:11434/v1/chat/completions".to_owned(),
            model: "qwen".to_owned(),
            enabled: true,
            has_api_key: false,
        });
        repository.save(settings).unwrap();
        repository
            .set_ai_api_key("local", Some(SecretValue::new("plain-secret-key")))
            .unwrap();
        repository
            .update(|settings| {
                settings.theme = Theme::Sakura;
                Ok(())
            })
            .unwrap();

        let view = repository.load().unwrap();
        assert!(view.ai.providers[0].has_api_key);
        assert_eq!(view.theme, Theme::Sakura);
        let bytes = fs::read(store.path_for(StoreFile::Settings)).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains("plain-secret-key"));
        assert!(text.contains(ENC_PREFIX));
        assert_eq!(
            repository
                .resolve_ai_api_key("local")
                .unwrap()
                .unwrap()
                .expose(),
            "plain-secret-key"
        );
    }

    #[test]
    fn rejects_duplicate_or_dangling_provider_ids() {
        let provider = AiProviderSettings {
            id: "one".to_owned(),
            label: "One".to_owned(),
            kind: AiProviderKind::Anthropic,
            endpoint: "https://api.anthropic.com/v1/messages".to_owned(),
            model: "claude".to_owned(),
            enabled: true,
            has_api_key: false,
        };
        let mut settings = AppSettings::default();
        settings.ai.providers = vec![provider.clone(), provider];
        assert!(settings.validate().is_err());
        settings.ai.providers.truncate(1);
        settings.ai.default_provider_id = Some("missing".to_owned());
        assert!(settings.validate().is_err());
    }

    #[test]
    fn security_reference_favorites_round_trip_through_typed_settings() {
        let (_root, store, repository) = repository();
        let mut settings = AppSettings::default();
        settings.security_reference.favorite_ids =
            vec!["py-sqli".to_owned(), "java-log4j".to_owned()];
        repository.save(settings.clone()).unwrap();

        assert_eq!(repository.load().unwrap(), settings);
        let saved = fs::read_to_string(store.path_for(StoreFile::Settings)).unwrap();
        assert!(saved.contains("security_reference"));
        assert!(saved.contains("java-log4j"));
    }

    #[test]
    fn security_reference_favorites_reject_unknown_duplicate_and_oversized_sets() {
        let mut settings = AppSettings::default();
        settings.security_reference.favorite_ids = vec!["not-in-catalog".to_owned()];
        assert!(settings.validate().is_err());

        settings.security_reference.favorite_ids = vec!["py-sqli".to_owned(), "py-sqli".to_owned()];
        assert!(settings.validate().is_err());

        settings.security_reference.favorite_ids = vec!["py-sqli".to_owned(); 513];
        assert!(settings.validate().is_err());
    }

    #[test]
    fn security_reference_favorites_default_when_loading_an_older_schema() {
        let mut json = serde_json::to_value(AppSettings::default()).unwrap();
        json.as_object_mut().unwrap().remove("security_reference");
        let settings: AppSettings = serde_json::from_value(json).unwrap();
        assert!(settings.security_reference.favorite_ids.is_empty());
    }

    #[test]
    fn application_log_level_round_trips_valid_values() {
        for level in ApplicationLogLevel::ALL {
            let encoded = serde_json::to_string(&level).unwrap();
            assert_eq!(encoded, format!("\"{}\"", level.as_str()));
            assert_eq!(
                serde_json::from_str::<ApplicationLogLevel>(&encoded).unwrap(),
                level
            );
        }
    }

    #[test]
    fn application_log_level_invalid_value_defaults_to_info() {
        assert_eq!(
            serde_json::from_str::<ApplicationLogLevel>("\"not-a-level\"").unwrap(),
            ApplicationLogLevel::Info
        );
    }

    #[test]
    fn application_log_level_missing_field_defaults_without_web_storage() {
        let mut json = serde_json::to_value(AppSettings::default()).unwrap();
        json.as_object_mut().unwrap().remove("log_level");
        let settings: AppSettings = serde_json::from_value(json).unwrap();
        assert_eq!(settings.log_level, ApplicationLogLevel::Info);
    }

    #[test]
    fn fresh_portable_ai_settings_ignore_and_preserve_unscoped_legacy_state() {
        let (root, store, repository) = repository();
        let legacy = root.0.join("lovelyres-ai-config");
        let legacy_text = r#"{"provider":"deepseek","apiKey":"plain-key"}"#;
        fs::write(&legacy, legacy_text).unwrap();

        let settings = repository.load().unwrap();
        assert!(settings.ai.providers.is_empty());
        assert!(settings.ai.default_provider_id.is_none());
        assert_eq!(fs::read_to_string(&legacy).unwrap(), legacy_text);
        let settings_path = store.path_for(StoreFile::Settings);
        if settings_path.exists() {
            assert!(
                !fs::read_to_string(settings_path)
                    .unwrap()
                    .contains("plain-key")
            );
        }
    }

    #[test]
    fn cloned_repositories_do_not_lose_concurrent_typed_updates() {
        let (_root, _store, repository) = repository();
        let barrier = Arc::new(Barrier::new(3));
        let theme_repository = repository.clone();
        let theme_barrier = barrier.clone();
        let theme_worker = thread::spawn(move || {
            theme_barrier.wait();
            theme_repository
                .update(|settings| {
                    settings.theme = Theme::IncidentCanvas;
                    Ok(())
                })
                .unwrap();
        });
        let favorites_repository = repository.clone();
        let favorites_barrier = barrier.clone();
        let favorites_worker = thread::spawn(move || {
            favorites_barrier.wait();
            favorites_repository
                .update(|settings| {
                    settings.security_reference.favorite_ids = vec!["java-log4j".to_owned()];
                    Ok(())
                })
                .unwrap();
        });
        barrier.wait();
        theme_worker.join().unwrap();
        favorites_worker.join().unwrap();

        let settings = repository.load().unwrap();
        assert_eq!(settings.theme, Theme::IncidentCanvas);
        assert_eq!(settings.security_reference.favorite_ids, ["java-log4j"]);
    }

    #[test]
    fn raw_provider_removal_is_rejected_without_side_effects() {
        let (_root, _store, repository) = repository();
        add_providers(&repository, &["one", "two"]);

        let error = repository
            .update(|settings| {
                settings
                    .ai
                    .providers
                    .retain(|provider| provider.id != "two");
                Ok(())
            })
            .unwrap_err();

        assert!(error.to_string().contains("plan_remove_ai_provider"));
        assert_eq!(repository.load().unwrap().ai.providers.len(), 2);
    }

    #[tokio::test]
    async fn provider_removal_requires_exact_confirmation_then_journals_and_verifies() {
        let (_root, store, repository) = repository();
        add_providers(&repository, &["one", "two"]);
        repository
            .set_ai_api_key("two", Some(SecretValue::new("provider-two-secret")))
            .unwrap();
        let journal = PortableOperationJournal::new(store);

        let cancelled = repository.plan_remove_ai_provider("two").unwrap();
        let cancelled_definition = cancelled.definition().clone();
        let error = repository
            .execute_remove_ai_provider(
                cancelled,
                DangerousConfirmation::reject(&cancelled_definition),
                &journal,
            )
            .await
            .unwrap_err();
        assert!(matches!(error, CoreError::OperationCancelled { .. }));
        assert_eq!(repository.load().unwrap().ai.providers.len(), 2);
        assert!(journal.entries().unwrap().is_empty());

        let removal = repository.plan_remove_ai_provider("two").unwrap();
        let key_clear = repository.plan_clear_ai_api_key("two").unwrap();
        let error = repository
            .execute_remove_ai_provider(
                removal,
                DangerousConfirmation::approve(key_clear.definition()),
                &journal,
            )
            .await
            .unwrap_err();
        assert!(matches!(error, CoreError::Validation { .. }));
        assert_eq!(repository.load().unwrap().ai.providers.len(), 2);
        assert!(journal.entries().unwrap().is_empty());

        let removal = repository.plan_remove_ai_provider("two").unwrap();
        let confirmation = DangerousConfirmation::approve(removal.definition());
        let outcome = repository
            .execute_remove_ai_provider(removal, confirmation, &journal)
            .await
            .unwrap();
        assert!(outcome.verification.passed);
        assert_eq!(
            repository
                .load()
                .unwrap()
                .ai
                .providers
                .iter()
                .map(|provider| provider.id.as_str())
                .collect::<Vec<_>>(),
            ["one"]
        );
        assert!(repository.resolve_ai_api_key("two").unwrap().is_none());
        let entries = journal.entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].phase, JournalPhase::Executed);
        assert_eq!(entries[1].phase, JournalPhase::VerificationPassed);
        assert!(
            !entries
                .iter()
                .any(|entry| entry.detail.contains("provider-two-secret"))
        );
    }

    #[tokio::test]
    async fn removal_plan_rejects_concurrent_default_provider_change() {
        let (_root, store, repository) = repository();
        add_providers(&repository, &["one", "two"]);
        let removal = repository.plan_remove_ai_provider("two").unwrap();
        let confirmation = DangerousConfirmation::approve(removal.definition());
        repository
            .update(|settings| {
                settings.ai.default_provider_id = Some("two".to_owned());
                Ok(())
            })
            .unwrap();
        let journal = PortableOperationJournal::new(store);

        let error = repository
            .execute_remove_ai_provider(removal, confirmation, &journal)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("changed after confirmation"));
        let settings = repository.load().unwrap();
        assert_eq!(settings.ai.default_provider_id.as_deref(), Some("two"));
        assert!(
            settings
                .ai
                .providers
                .iter()
                .any(|provider| provider.id == "two")
        );
        assert!(journal.entries().unwrap().is_empty());
    }

    #[tokio::test]
    async fn api_key_clear_rejects_replacement_then_exact_plan_journals_and_verifies() {
        let (_root, store, repository) = repository();
        add_providers(&repository, &["one"]);
        repository
            .set_ai_api_key("one", Some(SecretValue::new("first-secret")))
            .unwrap();
        let stale = repository.plan_clear_ai_api_key("one").unwrap();
        let stale_confirmation = DangerousConfirmation::approve(stale.definition());
        repository
            .set_ai_api_key("one", Some(SecretValue::new("replacement-secret")))
            .unwrap();
        let journal = PortableOperationJournal::new(store);

        assert!(
            repository
                .execute_clear_ai_api_key(stale, stale_confirmation, &journal)
                .await
                .is_err()
        );
        assert!(repository.load().unwrap().ai.providers[0].has_api_key);
        assert!(journal.entries().unwrap().is_empty());

        let clear = repository.plan_clear_ai_api_key("one").unwrap();
        let confirmation = DangerousConfirmation::approve(clear.definition());
        let outcome = repository
            .execute_clear_ai_api_key(clear, confirmation, &journal)
            .await
            .unwrap();
        assert!(outcome.verification.passed);
        assert!(!repository.load().unwrap().ai.providers[0].has_api_key);
        let entries = journal.entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].phase, JournalPhase::Executed);
        assert_eq!(entries[1].phase, JournalPhase::VerificationPassed);
    }

    #[test]
    fn atomic_key_update_preserves_concurrent_typed_update_and_redacts_hostile_secret() {
        let (_root, store, repository) = repository();
        add_providers(&repository, &["one"]);
        let hostile = "</input><script>globalThis.steal()</script>Bearer-secret";
        let secret = SecretValue::new(hostile);
        assert_eq!(format!("{secret:?}"), "SecretValue([REDACTED])");
        let barrier = Arc::new(Barrier::new(3));
        let key_repository = repository.clone();
        let key_barrier = barrier.clone();
        let key_worker = thread::spawn(move || {
            key_barrier.wait();
            key_repository
                .update_with_ai_key(
                    |settings| {
                        settings.theme = Theme::Sakura;
                        Ok(())
                    },
                    Some(("one".to_owned(), secret)),
                )
                .unwrap();
        });
        let typed_repository = repository.clone();
        let typed_barrier = barrier.clone();
        let typed_worker = thread::spawn(move || {
            typed_barrier.wait();
            typed_repository
                .update(|settings| {
                    settings.security_reference.favorite_ids = vec!["py-sqli".to_owned()];
                    Ok(())
                })
                .unwrap();
        });
        barrier.wait();
        key_worker.join().unwrap();
        typed_worker.join().unwrap();

        let view = repository.load().unwrap();
        assert_eq!(view.theme, Theme::Sakura);
        assert_eq!(view.security_reference.favorite_ids, ["py-sqli"]);
        assert!(view.ai.providers[0].has_api_key);
        assert!(!format!("{view:?}").contains(hostile));
        assert!(!serde_json::to_string(&view).unwrap().contains(hostile));
        assert!(
            !fs::read_to_string(store.path_for(StoreFile::Settings))
                .unwrap()
                .contains(hostile)
        );

        let invalid = format!("{hostile}\n");
        let error = repository
            .update_with_ai_key(
                |_| Ok(()),
                Some(("one".to_owned(), SecretValue::new(invalid.clone()))),
            )
            .unwrap_err();
        assert!(!format!("{error:?}").contains(hostile));
        assert!(!error.to_string().contains(hostile));
    }
}
