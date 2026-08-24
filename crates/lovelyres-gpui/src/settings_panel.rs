use std::{sync::Arc, time::Duration};

use gpui::{
    AnyElement, Context, Entity, EventEmitter, IntoElement, Render, SharedString, Subscription,
    Window, div, prelude::*, px,
};
use gpui_component::{
    Disableable, Selectable, Sizable,
    button::{Button, ButtonVariants},
    input::{Input, InputState},
    scroll::ScrollableElement,
};
use lovelyres_core::{
    BackendServices, CoreError, CoreResult,
    ai::AiProviderId,
    crypto::SecretValue,
    net_guard::{ProxySettings, ProxyType},
    operations::{DangerousConfirmation, OperationPlan},
    settings::{
        AiApiKeyClearPlan, AiProviderKind, AiProviderRemovalPlan, AiProviderSettings, AppSettings,
        ApplicationLogLevel, EMBEDDED_TERMINAL_FONT, Language, SettingsOperationOutcome, Theme,
    },
};

const PROVIDER_PROBE_TIMEOUT: Duration = Duration::from_secs(15);

use crate::{
    app::SharedAppState,
    interaction::{DialogAction, DialogError, DialogId, DialogOutcome},
    runtime::TokioBridge,
    theme::{ThemeId, ThemeTokens},
};

#[derive(Clone, Debug)]
pub enum SettingsPanelEvent {
    CloseRequested,
    Saved { settings: AppSettings },
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum SettingsTab {
    #[default]
    General,
    Connections,
    Terminal,
    Ai,
}

impl SettingsTab {
    const ALL: [Self; 4] = [Self::General, Self::Connections, Self::Terminal, Self::Ai];

    const fn label(self) -> &'static str {
        match self {
            Self::General => "通用",
            Self::Connections => "连接",
            Self::Terminal => "终端",
            Self::Ai => "AI",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SettingsLease {
    generation: u64,
    request_id: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ProviderProbeResult {
    Success {
        model_count: usize,
    },
    Failure {
        category: &'static str,
        detail: &'static str,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProviderProbeReport {
    provider_id: String,
    elapsed_ms: u128,
    result: ProviderProbeResult,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SettingsDangerKind {
    RemoveProvider { provider_id: String },
    ClearApiKey { provider_id: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SettingsDangerPlan {
    RemoveProvider(AiProviderRemovalPlan),
    ClearApiKey(AiApiKeyClearPlan),
}

impl SettingsDangerPlan {
    fn definition(&self) -> &OperationPlan {
        match self {
            Self::RemoveProvider(plan) => plan.definition(),
            Self::ClearApiKey(plan) => plan.definition(),
        }
    }

    fn kind(&self) -> SettingsDangerKind {
        match self {
            Self::RemoveProvider(plan) => SettingsDangerKind::RemoveProvider {
                provider_id: plan.provider_id().to_owned(),
            },
            Self::ClearApiKey(plan) => SettingsDangerKind::ClearApiKey {
                provider_id: plan.provider_id().to_owned(),
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SettingsDangerProposal {
    lease: SettingsLease,
    plan: SettingsDangerPlan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingSettingsDanger {
    proposal: SettingsDangerProposal,
    dialog_id: DialogId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SettingsDangerResolution {
    Ignored,
    Cancelled,
    Stale,
    Authorized {
        plan: Box<SettingsDangerPlan>,
        confirmation: DangerousConfirmation,
        presentation: SettingsLease,
    },
}

struct SettingsPanelModel {
    active: bool,
    generation: u64,
    next_request_id: u64,
    tab: SettingsTab,
    draft: AppSettings,
    selected_provider_id: Option<String>,
    adding_provider: bool,
    provider_kind: AiProviderKind,
    provider_enabled: bool,
    provider_default: bool,
    saving: bool,
    provider_test_request_id: Option<u64>,
    provider_probe: Option<ProviderProbeReport>,
    pending_danger: Option<PendingSettingsDanger>,
    notice: Option<(SharedString, bool)>,
}

impl Default for SettingsPanelModel {
    fn default() -> Self {
        Self {
            active: false,
            generation: 0,
            next_request_id: 0,
            tab: SettingsTab::General,
            draft: AppSettings::default(),
            selected_provider_id: None,
            adding_provider: false,
            provider_kind: AiProviderKind::OpenAiCompatible,
            provider_enabled: true,
            provider_default: false,
            saving: false,
            provider_test_request_id: None,
            provider_probe: None,
            pending_danger: None,
            notice: None,
        }
    }
}

impl SettingsPanelModel {
    fn activate(&mut self, settings: AppSettings) {
        if !self.active {
            self.generation = self.generation.wrapping_add(1).max(1);
        }
        self.active = true;
        self.draft = settings;
        self.selected_provider_id = self.draft.ai.default_provider_id.clone().or_else(|| {
            self.draft
                .ai
                .providers
                .first()
                .map(|provider| provider.id.clone())
        });
        self.adding_provider = false;
        self.sync_selected_provider_flags();
        self.provider_test_request_id = None;
        self.provider_probe = None;
        self.notice = None;
    }

    fn deactivate(&mut self) {
        self.active = false;
        self.saving = false;
        self.provider_test_request_id = None;
        self.pending_danger = None;
    }

    fn new_lease(&mut self) -> Option<SettingsLease> {
        if !self.active {
            return None;
        }
        self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
        Some(SettingsLease {
            generation: self.generation,
            request_id: self.next_request_id,
        })
    }

    fn accepts(&self, lease: &SettingsLease) -> bool {
        self.active && self.generation == lease.generation
    }

    fn begin_provider_test(&mut self) -> Option<SettingsLease> {
        let lease = self.new_lease()?;
        self.provider_test_request_id = Some(lease.request_id);
        Some(lease)
    }

    fn accepts_provider_test(&self, lease: &SettingsLease) -> bool {
        self.accepts(lease) && self.provider_test_request_id == Some(lease.request_id)
    }

    fn cancel_provider_test(&mut self) {
        self.provider_test_request_id = None;
    }

    fn select_provider(&mut self, id: &str) -> bool {
        if !self
            .draft
            .ai
            .providers
            .iter()
            .any(|provider| provider.id == id)
        {
            return false;
        }
        self.selected_provider_id = Some(id.to_owned());
        self.adding_provider = false;
        self.provider_probe = None;
        self.sync_selected_provider_flags();
        true
    }

    fn start_add_provider(&mut self) {
        self.selected_provider_id = None;
        self.adding_provider = true;
        self.provider_kind = AiProviderKind::OpenAiCompatible;
        self.provider_enabled = true;
        self.provider_default = false;
        self.provider_probe = None;
    }

    fn selected_provider(&self) -> Option<&AiProviderSettings> {
        let id = self.selected_provider_id.as_deref()?;
        self.draft
            .ai
            .providers
            .iter()
            .find(|provider| provider.id == id)
    }

    fn sync_selected_provider_flags(&mut self) {
        if let Some(provider) = self.selected_provider().cloned() {
            self.provider_kind = provider.kind;
            self.provider_enabled = provider.enabled;
            self.provider_default =
                self.draft.ai.default_provider_id.as_deref() == Some(provider.id.as_str());
        }
    }

    fn propose_danger(&mut self, plan: SettingsDangerPlan) -> CoreResult<SettingsDangerProposal> {
        let lease = self.new_lease().ok_or_else(|| CoreError::Validation {
            subject: "settings panel",
            message: "panel is not active".to_owned(),
        })?;
        Ok(SettingsDangerProposal { lease, plan })
    }

    fn arm_danger(&mut self, proposal: SettingsDangerProposal, dialog_id: DialogId) {
        self.pending_danger = Some(PendingSettingsDanger {
            proposal,
            dialog_id,
        });
    }

    fn pending_dialog_id(&self) -> Option<DialogId> {
        self.pending_danger
            .as_ref()
            .map(|pending| pending.dialog_id)
    }

    fn resolve_danger(&mut self, outcome: &DialogOutcome) -> SettingsDangerResolution {
        let Some(pending) = self.pending_danger.as_ref() else {
            return SettingsDangerResolution::Ignored;
        };
        let matches_dialog = match outcome {
            DialogOutcome::Cancelled { dialog_id }
            | DialogOutcome::DangerousApproved { dialog_id, .. } => *dialog_id == pending.dialog_id,
            DialogOutcome::AlertDismissed { .. } | DialogOutcome::PromptSubmitted { .. } => false,
        };
        if !matches_dialog {
            return SettingsDangerResolution::Ignored;
        }
        let pending = self
            .pending_danger
            .take()
            .expect("the matching settings danger exists");
        match outcome {
            DialogOutcome::Cancelled { .. } => SettingsDangerResolution::Cancelled,
            DialogOutcome::DangerousApproved { operation_id, .. }
                if operation_id == &pending.proposal.plan.definition().id =>
            {
                if !self.accepts(&pending.proposal.lease) {
                    return SettingsDangerResolution::Stale;
                }
                SettingsDangerResolution::Authorized {
                    confirmation: DangerousConfirmation::approve(
                        pending.proposal.plan.definition(),
                    ),
                    presentation: pending.proposal.lease,
                    plan: Box::new(pending.proposal.plan),
                }
            }
            DialogOutcome::DangerousApproved { .. } => SettingsDangerResolution::Ignored,
            DialogOutcome::AlertDismissed { .. } | DialogOutcome::PromptSubmitted { .. } => {
                SettingsDangerResolution::Ignored
            }
        }
    }

    fn apply_danger_success(&mut self, lease: &SettingsLease, kind: &SettingsDangerKind) -> bool {
        if !self.accepts(lease) {
            return false;
        }
        match kind {
            SettingsDangerKind::RemoveProvider { provider_id } => {
                self.draft
                    .ai
                    .providers
                    .retain(|provider| provider.id != provider_id.as_str());
                if self.draft.ai.default_provider_id.as_deref() == Some(provider_id) {
                    self.draft.ai.default_provider_id = self
                        .draft
                        .ai
                        .providers
                        .first()
                        .map(|provider| provider.id.clone());
                }
                self.selected_provider_id = None;
                self.adding_provider = false;
            }
            SettingsDangerKind::ClearApiKey { provider_id } => {
                if let Some(provider) = self
                    .draft
                    .ai
                    .providers
                    .iter_mut()
                    .find(|provider| provider.id == *provider_id)
                {
                    provider.has_api_key = false;
                }
            }
        }
        true
    }
}

#[derive(Clone, Copy)]
enum SettingsToggle {
    AutoConnect,
    Compact,
    Animations,
    StatusBar,
    Notifications,
    ConnectionNotifications,
    CommandNotifications,
    ErrorNotifications,
    SavePasswords,
    RequireConfirmation,
    DockerAutoRefresh,
    DockerSystemContainers,
    ProviderEnabled,
    ProxyEnabled,
}

struct SettingsPatch {
    draft: AppSettings,
    provider: Option<AiProviderSettings>,
    provider_was_existing: bool,
}

impl SettingsPatch {
    fn apply(self, settings: &mut AppSettings) -> CoreResult<()> {
        settings.theme = self.draft.theme;
        settings.language = self.draft.language;
        settings.auto_connect = self.draft.auto_connect;
        settings.default_ssh_port = self.draft.default_ssh_port;
        settings.terminal_font = self.draft.terminal_font;
        settings.terminal_font_size = self.draft.terminal_font_size;
        settings.max_log_lines = self.draft.max_log_lines;
        settings.log_level = self.draft.log_level;
        settings.notifications = self.draft.notifications;
        settings.security = self.draft.security;
        settings.ui = self.draft.ui;
        settings.docker = self.draft.docker;
        settings.ssh = self.draft.ssh;
        settings.ai.proxy = self.draft.ai.proxy;

        if let Some(provider) = self.provider {
            match settings
                .ai
                .providers
                .iter_mut()
                .find(|stored| stored.id == provider.id)
            {
                Some(stored) if self.provider_was_existing => *stored = provider,
                Some(_) => {
                    return Err(CoreError::Validation {
                        subject: "AI provider id",
                        message: "a provider with this id was added concurrently".to_owned(),
                    });
                }
                None if self.provider_was_existing => {
                    return Err(CoreError::NotFound {
                        entity: "AI provider",
                        id: provider.id,
                    });
                }
                None => settings.ai.providers.push(provider),
            }
        }
        settings.ai.default_provider_id = self.draft.ai.default_provider_id;
        Ok(())
    }
}

struct SettingsSaveRequest {
    patch: SettingsPatch,
    api_key: Option<(String, SecretValue)>,
}

pub struct SettingsPanel {
    services: Arc<BackendServices>,
    tokio: Arc<TokioBridge>,
    shared: Entity<SharedAppState>,
    model: SettingsPanelModel,
    sidebar_width: Entity<InputState>,
    session_timeout_minutes: Entity<InputState>,
    default_ssh_port: Entity<InputState>,
    ssh_keep_alive_seconds: Entity<InputState>,
    ssh_timeout_seconds: Entity<InputState>,
    ssh_retries: Entity<InputState>,
    docker_refresh_seconds: Entity<InputState>,
    terminal_font_size: Entity<InputState>,
    terminal_scrollback: Entity<InputState>,
    provider_id: Entity<InputState>,
    provider_label: Entity<InputState>,
    provider_endpoint: Entity<InputState>,
    provider_model: Entity<InputState>,
    provider_api_key: Entity<InputState>,
    proxy_url: Entity<InputState>,
    provider_test_abort: Option<tokio::task::AbortHandle>,
    _subscriptions: Vec<Subscription>,
}

impl EventEmitter<SettingsPanelEvent> for SettingsPanel {}

impl SettingsPanel {
    pub fn new(
        services: Arc<BackendServices>,
        tokio: Arc<TokioBridge>,
        shared: Entity<SharedAppState>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let sidebar_width = text_input(window, cx, "200..800");
        let session_timeout_minutes = text_input(window, cx, "1..1440 分钟");
        let default_ssh_port = text_input(window, cx, "1..65535");
        let ssh_keep_alive_seconds = text_input(window, cx, "5..300 秒");
        let ssh_timeout_seconds = text_input(window, cx, "0 或 1..600 秒");
        let ssh_retries = text_input(window, cx, "1..10");
        let docker_refresh_seconds = text_input(window, cx, "1..60 秒");
        let terminal_font_size = text_input(window, cx, "8..72");
        let terminal_scrollback = text_input(window, cx, "1..100000");
        let provider_id = text_input(window, cx, "provider-id");
        let provider_label = text_input(window, cx, "显示名称");
        let provider_endpoint = text_input(window, cx, "https://…");
        let provider_model = text_input(window, cx, "model-id");
        let provider_api_key = masked_text_input(window, cx, "只写；留空保持现有密钥");
        let proxy_url = text_input(window, cx, "http://127.0.0.1:8080");
        Self {
            services,
            tokio,
            shared,
            model: SettingsPanelModel::default(),
            sidebar_width,
            session_timeout_minutes,
            default_ssh_port,
            ssh_keep_alive_seconds,
            ssh_timeout_seconds,
            ssh_retries,
            docker_refresh_seconds,
            terminal_font_size,
            terminal_scrollback,
            provider_id,
            provider_label,
            provider_endpoint,
            provider_model,
            provider_api_key,
            proxy_url,
            provider_test_abort: None,
            _subscriptions: Vec::new(),
        }
    }

    pub fn activate(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        match self.services.settings().load() {
            Ok(settings) => {
                self.model.activate(settings);
                self.sync_inputs(window, cx);
                self.sidebar_width
                    .update(cx, |input, cx| input.focus(window, cx));
            }
            Err(error) => {
                self.model.active = true;
                self.model.generation = self.model.generation.wrapping_add(1).max(1);
                self.model.notice = Some((format!("设置加载失败：{error}").into(), true));
            }
        }
        cx.notify();
    }

    pub const fn is_active(&self) -> bool {
        self.model.active
    }

    pub fn deactivate(&mut self, cx: &mut Context<Self>) {
        abort_task(&mut self.provider_test_abort);
        if let Some(dialog_id) = self.model.pending_dialog_id() {
            self.shared.update(cx, |state, cx| {
                if state
                    .interactions
                    .dialogs
                    .active()
                    .map(|dialog| dialog.id())
                    == Some(dialog_id)
                {
                    let _ = state
                        .interactions
                        .dialogs
                        .dispatch(DialogAction::Cancel { dialog_id });
                    state.interactions.mark_overlay_closed();
                    cx.notify();
                }
            });
        }
        self.model.deactivate();
        cx.notify();
    }

    pub fn request_close(&mut self, cx: &mut Context<Self>) {
        cx.emit(SettingsPanelEvent::CloseRequested);
    }

    fn sync_inputs(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        set_input(
            &self.sidebar_width,
            self.model.draft.ui.sidebar_width.to_string(),
            window,
            cx,
        );
        set_input(
            &self.session_timeout_minutes,
            (self.model.draft.security.session_timeout_ms / 60_000).to_string(),
            window,
            cx,
        );
        set_input(
            &self.default_ssh_port,
            self.model.draft.default_ssh_port.to_string(),
            window,
            cx,
        );
        set_input(
            &self.ssh_keep_alive_seconds,
            (self.model.draft.ssh.keep_alive_interval_ms / 1_000).to_string(),
            window,
            cx,
        );
        set_input(
            &self.ssh_timeout_seconds,
            (self.model.draft.ssh.connection_timeout_ms / 1_000).to_string(),
            window,
            cx,
        );
        set_input(
            &self.ssh_retries,
            self.model.draft.ssh.max_retries.to_string(),
            window,
            cx,
        );
        set_input(
            &self.docker_refresh_seconds,
            (self.model.draft.docker.refresh_interval_ms / 1_000).to_string(),
            window,
            cx,
        );
        set_input(
            &self.terminal_font_size,
            self.model.draft.terminal_font_size.to_string(),
            window,
            cx,
        );
        set_input(
            &self.terminal_scrollback,
            self.model.draft.max_log_lines.to_string(),
            window,
            cx,
        );
        set_input(
            &self.proxy_url,
            self.model
                .draft
                .ai
                .proxy
                .as_ref()
                .map_or_else(String::new, |proxy| proxy.proxy_url.clone()),
            window,
            cx,
        );
        self.sync_provider_inputs(window, cx);
    }

    fn sync_provider_inputs(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let provider = self.model.selected_provider().cloned();
        set_input(
            &self.provider_id,
            provider.as_ref().map_or_else(String::new, |p| p.id.clone()),
            window,
            cx,
        );
        set_input(
            &self.provider_label,
            provider
                .as_ref()
                .map_or_else(String::new, |p| p.label.clone()),
            window,
            cx,
        );
        set_input(
            &self.provider_endpoint,
            provider
                .as_ref()
                .map_or_else(String::new, |p| p.endpoint.clone()),
            window,
            cx,
        );
        set_input(
            &self.provider_model,
            provider
                .as_ref()
                .map_or_else(String::new, |p| p.model.clone()),
            window,
            cx,
        );
        set_input(&self.provider_api_key, String::new(), window, cx);
    }

    fn select_tab(&mut self, tab: SettingsTab, cx: &mut Context<Self>) {
        self.model.tab = tab;
        cx.notify();
    }

    fn select_theme(&mut self, theme: Theme, cx: &mut Context<Self>) {
        self.model.draft.theme = theme;
        cx.notify();
    }

    fn select_language(&mut self, language: Language, cx: &mut Context<Self>) {
        self.model.draft.language = language;
        cx.notify();
    }

    fn select_log_level(&mut self, level: ApplicationLogLevel, cx: &mut Context<Self>) {
        self.model.draft.log_level = level;
        cx.notify();
    }

    fn select_provider_kind(&mut self, kind: AiProviderKind, cx: &mut Context<Self>) {
        self.model.provider_kind = kind;
        cx.notify();
    }

    fn select_proxy_type(&mut self, proxy_type: ProxyType, cx: &mut Context<Self>) {
        if let Some(proxy) = self.model.draft.ai.proxy.as_mut() {
            proxy.proxy_type = proxy_type;
        }
        cx.notify();
    }

    fn toggle(&mut self, setting: SettingsToggle, cx: &mut Context<Self>) {
        match setting {
            SettingsToggle::AutoConnect => {
                self.model.draft.auto_connect = !self.model.draft.auto_connect;
            }
            SettingsToggle::Compact => {
                self.model.draft.ui.compact_mode = !self.model.draft.ui.compact_mode;
            }
            SettingsToggle::Animations => {
                self.model.draft.ui.animations_enabled = !self.model.draft.ui.animations_enabled;
            }
            SettingsToggle::StatusBar => {
                self.model.draft.ui.show_status_bar = !self.model.draft.ui.show_status_bar;
            }
            SettingsToggle::Notifications => {
                self.model.draft.notifications.enabled = !self.model.draft.notifications.enabled;
            }
            SettingsToggle::ConnectionNotifications => {
                self.model.draft.notifications.connection_status =
                    !self.model.draft.notifications.connection_status;
            }
            SettingsToggle::CommandNotifications => {
                self.model.draft.notifications.command_completion =
                    !self.model.draft.notifications.command_completion;
            }
            SettingsToggle::ErrorNotifications => {
                self.model.draft.notifications.error_alerts =
                    !self.model.draft.notifications.error_alerts;
            }
            SettingsToggle::SavePasswords => {
                self.model.draft.security.save_passwords =
                    !self.model.draft.security.save_passwords;
            }
            SettingsToggle::RequireConfirmation => {
                self.model.draft.security.require_confirmation =
                    !self.model.draft.security.require_confirmation;
            }
            SettingsToggle::DockerAutoRefresh => {
                self.model.draft.docker.auto_refresh = !self.model.draft.docker.auto_refresh;
            }
            SettingsToggle::DockerSystemContainers => {
                self.model.draft.docker.show_system_containers =
                    !self.model.draft.docker.show_system_containers;
            }
            SettingsToggle::ProviderEnabled => {
                self.model.provider_enabled = !self.model.provider_enabled;
            }
            SettingsToggle::ProxyEnabled => {
                self.model.draft.ai.proxy = if self.model.draft.ai.proxy.is_some() {
                    None
                } else {
                    Some(ProxySettings {
                        proxy_type: ProxyType::Http,
                        proxy_url: String::new(),
                    })
                };
            }
        }
        cx.notify();
    }

    fn toggle_provider_default(&mut self, cx: &mut Context<Self>) {
        self.model.provider_default = !self.model.provider_default;
        cx.notify();
    }

    fn select_provider(&mut self, id: &str, window: &mut Window, cx: &mut Context<Self>) {
        self.stop_provider_test();
        if self.model.select_provider(id) {
            self.sync_provider_inputs(window, cx);
            cx.notify();
        }
    }

    fn start_add_provider(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.stop_provider_test();
        self.model.start_add_provider();
        self.sync_provider_inputs(window, cx);
        self.provider_id
            .update(cx, |input, cx| input.focus(window, cx));
        cx.notify();
    }

    fn save(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.model.saving {
            return;
        }
        self.stop_provider_test();
        let api_key = self.take_provider_api_key(window, cx);
        let request = match self.build_save_request(cx, api_key) {
            Ok(request) => request,
            Err(error) => {
                self.model.notice = Some((format!("设置验证失败：{error}").into(), true));
                cx.notify();
                return;
            }
        };
        let Some(lease) = self.model.new_lease() else {
            return;
        };
        self.model.saving = true;
        self.model.notice = Some(("正在保存设置…".into(), false));
        cx.notify();

        let repository = self.services.settings().clone();
        let task = self.tokio.spawn(async move {
            repository.update_with_ai_key(
                move |settings| request.patch.apply(settings),
                request.api_key,
            )
        });
        cx.spawn(async move |panel, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(panel) = panel.upgrade() {
                    panel.update(cx, |panel, cx| panel.finish_save(lease, result, cx));
                }
            });
        })
        .detach();
    }

    fn finish_save(
        &mut self,
        lease: SettingsLease,
        result: Result<CoreResult<AppSettings>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if !self.model.accepts(&lease) {
            return;
        }
        self.model.saving = false;
        match result {
            Err(error) => {
                self.model.notice = Some((format!("设置保存任务失败：{error}").into(), true));
            }
            Ok(Err(error)) => {
                self.model.notice = Some((format!("设置保存失败：{error}").into(), true));
            }
            Ok(Ok(settings)) => {
                let saved_provider_id = self
                    .model
                    .adding_provider
                    .then(|| input_value(&self.provider_id, cx));
                self.model.draft = settings.clone();
                if let Some(provider_id) = saved_provider_id {
                    let _ = self.model.select_provider(&provider_id);
                } else {
                    self.model.sync_selected_provider_flags();
                }
                self.model.notice = Some(("设置已原子保存".into(), false));
                cx.emit(SettingsPanelEvent::Saved { settings });
            }
        }
        cx.notify();
    }

    fn take_provider_api_key(
        &self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Option<SecretValue> {
        let secret = SecretValue::new(input_value(&self.provider_api_key, cx));
        set_input(&self.provider_api_key, String::new(), window, cx);
        (!secret.is_empty()).then_some(secret)
    }

    fn build_save_request(
        &self,
        cx: &Context<Self>,
        api_key: Option<SecretValue>,
    ) -> CoreResult<SettingsSaveRequest> {
        let mut draft = self.model.draft.clone();
        draft.ui.sidebar_width = parse_u32("sidebar width", &input_value(&self.sidebar_width, cx))?;
        draft.security.session_timeout_ms = seconds_or_minutes_to_ms(
            "session timeout",
            parse_u32(
                "session timeout",
                &input_value(&self.session_timeout_minutes, cx),
            )?,
            60_000,
        )?;
        draft.default_ssh_port =
            parse_u16("default SSH port", &input_value(&self.default_ssh_port, cx))?;
        draft.ssh.keep_alive_interval_ms = seconds_or_minutes_to_ms(
            "SSH keep-alive interval",
            parse_u32(
                "SSH keep-alive interval",
                &input_value(&self.ssh_keep_alive_seconds, cx),
            )?,
            1_000,
        )?;
        draft.ssh.connection_timeout_ms = seconds_or_minutes_to_ms(
            "SSH connection timeout",
            parse_u32(
                "SSH connection timeout",
                &input_value(&self.ssh_timeout_seconds, cx),
            )?,
            1_000,
        )?;
        draft.ssh.max_retries = parse_u8("SSH retries", &input_value(&self.ssh_retries, cx))?;
        draft.docker.refresh_interval_ms = seconds_or_minutes_to_ms(
            "Docker refresh interval",
            parse_u32(
                "Docker refresh interval",
                &input_value(&self.docker_refresh_seconds, cx),
            )?,
            1_000,
        )?;
        draft.terminal_font = EMBEDDED_TERMINAL_FONT.to_owned();
        draft.terminal_font_size = parse_u16(
            "terminal font size",
            &input_value(&self.terminal_font_size, cx),
        )?;
        draft.max_log_lines = parse_u32(
            "terminal scrollback",
            &input_value(&self.terminal_scrollback, cx),
        )?;
        if let Some(proxy) = draft.ai.proxy.as_mut() {
            proxy.proxy_url = input_value(&self.proxy_url, cx);
        }

        let selected_existing = self.model.selected_provider().cloned();
        let provider = if self.model.adding_provider || selected_existing.is_some() {
            let id = selected_existing.as_ref().map_or_else(
                || input_value(&self.provider_id, cx),
                |provider| provider.id.clone(),
            );
            let provider = AiProviderSettings {
                id,
                label: input_value(&self.provider_label, cx),
                kind: self.model.provider_kind,
                endpoint: input_value(&self.provider_endpoint, cx),
                model: input_value(&self.provider_model, cx),
                enabled: self.model.provider_enabled,
                has_api_key: selected_existing
                    .as_ref()
                    .is_some_and(|provider| provider.has_api_key),
            };
            if self.model.provider_default {
                draft.ai.default_provider_id = Some(provider.id.clone());
            } else if draft.ai.default_provider_id.as_deref() == Some(provider.id.as_str()) {
                draft.ai.default_provider_id = None;
            }
            Some(provider)
        } else {
            None
        };

        let api_key = if let Some(api_key) = api_key {
            let provider_id = provider
                .as_ref()
                .map(|provider| provider.id.clone())
                .ok_or_else(|| CoreError::Validation {
                    subject: "AI API key",
                    message: "select or add a provider before entering a key".to_owned(),
                })?;
            Some((provider_id, api_key))
        } else {
            None
        };

        let provider_was_existing = selected_existing.is_some();
        let mut validation = draft.clone();
        if let Some(provider) = &provider {
            match validation
                .ai
                .providers
                .iter_mut()
                .find(|stored| stored.id == provider.id)
            {
                Some(stored) if provider_was_existing => *stored = provider.clone(),
                Some(_) => {
                    return Err(CoreError::Validation {
                        subject: "AI provider id",
                        message: "must be unique".to_owned(),
                    });
                }
                None => validation.ai.providers.push(provider.clone()),
            }
        }
        validation.ai.default_provider_id = draft.ai.default_provider_id.clone();
        validation.validate()?;

        Ok(SettingsSaveRequest {
            patch: SettingsPatch {
                draft,
                provider,
                provider_was_existing,
            },
            api_key,
        })
    }

    fn request_test_provider(&mut self, cx: &mut Context<Self>) {
        if self.model.adding_provider {
            self.model.notice = Some((
                "新增 Provider 必须先保存，再使用已保存配置进行测试".into(),
                true,
            ));
            cx.notify();
            return;
        }
        let Some(provider_id) = self.model.selected_provider_id.clone() else {
            self.model.notice = Some(("请选择已保存的 Provider".into(), true));
            cx.notify();
            return;
        };
        let provider_id = match AiProviderId::new(provider_id) {
            Ok(provider_id) => provider_id,
            Err(error) => {
                self.model.notice = Some((format!("Provider ID 无效：{error}").into(), true));
                cx.notify();
                return;
            }
        };
        let ai = match self.services.ai() {
            Ok(ai) => ai.clone(),
            Err(_) => {
                self.model.notice = Some(("AI 服务尚未初始化".into(), true));
                cx.notify();
                return;
            }
        };
        let Some(lease) = self.model.begin_provider_test() else {
            return;
        };
        abort_task(&mut self.provider_test_abort);
        self.model.provider_probe = None;
        self.model.notice = Some(("正在测试已保存的 Provider…".into(), false));
        cx.notify();

        let task = self.tokio.spawn(async move {
            let provider_id_text = provider_id.to_string();
            let started = std::time::Instant::now();
            let result = match tokio::time::timeout(
                PROVIDER_PROBE_TIMEOUT,
                ai.list_models(provider_id).wait(),
            )
            .await
            {
                Ok(Ok(models)) => ProviderProbeResult::Success {
                    model_count: models.models.len(),
                },
                Ok(Err(error)) => safe_provider_probe_failure(&error),
                Err(_) => ProviderProbeResult::Failure {
                    category: "timeout",
                    detail: "Provider 在 15 秒内没有完成响应",
                },
            };
            ProviderProbeReport {
                provider_id: provider_id_text,
                elapsed_ms: started.elapsed().as_millis(),
                result,
            }
        });
        self.provider_test_abort = Some(task.abort_handle());
        cx.spawn(async move |panel, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(panel) = panel.upgrade() {
                    panel.update(cx, |panel, cx| {
                        panel.finish_provider_test(lease, result, cx)
                    });
                }
            });
        })
        .detach();
    }

    fn finish_provider_test(
        &mut self,
        lease: SettingsLease,
        result: Result<ProviderProbeReport, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if !self.model.accepts_provider_test(&lease) {
            return;
        }
        self.provider_test_abort = None;
        self.model.provider_test_request_id = None;
        match result {
            Ok(report) => {
                let succeeded = matches!(report.result, ProviderProbeResult::Success { .. });
                self.model.provider_probe = Some(report);
                self.model.notice = Some((
                    if succeeded {
                        "Provider 测试成功".into()
                    } else {
                        "Provider 测试失败；详情见测试结果".into()
                    },
                    !succeeded,
                ));
            }
            Err(error) if error.is_cancelled() => {}
            Err(_) => {
                self.model.provider_probe = Some(ProviderProbeReport {
                    provider_id: self.model.selected_provider_id.clone().unwrap_or_default(),
                    elapsed_ms: 0,
                    result: ProviderProbeResult::Failure {
                        category: "runtime",
                        detail: "Provider 测试任务异常结束",
                    },
                });
                self.model.notice = Some(("Provider 测试任务失败".into(), true));
            }
        }
        cx.notify();
    }

    fn cancel_provider_test(&mut self, cx: &mut Context<Self>) {
        self.stop_provider_test();
        self.model.notice = Some(("Provider 测试已取消".into(), false));
        cx.notify();
    }

    fn stop_provider_test(&mut self) {
        abort_task(&mut self.provider_test_abort);
        self.model.cancel_provider_test();
    }

    fn request_remove_provider(&mut self, cx: &mut Context<Self>) {
        let Some(provider_id) = self.model.selected_provider_id.clone() else {
            self.model.notice = Some(("请选择要删除的 Provider".into(), true));
            cx.notify();
            return;
        };
        match self
            .services
            .settings()
            .plan_remove_ai_provider(&provider_id)
            .and_then(|plan| {
                self.model
                    .propose_danger(SettingsDangerPlan::RemoveProvider(plan))
            }) {
            Ok(proposal) => self.open_danger_dialog(proposal, cx),
            Err(error) => {
                self.model.notice = Some((format!("无法创建删除计划：{error}").into(), true));
                cx.notify();
            }
        }
    }

    fn request_clear_api_key(&mut self, cx: &mut Context<Self>) {
        let Some(provider_id) = self.model.selected_provider_id.clone() else {
            self.model.notice = Some(("请选择要清除密钥的 Provider".into(), true));
            cx.notify();
            return;
        };
        match self
            .services
            .settings()
            .plan_clear_ai_api_key(&provider_id)
            .and_then(|plan| {
                self.model
                    .propose_danger(SettingsDangerPlan::ClearApiKey(plan))
            }) {
            Ok(proposal) => self.open_danger_dialog(proposal, cx),
            Err(error) => {
                self.model.notice = Some((format!("无法创建密钥清除计划：{error}").into(), true));
                cx.notify();
            }
        }
    }

    fn open_danger_dialog(&mut self, proposal: SettingsDangerProposal, cx: &mut Context<Self>) {
        let plan = proposal.plan.definition().clone();
        let dialog = self.shared.update(cx, |state, cx| {
            if state.interactions.dialogs.active().is_some() {
                return Err(DialogError::ActionTypeMismatch);
            }
            let dialog_id = state.interactions.dialogs.show_dangerous(&plan)?;
            state.interactions.focus_dialog();
            cx.notify();
            Ok(dialog_id)
        });
        match dialog {
            Ok(dialog_id) => self.model.arm_danger(proposal, dialog_id),
            Err(error) => {
                self.model.notice = Some((format!("危险确认框无法打开：{error:?}").into(), true));
            }
        }
        cx.notify();
    }

    pub fn handle_dialog_outcome(
        &mut self,
        outcome: &DialogOutcome,
        cx: &mut Context<Self>,
    ) -> bool {
        match self.model.resolve_danger(outcome) {
            SettingsDangerResolution::Ignored => false,
            SettingsDangerResolution::Cancelled => {
                self.model.notice = Some(("危险设置变更已取消".into(), false));
                cx.notify();
                true
            }
            SettingsDangerResolution::Stale => {
                self.model.notice = Some(("设置面板已变化，迟到确认未执行".into(), true));
                cx.notify();
                true
            }
            SettingsDangerResolution::Authorized {
                plan,
                confirmation,
                presentation,
            } => {
                let kind = plan.kind();
                let repository = self.services.settings().clone();
                let journal = self.services.operation_journal().clone();
                let task = self.tokio.spawn(async move {
                    match *plan {
                        SettingsDangerPlan::RemoveProvider(plan) => {
                            repository
                                .execute_remove_ai_provider(plan, confirmation, &journal)
                                .await
                        }
                        SettingsDangerPlan::ClearApiKey(plan) => {
                            repository
                                .execute_clear_ai_api_key(plan, confirmation, &journal)
                                .await
                        }
                    }
                });
                cx.spawn(async move |panel, cx| {
                    let result = task.await;
                    let _ = cx.update(|cx| {
                        if let Some(panel) = panel.upgrade() {
                            panel.update(cx, |panel, cx| {
                                panel.finish_danger(presentation, kind, result, cx)
                            });
                        }
                    });
                })
                .detach();
                true
            }
        }
    }

    fn finish_danger(
        &mut self,
        presentation: SettingsLease,
        kind: SettingsDangerKind,
        result: Result<CoreResult<SettingsOperationOutcome>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if !self.model.accepts(&presentation) {
            return;
        }
        match result {
            Err(error) => {
                self.model.notice = Some((format!("危险设置任务失败：{error}").into(), true));
            }
            Ok(Err(error)) => {
                self.model.notice = Some((format!("危险设置变更失败：{error}").into(), true));
            }
            Ok(Ok(outcome)) => {
                let _ = self.model.apply_danger_success(&presentation, &kind);
                self.model.notice = Some((
                    format!("危险设置变更已完成日志验证：{}", outcome.operation_id).into(),
                    false,
                ));
            }
        }
        cx.notify();
    }
}

fn text_input(
    window: &mut Window,
    cx: &mut Context<SettingsPanel>,
    placeholder: &'static str,
) -> Entity<InputState> {
    cx.new(|cx| InputState::new(window, cx).placeholder(placeholder))
}

fn masked_text_input(
    window: &mut Window,
    cx: &mut Context<SettingsPanel>,
    placeholder: &'static str,
) -> Entity<InputState> {
    cx.new(|cx| {
        InputState::new(window, cx)
            .placeholder(placeholder)
            .masked(true)
    })
}

fn safe_provider_probe_failure(error: &CoreError) -> ProviderProbeResult {
    let (category, detail) = match error {
        CoreError::NotFound { .. } => ("configuration", "已保存的 Provider 不存在，请重新加载设置"),
        CoreError::Unsupported { .. } => ("runtime", "AI 服务在当前运行环境中不可用"),
        CoreError::Crypto(_) => ("credentials", "无法解密已保存的 Provider 凭据"),
        CoreError::Io { .. } | CoreError::Encode { .. } | CoreError::Decode { .. } => {
            ("storage", "无法读取已保存的 Provider 配置")
        }
        CoreError::Validation { subject, .. } if *subject == "AI provider" => {
            ("configuration", "Provider 已禁用或配置无效")
        }
        CoreError::Validation { .. } => (
            "request",
            "Provider 请求未通过；请检查端点、模型、代理和凭据",
        ),
        _ => ("request", "Provider 测试未完成"),
    };
    ProviderProbeResult::Failure { category, detail }
}

fn abort_task(slot: &mut Option<tokio::task::AbortHandle>) {
    if let Some(abort) = slot.take() {
        abort.abort();
    }
}

fn set_input(
    input: &Entity<InputState>,
    value: String,
    window: &mut Window,
    cx: &mut Context<SettingsPanel>,
) {
    input.update(cx, |input, cx| input.set_value(value, window, cx));
}

fn input_value(input: &Entity<InputState>, cx: &Context<SettingsPanel>) -> String {
    input.read(cx).value().to_string()
}

fn parse_u32(subject: &'static str, value: &str) -> CoreResult<u32> {
    value
        .trim()
        .parse::<u32>()
        .map_err(|_| CoreError::Validation {
            subject,
            message: "must be an unsigned integer".to_owned(),
        })
}

fn parse_u16(subject: &'static str, value: &str) -> CoreResult<u16> {
    value
        .trim()
        .parse::<u16>()
        .map_err(|_| CoreError::Validation {
            subject,
            message: "must be an integer in the u16 range".to_owned(),
        })
}

fn parse_u8(subject: &'static str, value: &str) -> CoreResult<u8> {
    value
        .trim()
        .parse::<u8>()
        .map_err(|_| CoreError::Validation {
            subject,
            message: "must be an integer in the u8 range".to_owned(),
        })
}

fn seconds_or_minutes_to_ms(subject: &'static str, value: u32, multiplier: u32) -> CoreResult<u32> {
    value
        .checked_mul(multiplier)
        .ok_or_else(|| CoreError::Validation {
            subject,
            message: "value overflows milliseconds".to_owned(),
        })
}

fn section_title(
    title: &'static str,
    description: &'static str,
    tokens: ThemeTokens,
) -> AnyElement {
    div()
        .mb_3()
        .mt_2()
        .child(div().text_lg().child(title))
        .child(div().text_sm().text_color(tokens.muted).child(description))
        .into_any_element()
}

fn input_row(label: &'static str, input: &Entity<InputState>, tokens: ThemeTokens) -> AnyElement {
    div()
        .mb_3()
        .child(div().mb_1().text_xs().text_color(tokens.muted).child(label))
        .child(Input::new(input).small())
        .into_any_element()
}

fn toggle_row(label: &'static str, control: Button, tokens: ThemeTokens) -> AnyElement {
    div()
        .mb_2()
        .flex()
        .items_center()
        .child(
            div()
                .flex_1()
                .text_sm()
                .text_color(tokens.text)
                .child(label),
        )
        .child(control)
        .into_any_element()
}

impl Render for SettingsPanel {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens = self.shared.read(cx).theme.tokens();
        let notice = self.model.notice.clone();
        let tab = self.model.tab;
        let saving = self.model.saving;
        div()
            .id("native-settings-backdrop")
            .absolute()
            .inset_0()
            .p_5()
            .flex()
            .items_center()
            .justify_center()
            .bg(gpui::rgba(0x00000088))
            .on_click(cx.listener(|this, _, _, cx| this.request_close(cx)))
            .child(
                div()
                    .id("native-settings-panel")
                    .on_click(|_, _, cx| cx.stop_propagation())
                    .w(px(980.0))
                    .max_w_full()
                    .h(px(720.0))
                    .max_h_full()
                    .rounded_lg()
                    .border_1()
                    .border_color(tokens.border)
                    .bg(tokens.background)
                    .shadow_lg()
                    .flex()
                    .flex_col()
                    .child(
                        div()
                            .h(px(56.0))
                            .flex_none()
                            .px_5()
                            .flex()
                            .items_center()
                            .border_b_1()
                            .border_color(tokens.border)
                            .child(div().text_2xl().child("设置"))
                            .child(
                                div().ml_auto().child(
                                    crate::buttons::close_button("native-settings-close")
                                        .small()
                                        .on_click(
                                            cx.listener(|this, _, _, cx| this.request_close(cx)),
                                        ),
                                ),
                            ),
                    )
                    .when_some(notice, |panel, (message, is_error)| {
                        panel.child(
                            div()
                                .mx_5()
                                .mt_3()
                                .p_2()
                                .rounded_md()
                                .border_1()
                                .border_color(if is_error {
                                    tokens.danger
                                } else {
                                    tokens.success
                                })
                                .text_sm()
                                .text_color(if is_error {
                                    tokens.danger
                                } else {
                                    tokens.success
                                })
                                .child(message),
                        )
                    })
                    .child(
                        div()
                            .flex_1()
                            .min_h_0()
                            .flex()
                            .child(
                                div()
                                    .w(px(150.0))
                                    .flex_none()
                                    .p_3()
                                    .border_r_1()
                                    .border_color(tokens.border)
                                    .children(SettingsTab::ALL.into_iter().map(|entry| {
                                        crate::buttons::button(SharedString::from(format!(
                                            "settings-tab-{entry:?}"
                                        )))
                                        .label(entry.label())
                                        .w_full()
                                        .mb_2()
                                        .selected(entry == tab)
                                        .on_click(
                                            cx.listener(move |this, _, _, cx| {
                                                this.select_tab(entry, cx)
                                            }),
                                        )
                                    })),
                            )
                            .child(
                                div()
                                    .flex_1()
                                    .min_w_0()
                                    .min_h_0()
                                    .p_5()
                                    .overflow_y_scrollbar()
                                    .child(match tab {
                                        SettingsTab::General => self.render_general(tokens, cx),
                                        SettingsTab::Connections => {
                                            self.render_connections(tokens, cx)
                                        }
                                        SettingsTab::Terminal => self.render_terminal(tokens, cx),
                                        SettingsTab::Ai => self.render_ai(tokens, cx),
                                    }),
                            ),
                    )
                    .child(
                        div()
                            .h(px(58.0))
                            .flex_none()
                            .px_5()
                            .flex()
                            .items_center()
                            .justify_end()
                            .gap_2()
                            .border_t_1()
                            .border_color(tokens.border)
                            .child(
                                crate::buttons::button("native-settings-cancel")
                                    .label("取消")
                                    .small()
                                    .on_click(cx.listener(|this, _, _, cx| this.request_close(cx))),
                            )
                            .child(
                                crate::buttons::button("native-settings-save")
                                    .label(if saving { "保存中…" } else { "保存" })
                                    .small()
                                    .primary()
                                    .disabled(saving)
                                    .on_click(
                                        cx.listener(|this, _, window, cx| this.save(window, cx)),
                                    ),
                            ),
                    ),
            )
    }
}

impl SettingsPanel {
    fn render_general(&mut self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let draft = self.model.draft.clone();
        div()
            .child(section_title(
                "主题与语言",
                "四套离线主题与两种界面语言。",
                tokens,
            ))
            .child(
                div().flex().flex_wrap().gap_2().mb_3().children(
                    [
                        Theme::Light,
                        Theme::Dark,
                        Theme::Sakura,
                        Theme::IncidentCanvas,
                    ]
                    .into_iter()
                    .map(|theme| {
                        crate::buttons::button(SharedString::from(format!(
                            "settings-theme-{theme:?}"
                        )))
                        .label(ThemeId::from(theme).label())
                        .small()
                        .selected(theme == draft.theme)
                        .on_click(cx.listener(move |this, _, _, cx| this.select_theme(theme, cx)))
                    }),
                ),
            )
            .child(
                div()
                    .flex()
                    .gap_2()
                    .mb_5()
                    .child(
                        crate::buttons::button("settings-language-zh")
                            .label("简体中文")
                            .small()
                            .selected(draft.language == Language::ChineseSimplified)
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.select_language(Language::ChineseSimplified, cx)
                            })),
                    )
                    .child(
                        crate::buttons::button("settings-language-en")
                            .label("English")
                            .small()
                            .selected(draft.language == Language::English)
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.select_language(Language::English, cx)
                            })),
                    ),
            )
            .child(section_title(
                "界面",
                "密度、动画、状态栏与侧栏宽度。",
                tokens,
            ))
            .child(toggle_row(
                "紧凑密度",
                self.toggle_button(
                    "settings-compact",
                    draft.ui.compact_mode,
                    SettingsToggle::Compact,
                    cx,
                ),
                tokens,
            ))
            .child(toggle_row(
                "界面动画",
                self.toggle_button(
                    "settings-animations",
                    draft.ui.animations_enabled,
                    SettingsToggle::Animations,
                    cx,
                ),
                tokens,
            ))
            .child(toggle_row(
                "显示状态栏",
                self.toggle_button(
                    "settings-status-bar",
                    draft.ui.show_status_bar,
                    SettingsToggle::StatusBar,
                    cx,
                ),
                tokens,
            ))
            .child(input_row("侧栏宽度（px）", &self.sidebar_width, tokens))
            .child(section_title(
                "诊断日志",
                "级别会持久化；诊断面板最多保留最近 500 条原生日志。",
                tokens,
            ))
            .child(div().flex().flex_wrap().gap_2().mb_5().children(
                ApplicationLogLevel::ALL.into_iter().map(|level| {
                    crate::buttons::button(SharedString::from(format!(
                        "settings-log-level-{}",
                        level.as_str()
                    )))
                    .label(match level {
                        ApplicationLogLevel::Debug => "Debug",
                        ApplicationLogLevel::Info => "Info",
                        ApplicationLogLevel::Warn => "Warn",
                        ApplicationLogLevel::Error => "Error",
                    })
                    .small()
                    .selected(level == draft.log_level)
                    .on_click(cx.listener(move |this, _, _, cx| this.select_log_level(level, cx)))
                }),
            ))
            .child(section_title("通知", "连接、命令完成与错误提醒。", tokens))
            .child(toggle_row(
                "启用通知",
                self.toggle_button(
                    "settings-notifications",
                    draft.notifications.enabled,
                    SettingsToggle::Notifications,
                    cx,
                ),
                tokens,
            ))
            .child(toggle_row(
                "连接状态",
                self.toggle_button(
                    "settings-notify-connection",
                    draft.notifications.connection_status,
                    SettingsToggle::ConnectionNotifications,
                    cx,
                ),
                tokens,
            ))
            .child(toggle_row(
                "命令完成",
                self.toggle_button(
                    "settings-notify-command",
                    draft.notifications.command_completion,
                    SettingsToggle::CommandNotifications,
                    cx,
                ),
                tokens,
            ))
            .child(toggle_row(
                "错误提醒",
                self.toggle_button(
                    "settings-notify-error",
                    draft.notifications.error_alerts,
                    SettingsToggle::ErrorNotifications,
                    cx,
                ),
                tokens,
            ))
            .child(section_title(
                "安全",
                "凭据保存策略、危险确认与会话超时。",
                tokens,
            ))
            .child(toggle_row(
                "允许保存连接密码",
                self.toggle_button(
                    "settings-save-passwords",
                    draft.security.save_passwords,
                    SettingsToggle::SavePasswords,
                    cx,
                ),
                tokens,
            ))
            .child(toggle_row(
                "要求操作确认",
                self.toggle_button(
                    "settings-require-confirmation",
                    draft.security.require_confirmation,
                    SettingsToggle::RequireConfirmation,
                    cx,
                ),
                tokens,
            ))
            .child(input_row(
                "会话超时（分钟）",
                &self.session_timeout_minutes,
                tokens,
            ))
            .into_any_element()
    }

    fn render_connections(&mut self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let draft = self.model.draft.clone();
        div()
            .child(section_title(
                "SSH",
                "连接默认值、保活、超时和重试上限。",
                tokens,
            ))
            .child(toggle_row(
                "启动时自动连接",
                self.toggle_button(
                    "settings-auto-connect",
                    draft.auto_connect,
                    SettingsToggle::AutoConnect,
                    cx,
                ),
                tokens,
            ))
            .child(input_row("默认 SSH 端口", &self.default_ssh_port, tokens))
            .child(input_row(
                "Keepalive（秒）",
                &self.ssh_keep_alive_seconds,
                tokens,
            ))
            .child(input_row(
                "连接超时（秒，0 为禁用）",
                &self.ssh_timeout_seconds,
                tokens,
            ))
            .child(input_row("最大重试次数", &self.ssh_retries, tokens))
            .child(section_title(
                "Docker",
                "自动刷新、刷新周期与系统容器显示。",
                tokens,
            ))
            .child(toggle_row(
                "自动刷新",
                self.toggle_button(
                    "settings-docker-refresh",
                    draft.docker.auto_refresh,
                    SettingsToggle::DockerAutoRefresh,
                    cx,
                ),
                tokens,
            ))
            .child(toggle_row(
                "显示系统容器",
                self.toggle_button(
                    "settings-docker-system",
                    draft.docker.show_system_containers,
                    SettingsToggle::DockerSystemContainers,
                    cx,
                ),
                tokens,
            ))
            .child(input_row(
                "刷新周期（秒）",
                &self.docker_refresh_seconds,
                tokens,
            ))
            .into_any_element()
    }

    fn render_terminal(&mut self, tokens: ThemeTokens, _cx: &mut Context<Self>) -> AnyElement {
        div()
            .child(section_title(
                "终端字体",
                "正式包只使用本地嵌入资源，不读取 CDN 或 Web Font。",
                tokens,
            ))
            .child(
                div()
                    .mb_3()
                    .p_3()
                    .rounded_md()
                    .border_1()
                    .border_color(tokens.border)
                    .bg(tokens.surface_alt)
                    .child(EMBEDDED_TERMINAL_FONT),
            )
            .child(input_row("字号（px）", &self.terminal_font_size, tokens))
            .child(input_row(
                "最大滚动历史行数",
                &self.terminal_scrollback,
                tokens,
            ))
            .into_any_element()
    }

    fn render_ai(&mut self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let providers = self.model.draft.ai.providers.clone();
        let selected_id = self.model.selected_provider_id.clone();
        let adding = self.model.adding_provider;
        let provider = self.model.selected_provider().cloned();
        let proxy = self.model.draft.ai.proxy.clone();
        div()
            .child(section_title(
                "AI Providers",
                "API Key 为只写输入；界面只读取 has_api_key 状态。",
                tokens,
            ))
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_2()
                    .mb_3()
                    .children(providers.into_iter().map(|entry| {
                        let id = entry.id.clone();
                        crate::buttons::button(SharedString::from(format!(
                            "settings-provider-{}",
                            entry.id
                        )))
                        .label(entry.label)
                        .small()
                        .selected(selected_id.as_deref() == Some(entry.id.as_str()))
                        .on_click(cx.listener(
                            move |this, _, window, cx| this.select_provider(&id, window, cx),
                        ))
                    }))
                    .child(
                        crate::buttons::button("settings-provider-add")
                            .label("+ 新增 Provider")
                            .small()
                            .selected(adding)
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.start_add_provider(window, cx)
                            })),
                    ),
            )
            .when(adding || provider.is_some(), |root| {
                root.child(self.render_provider_editor(provider, adding, tokens, cx))
            })
            .child(section_title(
                "AI 代理",
                "代理仅用于 AI HTTP 请求，不影响 SSH。",
                tokens,
            ))
            .child(toggle_row(
                "启用代理",
                self.toggle_button(
                    "settings-proxy-enabled",
                    proxy.is_some(),
                    SettingsToggle::ProxyEnabled,
                    cx,
                ),
                tokens,
            ))
            .when_some(proxy, |root, proxy| {
                root.child(
                    div()
                        .flex()
                        .gap_2()
                        .mb_3()
                        .child(
                            crate::buttons::button("settings-proxy-http")
                                .label("HTTP/HTTPS")
                                .small()
                                .selected(proxy.proxy_type == ProxyType::Http)
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.select_proxy_type(ProxyType::Http, cx)
                                })),
                        )
                        .child(
                            crate::buttons::button("settings-proxy-socks5")
                                .label("SOCKS5")
                                .small()
                                .selected(proxy.proxy_type == ProxyType::Socks5)
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.select_proxy_type(ProxyType::Socks5, cx)
                                })),
                        ),
                )
                .child(input_row("代理 URL", &self.proxy_url, tokens))
            })
            .into_any_element()
    }

    fn render_provider_editor(
        &mut self,
        provider: Option<AiProviderSettings>,
        adding: bool,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let has_key = provider
            .as_ref()
            .is_some_and(|provider| provider.has_api_key);
        let provider_id = provider.as_ref().map(|provider| provider.id.clone());
        let testing = self.model.provider_test_request_id.is_some();
        let probe = self.model.provider_probe.clone();
        div()
            .mb_5()
            .p_4()
            .rounded_lg()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .child(if adding {
                input_row("Provider ID", &self.provider_id, tokens)
            } else {
                div()
                    .mb_3()
                    .child(
                        div()
                            .text_xs()
                            .text_color(tokens.muted)
                            .child("Provider ID"),
                    )
                    .child(provider_id.clone().unwrap_or_default())
                    .into_any_element()
            })
            .child(input_row("显示名称", &self.provider_label, tokens))
            .child(input_row("Endpoint", &self.provider_endpoint, tokens))
            .child(input_row("Model", &self.provider_model, tokens))
            .child(
                div().flex().flex_wrap().gap_2().mb_3().children(
                    [
                        (AiProviderKind::OpenAiCompatible, "OpenAI Compatible"),
                        (AiProviderKind::Anthropic, "Anthropic"),
                        (AiProviderKind::Gemini, "Gemini"),
                    ]
                    .into_iter()
                    .map(|(kind, label)| {
                        crate::buttons::button(SharedString::from(format!(
                            "settings-provider-kind-{kind:?}"
                        )))
                        .label(label)
                        .small()
                        .selected(self.model.provider_kind == kind)
                        .on_click(
                            cx.listener(move |this, _, _, cx| this.select_provider_kind(kind, cx)),
                        )
                    }),
                ),
            )
            .child(toggle_row(
                "启用 Provider",
                self.toggle_button(
                    "settings-provider-enabled",
                    self.model.provider_enabled,
                    SettingsToggle::ProviderEnabled,
                    cx,
                ),
                tokens,
            ))
            .child(toggle_row(
                "设为默认 Provider",
                crate::buttons::button("settings-provider-default")
                    .label(if self.model.provider_default {
                        "已设为默认"
                    } else {
                        "设为默认"
                    })
                    .small()
                    .selected(self.model.provider_default)
                    .on_click(cx.listener(|this, _, _, cx| this.toggle_provider_default(cx))),
                tokens,
            ))
            .child(input_row(
                if has_key {
                    "API Key（已保存；输入新值覆盖）"
                } else {
                    "API Key（只写）"
                },
                &self.provider_api_key,
                tokens,
            ))
            .when(!adding, |editor| {
                editor.child(
                    div()
                        .flex()
                        .flex_wrap()
                        .gap_2()
                        .child(
                            crate::buttons::button("settings-provider-test")
                                .label(if testing {
                                    "取消测试"
                                } else {
                                    "测试已保存 Provider"
                                })
                                .small()
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    if testing {
                                        this.cancel_provider_test(cx);
                                    } else {
                                        this.request_test_provider(cx);
                                    }
                                })),
                        )
                        .child(
                            crate::buttons::button("settings-provider-clear-key")
                                .label("清除 API Key")
                                .small()
                                .danger()
                                .disabled(!has_key)
                                .on_click(
                                    cx.listener(|this, _, _, cx| this.request_clear_api_key(cx)),
                                ),
                        )
                        .child(
                            crate::buttons::button("settings-provider-remove")
                                .label("删除 Provider")
                                .small()
                                .danger()
                                .on_click(
                                    cx.listener(|this, _, _, cx| this.request_remove_provider(cx)),
                                ),
                        ),
                )
            })
            .when_some(probe, |editor, report| {
                let (status, detail, color) = match report.result {
                    ProviderProbeResult::Success { model_count } => {
                        ("成功", format!("发现 {model_count} 个模型"), tokens.success)
                    }
                    ProviderProbeResult::Failure { category, detail } => {
                        ("失败", format!("{category}: {detail}"), tokens.danger)
                    }
                };
                editor.child(
                    div()
                        .mt_3()
                        .p_3()
                        .rounded_md()
                        .border_1()
                        .border_color(color)
                        .text_sm()
                        .child(format!(
                            "Provider {} · {} · {} ms · {}",
                            report.provider_id, status, report.elapsed_ms, detail
                        )),
                )
            })
            .into_any_element()
    }

    fn toggle_button(
        &self,
        id: &'static str,
        enabled: bool,
        setting: SettingsToggle,
        cx: &mut Context<Self>,
    ) -> Button {
        crate::buttons::button(id)
            .label(if enabled { "开启" } else { "关闭" })
            .small()
            .selected(enabled)
            .on_click(cx.listener(move |this, _, _, cx| this.toggle(setting, cx)))
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use lovelyres_core::{
        PortableStore,
        operations::{JournalPhase, PortableOperationJournal},
    };
    use uuid::Uuid;

    use super::*;
    use crate::interaction::{DialogAction, DialogHost};

    fn services() -> (PathBuf, Arc<BackendServices>) {
        let root =
            std::env::temp_dir().join(format!("lovelyres-settings-panel-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let store = PortableStore::prepare(root.clone()).unwrap();
        (root, Arc::new(BackendServices::new(store).unwrap()))
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

    fn seed_providers(services: &BackendServices) {
        services
            .settings()
            .update(|settings| {
                settings.ai.providers = vec![provider("one"), provider("two")];
                settings.ai.default_provider_id = Some("one".to_owned());
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn bounded_numbers_ids_and_urls_are_rejected_before_persistence() {
        assert!(parse_u32("sidebar width", "not-a-number").is_err());
        assert!(parse_u16("SSH port", "65536").is_err());
        assert!(parse_u8("SSH retries", "256").is_err());
        assert!(seconds_or_minutes_to_ms("timeout", u32::MAX, 60_000).is_err());

        let mut settings = AppSettings::default();
        settings.ui.sidebar_width = 199;
        assert!(settings.validate().is_err());
        settings.ui.sidebar_width = 280;
        settings.ai.providers = vec![AiProviderSettings {
            id: "../hostile".to_owned(),
            endpoint: "file:///etc/passwd".to_owned(),
            ..provider("valid")
        }];
        assert!(settings.validate().is_err());
    }

    #[test]
    fn cancelled_or_wrong_dialog_confirmation_has_zero_side_effects() {
        let (root, services) = services();
        seed_providers(&services);
        let repository = services.settings();
        let mut model = SettingsPanelModel::default();
        model.activate(repository.load().unwrap());

        let proposal = model
            .propose_danger(SettingsDangerPlan::RemoveProvider(
                repository.plan_remove_ai_provider("one").unwrap(),
            ))
            .unwrap();
        let mut dialogs = DialogHost::default();
        let dialog_id = dialogs.show_dangerous(proposal.plan.definition()).unwrap();
        model.arm_danger(proposal, dialog_id);
        let cancelled = dialogs
            .dispatch(DialogAction::Cancel { dialog_id })
            .unwrap();
        assert_eq!(
            model.resolve_danger(&cancelled),
            SettingsDangerResolution::Cancelled
        );
        assert_eq!(repository.load().unwrap().ai.providers.len(), 2);
        assert!(services.operation_journal().entries().unwrap().is_empty());

        let proposal = model
            .propose_danger(SettingsDangerPlan::RemoveProvider(
                repository.plan_remove_ai_provider("one").unwrap(),
            ))
            .unwrap();
        let other = repository.plan_remove_ai_provider("two").unwrap();
        let mut dialogs = DialogHost::default();
        let dialog_id = dialogs.show_dangerous(proposal.plan.definition()).unwrap();
        model.arm_danger(proposal, dialog_id);
        let wrong = DialogOutcome::DangerousApproved {
            dialog_id,
            operation_id: other.definition().id.clone(),
        };
        assert_eq!(
            model.resolve_danger(&wrong),
            SettingsDangerResolution::Ignored
        );
        assert_eq!(repository.load().unwrap().ai.providers.len(), 2);
        assert!(services.operation_journal().entries().unwrap().is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn detached_danger_finishes_journal_and_verify_while_late_ui_is_discarded() {
        let (root, services) = services();
        seed_providers(&services);
        let repository = services.settings();
        let mut model = SettingsPanelModel::default();
        model.activate(repository.load().unwrap());
        let proposal = model
            .propose_danger(SettingsDangerPlan::RemoveProvider(
                repository.plan_remove_ai_provider("two").unwrap(),
            ))
            .unwrap();
        let mut dialogs = DialogHost::default();
        let dialog_id = dialogs.show_dangerous(proposal.plan.definition()).unwrap();
        let operation_id = proposal.plan.definition().id.clone();
        model.arm_danger(proposal, dialog_id);
        let approved = dialogs
            .dispatch(DialogAction::ConfirmDangerous {
                dialog_id,
                operation_id,
            })
            .unwrap();
        let SettingsDangerResolution::Authorized {
            plan,
            confirmation,
            presentation,
        } = model.resolve_danger(&approved)
        else {
            panic!("exact confirmation must authorize the bound settings operation");
        };
        let kind = plan.kind();
        let SettingsDangerPlan::RemoveProvider(plan) = *plan else {
            panic!("the planned operation is provider removal");
        };
        let outcome = repository
            .execute_remove_ai_provider(plan, confirmation, services.operation_journal())
            .await
            .unwrap();
        assert!(outcome.verification.passed);

        model.deactivate();
        assert!(!model.apply_danger_success(&presentation, &kind));
        assert_eq!(model.draft.ai.providers.len(), 2);
        assert_eq!(repository.load().unwrap().ai.providers.len(), 1);
        let entries = services.operation_journal().entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].phase, JournalPhase::Executed);
        assert_eq!(entries[1].phase, JournalPhase::VerificationPassed);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn provider_probe_lifecycle_and_error_projection_never_render_remote_secret() {
        let mut model = SettingsPanelModel::default();
        model.activate(AppSettings::default());
        let lease = model.begin_provider_test().unwrap();
        assert!(model.accepts_provider_test(&lease));
        model.cancel_provider_test();
        assert!(!model.accepts_provider_test(&lease));
        let lease = model.begin_provider_test().unwrap();
        model.deactivate();
        model.activate(AppSettings::default());
        assert!(!model.accepts_provider_test(&lease));

        let hostile = "</div><script>steal('Bearer-secret')</script>";
        let report = ProviderProbeReport {
            provider_id: "saved-provider".to_owned(),
            elapsed_ms: 1,
            result: safe_provider_probe_failure(&CoreError::Validation {
                subject: "AI response",
                message: hostile.to_owned(),
            }),
        };
        let rendered_projection = format!("{report:?}");
        assert!(!rendered_projection.contains(hostile));
        assert!(!rendered_projection.contains("Bearer-secret"));
        assert!(rendered_projection.contains("request"));
    }

    #[test]
    fn write_only_secret_request_has_no_debug_or_serializable_plaintext_shape() {
        let hostile = "</input><img src=x onerror=steal()>Bearer-secret";
        let request = SettingsSaveRequest {
            patch: SettingsPatch {
                draft: AppSettings::default(),
                provider: None,
                provider_was_existing: false,
            },
            api_key: Some(("saved-provider".to_owned(), SecretValue::new(hostile))),
        };
        let (_, secret) = request.api_key.as_ref().unwrap();
        assert_eq!(format!("{secret:?}"), "SecretValue([REDACTED])");
        assert!(!format!("{:?}", request.patch.draft).contains(hostile));
    }

    #[test]
    fn operation_journal_type_is_portable_and_not_a_ui_event_bus() {
        let root = std::env::temp_dir().join(format!(
            "lovelyres-settings-journal-type-{}",
            Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let store = PortableStore::prepare(root.clone()).unwrap();
        let journal = PortableOperationJournal::new(store);
        assert!(journal.entries().unwrap().is_empty());
        fs::remove_dir_all(root).unwrap();
    }
}
