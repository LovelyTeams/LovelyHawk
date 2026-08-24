use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

use gpui::{
    AnyWindowHandle, AppContext, Context, Entity, EventEmitter, PathPromptOptions, Render,
    SharedString, Window, div, prelude::*,
};
use gpui_component::{
    Disableable, Selectable, Sizable,
    button::ButtonVariants,
    input::{Input, InputState},
};
use lovelyres_core::connections::{
    ConnectionConfig, ConnectionDeleteOutcome, ConnectionDeletePlan, ConnectionImportSummary,
    ConnectionProbePlan, ConnectionSecretChanges, ConnectionView, JumpHostConfig, SecretChange,
    SshAuthMethod,
};
use lovelyres_core::crypto::SecretValue;
use lovelyres_core::operations::DangerousConfirmation;
use lovelyres_core::ssh::{
    BoundSshSession, HostKeyConfirmations, SshConnectAuthorization, SshConnectionProbeSuccess,
    SshConnectionStatus,
};
use lovelyres_core::target::{TargetGuard, TargetIdentity};
use lovelyres_core::{
    BackendServices, CoreError, CoreResult, SshHostRole, SshKeyboardInteractiveChallenge,
};
use uuid::Uuid;

use crate::{
    app::{ActiveSshTarget, SharedAppState},
    interaction::NotificationSeverity,
    runtime::TokioBridge,
    theme::ThemeTokens,
};

#[derive(Clone, Debug, Eq, PartialEq)]
struct ConnectionDraft {
    base: ConnectionConfig,
    name: String,
    host: String,
    port: String,
    username: String,
    auth_method: SshAuthMethod,
    jump_enabled: bool,
    jump_auth_method: SshAuthMethod,
}

impl ConnectionDraft {
    fn new() -> Self {
        let id = Uuid::new_v4().to_string();
        Self {
            base: ConnectionConfig {
                id,
                name: String::new(),
                host: String::new(),
                port: 22,
                username: String::new(),
                auth_method: SshAuthMethod::Password,
                private_key_path: None,
                certificate_path: None,
                agent_identity_fingerprint: None,
                jump_host: None,
                tags: BTreeSet::new(),
                notes: None,
                environment: None,
                role: None,
                group: None,
                host_key_fingerprint: None,
            },
            name: String::new(),
            host: String::new(),
            port: "22".to_owned(),
            username: String::new(),
            auth_method: SshAuthMethod::Password,
            jump_enabled: false,
            jump_auth_method: SshAuthMethod::Password,
        }
    }

    fn from_view(view: &ConnectionView) -> Self {
        Self {
            base: view.config.clone(),
            name: view.config.name.clone(),
            host: view.config.host.clone(),
            port: view.config.port.to_string(),
            username: view.config.username.clone(),
            auth_method: view.config.auth_method,
            jump_enabled: view.config.jump_host.is_some(),
            jump_auth_method: view
                .config
                .jump_host
                .as_ref()
                .map_or(SshAuthMethod::Password, |jump| jump.auth_method),
        }
    }

    fn build(mut self) -> Result<ConnectionConfig, String> {
        let host = self.host.trim().to_owned();
        let port = self
            .port
            .trim()
            .parse::<u16>()
            .map_err(|_| "SSH 端口必须是 1–65535 的整数".to_owned())?;
        let endpoint_changed = self.base.host != host || self.base.port != port;
        self.base.name = self.name.trim().to_owned();
        self.base.host = host;
        self.base.port = port;
        self.base.username = self.username.trim().to_owned();
        self.base.auth_method = self.auth_method;
        if endpoint_changed {
            self.base.host_key_fingerprint = None;
        }
        self.base.validate().map_err(|error| error.to_string())?;
        Ok(self.base)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SecretField {
    Password,
    KeyPassphrase,
    JumpHostPassword,
    JumpHostKeyPassphrase,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CredentialPathField {
    PrivateKey,
    Certificate,
    JumpPrivateKey,
    JumpCertificate,
}

impl CredentialPathField {
    fn label(self) -> &'static str {
        match self {
            Self::PrivateKey => "SSH 私钥",
            Self::Certificate => "OpenSSH 用户证书",
            Self::JumpPrivateKey => "堡垒机 SSH 私钥",
            Self::JumpCertificate => "堡垒机 OpenSSH 用户证书",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DeleteConfirmation {
    plan: ConnectionDeletePlan,
}

#[derive(Clone, Debug)]
enum ConnectIntent {
    ActivateSaved { connection_id: String },
    Probe { plan: Box<ConnectionProbePlan> },
}

impl ConnectIntent {
    fn connection_id(&self) -> &str {
        match self {
            Self::ActivateSaved { connection_id } => connection_id,
            Self::Probe { plan } => plan.connection_id(),
        }
    }

    fn is_probe(&self) -> bool {
        matches!(self, Self::Probe { .. })
    }
}

#[derive(Debug)]
enum ConnectResult {
    Activated(SshConnectionStatus),
    Probed(Box<SshConnectionProbeSuccess>),
}

#[derive(Clone, Debug)]
struct ConnectAttempt {
    generation: u64,
    intent: ConnectIntent,
    authorization: SshConnectAuthorization,
}

impl ConnectAttempt {
    fn connection_id(&self) -> &str {
        self.intent.connection_id()
    }

    fn is_probe(&self) -> bool {
        self.intent.is_probe()
    }
}

#[derive(Clone, Debug)]
struct BindAttempt {
    connect: ConnectAttempt,
    session_id: String,
    guard: TargetGuard,
    label: SharedString,
}

#[derive(Clone, Debug)]
struct HostKeyConfirmation {
    attempt: ConnectAttempt,
    role: SshHostRole,
    host: String,
    port: u16,
    username: String,
    fingerprint: String,
}

struct KeyboardInteractiveConfirmation {
    attempt: ConnectAttempt,
    challenge: SshKeyboardInteractiveChallenge,
    inputs: Vec<Entity<InputState>>,
}

struct ConnectionEditor {
    draft: ConnectionDraft,
    name: Entity<InputState>,
    host: Entity<InputState>,
    port: Entity<InputState>,
    username: Entity<InputState>,
    private_key_path: Entity<InputState>,
    certificate_path: Entity<InputState>,
    agent_identity_fingerprint: Entity<InputState>,
    environment: Entity<InputState>,
    role: Entity<InputState>,
    group: Entity<InputState>,
    tags: Entity<InputState>,
    notes: Entity<InputState>,
    jump_host: Entity<InputState>,
    jump_port: Entity<InputState>,
    jump_username: Entity<InputState>,
    jump_private_key_path: Entity<InputState>,
    jump_certificate_path: Entity<InputState>,
    jump_agent_identity_fingerprint: Entity<InputState>,
    password: Entity<InputState>,
    key_passphrase: Entity<InputState>,
    jump_host_password: Entity<InputState>,
    jump_host_key_passphrase: Entity<InputState>,
    stored_password: bool,
    stored_key_passphrase: bool,
    stored_jump_host_password: bool,
    stored_jump_host_key_passphrase: bool,
    remove_password: bool,
    remove_key_passphrase: bool,
    remove_jump_host_password: bool,
    remove_jump_host_key_passphrase: bool,
}

impl ConnectionEditor {
    fn new(
        view: Option<&ConnectionView>,
        window: &mut Window,
        cx: &mut Context<ConnectionManager>,
    ) -> Self {
        let draft = view.map_or_else(ConnectionDraft::new, ConnectionDraft::from_view);
        let name = text_input("连接名称", &draft.name, false, window, cx);
        let host = text_input("主机名或 IP", &draft.host, false, window, cx);
        let port = text_input("SSH 端口", &draft.port, false, window, cx);
        let username = text_input("Linux 用户名", &draft.username, false, window, cx);
        let private_key_path = text_input(
            "本地私钥绝对路径",
            &path_text(draft.base.private_key_path.as_ref()),
            false,
            window,
            cx,
        );
        let certificate_path = text_input(
            "OpenSSH 用户证书绝对路径",
            &path_text(draft.base.certificate_path.as_ref()),
            false,
            window,
            cx,
        );
        let agent_identity_fingerprint = text_input(
            "SHA256:…（可选）",
            draft
                .base
                .agent_identity_fingerprint
                .as_deref()
                .unwrap_or_default(),
            false,
            window,
            cx,
        );
        let environment = text_input(
            "production / staging / ctf",
            draft.base.environment.as_deref().unwrap_or_default(),
            false,
            window,
            cx,
        );
        let role = text_input(
            "web / db / k8s",
            draft.base.role.as_deref().unwrap_or_default(),
            false,
            window,
            cx,
        );
        let group = text_input(
            "业务或赛题分组",
            draft.base.group.as_deref().unwrap_or_default(),
            false,
            window,
            cx,
        );
        let tags = text_input(
            "linux, internet, critical",
            &draft
                .base
                .tags
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", "),
            false,
            window,
            cx,
        );
        let notes = text_input(
            "连接备注",
            draft.base.notes.as_deref().unwrap_or_default(),
            false,
            window,
            cx,
        );
        let jump = draft.base.jump_host.as_ref();
        let jump_host = text_input(
            "堡垒机主机名或 IP",
            jump.map_or("", |jump| jump.host.as_str()),
            false,
            window,
            cx,
        );
        let jump_port = text_input(
            "堡垒机 SSH 端口",
            &jump.map_or_else(|| "22".to_owned(), |jump| jump.port.to_string()),
            false,
            window,
            cx,
        );
        let jump_username = text_input(
            "堡垒机 Linux 用户名",
            jump.map_or("root", |jump| jump.username.as_str()),
            false,
            window,
            cx,
        );
        let jump_private_key_path = text_input(
            "堡垒机本地私钥绝对路径",
            &path_text(jump.and_then(|jump| jump.private_key_path.as_ref())),
            false,
            window,
            cx,
        );
        let jump_certificate_path = text_input(
            "堡垒机 OpenSSH 用户证书绝对路径",
            &path_text(jump.and_then(|jump| jump.certificate_path.as_ref())),
            false,
            window,
            cx,
        );
        let jump_agent_identity_fingerprint = text_input(
            "堡垒机 SHA256:…（可选）",
            jump.and_then(|jump| jump.agent_identity_fingerprint.as_deref())
                .unwrap_or_default(),
            false,
            window,
            cx,
        );
        let password = text_input("留空保持现有密码", "", true, window, cx);
        let key_passphrase = text_input("留空保持现有密钥口令", "", true, window, cx);
        let jump_host_password = text_input("留空保持现有跳板机密码", "", true, window, cx);
        let jump_host_key_passphrase =
            text_input("留空保持现有跳板机密钥口令", "", true, window, cx);
        Self {
            draft,
            name,
            host,
            port,
            username,
            private_key_path,
            certificate_path,
            agent_identity_fingerprint,
            environment,
            role,
            group,
            tags,
            notes,
            jump_host,
            jump_port,
            jump_username,
            jump_private_key_path,
            jump_certificate_path,
            jump_agent_identity_fingerprint,
            password,
            key_passphrase,
            jump_host_password,
            jump_host_key_passphrase,
            stored_password: view.is_some_and(|view| view.has_password),
            stored_key_passphrase: view.is_some_and(|view| view.has_key_passphrase),
            stored_jump_host_password: view.is_some_and(|view| view.jump_host_has_password),
            stored_jump_host_key_passphrase: view
                .is_some_and(|view| view.jump_host_has_key_passphrase),
            remove_password: false,
            remove_key_passphrase: false,
            remove_jump_host_password: false,
            remove_jump_host_key_passphrase: false,
        }
    }

    fn collect_config(&self, cx: &Context<ConnectionManager>) -> Result<ConnectionConfig, String> {
        let mut draft = self.draft.clone();
        draft.name = input_value(&self.name, cx);
        draft.host = input_value(&self.host, cx);
        draft.port = input_value(&self.port, cx);
        draft.username = input_value(&self.username, cx);
        let jump_enabled = draft.jump_enabled;
        let jump_auth_method = draft.jump_auth_method;
        let previous_jump = draft.base.jump_host.clone();
        let mut config = draft.build()?;
        config.private_key_path = if uses_private_key(config.auth_method) {
            Some(required_absolute_path(
                &input_value(&self.private_key_path, cx),
                "SSH 私钥",
            )?)
        } else {
            None
        };
        config.certificate_path = if config.auth_method == SshAuthMethod::Certificate {
            Some(required_absolute_path(
                &input_value(&self.certificate_path, cx),
                "OpenSSH 用户证书",
            )?)
        } else {
            None
        };
        config.agent_identity_fingerprint = if config.auth_method == SshAuthMethod::Agent {
            optional_fingerprint(
                &input_value(&self.agent_identity_fingerprint, cx),
                "SSH Agent 身份指纹",
            )?
        } else {
            None
        };
        config.environment = optional_text(&input_value(&self.environment, cx), "环境", 32)?;
        config.role = optional_text(&input_value(&self.role, cx), "角色", 64)?;
        config.group = optional_text(&input_value(&self.group, cx), "分组", 64)?;
        config.notes = optional_text(&input_value(&self.notes, cx), "备注", 500)?;
        config.tags = parse_tags(&input_value(&self.tags, cx))?;
        config.jump_host = if jump_enabled {
            let host = input_value(&self.jump_host, cx).trim().to_owned();
            let port = input_value(&self.jump_port, cx)
                .trim()
                .parse::<u16>()
                .map_err(|_| "堡垒机端口必须是 1–65535 的整数".to_owned())?;
            let username = input_value(&self.jump_username, cx).trim().to_owned();
            let previous = previous_jump.as_ref();
            let host_key_fingerprint = preserved_jump_host_key_fingerprint(previous, &host, port);
            Some(JumpHostConfig {
                host,
                port,
                username,
                auth_method: jump_auth_method,
                private_key_path: if uses_private_key(jump_auth_method) {
                    Some(required_absolute_path(
                        &input_value(&self.jump_private_key_path, cx),
                        "堡垒机 SSH 私钥",
                    )?)
                } else {
                    None
                },
                certificate_path: if jump_auth_method == SshAuthMethod::Certificate {
                    Some(required_absolute_path(
                        &input_value(&self.jump_certificate_path, cx),
                        "堡垒机 OpenSSH 用户证书",
                    )?)
                } else {
                    None
                },
                agent_identity_fingerprint: if jump_auth_method == SshAuthMethod::Agent {
                    optional_fingerprint(
                        &input_value(&self.jump_agent_identity_fingerprint, cx),
                        "堡垒机 Agent 身份指纹",
                    )?
                } else {
                    None
                },
                host_key_fingerprint,
            })
        } else {
            None
        };
        config.validate().map_err(|error| error.to_string())?;
        Ok(config)
    }

    fn take_secret_changes(
        &self,
        window: &mut Window,
        cx: &mut Context<ConnectionManager>,
    ) -> ConnectionSecretChanges {
        let password = input_value(&self.password, cx);
        let key_passphrase = input_value(&self.key_passphrase, cx);
        let jump_host_password = input_value(&self.jump_host_password, cx);
        let jump_host_key_passphrase = input_value(&self.jump_host_key_passphrase, cx);
        let changes = ConnectionSecretChanges {
            password: secret_change_for_usage(
                password,
                self.remove_password,
                self.draft.auth_method == SshAuthMethod::Password,
            ),
            key_passphrase: secret_change_for_usage(
                key_passphrase,
                self.remove_key_passphrase,
                uses_private_key(self.draft.auth_method),
            ),
            jump_host_password: secret_change_for_usage(
                jump_host_password,
                self.remove_jump_host_password,
                self.draft.jump_enabled && self.draft.jump_auth_method == SshAuthMethod::Password,
            ),
            jump_host_key_passphrase: secret_change_for_usage(
                jump_host_key_passphrase,
                self.remove_jump_host_key_passphrase,
                self.draft.jump_enabled && uses_private_key(self.draft.jump_auth_method),
            ),
        };
        self.clear_secrets(window, cx);
        changes
    }

    fn validate_required_secrets(&self, cx: &Context<ConnectionManager>) -> Result<(), String> {
        if self.draft.auth_method == SshAuthMethod::Password
            && !secret_will_exist(
                &input_value(&self.password, cx),
                self.stored_password,
                self.remove_password,
            )
        {
            return Err("密码认证必须输入或保留一个 SSH 密码".to_owned());
        }
        if self.draft.jump_enabled
            && self.draft.jump_auth_method == SshAuthMethod::Password
            && !secret_will_exist(
                &input_value(&self.jump_host_password, cx),
                self.stored_jump_host_password,
                self.remove_jump_host_password,
            )
        {
            return Err("堡垒机密码认证必须输入或保留一个密码".to_owned());
        }
        Ok(())
    }

    fn has_new_secret_input(&self, cx: &Context<ConnectionManager>) -> bool {
        [
            &self.password,
            &self.key_passphrase,
            &self.jump_host_password,
            &self.jump_host_key_passphrase,
        ]
        .into_iter()
        .any(|input| !input_value(input, cx).is_empty())
    }

    fn clear_secrets(&self, window: &mut Window, cx: &mut Context<ConnectionManager>) {
        for input in [
            &self.password,
            &self.key_passphrase,
            &self.jump_host_password,
            &self.jump_host_key_passphrase,
        ] {
            input.update(cx, |state, cx| state.set_value("", window, cx));
        }
    }

    fn toggle_remove(&mut self, field: SecretField) {
        let remove = match field {
            SecretField::Password => &mut self.remove_password,
            SecretField::KeyPassphrase => &mut self.remove_key_passphrase,
            SecretField::JumpHostPassword => &mut self.remove_jump_host_password,
            SecretField::JumpHostKeyPassphrase => &mut self.remove_jump_host_key_passphrase,
        };
        *remove = !*remove;
    }
}

pub struct ConnectionManager {
    services: Arc<BackendServices>,
    tokio: Arc<TokioBridge>,
    shared: Entity<SharedAppState>,
    window_handle: AnyWindowHandle,
    connections: Vec<ConnectionView>,
    selected: Option<String>,
    editor: Option<ConnectionEditor>,
    delete_confirmation: Option<DeleteConfirmation>,
    deleting: Option<String>,
    connect_generation: u64,
    connecting: Option<ConnectAttempt>,
    tested_probe: Option<ConnectionProbePlan>,
    binding: Option<BindAttempt>,
    host_key_confirmation: Option<HostKeyConfirmation>,
    keyboard_interactive_confirmation: Option<KeyboardInteractiveConfirmation>,
    transfer_generation: u64,
    transfer_busy: bool,
    credential_picker_generation: u64,
    credential_picker_busy: bool,
    error: Option<SharedString>,
    status: Option<SharedString>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionManagerEvent {
    TargetReady,
}

impl EventEmitter<ConnectionManagerEvent> for ConnectionManager {}

impl ConnectionManager {
    pub fn new(
        services: Arc<BackendServices>,
        tokio: Arc<TokioBridge>,
        shared: Entity<SharedAppState>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        cx.observe(&shared, |_, _, cx| cx.notify()).detach();
        let (connections, error) = match services.connections().list() {
            Ok(connections) => (connections, None),
            Err(error) => (Vec::new(), Some(error.to_string().into())),
        };
        Self {
            services,
            tokio,
            shared,
            window_handle: window.window_handle(),
            connections,
            selected: None,
            editor: None,
            delete_confirmation: None,
            deleting: None,
            connect_generation: 0,
            connecting: None,
            tested_probe: None,
            binding: None,
            host_key_confirmation: None,
            keyboard_interactive_confirmation: None,
            transfer_generation: 0,
            transfer_busy: false,
            credential_picker_generation: 0,
            credential_picker_busy: false,
            error,
            status: None,
        }
    }

    fn refresh(&mut self, cx: &mut Context<Self>) {
        match self.services.connections().list() {
            Ok(connections) => {
                self.connections = connections;
                if self
                    .selected
                    .as_ref()
                    .is_some_and(|id| !self.connections.iter().any(|view| view.config.id == *id))
                {
                    self.selected = None;
                }
                self.error = None;
                self.status = Some("连接列表已刷新".into());
            }
            Err(error) => self.error = Some(error.to_string().into()),
        }
        cx.notify();
    }

    fn choose_export_path(&mut self, cx: &mut Context<Self>) {
        let Some(generation) = self.begin_transfer("等待选择连接导出路径…", cx) else {
            return;
        };
        let initial = self
            .services
            .store()
            .root()
            .parent()
            .map_or_else(|| self.services.store().root().to_path_buf(), PathBuf::from);
        let suggested = format!(
            "LovelyRes-connections-{}.json",
            chrono::Utc::now().format("%Y%m%d-%H%M%S")
        );
        let receiver = cx.prompt_for_new_path(&initial, Some(&suggested));
        cx.spawn(async move |manager, cx| {
            let selected = match receiver.await {
                Ok(Ok(Some(path))) => path,
                Ok(Ok(None)) => {
                    let _ = cx.update(|cx| {
                        if let Some(manager) = manager.upgrade() {
                            manager.update(cx, |manager, cx| {
                                manager.finish_transfer_cancel(generation, "已取消连接导出", cx)
                            });
                        }
                    });
                    return;
                }
                Ok(Err(error)) => {
                    let message = error.to_string();
                    let _ = cx.update(|cx| {
                        if let Some(manager) = manager.upgrade() {
                            manager.update(cx, |manager, cx| {
                                manager.finish_transfer_error(
                                    generation,
                                    format!("导出路径选择失败：{message}"),
                                    cx,
                                )
                            });
                        }
                    });
                    return;
                }
                Err(error) => {
                    let message = error.to_string();
                    let _ = cx.update(|cx| {
                        if let Some(manager) = manager.upgrade() {
                            manager.update(cx, |manager, cx| {
                                manager.finish_transfer_error(
                                    generation,
                                    format!("导出路径选择任务失败：{message}"),
                                    cx,
                                )
                            });
                        }
                    });
                    return;
                }
            };
            let _ = cx.update(|cx| {
                if let Some(manager) = manager.upgrade() {
                    manager.update(cx, |manager, cx| {
                        manager.start_export(generation, selected, cx)
                    });
                }
            });
        })
        .detach();
    }

    fn start_export(&mut self, generation: u64, destination: PathBuf, cx: &mut Context<Self>) {
        if !self.owns_transfer(generation) {
            return;
        }
        self.status = Some(format!("正在导出到 {}…", destination.display()).into());
        let repository = self.services.connections().clone();
        let task = self.tokio.spawn(async move {
            repository
                .write_new_export(&destination)
                .map(|count| (destination, count))
        });
        cx.spawn(async move |manager, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(manager) = manager.upgrade() {
                    manager.update(cx, |manager, cx| {
                        manager.finish_export(generation, result, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_export(
        &mut self,
        generation: u64,
        result: Result<CoreResult<(PathBuf, usize)>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if !self.owns_transfer(generation) {
            return;
        }
        self.transfer_busy = false;
        match result {
            Ok(Ok((path, count))) => {
                self.error = None;
                self.status = Some(format!("已导出 {count} 个连接：{}", path.display()).into());
            }
            Ok(Err(error)) => {
                self.error = Some(format!("连接导出失败：{error}").into());
                self.status = None;
            }
            Err(error) => {
                self.error = Some(format!("连接导出任务失败：{error}").into());
                self.status = None;
            }
        }
        cx.notify();
    }

    fn choose_import_path(&mut self, cx: &mut Context<Self>) {
        let Some(generation) = self.begin_transfer("等待选择连接导入文件…", cx) else {
            return;
        };
        let receiver = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some("选择 LovelyRes 连接 JSON".into()),
        });
        cx.spawn(async move |manager, cx| {
            let selected = match receiver.await {
                Ok(Ok(Some(mut paths))) if paths.len() == 1 => paths.remove(0),
                Ok(Ok(None)) => {
                    let _ = cx.update(|cx| {
                        if let Some(manager) = manager.upgrade() {
                            manager.update(cx, |manager, cx| {
                                manager.finish_transfer_cancel(generation, "已取消连接导入", cx)
                            });
                        }
                    });
                    return;
                }
                Ok(Ok(Some(_))) => {
                    let _ = cx.update(|cx| {
                        if let Some(manager) = manager.upgrade() {
                            manager.update(cx, |manager, cx| {
                                manager.finish_transfer_error(
                                    generation,
                                    "一次只能导入一个连接 JSON 文件".to_owned(),
                                    cx,
                                )
                            });
                        }
                    });
                    return;
                }
                Ok(Err(error)) => {
                    let message = error.to_string();
                    let _ = cx.update(|cx| {
                        if let Some(manager) = manager.upgrade() {
                            manager.update(cx, |manager, cx| {
                                manager.finish_transfer_error(
                                    generation,
                                    format!("导入文件选择失败：{message}"),
                                    cx,
                                )
                            });
                        }
                    });
                    return;
                }
                Err(error) => {
                    let message = error.to_string();
                    let _ = cx.update(|cx| {
                        if let Some(manager) = manager.upgrade() {
                            manager.update(cx, |manager, cx| {
                                manager.finish_transfer_error(
                                    generation,
                                    format!("导入文件选择任务失败：{message}"),
                                    cx,
                                )
                            });
                        }
                    });
                    return;
                }
            };
            let _ = cx.update(|cx| {
                if let Some(manager) = manager.upgrade() {
                    manager.update(cx, |manager, cx| {
                        manager.start_import(generation, selected, cx)
                    });
                }
            });
        })
        .detach();
    }

    fn start_import(&mut self, generation: u64, source: PathBuf, cx: &mut Context<Self>) {
        if !self.owns_transfer(generation) {
            return;
        }
        self.status = Some(format!("正在导入 {}…", source.display()).into());
        let repository = self.services.connections().clone();
        let task = self.tokio.spawn(async move {
            repository
                .import_file(&source)
                .map(|summary| (source, summary))
        });
        cx.spawn(async move |manager, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(manager) = manager.upgrade() {
                    manager.update(cx, |manager, cx| {
                        manager.finish_import(generation, result, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_import(
        &mut self,
        generation: u64,
        result: Result<CoreResult<(PathBuf, ConnectionImportSummary)>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if !self.owns_transfer(generation) {
            return;
        }
        self.transfer_busy = false;
        match result {
            Ok(Ok((path, summary))) => match self.services.connections().list() {
                Ok(connections) => {
                    self.connections = connections;
                    self.error = None;
                    self.status = Some(
                        format!(
                            "导入完成：新增 {}，跳过已有 {}，跳过文件内重复 {}（{}）",
                            summary.imported,
                            summary.skipped_existing,
                            summary.skipped_duplicate,
                            path.display()
                        )
                        .into(),
                    );
                }
                Err(error) => {
                    self.error = Some(format!("连接已导入，但刷新列表失败：{error}").into());
                    self.status = None;
                }
            },
            Ok(Err(error)) => {
                self.error = Some(format!("连接导入失败，未写入任何记录：{error}").into());
                self.status = None;
            }
            Err(error) => {
                self.error = Some(format!("连接导入任务失败：{error}").into());
                self.status = None;
            }
        }
        cx.notify();
    }

    fn begin_transfer(&mut self, status: &'static str, cx: &mut Context<Self>) -> Option<u64> {
        if self.transfer_busy {
            return None;
        }
        let Some(generation) = self.transfer_generation.checked_add(1) else {
            self.error = Some("连接导入/导出 generation 已耗尽，请重启应用".into());
            cx.notify();
            return None;
        };
        self.transfer_generation = generation;
        self.transfer_busy = true;
        self.error = None;
        self.status = Some(status.into());
        cx.notify();
        Some(generation)
    }

    fn owns_transfer(&self, generation: u64) -> bool {
        self.transfer_busy && self.transfer_generation == generation
    }

    fn finish_transfer_cancel(
        &mut self,
        generation: u64,
        message: &'static str,
        cx: &mut Context<Self>,
    ) {
        if !self.owns_transfer(generation) {
            return;
        }
        self.transfer_busy = false;
        self.error = None;
        self.status = Some(message.into());
        cx.notify();
    }

    fn finish_transfer_error(&mut self, generation: u64, message: String, cx: &mut Context<Self>) {
        if !self.owns_transfer(generation) {
            return;
        }
        self.transfer_busy = false;
        self.error = Some(message.into());
        self.status = None;
        cx.notify();
    }

    fn choose_credential_path(&mut self, field: CredentialPathField, cx: &mut Context<Self>) {
        if self.editor.is_none() || self.credential_picker_busy {
            return;
        }
        let Some(generation) = self.credential_picker_generation.checked_add(1) else {
            self.error = Some("凭据文件选择 generation 已耗尽，请重启应用".into());
            cx.notify();
            return;
        };
        self.credential_picker_generation = generation;
        self.credential_picker_busy = true;
        self.error = None;
        self.status = Some(format!("等待选择{}…", field.label()).into());
        let receiver = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some(format!("选择{}", field.label()).into()),
        });
        let window_handle = self.window_handle;
        cx.spawn(async move |manager, cx| {
            let selected = match receiver.await {
                Ok(Ok(Some(mut paths))) if paths.len() == 1 => paths.remove(0),
                Ok(Ok(None)) => {
                    let _ = cx.update(|cx| {
                        if let Some(manager) = manager.upgrade() {
                            manager.update(cx, |manager, cx| {
                                manager.finish_credential_picker(
                                    generation,
                                    None,
                                    Some("已取消凭据文件选择".to_owned()),
                                    cx,
                                )
                            });
                        }
                    });
                    return;
                }
                Ok(Ok(Some(_))) => {
                    let _ = cx.update(|cx| {
                        if let Some(manager) = manager.upgrade() {
                            manager.update(cx, |manager, cx| {
                                manager.finish_credential_picker(
                                    generation,
                                    Some("一次只能选择一个凭据文件".to_owned()),
                                    None,
                                    cx,
                                )
                            });
                        }
                    });
                    return;
                }
                Ok(Err(error)) => {
                    let message = error.to_string();
                    let _ = cx.update(|cx| {
                        if let Some(manager) = manager.upgrade() {
                            manager.update(cx, |manager, cx| {
                                manager.finish_credential_picker(
                                    generation,
                                    Some(format!("凭据文件选择失败：{message}")),
                                    None,
                                    cx,
                                )
                            });
                        }
                    });
                    return;
                }
                Err(error) => {
                    let message = error.to_string();
                    let _ = cx.update(|cx| {
                        if let Some(manager) = manager.upgrade() {
                            manager.update(cx, |manager, cx| {
                                manager.finish_credential_picker(
                                    generation,
                                    Some(format!("凭据文件选择任务失败：{message}")),
                                    None,
                                    cx,
                                )
                            });
                        }
                    });
                    return;
                }
            };
            let _ = cx.update_window(window_handle, |_, window, cx| {
                if let Some(manager) = manager.upgrade() {
                    manager.update(cx, |manager, cx| {
                        manager.apply_credential_path(generation, field, selected, window, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn apply_credential_path(
        &mut self,
        generation: u64,
        field: CredentialPathField,
        path: PathBuf,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if !self.owns_credential_picker(generation) {
            return;
        }
        let Some(editor) = self.editor.as_ref() else {
            self.invalidate_credential_picker();
            return;
        };
        let input = match field {
            CredentialPathField::PrivateKey => &editor.private_key_path,
            CredentialPathField::Certificate => &editor.certificate_path,
            CredentialPathField::JumpPrivateKey => &editor.jump_private_key_path,
            CredentialPathField::JumpCertificate => &editor.jump_certificate_path,
        };
        input.update(cx, |input, cx| {
            input.set_value(path.to_string_lossy().into_owned(), window, cx)
        });
        self.credential_picker_busy = false;
        self.error = None;
        self.status = Some(format!("已选择{}：{}", field.label(), path.display()).into());
        cx.notify();
    }

    fn finish_credential_picker(
        &mut self,
        generation: u64,
        error: Option<String>,
        status: Option<String>,
        cx: &mut Context<Self>,
    ) {
        if !self.owns_credential_picker(generation) {
            return;
        }
        self.credential_picker_busy = false;
        self.error = error.map(Into::into);
        self.status = status.map(Into::into);
        cx.notify();
    }

    fn owns_credential_picker(&self, generation: u64) -> bool {
        self.credential_picker_busy && self.credential_picker_generation == generation
    }

    fn invalidate_credential_picker(&mut self) {
        self.credential_picker_generation = self.credential_picker_generation.saturating_add(1);
        self.credential_picker_busy = false;
    }

    fn select(&mut self, id: String, cx: &mut Context<Self>) {
        self.cancel_pending_connect("已切换连接，先前连接请求已取消", cx);
        self.selected = Some(id);
        self.delete_confirmation = None;
        self.status = None;
        cx.notify();
    }

    fn begin_connect(&mut self, cx: &mut Context<Self>) {
        let Some(connection_id) = self.selected.clone() else {
            self.error = Some("请先选择连接".into());
            cx.notify();
            return;
        };
        if self.deleting.as_deref() == Some(&connection_id) {
            self.error = Some("连接正在删除，不能启动新会话".into());
            cx.notify();
            return;
        }
        self.cancel_pending_connect("先前连接请求已取消", cx);
        let Some(generation) = self.advance_connect_generation() else {
            self.error = Some("连接请求 generation 已耗尽，请重启应用".into());
            cx.notify();
            return;
        };
        let attempt = ConnectAttempt {
            generation,
            intent: ConnectIntent::ActivateSaved { connection_id },
            authorization: SshConnectAuthorization::default(),
        };
        self.launch_connect(attempt, cx);
    }

    fn begin_probe(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(editor) = self.editor.as_ref() else {
            return;
        };
        let config = match editor.collect_config(cx) {
            Ok(config) => config,
            Err(error) => {
                self.error = Some(error.into());
                cx.notify();
                return;
            }
        };
        if let Err(error) = editor.validate_required_secrets(cx) {
            self.error = Some(error.into());
            cx.notify();
            return;
        }
        let changes = editor.take_secret_changes(window, cx);
        self.cancel_pending_connect("连接草稿已变化，先前请求已取消", cx);
        self.tested_probe = None;
        let plan = match self.services.ssh().prepare_probe(config, changes) {
            Ok(plan) => plan,
            Err(error) => {
                self.error = Some(error.to_string().into());
                self.status = Some("凭据输入已从编辑器清空，请修正后重新输入".into());
                cx.notify();
                return;
            }
        };
        let Some(generation) = self.advance_connect_generation() else {
            self.error = Some("连接请求 generation 已耗尽，请重启应用".into());
            cx.notify();
            return;
        };
        self.launch_connect(
            ConnectAttempt {
                generation,
                intent: ConnectIntent::Probe {
                    plan: Box::new(plan),
                },
                authorization: SshConnectAuthorization::default(),
            },
            cx,
        );
    }

    fn launch_connect(&mut self, attempt: ConnectAttempt, cx: &mut Context<Self>) {
        self.connecting = Some(attempt.clone());
        self.host_key_confirmation = None;
        self.keyboard_interactive_confirmation = None;
        self.error = None;
        self.status = Some(if attempt.is_probe() {
            "正在测试连接；成功后测试会话会立即关闭…".into()
        } else {
            "正在建立 SSH 连接…".into()
        });
        cx.notify();

        let ssh = self.services.ssh().clone();
        let cleanup_ssh = ssh.clone();
        let task_intent = attempt.intent.clone();
        let authorization = attempt.authorization.clone();
        let window_handle = self.window_handle;
        let task = self.tokio.spawn(async move {
            match task_intent {
                ConnectIntent::ActivateSaved { connection_id } => ssh
                    .connect_authorized(&connection_id, authorization)
                    .await
                    .map(ConnectResult::Activated),
                ConnectIntent::Probe { plan } => ssh
                    .probe_authorized(&plan, authorization)
                    .await
                    .map(|success| ConnectResult::Probed(Box::new(success))),
            }
        });
        cx.spawn(async move |manager, cx| {
            let mut result = Some(task.await);
            let handled = cx
                .update_window(window_handle, |_, window, cx| {
                    if let Some(manager) = manager.upgrade() {
                        manager.update(cx, |manager, cx| {
                            manager.finish_connect(
                                attempt,
                                result.take().expect("connect result is consumed once"),
                                window,
                                cx,
                            )
                        });
                        true
                    } else {
                        false
                    }
                })
                .unwrap_or(false);
            if !handled
                && let Some(Ok(Ok(ConnectResult::Activated(status)))) = result
                && let Err(error) = cleanup_ssh.disconnect(&status.session_id).await
            {
                tracing::error!(
                    %error,
                    session_id = %status.session_id,
                    "failed to close SSH session after connection manager release"
                );
            }
        })
        .detach();
    }

    fn finish_connect(
        &mut self,
        attempt: ConnectAttempt,
        result: Result<Result<ConnectResult, CoreError>, tokio::task::JoinError>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if attempt.generation != self.connect_generation
            || self
                .connecting
                .as_ref()
                .is_none_or(|current| current.generation != attempt.generation)
        {
            if let Ok(Ok(ConnectResult::Activated(status))) = result {
                self.disconnect_session(status.session_id);
            }
            return;
        }
        self.connecting = None;

        match result {
            Ok(Ok(ConnectResult::Activated(status))) => {
                self.activate_connected_target(attempt, status, cx)
            }
            Ok(Ok(ConnectResult::Probed(success))) => {
                let success = *success;
                if !attempt.is_probe() {
                    self.error = Some("连接任务返回了不匹配的测试结果".into());
                    self.status = None;
                } else {
                    self.tested_probe = Some(success.verified_plan);
                    self.error = None;
                    self.status = Some(
                        format!(
                            "测试成功：{}@{}:{}，主机指纹 {}；测试会话已关闭，配置尚未保存。",
                            success.result.username,
                            success.result.host,
                            success.result.port,
                            success.result.host_key_fingerprint
                        )
                        .into(),
                    );
                }
            }
            Ok(Err(CoreError::SshHostKeyConfirmationRequired {
                role,
                host,
                port,
                username,
                fingerprint,
            })) => {
                self.host_key_confirmation = Some(HostKeyConfirmation {
                    attempt,
                    role,
                    host,
                    port,
                    username,
                    fingerprint,
                });
                self.error = None;
                self.status = Some("必须核验并明确确认 SSH 主机密钥".into());
            }
            Ok(Err(CoreError::SshKeyboardInteractiveRequired { challenge })) => {
                let challenge = *challenge;
                let supplied = attempt
                    .authorization
                    .keyboard_interactive_response_count(challenge.role);
                if supplied != challenge.supplied_responses {
                    self.keyboard_interactive_confirmation = None;
                    self.error = Some("拒绝交互认证：服务器挑战与本次已提交响应序列不一致".into());
                    self.status = None;
                } else {
                    let inputs = challenge
                        .prompts
                        .iter()
                        .map(|_| text_input("输入服务器请求的响应", "", true, window, cx))
                        .collect();
                    self.keyboard_interactive_confirmation =
                        Some(KeyboardInteractiveConfirmation {
                            attempt,
                            challenge,
                            inputs,
                        });
                    self.error = None;
                    self.status = Some("SSH 服务器要求交互认证 / MFA".into());
                }
            }
            Ok(Err(CoreError::SshHostKeyChanged {
                role,
                host,
                port,
                expected,
                observed,
            })) => {
                self.host_key_confirmation = None;
                self.keyboard_interactive_confirmation = None;
                self.error = Some(
                    format!(
                        "拒绝连接：{} {host}:{port} 主机密钥已变化；记录值 {expected}，本次值 {observed}。此界面不允许覆盖。",
                        host_key_role_label(role)
                    )
                    .into(),
                );
                self.status = None;
            }
            Ok(Err(error)) => {
                self.host_key_confirmation = None;
                self.keyboard_interactive_confirmation = None;
                self.error = Some(error.to_string().into());
                self.status = None;
            }
            Err(error) => {
                self.host_key_confirmation = None;
                self.keyboard_interactive_confirmation = None;
                self.error = Some(format!("SSH 连接任务异常结束：{error}").into());
                self.status = None;
            }
        }
        cx.notify();
    }

    fn confirm_host_key(&mut self, cx: &mut Context<Self>) {
        let Some(mut confirmation) = self.host_key_confirmation.take() else {
            return;
        };
        if confirmation.attempt.generation != self.connect_generation {
            self.status = Some("主机密钥确认已过期".into());
            cx.notify();
            return;
        }
        apply_host_key_confirmation(
            confirmation.attempt.authorization.host_keys_mut(),
            confirmation.role,
            &confirmation.fingerprint,
        );
        self.launch_connect(confirmation.attempt, cx);
    }

    fn submit_keyboard_interactive(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(mut confirmation) = self.keyboard_interactive_confirmation.take() else {
            return;
        };
        if confirmation.attempt.generation != self.connect_generation {
            self.clear_keyboard_interactive_inputs(&confirmation.inputs, window, cx);
            self.status = Some("交互认证挑战已过期".into());
            cx.notify();
            return;
        }
        let responses = confirmation
            .inputs
            .iter()
            .map(|input| input_value(input, cx))
            .collect::<Vec<_>>();
        self.clear_keyboard_interactive_inputs(&confirmation.inputs, window, cx);
        if let Err(error) = apply_keyboard_interactive_responses(
            &mut confirmation.attempt.authorization,
            &confirmation.challenge,
            responses,
        ) {
            self.error = Some(error.to_string().into());
            self.status = None;
            cx.notify();
            return;
        }
        self.launch_connect(confirmation.attempt, cx);
    }

    fn cancel_keyboard_interactive(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(confirmation) = self.keyboard_interactive_confirmation.as_ref() {
            self.clear_keyboard_interactive_inputs(&confirmation.inputs, window, cx);
        }
        self.cancel_connect(cx);
    }

    fn cancel_connect(&mut self, cx: &mut Context<Self>) {
        self.cancel_pending_connect("连接请求已取消；任何迟到结果都会被丢弃", cx);
        cx.notify();
    }

    fn cancel_pending_connect(&mut self, message: &'static str, cx: &mut Context<Self>) {
        if self.connecting.is_none()
            && self.binding.is_none()
            && self.host_key_confirmation.is_none()
            && self.keyboard_interactive_confirmation.is_none()
        {
            return;
        }
        if self.advance_connect_generation().is_none() {
            self.error = Some("连接请求 generation 已耗尽，请重启应用".into());
        }
        self.connecting = None;
        self.host_key_confirmation = None;
        self.keyboard_interactive_confirmation = None;
        if let Some(binding) = self.binding.take() {
            if let Err(error) = self.services.target().clear_if_current(&binding.guard) {
                self.error = Some(error.to_string().into());
            }
            self.disconnect_session(binding.session_id);
            self.shared.update(cx, |state, cx| {
                state.active_ssh = None;
                state.target_label = "未连接目标".into();
                cx.notify();
            });
        }
        self.status = Some(message.into());
    }

    fn advance_connect_generation(&mut self) -> Option<u64> {
        let next = self.connect_generation.checked_add(1)?;
        self.connect_generation = next;
        Some(next)
    }

    fn activate_connected_target(
        &mut self,
        attempt: ConnectAttempt,
        status: SshConnectionStatus,
        cx: &mut Context<Self>,
    ) {
        if attempt.is_probe() {
            self.disconnect_session(status.session_id);
            self.error = Some("测试连接结果不能激活目标上下文".into());
            return;
        }
        let identity = match TargetIdentity::new(attempt.connection_id().to_owned()) {
            Ok(identity) => identity,
            Err(error) => {
                self.disconnect_session(status.session_id);
                self.error = Some(error.to_string().into());
                return;
            }
        };
        let guard = match self.services.activate_target(identity) {
            Ok(guard) => guard,
            Err(error) => {
                self.disconnect_session(status.session_id);
                self.error = Some(error.to_string().into());
                return;
            }
        };
        let previous_session = self
            .shared
            .read(cx)
            .active_ssh
            .as_ref()
            .map(|active| active.session.session_id().to_owned());
        self.shared.update(cx, |state, cx| {
            state.active_ssh = None;
            state.target_label = "正在绑定 SSH 目标…".into();
            cx.notify();
        });
        if let Some(previous) = previous_session
            && previous != status.session_id
        {
            self.disconnect_session(previous);
        }
        let label: SharedString = self
            .connections
            .iter()
            .find(|view| view.config.id == attempt.connection_id())
            .map(|view| {
                format!(
                    "{} · {}@{}:{}",
                    view.config.name, view.config.username, view.config.host, view.config.port
                )
                .into()
            })
            .unwrap_or_else(|| {
                format!("{}@{}:{}", status.username, status.host, status.port).into()
            });
        let binding = BindAttempt {
            connect: attempt,
            session_id: status.session_id,
            guard,
            label,
        };
        self.binding = Some(binding.clone());
        self.error = None;
        self.status = Some("SSH 已连接，正在绑定目标代次…".into());
        cx.notify();

        let services = self.services.clone();
        let cleanup_ssh = self.services.ssh().clone();
        let task_guard = binding.guard.clone();
        let task_session_id = binding.session_id.clone();
        let cleanup_session_id = binding.session_id.clone();
        let finish_binding = binding.clone();
        let task = self.tokio.spawn(async move {
            services
                .bind_active_ssh_session(&task_guard, &task_session_id)
                .await
        });
        cx.spawn(async move |manager, cx| {
            let mut result = Some(task.await);
            let handled = cx
                .update(|cx| {
                    if let Some(manager) = manager.upgrade() {
                        manager.update(cx, |manager, cx| {
                            manager.finish_binding(
                                finish_binding,
                                result.take().expect("binding result is consumed once"),
                                cx,
                            )
                        });
                        true
                    } else {
                        false
                    }
                })
                .unwrap_or(false);
            if !handled && let Err(error) = cleanup_ssh.disconnect(&cleanup_session_id).await {
                tracing::error!(
                    %error,
                    session_id = %cleanup_session_id,
                    "failed to close SSH session after binding owner release"
                );
            }
        })
        .detach();
    }

    fn finish_binding(
        &mut self,
        binding: BindAttempt,
        result: Result<Result<BoundSshSession, CoreError>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let owns_binding = binding.connect.generation == self.connect_generation
            && self.binding.as_ref().is_some_and(|current| {
                current.connect.generation == binding.connect.generation
                    && current.session_id == binding.session_id
                    && current.guard == binding.guard
            });
        if !owns_binding {
            self.disconnect_session(binding.session_id);
            return;
        }
        self.binding = None;
        if let Err(error) = self.services.target().validate(&binding.guard) {
            self.fail_binding(binding, error.to_string(), cx);
            return;
        }

        let session = match result {
            Ok(Ok(session)) => session,
            Ok(Err(error)) => {
                self.fail_binding(binding, error.to_string(), cx);
                return;
            }
            Err(error) => {
                self.fail_binding(binding, format!("SSH 目标绑定任务异常结束：{error}"), cx);
                return;
            }
        };
        let session_id = session.session_id().to_owned();
        self.shared.update(cx, |state, cx| {
            state.target_label = binding.label.clone();
            state.active_ssh = Some(ActiveSshTarget {
                connection_id: Arc::from(binding.connect.connection_id()),
                session,
                label: binding.label,
            });
            state.interactions.notifications.push_toast(
                "ssh-target-status",
                NotificationSeverity::Success,
                "SSH 已连接；可打开原生 SSH 终端窗口",
            );
            cx.notify();
        });
        self.host_key_confirmation = None;
        self.keyboard_interactive_confirmation = None;
        self.error = None;
        self.status = Some(format!("SSH 会话 {session_id} 已连接").into());
        self.refresh_connection_views();
        cx.emit(ConnectionManagerEvent::TargetReady);
    }

    fn fail_binding(&mut self, binding: BindAttempt, message: String, cx: &mut Context<Self>) {
        tracing::error!(
            session_id = %binding.session_id,
            reason = %message,
            "SSH target binding failed; closing the session"
        );
        if let Err(error) = self.services.target().clear_if_current(&binding.guard) {
            self.error = Some(format!("{message}；清理目标失败：{error}").into());
        } else {
            self.error = Some(message.into());
        }
        self.disconnect_session(binding.session_id);
        self.shared.update(cx, |state, cx| {
            state.active_ssh = None;
            state.target_label = "未连接目标".into();
            state.interactions.notifications.push_toast(
                "ssh-target-status",
                NotificationSeverity::Error,
                "SSH 已建立但目标绑定失败，会话已关闭",
            );
            cx.notify();
        });
        self.status = None;
        cx.notify();
    }

    fn disconnect_active(&mut self, cx: &mut Context<Self>) {
        self.cancel_pending_connect("连接请求已取消", cx);
        let active = self.shared.read(cx).active_ssh.clone();
        let Some(active) = active else {
            return;
        };
        if let Err(error) = self
            .services
            .target()
            .clear_if_current(active.session.target())
        {
            self.error = Some(error.to_string().into());
            cx.notify();
            return;
        }
        self.shared.update(cx, |state, cx| {
            state.active_ssh = None;
            state.target_label = "未连接目标".into();
            state.interactions.notifications.push_toast(
                "ssh-target-status",
                NotificationSeverity::Info,
                "SSH 目标已断开",
            );
            cx.notify();
        });
        self.disconnect_session(active.session.session_id().to_owned());
        self.status = Some("正在关闭 SSH 会话".into());
        cx.notify();
    }

    fn disconnect_session(&self, session_id: String) {
        let ssh = self.services.ssh().clone();
        drop(self.tokio.spawn(async move {
            if let Err(error) = ssh.disconnect(&session_id).await {
                tracing::error!(%error, %session_id, "failed to close SSH session");
            }
        }));
    }

    fn refresh_connection_views(&mut self) {
        if let Ok(connections) = self.services.connections().list() {
            self.connections = connections;
        }
    }

    fn begin_create(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.invalidate_credential_picker();
        self.cancel_pending_connect("编辑连接前已取消在途连接请求", cx);
        self.clear_editor_secrets(window, cx);
        self.editor = Some(ConnectionEditor::new(None, window, cx));
        self.tested_probe = None;
        self.delete_confirmation = None;
        self.error = None;
        cx.notify();
    }

    fn begin_edit(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self
            .selected
            .as_deref()
            .is_some_and(|id| self.deleting.as_deref() == Some(id))
        {
            self.error = Some("连接正在删除，不能修改配置".into());
            cx.notify();
            return;
        }
        self.invalidate_credential_picker();
        let Some(view) = self.selected_view().cloned() else {
            self.error = Some("请先选择连接".into());
            cx.notify();
            return;
        };
        self.cancel_pending_connect("编辑连接前已取消在途连接请求", cx);
        self.clear_editor_secrets(window, cx);
        self.editor = Some(ConnectionEditor::new(Some(&view), window, cx));
        self.tested_probe = None;
        self.delete_confirmation = None;
        self.error = None;
        cx.notify();
    }

    fn cancel_edit(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.invalidate_credential_picker();
        self.cancel_pending_connect("连接编辑已取消，测试请求已作废", cx);
        self.clear_editor_secrets(window, cx);
        self.editor = None;
        self.tested_probe = None;
        self.error = None;
        cx.notify();
    }

    fn save(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.connecting.is_some()
            || self.host_key_confirmation.is_some()
            || self.keyboard_interactive_confirmation.is_some()
        {
            self.error = Some("请先完成或取消当前连接测试".into());
            cx.notify();
            return;
        }
        let Some(editor) = self.editor.as_ref() else {
            return;
        };
        let config = match editor.collect_config(cx) {
            Ok(config) => config,
            Err(error) => {
                self.error = Some(error.into());
                cx.notify();
                return;
            }
        };
        let tested = self
            .tested_probe
            .as_ref()
            .filter(|plan| plan.config() == &config && !editor.has_new_secret_input(cx))
            .cloned();
        if let Some(plan) = tested {
            let id = config.id.clone();
            self.tested_probe = None;
            self.cancel_pending_connect("正在保存已测试的连接配置", cx);
            match self.services.connections().commit_probe(plan) {
                Ok(saved) => self.finish_saved_connection(id, saved, cx),
                Err(error) => {
                    self.error = Some(error.to_string().into());
                    self.status = Some("已测试快照失效；请重新测试当前草稿".into());
                }
            }
            cx.notify();
            return;
        }
        if self.tested_probe.take().is_some() {
            self.status = Some("草稿在测试后已修改；请重新测试或重新输入凭据".into());
        }
        if let Err(error) = editor.validate_required_secrets(cx) {
            self.error = Some(error.into());
            cx.notify();
            return;
        }
        let id = config.id.clone();
        let changes = editor.take_secret_changes(window, cx);
        self.cancel_pending_connect("连接配置已变化，先前连接请求已取消", cx);
        match self.services.connections().upsert(config, changes) {
            Ok(saved) => self.finish_saved_connection(id, saved, cx),
            Err(error) => {
                self.error = Some(error.to_string().into());
                self.status = Some("凭据输入已从编辑器清空，请修正后重新输入".into());
            }
        }
        cx.notify();
    }

    fn finish_saved_connection(
        &mut self,
        id: String,
        saved: ConnectionView,
        cx: &mut Context<Self>,
    ) {
        let saved_connection_id = id.clone();
        self.connections.retain(|view| view.config.id != id);
        self.connections.push(saved);
        self.connections
            .sort_by(|left, right| left.config.name.cmp(&right.config.name));
        self.selected = Some(id);
        self.editor = None;
        self.tested_probe = None;
        self.invalidate_credential_picker();
        self.error = None;
        match self.detach_active_connection(
            &saved_connection_id,
            NotificationSeverity::Warning,
            "活动 SSH 配置已修改，会话已安全断开",
            cx,
        ) {
            Ok(_) => {
                self.status = Some("连接配置已保存；尚未建立 SSH 会话".into());
            }
            Err(error) => {
                self.error = Some(error.to_string().into());
                self.status = Some("配置已保存，但活动会话清理失败".into());
            }
        }
    }

    fn set_auth_method(&mut self, method: SshAuthMethod, cx: &mut Context<Self>) {
        self.tested_probe = None;
        if let Some(editor) = &mut self.editor {
            editor.draft.auth_method = method;
            cx.notify();
        }
    }

    fn toggle_jump_host(&mut self, cx: &mut Context<Self>) {
        self.tested_probe = None;
        if let Some(editor) = &mut self.editor {
            editor.draft.jump_enabled = !editor.draft.jump_enabled;
            cx.notify();
        }
    }

    fn set_jump_auth_method(&mut self, method: SshAuthMethod, cx: &mut Context<Self>) {
        self.tested_probe = None;
        if let Some(editor) = &mut self.editor {
            editor.draft.jump_auth_method = method;
            cx.notify();
        }
    }

    fn toggle_secret_remove(&mut self, field: SecretField, cx: &mut Context<Self>) {
        self.tested_probe = None;
        if let Some(editor) = &mut self.editor {
            editor.toggle_remove(field);
            cx.notify();
        }
    }

    fn begin_delete(&mut self, cx: &mut Context<Self>) {
        let Some(connection_id) = self.selected.clone() else {
            self.error = Some("请先选择连接".into());
            cx.notify();
            return;
        };
        if self.deleting.is_some() {
            self.error = Some("已有连接删除任务正在执行".into());
            cx.notify();
            return;
        }
        self.cancel_pending_connect("删除确认开始，先前连接请求已取消", cx);
        match self.services.connections().plan_delete(&connection_id) {
            Ok(plan) => {
                self.delete_confirmation = Some(DeleteConfirmation { plan });
                self.error = None;
            }
            Err(error) => {
                self.delete_confirmation = None;
                self.error = Some(format!("无法创建连接删除计划：{error}").into());
            }
        }
        cx.notify();
    }

    fn cancel_delete(&mut self, cx: &mut Context<Self>) {
        self.delete_confirmation = None;
        cx.notify();
    }

    fn confirm_delete(&mut self, cx: &mut Context<Self>) {
        let Some(confirmation) = self.delete_confirmation.take() else {
            return;
        };
        let connection_id = confirmation.plan.connection_id().to_owned();
        let connection_name = confirmation.plan.connection_name().to_owned();
        let approval = DangerousConfirmation::approve(confirmation.plan.definition());
        let repository = self.services.connections().clone();
        let journal = self.services.operation_journal().clone();
        let task = self.tokio.spawn(async move {
            repository
                .execute_delete(confirmation.plan, approval, &journal)
                .await
        });
        self.deleting = Some(connection_id.clone());
        self.error = None;
        self.status = Some(format!("正在删除连接“{connection_name}”…").into());
        cx.spawn(async move |manager, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(manager) = manager.upgrade() {
                    manager.update(cx, |manager, cx| {
                        manager.finish_delete(connection_id, connection_name, result, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_delete(
        &mut self,
        connection_id: String,
        connection_name: String,
        result: Result<CoreResult<ConnectionDeleteOutcome>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if self.deleting.as_deref() == Some(&connection_id) {
            self.deleting = None;
        }
        match result {
            Err(error) => {
                self.error = Some(format!("连接删除任务失败：{error}").into());
                self.status = None;
            }
            Ok(Err(error)) => {
                self.error =
                    Some(format!("连接删除流程未完整通过执行、审计与验证：{error}").into());
                self.status = None;
            }
            Ok(Ok(_outcome)) => {
                if let Err(error) = self.detach_active_connection(
                    &connection_id,
                    NotificationSeverity::Warning,
                    "活动 SSH 连接已删除并断开",
                    cx,
                ) {
                    self.error = Some(error.to_string().into());
                    self.status = Some("连接已删除并审计，但活动会话清理失败".into());
                    cx.notify();
                    return;
                }
                self.connections
                    .retain(|view| view.config.id != connection_id);
                if self.selected.as_deref() == Some(&connection_id) {
                    self.selected = None;
                }
                self.error = None;
                self.status = Some(format!("已删除并验证连接“{connection_name}”").into());
            }
        }
        cx.notify();
    }

    fn selected_view(&self) -> Option<&ConnectionView> {
        let selected = self.selected.as_deref()?;
        self.connections
            .iter()
            .find(|view| view.config.id == selected)
    }

    fn detach_active_connection(
        &mut self,
        connection_id: &str,
        severity: NotificationSeverity,
        message: &'static str,
        cx: &mut Context<Self>,
    ) -> Result<bool, CoreError> {
        let active = self
            .shared
            .read(cx)
            .active_ssh
            .as_ref()
            .filter(|active| active.connection_id.as_ref() == connection_id)
            .cloned();
        let Some(active) = active else {
            return Ok(false);
        };
        self.services
            .target()
            .clear_if_current(active.session.target())?;
        self.shared.update(cx, |state, cx| {
            state.active_ssh = None;
            state.target_label = "未连接目标".into();
            state
                .interactions
                .notifications
                .push_toast("ssh-target-status", severity, message);
            cx.notify();
        });
        self.disconnect_session(active.session.session_id().to_owned());
        Ok(true)
    }

    fn clear_editor_secrets(&self, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(editor) = &self.editor {
            editor.clear_secrets(window, cx);
        }
    }

    fn clear_keyboard_interactive_inputs(
        &self,
        inputs: &[Entity<InputState>],
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        for input in inputs {
            input.update(cx, |state, cx| state.set_value("", window, cx));
        }
    }
}

impl Render for ConnectionManager {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens = self.shared.read(cx).theme.tokens();
        let selected = self.selected.clone();
        let selected_view = self.selected_view().cloned();
        let editor = self.editor.as_ref();
        let delete_confirmation = self.delete_confirmation.clone();
        let host_key_confirmation = self.host_key_confirmation.clone();
        let keyboard_interactive_confirmation = self
            .keyboard_interactive_confirmation
            .as_ref()
            .map(|confirmation| {
                (
                    confirmation.challenge.clone(),
                    confirmation.inputs.clone(),
                    confirmation.attempt.is_probe(),
                )
            });
        let editor_connection_busy = self.connecting.is_some()
            || self.host_key_confirmation.is_some()
            || self.keyboard_interactive_confirmation.is_some();
        let tested_probe_ready = self.tested_probe.is_some();
        let connecting_id = self
            .connecting
            .as_ref()
            .map(|attempt| attempt.connection_id().to_owned())
            .or_else(|| {
                self.binding
                    .as_ref()
                    .map(|attempt| attempt.connect.connection_id().to_owned())
            });
        let active_connection_id = self
            .shared
            .read(cx)
            .active_ssh
            .as_ref()
            .map(|active| active.connection_id.to_string());
        let deleting_id = self.deleting.clone();
        let transfer_busy = self.transfer_busy;
        let credential_picker_busy = self.credential_picker_busy;
        let error = self.error.clone();
        let status = self.status.clone();

        div()
            .id("connection-manager")
            .mb_4()
            .rounded_lg()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .p_5()
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .mb_4()
                    .child(
                        div()
                            .child(
                                div()
                                    .text_lg()
                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                    .child("连接配置"),
                            )
                            .child(div().mt_1().text_xs().text_color(tokens.muted).child(
                                "选择已保存的连接，或新建连接；配置仅保存在本机便携数据目录。",
                            )),
                    )
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .child(
                                crate::buttons::button("connection-import")
                                    .label("导入")
                                    .small()
                                    .disabled(transfer_busy)
                                    .on_click(
                                        cx.listener(|this, _, _, cx| this.choose_import_path(cx)),
                                    ),
                            )
                            .child(
                                crate::buttons::button("connection-export")
                                    .label("导出")
                                    .small()
                                    .disabled(transfer_busy)
                                    .on_click(
                                        cx.listener(|this, _, _, cx| this.choose_export_path(cx)),
                                    ),
                            )
                            .child(
                                crate::buttons::button("connection-refresh")
                                    .label("刷新")
                                    .small()
                                    .on_click(cx.listener(|this, _, _, cx| this.refresh(cx))),
                            )
                            .child(
                                crate::buttons::button("connection-create")
                                    .label("新建")
                                    .small()
                                    .primary()
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.begin_create(window, cx)
                                    })),
                            ),
                    ),
            )
            .child(connection_list(
                self.connections.clone(),
                selected,
                tokens,
                cx,
            ))
            .when_some(selected_view, |panel, view| {
                let is_active = active_connection_id.as_deref() == Some(&view.config.id);
                let is_connecting = connecting_id.as_deref() == Some(&view.config.id);
                let is_deleting = deleting_id.as_deref() == Some(&view.config.id);
                panel.child(connection_details(
                    view,
                    is_active,
                    is_connecting,
                    is_deleting,
                    tokens,
                    cx,
                ))
            })
            .when_some(editor, |panel, editor| {
                panel.child(connection_editor(
                    editor,
                    tokens,
                    credential_picker_busy,
                    editor_connection_busy,
                    tested_probe_ready,
                    cx,
                ))
            })
            .when_some(delete_confirmation, |panel, confirmation| {
                panel.child(delete_confirmation_view(confirmation, tokens, cx))
            })
            .when_some(host_key_confirmation, |panel, confirmation| {
                panel.child(host_key_confirmation_view(confirmation, tokens, cx))
            })
            .when_some(
                keyboard_interactive_confirmation,
                |panel, (challenge, inputs, is_probe)| {
                    panel.child(keyboard_interactive_confirmation_view(
                        challenge, inputs, is_probe, tokens, cx,
                    ))
                },
            )
            .when_some(error, |panel, error| {
                panel.child(
                    div()
                        .mt_3()
                        .rounded_md()
                        .border_1()
                        .border_color(tokens.danger)
                        .p_3()
                        .text_sm()
                        .text_color(tokens.danger)
                        .child(error),
                )
            })
            .when_some(status, |panel, status| {
                panel.child(
                    div()
                        .mt_3()
                        .text_sm()
                        .text_color(tokens.muted)
                        .child(status),
                )
            })
    }
}

fn connection_list(
    connections: Vec<ConnectionView>,
    selected: Option<String>,
    tokens: ThemeTokens,
    cx: &mut Context<ConnectionManager>,
) -> impl IntoElement {
    div()
        .flex()
        .flex_wrap()
        .gap_2()
        .when(connections.is_empty(), |list| {
            list.child(
                div()
                    .text_sm()
                    .text_color(tokens.muted)
                    .child("暂无连接，点击“新建”添加。"),
            )
        })
        .children(connections.into_iter().map(|view| {
            let id = view.config.id.clone();
            let label = format!(
                "{} · {}@{}:{}",
                view.config.name, view.config.username, view.config.host, view.config.port
            );
            crate::buttons::button(SharedString::from(format!("connection-{id}")))
                .label(label)
                .small()
                .selected(selected.as_deref() == Some(&id))
                .on_click(cx.listener(move |this, _, _, cx| this.select(id.clone(), cx)))
        }))
}

fn connection_details(
    view: ConnectionView,
    is_active: bool,
    is_connecting: bool,
    is_deleting: bool,
    tokens: ThemeTokens,
    cx: &mut Context<ConnectionManager>,
) -> impl IntoElement {
    let credential_summary = format!(
        "密码 {} · 密钥口令 {} · 跳板机密码 {}",
        stored_label(view.has_password),
        stored_label(view.has_key_passphrase),
        stored_label(view.jump_host_has_password)
    );
    div()
        .mt_4()
        .rounded_md()
        .bg(tokens.surface_alt)
        .p_3()
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .child(div().child(view.config.name).child(
                    div().text_xs().text_color(tokens.muted).child(format!(
                        "{} · {}",
                        auth_label(view.config.auth_method),
                        credential_summary
                    )),
                ))
                .child(
                    div()
                        .flex()
                        .gap_2()
                        .child(if is_deleting {
                            crate::buttons::button("connection-delete-in-flight")
                                .label("删除中…")
                                .small()
                                .disabled(true)
                        } else if is_active {
                            crate::buttons::button("connection-disconnect")
                                .label("断开")
                                .small()
                                .danger()
                                .on_click(cx.listener(|this, _, _, cx| this.disconnect_active(cx)))
                        } else if is_connecting {
                            crate::buttons::button("connection-cancel-connect")
                                .label("取消连接")
                                .small()
                                .on_click(cx.listener(|this, _, _, cx| this.cancel_connect(cx)))
                        } else {
                            crate::buttons::button("connection-connect")
                                .label("连接")
                                .small()
                                .primary()
                                .on_click(cx.listener(|this, _, _, cx| this.begin_connect(cx)))
                        })
                        .child(
                            crate::buttons::button("connection-edit")
                                .label("编辑")
                                .small()
                                .disabled(is_deleting)
                                .on_click(
                                    cx.listener(|this, _, window, cx| this.begin_edit(window, cx)),
                                ),
                        )
                        .child(
                            crate::buttons::button("connection-delete")
                                .label("删除")
                                .small()
                                .danger()
                                .disabled(is_deleting)
                                .on_click(cx.listener(|this, _, _, cx| this.begin_delete(cx))),
                        ),
                ),
        )
}

fn connection_editor(
    editor: &ConnectionEditor,
    tokens: ThemeTokens,
    credential_picker_busy: bool,
    connection_busy: bool,
    tested_probe_ready: bool,
    cx: &mut Context<ConnectionManager>,
) -> impl IntoElement {
    let auth_method = editor.draft.auth_method;
    let jump_enabled = editor.draft.jump_enabled;
    let jump_auth_method = editor.draft.jump_auth_method;
    div()
        .id("connection-editor")
        .mt_4()
        .rounded_lg()
        .bg(tokens.surface_alt)
        .p_4()
        .child(
            div()
                .text_lg()
                .mb_3()
                .child(if editor.draft.name.is_empty() {
                    "新建连接"
                } else {
                    "编辑连接"
                }),
        )
        .child(
            div()
                .grid()
                .grid_cols(2)
                .gap_3()
                .child(labeled_input("名称", &editor.name))
                .child(labeled_input("主机", &editor.host))
                .child(labeled_input("端口", &editor.port))
                .child(labeled_input("用户名", &editor.username)),
        )
        .child(
            div()
                .mt_3()
                .text_sm()
                .text_color(tokens.muted)
                .child("认证方式"),
        )
        .child(
            div()
                .mt_2()
                .flex()
                .flex_wrap()
                .gap_2()
                .children(auth_methods().into_iter().map(|method| {
                    crate::buttons::button(SharedString::from(format!("auth-{method:?}")))
                        .label(auth_label(method))
                        .small()
                        .selected(method == auth_method)
                        .on_click(
                            cx.listener(move |this, _, _, cx| this.set_auth_method(method, cx)),
                        )
                })),
        )
        .when(auth_method == SshAuthMethod::Password, |panel| {
            panel.child(div().mt_3().child(secret_input(
                "SSH 密码",
                &editor.password,
                editor.stored_password,
                editor.remove_password,
                SecretField::Password,
                cx,
            )))
        })
        .when(uses_private_key(auth_method), |panel| {
            panel.child(
                div()
                    .mt_3()
                    .grid()
                    .grid_cols(2)
                    .gap_3()
                    .child(credential_path_input(
                        "私钥绝对路径",
                        &editor.private_key_path,
                        CredentialPathField::PrivateKey,
                        credential_picker_busy,
                        cx,
                    ))
                    .child(secret_input(
                        "私钥口令（可选）",
                        &editor.key_passphrase,
                        editor.stored_key_passphrase,
                        editor.remove_key_passphrase,
                        SecretField::KeyPassphrase,
                        cx,
                    )),
            )
        })
        .when(auth_method == SshAuthMethod::Certificate, |panel| {
            panel.child(div().mt_3().child(credential_path_input(
                "OpenSSH 用户证书绝对路径",
                &editor.certificate_path,
                CredentialPathField::Certificate,
                credential_picker_busy,
                cx,
            )))
        })
        .when(auth_method == SshAuthMethod::Agent, |panel| {
            panel.child(div().mt_3().child(labeled_input(
                "Agent 身份指纹（可选）",
                &editor.agent_identity_fingerprint,
            )))
        })
        .when(auth_method == SshAuthMethod::KeyboardInteractive, |panel| {
            panel.child(
                div()
                    .mt_3()
                    .rounded_md()
                    .bg(tokens.background)
                    .p_3()
                    .text_sm()
                    .text_color(tokens.muted)
                    .child("连接时按目标机提示输入密码、验证码或 MFA 响应，不会持久化响应。"),
            )
        })
        .child(
            div()
                .mt_4()
                .flex()
                .items_center()
                .justify_between()
                .child(
                    div()
                        .font_weight(gpui::FontWeight::SEMIBOLD)
                        .child("堡垒机 / ProxyJump"),
                )
                .child(
                    crate::buttons::button("connection-toggle-jump-host")
                        .label(if jump_enabled {
                            "停用堡垒机"
                        } else {
                            "启用堡垒机"
                        })
                        .small()
                        .selected(jump_enabled)
                        .on_click(cx.listener(|this, _, _, cx| this.toggle_jump_host(cx))),
                ),
        )
        .when(jump_enabled, |panel| {
            panel
                .child(
                    div()
                        .mt_3()
                        .grid()
                        .grid_cols(3)
                        .gap_3()
                        .child(labeled_input("堡垒机地址", &editor.jump_host))
                        .child(labeled_input("堡垒机端口", &editor.jump_port))
                        .child(labeled_input("堡垒机用户名", &editor.jump_username)),
                )
                .child(
                    div()
                        .mt_3()
                        .text_sm()
                        .text_color(tokens.muted)
                        .child("堡垒机认证方式"),
                )
                .child(div().mt_2().flex().flex_wrap().gap_2().children(
                    auth_methods().into_iter().map(|method| {
                        crate::buttons::button(SharedString::from(format!("jump-auth-{method:?}")))
                            .label(auth_label(method))
                            .small()
                            .selected(method == jump_auth_method)
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.set_jump_auth_method(method, cx)
                            }))
                    }),
                ))
                .when(jump_auth_method == SshAuthMethod::Password, |panel| {
                    panel.child(div().mt_3().child(secret_input(
                        "堡垒机密码",
                        &editor.jump_host_password,
                        editor.stored_jump_host_password,
                        editor.remove_jump_host_password,
                        SecretField::JumpHostPassword,
                        cx,
                    )))
                })
                .when(uses_private_key(jump_auth_method), |panel| {
                    panel.child(
                        div()
                            .mt_3()
                            .grid()
                            .grid_cols(2)
                            .gap_3()
                            .child(credential_path_input(
                                "堡垒机私钥绝对路径",
                                &editor.jump_private_key_path,
                                CredentialPathField::JumpPrivateKey,
                                credential_picker_busy,
                                cx,
                            ))
                            .child(secret_input(
                                "堡垒机私钥口令（可选）",
                                &editor.jump_host_key_passphrase,
                                editor.stored_jump_host_key_passphrase,
                                editor.remove_jump_host_key_passphrase,
                                SecretField::JumpHostKeyPassphrase,
                                cx,
                            )),
                    )
                })
                .when(jump_auth_method == SshAuthMethod::Certificate, |panel| {
                    panel.child(div().mt_3().child(credential_path_input(
                        "堡垒机 OpenSSH 用户证书绝对路径",
                        &editor.jump_certificate_path,
                        CredentialPathField::JumpCertificate,
                        credential_picker_busy,
                        cx,
                    )))
                })
                .when(jump_auth_method == SshAuthMethod::Agent, |panel| {
                    panel.child(div().mt_3().child(labeled_input(
                        "堡垒机 Agent 身份指纹（可选）",
                        &editor.jump_agent_identity_fingerprint,
                    )))
                })
                .when(
                    jump_auth_method == SshAuthMethod::KeyboardInteractive,
                    |panel| {
                        panel.child(
                            div()
                                .mt_3()
                                .rounded_md()
                                .bg(tokens.background)
                                .p_3()
                                .text_sm()
                                .text_color(tokens.muted)
                                .child("连接时按堡垒机提示输入交互认证或 MFA 响应。"),
                        )
                    },
                )
        })
        .child(
            div()
                .mt_4()
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .child("连接分类"),
        )
        .child(
            div()
                .mt_3()
                .grid()
                .grid_cols(3)
                .gap_3()
                .child(labeled_input("环境", &editor.environment))
                .child(labeled_input("角色", &editor.role))
                .child(labeled_input("分组", &editor.group)),
        )
        .child(
            div()
                .mt_3()
                .grid()
                .grid_cols(2)
                .gap_3()
                .child(labeled_input("标签（逗号分隔）", &editor.tags))
                .child(labeled_input("备注", &editor.notes)),
        )
        .child(
            div()
                .mt_4()
                .flex()
                .justify_end()
                .gap_2()
                .child(
                    crate::buttons::button("connection-editor-cancel")
                        .label("取消")
                        .small()
                        .on_click(cx.listener(|this, _, window, cx| this.cancel_edit(window, cx))),
                )
                .child(
                    crate::buttons::button("connection-editor-probe")
                        .label(if connection_busy {
                            "测试中…"
                        } else if tested_probe_ready {
                            "重新测试"
                        } else {
                            "测试连接"
                        })
                        .small()
                        .disabled(connection_busy)
                        .on_click(cx.listener(|this, _, window, cx| this.begin_probe(window, cx))),
                )
                .child(
                    crate::buttons::button("connection-editor-save")
                        .label(if tested_probe_ready {
                            "保存已测试配置"
                        } else {
                            "保存配置"
                        })
                        .small()
                        .primary()
                        .disabled(connection_busy)
                        .on_click(cx.listener(|this, _, window, cx| this.save(window, cx))),
                ),
        )
}

fn labeled_input(label: &'static str, input: &Entity<InputState>) -> impl IntoElement {
    div()
        .child(div().mb_1().text_xs().child(label))
        .child(Input::new(input))
}

fn credential_path_input(
    label: &'static str,
    input: &Entity<InputState>,
    field: CredentialPathField,
    busy: bool,
    cx: &mut Context<ConnectionManager>,
) -> impl IntoElement {
    div().child(div().mb_1().text_xs().child(label)).child(
        div()
            .flex()
            .items_center()
            .gap_2()
            .child(div().flex_1().child(Input::new(input)))
            .child(
                crate::buttons::button(SharedString::from(format!("choose-{field:?}")))
                    .label("选择")
                    .small()
                    .disabled(busy)
                    .on_click(
                        cx.listener(move |this, _, _, cx| this.choose_credential_path(field, cx)),
                    ),
            ),
    )
}

fn secret_input(
    label: &'static str,
    input: &Entity<InputState>,
    stored: bool,
    remove: bool,
    field: SecretField,
    cx: &mut Context<ConnectionManager>,
) -> impl IntoElement {
    div()
        .child(div().mb_1().text_xs().child(format!(
            "{label} · {}",
            if remove {
                "将移除"
            } else {
                stored_label(stored)
            }
        )))
        .child(Input::new(input))
        .child(
            crate::buttons::button(SharedString::from(format!("remove-{field:?}")))
                .label(if remove {
                    "保留现有"
                } else {
                    "移除已保存值"
                })
                .xsmall()
                .ghost()
                .disabled(!stored && !remove)
                .on_click(cx.listener(move |this, _, _, cx| this.toggle_secret_remove(field, cx))),
        )
}

fn delete_confirmation_view(
    confirmation: DeleteConfirmation,
    tokens: ThemeTokens,
    cx: &mut Context<ConnectionManager>,
) -> impl IntoElement {
    div()
        .id("connection-delete-confirmation")
        .mt_4()
        .rounded_md()
        .border_1()
        .border_color(tokens.danger)
        .p_4()
        .child(
            div()
                .text_color(tokens.danger)
                .child("危险确认：删除连接配置与已保存凭据"),
        )
        .child(div().my_2().text_sm().child(format!(
            "确认删除“{}”？此操作不可撤销。",
            confirmation.plan.connection_name()
        )))
        .child(
            div()
                .flex()
                .gap_2()
                .child(
                    crate::buttons::button("connection-delete-cancel")
                        .label("取消")
                        .small()
                        .on_click(cx.listener(|this, _, _, cx| this.cancel_delete(cx))),
                )
                .child(
                    crate::buttons::button("connection-delete-confirm")
                        .label("确认永久删除")
                        .small()
                        .danger()
                        .on_click(cx.listener(|this, _, _, cx| this.confirm_delete(cx))),
                ),
        )
}

fn host_key_confirmation_view(
    confirmation: HostKeyConfirmation,
    tokens: ThemeTokens,
    cx: &mut Context<ConnectionManager>,
) -> impl IntoElement {
    let is_probe = confirmation.attempt.is_probe();
    div()
        .id("ssh-host-key-confirmation")
        .mt_4()
        .rounded_md()
        .border_1()
        .border_color(tokens.danger)
        .bg(tokens.surface_alt)
        .p_4()
        .child(div().text_color(tokens.danger).child(if is_probe {
            "危险确认：测试连接的 SSH 主机密钥"
        } else {
            "危险确认：首次信任 SSH 主机密钥"
        }))
        .child(div().mt_2().text_sm().child(format!(
            "请通过独立可信渠道核验{} {}@{}:{} 的指纹。确认只对本次精确指纹生效。",
            host_key_role_label(confirmation.role),
            confirmation.username,
            confirmation.host,
            confirmation.port
        )))
        .child(
            div()
                .my_3()
                .rounded_md()
                .border_1()
                .border_color(tokens.border)
                .p_3()
                .font_family("monospace")
                .child(confirmation.fingerprint),
        )
        .child(
            div()
                .flex()
                .gap_2()
                .child(
                    crate::buttons::button("ssh-host-key-cancel")
                        .label(if is_probe {
                            "取消测试"
                        } else {
                            "取消连接"
                        })
                        .small()
                        .on_click(cx.listener(|this, _, _, cx| this.cancel_connect(cx))),
                )
                .child(
                    crate::buttons::button("ssh-host-key-confirm")
                        .label("我已独立核验，确认本次指纹")
                        .small()
                        .danger()
                        .on_click(cx.listener(|this, _, _, cx| this.confirm_host_key(cx))),
                ),
        )
}

fn keyboard_interactive_confirmation_view(
    challenge: SshKeyboardInteractiveChallenge,
    inputs: Vec<Entity<InputState>>,
    is_probe: bool,
    tokens: ThemeTokens,
    cx: &mut Context<ConnectionManager>,
) -> impl IntoElement {
    let endpoint = format!(
        "{} {}@{}:{}",
        host_key_role_label(challenge.role),
        challenge.username,
        challenge.host,
        challenge.port
    );
    div()
        .id("ssh-keyboard-interactive-confirmation")
        .mt_4()
        .rounded_md()
        .border_1()
        .border_color(tokens.accent)
        .bg(tokens.surface_alt)
        .p_4()
        .child(
            div()
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .child("SSH 交互认证 / MFA"),
        )
        .child(
            div()
                .mt_1()
                .text_sm()
                .text_color(tokens.muted)
                .child(endpoint),
        )
        .when(!challenge.name.is_empty(), |panel| {
            panel.child(div().mt_3().text_sm().child(challenge.name.clone()))
        })
        .when(!challenge.instructions.is_empty(), |panel| {
            panel.child(
                div()
                    .mt_2()
                    .text_sm()
                    .text_color(tokens.muted)
                    .child(challenge.instructions.clone()),
            )
        })
        .children(challenge.prompts.iter().zip(inputs.iter()).enumerate().map(
            |(index, (prompt, input))| {
                div()
                    .mt_3()
                    .child(div().mb_1().text_xs().child(if prompt.prompt.is_empty() {
                        format!("响应 {}", index + 1)
                    } else {
                        prompt.prompt.clone()
                    }))
                    .child(Input::new(input))
            },
        ))
        .child(
            div()
                .mt_4()
                .flex()
                .gap_2()
                .child(
                    crate::buttons::button("ssh-keyboard-interactive-cancel")
                        .label(if is_probe {
                            "取消测试"
                        } else {
                            "取消连接"
                        })
                        .small()
                        .on_click(cx.listener(|this, _, window, cx| {
                            this.cancel_keyboard_interactive(window, cx)
                        })),
                )
                .child(
                    crate::buttons::button("ssh-keyboard-interactive-submit")
                        .label("提交并继续")
                        .small()
                        .primary()
                        .on_click(cx.listener(|this, _, window, cx| {
                            this.submit_keyboard_interactive(window, cx)
                        })),
                ),
        )
}

fn text_input(
    placeholder: &'static str,
    value: &str,
    masked: bool,
    window: &mut Window,
    cx: &mut Context<ConnectionManager>,
) -> Entity<InputState> {
    let value = value.to_owned();
    cx.new(move |cx| {
        InputState::new(window, cx)
            .placeholder(placeholder)
            .default_value(value)
            .masked(masked)
    })
}

fn input_value(input: &Entity<InputState>, cx: &Context<ConnectionManager>) -> String {
    input.read(cx).value().to_string()
}

fn path_text(path: Option<&PathBuf>) -> String {
    path.map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn required_absolute_path(value: &str, label: &str) -> Result<PathBuf, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("请选择{label}"));
    }
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(format!("{label}必须使用本机绝对路径"));
    }
    Ok(path)
}

fn optional_text(value: &str, label: &str, maximum: usize) -> Result<Option<String>, String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > maximum || value.chars().any(char::is_control) {
        return Err(format!("{label}最多 {maximum} 字节且不能包含控制字符"));
    }
    Ok(Some(value.to_owned()))
}

fn optional_fingerprint(value: &str, label: &str) -> Result<Option<String>, String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if !value.starts_with("SHA256:") || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(format!("{label}必须使用 SHA256: OpenSSH 格式"));
    }
    Ok(Some(value.to_owned()))
}

fn parse_tags(value: &str) -> Result<BTreeSet<String>, String> {
    let tags = value
        .split([',', '，'])
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if tags.len() > 20 {
        return Err("标签最多 20 个".to_owned());
    }
    if tags
        .iter()
        .any(|tag| tag.len() > 64 || tag.chars().any(char::is_control))
    {
        return Err("每个标签最多 64 字节且不能包含控制字符".to_owned());
    }
    Ok(tags)
}

fn uses_private_key(method: SshAuthMethod) -> bool {
    matches!(
        method,
        SshAuthMethod::PublicKey | SshAuthMethod::Certificate
    )
}

fn preserved_jump_host_key_fingerprint(
    previous: Option<&JumpHostConfig>,
    host: &str,
    port: u16,
) -> Option<String> {
    previous
        .filter(|previous| previous.host == host && previous.port == port)
        .and_then(|previous| previous.host_key_fingerprint.clone())
}

fn secret_change_for_usage(value: String, remove: bool, active: bool) -> SecretChange {
    if active {
        secret_change(value, remove)
    } else {
        SecretChange::Remove
    }
}

fn secret_will_exist(value: &str, stored: bool, remove: bool) -> bool {
    !remove && (stored || !value.is_empty())
}

fn apply_host_key_confirmation(
    confirmations: &mut HostKeyConfirmations,
    role: SshHostRole,
    fingerprint: &str,
) {
    match role {
        SshHostRole::Target => {
            confirmations.target_fingerprint = Some(fingerprint.to_owned());
        }
        SshHostRole::JumpHost => {
            confirmations.jump_host_fingerprint = Some(fingerprint.to_owned());
        }
    }
}

fn apply_keyboard_interactive_responses(
    authorization: &mut SshConnectAuthorization,
    challenge: &SshKeyboardInteractiveChallenge,
    responses: Vec<String>,
) -> CoreResult<()> {
    if authorization.keyboard_interactive_response_count(challenge.role)
        != challenge.supplied_responses
    {
        return Err(CoreError::Validation {
            subject: "SSH keyboard-interactive responses",
            message: "response sequence does not match the server challenge".to_owned(),
        });
    }
    if responses.len() != challenge.prompts.len() {
        return Err(CoreError::Validation {
            subject: "SSH keyboard-interactive responses",
            message: "response count does not match the server prompt count".to_owned(),
        });
    }
    authorization.extend_keyboard_interactive_responses(
        challenge.role,
        responses.into_iter().map(SecretValue::new).collect(),
    )
}

fn host_key_role_label(role: SshHostRole) -> &'static str {
    match role {
        SshHostRole::Target => "目标机",
        SshHostRole::JumpHost => "跳板机",
    }
}

fn secret_change(value: String, remove: bool) -> SecretChange {
    if remove {
        SecretChange::Remove
    } else if value.is_empty() {
        SecretChange::Keep
    } else {
        SecretChange::Replace(SecretValue::new(value))
    }
}

fn stored_label(stored: bool) -> &'static str {
    if stored { "已保存" } else { "未保存" }
}

fn auth_methods() -> [SshAuthMethod; 5] {
    [
        SshAuthMethod::Password,
        SshAuthMethod::KeyboardInteractive,
        SshAuthMethod::PublicKey,
        SshAuthMethod::Agent,
        SshAuthMethod::Certificate,
    ]
}

fn auth_label(method: SshAuthMethod) -> &'static str {
    match method {
        SshAuthMethod::Password => "密码",
        SshAuthMethod::KeyboardInteractive => "交互认证 / MFA",
        SshAuthMethod::PublicKey => "公钥",
        SshAuthMethod::Agent => "SSH Agent",
        SshAuthMethod::Certificate => "证书",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draft_delegates_validation_to_core_connection_config() {
        let mut draft = ConnectionDraft::new();
        draft.name = "Production".to_owned();
        draft.host = "10.0.0.8".to_owned();
        draft.port = "22".to_owned();
        draft.username = "incident".to_owned();
        let config = draft.clone().build().unwrap();
        assert_eq!(config.name, "Production");
        assert_eq!(config.host, "10.0.0.8");

        draft.port = "0".to_owned();
        assert!(draft.build().unwrap_err().contains("non-zero"));
    }

    #[test]
    fn changing_the_ssh_endpoint_clears_the_persisted_host_key_pin() {
        let mut draft = ConnectionDraft::new();
        draft.name = "Production".to_owned();
        draft.host = "10.0.0.8".to_owned();
        draft.port = "22".to_owned();
        draft.username = "incident".to_owned();
        draft.base.host = draft.host.clone();
        draft.base.host_key_fingerprint = Some("SHA256:old-endpoint".to_owned());

        let unchanged = draft.clone().build().unwrap();
        assert_eq!(
            unchanged.host_key_fingerprint.as_deref(),
            Some("SHA256:old-endpoint")
        );

        draft.host = "10.0.0.9".to_owned();
        assert_eq!(draft.build().unwrap().host_key_fingerprint, None);
    }

    #[test]
    fn secret_changes_are_write_only_and_debug_redacted() {
        let changes = ConnectionSecretChanges {
            password: secret_change_for_usage("never-print-this".to_owned(), false, true),
            key_passphrase: secret_change_for_usage(String::new(), false, true),
            jump_host_password: secret_change_for_usage("ignored".to_owned(), false, false),
            jump_host_key_passphrase: secret_change_for_usage(
                "also-ignored".to_owned(),
                false,
                false,
            ),
        };
        assert!(matches!(changes.password, SecretChange::Replace(_)));
        assert!(matches!(changes.key_passphrase, SecretChange::Keep));
        assert!(matches!(changes.jump_host_password, SecretChange::Remove));
        assert!(matches!(
            changes.jump_host_key_passphrase,
            SecretChange::Remove
        ));
        assert!(!format!("{changes:?}").contains("never-print-this"));
    }

    #[test]
    fn advanced_paths_metadata_and_tags_fail_closed() {
        let absolute = std::env::temp_dir().join("lovelyres-test-key");
        assert_eq!(
            required_absolute_path(&absolute.to_string_lossy(), "SSH 私钥").unwrap(),
            absolute
        );
        assert!(required_absolute_path("relative/id_ed25519", "SSH 私钥").is_err());
        assert!(optional_fingerprint("SHA256:agent", "Agent").is_ok());
        assert!(optional_fingerprint("MD5:legacy", "Agent").is_err());
        assert!(optional_text("prod\nother", "环境", 32).is_err());

        let tags = parse_tags("linux, critical，linux").unwrap();
        assert_eq!(tags.len(), 2);
        assert!(tags.contains("critical"));
        let too_many_tags = (0..21)
            .map(|index| format!("tag-{index}"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(parse_tags(&too_many_tags).is_err());
    }

    #[test]
    fn jump_host_pin_survives_only_the_same_endpoint() {
        let jump = JumpHostConfig {
            host: "jump.example.test".to_owned(),
            port: 22,
            username: "root".to_owned(),
            auth_method: SshAuthMethod::Agent,
            private_key_path: None,
            certificate_path: None,
            agent_identity_fingerprint: None,
            host_key_fingerprint: Some("SHA256:jump".to_owned()),
        };
        assert_eq!(
            preserved_jump_host_key_fingerprint(Some(&jump), "jump.example.test", 22).as_deref(),
            Some("SHA256:jump")
        );
        assert!(
            preserved_jump_host_key_fingerprint(Some(&jump), "other.example.test", 22).is_none()
        );
        assert!(
            preserved_jump_host_key_fingerprint(Some(&jump), "jump.example.test", 2222).is_none()
        );
    }

    #[test]
    fn inactive_authentication_secrets_are_removed_not_silently_retained() {
        assert!(matches!(
            secret_change_for_usage("old-password".to_owned(), false, false),
            SecretChange::Remove
        ));
        assert!(matches!(
            secret_change_for_usage(String::new(), false, true),
            SecretChange::Keep
        ));
        assert!(secret_will_exist("new-password", false, false));
        assert!(secret_will_exist("", true, false));
        assert!(!secret_will_exist("new-password", true, true));
    }

    #[test]
    fn host_key_confirmation_is_bound_to_the_exact_scope_and_fingerprint() {
        let mut confirmations = HostKeyConfirmations::default();
        apply_host_key_confirmation(&mut confirmations, SshHostRole::Target, "SHA256:target");
        apply_host_key_confirmation(&mut confirmations, SshHostRole::JumpHost, "SHA256:jump");
        assert_eq!(
            confirmations.target_fingerprint.as_deref(),
            Some("SHA256:target")
        );
        assert_eq!(
            confirmations.jump_host_fingerprint.as_deref(),
            Some("SHA256:jump")
        );
    }

    #[test]
    fn keyboard_interactive_retries_keep_host_keys_and_bind_responses_to_role() {
        let mut authorization = SshConnectAuthorization::default();
        apply_host_key_confirmation(
            authorization.host_keys_mut(),
            SshHostRole::Target,
            "SHA256:target",
        );
        apply_host_key_confirmation(
            authorization.host_keys_mut(),
            SshHostRole::JumpHost,
            "SHA256:jump",
        );
        let first = SshKeyboardInteractiveChallenge {
            role: SshHostRole::Target,
            host: "target.test".to_owned(),
            port: 22,
            username: "operator".to_owned(),
            name: "MFA".to_owned(),
            instructions: "Enter both factors".to_owned(),
            prompts: vec![lovelyres_core::SshKeyboardInteractivePrompt {
                prompt: "Password: ".to_owned(),
                echo: false,
            }],
            supplied_responses: 0,
        };
        apply_keyboard_interactive_responses(
            &mut authorization,
            &first,
            vec!["password-never-log".to_owned()],
        )
        .unwrap();
        let second = SshKeyboardInteractiveChallenge {
            supplied_responses: 1,
            prompts: vec![lovelyres_core::SshKeyboardInteractivePrompt {
                prompt: "OTP: ".to_owned(),
                echo: false,
            }],
            ..first
        };
        apply_keyboard_interactive_responses(
            &mut authorization,
            &second,
            vec!["123456-never-log".to_owned()],
        )
        .unwrap();

        assert_eq!(
            authorization.keyboard_interactive_response_count(SshHostRole::Target),
            2
        );
        assert_eq!(
            authorization.keyboard_interactive_response_count(SshHostRole::JumpHost),
            0
        );
        assert_eq!(
            authorization.host_keys().target_fingerprint.as_deref(),
            Some("SHA256:target")
        );
        assert_eq!(
            authorization.host_keys().jump_host_fingerprint.as_deref(),
            Some("SHA256:jump")
        );
        let debug = format!("{authorization:?}");
        assert!(!debug.contains("password-never-log"));
        assert!(!debug.contains("123456-never-log"));
    }

    #[test]
    fn keyboard_interactive_challenge_mismatch_has_no_partial_response_mutation() {
        let mut authorization = SshConnectAuthorization::default();
        let challenge = SshKeyboardInteractiveChallenge {
            role: SshHostRole::Target,
            host: "target.test".to_owned(),
            port: 22,
            username: "operator".to_owned(),
            name: String::new(),
            instructions: String::new(),
            prompts: vec![lovelyres_core::SshKeyboardInteractivePrompt {
                prompt: "OTP: ".to_owned(),
                echo: false,
            }],
            supplied_responses: 1,
        };
        assert!(
            apply_keyboard_interactive_responses(
                &mut authorization,
                &challenge,
                vec!["must-not-stick".to_owned()],
            )
            .is_err()
        );
        assert_eq!(
            authorization.keyboard_interactive_response_count(SshHostRole::Target),
            0
        );
        assert!(auth_methods().contains(&SshAuthMethod::KeyboardInteractive));
    }

    #[test]
    fn probe_attempt_keeps_only_a_redacted_core_plan_between_authentication_retries() {
        use lovelyres_core::PortableStore;
        use lovelyres_core::connections::ConnectionRepository;
        use lovelyres_core::crypto::CryptoVault;

        let root = std::env::temp_dir().join(format!(
            "lovelyres-gpui-connection-probe-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let store = PortableStore::prepare(root.clone()).unwrap();
        let crypto = Arc::new(CryptoVault::load(&store).unwrap());
        let repository = ConnectionRepository::new(store, crypto);
        let mut draft = ConnectionDraft::new();
        draft.name = "Unsaved probe".to_owned();
        draft.host = "127.0.0.1".to_owned();
        draft.username = "operator".to_owned();
        let plan = repository
            .prepare_probe(
                draft.build().unwrap(),
                ConnectionSecretChanges {
                    password: SecretChange::Replace(SecretValue::new("never-render-probe")),
                    ..ConnectionSecretChanges::default()
                },
            )
            .unwrap();
        let attempt = ConnectAttempt {
            generation: 7,
            intent: ConnectIntent::Probe {
                plan: Box::new(plan),
            },
            authorization: SshConnectAuthorization::default(),
        };

        assert!(attempt.is_probe());
        assert!(!attempt.connection_id().is_empty());
        assert!(!format!("{attempt:?}").contains("never-render-probe"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn connection_editor_probe_is_wired_without_persisting_before_the_test() {
        let source = include_str!("connection_ui.rs");
        let start = source.find("fn begin_probe(").unwrap();
        let end = source[start..]
            .find("fn launch_connect(")
            .map(|offset| start + offset)
            .unwrap();
        let body = &source[start..end];
        assert!(body.contains("prepare_probe(config, changes)"));
        assert!(!body.contains(".upsert("));
        for required in [
            "connection-editor-probe",
            "probe_authorized(&plan, authorization)",
            "commit_probe(plan)",
            "保存已测试配置",
        ] {
            assert!(
                source.contains(required),
                "missing probe wiring: {required}"
            );
        }
    }
}
