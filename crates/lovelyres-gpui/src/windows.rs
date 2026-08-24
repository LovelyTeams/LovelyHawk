use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use gpui::{
    App, Bounds, ClipboardItem, Context, Entity, Focusable, Render, SharedString, Subscription,
    TitlebarOptions, Window, WindowBounds, WindowOptions, div, prelude::*, px, size,
};
use gpui_component::{
    Icon, IconName,
    input::{Input, InputEvent, InputState},
    scroll::ScrollableElement,
};
use lovelyres_core::ai::{
    AiCompletionRequest, AiMessage, AiMessageRole, AiProviderId, AiStreamCancellation, AiStreamId,
    AiStreamRequest,
};
use lovelyres_core::docker::ContainerIdentity;
use lovelyres_core::events::{
    AiStreamEvent, AiStreamEventKind, TerminalEvent as CoreTerminalEvent, TerminalEventKind,
    TerminalTransport as CoreTerminalTransport,
};
use lovelyres_core::sftp::RemotePath;
use lovelyres_core::ssh::{BoundSshSession, SshTerminalSession};
use lovelyres_core::types::{BashEnvironmentInfo, CommandCompletion as CoreCommandCompletion};
use lovelyres_core::{BackendServices, CoreError, target::TargetGuard};
use lovelyres_terminal::{
    RemoteCompletion, SearchOptions, TabDirection, TerminalAiState, TerminalAiToken,
    TerminalConfig, TerminalModel, TerminalPalette, TerminalPane, TerminalPaneEvent,
    TerminalShortcut, TerminalSize, TerminalTabId, TerminalTabState, TerminalTabToken,
    TerminalTransport as PaneTerminalTransport, TerminalTransportError, TerminalWorkspace,
};
use parking_lot::Mutex;
use uuid::Uuid;

#[cfg(target_os = "windows")]
use gpui::MouseButton;
#[cfg(target_os = "windows")]
use raw_window_handle::{HasWindowHandle, RawWindowHandle};
#[cfg(target_os = "windows")]
use windows::Win32::{
    Foundation::{HWND, LPARAM, WPARAM},
    UI::{
        Input::KeyboardAndMouse::ReleaseCapture,
        WindowsAndMessaging::{HTCAPTION, PostMessageW, SC_MOVE, WM_SYSCOMMAND},
    },
};

use crate::{
    app::SharedAppState,
    runtime::TokioBridge,
    sftp::{SftpNavigator, SftpWindow, SftpWindowEvent},
    theme::ThemeTokens,
};

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContainerTerminalWindowKey {
    target_identity: Arc<str>,
    target_generation: u64,
    container: Arc<str>,
}

impl ContainerTerminalWindowKey {
    pub fn new(session: &BoundSshSession, container: &ContainerIdentity) -> Self {
        Self::from_guard(session.target(), container)
    }

    pub(crate) fn from_guard(guard: &TargetGuard, container: &ContainerIdentity) -> Self {
        Self {
            target_identity: Arc::from(guard.identity.as_str()),
            target_generation: guard.generation,
            container: Arc::from(container.stable_key()),
        }
    }

    pub fn target_identity(&self) -> &str {
        &self.target_identity
    }

    pub const fn target_generation(&self) -> u64 {
        self.target_generation
    }

    pub fn container(&self) -> &str {
        &self.container
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum NativeWindowKind {
    Main,
    SshTerminal,
    Sftp,
    ContainerTerminal(ContainerTerminalWindowKey),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowLifecycle {
    Opening,
    Open,
    Closing,
    Closed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowTicket {
    pub kind: NativeWindowKind,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WindowRecord {
    lifecycle: WindowLifecycle,
    generation: u64,
}

impl WindowLifecycle {
    fn label(self) -> &'static str {
        match self {
            Self::Opening => "正在打开",
            Self::Open => "已打开",
            Self::Closing => "正在关闭",
            Self::Closed => "已关闭",
        }
    }
}

#[derive(Clone, Debug)]
pub struct NativeWindowRegistry {
    states: BTreeMap<NativeWindowKind, WindowRecord>,
    next_generation: u64,
}

impl Default for NativeWindowRegistry {
    fn default() -> Self {
        Self {
            states: BTreeMap::from([(
                NativeWindowKind::Main,
                WindowRecord {
                    lifecycle: WindowLifecycle::Open,
                    generation: 1,
                },
            )]),
            next_generation: 1,
        }
    }
}

impl NativeWindowRegistry {
    pub fn lifecycle(&self, kind: &NativeWindowKind) -> Option<WindowLifecycle> {
        self.states.get(kind).map(|record| record.lifecycle)
    }

    /// Reserves a fixed native-window identity and rejects duplicate opens.
    pub fn begin_open(&mut self, kind: NativeWindowKind) -> Option<WindowTicket> {
        if self
            .lifecycle(&kind)
            .is_some_and(|state| state != WindowLifecycle::Closed)
        {
            return None;
        }
        let generation = self.bump_generation();
        self.states.insert(
            kind.clone(),
            WindowRecord {
                lifecycle: WindowLifecycle::Opening,
                generation,
            },
        );
        Some(WindowTicket { kind, generation })
    }

    pub fn is_current(&self, ticket: &WindowTicket) -> bool {
        self.states.get(&ticket.kind).is_some_and(|record| {
            record.generation == ticket.generation
                && matches!(
                    record.lifecycle,
                    WindowLifecycle::Opening | WindowLifecycle::Open
                )
        })
    }

    pub fn mark_open(&mut self, ticket: &WindowTicket) -> bool {
        let Some(record) = self.states.get_mut(&ticket.kind) else {
            return false;
        };
        if record.generation != ticket.generation || record.lifecycle != WindowLifecycle::Opening {
            return false;
        }
        record.lifecycle = WindowLifecycle::Open;
        true
    }

    pub fn begin_close(&mut self, kind: &NativeWindowKind) {
        if self.lifecycle(kind) == Some(WindowLifecycle::Open) {
            let generation = self.bump_generation();
            self.states.insert(
                kind.clone(),
                WindowRecord {
                    lifecycle: WindowLifecycle::Closing,
                    generation,
                },
            );
        }
    }

    pub fn mark_closed(&mut self, kind: &NativeWindowKind) {
        let generation = self.bump_generation();
        self.states.insert(
            kind.clone(),
            WindowRecord {
                lifecycle: WindowLifecycle::Closed,
                generation,
            },
        );
    }

    fn bump_generation(&mut self) -> u64 {
        self.next_generation = self.next_generation.saturating_add(1);
        self.next_generation
    }
}

#[derive(Debug)]
pub struct SshTerminalTransportAdapter {
    session: Arc<SshTerminalSession>,
    services: Arc<BackendServices>,
    guard: TargetGuard,
}

impl SshTerminalTransportAdapter {
    pub fn new(
        session: Arc<SshTerminalSession>,
        services: Arc<BackendServices>,
        guard: TargetGuard,
    ) -> Self {
        Self {
            session,
            services,
            guard,
        }
    }
}

#[async_trait]
impl PaneTerminalTransport for SshTerminalTransportAdapter {
    async fn send_input(&self, bytes: &[u8]) -> Result<(), TerminalTransportError> {
        self.services
            .run_guarded(&self.guard, || async {
                CoreTerminalTransport::write_input(self.session.as_ref(), bytes.to_vec()).await
            })
            .await
            .map_err(terminal_transport_error)
    }

    async fn resize(&self, size: TerminalSize) -> Result<(), TerminalTransportError> {
        self.services
            .run_guarded(&self.guard, || async {
                CoreTerminalTransport::resize(self.session.as_ref(), size.columns, size.rows).await
            })
            .await
            .map_err(terminal_transport_error)
    }

    async fn close(&self) -> Result<(), TerminalTransportError> {
        CoreTerminalTransport::close(self.session.as_ref())
            .await
            .map_err(terminal_transport_error)
    }
}

pub(crate) fn terminal_transport_error(error: CoreError) -> TerminalTransportError {
    match error {
        CoreError::ChannelClosed { .. } => TerminalTransportError::Closed,
        error => TerminalTransportError::Other(error.to_string()),
    }
}

#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct TerminalBatchOutcome {
    pub(crate) output: Vec<u8>,
    pub(crate) last_sequence: u64,
    pub(crate) title: Option<String>,
    pub(crate) terminal_state: Option<TerminalTabState>,
    pub(crate) protocol_error: Option<String>,
}

pub(crate) fn reduce_terminal_batch(
    terminal_id: &str,
    previous_sequence: u64,
    events: Vec<CoreTerminalEvent>,
) -> TerminalBatchOutcome {
    let mut outcome = TerminalBatchOutcome {
        last_sequence: previous_sequence,
        ..TerminalBatchOutcome::default()
    };
    for event in events {
        let expected = outcome.last_sequence.saturating_add(1);
        if event.session_id != terminal_id {
            outcome.protocol_error = Some(format!(
                "终端事件归属错误：期望 {terminal_id}，收到 {}",
                event.session_id
            ));
        } else if event.sequence != expected {
            outcome.protocol_error = Some(format!(
                "终端事件序列不连续：期望 {expected}，收到 {}",
                event.sequence
            ));
        }
        outcome.last_sequence = event.sequence;
        match event.kind {
            TerminalEventKind::Output(bytes) => outcome.output.extend(bytes),
            TerminalEventKind::TitleChanged(title) => outcome.title = Some(title),
            TerminalEventKind::Bell => {}
            TerminalEventKind::Exited { exit_code } => {
                outcome.terminal_state = Some(TerminalTabState::Closed { exit_code });
            }
            TerminalEventKind::Failed { message } => {
                outcome.terminal_state = Some(TerminalTabState::Failed(message));
            }
        }
    }
    outcome
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TerminalPaneAdapterSlot {
    /// A real `Arc<dyn TerminalTransport>` will replace this state once the
    /// core SSH/container service exists. No synthetic transport is created.
    AwaitingTransport,
    Attached,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshTerminalBody {
    pub connection_id: Option<Arc<str>>,
    pub terminal: TerminalPaneAdapterSlot,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SftpBody {
    pub connection_id: Option<Arc<str>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainerTerminalBody {
    pub container_id: Arc<str>,
    pub terminal: TerminalPaneAdapterSlot,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeWindowBody {
    Main,
    Ssh(SshTerminalBody),
    Sftp(SftpBody),
    Container(ContainerTerminalBody),
}

impl From<&NativeWindowKind> for NativeWindowBody {
    fn from(kind: &NativeWindowKind) -> Self {
        match kind {
            NativeWindowKind::Main => Self::Main,
            NativeWindowKind::SshTerminal => Self::Ssh(SshTerminalBody {
                connection_id: None,
                terminal: TerminalPaneAdapterSlot::AwaitingTransport,
            }),
            NativeWindowKind::Sftp => Self::Sftp(SftpBody {
                connection_id: None,
            }),
            NativeWindowKind::ContainerTerminal(key) => Self::Container(ContainerTerminalBody {
                container_id: Arc::from(key.container()),
                terminal: TerminalPaneAdapterSlot::AwaitingTransport,
            }),
        }
    }
}

impl NativeWindowKind {
    pub fn title(&self) -> SharedString {
        match self {
            Self::Main => "LovelyRes".into(),
            Self::SshTerminal => "LovelyRes · SSH Terminal".into(),
            Self::Sftp => "LovelyRes · SFTP".into(),
            Self::ContainerTerminal(key) => {
                format!("LovelyRes · Container {}", key.container()).into()
            }
        }
    }
}

pub fn main_window_options(cx: &App) -> WindowOptions {
    WindowOptions {
        window_bounds: Some(WindowBounds::Windowed(Bounds::centered(
            None,
            size(px(1200.0), px(800.0)),
            cx,
        ))),
        window_min_size: Some(size(px(960.0), px(640.0))),
        titlebar: Some(TitlebarOptions {
            title: Some("LovelyRes".into()),
            appears_transparent: true,
            ..Default::default()
        }),
        app_id: Some("com.lovelyres.native".to_owned()),
        ..Default::default()
    }
}

pub fn secondary_window_options(kind: &NativeWindowKind, cx: &App) -> WindowOptions {
    WindowOptions {
        window_bounds: Some(WindowBounds::Windowed(Bounds::centered(
            None,
            size(px(1040.0), px(720.0)),
            cx,
        ))),
        window_min_size: Some(size(px(760.0), px(520.0))),
        titlebar: Some(TitlebarOptions {
            title: Some(kind.title()),
            appears_transparent: true,
            ..Default::default()
        }),
        app_id: Some("com.lovelyres.native".to_owned()),
        ..Default::default()
    }
}

struct TerminalTabRuntime {
    token: TerminalTabToken,
    terminal_id: String,
    directory: Option<RemotePath>,
    last_sequence: u64,
    model: Arc<Mutex<TerminalModel>>,
    pane: Entity<TerminalPane>,
    _session: Arc<SshTerminalSession>,
    _pane_subscription: Subscription,
}

struct TerminalOpenCompletion {
    terminal_id: String,
    directory: Option<RemotePath>,
    result: Result<Result<SshTerminalSession, CoreError>, tokio::task::JoinError>,
}

enum PtyPumpMessage {
    Batch(Vec<CoreTerminalEvent>),
    Failed(String),
}

enum AiPumpMessage {
    Started(AiStreamCancellation),
    Event(AiStreamEvent),
    Failed(String),
}

pub struct SecondaryWindow {
    ticket: WindowTicket,
    kind: NativeWindowKind,
    body: NativeWindowBody,
    shared: Entity<SharedAppState>,
    services: Arc<BackendServices>,
    tokio: Arc<TokioBridge>,
    sftp_window: Option<Entity<SftpWindow>>,
    terminal_workspace: TerminalWorkspace,
    terminal_tabs: BTreeMap<TerminalTabId, TerminalTabRuntime>,
    terminal_config: TerminalConfig,
    terminal_palette: TerminalPalette,
    bound_session: Option<BoundSshSession>,
    bound_guard: Option<TargetGuard>,
    search_input: Entity<InputState>,
    ai_input: Entity<InputState>,
    ai_cancellation: Option<(TerminalAiToken, AiStreamCancellation)>,
    ai_last_sequence: u64,
    bash_environment: Option<BashEnvironmentInfo>,
    bash_environment_error: Option<SharedString>,
    environment_generation: u64,
    completion_generation: u64,
    remote_completion_enabled: bool,
    notice: Option<SharedString>,
    focus_terminal_requested: Option<TerminalTabId>,
    focus_search_requested: bool,
    focus_ai_requested: bool,
    _input_subscriptions: Vec<Subscription>,
    _release_subscription: Subscription,
}

impl SecondaryWindow {
    pub fn new(
        ticket: WindowTicket,
        shared: Entity<SharedAppState>,
        services: Arc<BackendServices>,
        tokio: Arc<TokioBridge>,
        sftp_navigator: Entity<SftpNavigator>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let kind = ticket.kind.clone();
        let settings = services.settings().load().unwrap_or_default();
        let terminal_config = TerminalConfig {
            font_family: settings.terminal_font,
            font_size: f32::from(settings.terminal_font_size),
            ..TerminalConfig::default()
        };
        let terminal_workspace = TerminalWorkspace::new(terminal_config.font_size);
        let remote_completion_enabled =
            settings.notifications.enabled && settings.notifications.command_completion;
        let terminal_palette = palette_for_tokens(shared.read(cx).theme.tokens());
        let search_input = cx.new(|cx| InputState::new(window, cx).placeholder("搜索终端历史…"));
        let ai_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("询问当前终端（Enter 发送）…"));
        let mut input_subscriptions = vec![
            cx.subscribe_in(
                &search_input,
                window,
                |secondary, input, event: &InputEvent, _, cx| {
                    secondary.on_search_input(input, event, cx);
                },
            ),
            cx.subscribe_in(
                &ai_input,
                window,
                |secondary, input, event: &InputEvent, window, cx| {
                    secondary.on_ai_input(input, event, window, cx);
                },
            ),
        ];
        let sftp_window = (kind == NativeWindowKind::Sftp).then(|| {
            cx.new(|cx| {
                SftpWindow::new(
                    services.clone(),
                    tokio.clone(),
                    shared.clone(),
                    sftp_navigator,
                    window,
                    cx,
                )
            })
        });
        if let Some(sftp_window) = &sftp_window {
            input_subscriptions.push(cx.subscribe_in(
                sftp_window,
                window,
                |secondary, _, event: &SftpWindowEvent, _, cx| {
                    secondary.on_sftp_window_event(event, cx);
                },
            ));
            sftp_window.update(cx, |sftp, cx| sftp.activate(window, cx));
        }
        cx.observe(&shared, |secondary, _, cx| {
            secondary.maybe_open_terminal(cx);
            cx.notify();
        })
        .detach();
        shared.update(cx, |state, cx| {
            state.windows.mark_open(&ticket);
            cx.notify();
        });
        let closing_shared = shared.clone();
        let closing_kind = kind.clone();
        window.on_window_should_close(cx, move |_, cx| {
            closing_shared.update(cx, |state, cx| {
                state.windows.begin_close(&closing_kind);
                cx.notify();
            });
            true
        });
        let release_subscription = cx.on_release(|secondary: &mut Self, cx| {
            secondary.close_all_terminals_on_release(cx);
            if let Some(sftp_window) = &secondary.sftp_window {
                sftp_window.update(cx, |sftp, cx| sftp.deactivate(cx));
            }
            secondary.shared.update(cx, |state, cx| {
                state.windows.mark_closed(&secondary.kind);
                cx.notify();
            });
        });
        let body = NativeWindowBody::from(&kind);
        let mut secondary = Self {
            ticket,
            kind,
            body,
            shared,
            services,
            tokio,
            sftp_window,
            terminal_workspace,
            terminal_tabs: BTreeMap::new(),
            terminal_config,
            terminal_palette,
            bound_session: None,
            bound_guard: None,
            search_input,
            ai_input,
            ai_cancellation: None,
            ai_last_sequence: 0,
            bash_environment: None,
            bash_environment_error: None,
            environment_generation: 0,
            completion_generation: 0,
            remote_completion_enabled,
            notice: None,
            focus_terminal_requested: None,
            focus_search_requested: false,
            focus_ai_requested: false,
            _input_subscriptions: input_subscriptions,
            _release_subscription: release_subscription,
        };
        secondary.maybe_open_terminal(cx);
        secondary
    }

    fn request_close(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.close_all_terminals(cx);
        if let Some(sftp_window) = &self.sftp_window {
            sftp_window.update(cx, |sftp, cx| sftp.deactivate(cx));
        }
        self.shared.update(cx, |state, cx| {
            state.windows.begin_close(&self.kind);
            cx.notify();
        });
        window.remove_window();
    }

    fn on_sftp_window_event(&mut self, event: &SftpWindowEvent, cx: &mut Context<Self>) {
        let SftpWindowEvent::OpenDirectoryTerminal(intent) = event;
        let accepted = self.kind == NativeWindowKind::Sftp
            && self.services.target().validate(&intent.target).is_ok()
            && self
                .shared
                .read(cx)
                .active_ssh
                .as_ref()
                .is_some_and(|active| active.session.target() == &intent.target);
        let queued = accepted
            && self.shared.update(cx, |state, cx| {
                let queued = state.queue_directory_terminal(intent.clone());
                if queued {
                    cx.notify();
                }
                queued
            });
        let (message, error) = if queued {
            (
                format!("已发送到 SSH 终端：{}", intent.path.as_str()),
                false,
            )
        } else if accepted {
            ("待打开的目录终端请求过多，请稍后重试".to_owned(), true)
        } else {
            ("目标已切换，已拒绝打开目录终端".to_owned(), true)
        };
        if let Some(sftp) = self.sftp_window.clone() {
            sftp.update(cx, |sftp, cx| {
                sftp.report_directory_terminal_request(message, error, cx)
            });
        }
    }

    fn maybe_open_terminal(&mut self, cx: &mut Context<Self>) {
        if self.kind != NativeWindowKind::SshTerminal {
            return;
        }
        let (active, ticket_is_current) = {
            let shared = self.shared.read(cx);
            (
                shared.active_ssh.clone(),
                shared.windows.is_current(&self.ticket),
            )
        };
        if !ticket_is_current {
            self.close_all_terminals(cx);
            return;
        }
        let Some(active) = active else {
            if self.bound_guard.is_some() || !self.terminal_workspace.tabs().is_empty() {
                self.close_all_terminals(cx);
            }
            self.bound_session = None;
            self.bound_guard = None;
            self.set_ssh_body(None, TerminalPaneAdapterSlot::AwaitingTransport);
            return;
        };
        let guard = active.session.target().clone();
        let same_binding = self.bound_guard.as_ref() == Some(&guard)
            && self.bound_session.as_ref() == Some(&active.session);
        if same_binding {
            let requests = self.take_directory_terminal_requests(&guard, cx);
            if requests.is_empty() && self.terminal_workspace.tabs().is_empty() {
                self.open_new_tab(cx);
            } else {
                for request in requests {
                    self.open_directory_tab(request.path, cx);
                }
            }
            return;
        }
        self.close_all_terminals(cx);
        self.bound_guard = Some(guard.clone());
        self.bound_session = Some(active.session);
        self.set_ssh_body(
            Some(active.connection_id),
            TerminalPaneAdapterSlot::AwaitingTransport,
        );
        if let Err(error) = self.services.target().validate(&guard) {
            self.notice = Some(format!("目标校验失败：{error}").into());
            return;
        }
        if let Some(bound) = self.bound_session.clone() {
            self.request_bash_environment(bound, guard.clone(), cx);
        }
        let requests = self.take_directory_terminal_requests(&guard, cx);
        if requests.is_empty() {
            self.open_new_tab(cx);
        } else {
            for request in requests {
                self.open_directory_tab(request.path, cx);
            }
        }
    }

    fn take_directory_terminal_requests(
        &mut self,
        guard: &TargetGuard,
        cx: &mut Context<Self>,
    ) -> Vec<crate::sftp::OpenDirectoryTerminalIntent> {
        self.shared.update(cx, |state, cx| {
            let requests = state.take_directory_terminals_for(guard);
            if !requests.is_empty() {
                cx.notify();
            }
            requests
        })
    }

    fn request_bash_environment(
        &mut self,
        bound: BoundSshSession,
        guard: TargetGuard,
        cx: &mut Context<Self>,
    ) {
        self.environment_generation = self.environment_generation.saturating_add(1);
        let generation = self.environment_generation;
        self.bash_environment = None;
        self.bash_environment_error = None;
        let services = self.services.clone();
        let ssh = self.services.ssh().clone();
        let task_guard = guard.clone();
        let task = self.tokio.spawn(async move {
            services
                .run_guarded(&task_guard, || async {
                    ssh.bash_environment_bound(&bound).await
                })
                .await
        });
        let ticket = self.ticket.clone();
        cx.spawn(async move |secondary, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                let Some(secondary) = secondary.upgrade() else {
                    return;
                };
                secondary.update(cx, |secondary, cx| {
                    if secondary.environment_generation != generation
                        || secondary.bound_guard.as_ref() != Some(&guard)
                        || secondary.services.target().validate(&guard).is_err()
                        || !secondary.shared.read(cx).windows.is_current(&ticket)
                    {
                        return;
                    }
                    match result {
                        Ok(Ok(environment)) => {
                            secondary.bash_environment = Some(environment);
                            secondary.bash_environment_error = None;
                        }
                        Ok(Err(error)) => {
                            secondary.bash_environment_error =
                                Some(format!("shell 环境探测失败：{error}").into());
                        }
                        Err(error) => {
                            secondary.bash_environment_error =
                                Some(format!("shell 环境任务异常：{error}").into());
                        }
                    }
                    cx.notify();
                });
            });
        })
        .detach();
    }

    fn open_new_tab(&mut self, cx: &mut Context<Self>) {
        let (Some(bound), Some(guard)) = (self.bound_session.clone(), self.bound_guard.clone())
        else {
            self.notice = Some("请先在主窗口连接 SSH 目标".into());
            cx.notify();
            return;
        };
        if let Err(error) = self.services.target().validate(&guard) {
            self.notice = Some(format!("目标已切换：{error}").into());
            cx.notify();
            return;
        }
        let label = format!("Shell {}", self.terminal_workspace.tabs().len() + 1);
        let token = self.terminal_workspace.open_tab(label);
        self.spawn_terminal_open(token, bound, guard, None, cx);
        cx.notify();
    }

    fn open_directory_tab(&mut self, directory: RemotePath, cx: &mut Context<Self>) {
        let (Some(bound), Some(guard)) = (self.bound_session.clone(), self.bound_guard.clone())
        else {
            self.notice = Some("请先在主窗口连接 SSH 目标".into());
            cx.notify();
            return;
        };
        if self.services.target().validate(&guard).is_err() {
            self.notice = Some("目标已切换，目录终端未打开".into());
            cx.notify();
            return;
        }
        let token = self
            .terminal_workspace
            .open_tab(directory_terminal_label(&directory));
        self.spawn_terminal_open(token, bound, guard, Some(directory), cx);
        cx.notify();
    }

    fn spawn_terminal_open(
        &mut self,
        token: TerminalTabToken,
        bound_session: BoundSshSession,
        guard: TargetGuard,
        directory: Option<RemotePath>,
        cx: &mut Context<Self>,
    ) {
        if !self.terminal_workspace.contains(token)
            || self.services.target().validate(&guard).is_err()
        {
            let _ = self
                .terminal_workspace
                .mark_failed(token, "目标在终端发送前已切换");
            return;
        }
        let terminal_id = Uuid::new_v4().to_string();
        let ssh = self.services.ssh().clone();
        let sftp = self.services.sftp().clone();
        let task_terminal_id = terminal_id.clone();
        let task_guard = guard.clone();
        let launch_directory = directory.clone();
        let task = self.tokio.spawn(async move {
            if let Some(directory) = directory {
                let session = sftp
                    .bind_session(task_guard, bound_session.session_id())
                    .await?;
                sftp.open_directory_terminal(
                    &session,
                    &directory,
                    task_terminal_id,
                    TerminalSize::default().columns,
                    TerminalSize::default().rows,
                )
                .await
            } else {
                ssh.open_terminal_bound(
                    &bound_session,
                    task_terminal_id,
                    TerminalSize::default().columns,
                    TerminalSize::default().rows,
                )
                .await
            }
        });
        let ticket = self.ticket.clone();
        let tokio = self.tokio.clone();
        cx.spawn(async move |secondary, cx| {
            let mut completion = Some(TerminalOpenCompletion {
                terminal_id,
                directory: launch_directory,
                result: task.await,
            });
            let applied = cx
                .update(|cx| {
                    let Some(secondary) = secondary.upgrade() else {
                        return false;
                    };
                    secondary.update(cx, |secondary, cx| {
                        secondary.finish_open_terminal(
                            ticket,
                            guard,
                            token,
                            completion
                                .take()
                                .expect("terminal open result is consumed once"),
                            cx,
                        );
                    });
                    true
                })
                .unwrap_or(false);
            if !applied
                && let Some(TerminalOpenCompletion {
                    result: Ok(Ok(session)),
                    ..
                }) = completion
            {
                drop(tokio.spawn(async move {
                    if let Err(error) = CoreTerminalTransport::close(&session).await {
                        tracing::error!(%error, "failed to close terminal after window release");
                    }
                }));
            }
        })
        .detach();
    }

    fn finish_open_terminal(
        &mut self,
        ticket: WindowTicket,
        guard: TargetGuard,
        token: TerminalTabToken,
        completion: TerminalOpenCompletion,
        cx: &mut Context<Self>,
    ) {
        let TerminalOpenCompletion {
            terminal_id,
            directory,
            result,
        } = completion;
        let current = self.shared.read(cx).windows.is_current(&ticket)
            && self.bound_guard.as_ref() == Some(&guard)
            && self.terminal_workspace.contains(token)
            && self.services.target().validate(&guard).is_ok();
        if !current {
            if let Ok(Ok(session)) = result {
                self.close_detached_terminal(session);
            }
            return;
        }
        let session = match result {
            Ok(Ok(session)) => Arc::new(session),
            Ok(Err(error)) => {
                let _ = self
                    .terminal_workspace
                    .mark_failed(token, error.to_string());
                cx.notify();
                return;
            }
            Err(error) => {
                let _ = self
                    .terminal_workspace
                    .mark_failed(token, format!("终端打开任务异常结束：{error}"));
                cx.notify();
                return;
            }
        };
        let mut config = self.terminal_config.clone();
        config.font_size = self.terminal_workspace.font_size();
        let model = match TerminalModel::new(config) {
            Ok(model) => Arc::new(Mutex::new(model)),
            Err(error) => {
                let _ = self
                    .terminal_workspace
                    .mark_failed(token, error.to_string());
                self.close_arc_terminal(session);
                cx.notify();
                return;
            }
        };
        let transport: Arc<dyn PaneTerminalTransport> = Arc::new(SshTerminalTransportAdapter::new(
            session.clone(),
            self.services.clone(),
            guard.clone(),
        ));
        let pane = cx.new(|cx| TerminalPane::new(model.clone(), transport, cx));
        pane.update(cx, |pane, cx| pane.set_palette(self.terminal_palette, cx));
        let tab_id = token.id;
        let pane_subscription = cx.subscribe(&pane, move |secondary, _, event, cx| {
            secondary.on_terminal_pane_event(tab_id, event, cx);
        });
        if !self.terminal_workspace.mark_open(token) {
            self.close_arc_terminal(session);
            return;
        }
        if let Some(stale) = self.terminal_tabs.remove(&tab_id) {
            stale.pane.update(cx, |pane, cx| {
                let _ = pane.close(cx);
            });
        }
        self.terminal_tabs.insert(
            tab_id,
            TerminalTabRuntime {
                token,
                terminal_id: terminal_id.clone(),
                directory,
                last_sequence: 0,
                model,
                pane,
                _session: session.clone(),
                _pane_subscription: pane_subscription,
            },
        );
        self.set_ssh_body(self.ssh_connection_id(), TerminalPaneAdapterSlot::Attached);
        self.start_terminal_event_pump(session, guard, token, terminal_id, cx);
        self.focus_terminal_requested = Some(tab_id);
        self.sync_search(cx);
        cx.notify();
    }

    fn start_terminal_event_pump(
        &self,
        session: Arc<SshTerminalSession>,
        guard: TargetGuard,
        token: TerminalTabToken,
        terminal_id: String,
        cx: &mut Context<Self>,
    ) {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(64);
        drop(self.tokio.spawn(async move {
            loop {
                let first = match session.recv().await {
                    Ok(event) => event,
                    Err(error) => {
                        let _ = sender.send(PtyPumpMessage::Failed(error.to_string())).await;
                        break;
                    }
                };
                tokio::time::sleep(Duration::from_millis(12)).await;
                let mut events =
                    Vec::with_capacity(session.events().len().saturating_add(1).min(4096));
                events.push(first);
                while events.len() < 4096 {
                    match session.events().try_recv() {
                        Ok(Some(event)) => events.push(event),
                        Ok(None) | Err(CoreError::ChannelClosed { .. }) => break,
                        Err(error) => {
                            let _ = sender.send(PtyPumpMessage::Failed(error.to_string())).await;
                            return;
                        }
                    }
                }
                let ended = events.iter().any(|event| {
                    matches!(
                        event.kind,
                        TerminalEventKind::Exited { .. } | TerminalEventKind::Failed { .. }
                    )
                });
                if sender.send(PtyPumpMessage::Batch(events)).await.is_err() || ended {
                    break;
                }
            }
        }));
        cx.spawn(async move |secondary, cx| {
            while let Some(message) = receiver.recv().await {
                let applied = cx
                    .update(|cx| {
                        let Some(secondary) = secondary.upgrade() else {
                            return false;
                        };
                        secondary.update(cx, |secondary, cx| match message {
                            PtyPumpMessage::Batch(events) => secondary.apply_terminal_batch(
                                &guard,
                                token,
                                &terminal_id,
                                events,
                                cx,
                            ),
                            PtyPumpMessage::Failed(error) => {
                                secondary.mark_event_stream_failed(&guard, token, error, cx)
                            }
                        })
                    })
                    .unwrap_or(false);
                if !applied {
                    break;
                }
            }
        })
        .detach();
    }

    fn apply_terminal_batch(
        &mut self,
        guard: &TargetGuard,
        token: TerminalTabToken,
        terminal_id: &str,
        events: Vec<CoreTerminalEvent>,
        cx: &mut Context<Self>,
    ) -> bool {
        if self.bound_guard.as_ref() != Some(guard)
            || !self.terminal_workspace.contains(token)
            || self.services.target().validate(guard).is_err()
            || !self.shared.read(cx).windows.is_current(&self.ticket)
        {
            return false;
        }
        let Some(runtime) = self.terminal_tabs.get_mut(&token.id) else {
            return false;
        };
        if runtime.token != token || runtime.terminal_id != terminal_id {
            return false;
        }
        let outcome = reduce_terminal_batch(terminal_id, runtime.last_sequence, events);
        runtime.last_sequence = outcome.last_sequence;
        if !outcome.output.is_empty() {
            runtime.model.lock().feed_output(&outcome.output);
        }
        let pane = runtime.pane.clone();
        if let Some(title) = outcome.title {
            let _ = self.terminal_workspace.set_title(token, title);
        }
        if let Some(state) = outcome.terminal_state {
            match state {
                TerminalTabState::Closed { exit_code } => {
                    let _ = self.terminal_workspace.mark_closed(token, exit_code);
                }
                TerminalTabState::Failed(error) => {
                    let _ = self.terminal_workspace.mark_failed(token, error);
                }
                TerminalTabState::Opening
                | TerminalTabState::Open
                | TerminalTabState::Reconnecting => {}
            }
        }
        if let Some(error) = outcome.protocol_error {
            let _ = self.terminal_workspace.mark_failed(token, error);
        }
        pane.update(cx, |pane, cx| pane.notify_output_changed(cx));
        self.sync_search(cx);
        cx.notify();
        true
    }

    fn mark_event_stream_failed(
        &mut self,
        guard: &TargetGuard,
        token: TerminalTabToken,
        error: String,
        cx: &mut Context<Self>,
    ) -> bool {
        if self.bound_guard.as_ref() != Some(guard)
            || self.services.target().validate(guard).is_err()
            || !self.shared.read(cx).windows.is_current(&self.ticket)
        {
            return false;
        }
        let applied = self.terminal_workspace.mark_failed(token, error);
        if applied {
            cx.notify();
        }
        applied
    }

    fn on_terminal_pane_event(
        &mut self,
        tab_id: TerminalTabId,
        event: &TerminalPaneEvent,
        cx: &mut Context<Self>,
    ) {
        if self.terminal_workspace.active_id() != Some(tab_id) {
            return;
        }
        match event {
            TerminalPaneEvent::SearchRequested => {
                self.terminal_workspace.search.show();
                self.focus_search_requested = true;
            }
            TerminalPaneEvent::Shortcut(shortcut) => self.handle_terminal_shortcut(*shortcut, cx),
            TerminalPaneEvent::LinkActivated(link) => {
                cx.write_to_clipboard(ClipboardItem::new_string(link.uri.clone()));
                self.notice = Some("远端链接已复制；安全策略未自动打开".into());
            }
            TerminalPaneEvent::InputChanged { line } => {
                self.request_remote_completion(tab_id, line.clone(), cx);
            }
        }
        cx.notify();
    }

    fn request_remote_completion(
        &mut self,
        tab_id: TerminalTabId,
        line: String,
        cx: &mut Context<Self>,
    ) {
        self.completion_generation = self.completion_generation.saturating_add(1);
        let generation = self.completion_generation;
        if !self.remote_completion_enabled || line.trim().is_empty() {
            return;
        }
        let Some(runtime) = self.terminal_tabs.get(&tab_id) else {
            return;
        };
        if !runtime.pane.read(cx).completion_is_reliable() {
            return;
        }
        let token = runtime.token;
        let (Some(bound), Some(guard)) = (self.bound_session.clone(), self.bound_guard.clone())
        else {
            return;
        };
        if self.services.target().validate(&guard).is_err() {
            return;
        }
        let services = self.services.clone();
        let ssh = self.services.ssh().clone();
        let task_line = line.clone();
        let task_guard = guard.clone();
        let task = self.tokio.spawn(async move {
            tokio::time::sleep(Duration::from_millis(140)).await;
            services
                .run_guarded(&task_guard, || async {
                    let shell = ssh
                        .shell_completion_bound(&bound, &task_line, task_line.len())
                        .await?;
                    let command = ssh
                        .command_completion_bound(&bound, &task_line, task_line.len())
                        .await?;
                    Ok(merge_core_completions(shell, command))
                })
                .await
        });
        let ticket = self.ticket.clone();
        cx.spawn(async move |secondary, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                let Some(secondary) = secondary.upgrade() else {
                    return;
                };
                secondary.update(cx, |secondary, cx| {
                    if secondary.completion_generation != generation
                        || secondary.bound_guard.as_ref() != Some(&guard)
                        || secondary.services.target().validate(&guard).is_err()
                        || !secondary.shared.read(cx).windows.is_current(&ticket)
                        || !secondary.terminal_workspace.contains(token)
                    {
                        return;
                    }
                    let Some(runtime) = secondary.terminal_tabs.get(&tab_id) else {
                        return;
                    };
                    if runtime.token != token
                        || runtime.pane.read(cx).current_input_line() != line
                        || !runtime.pane.read(cx).completion_is_reliable()
                    {
                        return;
                    }
                    match result {
                        Ok(Ok(completion)) => {
                            let remote = RemoteCompletion::new(
                                line,
                                completion.candidates,
                                completion.replacement_start,
                                completion.replacement_end,
                            );
                            runtime
                                .pane
                                .update(cx, |pane, cx| pane.set_remote_completion(remote, cx));
                        }
                        Ok(Err(error)) => {
                            tracing::debug!(%error, "remote terminal completion failed");
                        }
                        Err(error) => {
                            tracing::debug!(%error, "remote terminal completion task failed");
                        }
                    }
                });
            });
        })
        .detach();
    }

    fn handle_terminal_shortcut(&mut self, shortcut: TerminalShortcut, cx: &mut Context<Self>) {
        match shortcut {
            TerminalShortcut::NewTab => self.open_new_tab(cx),
            TerminalShortcut::CloseTab => self.close_active_tab(cx),
            TerminalShortcut::NextTab => self.cycle_tab(TabDirection::Next, cx),
            TerminalShortcut::PreviousTab => self.cycle_tab(TabDirection::Previous, cx),
            TerminalShortcut::Reconnect => self.reconnect_active_tab(cx),
            TerminalShortcut::FontIncrease => self.change_font_size(1.0, cx),
            TerminalShortcut::FontDecrease => self.change_font_size(-1.0, cx),
            TerminalShortcut::FontReset => {
                let size = self.terminal_config.font_size;
                self.set_font_size(size, cx);
            }
            TerminalShortcut::ToggleAi => self.toggle_ai(cx),
            TerminalShortcut::AcceptCompletion
            | TerminalShortcut::ScrollPageUp
            | TerminalShortcut::ScrollPageDown
            | TerminalShortcut::ScrollToTop
            | TerminalShortcut::ScrollToBottom => {}
        }
    }

    fn activate_tab(&mut self, id: TerminalTabId, cx: &mut Context<Self>) {
        if self.terminal_workspace.activate(id) {
            self.focus_terminal_requested = Some(id);
            self.sync_search(cx);
            cx.notify();
        }
    }

    fn cycle_tab(&mut self, direction: TabDirection, cx: &mut Context<Self>) {
        if let Some(id) = self.terminal_workspace.cycle(direction) {
            self.focus_terminal_requested = Some(id);
            self.sync_search(cx);
            cx.notify();
        }
    }

    fn close_active_tab(&mut self, cx: &mut Context<Self>) {
        let Some(id) = self.terminal_workspace.active_id() else {
            return;
        };
        self.close_tab(id, cx);
    }

    fn close_tab(&mut self, id: TerminalTabId, cx: &mut Context<Self>) {
        if self
            .terminal_workspace
            .ai
            .active()
            .is_some_and(|token| token.tab.id == id)
        {
            self.cancel_ai(cx);
        }
        if self.terminal_workspace.close_tab(id).is_none() {
            return;
        }
        if let Some(runtime) = self.terminal_tabs.remove(&id) {
            runtime.pane.update(cx, |pane, cx| {
                let _ = pane.close(cx);
            });
        }
        if self.terminal_workspace.tabs().is_empty() {
            self.set_ssh_body(
                self.ssh_connection_id(),
                TerminalPaneAdapterSlot::AwaitingTransport,
            );
        }
        self.focus_terminal_requested = self.terminal_workspace.active_id();
        self.sync_search(cx);
        cx.notify();
    }

    fn reconnect_active_tab(&mut self, cx: &mut Context<Self>) {
        let (Some(id), Some(bound), Some(guard)) = (
            self.terminal_workspace.active_id(),
            self.bound_session.clone(),
            self.bound_guard.clone(),
        ) else {
            return;
        };
        if self
            .terminal_workspace
            .ai
            .active()
            .is_some_and(|token| token.tab.id == id)
        {
            self.cancel_ai(cx);
        }
        let Some(token) = self.terminal_workspace.begin_reconnect(id) else {
            return;
        };
        let directory = self
            .terminal_tabs
            .get(&id)
            .and_then(|runtime| runtime.directory.clone());
        if let Some(runtime) = self.terminal_tabs.remove(&id) {
            runtime.pane.update(cx, |pane, cx| {
                let _ = pane.close(cx);
            });
        }
        self.spawn_terminal_open(token, bound, guard, directory, cx);
        cx.notify();
    }

    fn change_font_size(&mut self, delta: f32, cx: &mut Context<Self>) {
        let size = self.terminal_workspace.change_font_size(delta);
        self.apply_font_size(size, cx);
    }

    fn set_font_size(&mut self, size: f32, cx: &mut Context<Self>) {
        let size = self.terminal_workspace.reset_font_size(size);
        self.apply_font_size(size, cx);
    }

    fn apply_font_size(&mut self, size: f32, cx: &mut Context<Self>) {
        for runtime in self.terminal_tabs.values() {
            runtime.pane.update(cx, |pane, cx| {
                if let Err(error) = pane.set_font_size(size, cx) {
                    tracing::error!(%error, "failed to update terminal font size");
                }
            });
        }
        cx.notify();
    }

    fn on_search_input(
        &mut self,
        input: &Entity<InputState>,
        event: &InputEvent,
        cx: &mut Context<Self>,
    ) {
        match event {
            InputEvent::Change => self.sync_search_query(input.read(cx).value().to_string(), cx),
            InputEvent::PressEnter { secondary } => self.navigate_search(*secondary, cx),
            InputEvent::Focus | InputEvent::Blur => {}
        }
    }

    fn sync_search(&mut self, cx: &mut Context<Self>) {
        if !self.terminal_workspace.search.visible {
            return;
        }
        let query = self.search_input.read(cx).value().to_string();
        self.sync_search_query(query, cx);
    }

    fn sync_search_query(&mut self, query: String, cx: &mut Context<Self>) {
        let Some(id) = self.terminal_workspace.active_id() else {
            self.terminal_workspace.search.set_result(query, None, 0);
            return;
        };
        let Some(runtime) = self.terminal_tabs.get(&id) else {
            self.terminal_workspace.search.set_result(query, None, 0);
            return;
        };
        let result = runtime.pane.update(cx, |pane, cx| {
            pane.update_search(query.clone(), SearchOptions::default(), cx)?;
            Ok::<_, lovelyres_terminal::TerminalModelError>((
                pane.search_state().current_index(),
                pane.search_state().len(),
            ))
        });
        match result {
            Ok((current, total)) => {
                self.terminal_workspace
                    .search
                    .set_result(query, current, total);
            }
            Err(error) => self
                .terminal_workspace
                .search
                .set_error(query, error.to_string()),
        }
        cx.notify();
    }

    fn navigate_search(&mut self, previous: bool, cx: &mut Context<Self>) {
        let Some(id) = self.terminal_workspace.active_id() else {
            return;
        };
        let Some(runtime) = self.terminal_tabs.get(&id) else {
            return;
        };
        let (current, total) = runtime.pane.update(cx, |pane, cx| {
            if previous {
                pane.search_previous(cx);
            } else {
                pane.search_next(cx);
            }
            (
                pane.search_state().current_index(),
                pane.search_state().len(),
            )
        });
        self.terminal_workspace.search.current = current;
        self.terminal_workspace.search.total = total;
        cx.notify();
    }

    fn toggle_ai(&mut self, cx: &mut Context<Self>) {
        if self.terminal_workspace.ai.visible {
            self.terminal_workspace.ai.hide();
            self.focus_terminal_requested = self.terminal_workspace.active_id();
        } else {
            self.terminal_workspace.ai.show();
            self.focus_ai_requested = true;
        }
        cx.notify();
    }

    fn on_ai_input(
        &mut self,
        input: &Entity<InputState>,
        event: &InputEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if matches!(event, InputEvent::PressEnter { .. }) {
            let prompt = input.read(cx).value().to_string();
            self.start_ai_request(prompt, cx);
            if self.terminal_workspace.ai.state == TerminalAiState::Streaming {
                input.update(cx, |input, cx| input.set_value("", window, cx));
            }
        }
    }

    fn start_ai_request(&mut self, prompt: String, cx: &mut Context<Self>) {
        let prompt = prompt.trim().to_owned();
        if prompt.is_empty() {
            return;
        }
        self.cancel_ai(cx);
        let (Some(tab), Some(guard)) = (
            self.terminal_workspace.active_token(),
            self.bound_guard.clone(),
        ) else {
            self.notice = Some("没有可供 AI 分析的活动终端".into());
            return;
        };
        if self.services.target().validate(&guard).is_err() {
            self.notice = Some("目标已切换，AI 请求未发送".into());
            return;
        }
        let Some(runtime) = self.terminal_tabs.get(&tab.id) else {
            self.notice = Some("终端尚未连接".into());
            return;
        };
        let context = {
            let model = runtime.model.lock();
            model
                .selected_text()
                .filter(|text| !text.trim().is_empty())
                .unwrap_or_else(|| model.visible_text())
        };
        let context = tail_utf8(&context, 32 * 1024);
        let settings = match self.services.settings().load() {
            Ok(settings) => settings,
            Err(error) => {
                self.notice = Some(format!("无法读取 AI 设置：{error}").into());
                return;
            }
        };
        let provider =
            settings
                .ai
                .default_provider_id
                .as_deref()
                .and_then(|id| {
                    settings.ai.providers.iter().find(|provider| {
                        provider.id == id && provider.enabled && provider.has_api_key
                    })
                })
                .or_else(|| {
                    settings
                        .ai
                        .providers
                        .iter()
                        .find(|provider| provider.enabled && provider.has_api_key)
                });
        let Some(provider) = provider else {
            self.notice = Some("请先配置并启用带密钥的 AI Provider".into());
            self.terminal_workspace.ai.show();
            return;
        };
        let stream_id_text = format!(
            "terminal:{}:{}:{}",
            self.ticket.generation,
            tab.id,
            Uuid::new_v4()
        );
        let Some(ai_token) =
            self.terminal_workspace
                .begin_ai(tab, stream_id_text.clone(), prompt.clone())
        else {
            return;
        };
        self.ai_last_sequence = 0;
        let provider_id = match AiProviderId::new(provider.id.clone()) {
            Ok(provider_id) => provider_id,
            Err(error) => {
                let _ = self
                    .terminal_workspace
                    .ai
                    .fail(&ai_token, error.to_string());
                return;
            }
        };
        let stream_id = match AiStreamId::new(stream_id_text) {
            Ok(stream_id) => stream_id,
            Err(error) => {
                let _ = self
                    .terminal_workspace
                    .ai
                    .fail(&ai_token, error.to_string());
                return;
            }
        };
        let request = AiStreamRequest::new(
            stream_id,
            AiCompletionRequest::new(
                provider_id,
                vec![
                    AiMessage::new(
                        AiMessageRole::System,
                        "You are a Linux incident-response terminal assistant. Explain evidence and propose cautious commands, but never claim a command ran. Return plain Markdown text without raw HTML.",
                    ),
                    AiMessage::new(
                        AiMessageRole::User,
                        format!("Terminal context:\n```text\n{context}\n```\n\nQuestion: {prompt}"),
                    ),
                ],
            )
            .with_max_output_tokens(4_096),
        );
        let ai = match self.services.ai() {
            Ok(ai) => ai.clone(),
            Err(error) => {
                let _ = self
                    .terminal_workspace
                    .ai
                    .fail(&ai_token, error.to_string());
                return;
            }
        };
        self.start_ai_pump(ai, request, ai_token, guard, cx);
        cx.notify();
    }

    fn start_ai_pump(
        &self,
        ai: lovelyres_core::ai::AiService,
        request: AiStreamRequest,
        token: TerminalAiToken,
        guard: TargetGuard,
        cx: &mut Context<Self>,
    ) {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(128);
        drop(self.tokio.spawn(async move {
            let mut stream = match ai.start_stream(request) {
                Ok(stream) => stream,
                Err(error) => {
                    let _ = sender.send(AiPumpMessage::Failed(error.to_string())).await;
                    return;
                }
            };
            if sender
                .send(AiPumpMessage::Started(stream.cancellation()))
                .await
                .is_err()
            {
                return;
            }
            loop {
                let event = match stream.events().recv().await {
                    Ok(event) => event,
                    Err(error) => {
                        let _ = sender.send(AiPumpMessage::Failed(error.to_string())).await;
                        return;
                    }
                };
                let terminal = matches!(
                    event.kind,
                    AiStreamEventKind::Completed
                        | AiStreamEventKind::Cancelled
                        | AiStreamEventKind::Failed { .. }
                );
                if sender.send(AiPumpMessage::Event(event)).await.is_err() || terminal {
                    break;
                }
            }
            if let Err(error) = stream.wait().await {
                let _ = sender.send(AiPumpMessage::Failed(error.to_string())).await;
            }
        }));
        cx.spawn(async move |secondary, cx| {
            while let Some(message) = receiver.recv().await {
                let keep_receiving = cx
                    .update(|cx| {
                        let Some(secondary) = secondary.upgrade() else {
                            return false;
                        };
                        secondary.update(cx, |secondary, cx| {
                            secondary.apply_ai_message(&guard, &token, message, cx)
                        })
                    })
                    .unwrap_or(false);
                if !keep_receiving {
                    break;
                }
            }
        })
        .detach();
    }

    fn apply_ai_message(
        &mut self,
        guard: &TargetGuard,
        token: &TerminalAiToken,
        message: AiPumpMessage,
        cx: &mut Context<Self>,
    ) -> bool {
        let current = self.bound_guard.as_ref() == Some(guard)
            && self.services.target().validate(guard).is_ok()
            && self.shared.read(cx).windows.is_current(&self.ticket)
            && self.terminal_workspace.contains(token.tab)
            && self.terminal_workspace.ai.active() == Some(token);
        if !current {
            if let AiPumpMessage::Started(cancellation) = message {
                cancellation.cancel();
            }
            return false;
        }
        match message {
            AiPumpMessage::Started(cancellation) => {
                self.ai_cancellation = Some((token.clone(), cancellation));
            }
            AiPumpMessage::Event(event) => {
                let expected = self.ai_last_sequence.saturating_add(1);
                if event.stream_id != token.stream_id || event.sequence != expected {
                    if let Some((_, cancellation)) = self.ai_cancellation.take() {
                        cancellation.cancel();
                    }
                    let _ = self.terminal_workspace.ai.fail(
                        token,
                        format!("AI 流序列错误：期望 {expected}，收到 {}", event.sequence),
                    );
                    cx.notify();
                    return false;
                }
                self.ai_last_sequence = event.sequence;
                match event.kind {
                    AiStreamEventKind::Delta(delta) => {
                        let _ = self.terminal_workspace.ai.apply_delta(token, &delta);
                    }
                    AiStreamEventKind::Completed => {
                        let _ = self.terminal_workspace.ai.complete(token);
                        self.ai_cancellation = None;
                    }
                    AiStreamEventKind::Cancelled => {
                        let _ = self.terminal_workspace.ai.cancel();
                        self.ai_cancellation = None;
                    }
                    AiStreamEventKind::Failed { message } => {
                        let _ = self.terminal_workspace.ai.fail(token, message);
                        self.ai_cancellation = None;
                    }
                }
            }
            AiPumpMessage::Failed(error) => {
                let _ = self.terminal_workspace.ai.fail(token, error);
                self.ai_cancellation = None;
            }
        }
        cx.notify();
        self.terminal_workspace.ai.active().is_some()
    }

    fn cancel_ai(&mut self, cx: &mut Context<Self>) {
        if let Some(token) = self.terminal_workspace.ai.cancel() {
            if let Some((active, cancellation)) = self.ai_cancellation.take()
                && active == token
            {
                cancellation.cancel();
            }
            cx.notify();
        }
    }

    fn close_all_terminals(&mut self, cx: &mut Context<Self>) {
        self.cancel_ai(cx);
        self.environment_generation = self.environment_generation.saturating_add(1);
        self.completion_generation = self.completion_generation.saturating_add(1);
        for (_, runtime) in std::mem::take(&mut self.terminal_tabs) {
            runtime.pane.update(cx, |pane, cx| {
                let _ = pane.close(cx);
            });
        }
        self.terminal_workspace.clear();
        self.bash_environment = None;
        self.bash_environment_error = None;
        self.focus_terminal_requested = None;
        self.bound_session = None;
        self.bound_guard = None;
    }

    fn close_all_terminals_on_release(&mut self, cx: &mut App) {
        if let Some((_, cancellation)) = self.ai_cancellation.take() {
            cancellation.cancel();
        }
        for (_, runtime) in std::mem::take(&mut self.terminal_tabs) {
            runtime.pane.update(cx, |pane, cx| {
                let _ = pane.close(cx);
            });
        }
        self.terminal_workspace.clear();
        self.environment_generation = self.environment_generation.saturating_add(1);
        self.completion_generation = self.completion_generation.saturating_add(1);
        self.bash_environment = None;
        self.bash_environment_error = None;
        self.focus_terminal_requested = None;
        self.bound_session = None;
        self.bound_guard = None;
    }

    fn set_ssh_body(&mut self, connection_id: Option<Arc<str>>, terminal: TerminalPaneAdapterSlot) {
        if let NativeWindowBody::Ssh(body) = &mut self.body {
            body.connection_id = connection_id;
            body.terminal = terminal;
        }
    }

    fn ssh_connection_id(&self) -> Option<Arc<str>> {
        match &self.body {
            NativeWindowBody::Ssh(body) => body.connection_id.clone(),
            _ => None,
        }
    }

    fn close_arc_terminal(&self, session: Arc<SshTerminalSession>) {
        drop(self.tokio.spawn(async move {
            if let Err(error) = CoreTerminalTransport::close(session.as_ref()).await {
                tracing::error!(%error, "failed to close SSH terminal");
            }
        }));
    }

    fn close_detached_terminal(&self, session: SshTerminalSession) {
        drop(self.tokio.spawn(async move {
            if let Err(error) = CoreTerminalTransport::close(&session).await {
                tracing::error!(%error, "failed to close stale SSH terminal");
            }
        }));
    }
}

impl Render for SecondaryWindow {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let (tokens, target, lifecycle) = {
            let shared = self.shared.read(cx);
            (
                shared.theme.tokens(),
                shared.target_label.clone(),
                shared
                    .windows
                    .lifecycle(&self.kind)
                    .unwrap_or(WindowLifecycle::Closed)
                    .label(),
            )
        };
        let palette = palette_for_tokens(tokens);
        if palette != self.terminal_palette {
            self.terminal_palette = palette;
            for runtime in self.terminal_tabs.values() {
                runtime
                    .pane
                    .update(cx, |pane, cx| pane.set_palette(palette, cx));
            }
        }
        if let Some(id) = self.focus_terminal_requested.take()
            && let Some(runtime) = self.terminal_tabs.get(&id)
        {
            runtime.pane.read(cx).focus_handle(cx).focus(window);
        }
        if self.focus_search_requested {
            self.focus_search_requested = false;
            self.search_input
                .update(cx, |input, cx| input.focus(window, cx));
        }
        if self.focus_ai_requested {
            self.focus_ai_requested = false;
            self.ai_input
                .update(cx, |input, cx| input.focus(window, cx));
        }
        let body = if self.kind == NativeWindowKind::SshTerminal {
            self.render_ssh_terminal(tokens, cx)
        } else if let Some(sftp_window) = &self.sftp_window {
            div().size_full().child(sftp_window.clone())
        } else {
            typed_body(&self.body, "".into(), tokens)
        };

        secondary_frame(
            tokens,
            self.kind.title(),
            target,
            lifecycle,
            secondary_body_is_flush(&self.kind),
            body,
            cx.listener(|this, _, window, cx| this.request_close(window, cx)),
        )
    }
}

impl SecondaryWindow {
    fn render_ssh_terminal(&mut self, tokens: ThemeTokens, cx: &mut Context<Self>) -> gpui::Div {
        let active_id = self.terminal_workspace.active_id();
        let tabs = self
            .terminal_workspace
            .tabs()
            .iter()
            .map(|tab| {
                (
                    tab.id(),
                    tab.display_title().to_owned(),
                    terminal_tab_state_label(tab.state()),
                    active_id == Some(tab.id()),
                )
            })
            .collect::<Vec<_>>();
        let tab_bar = div()
            .h(px(36.0))
            .flex_none()
            .flex()
            .items_end()
            .gap_1()
            .px_2()
            .overflow_x_scrollbar()
            .border_b_1()
            .border_color(tokens.border)
            .bg(tokens.surface_alt)
            .children(tabs.into_iter().map(|(id, title, state, active)| {
                let close_id = id;
                div()
                    .id(SharedString::from(format!("terminal-tab-{id}")))
                    .h(px(31.0))
                    .min_w(px(132.0))
                    .max_w(px(240.0))
                    .px_2()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap_2()
                    .rounded_t_md()
                    .cursor_pointer()
                    .border_1()
                    .border_color(if active { tokens.accent } else { tokens.border })
                    .bg(if active {
                        tokens.surface
                    } else {
                        tokens.surface_alt
                    })
                    .text_color(if active { tokens.text } else { tokens.muted })
                    .hover(|element| element.bg(tokens.surface))
                    .child(Icon::new(IconName::SquareTerminal).size_3())
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .text_xs()
                            .overflow_hidden()
                            .child(title),
                    )
                    .child(
                        div()
                            .id(SharedString::from(format!("terminal-tab-state-{id}")))
                            .text_xs()
                            .text_color(tokens.muted)
                            .child(state),
                    )
                    .child(
                        div()
                            .id(SharedString::from(format!("terminal-tab-close-{id}")))
                            .size(px(20.0))
                            .flex_none()
                            .flex()
                            .items_center()
                            .justify_center()
                            .rounded_sm()
                            .hover(|element| element.bg(tokens.danger).text_color(tokens.text))
                            .on_click(
                                cx.listener(move |this, _, _, cx| this.close_tab(close_id, cx)),
                            )
                            .child(Icon::new(IconName::Close).size_3()),
                    )
                    .on_click(cx.listener(move |this, _, _, cx| this.activate_tab(id, cx)))
            }));

        let font_size = self.terminal_workspace.font_size();
        let shell_environment: SharedString = self
            .bash_environment
            .as_ref()
            .map(|environment| {
                let shell = environment
                    .shell
                    .rsplit('/')
                    .next()
                    .unwrap_or(environment.shell.as_str());
                let completion = if environment.supports_completion {
                    "compgen"
                } else {
                    "no-compgen"
                };
                format!("{shell} {} · {completion}", environment.version).into()
            })
            .or_else(|| self.bash_environment_error.clone())
            .unwrap_or_else(|| "shell 环境探测中…".into());
        let toolbar = div()
            .h(px(38.0))
            .flex_none()
            .px_2()
            .flex()
            .items_center()
            .gap_1()
            .border_b_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .child(terminal_control_button(
                "terminal-new-tab",
                "+ 标签",
                tokens,
                cx.listener(|this, _, _, cx| this.open_new_tab(cx)),
            ))
            .child(terminal_control_button(
                "terminal-reconnect",
                "重连",
                tokens,
                cx.listener(|this, _, _, cx| this.reconnect_active_tab(cx)),
            ))
            .child(terminal_control_button(
                "terminal-search",
                "搜索",
                tokens,
                cx.listener(|this, _, _, cx| {
                    if this.terminal_workspace.search.visible {
                        this.terminal_workspace.search.hide();
                        this.focus_terminal_requested = this.terminal_workspace.active_id();
                    } else {
                        this.terminal_workspace.search.show();
                        this.focus_search_requested = true;
                        this.sync_search(cx);
                    }
                    cx.notify();
                }),
            ))
            .child(terminal_control_button(
                "terminal-ai",
                "AI 助手",
                tokens,
                cx.listener(|this, _, _, cx| this.toggle_ai(cx)),
            ))
            .child(
                div()
                    .ml_2()
                    .text_xs()
                    .text_color(tokens.muted)
                    .child(shell_environment),
            )
            .child(div().flex_1())
            .child(terminal_control_button(
                "terminal-font-decrease",
                "A−",
                tokens,
                cx.listener(|this, _, _, cx| this.change_font_size(-1.0, cx)),
            ))
            .child(
                div()
                    .w(px(50.0))
                    .text_center()
                    .text_xs()
                    .text_color(tokens.muted)
                    .child(format!("{font_size:.0}px")),
            )
            .child(terminal_control_button(
                "terminal-font-increase",
                "A+",
                tokens,
                cx.listener(|this, _, _, cx| this.change_font_size(1.0, cx)),
            ));

        let search_bar = self.terminal_workspace.search.visible.then(|| {
            let current = self
                .terminal_workspace
                .search
                .current
                .map(|index| index + 1)
                .unwrap_or(0);
            let result = self
                .terminal_workspace
                .search
                .error
                .clone()
                .unwrap_or_else(|| format!("{current}/{}", self.terminal_workspace.search.total));
            div()
                .h(px(42.0))
                .flex_none()
                .px_2()
                .flex()
                .items_center()
                .gap_2()
                .border_b_1()
                .border_color(tokens.border)
                .bg(tokens.surface_alt)
                .child(div().flex_1().child(Input::new(&self.search_input)))
                .child(div().text_xs().text_color(tokens.muted).child(result))
                .child(terminal_control_button(
                    "terminal-search-previous",
                    "↑",
                    tokens,
                    cx.listener(|this, _, _, cx| this.navigate_search(true, cx)),
                ))
                .child(terminal_control_button(
                    "terminal-search-next",
                    "↓",
                    tokens,
                    cx.listener(|this, _, _, cx| this.navigate_search(false, cx)),
                ))
                .child(terminal_control_button(
                    "terminal-search-close",
                    "×",
                    tokens,
                    cx.listener(|this, _, _, cx| {
                        this.terminal_workspace.search.hide();
                        this.focus_terminal_requested = this.terminal_workspace.active_id();
                        cx.notify();
                    }),
                ))
        });

        let active_pane = active_id.and_then(|id| {
            self.terminal_tabs
                .get(&id)
                .map(|runtime| runtime.pane.clone())
        });
        let active_state = self
            .terminal_workspace
            .active()
            .map(|tab| terminal_tab_state_label(tab.state()))
            .unwrap_or_else(|| "没有终端标签；点击“+ 标签”新建".into());
        let mut pane_surface = div()
            .flex_1()
            .min_w_0()
            .min_h_0()
            .relative()
            .bg(tokens.terminal_background);
        if let Some(pane) = active_pane {
            pane_surface = pane_surface.child(pane);
        } else {
            pane_surface = pane_surface.child(
                div()
                    .size_full()
                    .flex()
                    .items_center()
                    .justify_center()
                    .text_color(tokens.muted)
                    .child(active_state),
            );
        }

        let ai_panel = self
            .terminal_workspace
            .ai
            .visible
            .then(|| self.render_ai_panel(tokens, cx));
        let mut content = div().flex_1().min_h_0().flex().child(pane_surface);
        if let Some(ai_panel) = ai_panel {
            content = content.child(ai_panel);
        }

        let notice = self.notice.clone().map(|notice| {
            div()
                .flex_none()
                .px_3()
                .py_1()
                .border_t_1()
                .border_color(tokens.border)
                .bg(tokens.surface_alt)
                .text_xs()
                .text_color(tokens.warning)
                .child(notice)
        });

        div()
            .size_full()
            .flex()
            .flex_col()
            .rounded_lg()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .overflow_hidden()
            .child(tab_bar)
            .child(toolbar)
            .children(search_bar)
            .child(content)
            .children(notice)
    }

    fn render_ai_panel(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> gpui::Div {
        let state = terminal_ai_state_label(self.terminal_workspace.ai.state);
        let output: SharedString = if self.terminal_workspace.ai.output.is_empty() {
            "AI 输出会作为纯文本节点显示；不解析原始 HTML。".into()
        } else {
            self.terminal_workspace.ai.output.clone().into()
        };
        let error = self.terminal_workspace.ai.error.clone();
        div()
            .w(px(360.0))
            .flex_none()
            .min_h_0()
            .flex()
            .flex_col()
            .border_l_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .child(
                div()
                    .h(px(38.0))
                    .flex_none()
                    .px_3()
                    .flex()
                    .items_center()
                    .justify_between()
                    .border_b_1()
                    .border_color(tokens.border)
                    .child("终端 AI 助手")
                    .child(div().text_xs().text_color(tokens.muted).child(state)),
            )
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scrollbar()
                    .p_3()
                    .text_sm()
                    .child(output)
                    .children(error.map(|error| {
                        div()
                            .mt_3()
                            .text_color(tokens.danger)
                            .child(format!("错误：{error}"))
                    })),
            )
            .child(
                div()
                    .flex_none()
                    .p_2()
                    .border_t_1()
                    .border_color(tokens.border)
                    .child(Input::new(&self.ai_input))
                    .child(
                        div()
                            .mt_2()
                            .flex()
                            .items_center()
                            .justify_between()
                            .text_xs()
                            .text_color(tokens.muted)
                            .child("仅分析当前选区或可见终端；不会自动执行命令")
                            .when(
                                self.terminal_workspace.ai.state == TerminalAiState::Streaming,
                                |element| {
                                    element.child(terminal_control_button(
                                        "terminal-ai-cancel",
                                        "取消",
                                        tokens,
                                        cx.listener(|this, _, _, cx| this.cancel_ai(cx)),
                                    ))
                                },
                            ),
                    ),
            )
    }
}

fn terminal_tab_state_label(state: &TerminalTabState) -> SharedString {
    match state {
        TerminalTabState::Opening => "正在打开远端 PTY…".into(),
        TerminalTabState::Open => "SSH PTY 已连接".into(),
        TerminalTabState::Reconnecting => "正在重新连接远端 PTY…".into(),
        TerminalTabState::Closed {
            exit_code: Some(code),
        } => format!("SSH PTY 已退出（{code}）").into(),
        TerminalTabState::Closed { exit_code: None } => "SSH PTY 已关闭".into(),
        TerminalTabState::Failed(message) => format!("SSH PTY 失败：{message}").into(),
    }
}

fn terminal_ai_state_label(state: TerminalAiState) -> &'static str {
    match state {
        TerminalAiState::Hidden => "隐藏",
        TerminalAiState::Ready => "就绪",
        TerminalAiState::Streaming => "生成中",
        TerminalAiState::Completed => "已完成",
        TerminalAiState::Cancelled => "已取消",
        TerminalAiState::Failed => "失败",
    }
}

fn terminal_control_button(
    id: &'static str,
    label: &'static str,
    tokens: ThemeTokens,
    on_click: impl Fn(&gpui::ClickEvent, &mut Window, &mut App) + 'static,
) -> impl IntoElement {
    div()
        .id(id)
        .h(px(26.0))
        .min_w(px(28.0))
        .px_2()
        .flex()
        .items_center()
        .justify_center()
        .gap_1()
        .rounded_sm()
        .cursor_pointer()
        .text_xs()
        .text_color(tokens.muted)
        .hover(|element| element.bg(tokens.surface_alt).text_color(tokens.text))
        .on_click(on_click)
        .child(Icon::new(crate::buttons::icon_for_button_id(id)).size_3())
        .child(label)
}

fn directory_terminal_label(directory: &RemotePath) -> String {
    let name = directory.file_name().unwrap_or("/");
    let mut characters = name.chars();
    let visible = characters.by_ref().take(24).collect::<String>();
    if characters.next().is_some() {
        format!("终端 · {visible}…")
    } else {
        format!("终端 · {visible}")
    }
}

pub(crate) fn palette_for_tokens(tokens: ThemeTokens) -> TerminalPalette {
    let rgb24 = |color| u32::from(color) >> 8;
    let terminal = TerminalPalette::default();
    TerminalPalette {
        background: rgb24(tokens.terminal_background),
        cursor: rgb24(tokens.accent),
        ..terminal
    }
}

fn secondary_body_is_flush(kind: &NativeWindowKind) -> bool {
    matches!(kind, NativeWindowKind::SshTerminal)
}

fn tail_utf8(text: &str, maximum_bytes: usize) -> String {
    if text.len() <= maximum_bytes {
        return text.to_owned();
    }
    let mut start = text.len() - maximum_bytes;
    while !text.is_char_boundary(start) {
        start += 1;
    }
    text[start..].to_owned()
}

fn merge_core_completions(
    mut shell: CoreCommandCompletion,
    command: CoreCommandCompletion,
) -> CoreCommandCompletion {
    if shell.candidates.is_empty() {
        return command;
    }
    if shell.replacement_start == command.replacement_start
        && shell.replacement_end == command.replacement_end
    {
        shell.candidates.extend(command.candidates);
        shell.candidates.sort();
        shell.candidates.dedup();
        shell.candidates.truncate(100);
    }
    shell
}

fn typed_body(
    body: &NativeWindowBody,
    terminal_state: SharedString,
    tokens: ThemeTokens,
) -> gpui::Div {
    let (heading, detail, identity): (SharedString, SharedString, String) = match body {
        NativeWindowBody::Main => (
            "主窗口".into(),
            "主窗口由 AppShell 承载。".into(),
            "Main".to_owned(),
        ),
        NativeWindowBody::Ssh(ssh) => (
            "SSH 终端".into(),
            terminal_state,
            ssh.connection_id.as_deref().map_or_else(
                || "SshTerminal · 未绑定连接".to_owned(),
                |id| format!("SshTerminal · {id}"),
            ),
        ),
        NativeWindowBody::Sftp(sftp) => (
            "SFTP 文件".into(),
            "真实 SFTP service 尚未接入；当前窗口不执行文件操作。".into(),
            sftp.connection_id.as_deref().map_or_else(
                || "Sftp · 未绑定连接".to_owned(),
                |id| format!("Sftp · {id}"),
            ),
        ),
        NativeWindowBody::Container(container) => (
            "容器终端".into(),
            "TerminalPane adapter slot 正在等待真实容器 transport；不会创建伪会话。".into(),
            format!("ContainerTerminal({})", container.container_id),
        ),
    };

    div()
        .size_full()
        .rounded_lg()
        .border_1()
        .border_color(tokens.border)
        .bg(tokens.surface)
        .p_6()
        .child(div().text_2xl().mb_2().child(heading))
        .child(
            div()
                .text_sm()
                .text_color(tokens.muted)
                .mb_4()
                .child(identity),
        )
        .child(
            div()
                .id("native-window-adapter-slot")
                .rounded_md()
                .border_1()
                .border_color(tokens.border)
                .bg(tokens.surface_alt)
                .p_4()
                .child(detail),
        )
}

fn secondary_frame(
    tokens: ThemeTokens,
    title: SharedString,
    target: SharedString,
    lifecycle: &'static str,
    flush_body: bool,
    body: impl IntoElement,
    close: impl Fn(&gpui::ClickEvent, &mut Window, &mut App) + 'static,
) -> impl IntoElement {
    div()
        .size_full()
        .flex()
        .flex_col()
        .bg(tokens.background)
        .text_color(tokens.text)
        .font_family("Inter")
        .child(
            div()
                .h(px(40.0))
                .flex()
                .items_center()
                .bg(tokens.surface)
                .border_b_1()
                .border_color(tokens.border)
                .child(secondary_titlebar_drag_region(
                    div()
                        .h_full()
                        .flex_1()
                        .min_w_0()
                        .px_4()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap_3()
                        .child(title)
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap_3()
                                .child(div().text_xs().text_color(tokens.muted).child(lifecycle))
                                .child(target),
                        ),
                ))
                .child(
                    div()
                        .h_full()
                        .flex_none()
                        .flex()
                        .items_center()
                        .child(
                            div()
                                .id("secondary-window-minimize")
                                .size(px(40.0))
                                .flex()
                                .items_center()
                                .justify_center()
                                .cursor_pointer()
                                .hover(|element| element.bg(tokens.surface_alt))
                                .on_click(|_, window, _| window.minimize_window())
                                .child(Icon::new(IconName::WindowMinimize).size_4()),
                        )
                        .child(
                            div()
                                .id("secondary-window-maximize")
                                .size(px(40.0))
                                .flex()
                                .items_center()
                                .justify_center()
                                .cursor_pointer()
                                .hover(|element| element.bg(tokens.surface_alt))
                                .on_click(|_, window, _| window.zoom_window())
                                .child(Icon::new(IconName::WindowMaximize).size_4()),
                        )
                        .child(
                            div()
                                .id("secondary-window-close")
                                .size(px(40.0))
                                .flex()
                                .items_center()
                                .justify_center()
                                .cursor_pointer()
                                .hover(|element| {
                                    element.bg(tokens.danger).text_color(gpui::white())
                                })
                                .on_click(close)
                                .child(Icon::new(IconName::WindowClose).size_4()),
                        ),
                ),
        )
        .child(
            div()
                .flex_1()
                .min_w_0()
                .min_h_0()
                .when(!flush_body, |content| content.p_6())
                .child(body),
        )
}

#[cfg(target_os = "windows")]
fn secondary_titlebar_drag_region(region: gpui::Div) -> gpui::Div {
    region.on_mouse_down(MouseButton::Left, |_, window, _| {
        begin_native_window_drag(window);
    })
}

#[cfg(not(target_os = "windows"))]
fn secondary_titlebar_drag_region(region: gpui::Div) -> gpui::Div {
    region.window_control_area(gpui::WindowControlArea::Drag)
}

#[cfg(target_os = "windows")]
fn begin_native_window_drag(window: &Window) {
    let Some(hwnd) = raw_win32_hwnd(window) else {
        return;
    };
    if let Err(error) = unsafe { ReleaseCapture() } {
        tracing::error!(%error, "failed to release Win32 capture before secondary-window drag");
        return;
    }
    if let Err(error) = unsafe {
        PostMessageW(
            Some(hwnd),
            WM_SYSCOMMAND,
            WPARAM((SC_MOVE | HTCAPTION) as usize),
            LPARAM(0),
        )
    } {
        tracing::error!(%error, "failed to begin the native Win32 secondary-window drag");
    }
}

#[cfg(target_os = "windows")]
fn raw_win32_hwnd(window: &Window) -> Option<HWND> {
    let Ok(handle) = HasWindowHandle::window_handle(window) else {
        tracing::error!("cannot obtain the raw Win32 secondary-window handle");
        return None;
    };
    let RawWindowHandle::Win32(handle) = handle.as_raw() else {
        tracing::error!("GPUI returned a non-Win32 secondary-window handle on Windows");
        return None;
    };
    Some(HWND(handle.hwnd.get() as *mut std::ffi::c_void))
}

#[cfg(test)]
mod tests {
    use gpui::{EntityInputHandler, TestAppContext};

    use super::*;

    #[derive(Debug, Default)]
    struct TestTransport;

    #[async_trait]
    impl PaneTerminalTransport for TestTransport {
        async fn send_input(&self, _bytes: &[u8]) -> Result<(), TerminalTransportError> {
            Ok(())
        }

        async fn resize(&self, _size: TerminalSize) -> Result<(), TerminalTransportError> {
            Ok(())
        }

        async fn close(&self) -> Result<(), TerminalTransportError> {
            Ok(())
        }
    }

    #[test]
    fn fixed_window_identity_rejects_duplicates_and_tracks_close() {
        let mut registry = NativeWindowRegistry::default();
        let ssh = NativeWindowKind::SshTerminal;
        let first = registry.begin_open(ssh.clone()).unwrap();
        assert_eq!(registry.begin_open(ssh.clone()), None);
        assert_eq!(registry.lifecycle(&ssh), Some(WindowLifecycle::Opening));
        assert!(registry.is_current(&first));
        assert!(registry.mark_open(&first));
        registry.begin_close(&ssh);
        assert_eq!(registry.lifecycle(&ssh), Some(WindowLifecycle::Closing));
        assert!(!registry.is_current(&first));
        registry.mark_closed(&ssh);
        let second = registry.begin_open(ssh.clone()).unwrap();
        assert_ne!(first.generation, second.generation);
        assert_eq!(registry.lifecycle(&ssh), Some(WindowLifecycle::Opening));
    }

    #[test]
    fn secondary_window_controls_remain_client_click_targets() {
        let source = include_str!("windows.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source precedes tests");
        let native_close = ["WindowControlArea", "::", "Close"].concat();

        assert!(production.contains("secondary_titlebar_drag_region("));
        assert!(production.contains("PostMessageW("));
        assert!(production.contains("WM_SYSCOMMAND"));
        assert!(production.contains("SC_MOVE | HTCAPTION"));
        assert!(production.contains("WindowControlArea::Drag"));
        assert!(!production.contains(&native_close));
        for control in [
            "secondary-window-minimize",
            "secondary-window-maximize",
            "secondary-window-close",
        ] {
            assert!(
                production.contains(control),
                "missing client control {control}"
            );
        }

        let drag = production
            .find(".child(secondary_titlebar_drag_region(")
            .expect("secondary title drag region");
        let close = production
            .rfind(".id(\"secondary-window-close\")")
            .expect("secondary close control");
        assert!(
            close > drag,
            "window controls must stay outside the drag region"
        );
    }

    #[test]
    fn native_window_profiles_prioritize_interactive_drag_performance() {
        let manifest = include_str!("../../../Cargo.toml");
        let dev = manifest
            .split("[profile.dev]")
            .nth(1)
            .and_then(|tail| tail.split("[profile.dev.package.\"*\"]").next())
            .expect("dev profile");
        let dependencies = manifest
            .split("[profile.dev.package.\"*\"]")
            .nth(1)
            .and_then(|tail| tail.split("[profile.release]").next())
            .expect("optimized dev dependencies");
        let release = manifest
            .split("[profile.release]")
            .nth(1)
            .expect("release profile");

        assert!(dev.lines().any(|line| line.trim() == "opt-level = 1"));
        assert!(
            dependencies
                .lines()
                .any(|line| line.trim() == "opt-level = 3")
        );
        assert!(release.lines().any(|line| line.trim() == "opt-level = 3"));
    }

    #[test]
    fn ssh_terminal_is_flush_while_document_windows_keep_their_inset() {
        assert!(secondary_body_is_flush(&NativeWindowKind::SshTerminal));
        assert!(!secondary_body_is_flush(&NativeWindowKind::Sftp));
    }

    #[test]
    fn light_ui_theme_does_not_replace_terminal_foreground_or_selection_colors() {
        let tokens = crate::theme::ThemeId::Light.tokens();
        let palette = palette_for_tokens(tokens);
        let terminal = TerminalPalette::default();

        assert_eq!(palette.foreground, terminal.foreground);
        assert_eq!(palette.selection, terminal.selection);
        assert_ne!(palette.foreground, u32::from(tokens.text) >> 8);
        assert_ne!(palette.selection, u32::from(tokens.surface_alt) >> 8);
        assert_eq!(
            palette.background,
            u32::from(tokens.terminal_background) >> 8
        );
        assert_eq!(palette.cursor, u32::from(tokens.accent) >> 8);
    }

    #[test]
    fn directory_terminal_tab_labels_are_bounded_and_unicode_safe() {
        assert_eq!(
            directory_terminal_label(&RemotePath::new("/").unwrap()),
            "终端 · /"
        );
        assert_eq!(
            directory_terminal_label(&RemotePath::new("/var/log").unwrap()),
            "终端 · log"
        );
        let long = RemotePath::new(format!("/tmp/{}", "证据".repeat(20))).unwrap();
        let label = directory_terminal_label(&long);
        assert!(label.ends_with('…'));
        assert_eq!(label.chars().count(), "终端 · ".chars().count() + 25);
    }

    #[test]
    fn window_kinds_create_typed_non_transport_bodies() {
        assert!(matches!(
            NativeWindowBody::from(&NativeWindowKind::SshTerminal),
            NativeWindowBody::Ssh(SshTerminalBody {
                terminal: TerminalPaneAdapterSlot::AwaitingTransport,
                ..
            })
        ));
        let container_identity = ContainerIdentity::new(
            lovelyres_core::docker::ContainerRuntime::Docker,
            "aaaaaaaaaaaa",
        )
        .unwrap();
        let key = ContainerTerminalWindowKey::from_guard(
            &TargetGuard {
                identity: lovelyres_core::target::TargetIdentity::new("connection-a").unwrap(),
                generation: 7,
            },
            &container_identity,
        );
        let container = NativeWindowKind::ContainerTerminal(key);
        assert!(matches!(
            NativeWindowBody::from(&container),
            NativeWindowBody::Container(ContainerTerminalBody { container_id, .. })
                if container_id.as_ref() == "docker:aaaaaaaaaaaa"
        ));
    }

    #[test]
    fn container_window_identity_binds_target_epoch_runtime_and_container() {
        let identity = ContainerIdentity::new(
            lovelyres_core::docker::ContainerRuntime::Docker,
            "aaaaaaaaaaaa",
        )
        .unwrap();
        let guard = TargetGuard {
            identity: lovelyres_core::target::TargetIdentity::new("connection-a").unwrap(),
            generation: 7,
        };
        let key = ContainerTerminalWindowKey::from_guard(&guard, &identity);
        let same = ContainerTerminalWindowKey::from_guard(&guard, &identity);
        assert_eq!(key, same);
        assert_eq!(key.target_identity(), "connection-a");
        assert_eq!(key.target_generation(), 7);
        assert_eq!(key.container(), "docker:aaaaaaaaaaaa");

        let mut next_guard = guard.clone();
        next_guard.generation += 1;
        assert_ne!(
            key,
            ContainerTerminalWindowKey::from_guard(&next_guard, &identity)
        );
        let podman = ContainerIdentity::new(
            lovelyres_core::docker::ContainerRuntime::Podman,
            "aaaaaaaaaaaa",
        )
        .unwrap();
        assert_ne!(
            same,
            ContainerTerminalWindowKey::from_guard(&guard, &podman)
        );
    }

    #[test]
    fn typed_completion_merge_requires_the_same_replacement_range() {
        let merged = merge_core_completions(
            CoreCommandCompletion {
                candidates: vec!["ls".to_owned(), "less".to_owned()],
                replacement_start: 0,
                replacement_end: 1,
            },
            CoreCommandCompletion {
                candidates: vec!["ls".to_owned(), "lsof".to_owned()],
                replacement_start: 0,
                replacement_end: 1,
            },
        );
        assert_eq!(merged.candidates, vec!["less", "ls", "lsof"]);

        let different_range = merge_core_completions(
            CoreCommandCompletion {
                candidates: vec!["/tmp/a".to_owned()],
                replacement_start: 4,
                replacement_end: 10,
            },
            CoreCommandCompletion {
                candidates: vec!["awk".to_owned()],
                replacement_start: 0,
                replacement_end: 3,
            },
        );
        assert_eq!(different_range.candidates, vec!["/tmp/a"]);
        assert_eq!(different_range.replacement_start, 4);
    }

    #[test]
    fn terminal_batch_preserves_event_order_and_every_output_byte() {
        let expected = b"first\r\n\xe4\xb8\xadsecond".to_vec();
        let events = vec![
            CoreTerminalEvent {
                session_id: "terminal-1".to_owned(),
                sequence: 1,
                kind: TerminalEventKind::Output(b"first\r\n".to_vec()),
            },
            CoreTerminalEvent {
                session_id: "terminal-1".to_owned(),
                sequence: 2,
                kind: TerminalEventKind::Output("中".as_bytes().to_vec()),
            },
            CoreTerminalEvent {
                session_id: "terminal-1".to_owned(),
                sequence: 3,
                kind: TerminalEventKind::Output(b"second".to_vec()),
            },
        ];
        let outcome = reduce_terminal_batch("terminal-1", 0, events);
        assert_eq!(outcome.output, expected);
        assert_eq!(outcome.last_sequence, 3);
        assert_eq!(outcome.protocol_error, None);

        let mut model = TerminalModel::new(TerminalConfig::default()).unwrap();
        let report = model.feed_output(&outcome.output);
        assert_eq!(report.bytes_processed, outcome.output.len());
        assert_eq!(model.total_bytes(), outcome.output.len() as u64);
        assert!(model.visible_text().contains('中'));
    }

    #[test]
    fn terminal_batch_reports_sequence_gaps_without_reordering_received_bytes() {
        let events = vec![
            CoreTerminalEvent {
                session_id: "terminal-1".to_owned(),
                sequence: 1,
                kind: TerminalEventKind::Output(vec![1]),
            },
            CoreTerminalEvent {
                session_id: "terminal-1".to_owned(),
                sequence: 3,
                kind: TerminalEventKind::Output(vec![3]),
            },
            CoreTerminalEvent {
                session_id: "terminal-1".to_owned(),
                sequence: 4,
                kind: TerminalEventKind::Exited { exit_code: Some(0) },
            },
        ];
        let outcome = reduce_terminal_batch("terminal-1", 0, events);
        assert_eq!(outcome.output, vec![1, 3]);
        assert!(outcome.protocol_error.is_some());
        assert_eq!(
            outcome.terminal_state,
            Some(TerminalTabState::Closed { exit_code: Some(0) })
        );
    }

    #[test]
    fn terminal_batch_handles_sustained_output_without_byte_loss() {
        let chunks = (0_u64..4_096)
            .map(|index| {
                let bytes = format!("{index:04}:事件证据\r\n").into_bytes();
                CoreTerminalEvent {
                    session_id: "throughput".to_owned(),
                    sequence: index + 1,
                    kind: TerminalEventKind::Output(bytes),
                }
            })
            .collect::<Vec<_>>();
        let expected = chunks
            .iter()
            .flat_map(|event| match &event.kind {
                TerminalEventKind::Output(bytes) => bytes.clone(),
                _ => Vec::new(),
            })
            .collect::<Vec<_>>();
        let outcome = reduce_terminal_batch("throughput", 0, chunks);
        assert_eq!(outcome.output, expected);
        assert_eq!(outcome.last_sequence, 4_096);
        assert!(outcome.protocol_error.is_none());
    }

    #[test]
    fn ai_context_tail_preserves_utf8_boundaries() {
        let text = "prefix-".to_owned() + &"中文".repeat(20_000);
        let tail = tail_utf8(&text, 32 * 1024);
        assert!(tail.len() <= 32 * 1024);
        assert!(tail.is_char_boundary(0));
        assert!(tail.ends_with("中文"));
    }

    #[gpui::test]
    fn native_pane_keeps_cjk_ime_and_search_in_gpui(cx: &mut TestAppContext) {
        let window = cx.update(|cx| {
            cx.open_window(Default::default(), |_, cx| {
                let mut model = TerminalModel::new(TerminalConfig::default()).unwrap();
                for index in 0..80 {
                    model.feed_output(format!("line {index} 中文证据\r\n").as_bytes());
                }
                let model = Arc::new(Mutex::new(model));
                let transport: Arc<dyn PaneTerminalTransport> = Arc::new(TestTransport);
                cx.new(|cx| TerminalPane::new(model, transport, cx))
            })
            .unwrap()
        });

        window
            .update(cx, |pane, window, cx| {
                pane.replace_and_mark_text_in_range(None, "中文输入", Some(4..4), window, cx);
                assert_eq!(pane.ime().text(), "中文输入");
                pane.unmark_text(window, cx);
                assert!(pane.ime().text().is_empty());

                pane.update_search("中文证据", SearchOptions::default(), cx)
                    .unwrap();
                assert_eq!(pane.search_state().len(), 80);
                assert!(pane.model().lock().display_offset() > 0);
                assert!(pane.search_next(cx).is_some());
            })
            .unwrap();
    }
}
