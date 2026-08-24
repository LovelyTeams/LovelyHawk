//! Target-bound native container terminal window.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use gpui::{
    App, Context, Entity, Focusable, Render, SharedString, Subscription, Window, WindowControlArea,
    div, prelude::*, px,
};
use gpui_component::{Icon, IconName};
use lovelyres_core::docker::{ContainerIdentity, ContainerShell, ContainerTerminalSession};
use lovelyres_core::events::{
    TerminalEvent as CoreTerminalEvent, TerminalEventKind,
    TerminalTransport as CoreTerminalTransport,
};
use lovelyres_core::ssh::BoundSshSession;
use lovelyres_core::{BackendServices, CoreError};
use lovelyres_terminal::{
    TerminalConfig, TerminalModel, TerminalPalette, TerminalPane, TerminalPaneEvent,
    TerminalShortcut, TerminalSize, TerminalTabState, TerminalTransport as PaneTerminalTransport,
    TerminalTransportError,
};
use parking_lot::Mutex;

use crate::app::SharedAppState;
use crate::runtime::TokioBridge;
use crate::theme::ThemeTokens;
use crate::windows::{
    ContainerTerminalWindowKey, NativeWindowKind, WindowLifecycle, WindowTicket,
    palette_for_tokens, reduce_terminal_batch, terminal_transport_error,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainerTerminalLaunch {
    session: BoundSshSession,
    container: ContainerIdentity,
    shell: ContainerShell,
}

impl ContainerTerminalLaunch {
    pub fn new(
        session: BoundSshSession,
        container: ContainerIdentity,
        shell: ContainerShell,
    ) -> Self {
        Self {
            session,
            container,
            shell,
        }
    }

    pub fn session(&self) -> &BoundSshSession {
        &self.session
    }

    pub fn container(&self) -> &ContainerIdentity {
        &self.container
    }

    pub const fn shell(&self) -> ContainerShell {
        self.shell
    }

    pub fn window_key(&self) -> ContainerTerminalWindowKey {
        ContainerTerminalWindowKey::new(&self.session, &self.container)
    }

    pub fn window_kind(&self) -> NativeWindowKind {
        NativeWindowKind::ContainerTerminal(self.window_key())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ContainerTerminalLease {
    window_key: ContainerTerminalWindowKey,
    ticket_generation: u64,
    attempt: u64,
    shell: ContainerShell,
}

impl ContainerTerminalLease {
    fn new(ticket: &WindowTicket, launch: &ContainerTerminalLaunch, attempt: u64) -> Self {
        Self {
            window_key: launch.window_key(),
            ticket_generation: ticket.generation,
            attempt,
            shell: launch.shell,
        }
    }

    fn matches(
        &self,
        ticket: &WindowTicket,
        launch: &ContainerTerminalLaunch,
        attempt: u64,
        shell: ContainerShell,
    ) -> bool {
        self.window_key == launch.window_key()
            && self.ticket_generation == ticket.generation
            && self.attempt == attempt
            && self.shell == shell
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ContainerTerminalState {
    Opening,
    Open,
    Closed { exit_code: Option<i32> },
    Failed(SharedString),
}

impl ContainerTerminalState {
    fn label(&self) -> SharedString {
        match self {
            Self::Opening => "正在打开容器 PTY…".into(),
            Self::Open => "容器 PTY 已连接".into(),
            Self::Closed {
                exit_code: Some(code),
            } => format!("容器 PTY 已退出（{code}）").into(),
            Self::Closed { exit_code: None } => "容器 PTY 已关闭".into(),
            Self::Failed(message) => format!("容器 PTY 失败：{message}").into(),
        }
    }
}

#[derive(Debug)]
struct ContainerTerminalTransportAdapter {
    session: Arc<ContainerTerminalSession>,
}

#[async_trait]
impl PaneTerminalTransport for ContainerTerminalTransportAdapter {
    async fn send_input(&self, bytes: &[u8]) -> Result<(), TerminalTransportError> {
        CoreTerminalTransport::write_input(self.session.as_ref(), bytes.to_vec())
            .await
            .map_err(terminal_transport_error)
    }

    async fn resize(&self, size: TerminalSize) -> Result<(), TerminalTransportError> {
        CoreTerminalTransport::resize(self.session.as_ref(), size.columns, size.rows)
            .await
            .map_err(terminal_transport_error)
    }

    async fn close(&self) -> Result<(), TerminalTransportError> {
        CoreTerminalTransport::close(self.session.as_ref())
            .await
            .map_err(terminal_transport_error)
    }
}

struct AttachedContainerTerminal {
    terminal_id: String,
    last_sequence: u64,
    model: Arc<Mutex<TerminalModel>>,
    pane: Entity<TerminalPane>,
    session: Arc<ContainerTerminalSession>,
    _pane_subscription: Subscription,
}

enum ContainerPumpMessage {
    Batch(Vec<CoreTerminalEvent>),
    Failed(String),
}

pub struct ContainerTerminalWindow {
    ticket: WindowTicket,
    launch: ContainerTerminalLaunch,
    shared: Entity<SharedAppState>,
    services: Arc<BackendServices>,
    tokio: Arc<TokioBridge>,
    terminal_config: TerminalConfig,
    terminal_palette: TerminalPalette,
    shell: ContainerShell,
    attempt: u64,
    state: ContainerTerminalState,
    title: Option<SharedString>,
    notice: Option<SharedString>,
    attached: Option<AttachedContainerTerminal>,
    focus_terminal_requested: bool,
    close_window_requested: bool,
    _shared_subscription: Subscription,
    _release_subscription: Subscription,
}

impl ContainerTerminalWindow {
    pub fn new(
        ticket: WindowTicket,
        launch: ContainerTerminalLaunch,
        shared: Entity<SharedAppState>,
        services: Arc<BackendServices>,
        tokio: Arc<TokioBridge>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let settings = services.settings().load().unwrap_or_default();
        let terminal_config = TerminalConfig {
            font_family: settings.terminal_font,
            font_size: f32::from(settings.terminal_font_size),
            ..TerminalConfig::default()
        };
        let terminal_palette = palette_for_tokens(shared.read(cx).theme.tokens());
        let shared_subscription = cx.observe(&shared, |terminal, _, cx| {
            if !terminal.binding_is_current(cx) {
                terminal.invalidate_target(cx);
            }
            cx.notify();
        });
        let closing_shared = shared.clone();
        let closing_kind = ticket.kind.clone();
        window.on_window_should_close(cx, move |_, cx| {
            closing_shared.update(cx, |state, cx| {
                state.windows.begin_close(&closing_kind);
                cx.notify();
            });
            true
        });
        let release_subscription = cx.on_release(|terminal: &mut Self, cx| {
            terminal.close_attached(cx);
            terminal.shared.update(cx, |state, cx| {
                state.windows.mark_closed(&terminal.ticket.kind);
                cx.notify();
            });
        });
        let ticket_matches = ticket.kind == launch.window_kind();
        let mut terminal = Self {
            ticket,
            shell: launch.shell,
            launch,
            shared,
            services,
            tokio,
            terminal_config,
            terminal_palette,
            attempt: 0,
            state: ContainerTerminalState::Opening,
            title: None,
            notice: None,
            attached: None,
            focus_terminal_requested: false,
            close_window_requested: false,
            _shared_subscription: shared_subscription,
            _release_subscription: release_subscription,
        };
        if ticket_matches && terminal.binding_is_current(cx) {
            terminal.shared.update(cx, |state, cx| {
                state.windows.mark_open(&terminal.ticket);
                cx.notify();
            });
            terminal.open_terminal(cx);
        } else {
            terminal.state =
                ContainerTerminalState::Failed("窗口票据、SSH 目标或容器身份已失效".into());
            terminal.close_window_requested = true;
        }
        terminal
    }

    fn binding_is_current(&self, cx: &App) -> bool {
        self.services
            .target()
            .validate(self.launch.session.target())
            .is_ok()
            && self.shared.read(cx).windows.is_current(&self.ticket)
            && self
                .shared
                .read(cx)
                .active_ssh
                .as_ref()
                .is_some_and(|active| active.session == self.launch.session)
    }

    fn invalidate_target(&mut self, cx: &mut Context<Self>) {
        if self.close_window_requested {
            return;
        }
        self.attempt = self.attempt.saturating_add(1);
        self.close_attached(cx);
        self.state = ContainerTerminalState::Failed("目标已切换，容器终端已关闭".into());
        self.close_window_requested = true;
        self.shared.update(cx, |state, cx| {
            state.windows.begin_close(&self.ticket.kind);
            cx.notify();
        });
    }

    fn request_close(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.attempt = self.attempt.saturating_add(1);
        self.close_attached(cx);
        self.shared.update(cx, |state, cx| {
            state.windows.begin_close(&self.ticket.kind);
            cx.notify();
        });
        window.remove_window();
    }

    fn select_shell(&mut self, shell: ContainerShell, cx: &mut Context<Self>) {
        if self.shell == shell && matches!(self.state, ContainerTerminalState::Open) {
            return;
        }
        self.shell = shell;
        self.open_terminal(cx);
    }

    fn open_terminal(&mut self, cx: &mut Context<Self>) {
        self.attempt = self.attempt.saturating_add(1);
        self.close_attached(cx);
        if !self.binding_is_current(cx) {
            self.invalidate_target(cx);
            return;
        }
        self.state = ContainerTerminalState::Opening;
        self.notice = None;
        self.title = None;
        let lease = ContainerTerminalLease::new(&self.ticket, &self.launch, self.attempt);
        let service = self.services.docker().clone();
        let session = self.launch.session.clone();
        let container = self.launch.container.clone();
        let shell = self.shell;
        let task = self.tokio.spawn(async move {
            service
                .open_terminal(
                    &session,
                    &container,
                    shell,
                    TerminalSize::default().columns,
                    TerminalSize::default().rows,
                )
                .await
        });
        let tokio = self.tokio.clone();
        cx.spawn(async move |terminal, cx| {
            let mut result = Some(task.await);
            let applied = cx
                .update(|cx| {
                    let Some(terminal) = terminal.upgrade() else {
                        return false;
                    };
                    terminal.update(cx, |terminal, cx| {
                        terminal.finish_open(
                            lease,
                            result.take().expect("container open result consumed once"),
                            cx,
                        );
                    });
                    true
                })
                .unwrap_or(false);
            if !applied && let Some(Ok(Ok(session))) = result {
                drop(tokio.spawn(async move {
                    let _ = CoreTerminalTransport::close(&session).await;
                }));
            }
        })
        .detach();
        cx.notify();
    }

    fn accepts_lease(&self, lease: &ContainerTerminalLease, cx: &App) -> bool {
        lease.matches(&self.ticket, &self.launch, self.attempt, self.shell)
            && self.binding_is_current(cx)
    }

    fn finish_open(
        &mut self,
        lease: ContainerTerminalLease,
        result: Result<Result<ContainerTerminalSession, CoreError>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if !self.accepts_lease(&lease, cx) {
            if let Ok(Ok(session)) = result {
                self.close_detached(session);
            }
            return;
        }
        let session = match result {
            Ok(Ok(session)) => Arc::new(session),
            Ok(Err(error)) => {
                self.state = ContainerTerminalState::Failed(error.to_string().into());
                cx.notify();
                return;
            }
            Err(error) => {
                self.state =
                    ContainerTerminalState::Failed(format!("容器终端任务异常结束：{error}").into());
                cx.notify();
                return;
            }
        };
        let model = match TerminalModel::new(self.terminal_config.clone()) {
            Ok(model) => Arc::new(Mutex::new(model)),
            Err(error) => {
                self.close_arc(session);
                self.state = ContainerTerminalState::Failed(error.to_string().into());
                cx.notify();
                return;
            }
        };
        let transport: Arc<dyn PaneTerminalTransport> =
            Arc::new(ContainerTerminalTransportAdapter {
                session: session.clone(),
            });
        let pane = cx.new(|cx| TerminalPane::new(model.clone(), transport, cx));
        pane.update(cx, |pane, cx| pane.set_palette(self.terminal_palette, cx));
        let pane_subscription = cx.subscribe(&pane, |terminal, _, event, cx| {
            terminal.on_pane_event(event, cx);
        });
        let terminal_id = session.terminal_id().to_owned();
        self.attached = Some(AttachedContainerTerminal {
            terminal_id: terminal_id.clone(),
            last_sequence: 0,
            model,
            pane,
            session: session.clone(),
            _pane_subscription: pane_subscription,
        });
        self.state = ContainerTerminalState::Open;
        self.focus_terminal_requested = true;
        self.start_event_pump(session, lease, terminal_id, cx);
        cx.notify();
    }

    fn start_event_pump(
        &self,
        session: Arc<ContainerTerminalSession>,
        lease: ContainerTerminalLease,
        terminal_id: String,
        cx: &mut Context<Self>,
    ) {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(64);
        drop(self.tokio.spawn(async move {
            loop {
                let first = match session.recv().await {
                    Ok(event) => event,
                    Err(error) => {
                        let _ = sender
                            .send(ContainerPumpMessage::Failed(error.to_string()))
                            .await;
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
                            let _ = sender
                                .send(ContainerPumpMessage::Failed(error.to_string()))
                                .await;
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
                if sender
                    .send(ContainerPumpMessage::Batch(events))
                    .await
                    .is_err()
                    || ended
                {
                    break;
                }
            }
        }));
        cx.spawn(async move |terminal, cx| {
            while let Some(message) = receiver.recv().await {
                let keep_running = cx
                    .update(|cx| {
                        let Some(terminal) = terminal.upgrade() else {
                            return false;
                        };
                        terminal.update(cx, |terminal, cx| match message {
                            ContainerPumpMessage::Batch(events) => {
                                terminal.apply_batch(&lease, &terminal_id, events, cx)
                            }
                            ContainerPumpMessage::Failed(error) => {
                                terminal.fail_event_pump(&lease, &terminal_id, error, cx)
                            }
                        })
                    })
                    .unwrap_or(false);
                if !keep_running {
                    break;
                }
            }
        })
        .detach();
    }

    fn apply_batch(
        &mut self,
        lease: &ContainerTerminalLease,
        terminal_id: &str,
        events: Vec<CoreTerminalEvent>,
        cx: &mut Context<Self>,
    ) -> bool {
        if !self.accepts_lease(lease, cx) {
            return false;
        }
        let Some(attached) = self.attached.as_mut() else {
            return false;
        };
        if attached.terminal_id != terminal_id {
            return false;
        }
        let outcome = reduce_terminal_batch(terminal_id, attached.last_sequence, events);
        attached.last_sequence = outcome.last_sequence;
        if !outcome.output.is_empty() {
            attached.model.lock().feed_output(&outcome.output);
            attached
                .pane
                .update(cx, |pane, cx| pane.notify_output_changed(cx));
        }
        if let Some(title) = outcome.title {
            self.title = Some(title.into());
        }
        if let Some(error) = outcome.protocol_error {
            self.state = ContainerTerminalState::Failed(error.into());
            cx.notify();
            return false;
        }
        if let Some(state) = outcome.terminal_state {
            self.state = match state {
                TerminalTabState::Closed { exit_code } => {
                    ContainerTerminalState::Closed { exit_code }
                }
                TerminalTabState::Failed(message) => ContainerTerminalState::Failed(message.into()),
                _ => ContainerTerminalState::Open,
            };
            cx.notify();
            return false;
        }
        cx.notify();
        true
    }

    fn fail_event_pump(
        &mut self,
        lease: &ContainerTerminalLease,
        terminal_id: &str,
        error: String,
        cx: &mut Context<Self>,
    ) -> bool {
        if !self.accepts_lease(lease, cx)
            || self
                .attached
                .as_ref()
                .is_none_or(|attached| attached.terminal_id != terminal_id)
        {
            return false;
        }
        self.state = ContainerTerminalState::Failed(error.into());
        cx.notify();
        false
    }

    fn on_pane_event(&mut self, event: &TerminalPaneEvent, cx: &mut Context<Self>) {
        match event {
            TerminalPaneEvent::Shortcut(TerminalShortcut::Reconnect) => self.open_terminal(cx),
            TerminalPaneEvent::Shortcut(TerminalShortcut::CloseTab) => {
                self.attempt = self.attempt.saturating_add(1);
                self.close_attached(cx);
                self.state = ContainerTerminalState::Closed { exit_code: None };
            }
            TerminalPaneEvent::Shortcut(TerminalShortcut::FontIncrease) => {
                self.change_font_size(1.0, cx)
            }
            TerminalPaneEvent::Shortcut(TerminalShortcut::FontDecrease) => {
                self.change_font_size(-1.0, cx)
            }
            TerminalPaneEvent::Shortcut(TerminalShortcut::FontReset) => {
                self.set_font_size(TerminalConfig::default().font_size, cx)
            }
            TerminalPaneEvent::SearchRequested => {
                self.notice = Some("容器窗口搜索控件尚未暴露；复制与选择仍可直接使用".into());
            }
            TerminalPaneEvent::LinkActivated(link) => {
                self.notice = Some(format!("未自动打开远端链接：{}", link.uri).into());
            }
            TerminalPaneEvent::InputChanged { .. } | TerminalPaneEvent::Shortcut(_) => {}
        }
        cx.notify();
    }

    fn change_font_size(&mut self, delta: f32, cx: &mut Context<Self>) {
        self.set_font_size(
            (self.terminal_config.font_size + delta).clamp(8.0, 32.0),
            cx,
        );
    }

    fn set_font_size(&mut self, value: f32, cx: &mut Context<Self>) {
        self.terminal_config.font_size = value;
        if let Some(attached) = &self.attached
            && let Err(error) = attached
                .pane
                .update(cx, |pane, cx| pane.set_font_size(value, cx))
        {
            self.notice = Some(format!("字号更新失败：{error}").into());
        }
        cx.notify();
    }

    fn close_attached(&mut self, cx: &mut App) {
        let Some(attached) = self.attached.take() else {
            return;
        };
        attached.pane.update(cx, |pane, cx| {
            let _ = pane.close(cx);
        });
        self.close_arc(attached.session);
    }

    fn close_arc(&self, session: Arc<ContainerTerminalSession>) {
        drop(self.tokio.spawn(async move {
            if let Err(error) = CoreTerminalTransport::close(session.as_ref()).await {
                tracing::error!(%error, "failed to close container terminal");
            }
        }));
    }

    fn close_detached(&self, session: ContainerTerminalSession) {
        drop(self.tokio.spawn(async move {
            if let Err(error) = CoreTerminalTransport::close(&session).await {
                tracing::error!(%error, "failed to close stale container terminal");
            }
        }));
    }

    fn render_shell_button(
        &self,
        id: &'static str,
        shell: ContainerShell,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let active = self.shell == shell;
        div()
            .id(id)
            .h(px(26.0))
            .px_2()
            .flex()
            .items_center()
            .justify_center()
            .gap_1()
            .rounded_sm()
            .cursor_pointer()
            .text_xs()
            .border_1()
            .border_color(if active { tokens.accent } else { tokens.border })
            .bg(if active {
                tokens.surface_alt
            } else {
                tokens.surface
            })
            .on_click(cx.listener(move |terminal, _, _, cx| terminal.select_shell(shell, cx)))
            .child(Icon::new(IconName::SquareTerminal).size_3())
            .child(shell.label())
    }
}

impl Render for ContainerTerminalWindow {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        if self.close_window_requested {
            self.close_window_requested = false;
            window.remove_window();
        }
        let (tokens, target, lifecycle) = {
            let shared = self.shared.read(cx);
            (
                shared.theme.tokens(),
                shared.target_label.clone(),
                shared
                    .windows
                    .lifecycle(&self.ticket.kind)
                    .unwrap_or(WindowLifecycle::Closed),
            )
        };
        let palette = palette_for_tokens(tokens);
        if palette != self.terminal_palette {
            self.terminal_palette = palette;
            if let Some(attached) = &self.attached {
                attached
                    .pane
                    .update(cx, |pane, cx| pane.set_palette(palette, cx));
            }
        }
        if self.focus_terminal_requested {
            self.focus_terminal_requested = false;
            if let Some(attached) = &self.attached {
                attached.pane.read(cx).focus_handle(cx).focus(window);
            }
        }
        let pane = self.attached.as_ref().map(|attached| attached.pane.clone());
        let state = self.state.label();
        let title: SharedString = self
            .title
            .clone()
            .unwrap_or_else(|| self.ticket.kind.title());
        let lifecycle = match lifecycle {
            WindowLifecycle::Opening => "正在打开",
            WindowLifecycle::Open => "已打开",
            WindowLifecycle::Closing => "正在关闭",
            WindowLifecycle::Closed => "已关闭",
        };
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
                    .px_4()
                    .flex()
                    .items_center()
                    .justify_between()
                    .bg(tokens.surface)
                    .border_b_1()
                    .border_color(tokens.border)
                    .window_control_area(WindowControlArea::Drag)
                    .child(title)
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_3()
                            .child(div().text_xs().text_color(tokens.muted).child(lifecycle))
                            .child(div().text_xs().text_color(tokens.muted).child(target))
                            .child(
                                div()
                                    .id("container-terminal-window-close")
                                    .size(px(30.0))
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .rounded_sm()
                                    .cursor_pointer()
                                    .window_control_area(WindowControlArea::Close)
                                    .hover(|element| element.bg(tokens.surface_alt))
                                    .on_click(cx.listener(|terminal, _, window, cx| {
                                        terminal.request_close(window, cx)
                                    }))
                                    .child(Icon::new(IconName::Close).size_3p5()),
                            ),
                    ),
            )
            .child(
                div()
                    .h(px(40.0))
                    .px_3()
                    .flex()
                    .items_center()
                    .gap_2()
                    .border_b_1()
                    .border_color(tokens.border)
                    .bg(tokens.surface)
                    .child("Shell")
                    .child(self.render_shell_button(
                        "container-shell-sh",
                        ContainerShell::Sh,
                        tokens,
                        cx,
                    ))
                    .child(self.render_shell_button(
                        "container-shell-bash",
                        ContainerShell::Bash,
                        tokens,
                        cx,
                    ))
                    .child(self.render_shell_button(
                        "container-shell-ash",
                        ContainerShell::Ash,
                        tokens,
                        cx,
                    ))
                    .child(
                        div()
                            .id("container-terminal-reconnect")
                            .h(px(26.0))
                            .px_2()
                            .flex()
                            .items_center()
                            .gap_1()
                            .rounded_sm()
                            .cursor_pointer()
                            .border_1()
                            .border_color(tokens.border)
                            .on_click(cx.listener(|terminal, _, _, cx| terminal.open_terminal(cx)))
                            .child(Icon::new(IconName::Redo2).size_3())
                            .child("重连"),
                    )
                    .child(div().flex_1())
                    .child(
                        div()
                            .text_xs()
                            .text_color(tokens.muted)
                            .child(format!("{}px · {state}", self.terminal_config.font_size)),
                    ),
            )
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .min_h_0()
                    .bg(tokens.terminal_background)
                    .when_some(pane, |surface, pane| surface.child(pane))
                    .when(self.attached.is_none(), |surface| {
                        surface.child(
                            div()
                                .size_full()
                                .flex()
                                .items_center()
                                .justify_center()
                                .text_color(tokens.muted)
                                .child(state),
                        )
                    }),
            )
            .children(self.notice.clone().map(|notice| {
                div()
                    .px_3()
                    .py_1()
                    .border_t_1()
                    .border_color(tokens.border)
                    .bg(tokens.surface_alt)
                    .text_xs()
                    .text_color(tokens.warning)
                    .child(notice)
            }))
    }
}

#[cfg(test)]
mod tests {
    use lovelyres_core::docker::ContainerRuntime;
    use lovelyres_core::target::{TargetGuard, TargetIdentity};

    use super::*;

    fn key(generation: u64, runtime: ContainerRuntime) -> ContainerTerminalWindowKey {
        ContainerTerminalWindowKey::from_guard(
            &TargetGuard {
                identity: TargetIdentity::new("connection-a").unwrap(),
                generation,
            },
            &ContainerIdentity::new(runtime, "aaaaaaaaaaaa").unwrap(),
        )
    }

    #[test]
    fn open_lease_rejects_window_target_shell_and_attempt_changes() {
        let lease = ContainerTerminalLease {
            window_key: key(7, ContainerRuntime::Docker),
            ticket_generation: 11,
            attempt: 3,
            shell: ContainerShell::Sh,
        };
        assert_eq!(lease.window_key, key(7, ContainerRuntime::Docker));
        assert_ne!(lease.window_key, key(8, ContainerRuntime::Docker));
        assert_ne!(lease.window_key, key(7, ContainerRuntime::Podman));
        assert_ne!(lease.shell, ContainerShell::Bash);
        assert_ne!(lease.attempt, 4);
    }
}
