use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use async_channel::{Receiver, Sender, TrySendError};
use gpui::{
    App, AppContext, Bounds, ClipboardItem, Context, CursorStyle, ElementInputHandler, Entity,
    EntityInputHandler, EventEmitter, FocusHandle, Focusable, Font, FontFeatures, FontStyle,
    FontWeight, IntoElement, KeyDownEvent, MouseButton, MouseDownEvent, MouseMoveEvent,
    MouseUpEvent, Pixels, Point, Render, ScrollWheelEvent, Subscription, TextRun, Timer,
    UTF16Selection, Window, canvas, div, point, prelude::*, px, rgb, size,
};
use parking_lot::Mutex;
use thiserror::Error;

use crate::{
    CommandCompletion, ImeState, KeyAction, LinkMatch, MouseButtonCode, MouseEventKind,
    MouseModifiers, PointerSelection, RemoteCompletion, RenderCell, RenderCursor, SearchMatch,
    SearchOptions, SearchState, TerminalConfig, TerminalCursorShape, TerminalGeometry,
    TerminalKeyEncoder, TerminalModel, TerminalModelError, TerminalPalette, TerminalShortcut,
    TerminalSize, TerminalTransport, TerminalTransportError,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TerminalPaneEvent {
    SearchRequested,
    Shortcut(TerminalShortcut),
    LinkActivated(LinkMatch),
    InputChanged { line: String },
}

/// Interactive GPUI entity suitable for SSH and container terminal windows.
pub struct TerminalPane {
    model: Arc<Mutex<TerminalModel>>,
    transport: Arc<dyn TerminalTransport>,
    command_dispatcher: TransportCommandDispatcher,
    input_dispatch: PaneInputDispatch,
    focus_handle: FocusHandle,
    ime: ImeState,
    geometry: TerminalGeometry,
    last_bounds: Option<Bounds<Pixels>>,
    pointer: PointerSelection,
    palette: TerminalPalette,
    search_requested: bool,
    search_state: SearchState,
    pressed_link: Option<LinkMatch>,
    hovered_link: Option<LinkMatch>,
    activated_link: Option<LinkMatch>,
    completion: CommandCompletion,
    remote_completion: Option<RemoteCompletion>,
    focus_subscriptions: Vec<Subscription>,
    last_transport_error: Arc<Mutex<Option<TerminalTransportError>>>,
}

/// An input enqueue failure returns the bytes so callers can retry without loss.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TerminalInputQueueError {
    #[error("terminal input queue is full")]
    Backpressure(Vec<u8>),
    #[error("terminal input queue is closed")]
    Closed(Vec<u8>),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InputQueueSnapshot {
    pub rejected_events: u64,
    pub rejected_bytes: u64,
    pub last_rejected_bytes: usize,
    pub saturated: bool,
}

#[derive(Default)]
struct InputQueueCounters {
    rejected_events: AtomicU64,
    rejected_bytes: AtomicU64,
    last_rejected_bytes: AtomicUsize,
    saturated: AtomicBool,
}

impl InputQueueCounters {
    fn accepted(&self) {
        self.saturated.store(false, Ordering::Release);
    }

    fn rejected(&self, bytes: usize) {
        self.rejected_events.fetch_add(1, Ordering::Relaxed);
        self.rejected_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
        self.last_rejected_bytes.store(bytes, Ordering::Relaxed);
        self.saturated.store(true, Ordering::Release);
    }

    fn snapshot(&self) -> InputQueueSnapshot {
        InputQueueSnapshot {
            rejected_events: self.rejected_events.load(Ordering::Relaxed),
            rejected_bytes: self.rejected_bytes.load(Ordering::Relaxed),
            last_rejected_bytes: self.last_rejected_bytes.load(Ordering::Relaxed),
            saturated: self.saturated.load(Ordering::Acquire),
        }
    }
}

impl TerminalInputQueueError {
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            Self::Backpressure(bytes) | Self::Closed(bytes) => bytes,
        }
    }

    fn transport_error(&self) -> TerminalTransportError {
        match self {
            Self::Backpressure(_) => TerminalTransportError::Backpressure,
            Self::Closed(_) => TerminalTransportError::Closed,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResizeQueueStatus {
    Queued,
    Coalesced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseRequestStatus {
    Requested,
    AlreadyRequested,
}

#[derive(Clone)]
struct TransportCommandDispatcher {
    input_sender: Sender<Vec<u8>>,
    resize_pending: Arc<Mutex<Option<TerminalSize>>>,
    resize_notify: Sender<()>,
    close_sender: Sender<()>,
    closing: Arc<AtomicBool>,
}

struct TransportCommandWorkers {
    input_receiver: Receiver<Vec<u8>>,
    resize_pending: Arc<Mutex<Option<TerminalSize>>>,
    resize_notify: Receiver<()>,
    close_receiver: Receiver<()>,
    closing: Arc<AtomicBool>,
}

#[derive(Clone)]
struct PaneInputDispatch {
    commands: TransportCommandDispatcher,
    counters: Arc<InputQueueCounters>,
    last_transport_error: Arc<Mutex<Option<TerminalTransportError>>>,
}

impl PaneInputDispatch {
    fn new(
        commands: TransportCommandDispatcher,
        last_transport_error: Arc<Mutex<Option<TerminalTransportError>>>,
    ) -> Self {
        Self {
            commands,
            counters: Arc::new(InputQueueCounters::default()),
            last_transport_error,
        }
    }

    fn dispatch(&self, bytes: Vec<u8>) -> Result<(), TerminalInputQueueError> {
        let result = self.commands.try_send_input(bytes);
        match &result {
            Ok(()) => self.counters.accepted(),
            Err(error) => {
                let bytes = match error {
                    TerminalInputQueueError::Backpressure(bytes)
                    | TerminalInputQueueError::Closed(bytes) => bytes.len(),
                };
                self.counters.rejected(bytes);
                *self.last_transport_error.lock() = Some(error.transport_error());
            }
        }
        result
    }

    fn snapshot(&self) -> InputQueueSnapshot {
        self.counters.snapshot()
    }
}

fn transport_command_channel(
    input_capacity: usize,
) -> (TransportCommandDispatcher, TransportCommandWorkers) {
    let (input_sender, input_receiver) = async_channel::bounded(input_capacity);
    let (resize_notify_sender, resize_notify_receiver) = async_channel::bounded(1);
    let (close_sender, close_receiver) = async_channel::bounded(1);
    let resize_pending = Arc::new(Mutex::new(None));
    let closing = Arc::new(AtomicBool::new(false));
    (
        TransportCommandDispatcher {
            input_sender,
            resize_pending: resize_pending.clone(),
            resize_notify: resize_notify_sender,
            close_sender,
            closing: closing.clone(),
        },
        TransportCommandWorkers {
            input_receiver,
            resize_pending,
            resize_notify: resize_notify_receiver,
            close_receiver,
            closing,
        },
    )
}

impl TransportCommandDispatcher {
    fn try_send_input(&self, bytes: Vec<u8>) -> Result<(), TerminalInputQueueError> {
        if bytes.is_empty() {
            return Ok(());
        }
        if self.closing.load(Ordering::Acquire) {
            return Err(TerminalInputQueueError::Closed(bytes));
        }
        match self.input_sender.try_send(bytes) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(bytes)) => Err(TerminalInputQueueError::Backpressure(bytes)),
            Err(TrySendError::Closed(bytes)) => Err(TerminalInputQueueError::Closed(bytes)),
        }
    }

    fn request_resize(
        &self,
        size: TerminalSize,
    ) -> Result<ResizeQueueStatus, TerminalTransportError> {
        if self.closing.load(Ordering::Acquire) {
            return Err(TerminalTransportError::Closed);
        }
        let replaced = {
            let mut pending = self.resize_pending.lock();
            if self.closing.load(Ordering::Acquire) {
                return Err(TerminalTransportError::Closed);
            }
            pending.replace(size).is_some()
        };
        match self.resize_notify.try_send(()) {
            Ok(()) if replaced => Ok(ResizeQueueStatus::Coalesced),
            Ok(()) => Ok(ResizeQueueStatus::Queued),
            Err(TrySendError::Full(())) => Ok(ResizeQueueStatus::Coalesced),
            Err(TrySendError::Closed(())) => Err(TerminalTransportError::Closed),
        }
    }

    fn request_close(&self) -> Result<CloseRequestStatus, TerminalTransportError> {
        if self.closing.swap(true, Ordering::AcqRel) {
            return Ok(CloseRequestStatus::AlreadyRequested);
        }

        self.input_sender.close();
        self.resize_notify.close();
        match self.close_sender.try_send(()) {
            Ok(()) | Err(TrySendError::Full(())) => Ok(CloseRequestStatus::Requested),
            Err(TrySendError::Closed(())) => Err(TerminalTransportError::Closed),
        }
    }
}

async fn run_input_worker(
    receiver: Receiver<Vec<u8>>,
    closing: Arc<AtomicBool>,
    transport: Arc<dyn TerminalTransport>,
    last_error: Arc<Mutex<Option<TerminalTransportError>>>,
) {
    'commands: while let Ok(bytes) = receiver.recv().await {
        if closing.load(Ordering::Acquire) {
            break;
        }
        loop {
            if closing.load(Ordering::Acquire) {
                break 'commands;
            }
            match transport.send_input(&bytes).await {
                Ok(()) => break,
                Err(TerminalTransportError::Backpressure) => {
                    *last_error.lock() = Some(TerminalTransportError::Backpressure);
                    Timer::after(Duration::from_millis(1)).await;
                }
                Err(error) => {
                    let closed = error == TerminalTransportError::Closed;
                    *last_error.lock() = Some(error);
                    if closed {
                        break 'commands;
                    }
                    break;
                }
            }
        }
    }
}

async fn run_resize_worker(
    notify: Receiver<()>,
    pending: Arc<Mutex<Option<TerminalSize>>>,
    closing: Arc<AtomicBool>,
    transport: Arc<dyn TerminalTransport>,
    last_error: Arc<Mutex<Option<TerminalTransportError>>>,
) {
    while notify.recv().await.is_ok() {
        if closing.load(Ordering::Acquire) {
            break;
        }
        let Some(mut size) = pending.lock().take() else {
            continue;
        };
        loop {
            if closing.load(Ordering::Acquire) {
                return;
            }
            match transport.resize(size).await {
                Ok(()) => break,
                Err(TerminalTransportError::Backpressure) => {
                    *last_error.lock() = Some(TerminalTransportError::Backpressure);
                    if let Some(latest) = pending.lock().take() {
                        size = latest;
                    }
                    Timer::after(Duration::from_millis(1)).await;
                }
                Err(error) => {
                    let closed = error == TerminalTransportError::Closed;
                    *last_error.lock() = Some(error);
                    if closed {
                        return;
                    }
                    break;
                }
            }
        }
    }
}

async fn run_close_worker(
    receiver: Receiver<()>,
    transport: Arc<dyn TerminalTransport>,
    last_error: Arc<Mutex<Option<TerminalTransportError>>>,
) {
    if receiver.recv().await.is_err() {
        return;
    }
    loop {
        match transport.close().await {
            Ok(()) => return,
            Err(TerminalTransportError::Backpressure) => {
                *last_error.lock() = Some(TerminalTransportError::Backpressure);
                Timer::after(Duration::from_millis(1)).await;
            }
            Err(error) => {
                *last_error.lock() = Some(error);
                return;
            }
        }
    }
}

impl TerminalPane {
    pub fn new(
        model: Arc<Mutex<TerminalModel>>,
        transport: Arc<dyn TerminalTransport>,
        cx: &mut Context<Self>,
    ) -> Self {
        let (geometry, command_capacity) = {
            let model = model.lock();
            (
                TerminalGeometry::from_font(model.config().font_size, model.config().line_height),
                model.config().event_capacity,
            )
        };
        let (command_dispatcher, workers) = transport_command_channel(command_capacity);
        let last_transport_error = Arc::new(Mutex::new(None));
        let input_dispatch =
            PaneInputDispatch::new(command_dispatcher.clone(), last_transport_error.clone());
        cx.background_spawn(run_input_worker(
            workers.input_receiver,
            workers.closing.clone(),
            transport.clone(),
            last_transport_error.clone(),
        ))
        .detach();
        cx.background_spawn(run_resize_worker(
            workers.resize_notify,
            workers.resize_pending,
            workers.closing,
            transport.clone(),
            last_transport_error.clone(),
        ))
        .detach();
        cx.background_spawn(run_close_worker(
            workers.close_receiver,
            transport.clone(),
            last_transport_error.clone(),
        ))
        .detach();
        Self {
            model,
            transport,
            command_dispatcher,
            input_dispatch,
            focus_handle: cx.focus_handle(),
            ime: ImeState::default(),
            geometry,
            last_bounds: None,
            pointer: PointerSelection::default(),
            palette: TerminalPalette::default(),
            search_requested: false,
            search_state: SearchState::default(),
            pressed_link: None,
            hovered_link: None,
            activated_link: None,
            completion: CommandCompletion::new(),
            remote_completion: None,
            focus_subscriptions: Vec::new(),
            last_transport_error,
        }
    }

    pub fn attach(
        model: Arc<Mutex<TerminalModel>>,
        transport: Arc<dyn TerminalTransport>,
        cx: &mut App,
    ) -> Entity<Self> {
        cx.new(|cx| Self::new(model, transport, cx))
    }

    pub fn create(
        config: TerminalConfig,
        transport: Arc<dyn TerminalTransport>,
        cx: &mut App,
    ) -> Result<Entity<Self>, TerminalModelError> {
        let model = Arc::new(Mutex::new(TerminalModel::new(config)?));
        Ok(Self::attach(model, transport, cx))
    }

    pub fn model(&self) -> Arc<Mutex<TerminalModel>> {
        self.model.clone()
    }

    pub fn transport(&self) -> Arc<dyn TerminalTransport> {
        self.transport.clone()
    }

    pub fn ime(&self) -> &ImeState {
        &self.ime
    }

    pub fn geometry(&self) -> TerminalGeometry {
        self.geometry
    }

    pub fn set_palette(&mut self, palette: TerminalPalette, cx: &mut Context<Self>) {
        if self.palette == palette {
            return;
        }
        self.palette = palette;
        cx.notify();
    }

    pub fn set_font_size(
        &mut self,
        font_size: f32,
        cx: &mut Context<Self>,
    ) -> Result<(), TerminalModelError> {
        let line_height = self.model.lock().config().line_height;
        self.model.lock().update_font(font_size, line_height)?;
        self.geometry = TerminalGeometry::from_font(font_size, line_height)
            .with_padding(self.geometry.padding)
            .with_dpi_scale(self.geometry.dpi_scale);
        cx.notify();
        Ok(())
    }

    pub fn take_search_request(&mut self) -> bool {
        std::mem::take(&mut self.search_requested)
    }

    pub fn search_state(&self) -> &SearchState {
        &self.search_state
    }

    pub fn update_search(
        &mut self,
        query: impl Into<String>,
        options: SearchOptions,
        cx: &mut Context<Self>,
    ) -> Result<(), TerminalModelError> {
        self.search_state
            .update(&self.model.lock(), query, options)?;
        if let Some(found) = self.search_state.current().cloned() {
            self.reveal_search_match(&found);
        }
        cx.notify();
        Ok(())
    }

    pub fn search_next(&mut self, cx: &mut Context<Self>) -> Option<SearchMatch> {
        let found = self.search_state.next_match().cloned();
        if let Some(found) = &found {
            self.reveal_search_match(found);
        }
        cx.notify();
        found
    }

    pub fn search_previous(&mut self, cx: &mut Context<Self>) -> Option<SearchMatch> {
        let found = self.search_state.previous_match().cloned();
        if let Some(found) = &found {
            self.reveal_search_match(found);
        }
        cx.notify();
        found
    }

    pub fn clear_search(&mut self, cx: &mut Context<Self>) {
        self.search_state.clear();
        cx.notify();
    }

    fn reveal_search_match(&self, found: &SearchMatch) {
        let mut model = self.model.lock();
        let target = found
            .line
            .checked_neg()
            .and_then(|line| usize::try_from(line).ok())
            .unwrap_or(0)
            .min(model.history_size());
        let current = model.display_offset();
        let delta = i32::try_from(target)
            .unwrap_or(i32::MAX)
            .saturating_sub(i32::try_from(current).unwrap_or(i32::MAX));
        if delta != 0 {
            model.scroll_lines(delta);
        }
    }

    pub fn link_at_cell(&self, position: crate::CellPosition) -> Option<LinkMatch> {
        self.model.lock().hit_test_link(position)
    }

    /// Returns a Ctrl-clicked link for the owning window to validate and open.
    pub fn take_activated_link(&mut self) -> Option<LinkMatch> {
        self.activated_link.take()
    }

    pub fn completion_hint(&self) -> Option<&'static str> {
        self.completion.hint()
    }

    pub fn current_input_line(&self) -> &str {
        self.completion.line()
    }

    pub fn completion_is_reliable(&self) -> bool {
        self.completion.is_reliable()
    }

    pub fn set_remote_completion(
        &mut self,
        completion: Option<RemoteCompletion>,
        cx: &mut Context<Self>,
    ) {
        self.remote_completion = completion;
        cx.notify();
    }

    pub fn last_transport_error(&self) -> Option<TerminalTransportError> {
        self.last_transport_error.lock().clone()
    }

    pub fn clear_transport_error(&self) {
        *self.last_transport_error.lock() = None;
    }

    pub fn input_queue_snapshot(&self) -> InputQueueSnapshot {
        self.input_dispatch.snapshot()
    }

    pub fn close(&self, _cx: &Context<Self>) -> Result<CloseRequestStatus, TerminalTransportError> {
        let result = self.command_dispatcher.request_close();
        if let Err(error) = &result {
            *self.last_transport_error.lock() = Some(error.clone());
        }
        result
    }

    pub fn notify_output_changed(&self, cx: &mut Context<Self>) {
        cx.notify();
    }

    fn ensure_focus_reporting(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if !self.focus_subscriptions.is_empty() {
            return;
        }
        let handle = self.focus_handle.clone();
        let focused = cx.on_focus(&handle, window, |pane, _window, cx| {
            if pane.model.lock().reports_focus() && pane.dispatch_input(focus_report(true)).is_err()
            {
                cx.notify();
            }
        });
        let blurred = cx.on_blur(&handle, window, |pane, _window, cx| {
            if pane.model.lock().reports_focus()
                && pane.dispatch_input(focus_report(false)).is_err()
            {
                cx.notify();
            }
        });
        self.focus_subscriptions.extend([focused, blurred]);
    }

    pub fn try_send_input(&self, bytes: Vec<u8>) -> Result<(), TerminalInputQueueError> {
        self.input_dispatch.dispatch(bytes)
    }

    fn dispatch_input(&self, bytes: Vec<u8>) -> Result<(), TerminalInputQueueError> {
        self.try_send_input(bytes)
    }

    fn submit_user_input(&mut self, bytes: Vec<u8>, cx: &mut Context<Self>) {
        match self.dispatch_input(bytes.clone()) {
            Ok(()) => {
                self.remote_completion = None;
                self.completion.observe(&bytes);
                cx.emit(TerminalPaneEvent::InputChanged {
                    line: self.completion.line().to_owned(),
                });
            }
            Err(_) => cx.notify(),
        }
    }

    pub fn request_resize(
        &self,
        size: TerminalSize,
    ) -> Result<ResizeQueueStatus, TerminalTransportError> {
        let result = self.command_dispatcher.request_resize(size);
        if let Err(error) = &result {
            *self.last_transport_error.lock() = Some(error.clone());
        }
        result
    }

    fn dispatch_resize(&self, size: TerminalSize) {
        let _ = self.request_resize(size);
    }

    fn update_layout(
        &mut self,
        bounds: Bounds<Pixels>,
        measured_width: f32,
        measured_height: f32,
        dpi_scale: f32,
        cx: &mut Context<Self>,
    ) {
        self.last_bounds = Some(bounds);
        self.geometry = self
            .geometry
            .with_measured_cell(measured_width, measured_height)
            .with_dpi_scale(dpi_scale);
        let next_size = self
            .geometry
            .terminal_size(f32::from(bounds.size.width), f32::from(bounds.size.height));
        let changed = self.model.lock().size() != next_size;
        if changed && self.model.lock().resize(next_size).is_ok() {
            self.dispatch_resize(next_size);
            cx.notify();
        }
    }

    fn on_key_down(&mut self, event: &KeyDownEvent, _window: &mut Window, cx: &mut Context<Self>) {
        if TerminalKeyEncoder::is_plain_text(&event.keystroke) {
            return;
        }
        let (application_cursor, application_keypad) = {
            let model = self.model.lock();
            (model.is_application_cursor(), model.is_application_keypad())
        };
        match TerminalKeyEncoder::encode_with_modes(
            &event.keystroke,
            application_cursor,
            application_keypad,
        ) {
            KeyAction::Send(bytes) => {
                self.submit_user_input(bytes, cx);
            }
            KeyAction::Copy => {
                if let Some(text) = self.model.lock().selected_text() {
                    cx.write_to_clipboard(ClipboardItem::new_string(text));
                }
            }
            KeyAction::Paste => {
                if let Some(text) = cx.read_from_clipboard().and_then(|item| item.text()) {
                    let bytes = self.model.lock().paste_bytes(&text);
                    self.submit_user_input(bytes, cx);
                }
            }
            KeyAction::Search => {
                self.search_requested = true;
                cx.emit(TerminalPaneEvent::SearchRequested);
                cx.notify();
            }
            KeyAction::Workspace(TerminalShortcut::AcceptCompletion) => {
                let suffix = self
                    .remote_completion
                    .as_ref()
                    .and_then(|completion| completion.completion_suffix(self.completion.line()))
                    .or_else(|| self.completion.completion_suffix().map(str::to_owned));
                if let Some(suffix) = suffix {
                    self.submit_user_input(suffix.into_bytes(), cx);
                }
            }
            KeyAction::Workspace(TerminalShortcut::ScrollPageUp) => {
                self.model.lock().scroll_page_up();
                cx.notify();
            }
            KeyAction::Workspace(TerminalShortcut::ScrollPageDown) => {
                self.model.lock().scroll_page_down();
                cx.notify();
            }
            KeyAction::Workspace(TerminalShortcut::ScrollToTop) => {
                self.model.lock().scroll_to_top();
                cx.notify();
            }
            KeyAction::Workspace(TerminalShortcut::ScrollToBottom) => {
                self.model.lock().scroll_to_bottom();
                cx.notify();
            }
            KeyAction::Workspace(shortcut) => cx.emit(TerminalPaneEvent::Shortcut(shortcut)),
            KeyAction::Ignore => return,
        }
        cx.stop_propagation();
    }

    fn on_mouse_down(
        &mut self,
        event: &MouseDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.focus_handle.focus(window);
        let Some(position) = self.cell_for_window_point(event.position) else {
            return;
        };

        if event.button == MouseButton::Left && event.modifiers.secondary() {
            self.pressed_link = self.model.lock().hit_test_link(position);
            if self.pressed_link.is_some() {
                cx.stop_propagation();
                return;
            }
        }

        if !event.modifiers.shift
            && let Some(button) = mouse_button_code(event.button)
            && self.report_mouse(MouseEventKind::Press(button), position, event.modifiers, cx)
        {
            cx.stop_propagation();
            return;
        }

        if event.button != MouseButton::Left {
            return;
        }
        let _ = self.pointer.begin(&mut self.model.lock(), position);
        cx.notify();
    }

    fn on_mouse_move(
        &mut self,
        event: &MouseMoveEvent,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(position) = self.cell_for_window_point(event.position) else {
            return;
        };

        let hovered = self.model.lock().hit_test_link(position);
        if self.hovered_link != hovered {
            self.hovered_link = hovered;
            cx.notify();
        }

        if !event.modifiers.shift
            && self.report_mouse(
                MouseEventKind::Move(event.pressed_button.and_then(mouse_button_code)),
                position,
                event.modifiers,
                cx,
            )
        {
            cx.stop_propagation();
            return;
        }

        if !event.dragging() || !self.pointer.is_selecting() {
            return;
        }
        let _ = self.pointer.drag(&mut self.model.lock(), position);
        cx.notify();
    }

    fn on_mouse_up(&mut self, event: &MouseUpEvent, _window: &mut Window, cx: &mut Context<Self>) {
        let position = self.cell_for_window_point(event.position);
        if event.button == MouseButton::Left && event.modifiers.secondary() {
            let released = position.and_then(|position| self.model.lock().hit_test_link(position));
            if self.pressed_link.is_some() && self.pressed_link == released {
                self.activated_link = released;
                if let Some(link) = self.activated_link.clone() {
                    cx.emit(TerminalPaneEvent::LinkActivated(link));
                }
                self.pressed_link = None;
                self.pointer.end();
                cx.notify();
                cx.stop_propagation();
                return;
            }
        }
        self.pressed_link = None;

        if !event.modifiers.shift
            && let Some(position) = position
            && let Some(button) = mouse_button_code(event.button)
            && self.report_mouse(
                MouseEventKind::Release(button),
                position,
                event.modifiers,
                cx,
            )
        {
            self.pointer.end();
            cx.stop_propagation();
            return;
        }
        self.pointer.end();
    }

    fn on_scroll(
        &mut self,
        event: &ScrollWheelEvent,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let delta = event.delta.pixel_delta(px(self.geometry.cell_height));
        let lines = self.geometry.wheel_lines(f32::from(delta.y));
        if lines != 0
            && !event.modifiers.shift
            && let Some(position) = self.cell_for_window_point(event.position)
        {
            let event_kind = if lines > 0 {
                MouseEventKind::WheelUp
            } else {
                MouseEventKind::WheelDown
            };
            let mut reported = false;
            for _ in 0..lines.unsigned_abs() {
                reported |= self.report_mouse(event_kind, position, event.modifiers, cx);
            }
            if reported {
                cx.stop_propagation();
                return;
            }
        }
        if lines != 0 {
            self.model.lock().scroll_lines(lines);
            cx.notify();
            cx.stop_propagation();
        }
    }

    fn cell_for_window_point(&self, point: Point<Pixels>) -> Option<crate::CellPosition> {
        let bounds = self.last_bounds?;
        let x = f32::from(point.x - bounds.origin.x);
        let y = f32::from(point.y - bounds.origin.y);
        Some(
            self.geometry
                .cell_at_local_point(x, y, self.model.lock().size()),
        )
    }

    fn report_mouse(
        &self,
        event: MouseEventKind,
        position: crate::CellPosition,
        modifiers: gpui::Modifiers,
        cx: &mut Context<Self>,
    ) -> bool {
        let protocol = self.model.lock().mouse_protocol();
        let Some(bytes) = protocol.encode(event, position, mouse_modifiers(modifiers)) else {
            return false;
        };
        match self.dispatch_input(bytes) {
            Ok(()) => true,
            Err(_) => {
                cx.notify();
                false
            }
        }
    }

    fn cursor_local_origin(&self) -> (f32, f32) {
        let cursor = self.model.lock().render_snapshot().cursor;
        cursor
            .map(|cursor| {
                self.geometry
                    .cell_origin(crate::CellPosition::new(cursor.row, cursor.column))
            })
            .unwrap_or((self.geometry.padding, self.geometry.padding))
    }
}

impl Focusable for TerminalPane {
    fn focus_handle(&self, _cx: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

impl EntityInputHandler for TerminalPane {
    fn text_for_range(
        &mut self,
        range: Range<usize>,
        adjusted_range: &mut Option<Range<usize>>,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> Option<String> {
        let (adjusted, text) = self.ime.text_for_range(range)?;
        *adjusted_range = Some(adjusted);
        Some(text)
    }

    fn selected_text_range(
        &mut self,
        _ignore_disabled_input: bool,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> Option<UTF16Selection> {
        Some(UTF16Selection {
            range: self.ime.selection(),
            reversed: false,
        })
    }

    fn marked_text_range(
        &self,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> Option<Range<usize>> {
        self.ime.marked()
    }

    fn unmark_text(&mut self, _window: &mut Window, cx: &mut Context<Self>) {
        let bytes = self.ime.unmark_and_commit();
        self.submit_user_input(bytes, cx);
        cx.notify();
    }

    fn replace_text_in_range(
        &mut self,
        range: Option<Range<usize>>,
        text: &str,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let bytes = self.ime.commit(range, text);
        self.submit_user_input(bytes, cx);
        cx.notify();
    }

    fn replace_and_mark_text_in_range(
        &mut self,
        range: Option<Range<usize>>,
        new_text: &str,
        new_selected_range: Option<Range<usize>>,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.ime
            .replace_and_mark(range, new_text, new_selected_range);
        cx.notify();
    }

    fn bounds_for_range(
        &mut self,
        range_utf16: Range<usize>,
        element_bounds: Bounds<Pixels>,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> Option<Bounds<Pixels>> {
        let (cursor_x, cursor_y) = self.cursor_local_origin();
        let rect = self.ime.bounds_for_range(
            range_utf16,
            f32::from(element_bounds.origin.x) + cursor_x,
            f32::from(element_bounds.origin.y) + cursor_y,
            self.geometry.cell_width,
            self.geometry.cell_height,
        );
        Some(Bounds {
            origin: point(px(rect.x), px(rect.y)),
            size: size(px(rect.width), px(rect.height)),
        })
    }

    fn character_index_for_point(
        &mut self,
        point: Point<Pixels>,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> Option<usize> {
        let bounds = self.last_bounds?;
        let (cursor_x, _) = self.cursor_local_origin();
        Some(self.ime.character_index_for_x(
            f32::from(point.x),
            f32::from(bounds.origin.x) + cursor_x,
            self.geometry.cell_width,
        ))
    }
}

impl Render for TerminalPane {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.ensure_focus_reporting(window, cx);
        let snapshot = self.model.lock().render_snapshot();
        let focused = self.focus_handle.is_focused(window);
        let geometry = self.geometry;
        let palette = self.palette;
        let font_family = self.model.lock().config().font_family.clone();
        let font_size = self.model.lock().config().font_size;
        let cursor = snapshot.cursor.clone();
        let display_offset = snapshot.display_offset;
        let active_search_match = self.search_state.current().cloned();
        let input_queue = self.input_queue_snapshot();

        let rows = snapshot.rows.into_iter().map(move |cells| {
            div()
                .flex()
                .flex_none()
                .h(px(geometry.cell_height))
                .children(cells.into_iter().filter(|cell| cell.width != 0).map({
                    let cursor = cursor.clone();
                    let active_search_match = active_search_match.clone();
                    move |mut cell| {
                        if active_search_match.as_ref().is_some_and(|found| {
                            let line = i32::from(cell.row)
                                .saturating_sub(i32::try_from(display_offset).unwrap_or(i32::MAX));
                            line == found.line
                                && usize::from(cell.column) >= found.start_column
                                && usize::from(cell.column) < found.end_column
                        }) {
                            cell.selected = true;
                        }
                        render_cell(cell, cursor.clone(), focused, geometry, palette)
                    }
                }))
        });
        let terminal_content = div()
            .absolute()
            .left(px(geometry.padding))
            .top(px(geometry.padding))
            .flex()
            .flex_col()
            .children(rows);

        let pane_entity = cx.entity();
        let focus_handle = self.focus_handle.clone();
        let measure_family = font_family.clone();
        let line_height_multiplier = self.model.lock().config().line_height;
        let cursor_style = if self.hovered_link.is_some() {
            CursorStyle::PointingHand
        } else {
            CursorStyle::IBeam
        };
        let input_surface = canvas(
            move |_bounds, window, _cx| {
                let font = Font {
                    family: measure_family.into(),
                    features: FontFeatures::default(),
                    fallbacks: None,
                    weight: FontWeight::NORMAL,
                    style: FontStyle::Normal,
                };
                let run = TextRun {
                    len: 1,
                    font,
                    color: gpui::black(),
                    background_color: None,
                    underline: None,
                    strikethrough: None,
                };
                let shaped =
                    window
                        .text_system()
                        .shape_line("M".into(), px(font_size), &[run], None);
                (
                    f32::from(shaped.width),
                    f32::from(shaped.ascent + shaped.descent) * line_height_multiplier,
                    window.scale_factor(),
                )
            },
            move |bounds, (cell_width, cell_height, dpi_scale), window, cx| {
                window.handle_input(
                    &focus_handle,
                    ElementInputHandler::new(bounds, pane_entity.clone()),
                    cx,
                );
                pane_entity.update(cx, |pane, cx| {
                    pane.update_layout(bounds, cell_width, cell_height, dpi_scale, cx)
                });
            },
        )
        .absolute()
        .top_0()
        .left_0()
        .size_full();

        let (preedit_x, preedit_y) = self.cursor_local_origin();
        let preedit = (!self.ime.text().is_empty()).then(|| {
            div()
                .absolute()
                .left(px(preedit_x))
                .top(px(preedit_y))
                .h(px(geometry.cell_height))
                .line_height(px(geometry.cell_height))
                .bg(rgb(palette.background))
                .text_color(rgb(palette.foreground))
                .underline()
                .child(self.ime.text().to_owned())
        });
        let input_backpressure = input_queue.saturated.then(|| {
            div()
                .id("terminal-input-backpressure")
                .absolute()
                .top(px(8.0))
                .right(px(8.0))
                .rounded_md()
                .px_2()
                .py_1()
                .bg(rgb(0x7f1d1d))
                .text_color(rgb(0xfef2f2))
                .text_xs()
                .child(format!(
                    "输入队列繁忙：最近 {} 字节未接收",
                    input_queue.last_rejected_bytes
                ))
        });
        let completion_hint = self
            .remote_completion
            .as_ref()
            .map(|completion| {
                completion
                    .candidates()
                    .iter()
                    .take(8)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("  ")
            })
            .or_else(|| self.completion.hint().map(str::to_owned))
            .map(|hint| {
                div()
                    .id("terminal-command-hint")
                    .absolute()
                    .bottom(px(8.0))
                    .right(px(8.0))
                    .rounded_md()
                    .px_2()
                    .py_1()
                    .bg(rgb(0x172033))
                    .text_color(rgb(0xa9b7cb))
                    .text_xs()
                    .child(format!("提示：{hint}  ·  Ctrl+Space 补全"))
            });

        div()
            .id("lovelyres-terminal-pane")
            .key_context("Terminal")
            .track_focus(&self.focus_handle)
            .relative()
            .size_full()
            .overflow_hidden()
            .bg(rgb(palette.background))
            .font_family(font_family)
            .text_size(px(font_size))
            .cursor(cursor_style)
            .on_key_down(cx.listener(Self::on_key_down))
            .on_mouse_down(MouseButton::Left, cx.listener(Self::on_mouse_down))
            .on_mouse_down(MouseButton::Middle, cx.listener(Self::on_mouse_down))
            .on_mouse_down(MouseButton::Right, cx.listener(Self::on_mouse_down))
            .on_mouse_move(cx.listener(Self::on_mouse_move))
            .on_mouse_up(MouseButton::Left, cx.listener(Self::on_mouse_up))
            .on_mouse_up(MouseButton::Middle, cx.listener(Self::on_mouse_up))
            .on_mouse_up(MouseButton::Right, cx.listener(Self::on_mouse_up))
            .on_mouse_up_out(MouseButton::Left, cx.listener(Self::on_mouse_up))
            .on_mouse_up_out(MouseButton::Middle, cx.listener(Self::on_mouse_up))
            .on_mouse_up_out(MouseButton::Right, cx.listener(Self::on_mouse_up))
            .on_scroll_wheel(cx.listener(Self::on_scroll))
            .child(terminal_content)
            .children(preedit)
            .child(input_surface)
            .children(input_backpressure)
            .children(completion_hint)
    }
}

impl EventEmitter<TerminalPaneEvent> for TerminalPane {}

fn focus_report(focused: bool) -> Vec<u8> {
    if focused {
        b"\x1b[I".to_vec()
    } else {
        b"\x1b[O".to_vec()
    }
}

fn mouse_button_code(button: MouseButton) -> Option<MouseButtonCode> {
    match button {
        MouseButton::Left => Some(MouseButtonCode::Left),
        MouseButton::Middle => Some(MouseButtonCode::Middle),
        MouseButton::Right => Some(MouseButtonCode::Right),
        MouseButton::Navigate(_) => None,
    }
}

fn mouse_modifiers(modifiers: gpui::Modifiers) -> MouseModifiers {
    MouseModifiers {
        shift: modifiers.shift,
        alt: modifiers.alt,
        control: modifiers.control,
    }
}

fn render_cell(
    cell: RenderCell,
    cursor: Option<RenderCursor>,
    focused: bool,
    geometry: TerminalGeometry,
    palette: TerminalPalette,
) -> impl IntoElement {
    let mut foreground = palette.resolve(&cell.foreground, true, cell.bold, cell.dim);
    let mut background = palette.resolve(&cell.background, false, false, false);
    if cell.inverse {
        std::mem::swap(&mut foreground, &mut background);
    }
    if cell.selected {
        background = palette.selection;
    }
    let cursor_shape = cursor
        .as_ref()
        .filter(|cursor| cursor.row == cell.row && cursor.column == cell.column)
        .map(|cursor| cursor.shape);
    if focused && cursor_shape == Some(TerminalCursorShape::Block) {
        background = palette.cursor;
        foreground = palette.background;
    }
    let text = if cell.hidden { " " } else { &cell.text };

    div()
        .flex_none()
        .w(px(geometry.cell_width * f32::from(cell.width)))
        .h(px(geometry.cell_height))
        .line_height(px(geometry.cell_height))
        .overflow_hidden()
        .bg(rgb(background))
        .text_color(rgb(foreground))
        .when(cell.bold, |element| element.font_weight(FontWeight::BOLD))
        .when(cell.italic, |element| element.italic())
        .when(cell.underline, |element| element.underline())
        .when(cell.strikeout, |element| element.line_through())
        .when(
            focused && cursor_shape == Some(TerminalCursorShape::HollowBlock),
            |element| element.border_1().border_color(rgb(palette.cursor)),
        )
        .when(
            focused && cursor_shape == Some(TerminalCursorShape::Underline),
            |element| element.border_b_2().border_color(rgb(palette.cursor)),
        )
        .when(
            focused && cursor_shape == Some(TerminalCursorShape::Beam),
            |element| element.border_l_2().border_color(rgb(palette.cursor)),
        )
        .child(text.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::mpsc::{Receiver as StdReceiver, SyncSender, sync_channel};
    use std::thread::JoinHandle;

    struct RecordingTransport {
        inputs: Mutex<Vec<Vec<u8>>>,
        resizes: Mutex<Vec<TerminalSize>>,
        input_delay: Duration,
        resize_delay: Duration,
        input_started: SyncSender<()>,
        input_completed: SyncSender<()>,
        resize_started: SyncSender<()>,
        resize_completed: SyncSender<()>,
        close_completed: SyncSender<()>,
    }

    struct RecordingSignals {
        input_started: StdReceiver<()>,
        input_completed: StdReceiver<()>,
        resize_started: StdReceiver<()>,
        resize_completed: StdReceiver<()>,
        close_completed: StdReceiver<()>,
    }

    struct BackpressuredInputTransport {
        remaining_rejections: AtomicUsize,
        inputs: Mutex<Vec<Vec<u8>>>,
        input_completed: SyncSender<()>,
    }

    fn recording_transport(
        input_delay: Duration,
        resize_delay: Duration,
        signal_capacity: usize,
    ) -> (Arc<RecordingTransport>, RecordingSignals) {
        let (input_started_tx, input_started) = sync_channel(signal_capacity);
        let (input_completed_tx, input_completed) = sync_channel(signal_capacity);
        let (resize_started_tx, resize_started) = sync_channel(signal_capacity);
        let (resize_completed_tx, resize_completed) = sync_channel(signal_capacity);
        let (close_completed_tx, close_completed) = sync_channel(1);
        (
            Arc::new(RecordingTransport {
                inputs: Mutex::new(Vec::new()),
                resizes: Mutex::new(Vec::new()),
                input_delay,
                resize_delay,
                input_started: input_started_tx,
                input_completed: input_completed_tx,
                resize_started: resize_started_tx,
                resize_completed: resize_completed_tx,
                close_completed: close_completed_tx,
            }),
            RecordingSignals {
                input_started,
                input_completed,
                resize_started,
                resize_completed,
                close_completed,
            },
        )
    }

    #[async_trait::async_trait]
    impl TerminalTransport for RecordingTransport {
        async fn send_input(&self, bytes: &[u8]) -> Result<(), TerminalTransportError> {
            self.input_started.send(()).unwrap();
            std::thread::sleep(self.input_delay);
            self.inputs.lock().push(bytes.to_vec());
            self.input_completed.send(()).unwrap();
            Ok(())
        }

        async fn resize(&self, size: TerminalSize) -> Result<(), TerminalTransportError> {
            self.resize_started.send(()).unwrap();
            std::thread::sleep(self.resize_delay);
            self.resizes.lock().push(size);
            self.resize_completed.send(()).unwrap();
            Ok(())
        }

        async fn close(&self) -> Result<(), TerminalTransportError> {
            self.close_completed.send(()).unwrap();
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl TerminalTransport for BackpressuredInputTransport {
        async fn send_input(&self, bytes: &[u8]) -> Result<(), TerminalTransportError> {
            if self
                .remaining_rejections
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
            {
                return Err(TerminalTransportError::Backpressure);
            }
            self.inputs.lock().push(bytes.to_vec());
            self.input_completed.send(()).unwrap();
            Ok(())
        }

        async fn resize(&self, _size: TerminalSize) -> Result<(), TerminalTransportError> {
            Ok(())
        }

        async fn close(&self) -> Result<(), TerminalTransportError> {
            Ok(())
        }
    }

    fn spawn_transport_workers(
        workers: TransportCommandWorkers,
        transport: Arc<dyn TerminalTransport>,
        last_error: Arc<Mutex<Option<TerminalTransportError>>>,
    ) -> [JoinHandle<()>; 3] {
        let TransportCommandWorkers {
            input_receiver,
            resize_pending,
            resize_notify,
            close_receiver,
            closing,
        } = workers;
        let input_transport = transport.clone();
        let input_error = last_error.clone();
        let input_closing = closing.clone();
        let input_worker = std::thread::spawn(move || {
            futures::executor::block_on(run_input_worker(
                input_receiver,
                input_closing,
                input_transport,
                input_error,
            ));
        });
        let resize_transport = transport.clone();
        let resize_error = last_error.clone();
        let resize_worker = std::thread::spawn(move || {
            futures::executor::block_on(run_resize_worker(
                resize_notify,
                resize_pending,
                closing,
                resize_transport,
                resize_error,
            ));
        });
        let close_worker = std::thread::spawn(move || {
            futures::executor::block_on(run_close_worker(close_receiver, transport, last_error));
        });
        [input_worker, resize_worker, close_worker]
    }

    fn join_workers(workers: [JoinHandle<()>; 3]) {
        for worker in workers {
            worker.join().unwrap();
        }
    }

    #[test]
    fn dec_focus_reports_use_csi_i_and_o() {
        assert_eq!(focus_report(true), b"\x1b[I");
        assert_eq!(focus_report(false), b"\x1b[O");
    }

    #[test]
    fn navigation_mouse_buttons_are_not_reported_as_dec_buttons() {
        assert_eq!(
            mouse_button_code(MouseButton::Left),
            Some(MouseButtonCode::Left)
        );
        assert_eq!(
            mouse_button_code(MouseButton::Navigate(gpui::NavigationDirection::Back)),
            None
        );
    }

    #[test]
    fn bounded_input_queue_preserves_concurrent_producer_bytes_and_order() {
        const PRODUCERS: u8 = 3;
        const MESSAGES_PER_PRODUCER: u8 = 16;
        let message_count = usize::from(PRODUCERS) * usize::from(MESSAGES_PER_PRODUCER);
        let (transport, signals) =
            recording_transport(Duration::from_millis(2), Duration::ZERO, message_count);
        let (dispatcher, worker_queues) = transport_command_channel(2);
        let errors = Arc::new(Mutex::new(None));
        let input_dispatch = PaneInputDispatch::new(dispatcher.clone(), errors.clone());
        let workers = spawn_transport_workers(worker_queues, transport.clone(), errors.clone());
        let backpressure_count = Arc::new(AtomicUsize::new(0));

        let producers = (0..PRODUCERS)
            .map(|producer| {
                let input_dispatch = input_dispatch.clone();
                let backpressure_count = backpressure_count.clone();
                std::thread::spawn(move || {
                    for sequence in 0..MESSAGES_PER_PRODUCER {
                        let mut bytes = vec![producer, sequence, 0xa5];
                        loop {
                            match input_dispatch.dispatch(bytes) {
                                Ok(()) => break,
                                Err(TerminalInputQueueError::Backpressure(returned)) => {
                                    backpressure_count.fetch_add(1, Ordering::Relaxed);
                                    bytes = returned;
                                    std::thread::yield_now();
                                }
                                Err(TerminalInputQueueError::Closed(_)) => {
                                    panic!("input queue closed before the test completed")
                                }
                            }
                        }
                    }
                })
            })
            .collect::<Vec<_>>();
        for producer in producers {
            producer.join().unwrap();
        }
        for _ in 0..message_count {
            signals
                .input_completed
                .recv_timeout(Duration::from_secs(2))
                .unwrap();
        }

        assert!(backpressure_count.load(Ordering::Relaxed) > 0);
        let snapshot = input_dispatch.snapshot();
        assert!(snapshot.rejected_events > 0);
        assert!(snapshot.rejected_bytes > 0);
        let recorded = transport.inputs.lock().clone();
        assert_eq!(recorded.len(), message_count);
        for producer in 0..PRODUCERS {
            let sequences = recorded
                .iter()
                .filter(|bytes| bytes[0] == producer)
                .map(|bytes| bytes[1])
                .collect::<Vec<_>>();
            assert_eq!(sequences, (0..MESSAGES_PER_PRODUCER).collect::<Vec<_>>());
            assert!(
                recorded
                    .iter()
                    .filter(|bytes| bytes[0] == producer)
                    .all(|bytes| bytes.as_slice() == [producer, bytes[1], 0xa5])
            );
        }
        assert_eq!(*errors.lock(), Some(TerminalTransportError::Backpressure));

        assert_eq!(
            dispatcher.request_close().unwrap(),
            CloseRequestStatus::Requested
        );
        signals
            .close_completed
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        join_workers(workers);
    }

    #[test]
    fn full_input_queue_returns_the_unaccepted_bytes() {
        let (dispatcher, _workers) = transport_command_channel(1);
        let errors = Arc::new(Mutex::new(None));
        let input_dispatch = PaneInputDispatch::new(dispatcher, errors.clone());
        input_dispatch.dispatch(b"accepted".to_vec()).unwrap();
        let rejected = b"retry-me".to_vec();
        let error = input_dispatch.dispatch(rejected.clone()).unwrap_err();
        assert_eq!(
            error,
            TerminalInputQueueError::Backpressure(rejected.clone())
        );
        assert_eq!(error.into_bytes(), rejected);
        assert_eq!(
            input_dispatch.snapshot(),
            InputQueueSnapshot {
                rejected_events: 1,
                rejected_bytes: 8,
                last_rejected_bytes: 8,
                saturated: true,
            }
        );
        assert_eq!(*errors.lock(), Some(TerminalTransportError::Backpressure));
    }

    #[test]
    fn downstream_backpressure_retries_the_same_bytes_before_advancing() {
        let (completed_tx, completed) = sync_channel(2);
        let transport = Arc::new(BackpressuredInputTransport {
            remaining_rejections: AtomicUsize::new(3),
            inputs: Mutex::new(Vec::new()),
            input_completed: completed_tx,
        });
        let (dispatcher, worker_queues) = transport_command_channel(2);
        let errors = Arc::new(Mutex::new(None));
        let input_dispatch = PaneInputDispatch::new(dispatcher.clone(), errors.clone());
        let workers = spawn_transport_workers(worker_queues, transport.clone(), errors.clone());

        input_dispatch.dispatch(b"first".to_vec()).unwrap();
        input_dispatch.dispatch(b"second".to_vec()).unwrap();
        for _ in 0..2 {
            completed.recv_timeout(Duration::from_secs(1)).unwrap();
        }

        assert_eq!(
            *transport.inputs.lock(),
            vec![b"first".to_vec(), b"second".to_vec()]
        );
        assert_eq!(*errors.lock(), Some(TerminalTransportError::Backpressure));
        dispatcher.request_close().unwrap();
        join_workers(workers);
    }

    #[test]
    fn resize_queue_coalesces_to_the_latest_pending_size() {
        let (transport, signals) =
            recording_transport(Duration::ZERO, Duration::from_millis(150), 4);
        let (dispatcher, worker_queues) = transport_command_channel(1);
        let errors = Arc::new(Mutex::new(None));
        let workers = spawn_transport_workers(worker_queues, transport.clone(), errors.clone());
        let first = TerminalSize::new(80, 24).unwrap();
        let middle = TerminalSize::new(100, 30).unwrap();
        let latest = TerminalSize::new(140, 44).unwrap();

        assert_eq!(
            dispatcher.request_resize(first).unwrap(),
            ResizeQueueStatus::Queued
        );
        signals
            .resize_started
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        assert_eq!(
            dispatcher.request_resize(middle).unwrap(),
            ResizeQueueStatus::Queued
        );
        assert_eq!(
            dispatcher.request_resize(latest).unwrap(),
            ResizeQueueStatus::Coalesced
        );
        for _ in 0..2 {
            signals
                .resize_completed
                .recv_timeout(Duration::from_secs(1))
                .unwrap();
        }
        assert_eq!(*transport.resizes.lock(), vec![first, latest]);
        assert_eq!(*errors.lock(), None);

        dispatcher.request_close().unwrap();
        signals
            .close_completed
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        join_workers(workers);
    }

    #[test]
    fn close_bypasses_a_saturated_input_queue() {
        let (transport, signals) = recording_transport(Duration::from_secs(1), Duration::ZERO, 4);
        let (dispatcher, worker_queues) = transport_command_channel(1);
        let errors = Arc::new(Mutex::new(None));
        let input_dispatch = PaneInputDispatch::new(dispatcher.clone(), errors.clone());
        let workers = spawn_transport_workers(worker_queues, transport, errors);

        input_dispatch.dispatch(b"in-flight".to_vec()).unwrap();
        signals
            .input_started
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        input_dispatch.dispatch(b"queued".to_vec()).unwrap();
        assert!(matches!(
            input_dispatch.dispatch(b"rejected".to_vec()),
            Err(TerminalInputQueueError::Backpressure(bytes)) if bytes == b"rejected"
        ));

        assert_eq!(
            dispatcher.request_close().unwrap(),
            CloseRequestStatus::Requested
        );
        signals
            .close_completed
            .recv_timeout(Duration::from_millis(250))
            .expect("the independent close worker must not wait for input capacity");
        assert_eq!(
            dispatcher.request_close().unwrap(),
            CloseRequestStatus::AlreadyRequested
        );
        assert!(matches!(
            input_dispatch.dispatch(b"after-close".to_vec()),
            Err(TerminalInputQueueError::Closed(bytes)) if bytes == b"after-close"
        ));

        signals
            .input_completed
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        join_workers(workers);
    }
}
