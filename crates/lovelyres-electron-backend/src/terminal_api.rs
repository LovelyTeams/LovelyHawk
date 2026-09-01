//! Standalone, target-bound terminal boundary for the Electron sidecar.
//!
//! It owns a bounded headless terminal model and uses only the SSH binding capability minted by
//! `SshApi`. Raw binding and terminal handles stay behind the Electron main-process boundary.

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use lovelyres_core::{
    BackendServices, CoreError,
    docker::{ContainerIdentity, ContainerShell},
    events::{
        TerminalEvent as CoreTerminalEvent, TerminalEventKind,
        TerminalTransport as CoreTerminalTransport,
    },
    ssh::BoundSshSession,
    target::TargetGuard,
};
use lovelyres_terminal::{
    CellColor, RenderCell, RenderCursor, SearchOptions, TerminalConfig, TerminalCursorShape,
    TerminalModel, TerminalSize,
};
use serde::Serialize;
use uuid::Uuid;

use crate::ssh_api::SshApi;

const MAX_TERMINALS: usize = 16;
const MAX_TERMINALS_PER_TARGET: usize = 2;
const MAX_HANDLE_BYTES: usize = 128;
const MAX_COLUMNS: u16 = 160;
const MAX_ROWS: u16 = 60;
const MAX_SCROLLBACK_LINES: usize = 5_000;
const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_INPUT_BASE64_BYTES: usize = MAX_INPUT_BYTES.div_ceil(3) * 4;
const MAX_POLL_EVENTS: usize = 64;
const MAX_POLL_BYTES: usize = 256 * 1024;
const MAX_OUTPUT_EVENT_BYTES: usize = MAX_POLL_BYTES;
const MAX_TOTAL_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TITLE_BYTES: usize = 4 * 1024;
const MAX_CELL_TEXT_BYTES: usize = 256;
const MAX_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;
const MAX_SEARCH_QUERY_BYTES: usize = 1024;
const MAX_SEARCH_RESULTS: usize = 256;
const MAX_SEARCH_MATCH_BYTES: usize = 4 * 1024;
const MAX_SEARCH_RESPONSE_BYTES: usize = 128 * 1024;
const HANDLE_ATTEMPTS: usize = 8;
const OPEN_TIMEOUT: Duration = Duration::from_secs(30);
const OPEN_RESERVATION_TTL: Duration = Duration::from_secs(35);
const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct TerminalApi {
    services: BackendServices,
    ssh: Arc<SshApi>,
    registry: Mutex<TerminalRegistry>,
}

impl fmt::Debug for TerminalApi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let terminal_count = self
            .registry
            .lock()
            .map(|registry| registry.slots.len())
            .unwrap_or_default();
        formatter
            .debug_struct("TerminalApi")
            .field("terminal_count", &terminal_count)
            .finish()
    }
}

impl TerminalApi {
    pub(crate) fn new(services: BackendServices, ssh: Arc<SshApi>) -> Self {
        Self {
            services,
            ssh,
            registry: Mutex::new(TerminalRegistry::default()),
        }
    }

    /// Open a login shell on the bound host.
    pub(crate) async fn open(
        &self,
        binding_handle: &str,
        columns: u16,
        rows: u16,
    ) -> Result<TerminalOpenedDto, TerminalApiError> {
        self.open_launch(binding_handle, TerminalLaunch::HostShell, columns, rows)
            .await
    }

    /// Open a shell inside a running container on the bound host.
    ///
    /// The container identity is resolved from an opaque handle by the Docker
    /// read boundary before this is called, so nothing here ever sees a caller
    /// supplied container id.
    pub(crate) async fn open_container(
        &self,
        binding_handle: &str,
        container: ContainerIdentity,
        shell: ContainerShell,
        columns: u16,
        rows: u16,
    ) -> Result<TerminalOpenedDto, TerminalApiError> {
        self.open_launch(
            binding_handle,
            TerminalLaunch::Container { container, shell },
            columns,
            rows,
        )
        .await
    }

    async fn open_launch(
        &self,
        binding_handle: &str,
        launch: TerminalLaunch,
        columns: u16,
        rows: u16,
    ) -> Result<TerminalOpenedDto, TerminalApiError> {
        let size = terminal_size(columns, rows)?;
        let config = TerminalConfig {
            size,
            scrollback_limit: MAX_SCROLLBACK_LINES,
            ..TerminalConfig::default()
        };
        let model = TerminalModel::new(config).map_err(|_| TerminalApiError::InvalidBounds)?;
        let binding = self.binding_session(binding_handle)?;
        self.ensure_binding_unchanged(binding_handle, &binding)?;
        let guard = binding.target().clone();
        let (handle, terminal_id) =
            self.lock_registry()?
                .reserve(binding_handle, &guard, Instant::now())?;

        if let Err(error) = self.ensure_binding_unchanged(binding_handle, &binding) {
            self.remove_slot(&handle);
            return Err(error);
        }

        // The only step that differs between a host shell and a container
        // shell. Both arrive as the same `dyn` transport, so everything below
        // — the guard re-checks, the registry activation, the cleanup on every
        // failure path — is one implementation rather than two that can drift.
        let opened = match &launch {
            TerminalLaunch::HostShell => tokio::time::timeout(
                OPEN_TIMEOUT,
                self.services.run_guarded(&guard, || {
                    self.services.ssh().open_terminal_bound(
                        &binding,
                        terminal_id.clone(),
                        columns,
                        rows,
                    )
                }),
            )
            .await
            .map(|result| result.map(transport_of)),
            TerminalLaunch::Container { container, shell } => tokio::time::timeout(
                OPEN_TIMEOUT,
                self.services.run_guarded(&guard, || {
                    self.services.docker().open_terminal(
                        &binding,
                        container,
                        *shell,
                        terminal_id.clone(),
                        columns,
                        rows,
                    )
                }),
            )
            .await
            .map(|result| result.map(transport_of)),
        };
        let terminal = match opened {
            Ok(Ok(terminal)) => terminal,
            Ok(Err(error)) => {
                self.remove_slot(&handle);
                return Err(TerminalApiError::Core(error));
            }
            Err(_) => {
                self.remove_slot(&handle);
                return Err(TerminalApiError::TimedOut);
            }
        };

        if let Err(error) = self.ensure_binding_unchanged(binding_handle, &binding) {
            self.remove_slot(&handle);
            close_transport(&terminal).await;
            return Err(error);
        }

        let active = Arc::new(ActiveTerminal {
            binding_handle: binding_handle.to_owned(),
            binding,
            guard,
            terminal_id,
            transport: terminal,
            state: Mutex::new(TerminalState::new(model)),
        });
        if let Err(error) = self.ensure_active(&active) {
            self.remove_slot(&handle);
            close_transport(&active.transport).await;
            return Err(error);
        }
        let activation = {
            self.lock_registry()?.activate(
                &handle,
                &active.binding_handle,
                &active.guard,
                Arc::clone(&active),
                Instant::now(),
            )
        };
        if let Err(error) = activation {
            close_transport(&active.transport).await;
            return Err(error);
        }
        if let Err(error) = self.ensure_active(&active) {
            let _ = self.remove_active(&handle, &active);
            close_transport(&active.transport).await;
            return Err(error);
        }

        Ok(TerminalOpenedDto {
            handle,
            columns,
            rows,
        })
    }

    pub(crate) async fn poll(
        &self,
        handle: &str,
        maximum_events: usize,
        maximum_bytes: usize,
    ) -> Result<TerminalPollDto, TerminalApiError> {
        validate_poll_bounds(maximum_events, maximum_bytes)?;
        let active = self.active(handle)?;
        if let Err(error) = self.ensure_active(&active) {
            self.invalidate(handle, &active).await;
            return Err(error);
        }

        let drained = {
            let mut state = active.lock_state()?;
            state.poll(&active.terminal_id, maximum_events, maximum_bytes, || {
                read_terminal_event(&active.transport)
            })
        };
        let mut response = match drained {
            Ok(response) => response,
            Err(error) => {
                self.invalidate(handle, &active).await;
                return Err(error);
            }
        };
        response.has_more |= !active.transport.events().is_empty();
        if let Err(error) = self.ensure_active(&active) {
            self.invalidate(handle, &active).await;
            return Err(error);
        }
        Ok(response)
    }

    pub(crate) async fn input(
        &self,
        handle: &str,
        bytes_base64: &str,
    ) -> Result<TerminalInputDto, TerminalApiError> {
        let bytes = decode_input(bytes_base64)?;
        let accepted_bytes = bytes.len();
        let active = self.active(handle)?;
        if let Err(error) = self.ensure_active(&active) {
            self.invalidate(handle, &active).await;
            return Err(error);
        }
        let result = tokio::time::timeout(CONTROL_TIMEOUT, active.transport.write_input(bytes))
            .await
            .map_err(|_| TerminalApiError::TimedOut)?;
        if let Err(error) = result {
            self.invalidate(handle, &active).await;
            return Err(TerminalApiError::Core(error));
        }
        if let Err(error) = self.ensure_active(&active) {
            self.invalidate(handle, &active).await;
            return Err(error);
        }
        Ok(TerminalInputDto { accepted_bytes })
    }

    pub(crate) async fn resize(
        &self,
        handle: &str,
        columns: u16,
        rows: u16,
    ) -> Result<TerminalResizedDto, TerminalApiError> {
        let size = terminal_size(columns, rows)?;
        let active = self.active(handle)?;
        if let Err(error) = self.ensure_active(&active) {
            self.invalidate(handle, &active).await;
            return Err(error);
        }
        let result = tokio::time::timeout(CONTROL_TIMEOUT, active.transport.resize(columns, rows))
            .await
            .map_err(|_| TerminalApiError::TimedOut)?;
        if let Err(error) = result {
            self.invalidate(handle, &active).await;
            return Err(TerminalApiError::Core(error));
        }
        if let Err(error) = self.ensure_active(&active) {
            self.invalidate(handle, &active).await;
            return Err(error);
        }
        active
            .lock_state()?
            .model
            .resize(size)
            .map_err(|_| TerminalApiError::InvalidBounds)?;
        if let Err(error) = self.ensure_active(&active) {
            self.invalidate(handle, &active).await;
            return Err(error);
        }
        Ok(TerminalResizedDto { columns, rows })
    }

    pub(crate) async fn render_snapshot(
        &self,
        handle: &str,
    ) -> Result<TerminalRenderSnapshotDto, TerminalApiError> {
        let active = self.active(handle)?;
        if let Err(error) = self.ensure_active(&active) {
            self.invalidate(handle, &active).await;
            return Err(error);
        }
        let snapshot = active.lock_state()?.render_snapshot()?;
        if let Err(error) = self.ensure_active(&active) {
            self.invalidate(handle, &active).await;
            return Err(error);
        }
        Ok(snapshot)
    }

    pub(crate) async fn search(
        &self,
        handle: &str,
        query: &str,
        case_sensitive: bool,
        regex: bool,
        maximum_results: usize,
    ) -> Result<TerminalSearchDto, TerminalApiError> {
        validate_search(query, maximum_results)?;
        let active = self.active(handle)?;
        if let Err(error) = self.ensure_active(&active) {
            self.invalidate(handle, &active).await;
            return Err(error);
        }
        let response = active.lock_state()?.search(
            query,
            SearchOptions {
                case_sensitive,
                regex,
                max_results: maximum_results,
            },
        )?;
        if let Err(error) = self.ensure_active(&active) {
            self.invalidate(handle, &active).await;
            return Err(error);
        }
        Ok(response)
    }

    pub(crate) async fn close(&self, handle: &str) -> Result<TerminalClosedDto, TerminalApiError> {
        let active = self.active(handle)?;
        if let Err(error) = self.ensure_active(&active) {
            self.invalidate(handle, &active).await;
            return Err(error);
        }
        self.remove_active(handle, &active)?;
        let result = tokio::time::timeout(CONTROL_TIMEOUT, active.transport.close())
            .await
            .map_err(|_| TerminalApiError::TimedOut)?;
        result.map_err(TerminalApiError::Core)?;
        self.ensure_binding_unchanged(&active.binding_handle, &active.binding)?;
        Ok(TerminalClosedDto { closed: true })
    }

    pub(crate) async fn close_binding(&self, binding_handle: &str) -> Result<(), TerminalApiError> {
        let active = self.lock_registry()?.remove_binding(binding_handle);
        for terminal in active {
            close_transport(&terminal.transport).await;
        }
        Ok(())
    }

    pub(crate) async fn shutdown(&self) {
        let active = match self.registry.lock() {
            Ok(mut registry) => registry.drain_active(),
            Err(_) => return,
        };
        for terminal in active {
            close_transport(&terminal.transport).await;
        }
    }

    fn binding_session(&self, binding_handle: &str) -> Result<BoundSshSession, TerminalApiError> {
        let binding = self
            .ssh
            .binding_session_clone(binding_handle)
            .map_err(|_| TerminalApiError::BindingUnavailable)?;
        self.services
            .target()
            .validate(binding.target())
            .map_err(|_| TerminalApiError::BindingUnavailable)?;
        Ok(binding)
    }

    fn ensure_binding_unchanged(
        &self,
        binding_handle: &str,
        expected: &BoundSshSession,
    ) -> Result<(), TerminalApiError> {
        self.services
            .target()
            .validate(expected.target())
            .map_err(|_| TerminalApiError::BindingUnavailable)?;
        let current = self
            .ssh
            .binding_session_clone(binding_handle)
            .map_err(|_| TerminalApiError::BindingUnavailable)?;
        if &current != expected || current.target() != expected.target() {
            return Err(TerminalApiError::BindingUnavailable);
        }
        self.services
            .target()
            .validate(current.target())
            .map_err(|_| TerminalApiError::BindingUnavailable)
    }

    fn ensure_active(&self, active: &ActiveTerminal) -> Result<(), TerminalApiError> {
        if active.binding.target() != &active.guard {
            return Err(TerminalApiError::BindingUnavailable);
        }
        self.ensure_binding_unchanged(&active.binding_handle, &active.binding)
    }

    fn active(&self, handle: &str) -> Result<Arc<ActiveTerminal>, TerminalApiError> {
        validate_handle(handle)?;
        self.lock_registry()?.active(handle, Instant::now())
    }

    fn lock_registry(&self) -> Result<MutexGuard<'_, TerminalRegistry>, TerminalApiError> {
        self.registry
            .lock()
            .map_err(|_| TerminalApiError::RegistryUnavailable)
    }

    fn remove_slot(&self, handle: &str) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.slots.remove(handle);
        }
    }

    fn remove_active(
        &self,
        handle: &str,
        active: &Arc<ActiveTerminal>,
    ) -> Result<(), TerminalApiError> {
        self.lock_registry()?.remove_active(handle, active)
    }

    async fn invalidate(&self, handle: &str, active: &Arc<ActiveTerminal>) {
        let _ = self.remove_active(handle, active);
        close_transport(&active.transport).await;
    }
}

/// What a terminal slot was asked to launch. Kept internal: the wire never
/// names a shell program or a container id, only an already-resolved identity.
enum TerminalLaunch {
    HostShell,
    Container {
        container: ContainerIdentity,
        shell: ContainerShell,
    },
}

fn transport_of<T: CoreTerminalTransport + 'static>(terminal: T) -> Arc<dyn CoreTerminalTransport> {
    Arc::new(terminal)
}

async fn close_transport(terminal: &Arc<dyn CoreTerminalTransport>) {
    let _ = tokio::time::timeout(CONTROL_TIMEOUT, terminal.close()).await;
}

fn read_terminal_event(
    terminal: &Arc<dyn CoreTerminalTransport>,
) -> Result<EventRead, TerminalApiError> {
    match terminal.events().try_recv() {
        Ok(Some(event)) => Ok(EventRead::Event(event)),
        Ok(None) => Ok(EventRead::Empty),
        Err(CoreError::ChannelClosed { .. }) => Ok(EventRead::Closed),
        Err(error) => Err(TerminalApiError::Core(error)),
    }
}

struct ActiveTerminal {
    binding_handle: String,
    binding: BoundSshSession,
    guard: TargetGuard,
    terminal_id: String,
    // Behind `dyn` because a terminal here is either a login shell on the host
    // or a shell inside one of its containers. Everything past the open call —
    // polling, input, resize, close, the bounded model, the per-target caps —
    // is identical for both, and the only thing that differs is which core call
    // minted the session.
    transport: Arc<dyn CoreTerminalTransport>,
    state: Mutex<TerminalState>,
}

impl ActiveTerminal {
    fn lock_state(&self) -> Result<MutexGuard<'_, TerminalState>, TerminalApiError> {
        self.state
            .lock()
            .map_err(|_| TerminalApiError::RegistryUnavailable)
    }
}

#[derive(Default)]
struct TerminalRegistry {
    slots: HashMap<String, TerminalSlot>,
}

enum TerminalSlot {
    Opening {
        binding_handle: String,
        guard: TargetGuard,
        expires_at: Instant,
    },
    Active(Arc<ActiveTerminal>),
}

impl TerminalSlot {
    fn guard(&self) -> &TargetGuard {
        match self {
            Self::Opening { guard, .. } => guard,
            Self::Active(active) => &active.guard,
        }
    }
}

impl TerminalRegistry {
    fn reserve(
        &mut self,
        binding_handle: &str,
        guard: &TargetGuard,
        now: Instant,
    ) -> Result<(String, String), TerminalApiError> {
        self.remove_expired_openings(now);
        if self.slots.len() >= MAX_TERMINALS {
            return Err(TerminalApiError::RegistryCapacity);
        }
        if self
            .slots
            .values()
            .filter(|slot| slot.guard().identity == guard.identity)
            .count()
            >= MAX_TERMINALS_PER_TARGET
        {
            return Err(TerminalApiError::TargetCapacity);
        }
        for _ in 0..HANDLE_ATTEMPTS {
            let handle = Uuid::new_v4().to_string();
            if self.slots.contains_key(&handle) {
                continue;
            }
            let terminal_id = Uuid::new_v4().to_string();
            self.slots.insert(
                handle.clone(),
                TerminalSlot::Opening {
                    binding_handle: binding_handle.to_owned(),
                    guard: guard.clone(),
                    expires_at: now + OPEN_RESERVATION_TTL,
                },
            );
            return Ok((handle, terminal_id));
        }
        Err(TerminalApiError::RegistryCapacity)
    }

    fn activate(
        &mut self,
        handle: &str,
        binding_handle: &str,
        guard: &TargetGuard,
        active: Arc<ActiveTerminal>,
        now: Instant,
    ) -> Result<(), TerminalApiError> {
        self.remove_expired_openings(now);
        let Some(slot) = self.slots.get_mut(handle) else {
            return Err(TerminalApiError::TerminalUnavailable);
        };
        match slot {
            TerminalSlot::Opening {
                binding_handle: reserved_binding,
                guard: reserved_guard,
                ..
            } if reserved_binding == binding_handle && reserved_guard == guard => {
                *slot = TerminalSlot::Active(active);
                Ok(())
            }
            _ => Err(TerminalApiError::BindingUnavailable),
        }
    }

    fn active(
        &mut self,
        handle: &str,
        now: Instant,
    ) -> Result<Arc<ActiveTerminal>, TerminalApiError> {
        self.remove_expired_openings(now);
        match self.slots.get(handle) {
            Some(TerminalSlot::Active(active)) => Ok(Arc::clone(active)),
            _ => Err(TerminalApiError::TerminalUnavailable),
        }
    }

    fn remove_active(
        &mut self,
        handle: &str,
        expected: &Arc<ActiveTerminal>,
    ) -> Result<(), TerminalApiError> {
        match self.slots.get(handle) {
            Some(TerminalSlot::Active(active)) if Arc::ptr_eq(active, expected) => {
                self.slots.remove(handle);
                Ok(())
            }
            _ => Err(TerminalApiError::TerminalUnavailable),
        }
    }

    fn remove_expired_openings(&mut self, now: Instant) {
        self.slots.retain(|_, slot| {
            !matches!(slot, TerminalSlot::Opening { expires_at, .. } if *expires_at <= now)
        });
    }

    fn remove_binding(&mut self, binding_handle: &str) -> Vec<Arc<ActiveTerminal>> {
        let mut active = Vec::new();
        self.slots.retain(|_, slot| {
            let matches_binding = match slot {
                TerminalSlot::Opening {
                    binding_handle: current,
                    ..
                } => current == binding_handle,
                TerminalSlot::Active(terminal) => terminal.binding_handle == binding_handle,
            };
            if matches_binding {
                if let TerminalSlot::Active(terminal) = slot {
                    active.push(Arc::clone(terminal));
                }
                false
            } else {
                true
            }
        });
        active
    }

    fn drain_active(&mut self) -> Vec<Arc<ActiveTerminal>> {
        self.slots
            .drain()
            .filter_map(|(_, slot)| match slot {
                TerminalSlot::Active(terminal) => Some(terminal),
                TerminalSlot::Opening { .. } => None,
            })
            .collect()
    }
}

struct TerminalState {
    model: TerminalModel,
    deferred_event: Option<CoreTerminalEvent>,
    last_sequence: u64,
    channel_closed: bool,
}

impl TerminalState {
    fn new(model: TerminalModel) -> Self {
        Self {
            model,
            deferred_event: None,
            last_sequence: 0,
            channel_closed: false,
        }
    }

    fn poll(
        &mut self,
        terminal_id: &str,
        maximum_events: usize,
        maximum_bytes: usize,
        mut read: impl FnMut() -> Result<EventRead, TerminalApiError>,
    ) -> Result<TerminalPollDto, TerminalApiError> {
        let mut events = Vec::new();
        let mut raw_bytes = 0_usize;
        let mut budget_exhausted = false;

        while events.len() < maximum_events && !self.channel_closed {
            let event = match self.deferred_event.take() {
                Some(event) => event,
                None => match read()? {
                    EventRead::Event(event) => event,
                    EventRead::Empty => break,
                    EventRead::Closed => {
                        self.channel_closed = true;
                        events.push(TerminalPollEventDto::Closed {
                            sequence: self.next_sequence()?,
                        });
                        break;
                    }
                },
            };
            self.validate_event(terminal_id, &event)?;
            let event_bytes = bounded_event_bytes(&event)?;
            if !events.is_empty() && raw_bytes.saturating_add(event_bytes) > maximum_bytes {
                self.deferred_event = Some(event);
                budget_exhausted = true;
                break;
            }
            if let TerminalEventKind::Output(bytes) = &event.kind {
                let total = self
                    .model
                    .total_bytes()
                    .checked_add(bytes.len() as u64)
                    .ok_or(TerminalApiError::OutputLimit)?;
                if total > MAX_TOTAL_OUTPUT_BYTES {
                    return Err(TerminalApiError::OutputLimit);
                }
            }
            raw_bytes += event_bytes;
            self.last_sequence = event.sequence;
            events.push(self.apply_event(event));
        }
        if events.len() == maximum_events {
            budget_exhausted = true;
        }
        Ok(TerminalPollDto {
            events,
            raw_bytes,
            has_more: self.deferred_event.is_some() || budget_exhausted,
        })
    }

    fn validate_event(
        &self,
        terminal_id: &str,
        event: &CoreTerminalEvent,
    ) -> Result<(), TerminalApiError> {
        if event.session_id != terminal_id || event.sequence != self.next_sequence()? {
            return Err(TerminalApiError::ProtocolViolation);
        }
        Ok(())
    }

    fn next_sequence(&self) -> Result<u64, TerminalApiError> {
        self.last_sequence
            .checked_add(1)
            .ok_or(TerminalApiError::ProtocolViolation)
    }

    fn apply_event(&mut self, event: CoreTerminalEvent) -> TerminalPollEventDto {
        match event.kind {
            TerminalEventKind::Output(bytes) => {
                self.model.feed_output(&bytes);
                TerminalPollEventDto::Output {
                    sequence: event.sequence,
                    bytes_base64: STANDARD.encode(bytes),
                }
            }
            TerminalEventKind::TitleChanged(title) => {
                let (title, truncated) = truncate_utf8(&title, MAX_TITLE_BYTES);
                TerminalPollEventDto::TitleChanged {
                    sequence: event.sequence,
                    title,
                    truncated,
                }
            }
            TerminalEventKind::Bell => TerminalPollEventDto::Bell {
                sequence: event.sequence,
            },
            TerminalEventKind::Exited { exit_code } => TerminalPollEventDto::Exited {
                sequence: event.sequence,
                exit_code,
            },
            TerminalEventKind::Failed { .. } => TerminalPollEventDto::Failed {
                sequence: event.sequence,
                code: "terminal-transport-failed",
            },
        }
    }

    fn render_snapshot(&self) -> Result<TerminalRenderSnapshotDto, TerminalApiError> {
        let snapshot = self.model.render_snapshot();
        let rows = snapshot
            .rows
            .into_iter()
            .map(|row| {
                row.into_iter()
                    .map(TerminalRenderCellDto::try_from)
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;
        let dto = TerminalRenderSnapshotDto {
            columns: snapshot.size.columns,
            rows: snapshot.size.rows,
            cells: rows,
            cursor: snapshot.cursor.map(TerminalRenderCursorDto::from),
            display_offset: snapshot.display_offset,
            alternate_screen: snapshot.alternate_screen,
            total_output_bytes: self.model.total_bytes(),
        };
        if serde_json::to_vec(&dto)
            .map_err(|_| TerminalApiError::SnapshotLimit)?
            .len()
            > MAX_SNAPSHOT_BYTES
        {
            return Err(TerminalApiError::SnapshotLimit);
        }
        Ok(dto)
    }

    fn search(
        &self,
        query: &str,
        options: SearchOptions,
    ) -> Result<TerminalSearchDto, TerminalApiError> {
        let matches = self
            .model
            .search(query, &options)
            .map_err(|_| TerminalApiError::InvalidSearch)?;
        let limited = matches.len() == options.max_results;
        let mut total_text_bytes = 0_usize;
        let matches = matches
            .into_iter()
            .map(|found| {
                if found.text.len() > MAX_SEARCH_MATCH_BYTES {
                    return Err(TerminalApiError::SearchLimit);
                }
                total_text_bytes = total_text_bytes
                    .checked_add(found.text.len())
                    .ok_or(TerminalApiError::SearchLimit)?;
                if total_text_bytes > MAX_SEARCH_RESPONSE_BYTES {
                    return Err(TerminalApiError::SearchLimit);
                }
                Ok(TerminalSearchMatchDto {
                    line: found.line,
                    start_column: found.start_column,
                    end_column: found.end_column,
                    text: found.text,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let dto = TerminalSearchDto { matches, limited };
        if serde_json::to_vec(&dto)
            .map_err(|_| TerminalApiError::SearchLimit)?
            .len()
            > MAX_SEARCH_RESPONSE_BYTES
        {
            return Err(TerminalApiError::SearchLimit);
        }
        Ok(dto)
    }
}

enum EventRead {
    Event(CoreTerminalEvent),
    Empty,
    Closed,
}

fn bounded_event_bytes(event: &CoreTerminalEvent) -> Result<usize, TerminalApiError> {
    let bytes = match &event.kind {
        TerminalEventKind::Output(bytes) => {
            if bytes.len() > MAX_OUTPUT_EVENT_BYTES {
                return Err(TerminalApiError::OutputLimit);
            }
            bytes.len()
        }
        TerminalEventKind::TitleChanged(title) => title.len().min(MAX_TITLE_BYTES),
        TerminalEventKind::Bell
        | TerminalEventKind::Exited { .. }
        | TerminalEventKind::Failed { .. } => 0,
    };
    Ok(bytes)
}

fn terminal_size(columns: u16, rows: u16) -> Result<TerminalSize, TerminalApiError> {
    if columns > MAX_COLUMNS || rows > MAX_ROWS {
        return Err(TerminalApiError::InvalidBounds);
    }
    TerminalSize::new(columns, rows).map_err(|_| TerminalApiError::InvalidBounds)
}

fn validate_poll_bounds(
    maximum_events: usize,
    maximum_bytes: usize,
) -> Result<(), TerminalApiError> {
    if !(1..=MAX_POLL_EVENTS).contains(&maximum_events)
        || !(1..=MAX_POLL_BYTES).contains(&maximum_bytes)
    {
        return Err(TerminalApiError::InvalidBounds);
    }
    Ok(())
}

fn validate_search(query: &str, maximum_results: usize) -> Result<(), TerminalApiError> {
    if query.is_empty()
        || query.len() > MAX_SEARCH_QUERY_BYTES
        || !(1..=MAX_SEARCH_RESULTS).contains(&maximum_results)
        || query.chars().any(char::is_control)
    {
        return Err(TerminalApiError::InvalidSearch);
    }
    Ok(())
}

fn validate_handle(handle: &str) -> Result<(), TerminalApiError> {
    if handle.is_empty() || handle.len() > MAX_HANDLE_BYTES || Uuid::parse_str(handle).is_err() {
        return Err(TerminalApiError::TerminalUnavailable);
    }
    Ok(())
}

fn decode_input(encoded: &str) -> Result<Vec<u8>, TerminalApiError> {
    if encoded.is_empty() || encoded.len() > MAX_INPUT_BASE64_BYTES {
        return Err(TerminalApiError::InvalidInput);
    }
    let bytes = STANDARD
        .decode(encoded.as_bytes())
        .map_err(|_| TerminalApiError::InvalidInput)?;
    if bytes.is_empty() || bytes.len() > MAX_INPUT_BYTES {
        return Err(TerminalApiError::InvalidInput);
    }
    Ok(bytes)
}

fn truncate_utf8(value: &str, maximum_bytes: usize) -> (String, bool) {
    if value.len() <= maximum_bytes {
        return (value.to_owned(), false);
    }
    let mut end = maximum_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    (value[..end].to_owned(), true)
}

pub(crate) enum TerminalApiError {
    Core(CoreError),
    BindingUnavailable,
    TerminalUnavailable,
    InvalidBounds,
    InvalidInput,
    InvalidSearch,
    RegistryCapacity,
    TargetCapacity,
    RegistryUnavailable,
    OutputLimit,
    SnapshotLimit,
    SearchLimit,
    ProtocolViolation,
    TimedOut,
}

impl fmt::Debug for TerminalApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core(_) => "Core([REDACTED])",
            Self::BindingUnavailable => "BindingUnavailable",
            Self::TerminalUnavailable => "TerminalUnavailable",
            Self::InvalidBounds => "InvalidBounds",
            Self::InvalidInput => "InvalidInput",
            Self::InvalidSearch => "InvalidSearch",
            Self::RegistryCapacity => "RegistryCapacity",
            Self::TargetCapacity => "TargetCapacity",
            Self::RegistryUnavailable => "RegistryUnavailable",
            Self::OutputLimit => "OutputLimit",
            Self::SnapshotLimit => "SnapshotLimit",
            Self::SearchLimit => "SearchLimit",
            Self::ProtocolViolation => "ProtocolViolation",
            Self::TimedOut => "TimedOut",
        })
    }
}

impl fmt::Display for TerminalApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core(_) => "the terminal operation failed",
            Self::BindingUnavailable => "the SSH binding is missing or stale",
            Self::TerminalUnavailable => "the terminal handle is missing or stale",
            Self::InvalidBounds => "the terminal request bounds are invalid",
            Self::InvalidInput => "the terminal input is invalid",
            Self::InvalidSearch => "the terminal search is invalid",
            Self::RegistryCapacity => "the terminal registry is full",
            Self::TargetCapacity => "the target terminal limit was reached",
            Self::RegistryUnavailable => "the terminal registry is unavailable",
            Self::OutputLimit => "the terminal output exceeded its safety limit",
            Self::SnapshotLimit => "the terminal snapshot exceeded its safety limit",
            Self::SearchLimit => "the terminal search response exceeded its safety limit",
            Self::ProtocolViolation => "the terminal event stream is invalid",
            Self::TimedOut => "the terminal operation timed out",
        })
    }
}

impl std::error::Error for TerminalApiError {}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TerminalOpenedDto {
    pub(crate) handle: String,
    pub(crate) columns: u16,
    pub(crate) rows: u16,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TerminalPollDto {
    events: Vec<TerminalPollEventDto>,
    raw_bytes: usize,
    has_more: bool,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum TerminalPollEventDto {
    Output {
        sequence: u64,
        bytes_base64: String,
    },
    TitleChanged {
        sequence: u64,
        title: String,
        truncated: bool,
    },
    Bell {
        sequence: u64,
    },
    Exited {
        sequence: u64,
        exit_code: Option<i32>,
    },
    Failed {
        sequence: u64,
        code: &'static str,
    },
    Closed {
        sequence: u64,
    },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TerminalInputDto {
    accepted_bytes: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct TerminalResizedDto {
    columns: u16,
    rows: u16,
}

#[derive(Debug, Serialize)]
pub(crate) struct TerminalClosedDto {
    closed: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TerminalRenderSnapshotDto {
    columns: u16,
    rows: u16,
    cells: Vec<Vec<TerminalRenderCellDto>>,
    cursor: Option<TerminalRenderCursorDto>,
    display_offset: usize,
    alternate_screen: bool,
    total_output_bytes: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TerminalRenderCellDto {
    row: u16,
    column: u16,
    text: String,
    width: u8,
    foreground: TerminalColorDto,
    background: TerminalColorDto,
    bold: bool,
    dim: bool,
    italic: bool,
    underline: bool,
    strikeout: bool,
    inverse: bool,
    hidden: bool,
    selected: bool,
}

impl TryFrom<RenderCell> for TerminalRenderCellDto {
    type Error = TerminalApiError;

    fn try_from(cell: RenderCell) -> Result<Self, Self::Error> {
        if cell.text.len() > MAX_CELL_TEXT_BYTES {
            return Err(TerminalApiError::SnapshotLimit);
        }
        Ok(Self {
            row: cell.row,
            column: cell.column,
            text: cell.text,
            width: cell.width,
            foreground: cell.foreground.into(),
            background: cell.background.into(),
            bold: cell.bold,
            dim: cell.dim,
            italic: cell.italic,
            underline: cell.underline,
            strikeout: cell.strikeout,
            inverse: cell.inverse,
            hidden: cell.hidden,
            selected: cell.selected,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum TerminalColorDto {
    Named { name: String },
    Indexed { index: u8 },
    Rgb { red: u8, green: u8, blue: u8 },
}

impl From<CellColor> for TerminalColorDto {
    fn from(color: CellColor) -> Self {
        match color {
            CellColor::Named(name) => Self::Named { name },
            CellColor::Indexed(index) => Self::Indexed { index },
            CellColor::Rgb(red, green, blue) => Self::Rgb { red, green, blue },
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TerminalRenderCursorDto {
    row: u16,
    column: u16,
    shape: TerminalCursorShapeDto,
}

impl From<RenderCursor> for TerminalRenderCursorDto {
    fn from(cursor: RenderCursor) -> Self {
        Self {
            row: cursor.row,
            column: cursor.column,
            shape: cursor.shape.into(),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
enum TerminalCursorShapeDto {
    Block,
    Underline,
    Beam,
    HollowBlock,
}

impl From<TerminalCursorShape> for TerminalCursorShapeDto {
    fn from(shape: TerminalCursorShape) -> Self {
        match shape {
            TerminalCursorShape::Block => Self::Block,
            TerminalCursorShape::Underline => Self::Underline,
            TerminalCursorShape::Beam => Self::Beam,
            TerminalCursorShape::HollowBlock => Self::HollowBlock,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct TerminalSearchDto {
    matches: Vec<TerminalSearchMatchDto>,
    limited: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TerminalSearchMatchDto {
    line: i32,
    start_column: usize,
    end_column: usize,
    text: String,
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use lovelyres_core::target::TargetIdentity;

    use super::*;

    fn guard(identity: &str, generation: u64) -> TargetGuard {
        TargetGuard {
            identity: TargetIdentity::new(identity).unwrap(),
            generation,
        }
    }

    fn state(columns: u16, rows: u16) -> TerminalState {
        let config = TerminalConfig {
            size: TerminalSize::new(columns, rows).unwrap(),
            scrollback_limit: 32,
            ..TerminalConfig::default()
        };
        TerminalState::new(TerminalModel::new(config).unwrap())
    }

    fn event(sequence: u64, kind: TerminalEventKind) -> CoreTerminalEvent {
        CoreTerminalEvent {
            session_id: "terminal-internal".to_owned(),
            sequence,
            kind,
        }
    }

    #[test]
    fn registry_caps_global_and_per_target_open_reservations() {
        let now = Instant::now();
        let target = guard("server-a", 7);
        let mut registry = TerminalRegistry::default();
        registry.reserve("binding-a", &target, now).unwrap();
        registry.reserve("binding-a", &target, now).unwrap();
        assert!(matches!(
            registry.reserve("binding-a", &target, now),
            Err(TerminalApiError::TargetCapacity)
        ));
        assert!(matches!(
            registry.reserve("binding-a-new-generation", &guard("server-a", 8), now),
            Err(TerminalApiError::TargetCapacity)
        ));

        for index in 1..=(MAX_TERMINALS - MAX_TERMINALS_PER_TARGET) {
            registry
                .reserve(
                    &format!("binding-{index}"),
                    &guard(&format!("server-{index}"), 1),
                    now,
                )
                .unwrap();
        }
        assert!(matches!(
            registry.reserve("overflow", &guard("overflow", 1), now),
            Err(TerminalApiError::RegistryCapacity)
        ));

        registry.remove_expired_openings(now + OPEN_RESERVATION_TTL);
        assert!(registry.slots.is_empty());
    }

    #[test]
    fn binding_cleanup_removes_only_matching_open_reservations() {
        let now = Instant::now();
        let mut registry = TerminalRegistry::default();
        registry
            .reserve("binding-a", &guard("server-a", 1), now)
            .unwrap();
        registry
            .reserve("binding-b", &guard("server-b", 1), now)
            .unwrap();

        assert!(registry.remove_binding("binding-a").is_empty());
        assert_eq!(registry.slots.len(), 1);
        assert!(matches!(
            registry.slots.values().next(),
            Some(TerminalSlot::Opening { binding_handle, .. }) if binding_handle == "binding-b"
        ));
        assert!(registry.drain_active().is_empty());
        assert!(registry.slots.is_empty());
    }

    #[test]
    fn poll_defers_whole_event_at_byte_budget_and_preserves_order() {
        let mut state = state(32, 3);
        let mut source = VecDeque::from([
            event(1, TerminalEventKind::Output(b"alpha".to_vec())),
            event(2, TerminalEventKind::Output(b"beta".to_vec())),
        ]);
        let first = state
            .poll("terminal-internal", 8, 5, || {
                Ok(source
                    .pop_front()
                    .map_or(EventRead::Empty, EventRead::Event))
            })
            .unwrap();
        assert_eq!(first.events.len(), 1);
        assert_eq!(first.raw_bytes, 5);
        assert!(first.has_more);
        assert!(source.is_empty());
        assert!(state.deferred_event.is_some());

        let second = state
            .poll("terminal-internal", 8, 4, || Ok(EventRead::Empty))
            .unwrap();
        assert_eq!(second.events.len(), 1);
        assert_eq!(second.raw_bytes, 4);
        assert!(!second.has_more);
        assert_eq!(state.last_sequence, 2);
        assert!(state.model.visible_text().contains("alphabeta"));
    }

    #[test]
    fn poll_makes_progress_when_one_event_exceeds_the_caller_budget() {
        let mut state = state(32, 3);
        let mut source = VecDeque::from([event(
            1,
            TerminalEventKind::Output(b"larger-than-budget".to_vec()),
        )]);

        let response = state
            .poll("terminal-internal", 8, 4, || {
                Ok(source
                    .pop_front()
                    .map_or(EventRead::Empty, EventRead::Event))
            })
            .unwrap();

        assert_eq!(response.events.len(), 1);
        assert_eq!(response.raw_bytes, b"larger-than-budget".len());
        assert_eq!(state.last_sequence, 1);
        assert!(source.is_empty());
        assert!(state.deferred_event.is_none());
    }

    #[test]
    fn headless_model_snapshot_and_search_are_bounded_public_dtos() {
        let mut state = state(24, 3);
        let mut source = VecDeque::from([event(
            1,
            TerminalEventKind::Output(b"needle \x1b[31mred\x1b[0m\r\nsecond needle".to_vec()),
        )]);
        state
            .poll("terminal-internal", 4, 1024, || {
                Ok(source
                    .pop_front()
                    .map_or(EventRead::Empty, EventRead::Event))
            })
            .unwrap();
        let snapshot = serde_json::to_value(state.render_snapshot().unwrap()).unwrap();
        let search = serde_json::to_value(
            state
                .search(
                    "needle",
                    SearchOptions {
                        max_results: 4,
                        ..SearchOptions::default()
                    },
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(snapshot["columns"], 24);
        assert_eq!(search["matches"].as_array().unwrap().len(), 2);
        let encoded = format!("{snapshot}{search}");
        for forbidden in [
            "sessionId",
            "bindingHandle",
            "generation",
            "TargetGuard",
            "command",
            "path",
        ] {
            assert!(!encoded.contains(forbidden));
        }
    }

    #[test]
    fn hostile_failure_detail_and_stream_identity_never_cross_the_dto() {
        let hostile = "<script>steal()</script>/home/operator/private";
        let mut state = state(16, 2);
        let mut source = VecDeque::from([event(
            1,
            TerminalEventKind::Failed {
                message: hostile.to_owned(),
            },
        )]);
        let response = state
            .poll("terminal-internal", 4, 1024, || {
                Ok(source
                    .pop_front()
                    .map_or(EventRead::Empty, EventRead::Event))
            })
            .unwrap();
        let encoded = serde_json::to_string(&response).unwrap();
        assert!(encoded.contains("terminal-transport-failed"));
        assert!(!encoded.contains(hostile));
        assert!(!encoded.contains("terminal-internal"));
        assert!(
            !format!(
                "{:?}",
                TerminalApiError::Core(CoreError::Ssh {
                    operation: "terminal",
                    message: hostile.to_owned(),
                })
            )
            .contains(hostile)
        );
        assert!(
            !TerminalApiError::Core(CoreError::Ssh {
                operation: "terminal",
                message: hostile.to_owned(),
            })
            .to_string()
            .contains(hostile)
        );
    }

    #[test]
    fn protocol_and_output_limits_fail_closed_instead_of_reordering() {
        let mut wrong_sequence = state(16, 2);
        assert!(matches!(
            wrong_sequence.poll("terminal-internal", 4, 1024, || Ok(EventRead::Event(
                event(2, TerminalEventKind::Bell,)
            ))),
            Err(TerminalApiError::ProtocolViolation)
        ));

        let mut oversized = state(16, 2);
        assert!(matches!(
            oversized.poll("terminal-internal", 4, MAX_POLL_BYTES, || {
                Ok(EventRead::Event(event(
                    1,
                    TerminalEventKind::Output(vec![b'x'; MAX_OUTPUT_EVENT_BYTES + 1]),
                )))
            }),
            Err(TerminalApiError::OutputLimit)
        ));
        assert_eq!(oversized.model.total_bytes(), 0);
    }

    #[test]
    fn binary_input_is_base64_only_and_hard_bounded() {
        let bytes = [0_u8, 0xff, b'\n'];
        assert_eq!(decode_input(&STANDARD.encode(bytes)).unwrap(), bytes);
        assert!(matches!(
            decode_input("not base64!"),
            Err(TerminalApiError::InvalidInput)
        ));
        assert!(matches!(
            decode_input(&STANDARD.encode(vec![0_u8; MAX_INPUT_BYTES + 1])),
            Err(TerminalApiError::InvalidInput)
        ));
    }

    #[test]
    fn poll_closed_event_is_explicit_and_monotonic() {
        let mut state = state(16, 2);
        let response = state
            .poll("terminal-internal", 4, 1024, || Ok(EventRead::Closed))
            .unwrap();
        assert_eq!(response.events.len(), 1);
        assert!(
            serde_json::to_string(&response)
                .unwrap()
                .contains("\"kind\":\"closed\"")
        );
        assert!(state.channel_closed);
        assert_eq!(state.last_sequence, 0);
    }
}
