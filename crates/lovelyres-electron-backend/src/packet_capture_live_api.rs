//! Standalone Electron boundary for target-bound live packet capture.
//!
//! Core owns every remote command and the `tcpdump` lifecycle. The renderer can select only an
//! opaque interface capability, bounded capture parameters, and an opaque live-capture handle.
//! PCAP artifacts, paths, downloads, exports, evidence persistence, and generic execution are
//! deliberately absent from this phase-one surface.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use lovelyres_core::{
    BackendServices, CoreError,
    events::{
        PacketCaptureEvent as CoreCaptureEvent, PacketCaptureEventKind as CoreCaptureEventKind,
    },
    packet_capture::{
        LivePacketCapture, MAX_PCAP_CAPTURE_SECONDS, MAX_PCAP_PACKET_COUNT, NetworkInterface,
        PacketEntry as CorePacketEntry, PcapCaptureRequest,
    },
    ssh::BoundSshSession,
    target::TargetGuard,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ssh_api::SshApi;

const MAX_HANDLE_BYTES: usize = 128;
const MAX_INTERFACES: usize = 128;
const MAX_INTERFACE_ENTRIES: usize = 256;
const MAX_INTERFACE_ADDRESSES: usize = 16;
const MAX_INTERFACE_FIELD_BYTES: usize = 512;
const MAX_INTERFACE_RESPONSE_BYTES: usize = 256 * 1024;
const INTERFACE_RESPONSE_ENVELOPE_BYTES: usize = 1024;
const MAX_INTERFACE_REGISTRY_BYTES: usize = 2 * 1024 * 1024;
const INTERFACE_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_CAPTURES: usize = 8;
const MAX_CAPTURES_PER_BINDING: usize = 1;
const MAX_RETAINED_EVENTS: usize = 512;
const MAX_RETAINED_PACKETS: usize = 400;
const MAX_CAPTURE_JOURNAL_BYTES: usize = 4 * 1024 * 1024;
const MAX_PUBLIC_EVENT_BYTES: usize = 64 * 1024;
const MAX_POLL_EVENTS: usize = 100;
const MAX_POLL_BYTES: usize = 512 * 1024;
const MAX_CORE_DRAIN_PER_POLL: usize = 128;
const MAX_PACKET_FIELD_BYTES: usize = 4 * 1024;
const MAX_PACKET_RAW_BYTES: usize = 16 * 1024;
const MAX_INFO_BYTES: usize = 8 * 1024;
const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_GLOBAL_OPERATIONS: usize = 12;
const MAX_OPERATIONS_PER_BINDING: usize = 3;
const START_TIMEOUT: Duration = Duration::from_secs(30);
const START_RESERVATION_TTL: Duration = Duration::from_secs(35);
const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);
const CAPTURE_RETENTION_GRACE: Duration = Duration::from_secs(90);
const CLOSED_BINDING_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_CLOSED_BINDINGS: usize = 128;
const REDACTED_PACKET_CAPTURE_TEXT: &str = "[SENSITIVE PACKET CAPTURE TEXT REDACTED]";

pub(crate) struct PacketCaptureLiveApi {
    services: BackendServices,
    ssh_api: Arc<SshApi>,
    interfaces: Mutex<InterfaceRegistry>,
    captures: Mutex<CaptureRegistry>,
    operations: Arc<Mutex<OperationState>>,
}

impl fmt::Debug for PacketCaptureLiveApi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let interface_count = self
            .interfaces
            .lock()
            .map(|registry| registry.entries.len())
            .unwrap_or_default();
        let capture_count = self
            .captures
            .lock()
            .map(|registry| registry.slots.len())
            .unwrap_or_default();
        formatter
            .debug_struct("PacketCaptureLiveApi")
            .field("interface_count", &interface_count)
            .field("capture_count", &capture_count)
            .finish()
    }
}

impl PacketCaptureLiveApi {
    pub(crate) fn new(services: BackendServices, ssh_api: Arc<SshApi>) -> Self {
        Self {
            services,
            ssh_api,
            interfaces: Mutex::new(InterfaceRegistry::default()),
            captures: Mutex::new(CaptureRegistry::default()),
            operations: Arc::new(Mutex::new(OperationState::default())),
        }
    }

    pub(crate) async fn list_interfaces(
        &self,
        binding_handle: &str,
    ) -> Result<PacketCaptureInterfaceListDto, PacketCaptureLiveApiError> {
        let (binding, scope) = self.capture_binding(binding_handle)?;
        self.reap_stale(Some(&scope)).await;
        let _permit = self.acquire_operation(&scope)?;
        let interfaces = self
            .services
            .packet_capture()
            .list_interfaces(&binding)
            .await?;
        self.ensure_binding(&scope, &binding)?;
        let response =
            self.lock_interfaces()?
                .replace_scope(scope.clone(), interfaces, Instant::now())?;
        if let Err(error) = self.ensure_binding(&scope, &binding) {
            self.lock_interfaces()?
                .remove_binding(&scope.binding_handle);
            return Err(error);
        }
        Ok(response)
    }

    pub(crate) async fn start(
        &self,
        binding_handle: &str,
        interface_handle: &str,
        input: PacketCaptureStartInput,
    ) -> Result<PacketCaptureStartedDto, PacketCaptureLiveApiError> {
        validate_handle(interface_handle)?;
        input.validate()?;
        let (binding, scope) = self.capture_binding(binding_handle)?;
        self.reap_stale(Some(&scope)).await;
        let _permit = self.acquire_operation(&scope)?;
        let interface =
            self.lock_interfaces()?
                .resolve(&scope, interface_handle, Instant::now())?;
        let request = PcapCaptureRequest {
            interface,
            filter: input.filter,
            packet_limit: input.packet_limit,
            duration_seconds: input.duration_seconds,
        };
        request.validate()?;
        let (capture_handle, evicted) = self
            .lock_captures()?
            .reserve(scope.clone(), Instant::now())?;
        close_live_captures(evicted).await;
        let started = tokio::time::timeout(
            START_TIMEOUT,
            self.services.packet_capture().start_live(&binding, request),
        )
        .await;
        let live = match started {
            Ok(Ok(live)) => Arc::new(live),
            Ok(Err(_)) => {
                self.remove_slot(&capture_handle);
                return Err(PacketCaptureLiveApiError::Core);
            }
            Err(_) => {
                self.remove_slot(&capture_handle);
                return Err(PacketCaptureLiveApiError::TimedOut);
            }
        };
        let interface_still_current = self.lock_interfaces().and_then(|mut interfaces| {
            interfaces.resolve(&scope, interface_handle, Instant::now())
        });
        if self.ensure_binding(&scope, &binding).is_err() || interface_still_current.is_err() {
            self.remove_slot(&capture_handle);
            close_live_capture(&live).await;
            return Err(PacketCaptureLiveApiError::BindingUnavailable);
        }
        let expires_in = Duration::from_secs(u64::from(input.duration_seconds))
            .saturating_add(CAPTURE_RETENTION_GRACE);
        let active = Arc::new(ActiveCapture {
            binding_handle: binding_handle.to_owned(),
            binding,
            scope: scope.clone(),
            live,
            expires_at: Instant::now() + expires_in,
            state: Mutex::new(LiveCaptureState::default()),
        });
        let activation = self.lock_captures().and_then(|mut captures| {
            captures.activate(&capture_handle, &scope, Arc::clone(&active), Instant::now())
        });
        if let Err(error) = activation {
            close_live_capture(&active.live).await;
            return Err(error);
        }
        if let Err(error) = self.ensure_active(&active) {
            let _ = self.remove_active(&capture_handle, &active);
            close_live_capture(&active.live).await;
            return Err(error);
        }
        Ok(PacketCaptureStartedDto {
            capture_handle,
            status: "running",
            expires_in_seconds: expires_in.as_secs(),
        })
    }

    pub(crate) async fn poll(
        &self,
        binding_handle: &str,
        capture_handle: &str,
        after_sequence: u64,
    ) -> Result<PacketCapturePollDto, PacketCaptureLiveApiError> {
        validate_handle(capture_handle)?;
        if after_sequence > MAX_SAFE_JSON_INTEGER {
            return Err(PacketCaptureLiveApiError::InvalidCursor);
        }
        let (binding, scope) = self.capture_binding(binding_handle)?;
        self.reap_stale(Some(&scope)).await;
        let _permit = self.acquire_operation(&scope)?;
        let active = self.active(capture_handle)?;
        if active.scope != scope || active.binding != binding {
            self.invalidate(capture_handle, &active).await;
            return Err(PacketCaptureLiveApiError::BindingUnavailable);
        }
        if let Err(error) = self.ensure_active(&active) {
            self.invalidate(capture_handle, &active).await;
            return Err(error);
        }
        let polled = {
            let mut state = active.lock_state()?;
            state.poll(
                &active.live,
                capture_handle,
                after_sequence,
                &active.scope.sensitive_literals(),
            )
        };
        let (response, terminal_finished) = match polled {
            Ok(response) => response,
            Err(error) => {
                self.invalidate(capture_handle, &active).await;
                return Err(error);
            }
        };
        if let Err(error) = self
            .ensure_active(&active)
            .and_then(|()| self.ensure_registered(capture_handle, &active))
        {
            self.invalidate(capture_handle, &active).await;
            return Err(error);
        }
        if terminal_finished {
            close_live_capture(&active.live).await;
        }
        Ok(response)
    }

    pub(crate) async fn stop(
        &self,
        binding_handle: &str,
        capture_handle: &str,
    ) -> Result<PacketCaptureStoppedDto, PacketCaptureLiveApiError> {
        validate_handle(binding_handle)?;
        validate_handle(capture_handle)?;
        let (binding, scope) = match self.capture_binding(binding_handle) {
            Ok(binding) => binding,
            Err(error) => {
                let active = self
                    .lock_captures()?
                    .take_for_binding(capture_handle, binding_handle);
                if let Some(active) = active {
                    close_live_capture(&active.live).await;
                }
                return Err(error);
            }
        };
        self.reap_stale(Some(&scope)).await;
        let active = self.active(capture_handle)?;
        if active.scope != scope || active.binding != binding {
            self.invalidate(capture_handle, &active).await;
            return Err(PacketCaptureLiveApiError::BindingUnavailable);
        }
        self.remove_active(capture_handle, &active)?;
        close_live_capture(&active.live).await;
        self.ensure_binding(&scope, &binding)?;
        Ok(PacketCaptureStoppedDto { stopped: true })
    }

    pub(crate) async fn close_binding(&self, binding_handle: &str) {
        let active = self
            .captures
            .lock()
            .map(|mut captures| captures.close_binding(binding_handle, Instant::now()))
            .unwrap_or_default();
        if let Ok(mut interfaces) = self.interfaces.lock() {
            interfaces.remove_binding(binding_handle);
        }
        if let Ok(mut operations) = self.operations.lock() {
            operations.close_binding(binding_handle);
        }
        close_live_captures(active).await;
    }

    fn capture_binding(
        &self,
        binding_handle: &str,
    ) -> Result<(BoundSshSession, BindingScope), PacketCaptureLiveApiError> {
        validate_handle(binding_handle)?;
        let binding = self
            .ssh_api
            .binding_session_clone(binding_handle)
            .map_err(|_| PacketCaptureLiveApiError::BindingUnavailable)?;
        self.services
            .target()
            .validate(binding.target())
            .map_err(|_| PacketCaptureLiveApiError::BindingUnavailable)?;
        let scope = BindingScope::from_binding(binding_handle, &binding);
        self.ensure_binding_open(binding_handle)?;
        Ok((binding, scope))
    }

    fn ensure_binding(
        &self,
        expected: &BindingScope,
        binding: &BoundSshSession,
    ) -> Result<(), PacketCaptureLiveApiError> {
        self.ensure_binding_open(&expected.binding_handle)?;
        self.services
            .target()
            .validate(binding.target())
            .map_err(|_| PacketCaptureLiveApiError::BindingUnavailable)?;
        if &BindingScope::from_binding(&expected.binding_handle, binding) != expected {
            return Err(PacketCaptureLiveApiError::BindingUnavailable);
        }
        let current = self
            .ssh_api
            .binding_session_clone(&expected.binding_handle)
            .map_err(|_| PacketCaptureLiveApiError::BindingUnavailable)?;
        if BindingScope::from_binding(&expected.binding_handle, &current) != *expected {
            return Err(PacketCaptureLiveApiError::BindingUnavailable);
        }
        self.services
            .target()
            .validate(current.target())
            .map_err(|_| PacketCaptureLiveApiError::BindingUnavailable)?;
        self.ensure_binding_open(&expected.binding_handle)
    }

    fn ensure_active(&self, active: &ActiveCapture) -> Result<(), PacketCaptureLiveApiError> {
        if active.binding.target() != &active.scope.target {
            return Err(PacketCaptureLiveApiError::BindingUnavailable);
        }
        self.ensure_binding(&active.scope, &active.binding)
    }

    fn acquire_operation(
        &self,
        scope: &BindingScope,
    ) -> Result<OperationPermit, PacketCaptureLiveApiError> {
        OperationPermit::acquire(
            Arc::clone(&self.operations),
            scope.binding_handle.clone(),
            scope.concurrency_key(),
        )
    }

    fn ensure_binding_open(&self, binding_handle: &str) -> Result<(), PacketCaptureLiveApiError> {
        self.lock_captures()?
            .ensure_binding_open(binding_handle, Instant::now())
    }

    async fn reap_stale(&self, current: Option<&BindingScope>) {
        if let Ok(mut interfaces) = self.interfaces.lock() {
            interfaces.prune(Instant::now(), current);
        }
        let stale = self
            .captures
            .lock()
            .map(|mut captures| captures.take_stale(Instant::now(), current))
            .unwrap_or_default();
        close_live_captures(stale).await;
    }

    fn active(&self, handle: &str) -> Result<Arc<ActiveCapture>, PacketCaptureLiveApiError> {
        self.lock_captures()?.active(handle, Instant::now())
    }

    fn ensure_registered(
        &self,
        handle: &str,
        active: &Arc<ActiveCapture>,
    ) -> Result<(), PacketCaptureLiveApiError> {
        self.lock_captures()?.ensure_active(handle, active)
    }

    async fn invalidate(&self, handle: &str, active: &Arc<ActiveCapture>) {
        let _ = self.remove_active(handle, active);
        close_live_capture(&active.live).await;
    }

    fn remove_active(
        &self,
        handle: &str,
        active: &Arc<ActiveCapture>,
    ) -> Result<(), PacketCaptureLiveApiError> {
        self.lock_captures()?.remove_active(handle, active)
    }

    fn remove_slot(&self, handle: &str) {
        if let Ok(mut captures) = self.captures.lock() {
            captures.slots.remove(handle);
        }
    }

    fn lock_interfaces(
        &self,
    ) -> Result<MutexGuard<'_, InterfaceRegistry>, PacketCaptureLiveApiError> {
        self.interfaces
            .lock()
            .map_err(|_| PacketCaptureLiveApiError::RegistryUnavailable)
    }

    fn lock_captures(&self) -> Result<MutexGuard<'_, CaptureRegistry>, PacketCaptureLiveApiError> {
        self.captures
            .lock()
            .map_err(|_| PacketCaptureLiveApiError::RegistryUnavailable)
    }
}

impl Drop for PacketCaptureLiveApi {
    fn drop(&mut self) {
        if let Ok(captures) = self.captures.lock() {
            for slot in captures.slots.values() {
                if let CaptureSlot::Active(active) = slot {
                    active.live.request_stop();
                }
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PacketCaptureStartInput {
    filter: Option<String>,
    packet_limit: Option<u32>,
    duration_seconds: u32,
}

impl fmt::Debug for PacketCaptureStartInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PacketCaptureStartInput")
            .field("filter_present", &self.filter.is_some())
            .field("packet_limit", &self.packet_limit)
            .field("duration_seconds", &self.duration_seconds)
            .finish()
    }
}

impl PacketCaptureStartInput {
    fn validate(&self) -> Result<(), PacketCaptureLiveApiError> {
        if !(1..=MAX_PCAP_CAPTURE_SECONDS).contains(&self.duration_seconds)
            || self
                .packet_limit
                .is_some_and(|value| value == 0 || value > MAX_PCAP_PACKET_COUNT)
        {
            return Err(PacketCaptureLiveApiError::InvalidInput);
        }
        if let Some(filter) = self.filter.as_deref()
            && (filter.is_empty()
                || filter.trim() != filter
                || filter.len() > 2_048
                || filter.contains(['\0', '\n', '\r']))
        {
            return Err(PacketCaptureLiveApiError::InvalidInput);
        }
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PacketCaptureInterfaceListDto {
    interfaces: Vec<PacketCaptureInterfaceDto>,
    displayed: usize,
    truncated: bool,
    expires_in_seconds: u64,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PacketCaptureInterfaceDto {
    interface_handle: String,
    name: String,
    mac: Option<String>,
    addresses: Vec<String>,
    text_truncated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PacketCaptureStartedDto {
    capture_handle: String,
    status: &'static str,
    expires_in_seconds: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PacketCaptureStoppedDto {
    stopped: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PacketCapturePollDto {
    capture_handle: String,
    status: &'static str,
    oldest_sequence: u64,
    latest_sequence: u64,
    cursor_reset: bool,
    has_more: bool,
    truncated: bool,
    dropped_events: u64,
    retained_packets: usize,
    packets: u64,
    bytes: u64,
    events: Vec<PacketCaptureEventDto>,
}

#[derive(Clone, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub(crate) enum PacketCaptureEventDto {
    Started {
        sequence: u64,
        observed_at: String,
    },
    Packet {
        sequence: u64,
        observed_at: String,
        timestamp: String,
        protocol: String,
        source: String,
        destination: String,
        length: String,
        info: String,
        raw: String,
        text_truncated: bool,
    },
    Info {
        sequence: u64,
        observed_at: String,
        message: String,
        text_truncated: bool,
    },
    Progress {
        sequence: u64,
        observed_at: String,
        packets: u64,
        bytes: u64,
        counters_truncated: bool,
    },
    Stopped {
        sequence: u64,
        observed_at: String,
    },
    Failed {
        sequence: u64,
        observed_at: String,
        code: &'static str,
    },
}

impl PacketCaptureEventDto {
    const fn sequence(&self) -> u64 {
        match self {
            Self::Started { sequence, .. }
            | Self::Packet { sequence, .. }
            | Self::Info { sequence, .. }
            | Self::Progress { sequence, .. }
            | Self::Stopped { sequence, .. }
            | Self::Failed { sequence, .. } => *sequence,
        }
    }

    const fn is_packet(&self) -> bool {
        matches!(self, Self::Packet { .. })
    }
}

#[derive(Clone, Eq, PartialEq)]
struct BindingScope {
    binding_handle: String,
    session_id: String,
    connection_id: String,
    target: TargetGuard,
}

impl BindingScope {
    fn from_binding(binding_handle: &str, binding: &BoundSshSession) -> Self {
        Self {
            binding_handle: binding_handle.to_owned(),
            session_id: binding.session_id().to_owned(),
            connection_id: binding.connection_id().to_owned(),
            target: binding.target().clone(),
        }
    }

    fn concurrency_key(&self) -> String {
        format!(
            "{}\0{}\0{}\0{}\0{}",
            self.binding_handle,
            self.session_id,
            self.connection_id,
            self.target.identity.as_str(),
            self.target.generation,
        )
    }

    fn sensitive_literals(&self) -> [&str; 4] {
        [
            &self.binding_handle,
            &self.session_id,
            &self.connection_id,
            self.target.identity.as_str(),
        ]
    }
}

impl fmt::Debug for BindingScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PacketCaptureBindingScope([REDACTED])")
    }
}

struct ActiveCapture {
    binding_handle: String,
    binding: BoundSshSession,
    scope: BindingScope,
    live: Arc<LivePacketCapture>,
    expires_at: Instant,
    state: Mutex<LiveCaptureState>,
}

impl ActiveCapture {
    fn lock_state(&self) -> Result<MutexGuard<'_, LiveCaptureState>, PacketCaptureLiveApiError> {
        self.state
            .lock()
            .map_err(|_| PacketCaptureLiveApiError::RegistryUnavailable)
    }
}

impl fmt::Debug for ActiveCapture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ActivePacketCapture([REDACTED])")
    }
}

#[derive(Default)]
struct CaptureRegistry {
    slots: HashMap<String, CaptureSlot>,
    closed_bindings: HashMap<String, Instant>,
    closed_overflow_until: Option<Instant>,
}

enum CaptureSlot {
    Opening {
        scope: BindingScope,
        expires_at: Instant,
    },
    Active(Arc<ActiveCapture>),
}

impl CaptureSlot {
    fn scope(&self) -> &BindingScope {
        match self {
            Self::Opening { scope, .. } => scope,
            Self::Active(active) => &active.scope,
        }
    }
}

impl CaptureRegistry {
    fn reserve(
        &mut self,
        scope: BindingScope,
        now: Instant,
    ) -> Result<(String, Vec<Arc<ActiveCapture>>), PacketCaptureLiveApiError> {
        self.ensure_binding_open(&scope.binding_handle, now)?;
        if self
            .slots
            .values()
            .filter(|slot| slot.scope().binding_handle == scope.binding_handle)
            .count()
            >= MAX_CAPTURES_PER_BINDING
        {
            return Err(PacketCaptureLiveApiError::CaptureAlreadyActive);
        }
        let mut evicted = Vec::new();
        if self.slots.len() >= MAX_CAPTURES {
            let oldest = self
                .slots
                .iter()
                .filter_map(|(handle, slot)| match slot {
                    CaptureSlot::Active(active) => Some((handle.clone(), active.expires_at)),
                    CaptureSlot::Opening { .. } => None,
                })
                .min_by_key(|(_, expires_at)| *expires_at)
                .map(|(handle, _)| handle)
                .ok_or(PacketCaptureLiveApiError::RegistryCapacity)?;
            if let Some(CaptureSlot::Active(active)) = self.slots.remove(&oldest) {
                evicted.push(active);
            }
        }
        for _ in 0..8 {
            let handle = Uuid::new_v4().to_string();
            if self.slots.contains_key(&handle) {
                continue;
            }
            self.slots.insert(
                handle.clone(),
                CaptureSlot::Opening {
                    scope,
                    expires_at: now + START_RESERVATION_TTL,
                },
            );
            return Ok((handle, evicted));
        }
        Err(PacketCaptureLiveApiError::RegistryCapacity)
    }

    fn activate(
        &mut self,
        handle: &str,
        scope: &BindingScope,
        active: Arc<ActiveCapture>,
        now: Instant,
    ) -> Result<(), PacketCaptureLiveApiError> {
        let Some(slot) = self.slots.get_mut(handle) else {
            return Err(PacketCaptureLiveApiError::CaptureUnavailable);
        };
        match slot {
            CaptureSlot::Opening {
                scope: reserved,
                expires_at,
            } if reserved == scope && *expires_at > now => {
                *slot = CaptureSlot::Active(active);
                Ok(())
            }
            _ => Err(PacketCaptureLiveApiError::BindingUnavailable),
        }
    }

    fn active(
        &self,
        handle: &str,
        now: Instant,
    ) -> Result<Arc<ActiveCapture>, PacketCaptureLiveApiError> {
        match self.slots.get(handle) {
            Some(CaptureSlot::Active(active)) if active.expires_at > now => Ok(Arc::clone(active)),
            _ => Err(PacketCaptureLiveApiError::CaptureUnavailable),
        }
    }

    fn remove_active(
        &mut self,
        handle: &str,
        expected: &Arc<ActiveCapture>,
    ) -> Result<(), PacketCaptureLiveApiError> {
        match self.slots.get(handle) {
            Some(CaptureSlot::Active(active)) if Arc::ptr_eq(active, expected) => {
                self.slots.remove(handle);
                Ok(())
            }
            _ => Err(PacketCaptureLiveApiError::CaptureUnavailable),
        }
    }

    fn ensure_active(
        &self,
        handle: &str,
        expected: &Arc<ActiveCapture>,
    ) -> Result<(), PacketCaptureLiveApiError> {
        match self.slots.get(handle) {
            Some(CaptureSlot::Active(active)) if Arc::ptr_eq(active, expected) => Ok(()),
            _ => Err(PacketCaptureLiveApiError::CaptureUnavailable),
        }
    }

    fn take_for_binding(
        &mut self,
        handle: &str,
        binding_handle: &str,
    ) -> Option<Arc<ActiveCapture>> {
        let matches = matches!(
            self.slots.get(handle),
            Some(CaptureSlot::Active(active)) if active.binding_handle == binding_handle
        );
        if !matches {
            return None;
        }
        match self.slots.remove(handle) {
            Some(CaptureSlot::Active(active)) => Some(active),
            _ => None,
        }
    }

    fn take_stale(
        &mut self,
        now: Instant,
        current: Option<&BindingScope>,
    ) -> Vec<Arc<ActiveCapture>> {
        self.prune_closed_bindings(now);
        let handles = self
            .slots
            .iter()
            .filter_map(|(handle, slot)| {
                let expired = match slot {
                    CaptureSlot::Opening { expires_at, .. } => *expires_at <= now,
                    CaptureSlot::Active(active) => active.expires_at <= now,
                };
                let binding_changed = current.is_some_and(|current| {
                    slot.scope().binding_handle == current.binding_handle && slot.scope() != current
                });
                (expired || binding_changed).then_some(handle.clone())
            })
            .collect::<Vec<_>>();
        let mut active = Vec::new();
        for handle in handles {
            if let Some(CaptureSlot::Active(capture)) = self.slots.remove(&handle) {
                active.push(capture);
            }
        }
        active
    }

    fn ensure_binding_open(
        &mut self,
        binding_handle: &str,
        now: Instant,
    ) -> Result<(), PacketCaptureLiveApiError> {
        self.prune_closed_bindings(now);
        if self
            .closed_overflow_until
            .is_some_and(|expires_at| expires_at > now)
            || self.closed_bindings.contains_key(binding_handle)
        {
            return Err(PacketCaptureLiveApiError::BindingUnavailable);
        }
        Ok(())
    }

    fn close_binding(&mut self, binding_handle: &str, now: Instant) -> Vec<Arc<ActiveCapture>> {
        self.prune_closed_bindings(now);
        if self.closed_bindings.len() >= MAX_CLOSED_BINDINGS
            && !self.closed_bindings.contains_key(binding_handle)
        {
            self.closed_overflow_until = Some(now + CLOSED_BINDING_TTL);
        } else {
            self.closed_bindings
                .insert(binding_handle.to_owned(), now + CLOSED_BINDING_TTL);
        }
        let handles = self
            .slots
            .iter()
            .filter_map(|(handle, slot)| {
                (slot.scope().binding_handle == binding_handle).then_some(handle.clone())
            })
            .collect::<Vec<_>>();
        let mut active = Vec::new();
        for handle in handles {
            if let Some(CaptureSlot::Active(capture)) = self.slots.remove(&handle) {
                active.push(capture);
            }
        }
        active
    }

    fn prune_closed_bindings(&mut self, now: Instant) {
        self.closed_bindings
            .retain(|_, expires_at| *expires_at > now);
        if self
            .closed_overflow_until
            .is_some_and(|expires_at| expires_at <= now)
        {
            self.closed_overflow_until = None;
        }
    }
}

#[derive(Default)]
struct InterfaceRegistry {
    entries: HashMap<String, InterfaceEntry>,
    total_bytes: usize,
}

struct InterfaceEntry {
    scope: BindingScope,
    key: String,
    name: String,
    bytes: usize,
    expires_at: Instant,
    touched_at: Instant,
}

impl InterfaceRegistry {
    fn replace_scope(
        &mut self,
        scope: BindingScope,
        source: Vec<NetworkInterface>,
        now: Instant,
    ) -> Result<PacketCaptureInterfaceListDto, PacketCaptureLiveApiError> {
        self.prune(now, Some(&scope));
        let reusable = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.scope == scope)
            .map(|(handle, entry)| (entry.key.clone(), handle.clone()))
            .collect::<HashMap<_, _>>();
        let old = self
            .entries
            .iter()
            .filter_map(|(handle, entry)| (entry.scope == scope).then_some(handle.clone()))
            .collect::<Vec<_>>();
        for handle in old {
            self.remove(&handle);
        }
        let source_count = source.len();
        let mut seen = HashSet::new();
        let mut used_handles = self.entries.keys().cloned().collect::<HashSet<_>>();
        let mut projected = Vec::new();
        let mut pending = Vec::new();
        let mut response_bytes = INTERFACE_RESPONSE_ENVELOPE_BYTES;
        let sensitive_literals = scope.sensitive_literals();
        for interface in source.into_iter().take(MAX_INTERFACES) {
            let key = format!("{}\0{}", interface.index, interface.name);
            if !seen.insert(key.clone()) {
                continue;
            }
            let handle = reusable
                .get(&key)
                .cloned()
                .unwrap_or(unique_set_handle(&used_handles)?);
            if !used_handles.insert(handle.clone()) {
                return Err(PacketCaptureLiveApiError::RegistryCapacity);
            }
            let dto = project_interface(handle.clone(), &interface, &sensitive_literals);
            let dto_bytes = serde_json::to_vec(&dto)
                .map_err(|_| PacketCaptureLiveApiError::OutputLimit)?
                .len();
            if response_bytes.saturating_add(dto_bytes) > MAX_INTERFACE_RESPONSE_BYTES {
                break;
            }
            let bytes = dto_bytes
                .saturating_add(interface.name.len())
                .saturating_add(key.len());
            response_bytes = response_bytes.saturating_add(dto_bytes);
            projected.push(dto);
            pending.push((handle, key, interface.name, bytes));
        }
        let pending_bytes = pending.iter().fold(0usize, |total, (_, _, _, bytes)| {
            total.saturating_add(*bytes)
        });
        while self.entries.len().saturating_add(pending.len()) > MAX_INTERFACE_ENTRIES
            || self.total_bytes.saturating_add(pending_bytes) > MAX_INTERFACE_REGISTRY_BYTES
        {
            let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.touched_at)
                .map(|(handle, _)| handle.clone())
            else {
                break;
            };
            self.remove(&oldest);
        }
        if self.entries.len().saturating_add(pending.len()) > MAX_INTERFACE_ENTRIES
            || self.total_bytes.saturating_add(pending_bytes) > MAX_INTERFACE_REGISTRY_BYTES
        {
            return Err(PacketCaptureLiveApiError::RegistryCapacity);
        }
        let displayed = projected.len();
        let response = PacketCaptureInterfaceListDto {
            interfaces: projected,
            displayed,
            truncated: displayed < source_count,
            expires_in_seconds: INTERFACE_TTL.as_secs(),
        };
        if serde_json::to_vec(&response)
            .map_err(|_| PacketCaptureLiveApiError::OutputLimit)?
            .len()
            > MAX_INTERFACE_RESPONSE_BYTES
        {
            return Err(PacketCaptureLiveApiError::OutputLimit);
        }
        for (handle, key, name, bytes) in pending {
            self.total_bytes = self.total_bytes.saturating_add(bytes);
            self.entries.insert(
                handle,
                InterfaceEntry {
                    scope: scope.clone(),
                    key,
                    name,
                    bytes,
                    expires_at: now + INTERFACE_TTL,
                    touched_at: now,
                },
            );
        }
        Ok(response)
    }

    fn resolve(
        &mut self,
        scope: &BindingScope,
        handle: &str,
        now: Instant,
    ) -> Result<String, PacketCaptureLiveApiError> {
        let entry = self
            .entries
            .get_mut(handle)
            .filter(|entry| &entry.scope == scope && entry.expires_at > now)
            .ok_or(PacketCaptureLiveApiError::InterfaceUnavailable)?;
        entry.expires_at = now + INTERFACE_TTL;
        entry.touched_at = now;
        Ok(entry.name.clone())
    }

    fn prune(&mut self, now: Instant, current: Option<&BindingScope>) {
        let stale = self
            .entries
            .iter()
            .filter_map(|(handle, entry)| {
                let binding_changed = current.is_some_and(|current| {
                    entry.scope.binding_handle == current.binding_handle && entry.scope != *current
                });
                (entry.expires_at <= now || binding_changed).then_some(handle.clone())
            })
            .collect::<Vec<_>>();
        for handle in stale {
            self.remove(&handle);
        }
    }

    fn remove(&mut self, handle: &str) {
        if let Some(entry) = self.entries.remove(handle) {
            self.total_bytes = self.total_bytes.saturating_sub(entry.bytes);
        }
    }

    fn remove_binding(&mut self, binding_handle: &str) {
        let handles = self
            .entries
            .iter()
            .filter_map(|(handle, entry)| {
                (entry.scope.binding_handle == binding_handle).then_some(handle.clone())
            })
            .collect::<Vec<_>>();
        for handle in handles {
            self.remove(&handle);
        }
    }
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
enum CaptureStatus {
    #[default]
    Running,
    Stopped,
    Failed,
}

impl CaptureStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
        }
    }
}

#[derive(Default)]
struct LiveCaptureState {
    events: VecDeque<PacketCaptureEventDto>,
    event_bytes: usize,
    retained_packets: usize,
    dropped_events: u64,
    last_sequence: u64,
    total_packets: u64,
    total_bytes: u64,
    status: CaptureStatus,
    cleanup_requested: bool,
}

impl LiveCaptureState {
    fn poll(
        &mut self,
        live: &LivePacketCapture,
        capture_handle: &str,
        after_sequence: u64,
        sensitive_literals: &[&str],
    ) -> Result<(PacketCapturePollDto, bool), PacketCaptureLiveApiError> {
        for _ in 0..MAX_CORE_DRAIN_PER_POLL {
            match live.events().try_recv() {
                Ok(Some(event)) => {
                    self.apply_event(live.capture_id(), event, sensitive_literals)?
                }
                Ok(None) => break,
                Err(CoreError::ChannelClosed { .. }) => {
                    if self.status == CaptureStatus::Running {
                        self.status = CaptureStatus::Failed;
                    }
                    break;
                }
                Err(_) => return Err(PacketCaptureLiveApiError::Core),
            }
        }
        let oldest_sequence = self
            .events
            .front()
            .map(PacketCaptureEventDto::sequence)
            .unwrap_or(self.last_sequence);
        if after_sequence > self.last_sequence {
            return Err(PacketCaptureLiveApiError::InvalidCursor);
        }
        let cursor_reset =
            !self.events.is_empty() && after_sequence.saturating_add(1) < oldest_sequence;
        let effective_after = if cursor_reset {
            oldest_sequence.saturating_sub(1)
        } else {
            after_sequence
        };
        let mut events = Vec::new();
        let mut response_bytes = 0usize;
        let mut has_more = false;
        for event in self
            .events
            .iter()
            .filter(|event| event.sequence() > effective_after)
        {
            let bytes = serde_json::to_vec(event)
                .map_err(|_| PacketCaptureLiveApiError::OutputLimit)?
                .len();
            if events.len() >= MAX_POLL_EVENTS
                || response_bytes.saturating_add(bytes) > MAX_POLL_BYTES
            {
                has_more = true;
                break;
            }
            response_bytes = response_bytes.saturating_add(bytes);
            events.push(event.clone());
        }
        has_more |= !live.events().is_empty();
        let terminal_finished = self.status != CaptureStatus::Running && !self.cleanup_requested;
        self.cleanup_requested |= terminal_finished;
        let response = PacketCapturePollDto {
            capture_handle: capture_handle.to_owned(),
            status: self.status.as_str(),
            oldest_sequence,
            latest_sequence: self.last_sequence,
            cursor_reset,
            has_more,
            truncated: cursor_reset || has_more || self.dropped_events > 0,
            dropped_events: self.dropped_events,
            retained_packets: self.retained_packets,
            packets: self.total_packets,
            bytes: self.total_bytes,
            events,
        };
        if serde_json::to_vec(&response)
            .map_err(|_| PacketCaptureLiveApiError::OutputLimit)?
            .len()
            > MAX_POLL_BYTES
        {
            return Err(PacketCaptureLiveApiError::OutputLimit);
        }
        Ok((response, terminal_finished))
    }

    fn apply_event(
        &mut self,
        capture_id: &str,
        event: CoreCaptureEvent,
        sensitive_literals: &[&str],
    ) -> Result<(), PacketCaptureLiveApiError> {
        if event.capture_id != capture_id
            || event.sequence != self.next_sequence()?
            || event.sequence > MAX_SAFE_JSON_INTEGER
        {
            return Err(PacketCaptureLiveApiError::ProtocolViolation);
        }
        if self.last_sequence == 0 && !matches!(&event.kind, CoreCaptureEventKind::Started { .. }) {
            return Err(PacketCaptureLiveApiError::ProtocolViolation);
        }
        if self.last_sequence > 0 && matches!(&event.kind, CoreCaptureEventKind::Started { .. }) {
            return Err(PacketCaptureLiveApiError::ProtocolViolation);
        }
        if self.status == CaptureStatus::Stopped
            || (self.status == CaptureStatus::Failed
                && !matches!(&event.kind, CoreCaptureEventKind::Stopped))
        {
            return Err(PacketCaptureLiveApiError::ProtocolViolation);
        }
        let observed_at = event.observed_at.to_rfc3339();
        self.last_sequence = event.sequence;
        let projected = match event.kind {
            CoreCaptureEventKind::Started { .. } => PacketCaptureEventDto::Started {
                sequence: event.sequence,
                observed_at,
            },
            CoreCaptureEventKind::Data(packet) => {
                self.total_packets = bounded_add(self.total_packets, 1).0;
                let packet_length = packet.length.parse::<u64>().unwrap_or_default();
                self.total_bytes = bounded_add(self.total_bytes, packet_length).0;
                project_packet(event.sequence, observed_at, packet, sensitive_literals)
            }
            CoreCaptureEventKind::Info { message } => {
                let (message, text_truncated) =
                    project_public_single_line(&message, MAX_INFO_BYTES, sensitive_literals);
                PacketCaptureEventDto::Info {
                    sequence: event.sequence,
                    observed_at,
                    message,
                    text_truncated,
                }
            }
            CoreCaptureEventKind::Progress { packets, bytes } => {
                let (packets, packets_truncated) = bounded_u64(packets);
                let (bytes, bytes_truncated) = bounded_u64(bytes);
                self.total_packets = self.total_packets.max(packets);
                self.total_bytes = self.total_bytes.max(bytes);
                PacketCaptureEventDto::Progress {
                    sequence: event.sequence,
                    observed_at,
                    packets,
                    bytes,
                    counters_truncated: packets_truncated || bytes_truncated,
                }
            }
            CoreCaptureEventKind::Stopped => {
                if self.status != CaptureStatus::Failed {
                    self.status = CaptureStatus::Stopped;
                }
                PacketCaptureEventDto::Stopped {
                    sequence: event.sequence,
                    observed_at,
                }
            }
            CoreCaptureEventKind::Failed { .. } => {
                self.status = CaptureStatus::Failed;
                PacketCaptureEventDto::Failed {
                    sequence: event.sequence,
                    observed_at,
                    code: "capture-failed",
                }
            }
            CoreCaptureEventKind::ArtifactReady { .. } => {
                return Err(PacketCaptureLiveApiError::ProtocolViolation);
            }
        };
        self.append(projected)
    }

    fn append(&mut self, event: PacketCaptureEventDto) -> Result<(), PacketCaptureLiveApiError> {
        let event_bytes = serde_json::to_vec(&event)
            .map_err(|_| PacketCaptureLiveApiError::OutputLimit)?
            .len();
        if event_bytes > MAX_PUBLIC_EVENT_BYTES || event_bytes > MAX_CAPTURE_JOURNAL_BYTES {
            return Err(PacketCaptureLiveApiError::OutputLimit);
        }
        let adds_packet = event.is_packet();
        while self.events.len() >= MAX_RETAINED_EVENTS
            || self.event_bytes.saturating_add(event_bytes) > MAX_CAPTURE_JOURNAL_BYTES
            || (adds_packet && self.retained_packets >= MAX_RETAINED_PACKETS)
        {
            let Some(removed) = self.events.pop_front() else {
                return Err(PacketCaptureLiveApiError::OutputLimit);
            };
            let removed_bytes = serde_json::to_vec(&removed)
                .map_err(|_| PacketCaptureLiveApiError::OutputLimit)?
                .len();
            self.event_bytes = self.event_bytes.saturating_sub(removed_bytes);
            if removed.is_packet() {
                self.retained_packets = self.retained_packets.saturating_sub(1);
            }
            self.dropped_events = bounded_add(self.dropped_events, 1).0;
        }
        self.event_bytes = self.event_bytes.saturating_add(event_bytes);
        if adds_packet {
            self.retained_packets = self.retained_packets.saturating_add(1);
        }
        self.events.push_back(event);
        Ok(())
    }

    fn next_sequence(&self) -> Result<u64, PacketCaptureLiveApiError> {
        self.last_sequence
            .checked_add(1)
            .filter(|sequence| *sequence <= MAX_SAFE_JSON_INTEGER)
            .ok_or(PacketCaptureLiveApiError::ProtocolViolation)
    }
}

fn project_interface(
    handle: String,
    interface: &NetworkInterface,
    sensitive_literals: &[&str],
) -> PacketCaptureInterfaceDto {
    let (name, name_truncated) = project_public_single_line(
        &interface.name,
        MAX_INTERFACE_FIELD_BYTES,
        sensitive_literals,
    );
    let (mac, mac_truncated) = interface.mac.as_deref().map_or((None, false), |value| {
        let (value, truncated) =
            project_public_single_line(value, MAX_INTERFACE_FIELD_BYTES, sensitive_literals);
        (Some(value), truncated)
    });
    let mut addresses = Vec::new();
    let mut addresses_truncated = interface.ips.len() > MAX_INTERFACE_ADDRESSES;
    for address in interface.ips.iter().take(MAX_INTERFACE_ADDRESSES) {
        let (address, truncated) =
            project_public_single_line(address, MAX_INTERFACE_FIELD_BYTES, sensitive_literals);
        addresses.push(address);
        addresses_truncated |= truncated;
    }
    PacketCaptureInterfaceDto {
        interface_handle: handle,
        name,
        mac,
        addresses,
        text_truncated: name_truncated || mac_truncated || addresses_truncated,
    }
}

fn project_packet(
    sequence: u64,
    observed_at: String,
    packet: CorePacketEntry,
    sensitive_literals: &[&str],
) -> PacketCaptureEventDto {
    let (timestamp, timestamp_truncated) = project_public_single_line(
        &packet.timestamp,
        MAX_PACKET_FIELD_BYTES,
        sensitive_literals,
    );
    let (protocol, protocol_truncated) =
        project_public_single_line(&packet.protocol, MAX_PACKET_FIELD_BYTES, sensitive_literals);
    let (source, source_truncated) =
        project_public_single_line(&packet.src, MAX_PACKET_FIELD_BYTES, sensitive_literals);
    let (destination, destination_truncated) =
        project_public_single_line(&packet.dst, MAX_PACKET_FIELD_BYTES, sensitive_literals);
    let (length, length_truncated) =
        project_public_single_line(&packet.length, MAX_PACKET_FIELD_BYTES, sensitive_literals);
    let (info, info_truncated) =
        project_public_single_line(&packet.info, MAX_PACKET_RAW_BYTES, sensitive_literals);
    let (raw, raw_truncated) =
        project_public_single_line(&packet.raw, MAX_PACKET_RAW_BYTES, sensitive_literals);
    PacketCaptureEventDto::Packet {
        sequence,
        observed_at,
        timestamp,
        protocol,
        source,
        destination,
        length,
        info,
        raw,
        text_truncated: timestamp_truncated
            || protocol_truncated
            || source_truncated
            || destination_truncated
            || length_truncated
            || info_truncated
            || raw_truncated,
    }
}

#[derive(Default)]
struct OperationState {
    active: HashMap<Uuid, OperationEntry>,
}

struct OperationEntry {
    binding_handle: String,
    key: String,
}

impl OperationState {
    fn close_binding(&mut self, binding_handle: &str) {
        self.active
            .retain(|_, entry| entry.binding_handle != binding_handle);
    }
}

struct OperationPermit {
    state: Arc<Mutex<OperationState>>,
    token: Uuid,
}

impl OperationPermit {
    fn acquire(
        state: Arc<Mutex<OperationState>>,
        binding_handle: String,
        key: String,
    ) -> Result<Self, PacketCaptureLiveApiError> {
        let token = Uuid::new_v4();
        {
            let mut current = state
                .lock()
                .map_err(|_| PacketCaptureLiveApiError::RegistryUnavailable)?;
            let binding_operations = current
                .active
                .values()
                .filter(|entry| entry.key == key)
                .count();
            if current.active.len() >= MAX_GLOBAL_OPERATIONS
                || binding_operations >= MAX_OPERATIONS_PER_BINDING
            {
                return Err(PacketCaptureLiveApiError::ConcurrencyLimit);
            }
            current.active.insert(
                token,
                OperationEntry {
                    binding_handle,
                    key,
                },
            );
        }
        Ok(Self { state, token })
    }
}

impl Drop for OperationPermit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            state.active.remove(&self.token);
        }
    }
}

async fn close_live_capture(capture: &LivePacketCapture) {
    capture.request_stop();
    let _ = tokio::time::timeout(CONTROL_TIMEOUT, capture.stop()).await;
}

async fn close_live_captures(captures: Vec<Arc<ActiveCapture>>) {
    for capture in &captures {
        capture.live.request_stop();
    }
    let _ = tokio::time::timeout(CONTROL_TIMEOUT, async {
        for capture in captures {
            let _ = capture.live.stop().await;
        }
    })
    .await;
}

fn project_public_single_line(
    value: &str,
    maximum_bytes: usize,
    sensitive_literals: &[&str],
) -> (String, bool) {
    if is_sensitive_text(value, sensitive_literals) {
        return (REDACTED_PACKET_CAPTURE_TEXT.to_owned(), true);
    }
    bounded_single_line(value, maximum_bytes)
}

fn bounded_single_line(value: &str, maximum_bytes: usize) -> (String, bool) {
    let mut sanitized = String::with_capacity(value.len());
    let mut changed = false;
    for character in value.chars() {
        if character.is_control() {
            sanitized.push('\u{fffd}');
            changed = true;
        } else {
            sanitized.push(character);
        }
    }
    let (bounded, truncated) = truncate_utf8(&sanitized, maximum_bytes);
    (bounded, changed || truncated)
}

fn is_sensitive_text(value: &str, sensitive_literals: &[&str]) -> bool {
    value.contains(REDACTED_PACKET_CAPTURE_TEXT)
        || sensitive_literals
            .iter()
            .any(|literal| !literal.is_empty() && value.contains(*literal))
}

fn truncate_utf8(value: &str, maximum_bytes: usize) -> (String, bool) {
    if value.len() <= maximum_bytes {
        return (value.to_owned(), false);
    }
    let mut end = maximum_bytes.min(value.len());
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    (value[..end].to_owned(), true)
}

fn bounded_u64(value: u64) -> (u64, bool) {
    (
        value.min(MAX_SAFE_JSON_INTEGER),
        value > MAX_SAFE_JSON_INTEGER,
    )
}

fn bounded_add(left: u64, right: u64) -> (u64, bool) {
    let value = left.saturating_add(right);
    bounded_u64(value)
}

fn validate_handle(handle: &str) -> Result<(), PacketCaptureLiveApiError> {
    let canonical = Uuid::parse_str(handle)
        .is_ok_and(|parsed| handle.len() == 36 && parsed.to_string() == handle);
    if handle.is_empty() || handle.len() > MAX_HANDLE_BYTES || !canonical {
        return Err(PacketCaptureLiveApiError::InvalidHandle);
    }
    Ok(())
}

fn unique_set_handle(existing: &HashSet<String>) -> Result<String, PacketCaptureLiveApiError> {
    for _ in 0..8 {
        let handle = Uuid::new_v4().to_string();
        if !existing.contains(&handle) {
            return Ok(handle);
        }
    }
    Err(PacketCaptureLiveApiError::RegistryCapacity)
}

pub(crate) enum PacketCaptureLiveApiError {
    Core,
    BindingUnavailable,
    InvalidHandle,
    InvalidInput,
    InvalidCursor,
    InterfaceUnavailable,
    CaptureUnavailable,
    CaptureAlreadyActive,
    RegistryCapacity,
    RegistryUnavailable,
    ConcurrencyLimit,
    OutputLimit,
    ProtocolViolation,
    TimedOut,
}

impl fmt::Debug for PacketCaptureLiveApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core => "Core([REDACTED])",
            Self::BindingUnavailable => "BindingUnavailable",
            Self::InvalidHandle => "InvalidHandle",
            Self::InvalidInput => "InvalidInput",
            Self::InvalidCursor => "InvalidCursor",
            Self::InterfaceUnavailable => "InterfaceUnavailable",
            Self::CaptureUnavailable => "CaptureUnavailable",
            Self::CaptureAlreadyActive => "CaptureAlreadyActive",
            Self::RegistryCapacity => "RegistryCapacity",
            Self::RegistryUnavailable => "RegistryUnavailable",
            Self::ConcurrencyLimit => "ConcurrencyLimit",
            Self::OutputLimit => "OutputLimit",
            Self::ProtocolViolation => "ProtocolViolation",
            Self::TimedOut => "TimedOut",
        })
    }
}

impl fmt::Display for PacketCaptureLiveApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core => "the live packet capture operation failed",
            Self::BindingUnavailable => "the SSH binding is missing or stale",
            Self::InvalidHandle => "the packet capture capability is invalid",
            Self::InvalidInput => "the packet capture parameters are invalid",
            Self::InvalidCursor => "the packet capture cursor is invalid",
            Self::InterfaceUnavailable => "the interface capability is missing or stale",
            Self::CaptureUnavailable => "the live capture capability is missing or stale",
            Self::CaptureAlreadyActive => "a live capture is already active for this binding",
            Self::RegistryCapacity => "the packet capture registry is full",
            Self::RegistryUnavailable => "the packet capture registry is unavailable",
            Self::ConcurrencyLimit => "too many packet capture operations are active",
            Self::OutputLimit => "the packet capture output exceeded its safety limit",
            Self::ProtocolViolation => "the packet capture stream is invalid",
            Self::TimedOut => "the packet capture operation timed out",
        })
    }
}

impl std::error::Error for PacketCaptureLiveApiError {}

impl From<CoreError> for PacketCaptureLiveApiError {
    fn from(error: CoreError) -> Self {
        // The renderer only ever sees a fixed message, so without this the
        // reason a page failed is lost before anyone can read it.
        tracing::warn!(operation = "PacketCaptureLive", error = %error, "core operation failed");
        // A host that went away is not a failure of this feature. One lost
        // connection reported once beats a dozen features each announcing
        // their own breakage.
        if matches!(error, CoreError::SshDisconnected { .. }) {
            return Self::BindingUnavailable;
        }
        Self::Core
    }
}

#[cfg(test)]
mod tests {
    use lovelyres_core::target::TargetIdentity;

    use super::*;

    fn scope(name: &str, generation: u64) -> BindingScope {
        BindingScope {
            binding_handle: format!("binding-{name}"),
            session_id: format!("session-{generation}"),
            connection_id: name.to_owned(),
            target: TargetGuard {
                identity: TargetIdentity::new(name).unwrap(),
                generation,
            },
        }
    }

    fn interface(name: &str, index: u32) -> NetworkInterface {
        NetworkInterface {
            name: name.to_owned(),
            index,
            mac: None,
            ips: vec!["10.0.0.1/24".to_owned()],
        }
    }

    fn packet(sequence: u64, capture_id: &str, raw: &str) -> CoreCaptureEvent {
        serde_json::from_value(serde_json::json!({
            "capture_id": capture_id,
            "sequence": sequence,
            "observed_at": "2026-08-24T00:00:00Z",
            "kind": {
                "Data": {
                    "id": usize::MAX,
                    "timestamp": "2026-08-24 00:00:00",
                    "protocol": "HTTPS",
                    "src": "10.0.0.1.443",
                    "dst": "10.0.0.2.51000",
                    "length": "42",
                    "info": raw,
                    "raw": raw
                }
            }
        }))
        .unwrap()
    }

    fn started(sequence: u64, capture_id: &str) -> CoreCaptureEvent {
        serde_json::from_value(serde_json::json!({
            "capture_id": capture_id,
            "sequence": sequence,
            "observed_at": "2026-08-24T00:00:00Z",
            "kind": { "Started": { "interface": "eth0" } }
        }))
        .unwrap()
    }

    #[test]
    fn start_input_is_exact_bounded_and_debug_hides_filter() {
        let input: PacketCaptureStartInput = serde_json::from_value(serde_json::json!({
            "filter": "tcp port 443; id",
            "packetLimit": 5000,
            "durationSeconds": 60
        }))
        .unwrap();
        assert!(input.validate().is_ok());
        assert!(!format!("{input:?}").contains("tcp port"));
        assert!(
            serde_json::from_value::<PacketCaptureStartInput>(serde_json::json!({
                "filter": null,
                "packetLimit": 1,
                "durationSeconds": 1,
                "interface": "eth0"
            }))
            .is_err()
        );
        let invalid: PacketCaptureStartInput = serde_json::from_value(serde_json::json!({
            "filter": "tcp\nport 443",
            "packetLimit": null,
            "durationSeconds": 60
        }))
        .unwrap();
        assert!(invalid.validate().is_err());
        assert!(validate_handle("11111111-1111-4111-8111-111111111111").is_ok());
        assert!(validate_handle("{11111111-1111-4111-8111-111111111111}").is_err());
        assert!(validate_handle("11111111-1111-4111-8111-11111111111A").is_err());
    }

    #[test]
    fn interface_handles_are_stable_target_scoped_and_expiring() {
        let now = Instant::now();
        let current = scope("host-a", 1);
        let stale = scope("host-a", 2);
        let mut registry = InterfaceRegistry::default();
        let first = registry
            .replace_scope(current.clone(), vec![interface("eth0", 2)], now)
            .unwrap();
        let handle = first.interfaces[0].interface_handle.clone();
        let second = registry
            .replace_scope(current.clone(), vec![interface("eth0", 2)], now)
            .unwrap();
        assert_eq!(second.interfaces[0].interface_handle, handle);
        assert!(serde_json::to_vec(&second).unwrap().len() <= MAX_INTERFACE_RESPONSE_BYTES);
        assert!(registry.resolve(&stale, &handle, now).is_err());
        assert!(
            registry
                .resolve(
                    &current,
                    &handle,
                    now + INTERFACE_TTL + Duration::from_secs(1)
                )
                .is_err()
        );
    }

    #[test]
    fn hostile_packet_is_plain_bounded_and_never_serializes_core_id() {
        let hostile = "</pre><script>steal()</script>\0";
        let mut state = LiveCaptureState::default();
        state
            .apply_event(
                "core-capture-secret",
                started(1, "core-capture-secret"),
                &[],
            )
            .unwrap();
        state
            .apply_event(
                "core-capture-secret",
                packet(2, "core-capture-secret", hostile),
                &[],
            )
            .unwrap();
        let event = state.events.back().unwrap();
        let json = serde_json::to_string(event).unwrap();
        assert!(json.contains("<script>"));
        assert!(!json.contains("core-capture-secret"));
        assert!(!json.contains(&usize::MAX.to_string()));
        assert!(!json.contains("\\u0000"));
        assert!(json.contains("textTruncated"));
    }

    #[test]
    fn event_sequence_capture_identity_and_artifacts_fail_closed() {
        let mut state = LiveCaptureState::default();
        assert!(
            state
                .apply_event("expected", packet(2, "expected", "out of order"), &[])
                .is_err()
        );
        assert!(
            state
                .apply_event("expected", packet(1, "other", "wrong capture"), &[])
                .is_err()
        );
        let artifact: CoreCaptureEvent = serde_json::from_value(serde_json::json!({
            "capture_id": "expected",
            "sequence": 1,
            "observed_at": "2026-08-24T00:00:00Z",
            "kind": {
                "ArtifactReady": {
                    "path": "/tmp/secret.pcap",
                    "sha256": "a".repeat(64)
                }
            }
        }))
        .unwrap();
        assert!(state.apply_event("expected", artifact, &[]).is_err());
    }

    #[test]
    fn journal_caps_packets_bytes_and_resets_old_cursors() {
        let mut state = LiveCaptureState::default();
        state
            .apply_event("capture", started(1, "capture"), &[])
            .unwrap();
        for sequence in 2..=(MAX_RETAINED_PACKETS as u64 + 21) {
            state
                .apply_event("capture", packet(sequence, "capture", "packet"), &[])
                .unwrap();
        }
        assert_eq!(state.retained_packets, MAX_RETAINED_PACKETS);
        assert!(state.events.len() <= MAX_RETAINED_EVENTS);
        assert!(state.event_bytes <= MAX_CAPTURE_JOURNAL_BYTES);
        assert!(state.dropped_events > 0);
        let oldest = state.events.front().unwrap().sequence();
        assert!(oldest > 1);
        assert!(1_u64.saturating_add(1) < oldest);
    }

    #[test]
    fn per_binding_operation_concurrency_is_hard_bounded_and_released() {
        let state = Arc::new(Mutex::new(OperationState::default()));
        let permits = (0..MAX_OPERATIONS_PER_BINDING)
            .map(|_| {
                OperationPermit::acquire(
                    Arc::clone(&state),
                    "binding".to_owned(),
                    "scope".to_owned(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(
            OperationPermit::acquire(Arc::clone(&state), "binding".to_owned(), "scope".to_owned(),)
                .is_err()
        );
        drop(permits);
        assert!(OperationPermit::acquire(state, "binding".to_owned(), "scope".to_owned()).is_ok());
    }

    #[test]
    fn close_binding_clears_handles_bytes_and_permits_and_revokes_late_work() {
        let now = Instant::now();
        let current = scope("host-a", 1);
        let other = scope("host-b", 1);

        let mut interfaces = InterfaceRegistry::default();
        let current_list = interfaces
            .replace_scope(current.clone(), vec![interface("eth0", 1)], now)
            .unwrap();
        interfaces
            .replace_scope(other.clone(), vec![interface("eth1", 2)], now)
            .unwrap();
        let current_interface = current_list.interfaces[0].interface_handle.clone();
        interfaces.remove_binding(&current.binding_handle);
        assert!(
            interfaces
                .resolve(&current, &current_interface, now)
                .is_err()
        );
        assert!(interfaces.total_bytes > 0);
        assert!(
            interfaces
                .entries
                .values()
                .all(|entry| entry.scope.binding_handle == other.binding_handle)
        );

        let operations = Arc::new(Mutex::new(OperationState::default()));
        let revoked_permit = OperationPermit::acquire(
            Arc::clone(&operations),
            current.binding_handle.clone(),
            current.concurrency_key(),
        )
        .unwrap();
        let other_permit = OperationPermit::acquire(
            Arc::clone(&operations),
            other.binding_handle.clone(),
            other.concurrency_key(),
        )
        .unwrap();
        operations
            .lock()
            .unwrap()
            .close_binding(&current.binding_handle);
        assert_eq!(operations.lock().unwrap().active.len(), 1);
        drop(revoked_permit);
        assert_eq!(operations.lock().unwrap().active.len(), 1);
        drop(other_permit);
        assert!(operations.lock().unwrap().active.is_empty());

        let mut captures = CaptureRegistry::default();
        let (late_handle, _) = captures.reserve(current.clone(), now).unwrap();
        let (other_handle, _) = captures.reserve(other.clone(), now).unwrap();
        assert!(
            captures
                .close_binding(&current.binding_handle, now)
                .is_empty()
        );
        assert!(!captures.slots.contains_key(&late_handle));
        assert!(captures.slots.contains_key(&other_handle));
        assert!(
            captures
                .reserve(current, now + Duration::from_secs(1))
                .is_err()
        );
        for index in 0..=MAX_CLOSED_BINDINGS {
            captures.close_binding(&format!("closed-{index}"), now);
        }
        assert!(captures.closed_bindings.len() <= MAX_CLOSED_BINDINGS);
        assert!(captures.closed_overflow_until.is_some());
        assert!(
            captures
                .ensure_binding_open(&other.binding_handle, now)
                .is_err()
        );
    }

    #[test]
    fn public_text_projection_scrubs_scope_literals_only() {
        let current = scope("secret-host", 7);
        let sensitive_literals = current.sensitive_literals();
        let projected = project_interface(
            "11111111-1111-4111-8111-111111111111".to_owned(),
            &NetworkInterface {
                name: "PASSWORD=hunter2".to_owned(),
                index: 1,
                mac: Some("https://operator:secret@example.invalid/private".to_owned()),
                ips: vec![format!("scope={}", current.session_id)],
            },
            &sensitive_literals,
        );
        // An interface label that looks like a URL with credentials in it is
        // still the label the target reported.
        assert_ne!(projected.name, REDACTED_PACKET_CAPTURE_TEXT);
        assert_eq!(
            projected.mac.as_deref(),
            Some("https://operator:secret@example.invalid/private")
        );
        // The one address embeds our own session id, so that row is scrubbed.
        assert_eq!(projected.addresses, [REDACTED_PACKET_CAPTURE_TEXT]);
        assert!(projected.text_truncated);

        let mut state = LiveCaptureState::default();
        state
            .apply_event("capture", started(1, "capture"), &sensitive_literals)
            .unwrap();
        state
            .apply_event(
                "capture",
                packet(2, "capture", &format!("binding={}", current.binding_handle)),
                &sensitive_literals,
            )
            .unwrap();
        let json = serde_json::to_string(state.events.back().unwrap()).unwrap();
        assert!(json.contains(REDACTED_PACKET_CAPTURE_TEXT));
        for literal in sensitive_literals {
            assert!(!json.contains(literal));
        }
        let info: CoreCaptureEvent = serde_json::from_value(serde_json::json!({
            "capture_id": "capture",
            "sequence": 3,
            "observed_at": "2026-08-24T00:00:01Z",
            "kind": { "Info": { "message": "token=do-not-return" } }
        }))
        .unwrap();
        state.apply_event("capture", info, &[]).unwrap();
        assert_eq!(
            serde_json::to_value(state.events.back().unwrap()).unwrap()["message"],
            "token=do-not-return"
        );
        // A capture event that quotes a password field is shown as captured.
        let (quoted, changed) =
            project_public_single_line(r#"{"password":"super-secret"}"#, 256, &[]);
        assert!(!changed);
        assert_eq!(quoted, r#"{"password":"super-secret"}"#);
        let (control, changed) = project_public_single_line("safe\0text", 64, &[]);
        assert!(changed);
        assert!(!control.contains('\0'));
    }

    #[test]
    fn production_start_uses_only_core_typed_validated_filter_boundary() {
        let source = include_str!("packet_capture_live_api.rs");
        let start = source
            .split("pub(crate) async fn start(")
            .nth(1)
            .and_then(|value| value.split("pub(crate) async fn poll(").next())
            .unwrap();
        assert!(start.contains("let request = PcapCaptureRequest"));
        assert!(start.contains("request.validate()?"));
        assert!(start.contains(".start_live(&binding, request)"));
        for forbidden in ["shell_escape", "shq(", "CommandRunner", ".execute_bound("] {
            assert!(!start.contains(forbidden));
        }
    }

    #[test]
    fn binding_debug_is_redacted_and_target_generation_is_part_of_equality() {
        let first = scope("secret-host", 1);
        let second = scope("secret-host", 2);
        assert_ne!(first, second);
        assert!(!format!("{first:?}").contains("secret-host"));
    }
}
