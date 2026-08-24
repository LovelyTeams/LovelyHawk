use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    ops::Range,
    path::PathBuf,
    sync::Arc,
};

use gpui::{
    AnyElement, ClipboardItem, Context, Entity, IntoElement, Render, SharedString, Subscription,
    UniformListScrollHandle, Window, div, prelude::*, px, uniform_list,
};
use gpui_component::{
    Disableable, Selectable, Sizable,
    button::ButtonVariants,
    input::{Input, InputEvent, InputState},
    scroll::ScrollableElement,
};
use lovelyres_core::{
    BackendServices, CoreError, CoreResult,
    events::{PacketCaptureEvent, PacketCaptureEventKind},
    packet_capture::{
        LivePacketCapture, NetworkInterface, PacketEntry, PcapCaptureRequest, PcapEvidenceReceipt,
    },
    ssh::BoundSshSession,
    target::TargetGuard,
};
use tokio::task::AbortHandle;

use crate::{app::SharedAppState, runtime::TokioBridge, theme::ThemeTokens};

const MAX_VISIBLE_PACKETS: usize = 5_000;
const MAX_CAPTURE_EVENTS_PER_FRAME: usize = 256;
const MAX_THREATS: usize = 512;
const EXPORT_PACKET_LIMIT: usize = 1_000;

#[derive(Clone, Debug, Eq, PartialEq)]
struct PacketCaptureBinding {
    connection_id: String,
    session_id: String,
    target: TargetGuard,
}

impl PacketCaptureBinding {
    fn from_session(session: &BoundSshSession) -> Self {
        Self {
            connection_id: session.connection_id().to_owned(),
            session_id: session.session_id().to_owned(),
            target: session.target().clone(),
        }
    }

    fn capture(shared: &SharedAppState) -> Option<Self> {
        shared
            .active_ssh
            .as_ref()
            .map(|active| Self::from_session(&active.session))
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum PacketCaptureTab {
    #[default]
    Live,
    Statistics,
    Threats,
}

impl PacketCaptureTab {
    const ALL: [Self; 3] = [Self::Live, Self::Statistics, Self::Threats];

    const fn label(self) -> &'static str {
        match self {
            Self::Live => "实时数据",
            Self::Statistics => "统计与会话",
            Self::Threats => "威胁线索",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CaptureLease {
    activation_generation: u64,
    request_id: u64,
    binding: PacketCaptureBinding,
    capture_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ConversationRow {
    key: String,
    endpoint_a: String,
    endpoint_b: String,
    packets: u64,
    bytes: u64,
    last_seen: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ThreatFinding {
    packet_id: usize,
    severity: &'static str,
    title: &'static str,
    detail: String,
}

#[derive(Debug, Default)]
struct PacketCaptureModel {
    active: bool,
    activation_generation: u64,
    next_request_id: u64,
    binding: Option<PacketCaptureBinding>,
    tab: PacketCaptureTab,
    interfaces: Vec<NetworkInterface>,
    selected_interface: Option<String>,
    capture_id: Option<String>,
    capturing: bool,
    stopping: bool,
    last_sequence: u64,
    packets: VecDeque<PacketEntry>,
    filtered_indices: Vec<usize>,
    search: String,
    selected_packet_id: Option<usize>,
    total_packets: u64,
    total_bytes: u64,
    protocol_counts: BTreeMap<String, u64>,
    conversations: BTreeMap<String, ConversationRow>,
    port_targets: BTreeMap<String, BTreeSet<String>>,
    threats: VecDeque<ThreatFinding>,
    info: Option<String>,
}

impl PacketCaptureModel {
    fn activate(&mut self, binding: Option<PacketCaptureBinding>) {
        self.active = true;
        self.activation_generation = self.activation_generation.saturating_add(1);
        self.binding = binding;
    }

    fn deactivate(&mut self) {
        self.active = false;
        self.activation_generation = self.activation_generation.saturating_add(1);
        self.capture_id = None;
        self.capturing = false;
        self.stopping = false;
        self.binding = None;
    }

    fn rebind(&mut self, binding: Option<PacketCaptureBinding>) {
        if self.binding == binding {
            return;
        }
        self.activation_generation = self.activation_generation.saturating_add(1);
        self.capture_id = None;
        self.capturing = false;
        self.stopping = false;
        self.binding = binding;
        self.interfaces.clear();
        self.selected_interface = None;
    }

    fn begin_request(&mut self) -> CoreResult<CaptureLease> {
        if !self.active {
            return Err(CoreError::Validation {
                subject: "packet capture",
                message: "page is inactive".to_owned(),
            });
        }
        let binding = self.binding.clone().ok_or(CoreError::NoActiveTarget)?;
        self.next_request_id = self.next_request_id.saturating_add(1);
        Ok(CaptureLease {
            activation_generation: self.activation_generation,
            request_id: self.next_request_id,
            binding,
            capture_id: None,
        })
    }

    fn accepts(&self, lease: &CaptureLease, binding: Option<&PacketCaptureBinding>) -> bool {
        self.active
            && lease.activation_generation == self.activation_generation
            && binding == Some(&lease.binding)
            && self.binding.as_ref() == Some(&lease.binding)
            && lease.request_id == self.next_request_id
            && lease
                .capture_id
                .as_ref()
                .is_none_or(|capture_id| self.capture_id.as_ref() == Some(capture_id))
    }

    fn apply_interfaces(
        &mut self,
        lease: &CaptureLease,
        binding: Option<&PacketCaptureBinding>,
        interfaces: Vec<NetworkInterface>,
    ) -> bool {
        if !self.accepts(lease, binding) {
            return false;
        }
        let previous = self.selected_interface.clone();
        self.interfaces = interfaces;
        self.selected_interface = previous
            .filter(|selected| self.interfaces.iter().any(|item| item.name == *selected))
            .or_else(|| self.interfaces.first().map(|item| item.name.clone()));
        true
    }

    fn start_capture(&mut self, lease: &CaptureLease, capture_id: String) -> Option<CaptureLease> {
        if !self.accepts(lease, Some(&lease.binding)) {
            return None;
        }
        self.clear_capture_data();
        self.capture_id = Some(capture_id.clone());
        self.capturing = true;
        self.stopping = false;
        self.last_sequence = 0;
        self.info = Some("抓包通道已建立，等待远端数据…".to_owned());
        Some(CaptureLease {
            capture_id: Some(capture_id),
            ..lease.clone()
        })
    }

    fn apply_events(
        &mut self,
        lease: &CaptureLease,
        binding: Option<&PacketCaptureBinding>,
        events: Vec<PacketCaptureEvent>,
    ) -> bool {
        if !self.accepts(lease, binding) {
            return false;
        }
        for event in events {
            if Some(event.capture_id.as_str()) != lease.capture_id.as_deref()
                || event.sequence <= self.last_sequence
            {
                continue;
            }
            self.last_sequence = event.sequence;
            match event.kind {
                PacketCaptureEventKind::Started { interface } => {
                    self.capturing = true;
                    self.info = Some(format!("正在监听 {interface}"));
                }
                PacketCaptureEventKind::Data(packet) => self.push_packet(packet),
                PacketCaptureEventKind::Info { message } => self.info = Some(message),
                PacketCaptureEventKind::Progress { packets, bytes } => {
                    self.total_packets = self.total_packets.max(packets);
                    self.total_bytes = self.total_bytes.max(bytes);
                }
                PacketCaptureEventKind::ArtifactReady { .. } => {}
                PacketCaptureEventKind::Stopped => {
                    self.capturing = false;
                    self.stopping = false;
                    self.info = Some("抓包已停止".to_owned());
                }
                PacketCaptureEventKind::Failed { message } => {
                    self.capturing = false;
                    self.stopping = false;
                    self.info = Some(format!("抓包失败：{message}"));
                }
            }
        }
        self.rebuild_filter();
        true
    }

    fn push_packet(&mut self, packet: PacketEntry) {
        self.total_packets = self.total_packets.saturating_add(1);
        self.total_bytes = self
            .total_bytes
            .saturating_add(packet.length.parse::<u64>().unwrap_or_default());
        *self
            .protocol_counts
            .entry(packet.protocol.to_ascii_uppercase())
            .or_default() += 1;
        self.update_conversation(&packet);
        self.detect_threats(&packet);
        self.packets.push_back(packet);
        while self.packets.len() > MAX_VISIBLE_PACKETS {
            if let Some(removed) = self.packets.pop_front()
                && self.selected_packet_id == Some(removed.id)
            {
                self.selected_packet_id = None;
            }
        }
    }

    fn update_conversation(&mut self, packet: &PacketEntry) {
        let source = endpoint_host(&packet.src);
        let target = endpoint_host(&packet.dst);
        if source.is_empty() || target.is_empty() {
            return;
        }
        let (endpoint_a, endpoint_b) = if source <= target {
            (source, target)
        } else {
            (target, source)
        };
        let key = format!("{endpoint_a} ↔ {endpoint_b}");
        let row = self
            .conversations
            .entry(key.clone())
            .or_insert_with(|| ConversationRow {
                key,
                endpoint_a: endpoint_a.clone(),
                endpoint_b: endpoint_b.clone(),
                packets: 0,
                bytes: 0,
                last_seen: String::new(),
            });
        row.packets = row.packets.saturating_add(1);
        row.bytes = row
            .bytes
            .saturating_add(packet.length.parse::<u64>().unwrap_or_default());
        row.last_seen.clone_from(&packet.timestamp);
    }

    fn detect_threats(&mut self, packet: &PacketEntry) {
        let source = endpoint_host(&packet.src);
        let target = endpoint_host(&packet.dst);
        let port = endpoint_port(&packet.dst);
        if let Some(port) = port
            && matches!(port, 1337 | 4444 | 5555 | 6666 | 31337)
        {
            self.add_threat(ThreatFinding {
                packet_id: packet.id,
                severity: "高危",
                title: "异常端口通信",
                detail: format!("{source} → {target}:{port}"),
            });
        }
        if packet.info.contains("Flags [S]") && !source.is_empty() && !packet.dst.is_empty() {
            let targets = self.port_targets.entry(source.clone()).or_default();
            targets.insert(packet.dst.clone());
            if targets.len() == 20 {
                self.add_threat(ThreatFinding {
                    packet_id: packet.id,
                    severity: "高危",
                    title: "疑似端口扫描",
                    detail: format!("{source} 已访问 20 个不同目标端点"),
                });
            }
        }
        if packet.protocol.eq_ignore_ascii_case("DNS") && packet.info.len() > 160 {
            self.add_threat(ThreatFinding {
                packet_id: packet.id,
                severity: "中危",
                title: "异常 DNS 负载",
                detail: "DNS 数据长度异常，建议检查隧道或数据外传".to_owned(),
            });
        }
    }

    fn add_threat(&mut self, finding: ThreatFinding) {
        if self.threats.back() == Some(&finding) {
            return;
        }
        self.threats.push_back(finding);
        while self.threats.len() > MAX_THREATS {
            self.threats.pop_front();
        }
    }

    fn clear_capture_data(&mut self) {
        self.packets.clear();
        self.filtered_indices.clear();
        self.selected_packet_id = None;
        self.total_packets = 0;
        self.total_bytes = 0;
        self.protocol_counts.clear();
        self.conversations.clear();
        self.port_targets.clear();
        self.threats.clear();
    }

    fn set_search(&mut self, search: String) {
        self.search = search;
        self.rebuild_filter();
    }

    fn rebuild_filter(&mut self) {
        let query = self.search.trim().to_ascii_lowercase();
        self.filtered_indices = self
            .packets
            .iter()
            .enumerate()
            .filter_map(|(index, packet)| {
                (query.is_empty()
                    || packet.protocol.to_ascii_lowercase().contains(&query)
                    || packet.src.to_ascii_lowercase().contains(&query)
                    || packet.dst.to_ascii_lowercase().contains(&query)
                    || packet.info.to_ascii_lowercase().contains(&query))
                .then_some(index)
            })
            .collect();
    }

    fn selected_packet(&self) -> Option<&PacketEntry> {
        let id = self.selected_packet_id?;
        self.packets.iter().find(|packet| packet.id == id)
    }

    fn top_protocols(&self) -> Vec<(String, u64)> {
        let mut rows = self
            .protocol_counts
            .iter()
            .map(|(name, count)| (name.clone(), *count))
            .collect::<Vec<_>>();
        rows.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
        rows.truncate(12);
        rows
    }

    fn top_conversations(&self) -> Vec<ConversationRow> {
        let mut rows = self.conversations.values().cloned().collect::<Vec<_>>();
        rows.sort_by(|left, right| {
            right
                .packets
                .cmp(&left.packets)
                .then_with(|| left.key.cmp(&right.key))
        });
        rows.truncate(50);
        rows
    }
}

pub struct PacketCapturePage {
    services: Arc<BackendServices>,
    tokio: Arc<TokioBridge>,
    shared: Entity<SharedAppState>,
    model: PacketCaptureModel,
    filter_input: Entity<InputState>,
    duration_input: Entity<InputState>,
    count_input: Entity<InputState>,
    search_input: Entity<InputState>,
    scroll: UniformListScrollHandle,
    live: Option<Arc<LivePacketCapture>>,
    interfaces_abort: Option<AbortHandle>,
    start_abort: Option<AbortHandle>,
    evidence_loading: bool,
    error: Option<SharedString>,
    notice: Option<SharedString>,
    _subscriptions: Vec<Subscription>,
}

impl PacketCapturePage {
    pub fn new(
        services: Arc<BackendServices>,
        tokio: Arc<TokioBridge>,
        shared: Entity<SharedAppState>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let filter_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("BPF 过滤器（可选）"));
        let duration_input = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value("60")
                .placeholder("秒")
        });
        let count_input = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value("5000")
                .placeholder("包数上限")
        });
        let search_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("搜索协议、地址或摘要…"));
        let subscriptions = vec![
            cx.observe(&shared, |page, shared, cx| {
                let binding = PacketCaptureBinding::capture(shared.read(cx));
                page.on_shared_state_changed(binding, cx);
            }),
            cx.subscribe_in(
                &search_input,
                window,
                |page, input, event: &InputEvent, _, cx| {
                    if matches!(event, InputEvent::Change) {
                        page.model.set_search(input.read(cx).value().to_string());
                        cx.notify();
                    }
                },
            ),
        ];
        Self {
            services,
            tokio,
            shared,
            model: PacketCaptureModel::default(),
            filter_input,
            duration_input,
            count_input,
            search_input,
            scroll: UniformListScrollHandle::new(),
            live: None,
            interfaces_abort: None,
            start_abort: None,
            evidence_loading: false,
            error: None,
            notice: None,
            _subscriptions: subscriptions,
        }
    }

    pub fn activate(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let binding = PacketCaptureBinding::capture(self.shared.read(cx));
        self.model.activate(binding);
        self.refresh_interfaces(cx);
        self.search_input
            .update(cx, |input, cx| input.focus(window, cx));
        cx.notify();
    }

    pub fn deactivate(&mut self, cx: &mut Context<Self>) {
        self.request_stop();
        abort_task(&mut self.interfaces_abort);
        abort_task(&mut self.start_abort);
        self.model.deactivate();
        self.live = None;
        self.evidence_loading = false;
        cx.notify();
    }

    fn current_session(&self, cx: &Context<Self>) -> Option<BoundSshSession> {
        self.shared
            .read(cx)
            .active_ssh
            .as_ref()
            .map(|active| active.session.clone())
    }

    fn current_binding(&self, cx: &Context<Self>) -> Option<PacketCaptureBinding> {
        PacketCaptureBinding::capture(self.shared.read(cx))
    }

    fn on_shared_state_changed(
        &mut self,
        binding: Option<PacketCaptureBinding>,
        cx: &mut Context<Self>,
    ) {
        if self.model.binding == binding {
            return;
        }
        self.request_stop();
        abort_task(&mut self.interfaces_abort);
        abort_task(&mut self.start_abort);
        self.live = None;
        self.model.rebind(binding);
        if self.model.active {
            self.refresh_interfaces(cx);
        }
        cx.notify();
    }

    fn prepare_request(
        &mut self,
        cx: &mut Context<Self>,
    ) -> CoreResult<(CaptureLease, BoundSshSession)> {
        let session = self.current_session(cx).ok_or(CoreError::NoActiveTarget)?;
        let lease = self.model.begin_request()?;
        Ok((lease, session))
    }

    fn refresh_interfaces(&mut self, cx: &mut Context<Self>) {
        let (lease, session) = match self.prepare_request(cx) {
            Ok(value) => value,
            Err(error) => {
                self.error = Some(format!("无法读取网卡：{error}").into());
                return;
            }
        };
        abort_task(&mut self.interfaces_abort);
        let service = self.services.packet_capture().clone();
        let task = self
            .tokio
            .spawn(async move { service.list_interfaces(&session).await });
        self.interfaces_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_interfaces(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_interfaces(
        &mut self,
        lease: CaptureLease,
        result: Result<CoreResult<Vec<NetworkInterface>>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            return;
        }
        self.interfaces_abort = None;
        match result {
            Ok(Ok(interfaces)) => {
                let _ = self
                    .model
                    .apply_interfaces(&lease, binding.as_ref(), interfaces);
                self.error = None;
            }
            Ok(Err(error)) => self.error = Some(format!("读取网卡失败：{error}").into()),
            Err(error) if error.is_cancelled() => return,
            Err(error) => self.error = Some(format!("网卡任务失败：{error}").into()),
        }
        cx.notify();
    }

    fn start_capture(&mut self, cx: &mut Context<Self>) {
        if self.model.capturing || self.start_abort.is_some() || self.evidence_loading {
            return;
        }
        let (lease, session) = match self.prepare_request(cx) {
            Ok(value) => value,
            Err(error) => {
                self.error = Some(format!("无法开始抓包：{error}").into());
                return;
            }
        };
        let Some(interface) = self.model.selected_interface.clone() else {
            self.error = Some("请先选择网卡".into());
            return;
        };
        let request = match self.capture_request(interface, cx) {
            Ok(request) => request,
            Err(error) => {
                self.error = Some(format!("抓包参数无效：{error}").into());
                return;
            }
        };
        let service = self.services.packet_capture().clone();
        let task = self
            .tokio
            .spawn(async move { service.start_live(&session, request).await });
        self.start_abort = Some(task.abort_handle());
        self.error = None;
        self.notice = Some("正在建立远端抓包通道…".into());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_start(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn capture_request(
        &self,
        interface: String,
        cx: &Context<Self>,
    ) -> CoreResult<PcapCaptureRequest> {
        let duration_seconds = self
            .duration_input
            .read(cx)
            .value()
            .trim()
            .parse::<u32>()
            .map_err(|_| CoreError::Validation {
                subject: "capture duration",
                message: "must be an integer".to_owned(),
            })?;
        let packet_limit = self
            .count_input
            .read(cx)
            .value()
            .trim()
            .parse::<u32>()
            .map_err(|_| CoreError::Validation {
                subject: "packet limit",
                message: "must be an integer".to_owned(),
            })?;
        let filter = self.filter_input.read(cx).value().trim().to_owned();
        let request = PcapCaptureRequest {
            interface,
            filter: (!filter.is_empty()).then_some(filter),
            packet_limit: (packet_limit > 0).then_some(packet_limit),
            duration_seconds,
        };
        request.validate()?;
        Ok(request)
    }

    fn finish_start(
        &mut self,
        lease: CaptureLease,
        result: Result<CoreResult<LivePacketCapture>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        self.start_abort = None;
        let binding = self.current_binding(cx);
        match result {
            Ok(Ok(live)) => {
                if !self.model.accepts(&lease, binding.as_ref()) {
                    live.request_stop();
                    return;
                }
                let live = Arc::new(live);
                let Some(stream_lease) = self
                    .model
                    .start_capture(&lease, live.capture_id().to_owned())
                else {
                    live.request_stop();
                    return;
                };
                self.live = Some(live.clone());
                self.notice = Some("抓包已开始".into());
                self.spawn_event_pump(stream_lease, live, cx);
            }
            Ok(Err(error)) => self.error = Some(format!("启动抓包失败：{error}").into()),
            Err(error) if error.is_cancelled() => return,
            Err(error) => self.error = Some(format!("启动任务失败：{error}").into()),
        }
        cx.notify();
    }

    fn spawn_event_pump(
        &self,
        lease: CaptureLease,
        live: Arc<LivePacketCapture>,
        cx: &mut Context<Self>,
    ) {
        cx.spawn(async move |page, cx| {
            loop {
                let first = match live.recv().await {
                    Ok(event) => event,
                    Err(_) => break,
                };
                let mut batch = vec![first];
                while batch.len() < MAX_CAPTURE_EVENTS_PER_FRAME {
                    match live.events().try_recv() {
                        Ok(Some(event)) => batch.push(event),
                        Ok(None) | Err(_) => break,
                    }
                }
                let stopped = batch.iter().any(|event| {
                    matches!(
                        event.kind,
                        PacketCaptureEventKind::Stopped | PacketCaptureEventKind::Failed { .. }
                    )
                });
                if cx
                    .update(|cx| {
                        if let Some(page) = page.upgrade() {
                            page.update(cx, |page, cx| {
                                page.apply_capture_events(&lease, batch, cx)
                            });
                        }
                    })
                    .is_err()
                {
                    live.request_stop();
                    break;
                }
                if stopped {
                    break;
                }
            }
        })
        .detach();
    }

    fn apply_capture_events(
        &mut self,
        lease: &CaptureLease,
        events: Vec<PacketCaptureEvent>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if self.model.apply_events(lease, binding.as_ref(), events) {
            if !self.model.capturing {
                self.live = None;
            }
            cx.notify();
        }
    }

    fn request_stop(&mut self) {
        if let Some(live) = self.live.as_ref() {
            live.request_stop();
            self.model.stopping = true;
            self.notice = Some("正在停止抓包…".into());
        }
    }

    fn request_evidence_path(&mut self, cx: &mut Context<Self>) {
        if self.model.capturing || self.evidence_loading {
            return;
        }
        let initial = self
            .services
            .store()
            .root()
            .parent()
            .map_or_else(|| self.services.store().root().to_path_buf(), PathBuf::from);
        let suggested = format!(
            "lovelyres-capture-{}.pcap",
            chrono::Utc::now().format("%Y%m%d-%H%M%S")
        );
        let receiver = cx.prompt_for_new_path(&initial, Some(&suggested));
        cx.spawn(async move |page, cx| {
            let selected = match receiver.await {
                Ok(Ok(Some(path))) => path,
                Ok(Ok(None)) => return,
                Ok(Err(error)) => {
                    let message = error.to_string();
                    let _ = cx.update(|cx| {
                        if let Some(page) = page.upgrade() {
                            page.update(cx, |page, cx| {
                                page.error = Some(format!("保存路径选择失败：{message}").into());
                                cx.notify();
                            });
                        }
                    });
                    return;
                }
                Err(error) => {
                    let message = error.to_string();
                    let _ = cx.update(|cx| {
                        if let Some(page) = page.upgrade() {
                            page.update(cx, |page, cx| {
                                page.error = Some(format!("保存路径选择已取消：{message}").into());
                                cx.notify();
                            });
                        }
                    });
                    return;
                }
            };
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.start_evidence(selected, cx));
                }
            });
        })
        .detach();
    }

    fn start_evidence(&mut self, selected: PathBuf, cx: &mut Context<Self>) {
        let (lease, session) = match self.prepare_request(cx) {
            Ok(value) => value,
            Err(error) => {
                self.error = Some(format!("无法采集证据：{error}").into());
                return;
            }
        };
        let Some(interface) = self.model.selected_interface.clone() else {
            self.error = Some("请先选择网卡".into());
            return;
        };
        let request = match self.capture_request(interface, cx) {
            Ok(request) => request,
            Err(error) => {
                self.error = Some(format!("证据采集参数无效：{error}").into());
                return;
            }
        };
        let paths = match self
            .services
            .path_guard([self.services.store().root().to_path_buf()])
        {
            Ok(paths) => paths,
            Err(error) => {
                self.error = Some(format!("无法准备本地路径保护：{error}").into());
                return;
            }
        };
        self.evidence_loading = true;
        self.error = None;
        self.notice = Some(format!("正在采集原始 PCAP 到 {}…", selected.display()).into());
        let services = self.services.clone();
        let task = self.tokio.spawn(async move {
            services
                .packet_capture()
                .capture_evidence_to_path(services.sftp(), &paths, &session, request, &selected)
                .await
        });
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_evidence(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_evidence(
        &mut self,
        lease: CaptureLease,
        result: Result<CoreResult<PcapEvidenceReceipt>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            return;
        }
        self.evidence_loading = false;
        match result {
            Ok(Ok(receipt)) => {
                let cleanup = if receipt.remote_cleanup_verified {
                    "远端临时文件已清理"
                } else {
                    "远端临时文件清理未验证"
                };
                self.notice = Some(
                    format!(
                        "PCAP 已保存并校验：{} · {} · {}",
                        receipt.local_path.display(),
                        format_bytes(receipt.size_bytes),
                        cleanup
                    )
                    .into(),
                );
                self.error = None;
            }
            Ok(Err(error)) => self.error = Some(format!("PCAP 证据采集失败：{error}").into()),
            Err(error) if error.is_cancelled() => return,
            Err(error) => self.error = Some(format!("PCAP 证据任务失败：{error}").into()),
        }
        cx.notify();
    }

    fn copy_json(&mut self, cx: &mut Context<Self>) {
        let packets = self
            .model
            .packets
            .iter()
            .rev()
            .take(EXPORT_PACKET_LIMIT)
            .cloned()
            .collect::<Vec<_>>();
        match serde_json::to_string_pretty(&packets) {
            Ok(json) => {
                cx.write_to_clipboard(ClipboardItem::new_string(json));
                self.notice = Some(format!("已复制最近 {} 条数据为 JSON", packets.len()).into());
            }
            Err(error) => self.error = Some(format!("JSON 导出失败：{error}").into()),
        }
        cx.notify();
    }

    fn copy_csv(&mut self, cx: &mut Context<Self>) {
        let mut csv = "id,timestamp,protocol,source,destination,length,info\n".to_owned();
        for packet in self.model.packets.iter().rev().take(EXPORT_PACKET_LIMIT) {
            csv.push_str(&format!(
                "{},{},{},{},{},{},{}\n",
                packet.id,
                csv_field(&packet.timestamp),
                csv_field(&packet.protocol),
                csv_field(&packet.src),
                csv_field(&packet.dst),
                csv_field(&packet.length),
                csv_field(&packet.info),
            ));
        }
        cx.write_to_clipboard(ClipboardItem::new_string(csv));
        self.notice = Some("已复制最近抓包数据为 CSV".into());
        cx.notify();
    }

    fn render_header(&mut self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let capturing = self.model.capturing;
        let stopping = self.model.stopping;
        let selected = self.model.selected_interface.clone();
        let interfaces = self.model.interfaces.clone();
        div()
            .flex()
            .flex_col()
            .gap_3()
            .rounded_lg()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .p_4()
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(
                                div()
                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                    .child("网络抓包"),
                            )
                            .child(div().text_sm().text_color(tokens.muted).child(
                                "远端 tcpdump 实时流；数据有界、目标绑定，切换主机立即作废",
                            )),
                    )
                    .child(
                        div()
                            .text_sm()
                            .text_color(if capturing {
                                tokens.success
                            } else {
                                tokens.muted
                            })
                            .child(if capturing {
                                "● 正在采集"
                            } else {
                                "○ 已停止"
                            }),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .flex_wrap()
                    .child(div().text_sm().text_color(tokens.muted).child("网卡"))
                    .children(interfaces.into_iter().map(|interface| {
                        let name = interface.name.clone();
                        let label = if interface.ips.is_empty() {
                            name.clone()
                        } else {
                            format!("{} · {}", name, interface.ips.join(", "))
                        };
                        crate::buttons::button(("pc-interface", interface.index as usize))
                            .label(label)
                            .small()
                            .selected(selected.as_deref() == Some(name.as_str()))
                            .disabled(capturing || self.evidence_loading)
                            .on_click(cx.listener(move |page, _, _, cx| {
                                page.model.selected_interface = Some(name.clone());
                                cx.notify();
                            }))
                    }))
                    .child(
                        crate::buttons::button("pc-refresh-interfaces")
                            .label("刷新网卡")
                            .small()
                            .disabled(capturing || self.evidence_loading)
                            .on_click(cx.listener(|page, _, _, cx| page.refresh_interfaces(cx))),
                    ),
            )
            .child(
                div()
                    .grid()
                    .grid_cols(12)
                    .gap_2()
                    .child(div().col_span(6).child(Input::new(&self.filter_input)))
                    .child(
                        div()
                            .col_span(2)
                            .child(Input::new(&self.duration_input).suffix("秒")),
                    )
                    .child(
                        div()
                            .col_span(2)
                            .child(Input::new(&self.count_input).suffix("包")),
                    )
                    .child(
                        div()
                            .col_span(2)
                            .flex()
                            .gap_2()
                            .child(
                                crate::buttons::button("pc-start")
                                    .label(if self.start_abort.is_some() {
                                        "启动中…"
                                    } else {
                                        "开始"
                                    })
                                    .primary()
                                    .disabled(
                                        capturing
                                            || stopping
                                            || self.start_abort.is_some()
                                            || self.evidence_loading,
                                    )
                                    .on_click(cx.listener(|page, _, _, cx| page.start_capture(cx))),
                            )
                            .child(
                                crate::buttons::button("pc-stop")
                                    .label(if stopping { "停止中…" } else { "停止" })
                                    .danger()
                                    .disabled(!capturing || stopping)
                                    .on_click(cx.listener(|page, _, _, cx| {
                                        page.request_stop();
                                        cx.notify();
                                    })),
                            ),
                    ),
            )
            .into_any_element()
    }

    fn render_tabs(&mut self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let active = self.model.tab;
        div()
            .flex()
            .items_center()
            .justify_between()
            .child(
                div()
                    .flex()
                    .gap_2()
                    .children(PacketCaptureTab::ALL.map(|tab| {
                        crate::buttons::button(("pc-tab", tab as usize))
                            .label(tab.label())
                            .small()
                            .selected(active == tab)
                            .on_click(cx.listener(move |page, _, _, cx| {
                                page.model.tab = tab;
                                cx.notify();
                            }))
                    })),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(Input::new(&self.search_input).w(px(280.0)).small())
                    .child(
                        crate::buttons::button("pc-evidence")
                            .label(if self.evidence_loading {
                                "PCAP 采集中…"
                            } else {
                                "保存 PCAP 证据"
                            })
                            .small()
                            .disabled(self.model.capturing || self.evidence_loading)
                            .on_click(cx.listener(|page, _, _, cx| page.request_evidence_path(cx))),
                    )
                    .child(
                        crate::buttons::button("pc-copy-json")
                            .label("复制 JSON")
                            .small()
                            .on_click(cx.listener(|page, _, _, cx| page.copy_json(cx))),
                    )
                    .child(
                        crate::buttons::button("pc-copy-csv")
                            .label("复制 CSV")
                            .small()
                            .on_click(cx.listener(|page, _, _, cx| page.copy_csv(cx))),
                    )
                    .child(
                        crate::buttons::button("pc-clear")
                            .label("清空")
                            .small()
                            .disabled(self.model.capturing)
                            .on_click(cx.listener(|page, _, _, cx| {
                                page.model.clear_capture_data();
                                cx.notify();
                            })),
                    )
                    .child(div().text_sm().text_color(tokens.muted).child(format!(
                        "累计 {} 包 · {} · 缓冲 {}/{}",
                        self.model.total_packets,
                        format_bytes(self.model.total_bytes),
                        self.model.packets.len(),
                        MAX_VISIBLE_PACKETS
                    ))),
            )
            .into_any_element()
    }

    fn render_live(&mut self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let row_count = self.model.filtered_indices.len();
        let scroll = self.scroll.clone();
        let detail = self.model.selected_packet().cloned();
        div()
            .flex()
            .flex_1()
            .min_h_0()
            .gap_3()
            .child(
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_w_0()
                    .min_h_0()
                    .rounded_lg()
                    .border_1()
                    .border_color(tokens.border)
                    .bg(tokens.surface)
                    .child(packet_table_header(tokens))
                    .child(
                        div()
                            .relative()
                            .flex_1()
                            .min_h_0()
                            .when(row_count == 0, |body| {
                                body.child(
                                    div()
                                        .size_full()
                                        .flex()
                                        .items_center()
                                        .justify_center()
                                        .text_color(tokens.muted)
                                        .child(if self.model.capturing {
                                            "等待数据…"
                                        } else {
                                            "开始抓包后，数据将在这里实时显示"
                                        }),
                                )
                            })
                            .when(row_count > 0, |body| {
                                body.child(
                                    uniform_list(
                                        "packet-capture-rows",
                                        row_count,
                                        cx.processor(move |page, range: Range<usize>, _, cx| {
                                            page.render_packet_rows(range, tokens, cx)
                                        }),
                                    )
                                    .size_full()
                                    .track_scroll(scroll),
                                )
                            }),
                    ),
            )
            .when_some(detail, |layout, packet| {
                layout.child(packet_detail(packet, tokens, cx))
            })
            .into_any_element()
    }

    fn render_packet_rows(
        &mut self,
        range: Range<usize>,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> Vec<AnyElement> {
        range
            .filter_map(|visible| {
                let packet = {
                    let index = *self.model.filtered_indices.get(visible)?;
                    self.model.packets.get(index)?.clone()
                };
                let selected = self.model.selected_packet_id == Some(packet.id);
                let packet_id = packet.id;
                Some(
                    div()
                        .id(("packet-row", packet.id))
                        .h(px(36.0))
                        .flex()
                        .items_center()
                        .border_b_1()
                        .border_color(tokens.border)
                        .bg(if selected {
                            tokens.surface_alt
                        } else {
                            tokens.surface
                        })
                        .hover(|row| row.bg(tokens.surface_alt))
                        .cursor_pointer()
                        .on_click(cx.listener(move |page, _, _, cx| {
                            page.model.selected_packet_id = Some(packet_id);
                            cx.notify();
                        }))
                        .child(cell(packet.id.to_string(), 64.0, tokens.muted))
                        .child(cell(packet.timestamp, 172.0, tokens.text))
                        .child(cell(packet.protocol, 84.0, tokens.accent))
                        .child(cell(packet.src, 180.0, tokens.text))
                        .child(cell(packet.dst, 180.0, tokens.text))
                        .child(cell(packet.length, 72.0, tokens.muted))
                        .child(
                            div()
                                .flex_1()
                                .min_w(px(240.0))
                                .overflow_hidden()
                                .whitespace_nowrap()
                                .text_ellipsis()
                                .text_sm()
                                .child(packet.info),
                        )
                        .into_any_element(),
                )
            })
            .collect()
    }

    fn render_statistics(&self, tokens: ThemeTokens) -> AnyElement {
        let protocols = self.model.top_protocols();
        let conversations = self.model.top_conversations();
        div()
            .flex_1()
            .min_h_0()
            .overflow_y_scrollbar()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .grid()
                    .grid_cols(4)
                    .gap_3()
                    .child(metric(
                        "累计数据包",
                        self.model.total_packets.to_string(),
                        tokens,
                    ))
                    .child(metric(
                        "估算流量",
                        format_bytes(self.model.total_bytes),
                        tokens,
                    ))
                    .child(metric(
                        "协议种类",
                        self.model.protocol_counts.len().to_string(),
                        tokens,
                    ))
                    .child(metric(
                        "会话数量",
                        self.model.conversations.len().to_string(),
                        tokens,
                    )),
            )
            .child(
                div()
                    .grid()
                    .grid_cols(2)
                    .gap_3()
                    .child(
                        section("协议分布", tokens).children(
                            protocols
                                .into_iter()
                                .map(|(protocol, count)| statistic_row(protocol, count, tokens)),
                        ),
                    )
                    .child(
                        section("Top 会话", tokens).children(conversations.into_iter().map(
                            |row| {
                                statistic_row(
                                    format!("{} ↔ {}", row.endpoint_a, row.endpoint_b),
                                    row.packets,
                                    tokens,
                                )
                            },
                        )),
                    ),
            )
            .into_any_element()
    }

    fn render_threats(&self, tokens: ThemeTokens) -> AnyElement {
        let findings = self.model.threats.iter().rev().cloned().collect::<Vec<_>>();
        section("威胁线索", tokens)
            .flex_1()
            .min_h_0()
            .overflow_y_scrollbar()
            .when(findings.is_empty(), |panel| {
                panel.child(
                    div()
                        .p_6()
                        .text_color(tokens.muted)
                        .child("当前缓冲区未发现端口扫描、异常端口或可疑 DNS 负载"),
                )
            })
            .children(findings.into_iter().map(|finding| {
                div()
                    .flex()
                    .items_start()
                    .gap_3()
                    .border_b_1()
                    .border_color(tokens.border)
                    .py_3()
                    .child(
                        div()
                            .w(px(48.0))
                            .text_sm()
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .text_color(if finding.severity == "高危" {
                                tokens.danger
                            } else {
                                tokens.warning
                            })
                            .child(finding.severity),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .child(
                                div().font_weight(gpui::FontWeight::SEMIBOLD).child(format!(
                                    "{} · 包 #{}",
                                    finding.title, finding.packet_id
                                )),
                            )
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(tokens.muted)
                                    .child(finding.detail),
                            ),
                    )
            }))
            .into_any_element()
    }
}

impl Drop for PacketCapturePage {
    fn drop(&mut self) {
        if let Some(live) = self.live.as_ref() {
            live.request_stop();
        }
    }
}

impl Render for PacketCapturePage {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens = self.shared.read(cx).theme.tokens();
        let body = match self.model.tab {
            PacketCaptureTab::Live => self.render_live(tokens, cx),
            PacketCaptureTab::Statistics => self.render_statistics(tokens),
            PacketCaptureTab::Threats => self.render_threats(tokens),
        };
        div()
            .size_full()
            .min_h_0()
            .flex()
            .flex_col()
            .gap_3()
            .text_color(tokens.text)
            .child(self.render_header(tokens, cx))
            .child(self.render_tabs(tokens, cx))
            .when_some(self.error.clone(), |root, error| {
                root.child(
                    div()
                        .rounded_md()
                        .border_1()
                        .border_color(tokens.danger)
                        .bg(tokens.surface_alt)
                        .p_3()
                        .text_color(tokens.danger)
                        .child(error),
                )
            })
            .when_some(
                self.notice
                    .clone()
                    .or_else(|| self.model.info.clone().map(Into::into)),
                |root, notice| {
                    root.child(
                        div()
                            .rounded_md()
                            .bg(tokens.surface_alt)
                            .px_3()
                            .py_2()
                            .text_sm()
                            .text_color(tokens.muted)
                            .child(notice),
                    )
                },
            )
            .child(body)
    }
}

fn packet_table_header(tokens: ThemeTokens) -> AnyElement {
    div()
        .h(px(36.0))
        .flex()
        .items_center()
        .bg(tokens.surface_alt)
        .border_b_1()
        .border_color(tokens.border)
        .font_weight(gpui::FontWeight::SEMIBOLD)
        .text_sm()
        .child(cell("#", 64.0, tokens.muted))
        .child(cell("时间", 172.0, tokens.muted))
        .child(cell("协议", 84.0, tokens.muted))
        .child(cell("源", 180.0, tokens.muted))
        .child(cell("目标", 180.0, tokens.muted))
        .child(cell("长度", 72.0, tokens.muted))
        .child(div().flex_1().min_w(px(240.0)).child("摘要"))
        .into_any_element()
}

fn cell(value: impl Into<SharedString>, width: f32, color: gpui::Rgba) -> AnyElement {
    div()
        .w(px(width))
        .px_2()
        .overflow_hidden()
        .whitespace_nowrap()
        .text_ellipsis()
        .text_sm()
        .text_color(color)
        .child(value.into())
        .into_any_element()
}

fn packet_detail(
    packet: PacketEntry,
    tokens: ThemeTokens,
    cx: &mut Context<PacketCapturePage>,
) -> AnyElement {
    let raw = packet.raw.clone();
    section(format!("包详情 · #{}", packet.id), tokens)
        .w(px(320.0))
        .min_w(px(320.0))
        .overflow_y_scrollbar()
        .child(detail_row("时间", packet.timestamp, tokens))
        .child(detail_row("协议", packet.protocol, tokens))
        .child(detail_row("源", packet.src, tokens))
        .child(detail_row("目标", packet.dst, tokens))
        .child(detail_row("长度", packet.length, tokens))
        .child(detail_row("摘要", packet.info, tokens))
        .child(detail_row("原始行", packet.raw, tokens))
        .child(
            crate::buttons::button("pc-copy-raw")
                .label("复制原始行")
                .small()
                .on_click(cx.listener(move |_, _, _, cx| {
                    cx.write_to_clipboard(ClipboardItem::new_string(raw.clone()));
                })),
        )
        .into_any_element()
}

fn section(title: impl Into<SharedString>, tokens: ThemeTokens) -> gpui::Div {
    div()
        .flex()
        .flex_col()
        .gap_2()
        .rounded_lg()
        .border_1()
        .border_color(tokens.border)
        .bg(tokens.surface)
        .p_4()
        .child(
            div()
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .child(title.into()),
        )
}

fn metric(label: &'static str, value: String, tokens: ThemeTokens) -> AnyElement {
    div()
        .rounded_lg()
        .border_1()
        .border_color(tokens.border)
        .bg(tokens.surface)
        .p_4()
        .child(div().text_sm().text_color(tokens.muted).child(label))
        .child(
            div()
                .mt_1()
                .text_lg()
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .child(value),
        )
        .into_any_element()
}

fn statistic_row(label: String, value: u64, tokens: ThemeTokens) -> AnyElement {
    div()
        .flex()
        .items_center()
        .justify_between()
        .border_b_1()
        .border_color(tokens.border)
        .py_2()
        .child(div().text_sm().child(label))
        .child(
            div()
                .text_sm()
                .text_color(tokens.muted)
                .child(value.to_string()),
        )
        .into_any_element()
}

fn detail_row(label: &'static str, value: String, tokens: ThemeTokens) -> AnyElement {
    div()
        .flex()
        .flex_col()
        .gap_1()
        .py_2()
        .border_b_1()
        .border_color(tokens.border)
        .child(div().text_xs().text_color(tokens.muted).child(label))
        .child(div().text_sm().child(value))
        .into_any_element()
}

fn endpoint_host(endpoint: &str) -> String {
    endpoint
        .rsplit_once('.')
        .filter(|(_, port)| port.parse::<u16>().is_ok())
        .map_or(endpoint, |(host, _)| host)
        .trim_matches(['[', ']'])
        .to_owned()
}

fn endpoint_port(endpoint: &str) -> Option<u16> {
    endpoint.rsplit_once('.')?.1.parse().ok()
}

fn csv_field(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn format_bytes(value: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut amount = value as f64;
    let mut unit = 0;
    while amount >= 1024.0 && unit + 1 < UNITS.len() {
        amount /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", value, UNITS[unit])
    } else {
        format!("{amount:.1} {}", UNITS[unit])
    }
}

fn abort_task(slot: &mut Option<AbortHandle>) {
    if let Some(task) = slot.take() {
        task.abort();
    }
}

#[cfg(test)]
mod tests {
    use lovelyres_core::target::TargetIdentity;

    use super::*;

    fn binding(identity: &str, generation: u64) -> PacketCaptureBinding {
        PacketCaptureBinding {
            connection_id: identity.to_owned(),
            session_id: format!("session-{generation}"),
            target: TargetGuard {
                identity: TargetIdentity::new(identity).unwrap(),
                generation,
            },
        }
    }

    fn packet(id: usize, protocol: &str, source: &str, target: &str) -> PacketEntry {
        PacketEntry {
            id,
            timestamp: "2026-08-11 10:00:00".to_owned(),
            protocol: protocol.to_owned(),
            src: source.to_owned(),
            dst: target.to_owned(),
            length: "42".to_owned(),
            info: "Flags [S], hostile <script>alert(1)</script>".to_owned(),
            raw: "hostile <script>alert(1)</script>".to_owned(),
        }
    }

    #[test]
    fn target_and_capture_lease_reject_late_events() {
        let mut model = PacketCaptureModel::default();
        let first = binding("host-a", 1);
        model.activate(Some(first.clone()));
        let lease = model.begin_request().unwrap();
        let stream = model.start_capture(&lease, "pcap-one".to_owned()).unwrap();
        model.rebind(Some(binding("host-b", 2)));
        assert!(!model.apply_events(
            &stream,
            Some(&first),
            vec![PacketCaptureEvent {
                capture_id: "pcap-one".to_owned(),
                sequence: 1,
                observed_at: chrono::Utc::now(),
                kind: PacketCaptureEventKind::Data(packet(1, "SSH", "a.22", "b.44")),
            }],
        ));
        assert!(model.packets.is_empty());
    }

    #[test]
    fn bounded_packets_remain_plain_and_filterable() {
        let mut model = PacketCaptureModel::default();
        let binding = binding("host-a", 1);
        model.activate(Some(binding.clone()));
        let lease = model.begin_request().unwrap();
        let stream = model.start_capture(&lease, "pcap-one".to_owned()).unwrap();
        let events = (1..=MAX_VISIBLE_PACKETS + 20)
            .map(|id| PacketCaptureEvent {
                capture_id: "pcap-one".to_owned(),
                sequence: id as u64,
                observed_at: chrono::Utc::now(),
                kind: PacketCaptureEventKind::Data(packet(id, "SSH", "10.0.0.1.22", "10.0.0.2.44")),
            })
            .collect();
        assert!(model.apply_events(&stream, Some(&binding), events));
        assert_eq!(model.packets.len(), MAX_VISIBLE_PACKETS);
        model.set_search("<script>".to_owned());
        assert_eq!(model.filtered_indices.len(), MAX_VISIBLE_PACKETS);
        assert!(model.packets.back().unwrap().raw.contains("<script>"));
    }

    #[test]
    fn statistics_and_threat_detection_use_typed_packet_fields() {
        let mut model = PacketCaptureModel::default();
        model.push_packet(packet(1, "TCP", "10.0.0.1.40000", "10.0.0.2.4444"));
        assert_eq!(model.protocol_counts.get("TCP"), Some(&1));
        assert_eq!(model.conversations.len(), 1);
        assert_eq!(model.threats.len(), 1);
        assert_eq!(model.threats[0].title, "异常端口通信");
    }

    #[test]
    fn csv_export_escapes_remote_quotes_and_line_breaks_as_data() {
        assert_eq!(csv_field("a\"b"), "\"a\"\"b\"");
        assert_eq!(endpoint_host("10.0.0.1.443"), "10.0.0.1");
        assert_eq!(endpoint_port("10.0.0.1.443"), Some(443));
    }
}
