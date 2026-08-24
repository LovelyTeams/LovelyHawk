use std::{ops::Range, sync::Arc};

use gpui::{
    AnyElement, ClipboardItem, Context, Corner, Entity, IntoElement, KeyDownEvent, MouseButton,
    MouseDownEvent, Pixels, Point, Render, ScrollStrategy, SharedString, Subscription,
    UniformListScrollHandle, Window, anchored, deferred, div, prelude::*, px, uniform_list,
};
use gpui_component::{
    Disableable, Selectable, Sizable,
    button::ButtonVariants,
    input::{Input, InputEvent, InputState},
    scroll::ScrollableElement,
};
use lovelyres_core::{
    BackendServices, CoreError, CoreResult,
    ai::{
        AiCompletionRequest, AiMessage, AiMessageRole, AiProviderId, AiStreamCancellation,
        AiStreamId, AiStreamRequest,
    },
    events::{AiStreamEvent, AiStreamEventKind},
    investigation::{AddAiHistory, normalize_ioc_values},
    log_analysis::{
        COMMON_LOG_FILES, CreateLogMatchRule, IocSearchQuery, IocSearchResult, JournalQuery,
        LogAnalysisResult, LogCalendarDay, LogEntry, LogFileInfo, LogMatchRule, LogQuery,
        LogRuleRemovalOutcome, LogRuleRemovalPlan, LogRuleSeverity, MultiLogQuery, MultiLogResult,
        ThreatLevel, ThreatSummary,
    },
    operations::DangerousConfirmation,
    ssh::BoundSshSession,
    target::TargetGuard,
};
use tokio::task::AbortHandle;
use uuid::Uuid;

use crate::{
    app::SharedAppState,
    interaction::{DialogError, DialogId, DialogOutcome},
    runtime::TokioBridge,
    theme::ThemeTokens,
};

const DEFAULT_PAGE_SIZE: usize = 100;
const THREAT_ANALYSIS_LINES: usize = 2_000;
const MAX_AI_LOG_BYTES: usize = 16 * 1024;
const MAX_AI_OUTPUT_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogAnalysisBinding {
    connection_id: String,
    session_id: String,
    target: TargetGuard,
}

impl LogAnalysisBinding {
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
enum LogPageTab {
    #[default]
    Viewer,
    Threat,
    Ioc,
    Rules,
}

impl LogPageTab {
    const ALL: [Self; 4] = [Self::Viewer, Self::Threat, Self::Ioc, Self::Rules];

    const fn label(self) -> &'static str {
        match self {
            Self::Viewer => "日志查看",
            Self::Threat => "威胁分析",
            Self::Ioc => "IOC 搜索",
            Self::Rules => "规则 & 导出",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum LogSource {
    File(String),
    Journal,
    Correlated(Vec<String>),
}

impl Default for LogSource {
    fn default() -> Self {
        Self::File("/var/log/auth.log".to_owned())
    }
}

impl LogSource {
    fn label(&self, journal_unit: &str) -> String {
        match self {
            Self::File(path) => path.clone(),
            Self::Journal if journal_unit.trim().is_empty() => "journalctl".to_owned(),
            Self::Journal => format!("journalctl · {}", journal_unit.trim()),
            Self::Correlated(paths) => format!("关联分析 · {} 个日志源", paths.len()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LogViewFingerprint {
    source: LogSource,
    page: usize,
    page_size: usize,
    query: String,
    journal_unit: String,
    date_filter: Option<LogCalendarDay>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum LogRequestKind {
    Files,
    Logs(LogViewFingerprint),
    Threat(LogSource),
    Multi(Vec<String>),
    Ioc(Vec<String>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LogRequestLease {
    activation_generation: u64,
    request_id: u64,
    binding: LogAnalysisBinding,
    kind: LogRequestKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LogEntryId {
    entry: LogEntry,
    occurrence: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LogContextMenuLease {
    activation_generation: u64,
    binding: LogAnalysisBinding,
    view: LogViewFingerprint,
    entry_id: LogEntryId,
}

impl LogContextMenuLease {
    fn capture(model: &LogAnalysisModel, entry_id: LogEntryId) -> Option<Self> {
        Some(Self {
            activation_generation: model.activation_generation,
            binding: model.binding.clone()?,
            view: model.view_fingerprint(),
            entry_id,
        })
    }

    fn accepts(&self, model: &LogAnalysisModel) -> bool {
        model.active
            && model.tab == LogPageTab::Viewer
            && model.activation_generation == self.activation_generation
            && model.binding.as_ref() == Some(&self.binding)
            && model.view_fingerprint() == self.view
            && model.resolve_entry(&self.entry_id).is_some()
    }
}

#[derive(Clone, Debug)]
struct LogContextMenuState {
    lease: LogContextMenuLease,
    position: Point<Pixels>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingRuleRemoval {
    activation_generation: u64,
    dialog_id: DialogId,
    plan: LogRuleRemovalPlan,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LogContextAction {
    Copy,
    ExplainAi,
}

impl LogContextAction {
    const ALL: [Self; 2] = [Self::Copy, Self::ExplainAi];

    const fn id(self) -> &'static str {
        match self {
            Self::Copy => "log-context-copy",
            Self::ExplainAi => "log-context-ai-explain",
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Copy => "复制日志原文",
            Self::ExplainAi => "AI 解释日志",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LogAiState {
    Starting,
    Streaming,
    Completed,
    Cancelled,
    Failed,
}

#[derive(Clone, Debug)]
struct LogAiExplanation {
    lease: LogContextMenuLease,
    stream_id: String,
    provider_id: String,
    provider_label: String,
    model: String,
    prompt: String,
    raw: String,
    output: String,
    state: LogAiState,
    failure: Option<SharedString>,
}

impl LogAiExplanation {
    fn accepts(&self, model: &LogAnalysisModel) -> bool {
        self.lease.accepts(model)
    }
}

enum LogAiPumpMessage {
    Started(AiStreamCancellation),
    Event(AiStreamEvent),
    Failed(String),
}

#[derive(Debug, Default)]
pub struct LogAnalysisModel {
    active: bool,
    activation_generation: u64,
    next_request_id: u64,
    binding: Option<LogAnalysisBinding>,
    tab: LogPageTab,
    source: LogSource,
    page: usize,
    page_size: usize,
    query: String,
    journal_unit: String,
    date_filter: Option<LogCalendarDay>,
    files: Vec<LogFileInfo>,
    entries: Vec<LogEntry>,
    rules: Vec<LogMatchRule>,
    rule_matches: Vec<Option<LogMatchRule>>,
    highlighted_count: usize,
    threat: Option<ThreatSummary>,
    ioc_result: Option<IocSearchResult>,
    selected_entry: Option<LogEntryId>,
    latest_files: Option<u64>,
    latest_logs: Option<u64>,
    latest_threat: Option<u64>,
    latest_multi: Option<u64>,
    latest_ioc: Option<u64>,
}

impl LogAnalysisModel {
    fn activate(&mut self, binding: Option<LogAnalysisBinding>) {
        self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
        self.active = true;
        self.rebind(binding);
    }

    fn deactivate(&mut self) {
        self.active = false;
        self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
        self.invalidate_requests();
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    fn rebind(&mut self, binding: Option<LogAnalysisBinding>) {
        if self.binding == binding {
            return;
        }
        self.binding = binding;
        self.files.clear();
        self.entries.clear();
        self.rule_matches.clear();
        self.threat = None;
        self.ioc_result = None;
        self.selected_entry = None;
        self.source = LogSource::default();
        self.page = 1;
        self.date_filter = None;
        self.invalidate_requests();
    }

    fn invalidate_requests(&mut self) {
        self.latest_files = None;
        self.latest_logs = None;
        self.latest_threat = None;
        self.latest_multi = None;
        self.latest_ioc = None;
    }

    fn view_fingerprint(&self) -> LogViewFingerprint {
        LogViewFingerprint {
            source: self.source.clone(),
            page: self.page,
            page_size: self.page_size.max(1),
            query: self.query.clone(),
            journal_unit: self.journal_unit.clone(),
            date_filter: self.date_filter,
        }
    }

    fn begin_request(
        &mut self,
        kind: LogRequestKind,
        binding: Option<LogAnalysisBinding>,
    ) -> CoreResult<LogRequestLease> {
        if !self.active {
            return Err(CoreError::Validation {
                subject: "log analysis page",
                message: "page is not active".to_owned(),
            });
        }
        self.rebind(binding);
        let binding = self.binding.clone().ok_or(CoreError::NoActiveTarget)?;
        self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
        let request_id = self.next_request_id;
        match &kind {
            LogRequestKind::Files => self.latest_files = Some(request_id),
            LogRequestKind::Logs(_) => self.latest_logs = Some(request_id),
            LogRequestKind::Threat(_) => self.latest_threat = Some(request_id),
            LogRequestKind::Multi(_) => self.latest_multi = Some(request_id),
            LogRequestKind::Ioc(_) => self.latest_ioc = Some(request_id),
        }
        Ok(LogRequestLease {
            activation_generation: self.activation_generation,
            request_id,
            binding,
            kind,
        })
    }

    fn accepts(&self, lease: &LogRequestLease, binding: Option<&LogAnalysisBinding>) -> bool {
        if !self.active
            || self.activation_generation != lease.activation_generation
            || binding != Some(&lease.binding)
        {
            return false;
        }
        let latest = match &lease.kind {
            LogRequestKind::Files => self.latest_files,
            LogRequestKind::Logs(fingerprint) => {
                if *fingerprint != self.view_fingerprint() {
                    return false;
                }
                self.latest_logs
            }
            LogRequestKind::Threat(source) => {
                if source != &self.source {
                    return false;
                }
                self.latest_threat
            }
            LogRequestKind::Multi(paths) => {
                if self.source != LogSource::Correlated(paths.clone()) {
                    return false;
                }
                self.latest_multi
            }
            LogRequestKind::Ioc(_) => self.latest_ioc,
        };
        latest == Some(lease.request_id)
    }

    fn apply_files(
        &mut self,
        lease: &LogRequestLease,
        binding: Option<&LogAnalysisBinding>,
        files: Vec<LogFileInfo>,
    ) -> bool {
        if !matches!(lease.kind, LogRequestKind::Files) || !self.accepts(lease, binding) {
            return false;
        }
        self.files = files;
        if let LogSource::File(path) = &self.source
            && !self
                .files
                .iter()
                .any(|file| file.path == *path && file.readable)
            && let Some(file) = self.files.iter().find(|file| file.readable)
        {
            self.source = LogSource::File(file.path.clone());
            self.page = 1;
            self.latest_logs = None;
        }
        self.latest_files = None;
        true
    }

    fn apply_logs(
        &mut self,
        lease: &LogRequestLease,
        binding: Option<&LogAnalysisBinding>,
        result: LogAnalysisResult,
    ) -> bool {
        if !matches!(lease.kind, LogRequestKind::Logs(_)) || !self.accepts(lease, binding) {
            return false;
        }
        self.entries = result.entries;
        self.rule_matches.clear();
        self.highlighted_count = result.highlighted_count;
        if result.threat_summary.is_some() {
            self.threat = result.threat_summary;
        }
        self.selected_entry = None;
        self.latest_logs = None;
        true
    }

    fn apply_threat(
        &mut self,
        lease: &LogRequestLease,
        binding: Option<&LogAnalysisBinding>,
        result: LogAnalysisResult,
    ) -> bool {
        if !matches!(lease.kind, LogRequestKind::Threat(_)) || !self.accepts(lease, binding) {
            return false;
        }
        self.threat = result.threat_summary;
        self.latest_threat = None;
        true
    }

    fn apply_multi(
        &mut self,
        lease: &LogRequestLease,
        binding: Option<&LogAnalysisBinding>,
        result: MultiLogResult,
    ) -> bool {
        if !matches!(lease.kind, LogRequestKind::Multi(_)) || !self.accepts(lease, binding) {
            return false;
        }
        self.entries = result.entries;
        self.rule_matches.clear();
        self.highlighted_count = self
            .entries
            .iter()
            .filter(|entry| entry.highlighted)
            .count();
        self.threat = Some(result.threat_summary);
        self.selected_entry = None;
        self.latest_multi = None;
        true
    }

    fn apply_ioc(
        &mut self,
        lease: &LogRequestLease,
        binding: Option<&LogAnalysisBinding>,
        result: IocSearchResult,
    ) -> bool {
        if !matches!(lease.kind, LogRequestKind::Ioc(_)) || !self.accepts(lease, binding) {
            return false;
        }
        self.ioc_result = Some(result);
        self.latest_ioc = None;
        true
    }

    fn set_tab(&mut self, tab: LogPageTab) {
        if self.tab != tab {
            self.tab = tab;
            self.selected_entry = None;
        }
    }

    fn set_query(&mut self, value: String) {
        if self.query != value {
            self.query = value;
            self.page = 1;
            self.selected_entry = None;
            self.latest_logs = None;
        }
    }

    fn set_journal_unit(&mut self, value: String) {
        if self.journal_unit != value {
            self.journal_unit = value;
            self.page = 1;
            self.selected_entry = None;
            self.latest_logs = None;
            self.latest_threat = None;
        }
    }

    fn set_date_filter(&mut self, date_filter: Option<LogCalendarDay>) {
        if self.date_filter != date_filter {
            self.date_filter = date_filter;
            self.page = 1;
            self.selected_entry = None;
            self.latest_logs = None;
            self.latest_threat = None;
        }
    }

    fn select_file(&mut self, path: String) {
        self.source = LogSource::File(path);
        self.page = 1;
        self.selected_entry = None;
        self.latest_logs = None;
        self.latest_threat = None;
    }

    fn select_journal(&mut self) {
        self.source = LogSource::Journal;
        self.page = 1;
        self.selected_entry = None;
        self.latest_logs = None;
        self.latest_threat = None;
    }

    fn set_page_size(&mut self, page_size: usize) {
        self.page_size = page_size;
        self.page = 1;
        self.selected_entry = None;
        self.latest_logs = None;
    }

    fn change_page(&mut self, delta: isize) {
        self.page = self.page.saturating_add_signed(delta).max(1);
        self.selected_entry = None;
        self.latest_logs = None;
    }

    fn entry_id(&self, index: usize) -> Option<LogEntryId> {
        let entry = self.entries.get(index)?.clone();
        let occurrence = self.entries[..index]
            .iter()
            .filter(|candidate| **candidate == entry)
            .count();
        Some(LogEntryId { entry, occurrence })
    }

    fn resolve_entry_index(&self, id: &LogEntryId) -> Option<usize> {
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| **entry == id.entry)
            .nth(id.occurrence)
            .map(|(index, _)| index)
    }

    fn resolve_entry(&self, id: &LogEntryId) -> Option<&LogEntry> {
        self.resolve_entry_index(id)
            .and_then(|index| self.entries.get(index))
    }

    fn select_entry(&mut self, id: LogEntryId) -> bool {
        let exists = self.resolve_entry(&id).is_some();
        self.selected_entry = exists.then_some(id);
        exists
    }

    fn selected_entry(&self) -> Option<&LogEntry> {
        self.selected_entry
            .as_ref()
            .and_then(|id| self.resolve_entry(id))
    }

    fn set_rules(&mut self, rules: Vec<LogMatchRule>, matches: Vec<Option<LogMatchRule>>) -> bool {
        if matches.len() != self.entries.len() {
            return false;
        }
        self.rules = rules;
        self.rule_matches = matches;
        true
    }

    fn rule_match(&self, index: usize) -> Option<&LogMatchRule> {
        self.rule_matches.get(index).and_then(Option::as_ref)
    }

    fn source_paths(&self) -> Vec<String> {
        let mut paths = self
            .files
            .iter()
            .filter(|file| file.readable)
            .map(|file| file.path.clone())
            .take(5)
            .collect::<Vec<_>>();
        if paths.is_empty() {
            paths = COMMON_LOG_FILES
                .iter()
                .take(5)
                .map(|(path, _)| (*path).to_owned())
                .collect();
        }
        paths.sort();
        paths.dedup();
        paths
    }

    fn export_markdown(&self) -> String {
        let mut output = format!(
            "# LovelyRes 日志审计报告\n\n- 来源：{}\n- 页码：{}\n- 日志：{} 条\n- 告警：{} 条\n",
            self.source.label(&self.journal_unit),
            self.page,
            self.entries.len(),
            self.highlighted_count
        );
        if let Some(summary) = &self.threat {
            output.push_str(&format!(
                "- 威胁等级：{}\n- 暴力破解：{}\n- 成功登录：{}\n- 提权行为：{}\n- 可疑活动：{}\n",
                threat_label(summary.threat_level),
                summary.brute_force_count,
                summary.successful_login_count,
                summary.privilege_escalation_count,
                summary.suspicious_activity_count
            ));
        }
        output.push_str("\n## 日志\n\n");
        for entry in self.entries.iter().take(2_000) {
            output.push_str(&format!(
                "- `{}` **{}** `{}` {}\n",
                entry.timestamp, entry.level, entry.service, entry.message
            ));
        }
        output
    }
}

pub struct LogAnalysisPage {
    services: Arc<BackendServices>,
    tokio: Arc<TokioBridge>,
    shared: Entity<SharedAppState>,
    model: LogAnalysisModel,
    search_input: Entity<InputState>,
    journal_unit_input: Entity<InputState>,
    date_input: Entity<InputState>,
    rule_name_input: Entity<InputState>,
    rule_pattern_input: Entity<InputState>,
    ioc_input: Entity<InputState>,
    entry_scroll: UniformListScrollHandle,
    files_abort: Option<AbortHandle>,
    logs_abort: Option<AbortHandle>,
    threat_abort: Option<AbortHandle>,
    ioc_abort: Option<AbortHandle>,
    ai_abort: Option<AbortHandle>,
    ai_cancellation: Option<AiStreamCancellation>,
    ai_last_sequence: u64,
    files_loading: bool,
    logs_loading: bool,
    threat_loading: bool,
    ioc_loading: bool,
    error: Option<SharedString>,
    notice: Option<SharedString>,
    context_menu: Option<LogContextMenuState>,
    ai_explanation: Option<LogAiExplanation>,
    pending_rule_removal: Option<PendingRuleRemoval>,
    rule_severity: LogRuleSeverity,
    _subscriptions: Vec<Subscription>,
}

impl LogAnalysisPage {
    pub fn new(
        services: Arc<BackendServices>,
        tokio: Arc<TokioBridge>,
        shared: Entity<SharedAppState>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let search_input = cx.new(|cx| InputState::new(window, cx).placeholder("搜索日志关键词…"));
        let journal_unit_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("服务单元，如 sshd"));
        let date_input = cx.new(|cx| InputState::new(window, cx).placeholder("日期 YYYY-MM-DD"));
        let rule_name_input = cx.new(|cx| InputState::new(window, cx).placeholder("规则名称"));
        let rule_pattern_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder("正则表达式，如 eval\\(|base64_decode")
        });
        let ioc_input = cx.new(|cx| {
            InputState::new(window, cx)
                .multi_line(true)
                .placeholder("每行一个 IP、域名、哈希、路径或其他 IOC")
        });
        let subscriptions = vec![
            cx.subscribe_in(
                &search_input,
                window,
                |page, input, event: &InputEvent, _, cx| {
                    if matches!(event, InputEvent::Change) {
                        page.clear_transient_surfaces();
                        page.model.set_query(input.read(cx).value().to_string());
                        cx.notify();
                    }
                },
            ),
            cx.subscribe_in(
                &journal_unit_input,
                window,
                |page, input, event: &InputEvent, _, cx| {
                    if matches!(event, InputEvent::Change) {
                        page.clear_transient_surfaces();
                        page.model
                            .set_journal_unit(input.read(cx).value().to_string());
                        cx.notify();
                    }
                },
            ),
            cx.observe(&shared, |page, _, cx| page.handle_shared_change(cx)),
        ];
        Self {
            services,
            tokio,
            shared,
            model: LogAnalysisModel {
                page_size: DEFAULT_PAGE_SIZE,
                page: 1,
                ..LogAnalysisModel::default()
            },
            search_input,
            journal_unit_input,
            date_input,
            rule_name_input,
            rule_pattern_input,
            ioc_input,
            entry_scroll: UniformListScrollHandle::new(),
            files_abort: None,
            logs_abort: None,
            threat_abort: None,
            ioc_abort: None,
            ai_abort: None,
            ai_cancellation: None,
            ai_last_sequence: 0,
            files_loading: false,
            logs_loading: false,
            threat_loading: false,
            ioc_loading: false,
            error: None,
            notice: None,
            context_menu: None,
            ai_explanation: None,
            pending_rule_removal: None,
            rule_severity: LogRuleSeverity::Medium,
            _subscriptions: subscriptions,
        }
    }

    pub fn activate(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.model
            .activate(LogAnalysisBinding::capture(self.shared.read(cx)));
        self.search_input
            .update(cx, |input, cx| input.focus(window, cx));
        self.refresh_files(cx);
        self.refresh_rules();
        self.refresh_logs(cx);
    }

    pub fn deactivate(&mut self, cx: &mut Context<Self>) {
        self.abort_all();
        self.context_menu = None;
        self.ai_explanation = None;
        self.pending_rule_removal = None;
        self.model.deactivate();
        self.files_loading = false;
        self.logs_loading = false;
        self.threat_loading = false;
        self.ioc_loading = false;
        cx.notify();
    }

    pub const fn is_active(&self) -> bool {
        self.model.is_active()
    }

    fn abort_all(&mut self) {
        for task in [
            &mut self.files_abort,
            &mut self.logs_abort,
            &mut self.threat_abort,
            &mut self.ioc_abort,
        ] {
            if let Some(abort) = task.take() {
                abort.abort();
            }
        }
        self.cancel_ai_request();
    }

    fn handle_shared_change(&mut self, cx: &mut Context<Self>) {
        if !self.model.is_active() {
            return;
        }
        let binding = self.current_binding(cx);
        if self.model.binding == binding {
            return;
        }
        self.abort_all();
        self.context_menu = None;
        self.ai_explanation = None;
        self.pending_rule_removal = None;
        self.model.rebind(binding);
        self.error = None;
        if self.model.binding.is_some() {
            self.refresh_files(cx);
            self.refresh_logs(cx);
        } else {
            self.error = Some("未连接目标，无法查询日志".into());
            cx.notify();
        }
    }

    fn current_binding(&self, cx: &Context<Self>) -> Option<LogAnalysisBinding> {
        LogAnalysisBinding::capture(self.shared.read(cx))
    }

    fn current_session(&self, cx: &Context<Self>) -> Option<BoundSshSession> {
        self.shared
            .read(cx)
            .active_ssh
            .as_ref()
            .map(|active| active.session.clone())
    }

    fn refresh_rules(&mut self) {
        match self.services.log_analysis().list_rules().and_then(|rules| {
            let matches = self
                .services
                .log_analysis()
                .match_rules(&rules, &self.model.entries)?;
            Ok((rules, matches))
        }) {
            Ok((rules, matches)) => {
                let _ = self.model.set_rules(rules, matches);
            }
            Err(error) => {
                self.error = Some(format!("自定义日志规则读取失败：{error}").into());
            }
        }
    }

    fn prepare_request(
        &mut self,
        kind: LogRequestKind,
        cx: &mut Context<Self>,
    ) -> CoreResult<(LogRequestLease, BoundSshSession)> {
        let session = self.current_session(cx).ok_or(CoreError::NoActiveTarget)?;
        let binding = Some(LogAnalysisBinding::from_session(&session));
        let lease = self.model.begin_request(kind, binding)?;
        Ok((lease, session))
    }

    fn refresh_files(&mut self, cx: &mut Context<Self>) {
        let (lease, session) = match self.prepare_request(LogRequestKind::Files, cx) {
            Ok(value) => value,
            Err(error) => {
                self.error = Some(format!("无法列出日志文件：{error}").into());
                return;
            }
        };
        abort_task(&mut self.files_abort);
        self.files_loading = true;
        let service = self.services.log_analysis().clone();
        let task = self
            .tokio
            .spawn(async move { service.list_files(&session).await });
        self.files_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_files(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_files(
        &mut self,
        lease: LogRequestLease,
        result: Result<CoreResult<Vec<LogFileInfo>>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            return;
        }
        self.files_loading = false;
        self.files_abort = None;
        match result {
            Ok(Ok(files)) => {
                let source_before = self.model.source.clone();
                let applied = self.model.apply_files(&lease, binding.as_ref(), files);
                self.error = None;
                if applied && self.model.source != source_before {
                    self.refresh_logs(cx);
                }
            }
            Ok(Err(error)) => self.error = Some(format!("日志源读取失败：{error}").into()),
            Err(error) if error.is_cancelled() => return,
            Err(error) => self.error = Some(format!("日志源任务失败：{error}").into()),
        }
        cx.notify();
    }

    fn refresh_logs(&mut self, cx: &mut Context<Self>) {
        let fingerprint = self.model.view_fingerprint();
        if matches!(fingerprint.source, LogSource::Correlated(_)) {
            return;
        }
        let (lease, session) =
            match self.prepare_request(LogRequestKind::Logs(fingerprint.clone()), cx) {
                Ok(value) => value,
                Err(error) => {
                    self.error = Some(format!("无法查询日志：{error}").into());
                    return;
                }
            };
        abort_task(&mut self.logs_abort);
        self.logs_loading = true;
        self.error = None;
        let service = self.services.log_analysis().clone();
        let task = self.tokio.spawn(async move {
            match fingerprint.source {
                LogSource::File(log_path) => {
                    service
                        .read_file(
                            &session,
                            &LogQuery {
                                log_path,
                                page: fingerprint.page,
                                page_size: fingerprint.page_size,
                                filter: non_empty(fingerprint.query),
                                date_filter: fingerprint.date_filter,
                            },
                            false,
                        )
                        .await
                }
                LogSource::Journal => {
                    service
                        .read_journal(
                            &session,
                            &JournalQuery {
                                page: fingerprint.page,
                                page_size: fingerprint.page_size,
                                unit: non_empty(fingerprint.journal_unit),
                                filter: non_empty(fingerprint.query),
                                date_filter: fingerprint.date_filter,
                            },
                            false,
                        )
                        .await
                }
                LogSource::Correlated(_) => unreachable!(),
            }
        });
        self.logs_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_logs(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_logs(
        &mut self,
        lease: LogRequestLease,
        result: Result<CoreResult<LogAnalysisResult>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            return;
        }
        self.logs_loading = false;
        self.logs_abort = None;
        match result {
            Ok(Ok(result)) => {
                let _ = self.model.apply_logs(&lease, binding.as_ref(), result);
                self.refresh_rules();
                self.error = None;
                self.entry_scroll.scroll_to_item(0, ScrollStrategy::Top);
            }
            Ok(Err(error)) => self.error = Some(format!("日志查询失败：{error}").into()),
            Err(error) if error.is_cancelled() => return,
            Err(error) => self.error = Some(format!("日志查询任务失败：{error}").into()),
        }
        cx.notify();
    }

    fn run_threat_analysis(&mut self, cx: &mut Context<Self>) {
        let source = match &self.model.source {
            LogSource::Correlated(_) => {
                self.run_multi_analysis(cx);
                return;
            }
            source => source.clone(),
        };
        let (lease, session) =
            match self.prepare_request(LogRequestKind::Threat(source.clone()), cx) {
                Ok(value) => value,
                Err(error) => {
                    self.error = Some(format!("无法启动威胁分析：{error}").into());
                    return;
                }
            };
        abort_task(&mut self.threat_abort);
        self.threat_loading = true;
        self.model.source = source.clone();
        let unit = self.model.journal_unit.clone();
        let date_filter = self.model.date_filter;
        let service = self.services.log_analysis().clone();
        let task = self.tokio.spawn(async move {
            match source {
                LogSource::File(log_path) => {
                    service
                        .read_file(
                            &session,
                            &LogQuery {
                                log_path,
                                page: 1,
                                page_size: THREAT_ANALYSIS_LINES,
                                filter: None,
                                date_filter,
                            },
                            true,
                        )
                        .await
                }
                LogSource::Journal => {
                    service
                        .read_journal(
                            &session,
                            &JournalQuery {
                                page: 1,
                                page_size: THREAT_ANALYSIS_LINES,
                                unit: non_empty(unit),
                                filter: None,
                                date_filter,
                            },
                            true,
                        )
                        .await
                }
                LogSource::Correlated(_) => unreachable!(),
            }
        });
        self.threat_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_threat(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_threat(
        &mut self,
        lease: LogRequestLease,
        result: Result<CoreResult<LogAnalysisResult>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            return;
        }
        self.threat_loading = false;
        self.threat_abort = None;
        match result {
            Ok(Ok(result)) => {
                let _ = self.model.apply_threat(&lease, binding.as_ref(), result);
                self.notice = Some("威胁分析完成".into());
                self.error = None;
            }
            Ok(Err(error)) => self.error = Some(format!("威胁分析失败：{error}").into()),
            Err(error) if error.is_cancelled() => return,
            Err(error) => self.error = Some(format!("威胁分析任务失败：{error}").into()),
        }
        cx.notify();
    }

    fn run_multi_analysis(&mut self, cx: &mut Context<Self>) {
        let paths = self.model.source_paths();
        self.model.source = LogSource::Correlated(paths.clone());
        let (lease, session) = match self.prepare_request(LogRequestKind::Multi(paths.clone()), cx)
        {
            Ok(value) => value,
            Err(error) => {
                self.error = Some(format!("无法启动关联分析：{error}").into());
                return;
            }
        };
        abort_task(&mut self.threat_abort);
        self.threat_loading = true;
        let service = self.services.log_analysis().clone();
        let task = self.tokio.spawn(async move {
            service
                .analyze_multi(
                    &session,
                    &MultiLogQuery {
                        log_paths: paths,
                        line_limit: 500,
                    },
                )
                .await
        });
        self.threat_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_multi(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_multi(
        &mut self,
        lease: LogRequestLease,
        result: Result<CoreResult<MultiLogResult>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            return;
        }
        self.threat_loading = false;
        self.threat_abort = None;
        match result {
            Ok(Ok(result)) => {
                let _ = self.model.apply_multi(&lease, binding.as_ref(), result);
                self.refresh_rules();
                self.notice = Some("多日志关联分析完成".into());
                self.error = None;
            }
            Ok(Err(error)) => self.error = Some(format!("关联分析失败：{error}").into()),
            Err(error) if error.is_cancelled() => return,
            Err(error) => self.error = Some(format!("关联分析任务失败：{error}").into()),
        }
        cx.notify();
    }

    fn run_ioc_search(&mut self, cx: &mut Context<Self>) {
        let raw = self.ioc_input.read(cx).value().to_string();
        let values = raw.split([',', '\n']);
        let indicators = match normalize_ioc_values(values) {
            Ok(values) if !values.is_empty() => values,
            Ok(_) => {
                self.error = Some("请至少输入一个 IOC".into());
                cx.notify();
                return;
            }
            Err(error) => {
                self.error = Some(format!("IOC 输入无效：{error}").into());
                cx.notify();
                return;
            }
        };
        let paths = self.model.source_paths();
        let (lease, session) =
            match self.prepare_request(LogRequestKind::Ioc(indicators.clone()), cx) {
                Ok(value) => value,
                Err(error) => {
                    self.error = Some(format!("无法启动 IOC 搜索：{error}").into());
                    return;
                }
            };
        abort_task(&mut self.ioc_abort);
        self.ioc_loading = true;
        let service = self.services.log_analysis().clone();
        let task = self.tokio.spawn(async move {
            service
                .search_iocs(
                    &session,
                    &IocSearchQuery {
                        indicators,
                        log_paths: paths,
                    },
                )
                .await
        });
        self.ioc_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_ioc(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_ioc(
        &mut self,
        lease: LogRequestLease,
        result: Result<CoreResult<IocSearchResult>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            return;
        }
        self.ioc_loading = false;
        self.ioc_abort = None;
        match result {
            Ok(Ok(result)) => {
                let total = result.total_matches;
                let _ = self.model.apply_ioc(&lease, binding.as_ref(), result);
                self.notice = Some(format!("IOC 搜索完成：{total} 处命中").into());
                self.error = None;
            }
            Ok(Err(error)) => self.error = Some(format!("IOC 搜索失败：{error}").into()),
            Err(error) if error.is_cancelled() => return,
            Err(error) => self.error = Some(format!("IOC 搜索任务失败：{error}").into()),
        }
        cx.notify();
    }

    fn select_source(&mut self, path: String, cx: &mut Context<Self>) {
        self.clear_transient_surfaces();
        self.model.select_file(path);
        self.refresh_logs(cx);
    }

    fn select_journal(&mut self, cx: &mut Context<Self>) {
        self.clear_transient_surfaces();
        self.model.select_journal();
        self.refresh_logs(cx);
    }

    fn change_page(&mut self, delta: isize, cx: &mut Context<Self>) {
        self.clear_transient_surfaces();
        self.model.change_page(delta);
        self.refresh_logs(cx);
    }

    fn set_page_size(&mut self, page_size: usize, cx: &mut Context<Self>) {
        self.clear_transient_surfaces();
        self.model.set_page_size(page_size);
        self.refresh_logs(cx);
    }

    fn apply_date_filter(&mut self, cx: &mut Context<Self>) {
        let raw = self.date_input.read(cx).value().trim().to_owned();
        let date_filter = if raw.is_empty() {
            None
        } else {
            match LogCalendarDay::parse(&raw) {
                Ok(day) => Some(day),
                Err(_) => {
                    self.error = Some("日期必须是有效的 YYYY-MM-DD，例如 2026-08-13".into());
                    cx.notify();
                    return;
                }
            }
        };
        self.clear_transient_surfaces();
        self.model.set_date_filter(date_filter);
        self.error = None;
        self.refresh_logs(cx);
    }

    fn clear_date_filter(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.date_input.update(cx, |input, cx| {
            input.set_value("", window, cx);
        });
        self.clear_transient_surfaces();
        self.model.set_date_filter(None);
        self.error = None;
        self.refresh_logs(cx);
    }

    fn select_tab(&mut self, tab: LogPageTab, cx: &mut Context<Self>) {
        if self.model.tab != tab {
            self.clear_transient_surfaces();
            self.model.set_tab(tab);
            cx.notify();
        }
    }

    fn clear_transient_surfaces(&mut self) {
        self.context_menu = None;
        self.cancel_ai_request();
        self.ai_explanation = None;
    }

    fn add_rule(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let input = CreateLogMatchRule {
            name: self.rule_name_input.read(cx).value().to_string(),
            pattern: self.rule_pattern_input.read(cx).value().to_string(),
            severity: self.rule_severity,
        };
        match self.services.log_analysis().add_rule(input) {
            Ok(rule) => {
                self.rule_name_input
                    .update(cx, |input, cx| input.set_value("", window, cx));
                self.rule_pattern_input
                    .update(cx, |input, cx| input.set_value("", window, cx));
                self.refresh_rules();
                self.notice = Some(format!("规则「{}」已添加", rule.name).into());
                self.error = None;
            }
            Err(error) => self.error = Some(format!("无法添加日志规则：{error}").into()),
        }
        cx.notify();
    }

    fn request_remove_rule(&mut self, rule_id: &str, cx: &mut Context<Self>) {
        let plan = match self.services.log_analysis().plan_remove_rule(rule_id) {
            Ok(plan) => plan,
            Err(error) => {
                self.error = Some(format!("无法创建规则删除计划：{error}").into());
                cx.notify();
                return;
            }
        };
        let dialog = self.shared.update(cx, |state, cx| {
            if state.interactions.dialogs.active().is_some() {
                return Err(DialogError::ActionTypeMismatch);
            }
            let dialog_id = state
                .interactions
                .dialogs
                .show_dangerous(plan.definition())?;
            state.interactions.focus_dialog();
            cx.notify();
            Ok(dialog_id)
        });
        match dialog {
            Ok(dialog_id) => {
                self.pending_rule_removal = Some(PendingRuleRemoval {
                    activation_generation: self.model.activation_generation,
                    dialog_id,
                    plan,
                });
            }
            Err(error) => {
                self.error = Some(format!("危险确认框无法打开：{error:?}").into());
            }
        }
        cx.notify();
    }

    pub fn handle_dialog_outcome(
        &mut self,
        outcome: &DialogOutcome,
        cx: &mut Context<Self>,
    ) -> bool {
        let Some(pending) = self.pending_rule_removal.clone() else {
            return false;
        };
        let outcome_dialog = match outcome {
            DialogOutcome::AlertDismissed { dialog_id }
            | DialogOutcome::PromptSubmitted { dialog_id, .. }
            | DialogOutcome::Cancelled { dialog_id }
            | DialogOutcome::DangerousApproved { dialog_id, .. } => *dialog_id,
        };
        if outcome_dialog != pending.dialog_id {
            return false;
        }
        self.pending_rule_removal = None;
        match outcome {
            DialogOutcome::Cancelled { .. } => {
                self.notice = Some("日志规则删除已取消".into());
                cx.notify();
                true
            }
            DialogOutcome::DangerousApproved { operation_id, .. }
                if *operation_id == pending.plan.definition().id =>
            {
                if !self.model.active
                    || self.model.activation_generation != pending.activation_generation
                {
                    self.notice = Some("页面生命周期已变化，迟到确认未执行".into());
                    cx.notify();
                    return true;
                }
                let confirmation = DangerousConfirmation::approve(pending.plan.definition());
                let service = self.services.log_analysis().clone();
                let journal = self.services.operation_journal().clone();
                let generation = pending.activation_generation;
                let task = self.tokio.spawn(async move {
                    service
                        .execute_remove_rule(pending.plan, confirmation, &journal)
                        .await
                });
                cx.spawn(async move |page, cx| {
                    let result = task.await;
                    let _ = cx.update(|cx| {
                        if let Some(page) = page.upgrade() {
                            page.update(cx, |page, cx| {
                                page.finish_rule_removal(generation, result, cx)
                            });
                        }
                    });
                })
                .detach();
                true
            }
            _ => {
                self.error = Some("规则删除确认与操作计划不匹配".into());
                cx.notify();
                true
            }
        }
    }

    fn finish_rule_removal(
        &mut self,
        generation: u64,
        result: Result<CoreResult<LogRuleRemovalOutcome>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if !self.model.active || self.model.activation_generation != generation {
            return;
        }
        match result {
            Ok(Ok(outcome)) => {
                self.refresh_rules();
                self.notice = Some(format!("规则已删除并验证：{}", outcome.removed_rule_id).into());
                self.error = None;
            }
            Ok(Err(error)) => self.error = Some(format!("规则删除失败：{error}").into()),
            Err(error) => self.error = Some(format!("规则删除任务失败：{error}").into()),
        }
        cx.notify();
    }

    fn export_report(&mut self, cx: &mut Context<Self>) {
        cx.write_to_clipboard(ClipboardItem::new_string(self.model.export_markdown()));
        self.notice = Some("日志审计报告已复制为 Markdown".into());
        cx.notify();
    }

    fn open_context_menu(
        &mut self,
        entry_id: LogEntryId,
        position: Point<Pixels>,
        cx: &mut Context<Self>,
    ) {
        if !self.model.select_entry(entry_id.clone()) {
            self.context_menu = None;
            return;
        }
        let Some(lease) = LogContextMenuLease::capture(&self.model, entry_id) else {
            self.context_menu = None;
            return;
        };
        self.context_menu = Some(LogContextMenuState { lease, position });
        cx.notify();
    }

    fn dismiss_transient_on_key_down(
        &mut self,
        event: &KeyDownEvent,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if event.keystroke.key != "escape" {
            return;
        }
        if self.context_menu.take().is_some() {
            cx.stop_propagation();
            cx.notify();
        } else if self.ai_explanation.is_some() {
            self.close_ai_explanation(cx);
            cx.stop_propagation();
        }
    }

    fn dispatch_context_action(
        &mut self,
        lease: LogContextMenuLease,
        action: LogContextAction,
        cx: &mut Context<Self>,
    ) {
        self.context_menu = None;
        if !lease.accepts(&self.model)
            || self
                .services
                .target()
                .validate(&lease.binding.target)
                .is_err()
        {
            self.notice = Some("日志视图或目标已变化，已取消右键操作".into());
            cx.notify();
            return;
        }
        let Some(entry) = self.model.resolve_entry(&lease.entry_id).cloned() else {
            self.notice = Some("所选日志已不存在，请刷新后重试".into());
            cx.notify();
            return;
        };
        match action {
            LogContextAction::Copy => {
                cx.write_to_clipboard(ClipboardItem::new_string(entry.raw));
                self.notice = Some("日志原文已复制".into());
                cx.notify();
            }
            LogContextAction::ExplainAi => self.start_ai_explanation(lease, entry, cx),
        }
    }

    fn start_ai_explanation(
        &mut self,
        lease: LogContextMenuLease,
        entry: LogEntry,
        cx: &mut Context<Self>,
    ) {
        if !lease.accepts(&self.model)
            || self
                .services
                .target()
                .validate(&lease.binding.target)
                .is_err()
        {
            self.notice = Some("目标已切换，AI 请求未发送".into());
            cx.notify();
            return;
        }
        self.cancel_ai_request();
        let settings = match self.services.settings().load() {
            Ok(settings) => settings,
            Err(error) => {
                self.notice = Some(format!("无法读取 AI 设置：{error}").into());
                cx.notify();
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
            self.notice = Some("请先在设置中配置并启用带密钥的 AI Provider".into());
            cx.notify();
            return;
        };
        let raw = truncate_utf8_bytes(&entry.raw, MAX_AI_LOG_BYTES);
        let source = self.model.source.label(&self.model.journal_unit);
        let prompt = format!("请解释这条系统日志：\n{raw}\n\n上下文信息：{source}");
        let stream_id_text = format!(
            "log:{}:{}",
            self.model.activation_generation,
            Uuid::new_v4()
        );
        let provider_id = match AiProviderId::new(provider.id.clone()) {
            Ok(provider_id) => provider_id,
            Err(error) => {
                self.notice = Some(format!("AI Provider 配置无效：{error}").into());
                cx.notify();
                return;
            }
        };
        let stream_id = match AiStreamId::new(stream_id_text.clone()) {
            Ok(stream_id) => stream_id,
            Err(error) => {
                self.notice = Some(format!("无法创建 AI 流：{error}").into());
                cx.notify();
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
                        "你是一位资深的 Linux 系统日志分析专家。解释日志事件、日志级别与严重性；对错误或警告给出可能原因和谨慎的排查建议。使用中文，保持简洁专业。只返回纯 Markdown 文本，不要返回原始 HTML。",
                    ),
                    AiMessage::new(AiMessageRole::User, prompt.clone()),
                ],
            )
            .with_max_output_tokens(1_000),
        );
        let ai = match self.services.ai() {
            Ok(ai) => ai.clone(),
            Err(error) => {
                self.notice = Some(format!("AI 服务不可用：{error}").into());
                cx.notify();
                return;
            }
        };
        self.ai_last_sequence = 0;
        self.ai_explanation = Some(LogAiExplanation {
            lease: lease.clone(),
            stream_id: stream_id_text,
            provider_id: provider.id.clone(),
            provider_label: provider.label.clone(),
            model: provider.model.clone(),
            prompt,
            raw,
            output: String::new(),
            state: LogAiState::Starting,
            failure: None,
        });
        let (sender, mut receiver) = tokio::sync::mpsc::channel(128);
        let task = self.tokio.spawn(async move {
            let mut stream = match ai.start_stream(request) {
                Ok(stream) => stream,
                Err(error) => {
                    let _ = sender
                        .send(LogAiPumpMessage::Failed(error.to_string()))
                        .await;
                    return;
                }
            };
            if sender
                .send(LogAiPumpMessage::Started(stream.cancellation()))
                .await
                .is_err()
            {
                return;
            }
            loop {
                let event = match stream.events().recv().await {
                    Ok(event) => event,
                    Err(error) => {
                        let _ = sender
                            .send(LogAiPumpMessage::Failed(error.to_string()))
                            .await;
                        return;
                    }
                };
                let terminal = matches!(
                    event.kind,
                    AiStreamEventKind::Completed
                        | AiStreamEventKind::Cancelled
                        | AiStreamEventKind::Failed { .. }
                );
                if sender.send(LogAiPumpMessage::Event(event)).await.is_err() || terminal {
                    break;
                }
            }
            if let Err(error) = stream.wait().await {
                let _ = sender
                    .send(LogAiPumpMessage::Failed(error.to_string()))
                    .await;
            }
        });
        self.ai_abort = Some(task.abort_handle());
        drop(task);
        cx.spawn(async move |page, cx| {
            while let Some(message) = receiver.recv().await {
                let keep_receiving = cx
                    .update(|cx| {
                        let Some(page) = page.upgrade() else {
                            return false;
                        };
                        page.update(cx, |page, cx| page.apply_ai_message(message, cx))
                    })
                    .unwrap_or(false);
                if !keep_receiving {
                    break;
                }
            }
        })
        .detach();
        cx.notify();
    }

    fn apply_ai_message(&mut self, message: LogAiPumpMessage, cx: &mut Context<Self>) -> bool {
        let current = self
            .ai_explanation
            .as_ref()
            .is_some_and(|explanation| explanation.accepts(&self.model))
            && self.ai_explanation.as_ref().is_some_and(|explanation| {
                self.services
                    .target()
                    .validate(&explanation.lease.binding.target)
                    .is_ok()
            });
        if !current {
            if let LogAiPumpMessage::Started(cancellation) = message {
                cancellation.cancel();
            }
            self.cancel_ai_request();
            return false;
        }
        match message {
            LogAiPumpMessage::Started(cancellation) => {
                self.ai_cancellation = Some(cancellation);
                if let Some(explanation) = self.ai_explanation.as_mut() {
                    explanation.state = LogAiState::Streaming;
                }
            }
            LogAiPumpMessage::Event(event) => {
                let Some(explanation) = self.ai_explanation.as_mut() else {
                    return false;
                };
                let expected = self.ai_last_sequence.saturating_add(1);
                if event.stream_id != explanation.stream_id || event.sequence != expected {
                    let received = event.sequence;
                    self.cancel_ai_request();
                    if let Some(explanation) = self.ai_explanation.as_mut() {
                        explanation.state = LogAiState::Failed;
                        explanation.failure =
                            Some(format!("AI 流序列错误：期望 {expected}，收到 {received}").into());
                    }
                    cx.notify();
                    return false;
                }
                self.ai_last_sequence = event.sequence;
                match event.kind {
                    AiStreamEventKind::Delta(delta) => {
                        if append_utf8_bounded(&mut explanation.output, &delta, MAX_AI_OUTPUT_BYTES)
                        {
                            explanation.state = LogAiState::Streaming;
                        } else {
                            self.cancel_ai_request();
                            if let Some(explanation) = self.ai_explanation.as_mut() {
                                explanation.state = LogAiState::Failed;
                                explanation.failure =
                                    Some("AI 输出超过 1 MiB 安全上限，已取消".into());
                            }
                            cx.notify();
                            return false;
                        }
                    }
                    AiStreamEventKind::Completed => {
                        explanation.state = LogAiState::Completed;
                        self.ai_cancellation = None;
                        self.ai_abort = None;
                        let record = AddAiHistory {
                            provider: explanation.provider_id.clone(),
                            model: explanation.model.clone(),
                            prompt: explanation.prompt.clone(),
                            result: explanation.output.clone(),
                            source: "log-explain".to_owned(),
                        };
                        if let Err(error) = self.services.investigation().ai_history().add(record) {
                            self.notice =
                                Some(format!("AI 分析完成，但历史记录失败：{error}").into());
                        }
                    }
                    AiStreamEventKind::Cancelled => {
                        explanation.state = LogAiState::Cancelled;
                        self.ai_cancellation = None;
                        self.ai_abort = None;
                    }
                    AiStreamEventKind::Failed { message } => {
                        explanation.state = LogAiState::Failed;
                        explanation.failure = Some(message.into());
                        self.ai_cancellation = None;
                        self.ai_abort = None;
                    }
                }
            }
            LogAiPumpMessage::Failed(error) => {
                if let Some(explanation) = self.ai_explanation.as_mut() {
                    explanation.state = LogAiState::Failed;
                    explanation.failure = Some(error.into());
                }
                self.ai_cancellation = None;
                self.ai_abort = None;
            }
        }
        cx.notify();
        self.ai_explanation.as_ref().is_some_and(|explanation| {
            matches!(
                explanation.state,
                LogAiState::Starting | LogAiState::Streaming
            )
        })
    }

    fn cancel_ai_request(&mut self) {
        if let Some(cancellation) = self.ai_cancellation.take() {
            cancellation.cancel();
        }
        abort_task(&mut self.ai_abort);
    }

    fn close_ai_explanation(&mut self, cx: &mut Context<Self>) {
        self.cancel_ai_request();
        self.ai_explanation = None;
        cx.notify();
    }

    fn render_header(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        div()
            .flex_none()
            .flex()
            .items_center()
            .gap_2()
            .children(LogPageTab::ALL.into_iter().map(|tab| {
                crate::buttons::button(SharedString::from(format!("log-tab-{tab:?}")))
                    .label(tab.label())
                    .selected(self.model.tab == tab)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.select_tab(tab, cx);
                    }))
            }))
            .child(
                div()
                    .ml_auto()
                    .text_xs()
                    .text_color(tokens.muted)
                    .child(self.model.source.label(&self.model.journal_unit)),
            )
            .child(
                crate::buttons::button("log-export")
                    .label("复制报告")
                    .small()
                    .on_click(cx.listener(|this, _, _, cx| this.export_report(cx))),
            )
            .into_any_element()
    }

    fn render_source_panel(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let files = self.model.files.clone();
        let selected = self.model.source.clone();
        div()
            .w(px(224.0))
            .flex_none()
            .min_h_0()
            .rounded_lg()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .p_2()
            .flex()
            .flex_col()
            .gap_1()
            .child(
                div()
                    .px_2()
                    .py_2()
                    .flex()
                    .items_center()
                    .child(
                        div()
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child("日志源"),
                    )
                    .child(
                        crate::buttons::button("refresh-log-files")
                            .label(if self.files_loading {
                                "加载中"
                            } else {
                                "刷新"
                            })
                            .small()
                            .ml_auto()
                            .disabled(self.files_loading)
                            .on_click(cx.listener(|this, _, _, cx| this.refresh_files(cx))),
                    ),
            )
            .child(
                div()
                    .id("journal-log-source")
                    .h(px(34.0))
                    .px_3()
                    .flex()
                    .items_center()
                    .rounded_md()
                    .cursor_pointer()
                    .text_sm()
                    .bg(if selected == LogSource::Journal {
                        tokens.surface_alt
                    } else {
                        tokens.surface
                    })
                    .text_color(if selected == LogSource::Journal {
                        tokens.accent
                    } else {
                        tokens.text
                    })
                    .hover(|item| item.bg(tokens.surface_alt))
                    .child("Journal")
                    .on_click(cx.listener(|this, _, _, cx| this.select_journal(cx))),
            )
            .child(
                div()
                    .mt_2()
                    .px_2()
                    .text_xs()
                    .text_color(tokens.muted)
                    .child("系统日志文件"),
            )
            .child(div().flex_1().min_h_0().overflow_y_scrollbar().children(
                files.into_iter().enumerate().map(|(index, file)| {
                    let path = file.path.clone();
                    let is_selected = selected == LogSource::File(path.clone());
                    div()
                        .id(SharedString::from(format!("log-source-{index}")))
                        .min_h(px(38.0))
                        .px_3()
                        .py_1()
                        .flex()
                        .flex_col()
                        .justify_center()
                        .rounded_md()
                        .cursor_pointer()
                        .text_sm()
                        .bg(if is_selected {
                            tokens.surface_alt
                        } else {
                            tokens.surface
                        })
                        .text_color(if file.readable {
                            if is_selected {
                                tokens.accent
                            } else {
                                tokens.text
                            }
                        } else {
                            tokens.muted
                        })
                        .hover(|item| item.bg(tokens.surface_alt))
                        .child(div().truncate().child(file.name))
                        .child(div().text_xs().text_color(tokens.muted).truncate().child(
                            if file.readable {
                                format_bytes(file.size)
                            } else {
                                "不可读/不存在".to_owned()
                            },
                        ))
                        .when(file.readable, |item| {
                            item.on_click(cx.listener(move |this, _, _, cx| {
                                this.select_source(path.clone(), cx);
                            }))
                        })
                }),
            ))
            .into_any_element()
    }

    fn render_viewer(&mut self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let count = self.model.entries.len();
        let selected = self.model.selected_entry().cloned();
        div()
            .flex_1()
            .min_h_0()
            .flex()
            .gap_3()
            .child(self.render_source_panel(tokens, cx))
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .min_h_0()
                    .rounded_lg()
                    .border_1()
                    .border_color(tokens.border)
                    .bg(tokens.surface)
                    .p_3()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(self.render_viewer_toolbar(tokens, cx))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_4()
                            .text_xs()
                            .text_color(tokens.muted)
                            .child(format!("{} 条日志", count))
                            .child(format!("{} 条告警", self.model.highlighted_count))
                            .child(format!("第 {} 页", self.model.page)),
                    )
                    .child(self.render_entries(tokens, cx)),
            )
            .children(selected.map(|entry| self.render_entry_detail(entry, tokens, cx)))
            .into_any_element()
    }

    fn render_viewer_toolbar(&self, _tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let journal = self.model.source == LogSource::Journal;
        div()
            .flex()
            .items_center()
            .gap_3()
            .child(div().w(px(300.0)).child(Input::new(&self.search_input)))
            .when(journal, |toolbar| {
                toolbar.child(
                    div()
                        .w(px(220.0))
                        .child(Input::new(&self.journal_unit_input)),
                )
            })
            .child(div().w(px(152.0)).child(Input::new(&self.date_input)))
            .child(
                crate::buttons::button("log-apply-date-filter")
                    .label("按日期")
                    .small()
                    .selected(self.model.date_filter.is_some())
                    .disabled(self.logs_loading)
                    .on_click(cx.listener(|this, _, _, cx| this.apply_date_filter(cx))),
            )
            .when(self.model.date_filter.is_some(), |toolbar| {
                toolbar.child(
                    crate::buttons::button("log-clear-date-filter")
                        .label("清除日期")
                        .small()
                        .disabled(self.logs_loading)
                        .on_click(cx.listener(|this, _, window, cx| {
                            this.clear_date_filter(window, cx);
                        })),
                )
            })
            .child(
                crate::buttons::button("refresh-logs")
                    .label(if self.logs_loading {
                        "查询中"
                    } else {
                        "查询"
                    })
                    .primary()
                    .small()
                    .disabled(self.logs_loading)
                    .on_click(cx.listener(|this, _, _, cx| this.refresh_logs(cx))),
            )
            .child(
                div()
                    .ml_auto()
                    .flex()
                    .gap_1()
                    .children([50, 100, 200, 500].into_iter().map(|size| {
                        crate::buttons::button(SharedString::from(format!("log-page-size-{size}")))
                            .label(size.to_string())
                            .small()
                            .selected(self.model.page_size == size)
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.set_page_size(size, cx);
                            }))
                    }))
                    .child(
                        crate::buttons::button("log-prev-page")
                            .label("上一页")
                            .small()
                            .disabled(self.model.page <= 1 || self.logs_loading)
                            .on_click(cx.listener(|this, _, _, cx| this.change_page(-1, cx))),
                    )
                    .child(
                        crate::buttons::button("log-next-page")
                            .label("下一页")
                            .small()
                            .disabled(
                                self.model.entries.len() < self.model.page_size
                                    || self.logs_loading,
                            )
                            .on_click(cx.listener(|this, _, _, cx| this.change_page(1, cx))),
                    ),
            )
            .into_any_element()
    }

    fn render_entries(&mut self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let count = self.model.entries.len();
        div()
            .flex_1()
            .min_h_0()
            .relative()
            .when(count == 0, |body| {
                body.child(
                    div()
                        .size_full()
                        .flex()
                        .items_center()
                        .justify_center()
                        .text_color(tokens.muted)
                        .child(if self.logs_loading {
                            "正在读取日志…"
                        } else {
                            "当前条件没有日志"
                        }),
                )
            })
            .when(count > 0, |body| {
                body.child(
                    uniform_list(
                        "log-analysis-entries",
                        count,
                        cx.processor(move |this, range: Range<usize>, _, cx| {
                            this.render_entry_rows(range, tokens, cx)
                        }),
                    )
                    .size_full()
                    .track_scroll(self.entry_scroll.clone()),
                )
            })
            .vertical_scrollbar(&self.entry_scroll)
            .into_any_element()
    }

    fn render_entry_rows(
        &mut self,
        range: Range<usize>,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> Vec<AnyElement> {
        range
            .filter_map(|index| {
                let entry = self.model.entries.get(index)?.clone();
                let rule_match = self.model.rule_match(index).cloned();
                let entry_id = self.model.entry_id(index)?;
                let right_click_id = entry_id.clone();
                let selected = self.model.selected_entry.as_ref() == Some(&entry_id);
                Some(
                    div()
                        .id(SharedString::from(format!("log-entry-{index}")))
                        .h(px(48.0))
                        .flex_none()
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
                        .child(
                            div()
                                .w(px(148.0))
                                .flex_none()
                                .px_2()
                                .text_xs()
                                .text_color(tokens.muted)
                                .truncate()
                                .child(entry.timestamp),
                        )
                        .child(
                            div()
                                .w(px(64.0))
                                .flex_none()
                                .text_xs()
                                .text_color(level_color(&entry.level, tokens))
                                .child(entry.level),
                        )
                        .child(
                            div()
                                .w(px(112.0))
                                .flex_none()
                                .px_2()
                                .text_xs()
                                .truncate()
                                .child(entry.service),
                        )
                        .children(rule_match.map(|rule| {
                            div()
                                .flex_none()
                                .max_w(px(132.0))
                                .mr_2()
                                .px_2()
                                .py_1()
                                .rounded_sm()
                                .bg(rule_severity_background(rule.severity, tokens))
                                .text_color(rule_severity_color(rule.severity, tokens))
                                .text_xs()
                                .truncate()
                                .child(format!("规则 · {}", rule.name))
                        }))
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .px_2()
                                .text_sm()
                                .when(entry.highlighted, |message| {
                                    message.text_color(tokens.warning)
                                })
                                .truncate()
                                .child(entry.message),
                        )
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.context_menu = None;
                            let _ = this.model.select_entry(entry_id.clone());
                            cx.notify();
                        }))
                        .on_mouse_down(
                            MouseButton::Right,
                            cx.listener(move |this, event: &MouseDownEvent, _, cx| {
                                this.open_context_menu(right_click_id.clone(), event.position, cx);
                            }),
                        )
                        .into_any_element(),
                )
            })
            .collect()
    }

    fn render_entry_detail(
        &self,
        entry: LogEntry,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let raw = entry.raw.clone();
        div()
            .w(px(340.0))
            .flex_none()
            .min_h_0()
            .rounded_lg()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .p_3()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex()
                    .items_center()
                    .child(
                        div()
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child("日志详情"),
                    )
                    .child(
                        crate::buttons::button("copy-log-entry")
                            .label("复制")
                            .small()
                            .ml_auto()
                            .on_click(cx.listener(move |this, _, _, cx| {
                                cx.write_to_clipboard(ClipboardItem::new_string(raw.clone()));
                                this.notice = Some("日志原文已复制".into());
                                cx.notify();
                            })),
                    ),
            )
            .child(detail_field("时间", entry.timestamp, tokens))
            .child(detail_field("等级", entry.level, tokens))
            .child(detail_field("服务", entry.service, tokens))
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scrollbar()
                    .p_3()
                    .rounded_md()
                    .bg(tokens.surface_alt)
                    .font_family("Cascadia Mono")
                    .text_xs()
                    .child(entry.raw),
            )
            .into_any_element()
    }

    fn render_context_menu(
        &mut self,
        tokens: ThemeTokens,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Option<AnyElement> {
        let state = self.context_menu.clone()?;
        if !state.lease.accepts(&self.model) {
            self.context_menu = None;
            return None;
        }
        let entry = self.model.resolve_entry(&state.lease.entry_id)?.clone();
        let title = truncate_chars(&entry.message, 56);
        let menu = div()
            .w(px(248.0))
            .p_1()
            .rounded_md()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .text_color(tokens.text)
            .occlude()
            .on_mouse_down_out(cx.listener(|this, _, _, cx| {
                this.context_menu = None;
                cx.notify();
            }))
            .child(
                div()
                    .px_3()
                    .py_2()
                    .text_xs()
                    .text_color(tokens.muted)
                    .truncate()
                    .child(title),
            )
            .children(LogContextAction::ALL.into_iter().map(|action| {
                let lease = state.lease.clone();
                crate::buttons::button(action.id())
                    .label(action.label())
                    .w_full()
                    .justify_start()
                    .ghost()
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.dispatch_context_action(lease.clone(), action, cx);
                    }))
            }));
        let window_size = window.bounds().size;
        Some(
            deferred(
                anchored().child(
                    div()
                        .w(window_size.width)
                        .h(window_size.height)
                        .occlude()
                        .child(
                            anchored()
                                .position(state.position)
                                .snap_to_window_with_margin(px(8.0))
                                .anchor(Corner::TopLeft)
                                .child(menu),
                        ),
                ),
            )
            .with_priority(2)
            .into_any_element(),
        )
    }

    fn render_ai_explanation(
        &mut self,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> Option<AnyElement> {
        if self
            .ai_explanation
            .as_ref()
            .is_some_and(|explanation| !explanation.accepts(&self.model))
        {
            self.cancel_ai_request();
            self.ai_explanation = None;
            return None;
        }
        let explanation = self.ai_explanation.clone()?;
        let output = if explanation.output.is_empty() {
            vec![SharedString::from(match explanation.state {
                LogAiState::Starting => "正在建立 AI 流…",
                LogAiState::Streaming => "正在分析日志…",
                LogAiState::Completed => "AI 未返回文本",
                LogAiState::Cancelled => "分析已取消",
                LogAiState::Failed => "分析失败",
            })]
        } else {
            explanation
                .output
                .lines()
                .map(|line| SharedString::from(if line.is_empty() { " " } else { line }.to_owned()))
                .collect::<Vec<_>>()
        };
        let running = matches!(
            explanation.state,
            LogAiState::Starting | LogAiState::Streaming
        );
        let state_label = match explanation.state {
            LogAiState::Starting => "正在连接",
            LogAiState::Streaming => "流式分析中",
            LogAiState::Completed => "分析完成",
            LogAiState::Cancelled => "已取消",
            LogAiState::Failed => "分析失败",
        };
        let copy_output = explanation.output.clone();
        Some(
            div()
                .id("log-ai-explanation-backdrop")
                .absolute()
                .inset_0()
                .flex()
                .items_center()
                .justify_center()
                .p_5()
                .bg(gpui::rgba(0x00000088))
                .on_click(cx.listener(|this, _, _, cx| this.close_ai_explanation(cx)))
                .child(
                    div()
                        .id("log-ai-explanation-panel")
                        .on_click(|_, _, cx| cx.stop_propagation())
                        .w(px(880.0))
                        .max_w_full()
                        .h(px(640.0))
                        .max_h_full()
                        .rounded_lg()
                        .border_1()
                        .border_color(tokens.border)
                        .bg(tokens.surface)
                        .text_color(tokens.text)
                        .p_5()
                        .flex()
                        .flex_col()
                        .gap_4()
                        .child(
                            div()
                                .flex()
                                .items_start()
                                .gap_3()
                                .child(
                                    div()
                                        .flex_1()
                                        .min_w_0()
                                        .child(
                                            div()
                                                .text_xl()
                                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                                .child("AI 日志解释"),
                                        )
                                        .child(
                                            div().mt_1().text_xs().text_color(tokens.muted).child(
                                                format!(
                                                    "{} · {} · 安全纯文本预览",
                                                    explanation.provider_label, state_label
                                                ),
                                            ),
                                        ),
                                )
                                .child(
                                    crate::buttons::button("log-ai-copy-result")
                                        .label("复制解释")
                                        .small()
                                        .disabled(copy_output.is_empty())
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            cx.write_to_clipboard(ClipboardItem::new_string(
                                                copy_output.clone(),
                                            ));
                                            this.notice = Some("AI 解释已复制".into());
                                            cx.notify();
                                        })),
                                )
                                .child(
                                    (if running {
                                        crate::buttons::button("log-ai-cancel").label("取消分析")
                                    } else {
                                        crate::buttons::close_button("log-ai-close")
                                    })
                                    .small()
                                    .on_click(cx.listener(
                                        |this, _, _, cx| {
                                            this.close_ai_explanation(cx);
                                        },
                                    )),
                                ),
                        )
                        .child(
                            div()
                                .flex_none()
                                .max_h(px(132.0))
                                .overflow_y_scrollbar()
                                .rounded_md()
                                .bg(tokens.surface_alt)
                                .p_3()
                                .font_family("Cascadia Mono")
                                .text_xs()
                                .whitespace_normal()
                                .child(explanation.raw),
                        )
                        .children(explanation.failure.map(|failure| {
                            div()
                                .flex_none()
                                .rounded_md()
                                .border_1()
                                .border_color(tokens.danger)
                                .p_3()
                                .text_sm()
                                .text_color(tokens.danger)
                                .child(failure)
                        }))
                        .child(
                            div()
                                .flex_1()
                                .min_h_0()
                                .overflow_y_scrollbar()
                                .rounded_md()
                                .border_1()
                                .border_color(tokens.border)
                                .p_4()
                                .text_sm()
                                .children(output.into_iter().map(|line| {
                                    div().min_h(px(20.0)).whitespace_normal().child(line)
                                })),
                        ),
                )
                .into_any_element(),
        )
    }

    fn render_threat(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let summary = self.model.threat.clone();
        div()
            .flex_1()
            .min_h_0()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(
                        crate::buttons::button("run-log-threat-analysis")
                            .label(if self.threat_loading {
                                "分析中…"
                            } else {
                                "分析当前日志源"
                            })
                            .primary()
                            .disabled(self.threat_loading)
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.run_threat_analysis(cx);
                            })),
                    )
                    .child(
                        crate::buttons::button("run-multi-log-analysis")
                            .label("多日志关联分析")
                            .disabled(self.threat_loading)
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.run_multi_analysis(cx);
                            })),
                    )
                    .child(
                        div()
                            .ml_auto()
                            .text_xs()
                            .text_color(tokens.muted)
                            .child("最多分析 2,000 行/源；所有远端文本均按纯文本处理"),
                    ),
            )
            .children(summary.map(|summary| self.render_threat_summary(summary, tokens)))
            .when(self.model.threat.is_none(), |body| {
                body.child(
                    div()
                        .flex_1()
                        .rounded_lg()
                        .border_1()
                        .border_color(tokens.border)
                        .bg(tokens.surface)
                        .flex()
                        .items_center()
                        .justify_center()
                        .text_color(tokens.muted)
                        .child("选择分析方式后显示威胁摘要"),
                )
            })
            .into_any_element()
    }

    fn render_threat_summary(&self, summary: ThreatSummary, tokens: ThemeTokens) -> AnyElement {
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
                    .grid_cols(5)
                    .gap_3()
                    .child(metric_card(
                        "威胁等级",
                        threat_label(summary.threat_level),
                        tokens,
                    ))
                    .child(metric_card(
                        "暴力破解",
                        summary.brute_force_count.to_string(),
                        tokens,
                    ))
                    .child(metric_card(
                        "成功登录",
                        summary.successful_login_count.to_string(),
                        tokens,
                    ))
                    .child(metric_card(
                        "提权行为",
                        summary.privilege_escalation_count.to_string(),
                        tokens,
                    ))
                    .child(metric_card(
                        "可疑活动",
                        summary.suspicious_activity_count.to_string(),
                        tokens,
                    )),
            )
            .child(
                div()
                    .grid()
                    .grid_cols(2)
                    .gap_3()
                    .child(threat_list(
                        "Top 来源 IP",
                        summary
                            .top_source_ips
                            .into_iter()
                            .map(|item| format!("{} · {} 次", item.ip, item.count))
                            .collect(),
                        tokens,
                    ))
                    .child(threat_list(
                        "Top 目标用户",
                        summary
                            .top_target_users
                            .into_iter()
                            .map(|item| {
                                format!(
                                    "{} · 成功 {} / 失败 {}",
                                    item.username, item.success_count, item.fail_count
                                )
                            })
                            .collect(),
                        tokens,
                    )),
            )
            .into_any_element()
    }

    fn render_ioc(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let result = self.model.ioc_result.clone();
        div()
            .flex_1()
            .min_h_0()
            .grid()
            .grid_cols(2)
            .gap_3()
            .child(
                div()
                    .rounded_lg()
                    .border_1()
                    .border_color(tokens.border)
                    .bg(tokens.surface)
                    .p_4()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(
                        div()
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child("IOC 批量搜索"),
                    )
                    .child(
                        div()
                            .text_sm()
                            .text_color(tokens.muted)
                            .child("输入 IP、域名、哈希、路径或其他指标，在已选日志中批量搜索。"),
                    )
                    .child(div().h(px(220.0)).child(Input::new(&self.ioc_input)))
                    .child(
                        crate::buttons::button("search-log-ioc")
                            .label(if self.ioc_loading {
                                "搜索中…"
                            } else {
                                "搜索"
                            })
                            .primary()
                            .disabled(self.ioc_loading)
                            .on_click(cx.listener(|this, _, _, cx| this.run_ioc_search(cx))),
                    ),
            )
            .child(
                div()
                    .min_h_0()
                    .rounded_lg()
                    .border_1()
                    .border_color(tokens.border)
                    .bg(tokens.surface)
                    .p_4()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(div().font_weight(gpui::FontWeight::SEMIBOLD).child(
                        result.as_ref().map_or_else(
                            || "搜索结果".to_owned(),
                            |result| format!("搜索结果 · {} 处命中", result.total_matches),
                        ),
                    ))
                    .child(
                        div()
                            .flex_1()
                            .min_h_0()
                            .overflow_y_scrollbar()
                            .when(result.is_none(), |body| {
                                body.child(
                                    div()
                                        .size_full()
                                        .flex()
                                        .items_center()
                                        .justify_center()
                                        .text_color(tokens.muted)
                                        .child("搜索结果将显示在这里"),
                                )
                            })
                            .children(result.into_iter().flat_map(|result| result.results).map(
                                |item| {
                                    div()
                                        .mb_2()
                                        .p_3()
                                        .rounded_md()
                                        .bg(tokens.surface_alt)
                                        .child(
                                            div()
                                                .flex()
                                                .items_center()
                                                .child(
                                                    div()
                                                        .font_weight(gpui::FontWeight::SEMIBOLD)
                                                        .child(item.indicator),
                                                )
                                                .child(
                                                    div()
                                                        .ml_auto()
                                                        .text_color(tokens.warning)
                                                        .child(format!("{} 次", item.count)),
                                                ),
                                        )
                                        .child(
                                            div()
                                                .text_xs()
                                                .text_color(tokens.muted)
                                                .child(item.log_file),
                                        )
                                        .children(item.sample_lines.into_iter().map(|line| {
                                            div()
                                                .mt_1()
                                                .font_family("Cascadia Mono")
                                                .text_xs()
                                                .text_color(tokens.text)
                                                .child(line)
                                        }))
                                },
                            )),
                    ),
            )
            .into_any_element()
    }

    fn render_rules(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let rules = self.model.rules.clone();
        let selected_severity = self.rule_severity;
        div()
            .flex_1()
            .min_h_0()
            .grid()
            .grid_cols(2)
            .gap_3()
            .child(
                div()
                    .min_h_0()
                    .rounded_lg()
                    .border_1()
                    .border_color(tokens.border)
                    .bg(tokens.surface)
                    .p_4()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(
                        div()
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child("新增匹配规则"),
                    )
                    .child(
                        div()
                            .text_sm()
                            .text_color(tokens.muted)
                            .child("规则保存在便携 data 目录；同一日志只采用首个匹配规则。"),
                    )
                    .child(
                        div()
                            .child(
                                div()
                                    .mb_1()
                                    .text_xs()
                                    .text_color(tokens.muted)
                                    .child("规则名称"),
                            )
                            .child(Input::new(&self.rule_name_input)),
                    )
                    .child(
                        div()
                            .child(
                                div()
                                    .mb_1()
                                    .text_xs()
                                    .text_color(tokens.muted)
                                    .child("正则表达式"),
                            )
                            .child(Input::new(&self.rule_pattern_input)),
                    )
                    .child(
                        div()
                            .child(
                                div()
                                    .mb_1()
                                    .text_xs()
                                    .text_color(tokens.muted)
                                    .child("严重级别"),
                            )
                            .child(
                                div().flex().flex_wrap().gap_2().children(
                                    [
                                        LogRuleSeverity::Low,
                                        LogRuleSeverity::Medium,
                                        LogRuleSeverity::High,
                                        LogRuleSeverity::Critical,
                                    ]
                                    .into_iter()
                                    .map(|severity| {
                                        crate::buttons::button(SharedString::from(format!(
                                            "log-rule-severity-{severity:?}"
                                        )))
                                        .label(rule_severity_label(severity))
                                        .small()
                                        .selected(selected_severity == severity)
                                        .on_click(
                                            cx.listener(move |this, _, _, cx| {
                                                this.rule_severity = severity;
                                                cx.notify();
                                            }),
                                        )
                                    }),
                                ),
                            ),
                    )
                    .child(
                        crate::buttons::button("log-rule-add")
                            .label("添加规则")
                            .primary()
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.add_rule(window, cx);
                            })),
                    )
                    .child(
                        div()
                            .mt_auto()
                            .pt_3()
                            .border_t_1()
                            .border_color(tokens.border)
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(tokens.muted)
                                    .child("导出内容包含当前日志、威胁摘要和数据源信息。"),
                            )
                            .child(
                                crate::buttons::button("log-rule-export-report")
                                    .label("复制当前报告")
                                    .mt_2()
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.export_report(cx);
                                    })),
                            ),
                    ),
            )
            .child(
                div()
                    .min_h_0()
                    .rounded_lg()
                    .border_1()
                    .border_color(tokens.border)
                    .bg(tokens.surface)
                    .p_4()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .child(
                                div()
                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                    .child(format!("已保存规则 · {}", rules.len())),
                            )
                            .child(
                                crate::buttons::button("log-rule-refresh")
                                    .label("刷新")
                                    .small()
                                    .ml_auto()
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.refresh_rules();
                                        cx.notify();
                                    })),
                            ),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_h_0()
                            .overflow_y_scrollbar()
                            .when(rules.is_empty(), |body| {
                                body.child(
                                    div()
                                        .size_full()
                                        .flex()
                                        .items_center()
                                        .justify_center()
                                        .text_color(tokens.muted)
                                        .child("尚未添加自定义规则"),
                                )
                            })
                            .children(rules.into_iter().map(|rule| {
                                let rule_id = rule.id.clone();
                                let severity = rule.severity;
                                div()
                                    .mb_2()
                                    .p_3()
                                    .rounded_md()
                                    .border_1()
                                    .border_color(tokens.border)
                                    .bg(tokens.surface_alt)
                                    .child(
                                        div()
                                            .flex()
                                            .items_center()
                                            .gap_2()
                                            .child(
                                                div()
                                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                                    .child(rule.name),
                                            )
                                            .child(
                                                div()
                                                    .px_2()
                                                    .py_1()
                                                    .rounded_md()
                                                    .text_xs()
                                                    .bg(rule_severity_background(severity, tokens))
                                                    .text_color(rule_severity_color(
                                                        severity, tokens,
                                                    ))
                                                    .child(rule_severity_label(severity)),
                                            )
                                            .child(
                                                crate::buttons::button(SharedString::from(
                                                    format!("log-rule-delete-{rule_id}"),
                                                ))
                                                .label("删除")
                                                .small()
                                                .danger()
                                                .ml_auto()
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.request_remove_rule(&rule_id, cx);
                                                })),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .mt_2()
                                            .font_family("Cascadia Mono")
                                            .text_xs()
                                            .text_color(tokens.text)
                                            .whitespace_normal()
                                            .child(rule.pattern),
                                    )
                            })),
                    ),
            )
            .into_any_element()
    }
}

impl Render for LogAnalysisPage {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens = self.shared.read(cx).theme.tokens();
        let context_menu = self.render_context_menu(tokens, window, cx);
        let ai_explanation = self.render_ai_explanation(tokens, cx);
        div()
            .size_full()
            .min_h_0()
            .relative()
            .flex()
            .flex_col()
            .gap_3()
            .text_color(tokens.text)
            .on_key_down(cx.listener(Self::dismiss_transient_on_key_down))
            .child(self.render_header(tokens, cx))
            .children(self.error.clone().map(|error| {
                div()
                    .flex_none()
                    .px_3()
                    .py_2()
                    .rounded_md()
                    .border_1()
                    .border_color(tokens.danger)
                    .text_color(tokens.danger)
                    .child(error)
            }))
            .children(self.notice.clone().map(|notice| {
                div()
                    .flex_none()
                    .px_3()
                    .py_2()
                    .rounded_md()
                    .border_1()
                    .border_color(tokens.success)
                    .text_color(tokens.success)
                    .child(notice)
            }))
            .child(match self.model.tab {
                LogPageTab::Viewer => self.render_viewer(tokens, cx),
                LogPageTab::Threat => self.render_threat(tokens, cx),
                LogPageTab::Ioc => self.render_ioc(tokens, cx),
                LogPageTab::Rules => self.render_rules(tokens, cx),
            })
            .children(ai_explanation)
            .children(context_menu)
    }
}

fn abort_task(task: &mut Option<AbortHandle>) {
    if let Some(abort) = task.take() {
        abort.abort();
    }
}

fn non_empty(value: String) -> Option<String> {
    (!value.trim().is_empty()).then_some(value)
}

fn truncate_chars(value: &str, maximum: usize) -> String {
    let mut chars = value.chars();
    let mut value = chars.by_ref().take(maximum).collect::<String>();
    if chars.next().is_some() {
        value.push('…');
    }
    value
}

fn truncate_utf8_bytes(value: &str, maximum: usize) -> String {
    if value.len() <= maximum {
        return value.to_owned();
    }
    let mut boundary = maximum;
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    let mut truncated = value[..boundary].to_owned();
    truncated.push('…');
    truncated
}

fn append_utf8_bounded(output: &mut String, delta: &str, maximum: usize) -> bool {
    if output.len().saturating_add(delta.len()) > maximum {
        return false;
    }
    output.push_str(delta);
    true
}

fn threat_label(level: ThreatLevel) -> &'static str {
    match level {
        ThreatLevel::None => "无",
        ThreatLevel::Low => "低",
        ThreatLevel::Medium => "中",
        ThreatLevel::High => "高",
        ThreatLevel::Critical => "严重",
    }
}

fn rule_severity_label(severity: LogRuleSeverity) -> &'static str {
    match severity {
        LogRuleSeverity::Low => "低",
        LogRuleSeverity::Medium => "中",
        LogRuleSeverity::High => "高",
        LogRuleSeverity::Critical => "严重",
    }
}

fn rule_severity_color(severity: LogRuleSeverity, tokens: ThemeTokens) -> gpui::Rgba {
    match severity {
        LogRuleSeverity::Low => tokens.success,
        LogRuleSeverity::Medium => tokens.warning,
        LogRuleSeverity::High | LogRuleSeverity::Critical => tokens.danger,
    }
}

fn rule_severity_background(_severity: LogRuleSeverity, tokens: ThemeTokens) -> gpui::Rgba {
    tokens.surface
}

fn level_color(level: &str, tokens: ThemeTokens) -> gpui::Rgba {
    let level = level.to_ascii_uppercase();
    if level.contains("ERROR") || level.contains("FAIL") {
        tokens.danger
    } else if level.contains("WARN") {
        tokens.warning
    } else if level.contains("DEBUG") {
        tokens.muted
    } else {
        tokens.success
    }
}

fn detail_field(label: &'static str, value: String, tokens: ThemeTokens) -> AnyElement {
    div()
        .child(div().text_xs().text_color(tokens.muted).child(label))
        .child(div().text_sm().child(value))
        .into_any_element()
}

fn metric_card(
    label: &'static str,
    value: impl Into<SharedString>,
    tokens: ThemeTokens,
) -> AnyElement {
    div()
        .p_3()
        .rounded_lg()
        .border_1()
        .border_color(tokens.border)
        .bg(tokens.surface)
        .child(div().text_xs().text_color(tokens.muted).child(label))
        .child(
            div()
                .mt_1()
                .text_lg()
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .child(value.into()),
        )
        .into_any_element()
}

fn threat_list(title: &'static str, items: Vec<String>, tokens: ThemeTokens) -> AnyElement {
    div()
        .min_h(px(180.0))
        .p_3()
        .rounded_lg()
        .border_1()
        .border_color(tokens.border)
        .bg(tokens.surface)
        .child(div().font_weight(gpui::FontWeight::SEMIBOLD).child(title))
        .children(
            items
                .into_iter()
                .take(20)
                .map(|item| div().mt_2().text_sm().text_color(tokens.text).child(item)),
        )
        .into_any_element()
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

#[cfg(test)]
mod tests {
    use super::*;
    use gpui_component::IconNamed;
    use lovelyres_core::target::TargetIdentity;

    fn binding(identity: &str, generation: u64) -> LogAnalysisBinding {
        LogAnalysisBinding {
            connection_id: "connection-a".to_owned(),
            session_id: "session-a".to_owned(),
            target: TargetGuard {
                identity: TargetIdentity::new(identity).unwrap(),
                generation,
            },
        }
    }

    fn result(message: &str) -> LogAnalysisResult {
        LogAnalysisResult {
            entries: vec![entry(message)],
            total_count: 1,
            highlighted_count: 0,
            threat_summary: None,
        }
    }

    fn entry(message: &str) -> LogEntry {
        LogEntry {
            timestamp: "Aug 11 10:00:00".to_owned(),
            level: "INFO".to_owned(),
            service: "sshd".to_owned(),
            message: message.to_owned(),
            raw: message.to_owned(),
            highlighted: false,
            source: None,
        }
    }

    #[test]
    fn target_and_view_changes_reject_late_log_results() {
        let first = binding("server-a", 1);
        let second = binding("server-b", 2);
        let mut model = LogAnalysisModel {
            page: 1,
            page_size: DEFAULT_PAGE_SIZE,
            ..LogAnalysisModel::default()
        };
        model.activate(Some(first.clone()));
        let lease = model
            .begin_request(
                LogRequestKind::Logs(model.view_fingerprint()),
                Some(first.clone()),
            )
            .unwrap();
        model.set_query("new query".to_owned());
        assert!(!model.apply_logs(&lease, Some(&first), result("late")));

        let lease = model
            .begin_request(
                LogRequestKind::Logs(model.view_fingerprint()),
                Some(first.clone()),
            )
            .unwrap();
        model.rebind(Some(second.clone()));
        assert!(!model.apply_logs(&lease, Some(&second), result("wrong target")));
    }

    #[test]
    fn file_refresh_uses_readable_source_and_report_keeps_hostile_text_plain() {
        let current = binding("server-a", 1);
        let mut model = LogAnalysisModel {
            page: 1,
            page_size: DEFAULT_PAGE_SIZE,
            ..LogAnalysisModel::default()
        };
        model.activate(Some(current.clone()));
        let files_lease = model
            .begin_request(LogRequestKind::Files, Some(current.clone()))
            .unwrap();
        assert!(model.apply_files(
            &files_lease,
            Some(&current),
            vec![LogFileInfo {
                path: "/var/log/messages".to_owned(),
                name: "messages".to_owned(),
                size: 12,
                modified: "1".to_owned(),
                readable: true,
            }]
        ));
        assert_eq!(
            model.source,
            LogSource::File("/var/log/messages".to_owned())
        );

        let lease = model
            .begin_request(
                LogRequestKind::Logs(model.view_fingerprint()),
                Some(current.clone()),
            )
            .unwrap();
        assert!(model.apply_logs(&lease, Some(&current), result("<script>alert(1)</script>")));
        let report = model.export_markdown();
        assert!(report.contains("<script>alert(1)</script>"));
        let source = include_str!("log_analysis.rs").to_lowercase();
        assert!(!source.contains(&["inner", "_html"].concat()));
        assert!(!source.contains(&["render", "_markdown"].concat()));
    }

    #[test]
    fn ioc_result_requires_exact_request_and_is_bounded_by_core_shape() {
        let current = binding("server-a", 1);
        let mut model = LogAnalysisModel::default();
        model.activate(Some(current.clone()));
        let lease = model
            .begin_request(
                LogRequestKind::Ioc(vec!["192.0.2.1".to_owned()]),
                Some(current.clone()),
            )
            .unwrap();
        let newer = model
            .begin_request(
                LogRequestKind::Ioc(vec!["evil.example".to_owned()]),
                Some(current.clone()),
            )
            .unwrap();
        let empty = IocSearchResult {
            results: Vec::new(),
            total_matches: 0,
        };
        assert!(!model.apply_ioc(&lease, Some(&current), empty.clone()));
        assert!(model.apply_ioc(&newer, Some(&current), empty));
    }

    #[test]
    fn context_menu_uses_stable_log_identity_instead_of_visible_index() {
        let current = binding("server-a", 1);
        let duplicate = entry("same raw line");
        let mut model = LogAnalysisModel {
            active: true,
            activation_generation: 7,
            binding: Some(current),
            page: 1,
            page_size: DEFAULT_PAGE_SIZE,
            entries: vec![entry("first"), duplicate.clone(), duplicate.clone()],
            ..LogAnalysisModel::default()
        };
        let id = model.entry_id(2).unwrap();
        let lease = LogContextMenuLease::capture(&model, id.clone()).unwrap();

        model.entries.insert(0, entry("newer entry"));
        assert_eq!(model.resolve_entry(&id), Some(&duplicate));
        assert!(lease.accepts(&model));

        model.entries.retain(|candidate| candidate != &duplicate);
        assert!(model.resolve_entry(&id).is_none());
        assert!(!lease.accepts(&model));
    }

    #[test]
    fn context_menu_lease_rejects_view_target_and_lifecycle_changes() {
        let current = binding("server-a", 1);
        let mut model = LogAnalysisModel {
            page: 1,
            page_size: DEFAULT_PAGE_SIZE,
            entries: vec![entry("audit line")],
            ..LogAnalysisModel::default()
        };
        model.activate(Some(current.clone()));
        model.entries = vec![entry("audit line")];
        let id = model.entry_id(0).unwrap();
        let lease = LogContextMenuLease::capture(&model, id).unwrap();
        assert!(lease.accepts(&model));

        model.set_query("different view".to_owned());
        assert!(!lease.accepts(&model));

        model.query.clear();
        model.rebind(Some(binding("server-b", 2)));
        assert!(!lease.accepts(&model));

        model.rebind(Some(current));
        model.entries = vec![entry("audit line")];
        model.deactivate();
        assert!(!lease.accepts(&model));
    }

    #[test]
    fn date_filter_is_part_of_the_exact_log_view_and_resets_pagination() {
        let current = binding("server-a", 1);
        let mut model = LogAnalysisModel {
            page: 4,
            page_size: DEFAULT_PAGE_SIZE,
            entries: vec![entry("before filter")],
            ..LogAnalysisModel::default()
        };
        model.activate(Some(current));
        model.page = 4;
        model.entries = vec![entry("before filter")];
        let before = model.view_fingerprint();
        let day = LogCalendarDay::parse("2026-08-13").unwrap();
        model.set_date_filter(Some(day));
        let after = model.view_fingerprint();

        assert_eq!(model.page, 1);
        assert_eq!(after.date_filter, Some(day));
        assert_ne!(before, after);
        assert!(model.selected_entry().is_none());

        model.set_date_filter(None);
        assert_eq!(model.view_fingerprint().date_filter, None);
    }

    #[test]
    fn ai_text_bounds_preserve_utf8_and_hostile_markup_as_literal_text() {
        let hostile = format!(
            "{}<script>open_url('https://evil.invalid')</script>",
            "你".repeat(20)
        );
        let truncated = truncate_utf8_bytes(&hostile, 17);
        assert!(truncated.is_char_boundary(truncated.len()));
        assert!(truncated.ends_with('…'));

        let mut output = String::new();
        assert!(append_utf8_bounded(
            &mut output,
            "<img src=x onerror=alert(1)>",
            64
        ));
        assert_eq!(output, "<img src=x onerror=alert(1)>");
        assert!(!append_utf8_bounded(&mut output, &"界".repeat(20), 64));
        assert_eq!(output, "<img src=x onerror=alert(1)>");

        let source = include_str!("log_analysis.rs").to_ascii_lowercase();
        assert!(!source.contains(&["textview", "::markdown"].concat()));
        assert!(!source.contains(&["cx.", "open_url"].concat()));
        assert!(!source.contains(&["inner", "html"].concat()));
    }

    #[test]
    fn legacy_log_context_actions_are_complete_and_icon_backed() {
        assert_eq!(LogContextAction::ALL.len(), 2);
        assert_eq!(LogContextAction::Copy.label(), "复制日志原文");
        assert_eq!(LogContextAction::ExplainAi.label(), "AI 解释日志");
        for action in LogContextAction::ALL {
            assert!(
                !crate::buttons::icon_for_button_id(action.id())
                    .path()
                    .is_empty()
            );
        }
    }

    #[test]
    fn custom_rule_tab_uses_aligned_cached_matches_and_svg_actions() {
        assert_eq!(LogPageTab::ALL.len(), 4);
        assert_eq!(LogPageTab::Rules.label(), "规则 & 导出");

        let current = binding("server-a", 1);
        let matched = LogMatchRule {
            id: "rule-1".to_owned(),
            name: "可疑编码 <script>".to_owned(),
            pattern: "base64[_-]decode".to_owned(),
            severity: LogRuleSeverity::High,
        };
        let mut model = LogAnalysisModel {
            active: true,
            activation_generation: 9,
            binding: Some(current),
            entries: vec![entry("base64_decode payload"), entry("normal")],
            ..LogAnalysisModel::default()
        };
        assert!(model.set_rules(vec![matched.clone()], vec![Some(matched.clone()), None]));
        assert_eq!(model.rule_match(0), Some(&matched));
        assert_eq!(model.rule_match(1), None);

        assert!(!model.set_rules(Vec::new(), vec![None]));
        assert_eq!(model.rules, vec![matched]);
        assert_eq!(model.rule_matches.len(), model.entries.len());

        for id in [
            "log-rule-add",
            "log-rule-refresh",
            "log-rule-delete-rule-1",
            "log-rule-export-report",
            "log-rule-severity-Critical",
        ] {
            assert!(!crate::buttons::icon_for_button_id(id).path().is_empty());
        }
        let source = include_str!("log_analysis.rs").to_ascii_lowercase();
        assert!(!source.contains(&["local", "storage"].concat()));
        let app_source = include_str!("app.rs");
        assert!(app_source.contains("page.handle_dialog_outcome(outcome, cx)"));
    }
}
