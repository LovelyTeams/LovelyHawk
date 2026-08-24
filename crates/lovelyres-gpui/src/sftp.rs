use std::{cmp::Ordering, collections::BTreeSet, path::PathBuf, sync::Arc};

use gpui::{
    AnyElement, ClipboardItem, Context, Corner, Entity, EventEmitter, IntoElement, KeyDownEvent,
    MouseButton, MouseDownEvent, PathPromptOptions, Pixels, Point, Render, SharedString,
    Subscription, Window, anchored, deferred, div, prelude::*, px,
};
use gpui_component::{
    Disableable, Icon, IconName, Selectable, Sizable,
    button::ButtonVariants,
    input::{Input, InputEvent, InputState},
    scroll::ScrollableElement,
};
use lovelyres_core::{
    BackendServices, CoreError, CoreResult,
    file_analysis::{FileAnalysisCheck, FileAnalysisRequest, FileAnalysisResult},
    operations::{DangerousConfirmation, OperationState, VerificationResult},
    path_guard::sensitive_roots_for_home,
    sftp::{
        ArchiveFormat, BoundSftpSession, MAX_EDIT_BYTES, MAX_TRANSFER_BYTES, RemotePath, SftpEntry,
        SftpFileKind, SftpLocation, SftpMetadata, SftpMutation, SftpPlannedOperation, SftpService,
    },
    ssh::BoundSshSession,
    target::TargetGuard,
};

use crate::{app::SharedAppState, runtime::TokioBridge, theme::ThemeTokens};

const ROW_WINDOW_SIZE: usize = 100;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FileId(String);

impl FileId {
    pub fn from_path(path: &RemotePath) -> Self {
        Self(path.as_str().to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SftpContextAction {
    Open,
    Details,
    Analyze,
    Download,
    Rename,
    Chmod,
    Compress,
    Extract,
    CopyPath,
    CopyName,
    OpenTerminal,
    Delete,
}

impl SftpContextAction {
    const ALL: [Self; 12] = [
        Self::Open,
        Self::Details,
        Self::Analyze,
        Self::Download,
        Self::Rename,
        Self::Chmod,
        Self::Compress,
        Self::Extract,
        Self::CopyPath,
        Self::CopyName,
        Self::OpenTerminal,
        Self::Delete,
    ];

    const fn id(self) -> &'static str {
        match self {
            Self::Open => "sftp-context-open",
            Self::Details => "sftp-context-details",
            Self::Analyze => "sftp-context-analyze",
            Self::Download => "sftp-context-download",
            Self::Rename => "sftp-context-rename",
            Self::Chmod => "sftp-context-chmod",
            Self::Compress => "sftp-context-compress",
            Self::Extract => "sftp-context-extract",
            Self::CopyPath => "sftp-context-copy-path",
            Self::CopyName => "sftp-context-copy-name",
            Self::OpenTerminal => "sftp-context-open-terminal",
            Self::Delete => "sftp-context-delete",
        }
    }

    const fn label(self, kind: SftpFileKind) -> &'static str {
        match self {
            Self::Open if matches!(kind, SftpFileKind::Directory) => "进入目录",
            Self::Open => "查看文件",
            Self::Details => "查看详细信息",
            Self::Analyze => "文件安全分析",
            Self::Download => "下载到本地",
            Self::Rename => "重命名",
            Self::Chmod => "修改权限",
            Self::Compress => "创建 .tar.gz 归档",
            Self::Extract => "安全解压…",
            Self::CopyPath => "复制完整路径",
            Self::CopyName => "复制文件名",
            Self::OpenTerminal => "在终端中打开",
            Self::Delete => "删除（可恢复）",
        }
    }

    const fn starts_section(self) -> bool {
        matches!(self, Self::Download | Self::CopyPath | Self::Delete)
    }

    fn available(self, row: &SftpRow, busy: bool, session_ready: bool) -> bool {
        let kind = row.entry.metadata.kind;
        let is_file = kind == SftpFileKind::File;
        let is_file_or_directory = matches!(kind, SftpFileKind::File | SftpFileKind::Directory);
        match self {
            Self::Open => is_file_or_directory,
            Self::Details | Self::CopyPath | Self::CopyName => true,
            Self::Analyze | Self::Download => is_file,
            Self::Rename | Self::Chmod | Self::Compress | Self::Delete => !busy,
            Self::Extract => {
                is_file
                    && !busy
                    && SftpService::suggested_extraction_destination(&row.entry.path).is_ok()
            }
            Self::OpenTerminal => is_file_or_directory && session_ready,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SftpContextMenuLease {
    activation_generation: u64,
    binding: SftpBinding,
    file_id: FileId,
}

impl SftpContextMenuLease {
    fn capture(model: &SftpModel, file_id: FileId) -> Option<Self> {
        if !model.active || !model.rows.iter().any(|row| row.id == file_id) {
            return None;
        }
        Some(Self {
            activation_generation: model.activation_generation,
            binding: model.binding.clone()?,
            file_id,
        })
    }

    fn accepts(&self, model: &SftpModel) -> bool {
        model.active
            && self.activation_generation == model.activation_generation
            && model.binding.as_ref() == Some(&self.binding)
            && model.rows.iter().any(|row| row.id == self.file_id)
    }
}

#[derive(Clone, Debug)]
struct SftpContextMenuState {
    lease: SftpContextMenuLease,
    position: Point<Pixels>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SftpSort {
    #[default]
    Name,
    Kind,
    Size,
    Modified,
}

impl SftpSort {
    const ALL: [Self; 4] = [Self::Name, Self::Kind, Self::Size, Self::Modified];

    const fn label(self) -> &'static str {
        match self {
            Self::Name => "名称",
            Self::Kind => "类型",
            Self::Size => "大小",
            Self::Modified => "修改时间",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SftpRow {
    pub id: FileId,
    pub entry: SftpEntry,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SftpBinding {
    pub connection_id: String,
    pub session_id: String,
    pub target: TargetGuard,
}

impl SftpBinding {
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

#[derive(Debug, Default)]
pub struct SftpNavigator {
    location: Option<SftpLocation>,
    revision: u64,
}

impl SftpNavigator {
    pub fn location(&self) -> Option<&SftpLocation> {
        self.location.as_ref()
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn bind_target(&mut self, target: TargetGuard, path: RemotePath, cx: &mut Context<Self>) {
        self.set_location(SftpLocation::new(target, path));
        cx.notify();
    }

    pub fn navigate(
        &mut self,
        target: &TargetGuard,
        path: RemotePath,
        cx: &mut Context<Self>,
    ) -> CoreResult<()> {
        self.navigate_checked(target, path)?;
        cx.notify();
        Ok(())
    }

    fn navigate_checked(&mut self, target: &TargetGuard, path: RemotePath) -> CoreResult<()> {
        let current = self.location.as_ref().ok_or(CoreError::NoActiveTarget)?;
        if &current.target != target {
            return Err(CoreError::TargetChanged {
                expected_identity: current.target.identity.as_str().to_owned(),
                expected_generation: current.target.generation,
                current: format!("{}@{}", target.identity.as_str(), target.generation),
            });
        }
        self.set_location(SftpLocation::new(target.clone(), path));
        Ok(())
    }

    fn set_location(&mut self, location: SftpLocation) {
        if self.location.as_ref() == Some(&location) {
            return;
        }
        self.location = Some(location);
        self.revision = self.revision.wrapping_add(1).max(1);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RequestLease {
    activation_generation: u64,
    request_id: u64,
    binding: SftpBinding,
    path: RemotePath,
}

#[derive(Debug)]
pub struct SftpModel {
    active: bool,
    activation_generation: u64,
    next_request_id: u64,
    binding: Option<SftpBinding>,
    path: RemotePath,
    rows: Vec<SftpRow>,
    query: String,
    sort: SftpSort,
    ascending: bool,
    selected: Option<FileId>,
    row_window_start: usize,
    latest_list_request: Option<u64>,
    latest_read_request: Option<(u64, FileId)>,
}

impl Default for SftpModel {
    fn default() -> Self {
        Self {
            active: false,
            activation_generation: 0,
            next_request_id: 0,
            binding: None,
            path: RemotePath::new("/").expect("root remote path is valid"),
            rows: Vec::new(),
            query: String::new(),
            sort: SftpSort::Name,
            ascending: true,
            selected: None,
            row_window_start: 0,
            latest_list_request: None,
            latest_read_request: None,
        }
    }
}

impl SftpModel {
    pub fn activate(&mut self, binding: Option<SftpBinding>, path: RemotePath) {
        self.active = true;
        self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
        self.rebind(binding, path);
    }

    pub fn deactivate(&mut self) {
        self.active = false;
        self.latest_list_request = None;
        self.latest_read_request = None;
        self.selected = None;
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn binding(&self) -> Option<&SftpBinding> {
        self.binding.as_ref()
    }

    pub fn path(&self) -> &RemotePath {
        &self.path
    }

    pub fn selected_row(&self) -> Option<&SftpRow> {
        let selected = self.selected.as_ref()?;
        self.rows.iter().find(|row| &row.id == selected)
    }

    pub fn set_query(&mut self, query: String) {
        self.query = query;
        self.row_window_start = 0;
    }

    pub fn set_sort(&mut self, sort: SftpSort) {
        if self.sort == sort {
            self.ascending = !self.ascending;
        } else {
            self.sort = sort;
            self.ascending = true;
        }
        self.row_window_start = 0;
    }

    pub fn select(&mut self, id: FileId) -> bool {
        if self.rows.iter().any(|row| row.id == id) {
            self.selected = Some(id);
            true
        } else {
            false
        }
    }

    pub fn visible_rows(&self) -> Vec<&SftpRow> {
        let query = self.query.to_lowercase();
        let mut rows = self
            .rows
            .iter()
            .filter(|row| {
                query.is_empty()
                    || row.entry.name.to_lowercase().contains(&query)
                    || row.entry.path.as_str().to_lowercase().contains(&query)
            })
            .collect::<Vec<_>>();
        rows.sort_by(|left, right| self.compare_rows(left, right));
        let start = self.row_window_start.min(rows.len());
        rows.into_iter().skip(start).take(ROW_WINDOW_SIZE).collect()
    }

    pub fn scroll_window(&mut self, pages: isize) {
        let filtered_count = self.filtered_count();
        let maximum = filtered_count.saturating_sub(ROW_WINDOW_SIZE);
        self.row_window_start = if pages.is_negative() {
            self.row_window_start
                .saturating_sub(pages.unsigned_abs() * ROW_WINDOW_SIZE)
        } else {
            self.row_window_start
                .saturating_add(pages as usize * ROW_WINDOW_SIZE)
                .min(maximum)
        };
    }

    fn filtered_count(&self) -> usize {
        let query = self.query.to_lowercase();
        self.rows
            .iter()
            .filter(|row| {
                query.is_empty()
                    || row.entry.name.to_lowercase().contains(&query)
                    || row.entry.path.as_str().to_lowercase().contains(&query)
            })
            .count()
    }

    fn rebind(&mut self, binding: Option<SftpBinding>, path: RemotePath) {
        self.binding = binding;
        self.path = path;
        self.rows.clear();
        self.query.clear();
        self.sort = SftpSort::Name;
        self.ascending = true;
        self.selected = None;
        self.latest_list_request = None;
        self.latest_read_request = None;
        self.row_window_start = 0;
    }

    fn navigate(&mut self, path: RemotePath) {
        if self.path == path {
            return;
        }
        self.path = path;
        self.rows.clear();
        self.selected = None;
        self.latest_list_request = None;
        self.latest_read_request = None;
        self.row_window_start = 0;
    }

    fn begin_list(&mut self) -> CoreResult<RequestLease> {
        let binding = self.binding.clone().ok_or(CoreError::NoActiveTarget)?;
        self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
        self.latest_list_request = Some(self.next_request_id);
        Ok(RequestLease {
            activation_generation: self.activation_generation,
            request_id: self.next_request_id,
            binding,
            path: self.path.clone(),
        })
    }

    fn begin_read(&mut self, id: FileId) -> CoreResult<RequestLease> {
        let binding = self.binding.clone().ok_or(CoreError::NoActiveTarget)?;
        let row =
            self.rows
                .iter()
                .find(|row| row.id == id)
                .ok_or_else(|| CoreError::Validation {
                    subject: "SFTP selection",
                    message: "file no longer exists".to_owned(),
                })?;
        if row.entry.metadata.kind != SftpFileKind::File {
            return Err(CoreError::Validation {
                subject: "SFTP viewer",
                message: "only regular files can be viewed".to_owned(),
            });
        }
        self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
        self.latest_read_request = Some((self.next_request_id, id));
        Ok(RequestLease {
            activation_generation: self.activation_generation,
            request_id: self.next_request_id,
            binding,
            path: row.entry.path.clone(),
        })
    }

    fn accepts_list(&self, lease: &RequestLease, binding: Option<&SftpBinding>) -> bool {
        self.active
            && lease.activation_generation == self.activation_generation
            && self.latest_list_request == Some(lease.request_id)
            && self.binding.as_ref() == Some(&lease.binding)
            && binding == Some(&lease.binding)
            && self.path == lease.path
    }

    fn accepts_read(&self, lease: &RequestLease, binding: Option<&SftpBinding>) -> bool {
        self.active
            && lease.activation_generation == self.activation_generation
            && self
                .latest_read_request
                .as_ref()
                .is_some_and(|(request_id, id)| {
                    *request_id == lease.request_id
                        && id.as_str() == lease.path.as_str()
                        && self.selected.as_ref() == Some(id)
                })
            && self.binding.as_ref() == Some(&lease.binding)
            && binding == Some(&lease.binding)
    }

    fn apply_list(
        &mut self,
        lease: &RequestLease,
        binding: Option<&SftpBinding>,
        entries: Vec<SftpEntry>,
    ) -> bool {
        if !self.accepts_list(lease, binding) {
            return false;
        }
        let selected = self.selected.clone();
        self.rows = entries
            .into_iter()
            .map(|entry| SftpRow {
                id: FileId::from_path(&entry.path),
                entry,
            })
            .collect();
        self.selected = selected.filter(|id| self.rows.iter().any(|row| &row.id == id));
        true
    }

    fn compare_rows(&self, left: &SftpRow, right: &SftpRow) -> Ordering {
        let directories =
            || kind_rank(left.entry.metadata.kind).cmp(&kind_rank(right.entry.metadata.kind));
        directories()
            .then_with(|| {
                let ordering = match self.sort {
                    SftpSort::Name => left
                        .entry
                        .name
                        .to_lowercase()
                        .cmp(&right.entry.name.to_lowercase()),
                    SftpSort::Kind => kind_rank(left.entry.metadata.kind)
                        .cmp(&kind_rank(right.entry.metadata.kind)),
                    SftpSort::Size => left.entry.metadata.size.cmp(&right.entry.metadata.size),
                    SftpSort::Modified => left
                        .entry
                        .metadata
                        .modified_at
                        .cmp(&right.entry.metadata.modified_at),
                };
                if self.ascending {
                    ordering
                } else {
                    ordering.reverse()
                }
            })
            .then_with(|| {
                let ordering = left.id.cmp(&right.id);
                if self.ascending {
                    ordering
                } else {
                    ordering.reverse()
                }
            })
    }
}

fn kind_rank(kind: SftpFileKind) -> u8 {
    match kind {
        SftpFileKind::Directory => 0,
        SftpFileKind::File => 1,
        SftpFileKind::Symlink => 2,
        SftpFileKind::Other => 3,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenDirectoryTerminalIntent {
    pub target: TargetGuard,
    pub path: RemotePath,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SftpWindowEvent {
    OpenDirectoryTerminal(OpenDirectoryTerminalIntent),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Overlay {
    Viewer,
    Edit,
    CreateFile,
    CreateDirectory,
    Rename,
    Chmod,
    Analysis,
    History,
    Extract,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExtractPlanLease {
    activation_generation: u64,
    request_id: u64,
    binding: SftpBinding,
    archive: RemotePath,
    destination: RemotePath,
}

impl ExtractPlanLease {
    fn accepts(
        &self,
        active: bool,
        activation_generation: u64,
        latest_request_id: u64,
        binding: Option<&SftpBinding>,
        selected_path: Option<&RemotePath>,
    ) -> bool {
        active
            && self.activation_generation == activation_generation
            && self.request_id == latest_request_id
            && binding == Some(&self.binding)
            && selected_path == Some(&self.archive)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AnalysisLease {
    activation_generation: u64,
    request_id: u64,
    binding: SftpBinding,
    path: RemotePath,
}

#[derive(Debug)]
struct FileAnalysisModel {
    checks: BTreeSet<FileAnalysisCheck>,
    path: Option<RemotePath>,
    result: Option<FileAnalysisResult>,
    selected: Option<FileAnalysisCheck>,
    next_request_id: u64,
    latest: Option<AnalysisLease>,
}

impl Default for FileAnalysisModel {
    fn default() -> Self {
        Self {
            checks: FileAnalysisCheck::ALL
                .into_iter()
                .filter(|check| check.recommended())
                .collect(),
            path: None,
            result: None,
            selected: None,
            next_request_id: 0,
            latest: None,
        }
    }
}

impl FileAnalysisModel {
    fn open(&mut self, path: RemotePath) {
        self.path = Some(path);
        self.result = None;
        self.selected = None;
        self.latest = None;
    }

    fn close(&mut self) {
        self.path = None;
        self.result = None;
        self.selected = None;
        self.latest = None;
    }

    fn select_recommended(&mut self) {
        self.checks = FileAnalysisCheck::ALL
            .into_iter()
            .filter(|check| check.recommended())
            .collect();
    }

    fn select_all(&mut self) {
        self.checks = FileAnalysisCheck::ALL.into_iter().collect();
    }

    fn clear_checks(&mut self) {
        self.checks.clear();
    }

    fn toggle(&mut self, check: FileAnalysisCheck) {
        if !self.checks.remove(&check) {
            self.checks.insert(check);
        }
    }

    fn begin(
        &mut self,
        activation_generation: u64,
        binding: SftpBinding,
    ) -> CoreResult<(AnalysisLease, FileAnalysisRequest)> {
        let path = self.path.clone().ok_or_else(|| CoreError::Validation {
            subject: "file analysis selection",
            message: "no file is selected for analysis".to_owned(),
        })?;
        let request = FileAnalysisRequest {
            remote_path: path.as_str().to_owned(),
            checks: self.checks.clone(),
            strings_limit: 100,
            hex_bytes: 512,
        };
        request.validate()?;
        self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
        let lease = AnalysisLease {
            activation_generation,
            request_id: self.next_request_id,
            binding,
            path,
        };
        self.latest = Some(lease.clone());
        self.result = None;
        self.selected = None;
        Ok((lease, request))
    }

    fn accepts(
        &self,
        lease: &AnalysisLease,
        active: bool,
        activation_generation: u64,
        binding: Option<&SftpBinding>,
    ) -> bool {
        active
            && activation_generation == lease.activation_generation
            && self.latest.as_ref() == Some(lease)
            && self.path.as_ref() == Some(&lease.path)
            && binding == Some(&lease.binding)
    }

    fn apply(
        &mut self,
        lease: &AnalysisLease,
        active: bool,
        activation_generation: u64,
        binding: Option<&SftpBinding>,
        result: FileAnalysisResult,
    ) -> bool {
        if !self.accepts(lease, active, activation_generation, binding)
            || result.remote_path != lease.path.as_str()
        {
            return false;
        }
        self.latest = None;
        self.selected = result.findings.first().map(|finding| finding.check);
        self.result = Some(result);
        true
    }

    fn finish_failed(
        &mut self,
        lease: &AnalysisLease,
        active: bool,
        activation_generation: u64,
        binding: Option<&SftpBinding>,
    ) -> bool {
        if !self.accepts(lease, active, activation_generation, binding) {
            return false;
        }
        self.latest = None;
        true
    }
}

struct PendingOperation {
    operation: SftpPlannedOperation,
    activation_generation: u64,
    target: TargetGuard,
}

struct OperationCompletion {
    operation: SftpPlannedOperation,
    result: CoreResult<VerificationResult>,
}

pub struct SftpWindow {
    services: Arc<BackendServices>,
    tokio: Arc<TokioBridge>,
    shared: Entity<SharedAppState>,
    navigator: Entity<SftpNavigator>,
    model: SftpModel,
    session: Option<BoundSftpSession>,
    search_input: Entity<InputState>,
    name_input: Entity<InputState>,
    mode_input: Entity<InputState>,
    editor_input: Entity<InputState>,
    loaded_text: String,
    overlay: Option<Overlay>,
    context_menu: Option<SftpContextMenuState>,
    editor_path: Option<RemotePath>,
    analysis: FileAnalysisModel,
    analysis_abort: Option<tokio::task::AbortHandle>,
    extract_plan_abort: Option<tokio::task::AbortHandle>,
    extract_plan_request_id: u64,
    pending_operation: Option<PendingOperation>,
    bind_abort: Option<tokio::task::AbortHandle>,
    list_abort: Option<tokio::task::AbortHandle>,
    read_abort: Option<tokio::task::AbortHandle>,
    loading: bool,
    operation_running_generation: Option<u64>,
    notice: Option<(SharedString, bool)>,
    _subscriptions: Vec<Subscription>,
}

impl EventEmitter<SftpWindowEvent> for SftpWindow {}

impl SftpWindow {
    pub fn new(
        services: Arc<BackendServices>,
        tokio: Arc<TokioBridge>,
        shared: Entity<SharedAppState>,
        navigator: Entity<SftpNavigator>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let search_input = cx.new(|cx| InputState::new(window, cx).placeholder("搜索当前目录…"));
        let name_input = cx.new(|cx| InputState::new(window, cx).placeholder("名称"));
        let mode_input = cx.new(|cx| InputState::new(window, cx).placeholder("权限（如 0640）"));
        let editor_input = cx.new(|cx| {
            InputState::new(window, cx)
                .multi_line(true)
                .placeholder("UTF-8 文本，最大 2 MiB")
        });
        let subscriptions = vec![
            cx.subscribe_in(
                &search_input,
                window,
                |sftp, input, event: &InputEvent, _, cx| {
                    if matches!(event, InputEvent::Change) {
                        sftp.context_menu = None;
                        sftp.model.set_query(input.read(cx).value().to_string());
                        cx.notify();
                    }
                },
            ),
            cx.observe(&shared, |sftp, _, cx| sftp.handle_shared_change(cx)),
            cx.observe(&navigator, |sftp, _, cx| sftp.handle_navigation(cx)),
        ];
        Self {
            services,
            tokio,
            shared,
            navigator,
            model: SftpModel::default(),
            session: None,
            search_input,
            name_input,
            mode_input,
            editor_input,
            loaded_text: String::new(),
            overlay: None,
            context_menu: None,
            editor_path: None,
            analysis: FileAnalysisModel::default(),
            analysis_abort: None,
            extract_plan_abort: None,
            extract_plan_request_id: 0,
            pending_operation: None,
            bind_abort: None,
            list_abort: None,
            read_abort: None,
            loading: false,
            operation_running_generation: None,
            notice: None,
            _subscriptions: subscriptions,
        }
    }

    pub fn activate(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let binding = SftpBinding::capture(self.shared.read(cx));
        let path = binding
            .as_ref()
            .and_then(|binding| {
                self.navigator
                    .read(cx)
                    .location()
                    .filter(|location| location.target == binding.target)
                    .map(|location| location.path.clone())
            })
            .unwrap_or_else(|| RemotePath::new("/").expect("root path is valid"));
        self.model.activate(binding, path);
        self.search_input
            .update(cx, |input, cx| input.focus(window, cx));
        self.rebind_session(cx);
    }

    pub fn deactivate(&mut self, cx: &mut Context<Self>) {
        self.abort_reads();
        self.abort_analysis();
        self.abort_extract_plan();
        if let Some(abort) = self.bind_abort.take() {
            abort.abort();
        }
        self.session = None;
        self.overlay = None;
        self.context_menu = None;
        self.editor_path = None;
        self.analysis.close();
        self.pending_operation = None;
        self.operation_running_generation = None;
        self.model.deactivate();
        cx.notify();
    }

    pub const fn is_active(&self) -> bool {
        self.model.is_active()
    }

    pub fn navigator(&self) -> Entity<SftpNavigator> {
        self.navigator.clone()
    }

    pub(crate) fn report_directory_terminal_request(
        &mut self,
        message: impl Into<SharedString>,
        error: bool,
        cx: &mut Context<Self>,
    ) {
        self.notice = Some((message.into(), error));
        cx.notify();
    }

    fn abort_reads(&mut self) {
        if let Some(abort) = self.list_abort.take() {
            abort.abort();
        }
        if let Some(abort) = self.read_abort.take() {
            abort.abort();
        }
        self.loading = false;
    }

    fn abort_analysis(&mut self) {
        if let Some(abort) = self.analysis_abort.take() {
            abort.abort();
        }
        self.analysis.latest = None;
    }

    fn abort_extract_plan(&mut self) {
        if let Some(abort) = self.extract_plan_abort.take() {
            abort.abort();
        }
        self.extract_plan_request_id = self.extract_plan_request_id.wrapping_add(1).max(1);
    }

    fn current_binding(&self, cx: &Context<Self>) -> Option<SftpBinding> {
        SftpBinding::capture(self.shared.read(cx))
    }

    fn handle_shared_change(&mut self, cx: &mut Context<Self>) {
        if !self.model.is_active() {
            return;
        }
        let binding = self.current_binding(cx);
        if self.model.binding() == binding.as_ref() {
            return;
        }
        self.abort_reads();
        self.abort_analysis();
        self.abort_extract_plan();
        if let Some(abort) = self.bind_abort.take() {
            abort.abort();
        }
        self.session = None;
        self.overlay = None;
        self.context_menu = None;
        self.editor_path = None;
        self.analysis.close();
        self.pending_operation = None;
        self.operation_running_generation = None;
        let root = RemotePath::new("/").expect("root path is valid");
        self.model.activate(binding.clone(), root.clone());
        if let Some(binding) = binding {
            self.navigator.update(cx, |navigator, cx| {
                navigator.bind_target(binding.target, root, cx);
            });
            self.rebind_session(cx);
        } else {
            self.notice = Some(("未连接目标，SFTP 已停止".into(), true));
            cx.notify();
        }
    }

    fn handle_navigation(&mut self, cx: &mut Context<Self>) {
        if !self.model.is_active() {
            return;
        }
        let Some(location) = self.navigator.read(cx).location().cloned() else {
            return;
        };
        let Some(binding) = self.model.binding() else {
            return;
        };
        if location.target != binding.target {
            self.notice = Some(("已拒绝来自其他目标的 SFTP 导航".into(), true));
            cx.notify();
            return;
        }
        if self.model.path() != &location.path {
            self.abort_reads();
            self.abort_extract_plan();
            self.context_menu = None;
            if self.overlay == Some(Overlay::Analysis) {
                self.abort_analysis();
                self.analysis.close();
                self.overlay = None;
            }
            self.model.navigate(location.path);
            self.refresh(cx);
        }
    }

    fn rebind_session(&mut self, cx: &mut Context<Self>) {
        let Some(binding) = self.model.binding().cloned() else {
            self.notice = Some(("未连接目标，无法建立 SFTP 会话".into(), true));
            return;
        };
        if let Some(abort) = self.bind_abort.take() {
            abort.abort();
        }
        let service = self.services.sftp().clone();
        let target = binding.target.clone();
        let session_id = binding.session_id.clone();
        let task = self
            .tokio
            .spawn(async move { service.bind_session(target, &session_id).await });
        self.bind_abort = Some(task.abort_handle());
        cx.spawn(async move |sftp, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(sftp) = sftp.upgrade() {
                    sftp.update(cx, |sftp, cx| sftp.finish_bind(binding, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_bind(
        &mut self,
        binding: SftpBinding,
        result: Result<CoreResult<BoundSftpSession>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if !self.model.is_active()
            || self.model.binding() != Some(&binding)
            || self.current_binding(cx).as_ref() != Some(&binding)
        {
            return;
        }
        self.bind_abort = None;
        match result {
            Ok(Ok(session)) => {
                self.session = Some(session);
                self.notice = None;
                if self.navigator.read(cx).location().is_none() {
                    let path = self.model.path().clone();
                    self.navigator.update(cx, |navigator, cx| {
                        navigator.bind_target(binding.target.clone(), path, cx);
                    });
                }
                self.refresh(cx);
            }
            Ok(Err(error)) => {
                self.notice = Some((format!("SFTP 会话绑定失败：{error}").into(), true));
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.notice = Some((format!("SFTP 绑定任务失败：{error}").into(), true));
            }
        }
        cx.notify();
    }

    fn refresh(&mut self, cx: &mut Context<Self>) {
        self.context_menu = None;
        let Some(session) = self.session.clone() else {
            return;
        };
        let lease = match self.model.begin_list() {
            Ok(lease) => lease,
            Err(error) => {
                self.notice = Some((format!("无法刷新 SFTP：{error}").into(), true));
                return;
            }
        };
        if let Some(abort) = self.list_abort.take() {
            abort.abort();
        }
        self.loading = true;
        let service = self.services.sftp().clone();
        let path = lease.path.clone();
        let task = self
            .tokio
            .spawn(async move { service.list(&session, &path).await });
        self.list_abort = Some(task.abort_handle());
        cx.spawn(async move |sftp, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(sftp) = sftp.upgrade() {
                    sftp.update(cx, |sftp, cx| sftp.finish_list(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_list(
        &mut self,
        lease: RequestLease,
        result: Result<CoreResult<Vec<SftpEntry>>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts_list(&lease, binding.as_ref()) {
            return;
        }
        self.loading = false;
        self.list_abort = None;
        match result {
            Ok(Ok(entries)) => {
                let _ = self.model.apply_list(&lease, binding.as_ref(), entries);
                self.notice = None;
            }
            Ok(Err(error)) => {
                self.notice = Some((format!("目录读取失败：{error}").into(), true));
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.notice = Some((format!("目录任务失败：{error}").into(), true));
            }
        }
        cx.notify();
    }

    fn navigate_to(&mut self, path: RemotePath, cx: &mut Context<Self>) {
        self.context_menu = None;
        let Some(binding) = self.model.binding().cloned() else {
            return;
        };
        if let Err(error) = self.navigator.update(cx, |navigator, cx| {
            navigator.navigate(&binding.target, path, cx)
        }) {
            self.notice = Some((format!("导航失败：{error}").into(), true));
            cx.notify();
        }
    }

    fn open_selected(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(row) = self.model.selected_row().cloned() else {
            return;
        };
        if row.entry.metadata.kind == SftpFileKind::Directory {
            self.navigate_to(row.entry.path, cx);
        } else if row.entry.metadata.kind == SftpFileKind::File {
            self.read_selected(false, window, cx);
        } else {
            self.notice = Some(("符号链接及特殊文件默认不跟随".into(), true));
            cx.notify();
        }
    }

    fn read_selected(&mut self, _edit: bool, _window: &mut Window, cx: &mut Context<Self>) {
        let Some(row) = self.model.selected_row().cloned() else {
            return;
        };
        let Some(session) = self.session.clone() else {
            return;
        };
        let lease = match self.model.begin_read(row.id.clone()) {
            Ok(lease) => lease,
            Err(error) => {
                self.notice = Some((format!("无法打开文件：{error}").into(), true));
                cx.notify();
                return;
            }
        };
        if let Some(abort) = self.read_abort.take() {
            abort.abort();
        }
        self.loading = true;
        let service = self.services.sftp().clone();
        let path = row.entry.path;
        let task = self
            .tokio
            .spawn(async move { service.read_text(&session, &path).await });
        self.read_abort = Some(task.abort_handle());
        cx.spawn(async move |sftp, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(sftp) = sftp.upgrade() {
                    sftp.update(cx, |sftp, cx| sftp.finish_read(lease, result, cx));
                }
            });
        })
        .detach();
    }

    fn finish_read(
        &mut self,
        lease: RequestLease,
        result: Result<CoreResult<String>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts_read(&lease, binding.as_ref()) {
            return;
        }
        self.loading = false;
        self.read_abort = None;
        match result {
            Ok(Ok(content)) => {
                self.loaded_text = content;
                self.editor_path = Some(lease.path);
                self.overlay = Some(Overlay::Viewer);
                self.notice = None;
            }
            Ok(Err(error)) => {
                self.notice = Some((format!("文件读取失败：{error}").into(), true));
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.notice = Some((format!("文件读取任务失败：{error}").into(), true));
            }
        }
        cx.notify();
    }

    fn close_overlay(&mut self, cx: &mut Context<Self>) {
        if self.overlay == Some(Overlay::Analysis) {
            self.abort_analysis();
            self.analysis.close();
        }
        self.overlay = None;
        self.editor_path = None;
        self.loaded_text.clear();
        cx.notify();
    }

    fn begin_edit_from_viewer(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.editor_path.is_none() {
            return;
        }
        let content = self.loaded_text.clone();
        self.editor_input.update(cx, |input, cx| {
            input.set_value(content, window, cx);
            input.focus(window, cx);
        });
        self.overlay = Some(Overlay::Edit);
        cx.notify();
    }

    fn show_overlay(&mut self, overlay: Overlay, window: &mut Window, cx: &mut Context<Self>) {
        self.context_menu = None;
        self.overlay = Some(overlay);
        match overlay {
            Overlay::Rename => {
                let value = self
                    .model
                    .selected_row()
                    .map(|row| row.entry.name.clone())
                    .unwrap_or_default();
                self.name_input
                    .update(cx, |input, cx| input.set_value(value, window, cx));
            }
            Overlay::Chmod => {
                let value = self
                    .model
                    .selected_row()
                    .and_then(|row| row.entry.metadata.permissions)
                    .map(|mode| format!("{:04o}", mode & 0o7777))
                    .unwrap_or_default();
                self.mode_input
                    .update(cx, |input, cx| input.set_value(value, window, cx));
            }
            Overlay::CreateFile => {
                self.name_input
                    .update(cx, |input, cx| input.set_value("", window, cx));
                self.editor_input
                    .update(cx, |input, cx| input.set_value("", window, cx));
            }
            Overlay::CreateDirectory => {
                self.name_input
                    .update(cx, |input, cx| input.set_value("", window, cx));
            }
            Overlay::Extract => {
                let value = self
                    .model
                    .selected_row()
                    .and_then(|row| {
                        SftpService::suggested_extraction_destination(&row.entry.path).ok()
                    })
                    .map_or_else(String::new, |path| path.as_str().to_owned());
                self.name_input.update(cx, |input, cx| {
                    input.set_value(value, window, cx);
                    input.focus(window, cx);
                });
            }
            Overlay::Viewer | Overlay::Edit | Overlay::Analysis | Overlay::History => {}
        }
        cx.notify();
    }

    fn open_analysis(&mut self, cx: &mut Context<Self>) {
        let Some((kind, path)) = self
            .model
            .selected_row()
            .map(|row| (row.entry.metadata.kind, row.entry.path.clone()))
        else {
            return;
        };
        if kind != SftpFileKind::File {
            self.notice = Some(("只能分析普通文件；目录、链接和设备不会被跟随".into(), true));
            cx.notify();
            return;
        }
        self.abort_analysis();
        self.analysis.open(path);
        self.overlay = Some(Overlay::Analysis);
        cx.notify();
    }

    fn toggle_analysis_check(&mut self, check: FileAnalysisCheck, cx: &mut Context<Self>) {
        if self.analysis.latest.is_some() {
            return;
        }
        self.analysis.toggle(check);
        cx.notify();
    }

    fn select_recommended_analysis(&mut self, cx: &mut Context<Self>) {
        if self.analysis.latest.is_none() {
            self.analysis.select_recommended();
            cx.notify();
        }
    }

    fn select_all_analysis(&mut self, cx: &mut Context<Self>) {
        if self.analysis.latest.is_none() {
            self.analysis.select_all();
            cx.notify();
        }
    }

    fn clear_analysis_checks(&mut self, cx: &mut Context<Self>) {
        if self.analysis.latest.is_none() {
            self.analysis.clear_checks();
            cx.notify();
        }
    }

    fn select_analysis_result(&mut self, check: FileAnalysisCheck, cx: &mut Context<Self>) {
        if self
            .analysis
            .result
            .as_ref()
            .is_some_and(|result| result.findings.iter().any(|finding| finding.check == check))
        {
            self.analysis.selected = Some(check);
            cx.notify();
        }
    }

    fn begin_analysis(&mut self, cx: &mut Context<Self>) {
        if self.analysis_abort.is_some() {
            return;
        }
        let Some(binding) = self.model.binding().cloned() else {
            self.notice = Some(("没有可用的 SSH 目标，无法分析文件".into(), true));
            cx.notify();
            return;
        };
        let ssh_session = self
            .shared
            .read(cx)
            .active_ssh
            .as_ref()
            .filter(|active| {
                active.session.connection_id() == binding.connection_id
                    && active.session.session_id() == binding.session_id
                    && active.session.target() == &binding.target
            })
            .map(|active| active.session.clone());
        let Some(ssh_session) = ssh_session else {
            self.notice = Some(("SFTP 文件与当前 SSH 会话不再属于同一目标".into(), true));
            cx.notify();
            return;
        };
        let (lease, request) = match self
            .analysis
            .begin(self.model.activation_generation, binding)
        {
            Ok(value) => value,
            Err(error) => {
                self.notice = Some((format!("无法开始文件分析：{error}").into(), true));
                cx.notify();
                return;
            }
        };
        let service = self.services.file_analysis().clone();
        let task = self
            .tokio
            .spawn(async move { service.analyze(&ssh_session, &request).await });
        self.analysis_abort = Some(task.abort_handle());
        cx.spawn(async move |sftp, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(sftp) = sftp.upgrade() {
                    sftp.update(cx, |sftp, cx| sftp.finish_analysis(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_analysis(
        &mut self,
        lease: AnalysisLease,
        result: Result<CoreResult<FileAnalysisResult>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let current = self.current_binding(cx);
        let accepts = self.analysis.accepts(
            &lease,
            self.model.is_active(),
            self.model.activation_generation,
            current.as_ref(),
        );
        if !accepts {
            return;
        }
        self.analysis_abort = None;
        match result {
            Ok(Ok(result)) => {
                let _ = self.analysis.apply(
                    &lease,
                    self.model.is_active(),
                    self.model.activation_generation,
                    current.as_ref(),
                    result,
                );
                self.notice = Some(("文件安全分析完成".into(), false));
            }
            Ok(Err(error)) => {
                let _ = self.analysis.finish_failed(
                    &lease,
                    self.model.is_active(),
                    self.model.activation_generation,
                    current.as_ref(),
                );
                tracing::error!(%error, path = %lease.path.as_str(), "file analysis failed");
                self.notice = Some((format!("文件分析失败：{error}").into(), true));
            }
            Err(error) if error.is_cancelled() => {
                let _ = self.analysis.finish_failed(
                    &lease,
                    self.model.is_active(),
                    self.model.activation_generation,
                    current.as_ref(),
                );
                self.notice = Some(("文件分析已取消".into(), false));
            }
            Err(error) => {
                let _ = self.analysis.finish_failed(
                    &lease,
                    self.model.is_active(),
                    self.model.activation_generation,
                    current.as_ref(),
                );
                tracing::error!(%error, path = %lease.path.as_str(), "file analysis task failed");
                self.notice = Some((format!("文件分析任务失败：{error}").into(), true));
            }
        }
        cx.notify();
    }

    fn cancel_analysis(&mut self, cx: &mut Context<Self>) {
        if self.analysis_abort.is_none() {
            return;
        }
        self.abort_analysis();
        self.notice = Some(("文件分析已取消".into(), false));
        cx.notify();
    }

    fn queue_mutation(&mut self, mutation: SftpMutation, cx: &mut Context<Self>) {
        if self.operation_running_generation.is_some()
            || self.pending_operation.is_some()
            || self.extract_plan_abort.is_some()
        {
            return;
        }
        let (Some(session), Some(binding)) = (self.session.as_ref(), self.model.binding().cloned())
        else {
            self.notice = Some(("没有可用的 SFTP 会话".into(), true));
            cx.notify();
            return;
        };
        match self.services.sftp().plan(session, mutation) {
            Ok(operation) => {
                self.pending_operation = Some(PendingOperation {
                    operation,
                    activation_generation: self.model.activation_generation,
                    target: binding.target,
                });
                self.overlay = None;
                cx.notify();
            }
            Err(error) => {
                self.notice = Some((format!("操作计划失败：{error}").into(), true));
                cx.notify();
            }
        }
    }

    fn begin_extract_plan(&mut self, cx: &mut Context<Self>) {
        if self.operation_running_generation.is_some()
            || self.pending_operation.is_some()
            || self.extract_plan_abort.is_some()
        {
            return;
        }
        let (Some(session), Some(binding), Some(row)) = (
            self.session.clone(),
            self.model.binding().cloned(),
            self.model.selected_row().cloned(),
        ) else {
            self.notice = Some(("没有可用的 SFTP 会话或归档选择".into(), true));
            cx.notify();
            return;
        };
        if row.entry.metadata.kind != SftpFileKind::File
            || SftpService::suggested_extraction_destination(&row.entry.path).is_err()
        {
            self.notice = Some(("所选文件不是受支持的归档格式".into(), true));
            cx.notify();
            return;
        }
        let destination = match RemotePath::new(self.name_input.read(cx).value().to_string()) {
            Ok(path) => path,
            Err(error) => {
                self.notice = Some((format!("解压目标无效：{error}").into(), true));
                cx.notify();
                return;
            }
        };
        self.extract_plan_request_id = self.extract_plan_request_id.wrapping_add(1).max(1);
        let lease = ExtractPlanLease {
            activation_generation: self.model.activation_generation,
            request_id: self.extract_plan_request_id,
            binding,
            archive: row.entry.path,
            destination,
        };
        let service = self.services.sftp().clone();
        let archive = lease.archive.clone();
        let destination = lease.destination.clone();
        let task = self
            .tokio
            .spawn(async move { service.plan_extract(&session, archive, destination).await });
        self.extract_plan_abort = Some(task.abort_handle());
        self.overlay = None;
        self.notice = Some(("正在预检归档条目与远端内容摘要…".into(), false));
        cx.spawn(async move |sftp, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(sftp) = sftp.upgrade() {
                    sftp.update(cx, |sftp, cx| sftp.finish_extract_plan(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_extract_plan(
        &mut self,
        lease: ExtractPlanLease,
        result: Result<CoreResult<SftpPlannedOperation>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let current = self.current_binding(cx);
        let selected_path = self.model.selected_row().map(|row| &row.entry.path);
        let is_latest = lease.request_id == self.extract_plan_request_id;
        if is_latest {
            self.extract_plan_abort = None;
        }
        if !lease.accepts(
            self.model.is_active(),
            self.model.activation_generation,
            self.extract_plan_request_id,
            current.as_ref(),
            selected_path,
        ) {
            if is_latest {
                cx.notify();
            }
            return;
        }
        match result {
            Ok(Ok(operation)) => {
                self.pending_operation = Some(PendingOperation {
                    operation,
                    activation_generation: lease.activation_generation,
                    target: lease.binding.target,
                });
                self.notice = Some(("归档预检通过，等待危险操作确认".into(), false));
            }
            Ok(Err(error)) => {
                self.notice = Some((format!("归档预检失败：{error}").into(), true));
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.notice = Some((format!("归档预检任务失败：{error}").into(), true));
            }
        }
        cx.notify();
    }

    fn cancel_extract_plan(&mut self, cx: &mut Context<Self>) {
        if self.extract_plan_abort.is_none() {
            return;
        }
        self.abort_extract_plan();
        self.notice = Some(("归档预检已取消".into(), false));
        cx.notify();
    }

    fn approve_pending(&mut self, cx: &mut Context<Self>) {
        let Some(mut pending) = self.pending_operation.take() else {
            return;
        };
        let confirmation = DangerousConfirmation::approve(pending.operation.definition());
        if let Err(error) = pending.operation.confirm(confirmation) {
            self.notice = Some((format!("操作确认失败：{error}").into(), true));
            cx.notify();
            return;
        }
        let activation_generation = pending.activation_generation;
        self.operation_running_generation = Some(activation_generation);
        let target = pending.target;
        let task = self.tokio.spawn(async move {
            let result = pending.operation.execute_and_verify().await;
            let needs_restore = result
                .as_ref()
                .is_ok_and(|verification| !verification.passed)
                || pending.operation.state() == OperationState::VerificationFailed;
            if needs_restore {
                let restore_result = pending.operation.restore().await;
                let result = match restore_result {
                    Ok(()) => Err(CoreError::Validation {
                        subject: "SFTP verification",
                        message: "verification failed; the operation was restored".to_owned(),
                    }),
                    Err(error) => Err(error),
                };
                OperationCompletion {
                    operation: pending.operation,
                    result,
                }
            } else {
                OperationCompletion {
                    operation: pending.operation,
                    result,
                }
            }
        });
        cx.spawn(async move |sftp, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(sftp) = sftp.upgrade() {
                    sftp.update(cx, |sftp, cx| {
                        sftp.finish_operation(activation_generation, target, result, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_operation(
        &mut self,
        activation_generation: u64,
        target: TargetGuard,
        result: Result<OperationCompletion, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let current = self.current_binding(cx);
        let applies = self.model.is_active()
            && self.model.activation_generation == activation_generation
            && current
                .as_ref()
                .is_some_and(|binding| binding.target == target);
        if !applies {
            if self.operation_running_generation == Some(activation_generation) {
                self.operation_running_generation = None;
                cx.notify();
            }
            return;
        }
        self.operation_running_generation = None;
        match result {
            Ok(OperationCompletion {
                operation: _,
                result: Ok(verification),
            }) => {
                self.notice = Some((verification.detail.into(), false));
                self.refresh(cx);
            }
            Ok(OperationCompletion {
                operation,
                result: Err(error),
            }) => {
                self.notice = Some((
                    format!(
                        "SFTP 操作未完整通过（状态 {:?}）：{error}",
                        operation.state()
                    )
                    .into(),
                    true,
                ));
                self.refresh(cx);
            }
            Err(error) => {
                self.notice = Some((format!("SFTP 操作任务失败：{error}").into(), true));
            }
        }
        cx.notify();
    }

    fn cancel_pending(&mut self, cx: &mut Context<Self>) {
        self.pending_operation = None;
        cx.notify();
    }

    fn save_overlay(&mut self, cx: &mut Context<Self>) {
        let Some(overlay) = self.overlay else {
            return;
        };
        if overlay == Overlay::Extract {
            self.begin_extract_plan(cx);
            return;
        }
        let mutation = match overlay {
            Overlay::Edit => {
                let Some(path) = self.editor_path.clone() else {
                    return;
                };
                let content = self.editor_input.read(cx).value().as_bytes().to_vec();
                if content.len() as u64 > MAX_EDIT_BYTES {
                    self.notice = Some(("编辑内容超过 2 MiB 限制".into(), true));
                    cx.notify();
                    return;
                }
                SftpMutation::AtomicWrite { path, content }
            }
            Overlay::CreateFile => {
                let name = self.name_input.read(cx).value().to_string();
                let path = match self.model.path().child(&name) {
                    Ok(path) => path,
                    Err(error) => {
                        self.notice = Some((format!("文件名无效：{error}").into(), true));
                        cx.notify();
                        return;
                    }
                };
                let content = self.editor_input.read(cx).value().as_bytes().to_vec();
                SftpMutation::CreateFile {
                    path,
                    content,
                    mode: None,
                }
            }
            Overlay::CreateDirectory => {
                let name = self.name_input.read(cx).value().to_string();
                let path = match self.model.path().child(&name) {
                    Ok(path) => path,
                    Err(error) => {
                        self.notice = Some((format!("目录名无效：{error}").into(), true));
                        cx.notify();
                        return;
                    }
                };
                SftpMutation::CreateDirectory { path }
            }
            Overlay::Rename => {
                let Some(row) = self.model.selected_row() else {
                    return;
                };
                let name = self.name_input.read(cx).value().to_string();
                let to = match self.model.path().child(&name) {
                    Ok(path) => path,
                    Err(error) => {
                        self.notice = Some((format!("新名称无效：{error}").into(), true));
                        cx.notify();
                        return;
                    }
                };
                SftpMutation::Rename {
                    from: row.entry.path.clone(),
                    to,
                }
            }
            Overlay::Chmod => {
                let Some(row) = self.model.selected_row() else {
                    return;
                };
                let value = self.mode_input.read(cx).value().to_string();
                let Ok(mode) = u32::from_str_radix(value.trim_start_matches("0o"), 8) else {
                    self.notice = Some(("权限必须是 0000..7777 的八进制数".into(), true));
                    cx.notify();
                    return;
                };
                SftpMutation::Chmod {
                    path: row.entry.path.clone(),
                    mode,
                }
            }
            Overlay::Viewer | Overlay::Analysis | Overlay::History | Overlay::Extract => return,
        };
        self.queue_mutation(mutation, cx);
    }

    fn remove_selected(&mut self, cx: &mut Context<Self>) {
        let Some(row) = self.model.selected_row() else {
            return;
        };
        self.queue_mutation(
            SftpMutation::Remove {
                path: row.entry.path.clone(),
            },
            cx,
        );
    }

    fn compress_selected(&mut self, cx: &mut Context<Self>) {
        let Some(row) = self.model.selected_row() else {
            return;
        };
        let destination = match self
            .model
            .path()
            .child(&format!("{}.tar.gz", row.entry.name))
        {
            Ok(path) => path,
            Err(error) => {
                self.notice = Some((format!("归档路径无效：{error}").into(), true));
                cx.notify();
                return;
            }
        };
        self.queue_mutation(
            SftpMutation::CreateArchive {
                sources: vec![row.entry.path.clone()],
                destination,
                format: ArchiveFormat::TarGzip,
            },
            cx,
        );
    }

    fn request_upload(&mut self, cx: &mut Context<Self>) {
        let Some(session) = self.session.clone() else {
            return;
        };
        let Some(binding) = self.model.binding().cloned() else {
            return;
        };
        let directory = self.model.path().clone();
        let receiver = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some("选择要上传的文件".into()),
        });
        let paths = match self.services.path_guard([]) {
            Ok(paths) => paths,
            Err(error) => {
                self.notice = Some((format!("无法准备上传目录：{error}").into(), true));
                return;
            }
        };
        let service = self.services.sftp().clone();
        let tokio = self.tokio.clone();
        cx.spawn(async move |sftp, cx| {
            let selection = receiver.await;
            let selected = match selection {
                Ok(Ok(Some(mut paths))) if paths.len() == 1 => paths.remove(0),
                Ok(Ok(None)) => return,
                Ok(Ok(Some(_))) => {
                    let _ = cx.update(|cx| {
                        if let Some(sftp) = sftp.upgrade() {
                            sftp.update(cx, |sftp, cx| {
                                sftp.notice = Some(("上传一次只允许选择一个文件".into(), true));
                                cx.notify();
                            });
                        }
                    });
                    return;
                }
                Ok(Err(error)) => {
                    let message = error.to_string();
                    let _ = cx.update(|cx| {
                        if let Some(sftp) = sftp.upgrade() {
                            sftp.update(cx, |sftp, cx| {
                                sftp.notice =
                                    Some((format!("文件选择失败：{message}").into(), true));
                                cx.notify();
                            });
                        }
                    });
                    return;
                }
                Err(error) => {
                    let message = error.to_string();
                    let _ = cx.update(|cx| {
                        if let Some(sftp) = sftp.upgrade() {
                            sftp.update(cx, |sftp, cx| {
                                sftp.notice =
                                    Some((format!("文件选择已取消：{message}").into(), true));
                                cx.notify();
                            });
                        }
                    });
                    return;
                }
            };
            let Some(name) = selected
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_owned)
            else {
                return;
            };
            let remote_path = match directory.child(&name) {
                Ok(path) => path,
                Err(_) => return,
            };
            let stage_paths = paths.clone();
            let task = tokio.spawn(async move {
                tokio::task::spawn_blocking(move || {
                    stage_paths.stage_native_selected_upload(&selected, MAX_TRANSFER_BYTES)
                })
                .await
                .map_err(|error| CoreError::Validation {
                    subject: "upload staging task",
                    message: error.to_string(),
                })?
            });
            let staged = match task.await {
                Ok(Ok(path)) => path,
                Ok(Err(error)) => {
                    let _ = cx.update(|cx| {
                        if let Some(sftp) = sftp.upgrade() {
                            sftp.update(cx, |sftp, cx| {
                                sftp.notice = Some((format!("上传暂存失败：{error}").into(), true));
                                cx.notify();
                            });
                        }
                    });
                    return;
                }
                Err(error) => {
                    let _ = cx.update(|cx| {
                        if let Some(sftp) = sftp.upgrade() {
                            sftp.update(cx, |sftp, cx| {
                                sftp.notice =
                                    Some((format!("上传暂存任务失败：{error}").into(), true));
                                cx.notify();
                            });
                        }
                    });
                    return;
                }
            };
            let _ = cx.update(|cx| {
                if let Some(sftp) = sftp.upgrade() {
                    sftp.update(cx, |sftp, cx| {
                        if !sftp.model.is_active() || sftp.model.binding() != Some(&binding) {
                            let _ = std::fs::remove_file(&staged);
                            return;
                        }
                        match service.plan_upload(&session, &paths, &staged, remote_path) {
                            Ok(operation) => {
                                sftp.pending_operation = Some(PendingOperation {
                                    operation,
                                    activation_generation: sftp.model.activation_generation,
                                    target: binding.target,
                                });
                            }
                            Err(error) => {
                                let _ = std::fs::remove_file(&staged);
                                sftp.notice = Some((format!("上传计划失败：{error}").into(), true));
                            }
                        }
                        cx.notify();
                    });
                } else {
                    let _ = std::fs::remove_file(&staged);
                }
            });
        })
        .detach();
    }

    fn request_download(&mut self, cx: &mut Context<Self>) {
        let Some(row) = self.model.selected_row().cloned() else {
            return;
        };
        if row.entry.metadata.kind != SftpFileKind::File {
            self.notice = Some(("当前安全子集不下载目录或符号链接".into(), true));
            cx.notify();
            return;
        }
        let Some(session) = self.session.clone() else {
            return;
        };
        let binding = self.model.binding().cloned();
        let initial = self.services.store().root().to_path_buf();
        let receiver = cx.prompt_for_new_path(&initial, Some(&row.entry.name));
        let paths = match self.services.path_guard(local_sensitive_roots()) {
            Ok(paths) => paths,
            Err(error) => {
                self.notice = Some((format!("无法准备下载路径校验：{error}").into(), true));
                return;
            }
        };
        let service = self.services.sftp().clone();
        let remote_path = row.entry.path;
        let task_bridge = self.tokio.clone();
        cx.spawn(async move |sftp, cx| {
            let selection = receiver.await;
            let selected = match selection {
                Ok(Ok(Some(path))) => path,
                Ok(Ok(None)) => return,
                Ok(Err(error)) => {
                    let message = error.to_string();
                    let _ = cx.update(|cx| {
                        if let Some(sftp) = sftp.upgrade() {
                            sftp.update(cx, |sftp, cx| {
                                sftp.notice =
                                    Some((format!("保存路径选择失败：{message}").into(), true));
                                cx.notify();
                            });
                        }
                    });
                    return;
                }
                Err(error) => {
                    let message = error.to_string();
                    let _ = cx.update(|cx| {
                        if let Some(sftp) = sftp.upgrade() {
                            sftp.update(cx, |sftp, cx| {
                                sftp.notice =
                                    Some((format!("保存路径选择已取消：{message}").into(), true));
                                cx.notify();
                            });
                        }
                    });
                    return;
                }
            };
            let selected_for_result = selected.clone();
            let task = task_bridge.spawn(async move {
                service
                    .download_new(&session, &paths, &remote_path, &selected)
                    .await
            });
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(sftp) = sftp.upgrade() {
                    sftp.update(cx, |sftp, cx| {
                        if !sftp.model.is_active() || sftp.model.binding() != binding.as_ref() {
                            if let Ok(Ok(receipt)) = &result
                                && let Some(path) = &receipt.local_path
                            {
                                let _ = std::fs::remove_file(path);
                            }
                            return;
                        }
                        sftp.notice = Some(match result {
                            Ok(Ok(receipt)) => (
                                format!(
                                    "已下载 {} 字节到 {}",
                                    receipt.bytes,
                                    selected_for_result.display()
                                )
                                .into(),
                                false,
                            ),
                            Ok(Err(error)) => (format!("下载失败：{error}").into(), true),
                            Err(error) => (format!("下载任务失败：{error}").into(), true),
                        });
                        cx.notify();
                    });
                }
            });
        })
        .detach();
    }

    fn copy_selected_path(&mut self, cx: &mut Context<Self>) {
        let Some(row) = self.model.selected_row() else {
            return;
        };
        cx.write_to_clipboard(ClipboardItem::new_string(
            row.entry.path.as_str().to_owned(),
        ));
        self.notice = Some(("远端绝对路径已复制".into(), false));
        cx.notify();
    }

    fn copy_selected_name(&mut self, cx: &mut Context<Self>) {
        let Some(row) = self.model.selected_row() else {
            return;
        };
        cx.write_to_clipboard(ClipboardItem::new_string(row.entry.name.clone()));
        self.notice = Some(("文件名已复制".into(), false));
        cx.notify();
    }

    fn open_selected_in_terminal(&mut self, cx: &mut Context<Self>) {
        let Some(binding) = self.model.binding().cloned() else {
            self.notice = Some(("当前 SFTP 目标已失效".into(), true));
            cx.notify();
            return;
        };
        let Some(session) = self.session.as_ref() else {
            self.notice = Some(("SFTP 会话尚未就绪".into(), true));
            cx.notify();
            return;
        };
        if session.target() != &binding.target
            || self.services.target().validate(&binding.target).is_err()
        {
            self.notice = Some(("目标已切换，已拒绝打开目录终端".into(), true));
            cx.notify();
            return;
        }
        let directory = match selected_terminal_directory(&self.model) {
            Ok(directory) => directory,
            Err(error) => {
                self.notice = Some((format!("无法打开目录终端：{error}").into(), true));
                cx.notify();
                return;
            }
        };
        self.notice = Some((
            format!("正在 SSH 终端中打开 {}", directory.as_str()).into(),
            false,
        ));
        cx.emit(SftpWindowEvent::OpenDirectoryTerminal(
            OpenDirectoryTerminalIntent {
                target: binding.target,
                path: directory,
            },
        ));
        cx.notify();
    }

    fn open_context_menu(
        &mut self,
        file_id: FileId,
        position: Point<Pixels>,
        cx: &mut Context<Self>,
    ) {
        if !self.model.select(file_id.clone()) {
            self.context_menu = None;
            return;
        }
        let Some(lease) = SftpContextMenuLease::capture(&self.model, file_id) else {
            self.context_menu = None;
            return;
        };
        self.context_menu = Some(SftpContextMenuState { lease, position });
        cx.notify();
    }

    fn dismiss_context_menu_on_key_down(
        &mut self,
        event: &KeyDownEvent,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if event.keystroke.key == "escape" && self.context_menu.take().is_some() {
            cx.stop_propagation();
            cx.notify();
        }
    }

    fn dispatch_context_action(
        &mut self,
        lease: SftpContextMenuLease,
        action: SftpContextAction,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.context_menu = None;
        if !lease.accepts(&self.model) || !self.model.select(lease.file_id.clone()) {
            self.notice = Some(("目录内容或目标已变化，已取消右键操作".into(), true));
            cx.notify();
            return;
        }
        let Some(row) = self.model.selected_row().cloned() else {
            self.notice = Some(("所选文件已不存在，请刷新后重试".into(), true));
            cx.notify();
            return;
        };
        let busy = self.operation_running_generation.is_some()
            || self.pending_operation.is_some()
            || self.extract_plan_abort.is_some();
        if !action.available(&row, busy, self.session.is_some()) {
            self.notice = Some(("当前文件类型或操作状态不允许执行此动作".into(), true));
            cx.notify();
            return;
        }
        match action {
            SftpContextAction::Open => self.open_selected(window, cx),
            SftpContextAction::Details => cx.notify(),
            SftpContextAction::Analyze => self.open_analysis(cx),
            SftpContextAction::Download => self.request_download(cx),
            SftpContextAction::Rename => self.show_overlay(Overlay::Rename, window, cx),
            SftpContextAction::Chmod => self.show_overlay(Overlay::Chmod, window, cx),
            SftpContextAction::Compress => self.compress_selected(cx),
            SftpContextAction::Extract => self.show_overlay(Overlay::Extract, window, cx),
            SftpContextAction::CopyPath => self.copy_selected_path(cx),
            SftpContextAction::CopyName => self.copy_selected_name(cx),
            SftpContextAction::OpenTerminal => self.open_selected_in_terminal(cx),
            SftpContextAction::Delete => self.remove_selected(cx),
        }
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
        let row = self
            .model
            .rows
            .iter()
            .find(|row| row.id == state.lease.file_id)
            .cloned()?;
        let busy = self.operation_running_generation.is_some()
            || self.pending_operation.is_some()
            || self.extract_plan_abort.is_some();
        let session_ready = self.session.is_some();
        let identity = bounded_context_label(&row.entry.name);
        let kind = row.entry.metadata.kind;
        let menu = div()
            .id("sftp-row-context-menu")
            .w(px(248.0))
            .max_h(px(520.0))
            .overflow_y_scrollbar()
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
                    .child(format!("{} · {}", kind_label(kind), identity)),
            )
            .children(SftpContextAction::ALL.into_iter().map(|action| {
                let available = action.available(&row, busy, session_ready);
                let lease = state.lease.clone();
                let button = crate::buttons::button(action.id())
                    .label(action.label(kind))
                    .w_full()
                    .justify_start()
                    .disabled(!available)
                    .on_click(cx.listener(move |this, _, window, cx| {
                        this.dispatch_context_action(lease.clone(), action, window, cx);
                    }));
                div()
                    .when(action.starts_section(), |section| {
                        section
                            .mt_1()
                            .pt_1()
                            .border_t_1()
                            .border_color(tokens.border)
                    })
                    .child(if action == SftpContextAction::Delete {
                        button.danger()
                    } else {
                        button.ghost()
                    })
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
}

fn selected_terminal_directory(model: &SftpModel) -> CoreResult<RemotePath> {
    let row = model.selected_row().ok_or_else(|| CoreError::Validation {
        subject: "SFTP directory terminal",
        message: "no file or directory is selected".to_owned(),
    })?;
    match row.entry.metadata.kind {
        SftpFileKind::Directory => Ok(row.entry.path.clone()),
        SftpFileKind::File => Ok(model.path().clone()),
        SftpFileKind::Symlink | SftpFileKind::Other => Err(CoreError::Validation {
            subject: "SFTP directory terminal",
            message: "symbolic links and special files are not followed".to_owned(),
        }),
    }
}

fn local_sensitive_roots() -> Vec<PathBuf> {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .map(|path| sensitive_roots_for_home(&path))
        .unwrap_or_default()
}

impl Render for SftpWindow {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens = self.shared.read(cx).theme.tokens();
        let binding = self
            .model
            .binding()
            .map(|binding| {
                format!(
                    "{} · generation {}",
                    binding.target.identity.as_str(),
                    binding.target.generation
                )
            })
            .unwrap_or_else(|| "未连接目标".to_owned());
        let rows = self
            .model
            .visible_rows()
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        let selected = self.model.selected_row().cloned();
        let notice = self.notice.clone();
        let loading = self.loading || self.bind_abort.is_some();
        let planning_extract = self.extract_plan_abort.is_some();
        let busy = self.operation_running_generation.is_some()
            || self.pending_operation.is_some()
            || planning_extract;
        let context_menu = self.render_context_menu(tokens, window, cx);

        div()
            .id("sftp-native-window")
            .on_key_down(cx.listener(Self::dismiss_context_menu_on_key_down))
            .size_full()
            .relative()
            .flex()
            .flex_col()
            .gap_3()
            .bg(tokens.background)
            .text_color(tokens.text)
            .p_4()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(
                        div()
                            .flex_1()
                            .child(div().text_2xl().child("SFTP 文件调查"))
                            .child(div().text_xs().text_color(tokens.muted).child(binding)),
                    )
                    .child(
                        crate::buttons::button("sftp-refresh")
                            .label(if loading { "刷新中…" } else { "刷新" })
                            .small()
                            .disabled(self.session.is_none() || loading)
                            .on_click(cx.listener(|this, _, _, cx| this.refresh(cx))),
                    )
                    .child(
                        crate::buttons::button("sftp-upload")
                            .label("上传")
                            .small()
                            .primary()
                            .disabled(self.session.is_none() || busy)
                            .on_click(cx.listener(|this, _, _, cx| this.request_upload(cx))),
                    )
                    .child(
                        crate::buttons::button("sftp-new-file")
                            .label("新建文件")
                            .small()
                            .disabled(self.session.is_none() || busy)
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.show_overlay(Overlay::CreateFile, window, cx)
                            })),
                    )
                    .child(
                        crate::buttons::button("sftp-new-directory")
                            .label("新建目录")
                            .small()
                            .disabled(self.session.is_none() || busy)
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.show_overlay(Overlay::CreateDirectory, window, cx)
                            })),
                    )
                    .child(
                        crate::buttons::button("sftp-history")
                            .label("操作历史")
                            .small()
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.show_overlay(Overlay::History, window, cx)
                            })),
                    ),
            )
            .when_some(notice, |view, (message, error)| {
                view.child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .rounded_md()
                        .border_1()
                        .border_color(if error { tokens.danger } else { tokens.success })
                        .p_2()
                        .text_sm()
                        .text_color(if error { tokens.danger } else { tokens.success })
                        .child(div().flex_1().child(message))
                        .when(planning_extract, |notice| {
                            notice.child(
                                crate::buttons::button("sftp-cancel-extract-plan")
                                    .label("取消预检")
                                    .small()
                                    .on_click(
                                        cx.listener(|this, _, _, cx| this.cancel_extract_plan(cx)),
                                    ),
                            )
                        }),
                )
            })
            .child(self.render_path_bar(tokens, cx))
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .flex()
                    .gap_3()
                    .child(self.render_rows(rows, tokens, cx))
                    .when_some(selected, |view, row| {
                        view.child(self.render_details(row, tokens, cx))
                    }),
            )
            .when_some(self.overlay, |view, overlay| {
                view.child(self.render_overlay(overlay, tokens, cx))
            })
            .when(self.pending_operation.is_some(), |view| {
                view.child(self.render_confirmation(tokens, cx))
            })
            .when_some(context_menu, |view, menu| view.child(menu))
    }
}

impl SftpWindow {
    fn render_path_bar(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let path = self.model.path().clone();
        let parent = path.parent().ok();
        let breadcrumbs = breadcrumb_paths(&path);
        div()
            .rounded_lg()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .p_2()
            .flex()
            .items_center()
            .gap_2()
            .child(
                crate::buttons::button("sftp-parent")
                    .label("上级")
                    .xsmall()
                    .disabled(path.as_str() == "/")
                    .on_click(cx.listener(move |this, _, _, cx| {
                        if let Some(parent) = parent.clone() {
                            this.navigate_to(parent, cx);
                        }
                    })),
            )
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .flex()
                    .items_center()
                    .gap_1()
                    .overflow_x_scrollbar()
                    .children(breadcrumbs.into_iter().enumerate().map(|(index, path)| {
                        let label = if path.as_str() == "/" {
                            "/".to_owned()
                        } else {
                            path.file_name().unwrap_or("?").to_owned()
                        };
                        crate::buttons::button(SharedString::from(format!("sftp-crumb-{index}")))
                            .label(label)
                            .xsmall()
                            .on_click(
                                cx.listener(move |this, _, _, cx| {
                                    this.navigate_to(path.clone(), cx)
                                }),
                            )
                    })),
            )
            .child(
                div()
                    .w(px(260.0))
                    .child(Input::new(&self.search_input).small()),
            )
            .into_any_element()
    }

    fn render_rows(
        &self,
        rows: Vec<SftpRow>,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let selected = self.model.selected.clone();
        let filtered_count = self.model.filtered_count();
        let start = self.model.row_window_start;
        let end = (start + rows.len()).min(filtered_count);
        div()
            .flex_1()
            .min_w_0()
            .min_h_0()
            .rounded_lg()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .flex()
            .flex_col()
            .child(
                div()
                    .p_2()
                    .border_b_1()
                    .border_color(tokens.border)
                    .flex()
                    .items_center()
                    .gap_2()
                    .children(SftpSort::ALL.into_iter().map(|sort| {
                        let active = self.model.sort == sort;
                        crate::buttons::button(SharedString::from(format!("sftp-sort-{sort:?}")))
                            .label(if active {
                                format!(
                                    "{} {}",
                                    sort.label(),
                                    if self.model.ascending { "↑" } else { "↓" }
                                )
                            } else {
                                sort.label().to_owned()
                            })
                            .xsmall()
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.context_menu = None;
                                this.model.set_sort(sort);
                                cx.notify();
                            }))
                    }))
                    .child(div().flex_1())
                    .child(
                        div()
                            .text_xs()
                            .text_color(tokens.muted)
                            .child(if filtered_count == 0 {
                                "目录为空".to_owned()
                            } else {
                                format!("{}–{} / {}", start + 1, end, filtered_count)
                            }),
                    )
                    .child(
                        crate::buttons::button("sftp-window-previous")
                            .label("上一段")
                            .xsmall()
                            .disabled(start == 0)
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.context_menu = None;
                                this.model.scroll_window(-1);
                                cx.notify();
                            })),
                    )
                    .child(
                        crate::buttons::button("sftp-window-next")
                            .label("下一段")
                            .xsmall()
                            .disabled(end >= filtered_count)
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.context_menu = None;
                                this.model.scroll_window(1);
                                cx.notify();
                            })),
                    ),
            )
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scrollbar()
                    .when(rows.is_empty(), |list| {
                        list.child(div().p_6().text_color(tokens.muted).child(if self.loading {
                            "正在读取目录…"
                        } else {
                            "没有匹配的条目"
                        }))
                    })
                    .children(rows.into_iter().enumerate().map(|(index, row)| {
                        let id = row.id.clone();
                        let right_click_id = id.clone();
                        let is_selected = selected.as_ref() == Some(&id);
                        let kind_icon = file_kind_icon(row.entry.metadata.kind);
                        let size = format_size(row.entry.metadata.size);
                        let permissions = row
                            .entry
                            .metadata
                            .permissions
                            .map(|mode| format!("{:04o}", mode & 0o7777))
                            .unwrap_or_else(|| "—".to_owned());
                        let modified = row
                            .entry
                            .metadata
                            .modified_at
                            .map(|time| time.format("%Y-%m-%d %H:%M:%S").to_string())
                            .unwrap_or_else(|| "—".to_owned());
                        div()
                            .id(SharedString::from(format!("sftp-row-{index}")))
                            .p_2()
                            .border_b_1()
                            .border_color(tokens.border)
                            .cursor_pointer()
                            .when(is_selected, |item| item.bg(tokens.surface_alt))
                            .hover(|item| item.bg(tokens.surface_alt))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.context_menu = None;
                                let _ = this.model.select(id.clone());
                                cx.notify();
                            }))
                            .on_mouse_down(
                                MouseButton::Right,
                                cx.listener(move |this, event: &MouseDownEvent, _, cx| {
                                    this.open_context_menu(
                                        right_click_id.clone(),
                                        event.position,
                                        cx,
                                    );
                                }),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_3()
                                    .child(
                                        div()
                                            .w(px(20.0))
                                            .flex_none()
                                            .flex()
                                            .justify_center()
                                            .child(
                                                Icon::new(kind_icon)
                                                    .size_4()
                                                    .text_color(tokens.muted),
                                            ),
                                    )
                                    .child(div().flex_1().min_w_0().child(row.entry.name.clone()))
                                    .child(
                                        div()
                                            .w(px(90.0))
                                            .text_xs()
                                            .text_color(tokens.muted)
                                            .child(size),
                                    )
                                    .child(
                                        div()
                                            .w(px(70.0))
                                            .text_xs()
                                            .text_color(tokens.muted)
                                            .child(permissions),
                                    )
                                    .child(
                                        div()
                                            .w(px(150.0))
                                            .text_xs()
                                            .text_color(tokens.muted)
                                            .child(modified),
                                    ),
                            )
                    })),
            )
            .into_any_element()
    }

    fn render_details(
        &self,
        row: SftpRow,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let is_file = row.entry.metadata.kind == SftpFileKind::File;
        let is_directory = row.entry.metadata.kind == SftpFileKind::Directory;
        let can_extract =
            is_file && SftpService::suggested_extraction_destination(&row.entry.path).is_ok();
        let busy = self.operation_running_generation.is_some()
            || self.pending_operation.is_some()
            || self.extract_plan_abort.is_some();
        div()
            .w(px(330.0))
            .flex_none()
            .min_h_0()
            .overflow_y_scrollbar()
            .rounded_lg()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .p_3()
            .child(div().text_lg().child(row.entry.name.clone()))
            .child(
                div()
                    .mt_1()
                    .text_xs()
                    .text_color(tokens.muted)
                    .child(row.entry.path.as_str().to_owned()),
            )
            .child(self.render_metadata(&row.entry.metadata, tokens))
            .child(
                div()
                    .mt_3()
                    .flex()
                    .flex_wrap()
                    .gap_2()
                    .child(
                        crate::buttons::button("sftp-open-selected")
                            .label(if is_directory { "进入" } else { "查看" })
                            .small()
                            .disabled(!(is_file || is_directory))
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.open_selected(window, cx)
                            })),
                    )
                    .child(
                        crate::buttons::button("sftp-edit-selected")
                            .label("编辑")
                            .small()
                            .disabled(!is_file || busy)
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.read_selected(true, window, cx)
                            })),
                    )
                    .child(
                        crate::buttons::button("sftp-download-selected")
                            .label("下载")
                            .small()
                            .disabled(!is_file)
                            .on_click(cx.listener(|this, _, _, cx| this.request_download(cx))),
                    )
                    .child(
                        crate::buttons::button("sftp-rename-selected")
                            .label("重命名")
                            .small()
                            .disabled(busy)
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.show_overlay(Overlay::Rename, window, cx)
                            })),
                    )
                    .child(
                        crate::buttons::button("sftp-chmod-selected")
                            .label("权限")
                            .small()
                            .disabled(busy)
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.show_overlay(Overlay::Chmod, window, cx)
                            })),
                    )
                    .child(
                        crate::buttons::button("sftp-compress-selected")
                            .label("压缩")
                            .small()
                            .disabled(busy)
                            .on_click(cx.listener(|this, _, _, cx| this.compress_selected(cx))),
                    )
                    .child(
                        crate::buttons::button("sftp-extract-selected")
                            .label(if self.extract_plan_abort.is_some() {
                                "预检中…"
                            } else {
                                "解压"
                            })
                            .small()
                            .disabled(!can_extract || busy)
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.show_overlay(Overlay::Extract, window, cx)
                            })),
                    )
                    .child(
                        crate::buttons::button("sftp-analyze-selected")
                            .label("安全分析")
                            .small()
                            .disabled(!is_file)
                            .on_click(cx.listener(|this, _, _, cx| this.open_analysis(cx))),
                    )
                    .child(
                        crate::buttons::button("sftp-terminal-selected")
                            .label("在终端打开")
                            .small()
                            .disabled(!(is_file || is_directory) || self.session.is_none())
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.open_selected_in_terminal(cx)
                            })),
                    )
                    .child(
                        crate::buttons::button("sftp-copy-path")
                            .label("复制路径")
                            .small()
                            .on_click(cx.listener(|this, _, _, cx| this.copy_selected_path(cx))),
                    )
                    .child(
                        crate::buttons::button("sftp-delete-selected")
                            .label("删除")
                            .small()
                            .danger()
                            .disabled(busy)
                            .on_click(cx.listener(|this, _, _, cx| this.remove_selected(cx))),
                    ),
            )
            .child(
                div()
                    .mt_3()
                    .text_xs()
                    .text_color(tokens.muted)
                    .child(
                        "远端名称与内容始终作为文本节点渲染；符号链接默认不跟随。删除会移动到可恢复备份命名空间。",
                    ),
            )
            .into_any_element()
    }

    fn render_metadata(&self, metadata: &SftpMetadata, tokens: ThemeTokens) -> AnyElement {
        let fields = [
            ("类型", kind_label(metadata.kind).to_owned()),
            ("大小", format_size(metadata.size)),
            (
                "权限",
                metadata
                    .permissions
                    .map(|mode| format!("{:04o}", mode & 0o7777))
                    .unwrap_or_else(|| "—".to_owned()),
            ),
            (
                "UID/GID",
                format!(
                    "{}/{}",
                    metadata
                        .uid
                        .map_or_else(|| "—".to_owned(), |id| id.to_string()),
                    metadata
                        .gid
                        .map_or_else(|| "—".to_owned(), |id| id.to_string())
                ),
            ),
        ];
        div()
            .mt_3()
            .rounded_md()
            .border_1()
            .border_color(tokens.border)
            .children(fields.into_iter().map(|(label, value)| {
                div()
                    .p_2()
                    .border_b_1()
                    .border_color(tokens.border)
                    .child(div().text_xs().text_color(tokens.muted).child(label))
                    .child(div().text_sm().child(value))
            }))
            .into_any_element()
    }

    fn render_overlay(
        &self,
        overlay: Overlay,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let (title, message): (&str, Option<&str>) = match overlay {
            Overlay::Viewer => ("文件查看", None),
            Overlay::Edit => (
                "原子编辑",
                Some("保存将先备份原文件，再以临时文件原子替换。"),
            ),
            Overlay::CreateFile => ("新建文件", Some("目标必须不存在；创建后会读回验证。")),
            Overlay::CreateDirectory => ("新建目录", Some("目标必须不存在。")),
            Overlay::Rename => ("重命名", Some("新目标必须不存在。")),
            Overlay::Chmod => ("修改权限", Some("原权限会记录为恢复令牌。")),
            Overlay::Analysis => (
                "文件安全分析",
                Some("仅执行闭集只读检查；结果绑定当前目标、会话代次与远端绝对路径。"),
            ),
            Overlay::History => ("SFTP 操作历史", None),
            Overlay::Extract => (
                "安全解压",
                Some(
                    "目标必须是不存在的绝对路径。执行前会验证格式、归档 SHA-256、条目路径与类型；不允许链接、设备或覆盖。",
                ),
            ),
        };
        let body = match overlay {
            Overlay::Viewer => div()
                .h(px(420.0))
                .overflow_y_scrollbar()
                .rounded_md()
                .border_1()
                .border_color(tokens.border)
                .bg(tokens.terminal_background)
                .p_3()
                .font_family("Cascadia Mono")
                .text_sm()
                .child(self.loaded_text.clone())
                .into_any_element(),
            Overlay::Edit => div()
                .h(px(420.0))
                .child(Input::new(&self.editor_input))
                .into_any_element(),
            Overlay::CreateFile => div()
                .flex()
                .flex_col()
                .gap_2()
                .child(Input::new(&self.name_input).small())
                .child(div().h(px(320.0)).child(Input::new(&self.editor_input)))
                .into_any_element(),
            Overlay::CreateDirectory | Overlay::Rename => div()
                .child(Input::new(&self.name_input).small())
                .into_any_element(),
            Overlay::Chmod => div()
                .child(Input::new(&self.mode_input).small())
                .into_any_element(),
            Overlay::Analysis => self.render_analysis(tokens, cx),
            Overlay::History => self.render_history(tokens),
            Overlay::Extract => div()
                .flex()
                .flex_col()
                .gap_2()
                .child(
                    div()
                        .text_xs()
                        .text_color(tokens.muted)
                        .child("新建目标目录"),
                )
                .child(Input::new(&self.name_input))
                .child(
                    div()
                        .text_xs()
                        .text_color(tokens.warning)
                        .child("解压后若目录内容发生变化，自动恢复会拒绝删除该目录。"),
                )
                .into_any_element(),
        };
        let can_save = matches!(
            overlay,
            Overlay::Edit
                | Overlay::CreateFile
                | Overlay::CreateDirectory
                | Overlay::Rename
                | Overlay::Chmod
                | Overlay::Extract
        );
        div()
            .absolute()
            .inset_0()
            .bg(gpui::rgba(0x000000aa))
            .flex()
            .items_center()
            .justify_center()
            .child(
                div()
                    .w(if overlay == Overlay::Analysis {
                        px(1040.0)
                    } else {
                        px(760.0)
                    })
                    .max_h(if overlay == Overlay::Analysis {
                        px(720.0)
                    } else {
                        px(620.0)
                    })
                    .rounded_lg()
                    .border_1()
                    .border_color(tokens.border)
                    .bg(tokens.surface)
                    .p_4()
                    .child(div().text_xl().child(title))
                    .when_some(message, |panel, message| {
                        panel.child(
                            div()
                                .mt_1()
                                .mb_3()
                                .text_xs()
                                .text_color(tokens.muted)
                                .child(message),
                        )
                    })
                    .child(body)
                    .child(
                        div()
                            .mt_3()
                            .flex()
                            .justify_end()
                            .gap_2()
                            .when(overlay == Overlay::Viewer, |actions| {
                                actions.child(
                                    crate::buttons::button("sftp-viewer-edit")
                                        .label("编辑")
                                        .small()
                                        .on_click(cx.listener(|this, _, window, cx| {
                                            this.begin_edit_from_viewer(window, cx)
                                        })),
                                )
                            })
                            .when(can_save, |actions| {
                                actions.child(
                                    crate::buttons::button("sftp-overlay-save")
                                        .label(if overlay == Overlay::Extract {
                                            "预检并生成操作计划"
                                        } else {
                                            "生成危险操作计划"
                                        })
                                        .small()
                                        .primary()
                                        .on_click(
                                            cx.listener(|this, _, _, cx| this.save_overlay(cx)),
                                        ),
                                )
                            })
                            .when(overlay == Overlay::Analysis, |actions| {
                                actions
                                    .child(
                                        crate::buttons::button("sftp-analysis-run")
                                            .label(if self.analysis_abort.is_some() {
                                                "分析中…"
                                            } else {
                                                "开始分析"
                                            })
                                            .small()
                                            .primary()
                                            .disabled(
                                                self.analysis_abort.is_some()
                                                    || self.analysis.checks.is_empty(),
                                            )
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.begin_analysis(cx)
                                            })),
                                    )
                                    .when(self.analysis_abort.is_some(), |actions| {
                                        actions.child(
                                            crate::buttons::button("sftp-analysis-cancel")
                                                .label("取消")
                                                .small()
                                                .danger()
                                                .on_click(cx.listener(|this, _, _, cx| {
                                                    this.cancel_analysis(cx)
                                                })),
                                        )
                                    })
                            })
                            .child(
                                crate::buttons::close_button("sftp-overlay-close")
                                    .small()
                                    .on_click(cx.listener(|this, _, _, cx| this.close_overlay(cx))),
                            ),
                    ),
            )
            .into_any_element()
    }

    fn render_analysis(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let path = self
            .analysis
            .path
            .as_ref()
            .map_or_else(|| "未选择文件".to_owned(), |path| path.as_str().to_owned());
        let running = self.analysis_abort.is_some();
        let selected = self.analysis.selected;
        let findings = self
            .analysis
            .result
            .as_ref()
            .map(|result| {
                result
                    .findings
                    .iter()
                    .map(|finding| (finding.check, finding.truncated))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let selected_finding = self.analysis.result.as_ref().and_then(|result| {
            result
                .findings
                .iter()
                .find(|finding| Some(finding.check) == selected)
                .map(|finding| (finding.check, finding.output.clone(), finding.truncated))
        });

        div()
            .h(px(500.0))
            .min_h_0()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .rounded_md()
                    .border_1()
                    .border_color(tokens.border)
                    .bg(tokens.surface_alt)
                    .p_2()
                    .text_sm()
                    .font_family("Cascadia Mono")
                    .child(path),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(
                        crate::buttons::button("sftp-analysis-recommended")
                            .label("常用检查")
                            .xsmall()
                            .disabled(running)
                            .on_click(
                                cx.listener(|this, _, _, cx| this.select_recommended_analysis(cx)),
                            ),
                    )
                    .child(
                        crate::buttons::button("sftp-analysis-all")
                            .label("全选 29 项")
                            .xsmall()
                            .disabled(running)
                            .on_click(cx.listener(|this, _, _, cx| this.select_all_analysis(cx))),
                    )
                    .child(
                        crate::buttons::button("sftp-analysis-clear")
                            .label("清空")
                            .xsmall()
                            .disabled(running)
                            .on_click(cx.listener(|this, _, _, cx| this.clear_analysis_checks(cx))),
                    )
                    .child(div().flex_1())
                    .child(div().text_xs().text_color(tokens.muted).child(format!(
                        "已选 {} 项 · 最大并发 4",
                        self.analysis.checks.len()
                    ))),
            )
            .child(
                div()
                    .max_h(px(178.0))
                    .overflow_y_scrollbar()
                    .rounded_md()
                    .border_1()
                    .border_color(tokens.border)
                    .p_2()
                    .children(
                        ["基础信息", "内容与结构", "系统关联", "安全检测"]
                            .into_iter()
                            .map(|group| {
                                div()
                                    .mb_2()
                                    .child(
                                        div()
                                            .mb_1()
                                            .text_xs()
                                            .text_color(tokens.muted)
                                            .child(group),
                                    )
                                    .child(
                                        div().flex().flex_wrap().gap_1().children(
                                            FileAnalysisCheck::ALL
                                                .into_iter()
                                                .filter(move |check| check.group_label() == group)
                                                .map(|check| {
                                                    crate::buttons::button(SharedString::from(
                                                        format!("sftp-analysis-check-{check:?}"),
                                                    ))
                                                    .label(check.label())
                                                    .xsmall()
                                                    .selected(self.analysis.checks.contains(&check))
                                                    .disabled(running)
                                                    .on_click(cx.listener(move |this, _, _, cx| {
                                                        this.toggle_analysis_check(check, cx)
                                                    }))
                                                }),
                                        ),
                                    )
                            }),
                    ),
            )
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .when(running, |view| {
                        view.child(
                            div()
                                .h_full()
                                .flex()
                                .items_center()
                                .justify_center()
                                .text_color(tokens.muted)
                                .child("正在并发执行闭集只读检查…"),
                        )
                    })
                    .when(!running && findings.is_empty(), |view| {
                        view.child(
                            div()
                                .h_full()
                                .flex()
                                .items_center()
                                .justify_center()
                                .text_color(tokens.muted)
                                .child("选择检查项后点击“开始分析”"),
                        )
                    })
                    .when(!running && !findings.is_empty(), |view| {
                        view.child(
                            div()
                                .size_full()
                                .flex()
                                .gap_2()
                                .child(
                                    div()
                                        .w(px(220.0))
                                        .flex_none()
                                        .overflow_y_scrollbar()
                                        .rounded_md()
                                        .border_1()
                                        .border_color(tokens.border)
                                        .p_1()
                                        .children(findings.into_iter().map(
                                            |(check, truncated)| {
                                                crate::buttons::button(SharedString::from(format!(
                                                    "sftp-analysis-result-{check:?}"
                                                )))
                                                .label(if truncated {
                                                    format!("{} · 已截断", check.label())
                                                } else {
                                                    check.label().to_owned()
                                                })
                                                .small()
                                                .w_full()
                                                .selected(selected == Some(check))
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.select_analysis_result(check, cx)
                                                }))
                                            },
                                        )),
                                )
                                .child(
                                    div()
                                        .flex_1()
                                        .min_w_0()
                                        .min_h_0()
                                        .overflow_scrollbar()
                                        .rounded_md()
                                        .border_1()
                                        .border_color(tokens.border)
                                        .bg(tokens.terminal_background)
                                        .p_3()
                                        .font_family("Cascadia Mono")
                                        .text_sm()
                                        .text_color(gpui::rgb(0xe5edf7))
                                        .child(selected_finding.map_or_else(
                                            || "请选择一项结果".to_owned(),
                                            |(check, output, truncated)| {
                                                let output = if output.trim().is_empty() {
                                                    "（未发现匹配内容）".to_owned()
                                                } else {
                                                    output
                                                };
                                                if truncated {
                                                    format!(
                                                        "{}\n\n{}\n\n[结果已按 64 KiB 上限截断]",
                                                        check.label(),
                                                        output
                                                    )
                                                } else {
                                                    format!("{}\n\n{}", check.label(), output)
                                                }
                                            },
                                        )),
                                ),
                        )
                    }),
            )
            .into_any_element()
    }

    fn render_history(&self, tokens: ThemeTokens) -> AnyElement {
        let target = self.model.binding().map(|binding| binding.target.clone());
        let entries = self
            .services
            .operation_journal()
            .entries()
            .unwrap_or_default()
            .into_iter()
            .filter(|entry| target.as_ref() == Some(&entry.target))
            .rev()
            .take(100)
            .collect::<Vec<_>>();
        div()
            .h(px(420.0))
            .overflow_y_scrollbar()
            .when(entries.is_empty(), |history| {
                history.child(
                    div()
                        .p_4()
                        .text_color(tokens.muted)
                        .child("当前目标尚无操作日志"),
                )
            })
            .children(entries.into_iter().map(|entry| {
                div()
                    .p_2()
                    .border_b_1()
                    .border_color(tokens.border)
                    .child(div().text_sm().child(entry.summary))
                    .child(
                        div()
                            .text_xs()
                            .text_color(tokens.muted)
                            .child(format!("{:?} · {}", entry.phase, entry.occurred_at)),
                    )
            }))
            .into_any_element()
    }

    fn render_confirmation(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let (operation_id, summary, restore) = self
            .pending_operation
            .as_ref()
            .map(|pending| {
                let plan = pending.operation.definition();
                (
                    plan.id.clone(),
                    plan.summary.clone(),
                    plan.restore_description.clone(),
                )
            })
            .unwrap_or_default();
        div()
            .absolute()
            .inset_0()
            .bg(gpui::rgba(0x000000cc))
            .flex()
            .items_center()
            .justify_center()
            .child(
                div()
                    .w(px(620.0))
                    .rounded_lg()
                    .border_1()
                    .border_color(tokens.danger)
                    .bg(tokens.surface)
                    .p_5()
                    .child(
                        div()
                            .text_xl()
                            .text_color(tokens.danger)
                            .child("危险操作确认"),
                    )
                    .child(div().mt_3().text_sm().child(summary))
                    .child(
                        div()
                            .mt_2()
                            .text_xs()
                            .text_color(tokens.muted)
                            .child(format!("Operation ID: {operation_id}")),
                    )
                    .when_some(restore, |panel, restore| {
                        panel.child(
                            div()
                                .mt_2()
                                .text_xs()
                                .text_color(tokens.success)
                                .child(format!("恢复路径：{restore}")),
                        )
                    })
                    .child(
                        div()
                            .mt_4()
                            .flex()
                            .justify_end()
                            .gap_2()
                            .child(
                                crate::buttons::button("sftp-confirm-cancel")
                                    .label("取消")
                                    .small()
                                    .on_click(
                                        cx.listener(|this, _, _, cx| this.cancel_pending(cx)),
                                    ),
                            )
                            .child(
                                crate::buttons::button("sftp-confirm-approve")
                                    .label("确认执行")
                                    .small()
                                    .danger()
                                    .on_click(
                                        cx.listener(|this, _, _, cx| this.approve_pending(cx)),
                                    ),
                            ),
                    ),
            )
            .into_any_element()
    }
}

fn breadcrumb_paths(path: &RemotePath) -> Vec<RemotePath> {
    let mut paths = vec![RemotePath::new("/").expect("root path is valid")];
    if path.as_str() == "/" {
        return paths;
    }
    let mut current = String::new();
    for component in path.as_str().trim_start_matches('/').split('/') {
        current.push('/');
        current.push_str(component);
        if let Ok(path) = RemotePath::new(current.clone()) {
            paths.push(path);
        }
    }
    paths
}

fn kind_label(kind: SftpFileKind) -> &'static str {
    match kind {
        SftpFileKind::File => "文件",
        SftpFileKind::Directory => "目录",
        SftpFileKind::Symlink => "符号链接",
        SftpFileKind::Other => "特殊文件",
    }
}

fn file_kind_icon(kind: SftpFileKind) -> IconName {
    match kind {
        SftpFileKind::File => IconName::File,
        SftpFileKind::Directory => IconName::FolderClosed,
        SftpFileKind::Symlink => IconName::ExternalLink,
        SftpFileKind::Other => IconName::Asterisk,
    }
}

fn bounded_context_label(value: &str) -> String {
    const MAX_CHARS: usize = 48;
    let mut chars = value.chars();
    let mut bounded = chars.by_ref().take(MAX_CHARS).collect::<String>();
    if chars.next().is_some() {
        bounded.push('…');
    }
    if bounded.trim().is_empty() {
        "当前条目".to_owned()
    } else {
        bounded
    }
}

fn format_size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use gpui::TestAppContext;
    use gpui_component::IconNamed;
    use lovelyres_core::target::TargetIdentity;

    use super::*;

    #[test]
    fn file_list_uses_embedded_svg_icons_instead_of_a_text_kind_column() {
        for (kind, expected_path) in [
            (SftpFileKind::File, "icons/file.svg"),
            (SftpFileKind::Directory, "icons/folder-closed.svg"),
            (SftpFileKind::Symlink, "icons/external-link.svg"),
            (SftpFileKind::Other, "icons/asterisk.svg"),
        ] {
            assert_eq!(file_kind_icon(kind).path().as_ref(), expected_path);
        }

        let source = include_str!("sftp.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source precedes tests");
        let start = production
            .find("fn render_rows")
            .expect("native SFTP row renderer");
        let end = production[start..]
            .find("fn render_details")
            .map(|offset| start + offset)
            .expect("native SFTP row renderer boundary");
        let row_renderer = &production[start..end];
        assert!(row_renderer.contains("Icon::new(kind_icon)"));
        assert!(!row_renderer.contains("kind_label("));
    }

    fn binding(identity: &str, generation: u64) -> SftpBinding {
        SftpBinding {
            connection_id: identity.to_owned(),
            session_id: format!("session-{identity}"),
            target: TargetGuard {
                identity: TargetIdentity::new(identity).unwrap(),
                generation,
            },
        }
    }

    fn entry(path: &str, kind: SftpFileKind, size: u64) -> SftpEntry {
        let path = RemotePath::new(path).unwrap();
        SftpEntry {
            name: path.file_name().unwrap().to_owned(),
            path,
            metadata: SftpMetadata {
                size,
                permissions: Some(0o640),
                uid: Some(1000),
                gid: Some(1000),
                modified_at: None,
                kind,
            },
        }
    }

    fn loaded_model(entries: Vec<SftpEntry>) -> (SftpModel, SftpBinding) {
        let current = binding("host-a", 1);
        let mut model = SftpModel::default();
        model.activate(Some(current.clone()), RemotePath::new("/tmp").unwrap());
        let lease = model.begin_list().unwrap();
        assert!(model.apply_list(&lease, Some(&current), entries));
        (model, current)
    }

    #[gpui::test]
    fn shared_navigator_rejects_cross_target_navigation(_cx: &mut TestAppContext) {
        let first = binding("host-a", 1).target;
        let second = binding("host-b", 2).target;
        let mut navigator = SftpNavigator::default();
        navigator.set_location(SftpLocation::new(
            first.clone(),
            RemotePath::new("/var/log").unwrap(),
        ));
        assert!(
            navigator
                .navigate_checked(&second, RemotePath::new("/etc").unwrap())
                .is_err()
        );
        assert_eq!(
            navigator.location().unwrap().path,
            RemotePath::new("/var/log").unwrap()
        );
        assert!(
            navigator
                .navigate_checked(&first, RemotePath::new("/var/lib").unwrap())
                .is_ok()
        );
    }

    #[test]
    fn stable_file_identity_survives_sort_filter_and_refresh_insertion() {
        let (mut model, current) = loaded_model(vec![
            entry("/tmp/zeta.txt", SftpFileKind::File, 9),
            entry("/tmp/alpha", SftpFileKind::Directory, 0),
        ]);
        let selected = FileId::from_path(&RemotePath::new("/tmp/zeta.txt").unwrap());
        assert!(model.select(selected.clone()));
        model.set_sort(SftpSort::Size);
        model.set_query("zeta".to_owned());
        assert_eq!(model.visible_rows()[0].id, selected);

        model.set_query(String::new());
        let lease = model.begin_list().unwrap();
        assert!(model.apply_list(
            &lease,
            Some(&current),
            vec![
                entry("/tmp/new.txt", SftpFileKind::File, 1),
                entry("/tmp/zeta.txt", SftpFileKind::File, 9),
                entry("/tmp/alpha", SftpFileKind::Directory, 0),
            ]
        ));
        assert_eq!(model.selected_row().unwrap().id, selected);
    }

    #[test]
    fn context_menu_lease_survives_sort_and_refresh_but_rejects_removed_file() {
        let (mut model, current) = loaded_model(vec![
            entry("/tmp/zeta.txt", SftpFileKind::File, 9),
            entry("/tmp/alpha", SftpFileKind::Directory, 0),
        ]);
        let selected = FileId::from_path(&RemotePath::new("/tmp/zeta.txt").unwrap());
        let lease = SftpContextMenuLease::capture(&model, selected.clone()).unwrap();

        model.set_sort(SftpSort::Size);
        model.set_query("zeta".to_owned());
        assert!(lease.accepts(&model));

        model.set_query(String::new());
        let refresh = model.begin_list().unwrap();
        assert!(model.apply_list(
            &refresh,
            Some(&current),
            vec![
                entry("/tmp/new.txt", SftpFileKind::File, 1),
                entry("/tmp/zeta.txt", SftpFileKind::File, 9),
            ]
        ));
        assert!(lease.accepts(&model));
        assert!(model.select(lease.file_id.clone()));
        assert_eq!(
            model.selected_row().unwrap().entry.path.as_str(),
            "/tmp/zeta.txt"
        );

        let refresh = model.begin_list().unwrap();
        assert!(model.apply_list(
            &refresh,
            Some(&current),
            vec![entry("/tmp/new.txt", SftpFileKind::File, 1)]
        ));
        assert!(!lease.accepts(&model));
    }

    #[test]
    fn context_menu_lease_rejects_target_and_lifecycle_changes() {
        let (mut model, _) = loaded_model(vec![entry("/tmp/evidence.bin", SftpFileKind::File, 42)]);
        let file_id = FileId::from_path(&RemotePath::new("/tmp/evidence.bin").unwrap());
        let lease = SftpContextMenuLease::capture(&model, file_id).unwrap();
        assert!(lease.accepts(&model));

        model.deactivate();
        assert!(!lease.accepts(&model));
        model.activate(Some(binding("host-b", 2)), RemotePath::new("/tmp").unwrap());
        assert!(!lease.accepts(&model));
    }

    #[test]
    fn context_menu_actions_follow_file_kind_and_busy_state() {
        let file = SftpRow {
            id: FileId("/tmp/evidence.zip".to_owned()),
            entry: entry("/tmp/evidence.zip", SftpFileKind::File, 42),
        };
        let directory = SftpRow {
            id: FileId("/tmp/evidence".to_owned()),
            entry: entry("/tmp/evidence", SftpFileKind::Directory, 0),
        };
        let symlink = SftpRow {
            id: FileId("/tmp/link".to_owned()),
            entry: entry("/tmp/link", SftpFileKind::Symlink, 0),
        };

        assert!(SftpContextAction::Open.available(&file, false, true));
        assert!(SftpContextAction::Open.available(&directory, false, true));
        assert!(!SftpContextAction::Open.available(&symlink, false, true));
        assert!(SftpContextAction::Analyze.available(&file, false, true));
        assert!(!SftpContextAction::Analyze.available(&directory, false, true));
        assert!(SftpContextAction::Extract.available(&file, false, true));
        assert!(!SftpContextAction::Extract.available(&directory, false, true));
        assert!(!SftpContextAction::Rename.available(&file, true, true));
        assert!(!SftpContextAction::OpenTerminal.available(&file, false, false));
        assert!(SftpContextAction::CopyPath.available(&symlink, true, false));
    }

    #[test]
    fn context_menu_is_flat_typed_and_utf8_bounded() {
        assert_eq!(SftpContextAction::ALL.len(), 12);
        assert_eq!(bounded_context_label("   "), "当前条目");
        let bounded = bounded_context_label(&"证".repeat(80));
        assert_eq!(bounded.chars().count(), 49);
        assert!(bounded.ends_with('…'));

        let source = include_str!("sftp.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source precedes tests");
        let start = production
            .find("fn render_context_menu")
            .expect("native SFTP context menu renderer");
        let end = production[start..]
            .find("fn selected_terminal_directory")
            .map(|offset| start + offset)
            .expect("SFTP context menu renderer boundary");
        let menu = &production[start..end];
        assert!(menu.contains("sftp-row-context-menu"));
        assert!(menu.contains("dispatch_context_action"));
        assert!(!menu.contains("shadow_"));
        assert!(!menu.contains("ssh_execute_command"));
        assert!(!menu.contains("invoke("));
    }

    #[test]
    fn legacy_sort_index_contract_uses_stable_ids_and_keeps_directories_first() {
        let (mut model, _) = loaded_model(vec![
            entry("/tmp/zeta.txt", SftpFileKind::File, 9),
            entry("/tmp/alpha", SftpFileKind::Directory, 0),
            entry("/tmp/beta.txt", SftpFileKind::File, 1),
        ]);
        let directory = FileId::from_path(&RemotePath::new("/tmp/alpha").unwrap());

        for sort in SftpSort::ALL {
            model.set_sort(sort);
            let descending = model
                .visible_rows()
                .into_iter()
                .map(|row| row.id.clone())
                .collect::<Vec<_>>();
            assert_eq!(descending.first(), Some(&directory));

            model.set_sort(sort);
            let ascending = model
                .visible_rows()
                .into_iter()
                .map(|row| row.id.clone())
                .collect::<Vec<_>>();
            assert_eq!(ascending.first(), Some(&directory));
            assert_ne!(ascending, descending);
        }

        let missing = FileId::from_path(&RemotePath::new("/tmp/missing.txt").unwrap());
        assert!(!model.select(missing));
    }

    #[test]
    fn target_switch_and_selection_change_reject_stale_results() {
        let (mut model, first) = loaded_model(vec![
            entry("/tmp/a.txt", SftpFileKind::File, 1),
            entry("/tmp/b.txt", SftpFileKind::File, 1),
        ]);
        let first_id = FileId::from_path(&RemotePath::new("/tmp/a.txt").unwrap());
        let second_id = FileId::from_path(&RemotePath::new("/tmp/b.txt").unwrap());
        assert!(model.select(first_id.clone()));
        let read = model.begin_read(first_id).unwrap();
        assert!(model.select(second_id));
        assert!(!model.accepts_read(&read, Some(&first)));

        let list = model.begin_list().unwrap();
        let second = binding("host-b", 2);
        model.activate(Some(second.clone()), RemotePath::new("/tmp").unwrap());
        assert!(!model.apply_list(
            &list,
            Some(&second),
            vec![entry("/tmp/late.txt", SftpFileKind::File, 1)]
        ));
    }

    #[test]
    fn extract_plan_lease_rejects_target_selection_lifecycle_and_request_changes() {
        let current = binding("host-a", 3);
        let archive = RemotePath::new("/tmp/case.tar.gz").unwrap();
        let destination = RemotePath::new("/tmp/case").unwrap();
        let lease = ExtractPlanLease {
            activation_generation: 9,
            request_id: 11,
            binding: current.clone(),
            archive: archive.clone(),
            destination,
        };
        assert!(lease.accepts(true, 9, 11, Some(&current), Some(&archive)));
        assert!(!lease.accepts(false, 9, 11, Some(&current), Some(&archive)));
        assert!(!lease.accepts(true, 10, 11, Some(&current), Some(&archive)));
        assert!(!lease.accepts(true, 9, 12, Some(&current), Some(&archive)));
        assert!(!lease.accepts(true, 9, 11, Some(&binding("host-b", 4)), Some(&archive)));
        assert!(!lease.accepts(
            true,
            9,
            11,
            Some(&current),
            Some(&RemotePath::new("/tmp/other.zip").unwrap())
        ));
    }

    #[test]
    fn native_extract_action_is_enabled_only_for_supported_archive_names() {
        assert!(
            SftpService::suggested_extraction_destination(
                &RemotePath::new("/tmp/evidence.zip").unwrap()
            )
            .is_ok()
        );
        assert!(
            SftpService::suggested_extraction_destination(
                &RemotePath::new("/tmp/evidence.tar.zst").unwrap()
            )
            .is_ok()
        );
        assert!(
            SftpService::suggested_extraction_destination(
                &RemotePath::new("/tmp/evidence.txt").unwrap()
            )
            .is_err()
        );
        let source = include_str!("sftp.rs");
        assert!(source.contains(".label(if self.extract_plan_abort.is_some()"));
        assert!(!source.contains(&["解压", "（禁用）"].concat()));
        assert!(!source.contains(&["Unsupported", "Extract"].concat()));
    }

    #[test]
    fn target_switch_clears_path_query_sort_selection_and_cached_rows() {
        let (mut model, _) = loaded_model(vec![
            entry("/tmp/a.txt", SftpFileKind::File, 1),
            entry("/tmp/b.txt", SftpFileKind::File, 2),
        ]);
        model.set_query("a".to_owned());
        model.set_sort(SftpSort::Size);
        assert!(model.select(FileId::from_path(&RemotePath::new("/tmp/a.txt").unwrap())));
        assert!(!model.rows.is_empty());

        model.activate(Some(binding("host-b", 2)), RemotePath::new("/").unwrap());
        assert_eq!(model.path().as_str(), "/");
        assert!(model.rows.is_empty());
        assert!(model.query.is_empty());
        assert_eq!(model.sort, SftpSort::Name);
        assert!(model.ascending);
        assert!(model.selected.is_none());
        assert!(model.latest_list_request.is_none());
        assert!(model.latest_read_request.is_none());
    }

    #[test]
    fn hostile_names_and_file_text_remain_inert_plain_strings() {
        // POSIX file names cannot contain '/', so use hostile markup that is
        // still one valid path component.
        let attack = "<img src=x onerror=alert(1)><script>bad().txt";
        let path = format!("/tmp/{attack}");
        let (mut model, _) = loaded_model(vec![entry(&path, SftpFileKind::File, 1)]);
        model.set_query("<script>".to_owned());
        assert_eq!(model.visible_rows()[0].entry.name, attack);
        let source = include_str!("sftp.rs").to_lowercase();
        assert!(!source.contains(&["inner", "_html"].concat()));
        assert!(!source.contains(&["render", "_markdown"].concat()));
    }

    #[test]
    fn file_analysis_uses_the_closed_twenty_nine_check_catalog() {
        let mut analysis = FileAnalysisModel::default();
        assert_eq!(analysis.checks.len(), 13);
        assert!(analysis.checks.iter().all(|check| check.recommended()));

        analysis.select_all();
        assert_eq!(analysis.checks.len(), FileAnalysisCheck::ALL.len());
        assert_eq!(analysis.checks.len(), 29);

        analysis.clear_checks();
        analysis.open(RemotePath::new("/tmp/evidence.bin").unwrap());
        assert!(analysis.begin(7, binding("host-a", 1)).is_err());

        analysis.select_recommended();
        let (_, request) = analysis.begin(7, binding("host-a", 1)).unwrap();
        assert_eq!(request.remote_path, "/tmp/evidence.bin");
        assert_eq!(request.checks, analysis.checks);
    }

    #[test]
    fn file_analysis_rejects_stale_leases_and_preserves_remote_text_as_data() {
        let current = binding("host-a", 3);
        let hostile_path = RemotePath::new("/tmp/<script>alert(1).bin").unwrap();
        let mut analysis = FileAnalysisModel::default();
        analysis.open(hostile_path.clone());
        let (lease, _) = analysis.begin(11, current.clone()).unwrap();
        let result = FileAnalysisResult {
            remote_path: hostile_path.as_str().to_owned(),
            findings: vec![lovelyres_core::file_analysis::FileAnalysisFinding {
                check: FileAnalysisCheck::Strings,
                output: "<img src=x onerror=alert(1)>\n<script>bad()</script>".to_owned(),
                truncated: false,
            }],
        };

        assert!(!analysis.apply(&lease, false, 11, Some(&current), result.clone()));
        assert!(!analysis.apply(&lease, true, 12, Some(&current), result.clone()));
        assert!(!analysis.apply(
            &lease,
            true,
            11,
            Some(&binding("host-b", 4)),
            result.clone(),
        ));
        assert!(analysis.apply(&lease, true, 11, Some(&current), result));

        let finding = &analysis.result.as_ref().unwrap().findings[0];
        assert_eq!(finding.check, FileAnalysisCheck::Strings);
        assert_eq!(
            finding.output,
            "<img src=x onerror=alert(1)>\n<script>bad()</script>"
        );
        assert_eq!(analysis.selected, Some(FileAnalysisCheck::Strings));
        assert!(analysis.latest.is_none());
    }

    #[test]
    fn large_directory_is_windowed_to_one_hundred_rows() {
        let entries = (0..1_000)
            .map(|index| {
                entry(
                    &format!("/tmp/file-{index:04}.txt"),
                    SftpFileKind::File,
                    index,
                )
            })
            .collect();
        let (mut model, _) = loaded_model(entries);
        assert_eq!(model.visible_rows().len(), ROW_WINDOW_SIZE);
        assert_eq!(model.visible_rows()[0].entry.name, "file-0000.txt");
        model.scroll_window(1);
        assert_eq!(model.visible_rows()[0].entry.name, "file-0100.txt");
        model.set_query("file-0999".to_owned());
        assert_eq!(model.visible_rows().len(), 1);
        assert_eq!(model.row_window_start, 0);
    }

    #[test]
    fn breadcrumbs_are_absolute_and_never_synthesize_parent_traversal() {
        let paths = breadcrumb_paths(&RemotePath::new("/var/log/nginx").unwrap());
        assert_eq!(
            paths.iter().map(RemotePath::as_str).collect::<Vec<_>>(),
            vec!["/", "/var", "/var/log", "/var/log/nginx"]
        );
        assert!(paths.iter().all(|path| !path.as_str().contains("..")));
    }

    #[test]
    fn terminal_directory_uses_selected_directory_or_current_file_parent() {
        let (mut model, _) = loaded_model(vec![
            entry("/tmp/evidence", SftpFileKind::Directory, 0),
            entry("/tmp/report.txt", SftpFileKind::File, 12),
            entry("/tmp/current-link", SftpFileKind::Symlink, 0),
        ]);

        assert!(model.select(FileId::from_path(
            &RemotePath::new("/tmp/evidence").unwrap()
        )));
        assert_eq!(
            selected_terminal_directory(&model).unwrap(),
            RemotePath::new("/tmp/evidence").unwrap()
        );

        assert!(model.select(FileId::from_path(
            &RemotePath::new("/tmp/report.txt").unwrap()
        )));
        assert_eq!(
            selected_terminal_directory(&model).unwrap(),
            RemotePath::new("/tmp").unwrap()
        );

        assert!(model.select(FileId::from_path(
            &RemotePath::new("/tmp/current-link").unwrap()
        )));
        assert!(selected_terminal_directory(&model).is_err());

        let source = include_str!("sftp.rs");
        assert!(source.contains(".label(\"在终端打开\")"));
        assert!(!source.contains(&["目录终端", "（待迁移）"].concat()));
    }
}
