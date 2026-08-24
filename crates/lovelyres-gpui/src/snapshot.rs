use std::{collections::BTreeSet, sync::Arc};

use gpui::{
    AnyElement, ClipboardItem, Context, Entity, IntoElement, Render, SharedString, Subscription,
    Window, div, prelude::*, px,
};
use gpui_component::{
    Disableable, Selectable, Sizable, StyledExt, button::ButtonVariants, scroll::ScrollableElement,
};
use lovelyres_core::{
    BackendServices, CoreError, CoreResult,
    operations::{DangerousConfirmation, OperationJournalEntry},
    snapshot::{
        DirectoryDeletePlan, DirectoryRestorePlan, DirectorySnapshot, ForensicCancellation,
        ForensicCaptureEvent, ForensicCollector, ForensicSnapshot, ForensicSnapshotDiff,
        SnapshotOperationOutcome, SnapshotPreset, forensic_event_channel,
    },
    ssh::BoundSshSession,
    target::TargetGuard,
};
use tokio::task::AbortHandle;

use crate::{app::SharedAppState, runtime::TokioBridge, theme::ThemeTokens};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SnapshotTab {
    Directory,
    Forensic,
    Journal,
}

impl SnapshotTab {
    const ALL: [Self; 3] = [Self::Directory, Self::Forensic, Self::Journal];

    const fn label(self) -> &'static str {
        match self {
            Self::Directory => "目录归档",
            Self::Forensic => "主机取证",
            Self::Journal => "操作记录",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SnapshotBinding {
    session_id: String,
    connection_id: String,
    target: TargetGuard,
}

impl SnapshotBinding {
    fn from_session(session: &BoundSshSession) -> Self {
        Self {
            session_id: session.session_id().to_owned(),
            connection_id: session.connection_id().to_owned(),
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct SnapshotLease {
    activation_generation: u64,
    request_id: u64,
    binding: SnapshotBinding,
}

#[derive(Debug)]
enum PendingMutation {
    Restore(DirectoryRestorePlan),
    Delete(DirectoryDeletePlan),
}

impl PendingMutation {
    fn definition(&self) -> &lovelyres_core::operations::OperationPlan {
        match self {
            Self::Restore(plan) => plan.definition(),
            Self::Delete(plan) => plan.definition(),
        }
    }
}

#[derive(Debug)]
struct SnapshotModel {
    active: bool,
    activation_generation: u64,
    next_request_id: u64,
    latest_request_id: Option<u64>,
    binding: Option<SnapshotBinding>,
    tab: SnapshotTab,
    selected_presets: BTreeSet<SnapshotPreset>,
    directory: Vec<DirectorySnapshot>,
    selected_directory_id: Option<String>,
    forensic: Vec<ForensicSnapshot>,
    selected_forensic_id: Option<String>,
    diff_older_id: Option<String>,
    diff_newer_id: Option<String>,
    selected_collector: ForensicCollector,
    diff: Option<ForensicSnapshotDiff>,
    journal: Vec<OperationJournalEntry>,
}

impl Default for SnapshotModel {
    fn default() -> Self {
        Self {
            active: false,
            activation_generation: 0,
            next_request_id: 0,
            latest_request_id: None,
            binding: None,
            tab: SnapshotTab::Directory,
            selected_presets: SnapshotPreset::ALL
                .into_iter()
                .filter(|preset| preset.selected_by_default())
                .collect(),
            directory: Vec::new(),
            selected_directory_id: None,
            forensic: Vec::new(),
            selected_forensic_id: None,
            diff_older_id: None,
            diff_newer_id: None,
            selected_collector: ForensicCollector::Processes,
            diff: None,
            journal: Vec::new(),
        }
    }
}

impl SnapshotModel {
    fn activate(&mut self, binding: Option<SnapshotBinding>) {
        self.active = true;
        self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
        self.rebind(binding);
    }

    fn deactivate(&mut self) {
        self.active = false;
        self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
        self.latest_request_id = None;
    }

    fn rebind(&mut self, binding: Option<SnapshotBinding>) {
        if self.binding == binding {
            return;
        }
        self.binding = binding;
        self.latest_request_id = None;
        self.directory.clear();
        self.selected_directory_id = None;
        self.forensic.clear();
        self.selected_forensic_id = None;
        self.diff_older_id = None;
        self.diff_newer_id = None;
        self.diff = None;
        self.journal.clear();
    }

    fn begin_request(&mut self, binding: SnapshotBinding) -> CoreResult<SnapshotLease> {
        if !self.active {
            return Err(CoreError::Validation {
                subject: "snapshot page",
                message: "page is not active".to_owned(),
            });
        }
        self.rebind(Some(binding.clone()));
        self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
        self.latest_request_id = Some(self.next_request_id);
        Ok(SnapshotLease {
            activation_generation: self.activation_generation,
            request_id: self.next_request_id,
            binding,
        })
    }

    fn accepts(&self, lease: &SnapshotLease, binding: Option<&SnapshotBinding>) -> bool {
        self.active
            && self.activation_generation == lease.activation_generation
            && self.latest_request_id == Some(lease.request_id)
            && binding == Some(&lease.binding)
    }

    fn selected_directory(&self) -> Option<&DirectorySnapshot> {
        let id = self.selected_directory_id.as_ref()?;
        self.directory.iter().find(|snapshot| &snapshot.id == id)
    }

    fn selected_forensic(&self) -> Option<&ForensicSnapshot> {
        let id = self.selected_forensic_id.as_ref()?;
        self.forensic.iter().find(|snapshot| &snapshot.id == id)
    }

    fn apply_lists(
        &mut self,
        directory: Vec<DirectorySnapshot>,
        forensic: Vec<ForensicSnapshot>,
        journal: Vec<OperationJournalEntry>,
    ) {
        self.directory = directory;
        self.forensic = forensic;
        self.journal = journal;
        if !self
            .directory
            .iter()
            .any(|snapshot| self.selected_directory_id.as_ref() == Some(&snapshot.id))
        {
            self.selected_directory_id = self.directory.first().map(|item| item.id.clone());
        }
        if !self
            .forensic
            .iter()
            .any(|snapshot| self.selected_forensic_id.as_ref() == Some(&snapshot.id))
        {
            self.selected_forensic_id = self.forensic.first().map(|item| item.id.clone());
        }
        self.diff = None;
    }
}

pub struct SnapshotPage {
    services: Arc<BackendServices>,
    tokio: Arc<TokioBridge>,
    shared: Entity<SharedAppState>,
    model: SnapshotModel,
    task_abort: Option<AbortHandle>,
    cancellation: Option<ForensicCancellation>,
    busy: bool,
    progress: Option<SharedString>,
    pending: Option<PendingMutation>,
    error: Option<SharedString>,
    notice: Option<SharedString>,
    _subscriptions: Vec<Subscription>,
}

impl SnapshotPage {
    pub fn new(
        services: Arc<BackendServices>,
        tokio: Arc<TokioBridge>,
        shared: Entity<SharedAppState>,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let subscriptions = vec![cx.observe(&shared, |page, _, cx| page.handle_shared_change(cx))];
        Self {
            services,
            tokio,
            shared,
            model: SnapshotModel::default(),
            task_abort: None,
            cancellation: None,
            busy: false,
            progress: None,
            pending: None,
            error: None,
            notice: None,
            _subscriptions: subscriptions,
        }
    }

    pub fn activate(&mut self, _window: &mut Window, cx: &mut Context<Self>) {
        self.model.activate(self.current_binding(cx));
        self.refresh(cx);
        cx.notify();
    }

    pub fn deactivate(&mut self, cx: &mut Context<Self>) {
        self.cancel_task();
        self.pending = None;
        self.model.deactivate();
        cx.notify();
    }

    pub const fn is_active(&self) -> bool {
        self.model.active
    }

    fn current_binding(&self, cx: &Context<Self>) -> Option<SnapshotBinding> {
        SnapshotBinding::capture(self.shared.read(cx))
    }

    fn current_session(&self, cx: &Context<Self>) -> Option<BoundSshSession> {
        self.shared
            .read(cx)
            .active_ssh
            .as_ref()
            .map(|active| active.session.clone())
    }

    fn cancel_task(&mut self) {
        if let Some(cancellation) = self.cancellation.take() {
            cancellation.cancel();
        }
        if let Some(task) = self.task_abort.take() {
            task.abort();
        }
        self.busy = false;
        self.progress = None;
        self.model.latest_request_id = None;
    }

    fn handle_shared_change(&mut self, cx: &mut Context<Self>) {
        if !self.model.active {
            return;
        }
        let binding = self.current_binding(cx);
        if binding == self.model.binding {
            return;
        }
        self.cancel_task();
        self.pending = None;
        self.model.rebind(binding);
        self.error = None;
        self.notice = None;
        if self.model.binding.is_some() {
            self.refresh(cx);
        } else {
            self.error = Some("未连接可信目标，无法使用取证快照".into());
            cx.notify();
        }
    }

    fn refresh(&mut self, cx: &mut Context<Self>) {
        let Some(binding) = self.current_binding(cx) else {
            self.error = Some("未连接可信目标".into());
            return;
        };
        let directory = self.services.snapshots().list_directory(&binding.target);
        let forensic = self.services.snapshots().list_forensic(&binding.target);
        let journal = self.services.operation_journal().entries().map(|entries| {
            entries
                .into_iter()
                .filter(|entry| entry.target.identity == binding.target.identity)
                .rev()
                .take(200)
                .collect::<Vec<_>>()
        });
        match (directory, forensic, journal) {
            (Ok(directory), Ok(forensic), Ok(journal)) => {
                self.model.rebind(Some(binding));
                self.model.apply_lists(directory, forensic, journal);
                self.error = None;
            }
            (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => {
                self.error = Some(format!("无法读取快照索引：{error}").into());
            }
        }
        cx.notify();
    }

    fn create_directory(&mut self, cx: &mut Context<Self>) {
        if self.busy || self.pending.is_some() {
            return;
        }
        let Some(session) = self.current_session(cx) else {
            self.error = Some("未连接可信目标".into());
            return;
        };
        let binding = SnapshotBinding::from_session(&session);
        let lease = match self.model.begin_request(binding) {
            Ok(lease) => lease,
            Err(error) => {
                self.error = Some(error.to_string().into());
                return;
            }
        };
        let plan = match self
            .services
            .snapshots()
            .plan_directory_snapshot(&session, self.model.selected_presets.iter().copied())
        {
            Ok(plan) => plan,
            Err(error) => {
                self.error = Some(format!("无法创建快照计划：{error}").into());
                return;
            }
        };
        self.busy = true;
        self.error = None;
        self.notice = Some("正在远端创建只读归档并回读 SHA-256…".into());
        let service = self.services.snapshots().clone();
        let task = self
            .tokio
            .spawn(async move { service.execute_directory_snapshot(&session, plan).await });
        self.task_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_directory(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_directory(
        &mut self,
        lease: SnapshotLease,
        result: Result<CoreResult<DirectorySnapshot>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            return;
        }
        self.busy = false;
        self.task_abort = None;
        match result {
            Ok(Ok(snapshot)) => {
                self.notice =
                    Some(format!("目录快照已建立并验证：{} 项", snapshot.items.len()).into());
                self.error = None;
                self.refresh(cx);
            }
            Ok(Err(error)) => self.error = Some(format!("目录快照失败：{error}").into()),
            Err(error) if error.is_cancelled() => return,
            Err(error) => self.error = Some(format!("目录快照任务异常终止：{error}").into()),
        }
        cx.notify();
    }

    fn capture_forensic(&mut self, cx: &mut Context<Self>) {
        if self.busy || self.pending.is_some() {
            return;
        }
        let Some(session) = self.current_session(cx) else {
            self.error = Some("未连接可信目标".into());
            return;
        };
        let binding = SnapshotBinding::from_session(&session);
        let lease = match self.model.begin_request(binding) {
            Ok(lease) => lease,
            Err(error) => {
                self.error = Some(error.to_string().into());
                return;
            }
        };
        let (events, receiver) = match forensic_event_channel(64) {
            Ok(channel) => channel,
            Err(error) => {
                self.error = Some(error.to_string().into());
                return;
            }
        };
        let cancellation = ForensicCancellation::default();
        self.cancellation = Some(cancellation.clone());
        self.busy = true;
        self.error = None;
        self.progress = Some("准备采集 12 项主机状态…".into());
        let service = self.services.snapshots().clone();
        let task = self.tokio.spawn(async move {
            service
                .capture_forensic(&session, cancellation, Some(events))
                .await
        });
        self.task_abort = Some(task.abort_handle());
        let event_lease = lease.clone();
        cx.spawn(async move |page, cx| {
            while let Some(event) = receiver.recv().await {
                let _ = cx.update(|cx| {
                    if let Some(page) = page.upgrade() {
                        page.update(cx, |page, cx| {
                            page.apply_forensic_event(&event_lease, &event, cx)
                        });
                    }
                });
            }
        })
        .detach();
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_forensic(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn apply_forensic_event(
        &mut self,
        lease: &SnapshotLease,
        event: &ForensicCaptureEvent,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts(lease, binding.as_ref()) {
            return;
        }
        self.progress = Some(
            match event {
                ForensicCaptureEvent::Started { total, .. } => {
                    format!("准备采集 {total} 项主机状态…")
                }
                ForensicCaptureEvent::CollectorStarted {
                    collector,
                    ordinal,
                    total,
                    ..
                } => format!("{ordinal}/{total} · 正在采集 {}", collector.label()),
                ForensicCaptureEvent::CollectorFinished {
                    completed,
                    total,
                    failed,
                    ..
                } => format!(
                    "已完成 {completed}/{total}{}",
                    if *failed {
                        " · 本项失败已记录"
                    } else {
                        ""
                    }
                ),
                ForensicCaptureEvent::Finished { failed, .. } => {
                    format!("采集完成 · 失败 {failed} 项")
                }
            }
            .into(),
        );
        cx.notify();
    }

    fn finish_forensic(
        &mut self,
        lease: SnapshotLease,
        result: Result<CoreResult<ForensicSnapshot>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            return;
        }
        self.busy = false;
        self.task_abort = None;
        self.cancellation = None;
        self.progress = None;
        match result {
            Ok(Ok(snapshot)) => {
                self.notice = Some(
                    format!(
                        "取证快照已保存：12 项，失败 {} 项",
                        snapshot.collection.failed
                    )
                    .into(),
                );
                self.error = None;
                self.refresh(cx);
            }
            Ok(Err(error)) => self.error = Some(format!("取证采集失败：{error}").into()),
            Err(error) if error.is_cancelled() => return,
            Err(error) => self.error = Some(format!("取证任务异常终止：{error}").into()),
        }
        cx.notify();
    }

    fn plan_restore(
        &mut self,
        snapshot_id: String,
        preset: SnapshotPreset,
        cx: &mut Context<Self>,
    ) {
        let Some(session) = self.current_session(cx) else {
            self.error = Some("未连接可信目标".into());
            return;
        };
        match self
            .services
            .snapshots()
            .plan_restore_item(&session, &snapshot_id, preset)
        {
            Ok(plan) => {
                self.pending = Some(PendingMutation::Restore(plan));
                self.error = None;
                self.notice = None;
            }
            Err(error) => self.error = Some(format!("无法创建恢复计划：{error}").into()),
        }
        cx.notify();
    }

    fn plan_delete(&mut self, snapshot_id: String, cx: &mut Context<Self>) {
        let Some(session) = self.current_session(cx) else {
            self.error = Some("未连接可信目标".into());
            return;
        };
        match self
            .services
            .snapshots()
            .plan_delete_directory(&session, &snapshot_id)
        {
            Ok(plan) => {
                self.pending = Some(PendingMutation::Delete(plan));
                self.error = None;
                self.notice = None;
            }
            Err(error) => self.error = Some(format!("无法创建删除计划：{error}").into()),
        }
        cx.notify();
    }

    fn approve_mutation(&mut self, cx: &mut Context<Self>) {
        if self.busy {
            return;
        }
        let Some(pending) = self.pending.take() else {
            return;
        };
        let Some(session) = self.current_session(cx) else {
            self.error = Some("目标已断开，操作计划已取消".into());
            return;
        };
        let binding = SnapshotBinding::from_session(&session);
        let lease = match self.model.begin_request(binding) {
            Ok(lease) => lease,
            Err(error) => {
                self.error = Some(error.to_string().into());
                return;
            }
        };
        let confirmation = DangerousConfirmation::approve(pending.definition());
        self.busy = true;
        self.error = None;
        self.notice = Some("正在执行危险操作并回读验证…".into());
        let service = self.services.snapshots().clone();
        let task = self.tokio.spawn(async move {
            match pending {
                PendingMutation::Restore(plan) => {
                    service
                        .execute_restore_item(&session, plan, confirmation)
                        .await
                }
                PendingMutation::Delete(plan) => {
                    service
                        .execute_delete_directory(&session, plan, confirmation)
                        .await
                }
            }
        });
        self.task_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_mutation(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_mutation(
        &mut self,
        lease: SnapshotLease,
        result: Result<CoreResult<SnapshotOperationOutcome>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            return;
        }
        self.busy = false;
        self.task_abort = None;
        match result {
            Ok(Ok(outcome)) if outcome.verified => {
                self.notice = Some("操作已执行、记录并通过回读验证".into());
                self.error = None;
                self.refresh(cx);
            }
            Ok(Ok(outcome)) => {
                self.error = Some(
                    format!(
                        "验证失败{}：{}",
                        if outcome.restored_after_failed_verification {
                            "，已恢复执行前状态"
                        } else {
                            ""
                        },
                        outcome.detail
                    )
                    .into(),
                );
            }
            Ok(Err(error)) => self.error = Some(format!("快照操作失败：{error}").into()),
            Err(error) if error.is_cancelled() => return,
            Err(error) => self.error = Some(format!("快照操作异常终止：{error}").into()),
        }
        cx.notify();
    }

    fn export_selected(&mut self, cx: &mut Context<Self>) {
        let Some(binding) = self.current_binding(cx) else {
            return;
        };
        let Some(snapshot) = self.model.selected_forensic() else {
            self.error = Some("请先选择一份取证快照".into());
            return;
        };
        match self
            .services
            .snapshots()
            .export_forensic(&binding.target, &snapshot.id)
        {
            Ok(artifact) => {
                let name = format!(
                    "forensic-snapshot-{}-{}.json",
                    snapshot.id,
                    &snapshot.sha256[..12]
                );
                cx.write_to_clipboard(ClipboardItem::new_string(artifact));
                self.notice = Some(format!("已复制精确 JSON 归档：{name}").into());
                self.error = None;
            }
            Err(error) => self.error = Some(format!("导出失败：{error}").into()),
        }
        cx.notify();
    }

    fn calculate_diff(&mut self, cx: &mut Context<Self>) {
        let Some(binding) = self.current_binding(cx) else {
            return;
        };
        let (Some(older), Some(newer)) = (
            self.model.diff_older_id.as_deref(),
            self.model.diff_newer_id.as_deref(),
        ) else {
            self.error = Some("请分别选择基线快照和对比快照".into());
            return;
        };
        match self
            .services
            .snapshots()
            .diff_forensic(&binding.target, older, newer)
        {
            Ok(diff) => {
                self.model.diff = Some(diff);
                self.error = None;
                self.notice = Some("已按去空白的逐行集合计算差异".into());
            }
            Err(error) => self.error = Some(format!("快照对比失败：{error}").into()),
        }
        cx.notify();
    }

    fn render_directory(&mut self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let selected = self.model.selected_directory().cloned();
        let snapshots = self.model.directory.clone();
        div()
            .size_full()
            .min_h_0()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .flex_wrap()
                    .children(SnapshotPreset::ALL.into_iter().map(|preset| {
                        crate::buttons::button(SharedString::from(format!(
                            "snapshot-preset-{}",
                            preset.id()
                        )))
                        .label(preset.label())
                        .small()
                        .selected(self.model.selected_presets.contains(&preset))
                        .disabled(self.busy)
                        .on_click(cx.listener(move |page, _, _, cx| {
                            if !page.model.selected_presets.remove(&preset) {
                                page.model.selected_presets.insert(preset);
                            }
                            cx.notify();
                        }))
                    }))
                    .child(div().flex_1())
                    .child(
                        crate::buttons::button("snapshot-create-directory")
                            .label(if self.busy {
                                "处理中…"
                            } else {
                                "建立目录快照"
                            })
                            .primary()
                            .disabled(self.busy || self.model.selected_presets.is_empty())
                            .on_click(cx.listener(|page, _, _, cx| page.create_directory(cx))),
                    ),
            )
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .flex()
                    .gap_3()
                    .child(
                        div()
                            .w(px(330.0))
                            .min_h_0()
                            .overflow_y_scrollbar()
                            .rounded_lg()
                            .border_1()
                            .border_color(tokens.border)
                            .bg(tokens.surface)
                            .when(snapshots.is_empty(), |view| {
                                view.child(empty_state("尚未建立目录快照", tokens))
                            })
                            .children(snapshots.into_iter().map(|snapshot| {
                                let id = snapshot.id.clone();
                                let selected =
                                    self.model.selected_directory_id.as_ref() == Some(&id);
                                div()
                                    .id(SharedString::from(format!("directory-snapshot-{id}")))
                                    .px_3()
                                    .py_3()
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
                                        page.model.selected_directory_id = Some(id.clone());
                                        cx.notify();
                                    }))
                                    .child(
                                        div()
                                            .text_sm()
                                            .font_semibold()
                                            .child(format!("{} 项归档", snapshot.items.len())),
                                    )
                                    .child(
                                        div().mt_1().text_xs().text_color(tokens.muted).child(
                                            snapshot
                                                .created_at
                                                .format("%Y-%m-%d %H:%M:%S UTC")
                                                .to_string(),
                                        ),
                                    )
                                    .child(
                                        div()
                                            .mt_1()
                                            .font_family("Cascadia Mono")
                                            .text_xs()
                                            .text_color(tokens.muted)
                                            .child(snapshot.id),
                                    )
                            })),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .min_h_0()
                            .overflow_y_scrollbar()
                            .rounded_lg()
                            .border_1()
                            .border_color(tokens.border)
                            .bg(tokens.surface)
                            .when_some(selected, |view, snapshot| {
                                let snapshot_id = snapshot.id.clone();
                                view.child(
                                    div()
                                        .flex()
                                        .items_center()
                                        .justify_between()
                                        .px_4()
                                        .py_3()
                                        .border_b_1()
                                        .border_color(tokens.border)
                                        .child(
                                            div()
                                                .child(div().font_semibold().child("归档内容"))
                                                .child(
                                                    div().text_xs().text_color(tokens.muted).child(
                                                        format!(
                                                            "远端只读命名空间 · SHA {}…",
                                                            &snapshot.record_sha256[..12]
                                                        ),
                                                    ),
                                                ),
                                        )
                                        .child(
                                            crate::buttons::button("snapshot-delete-directory")
                                                .label("删除整份")
                                                .danger()
                                                .small()
                                                .disabled(self.busy)
                                                .on_click(cx.listener(move |page, _, _, cx| {
                                                    page.plan_delete(snapshot_id.clone(), cx)
                                                })),
                                        ),
                                )
                                .children(
                                    snapshot.items.into_iter().map(|item| {
                                        let snapshot_id = snapshot.id.clone();
                                        let preset = item.preset;
                                        div()
                                            .flex()
                                            .items_center()
                                            .gap_3()
                                            .px_4()
                                            .py_3()
                                            .border_b_1()
                                            .border_color(tokens.border)
                                            .child(
                                                div()
                                                    .flex_1()
                                                    .min_w_0()
                                                    .child(
                                                        div()
                                                            .text_sm()
                                                            .font_semibold()
                                                            .child(item.preset.label()),
                                                    )
                                                    .child(
                                                        div()
                                                            .mt_1()
                                                            .font_family("Cascadia Mono")
                                                            .text_xs()
                                                            .text_color(tokens.muted)
                                                            .child(format!(
                                                                "{} · {} bytes · {}…",
                                                                item.source,
                                                                item.bytes,
                                                                &item.archive_sha256[..12]
                                                            )),
                                                    ),
                                            )
                                            .child(
                                                crate::buttons::button(SharedString::from(
                                                    format!("snapshot-restore-{}", preset.id()),
                                                ))
                                                .label("恢复此项")
                                                .small()
                                                .disabled(self.busy)
                                                .on_click(cx.listener(move |page, _, _, cx| {
                                                    page.plan_restore(
                                                        snapshot_id.clone(),
                                                        preset,
                                                        cx,
                                                    )
                                                })),
                                            )
                                    }),
                                )
                            })
                            .when(self.model.selected_directory().is_none(), |view| {
                                view.child(empty_state("选择左侧快照查看和恢复归档项", tokens))
                            }),
                    ),
            )
            .into_any_element()
    }

    fn render_forensic(&mut self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let snapshots = self.model.forensic.clone();
        let selected = self.model.selected_forensic().cloned();
        let selected_collector = self.model.selected_collector;
        let diff = self.model.diff.clone();
        div()
            .size_full()
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
                        crate::buttons::button("forensic-capture")
                            .label(if self.busy {
                                "采集中…"
                            } else {
                                "采集 12 项取证"
                            })
                            .primary()
                            .disabled(self.busy)
                            .on_click(cx.listener(|page, _, _, cx| page.capture_forensic(cx))),
                    )
                    .when(self.cancellation.is_some(), |view| {
                        view.child(
                            crate::buttons::button("forensic-cancel")
                                .label("取消")
                                .on_click(cx.listener(|page, _, _, cx| {
                                    page.cancel_task();
                                    page.notice = Some("取证采集已取消，未保存不完整快照".into());
                                    cx.notify();
                                })),
                        )
                    })
                    .child(
                        crate::buttons::button("forensic-export")
                            .label("复制 JSON")
                            .disabled(selected.is_none())
                            .on_click(cx.listener(|page, _, _, cx| page.export_selected(cx))),
                    )
                    .child(
                        crate::buttons::button("forensic-diff")
                            .label("比较所选两份")
                            .disabled(
                                self.model.diff_older_id.is_none()
                                    || self.model.diff_newer_id.is_none(),
                            )
                            .on_click(cx.listener(|page, _, _, cx| page.calculate_diff(cx))),
                    )
                    .when_some(self.progress.clone(), |view, progress| {
                        view.child(
                            div()
                                .ml_2()
                                .text_sm()
                                .text_color(tokens.accent)
                                .child(progress),
                        )
                    }),
            )
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .flex()
                    .gap_3()
                    .child(
                        div()
                            .w(px(360.0))
                            .min_h_0()
                            .overflow_y_scrollbar()
                            .rounded_lg()
                            .border_1()
                            .border_color(tokens.border)
                            .bg(tokens.surface)
                            .when(snapshots.is_empty(), |view| {
                                view.child(empty_state("尚未采集主机取证快照", tokens))
                            })
                            .children(snapshots.into_iter().map(|snapshot| {
                                let select_id = snapshot.id.clone();
                                let baseline_id = snapshot.id.clone();
                                let compare_id = snapshot.id.clone();
                                let selected =
                                    self.model.selected_forensic_id.as_ref() == Some(&snapshot.id);
                                div()
                                    .id(SharedString::from(format!(
                                        "forensic-snapshot-{}",
                                        snapshot.id
                                    )))
                                    .px_3()
                                    .py_3()
                                    .border_b_1()
                                    .border_color(tokens.border)
                                    .bg(if selected {
                                        tokens.surface_alt
                                    } else {
                                        tokens.surface
                                    })
                                    .child(
                                        div()
                                            .id(SharedString::from(format!(
                                                "forensic-select-{}",
                                                snapshot.id
                                            )))
                                            .cursor_pointer()
                                            .on_click(cx.listener(move |page, _, _, cx| {
                                                page.model.selected_forensic_id =
                                                    Some(select_id.clone());
                                                cx.notify();
                                            }))
                                            .child(
                                                div()
                                                    .flex()
                                                    .items_center()
                                                    .justify_between()
                                                    .child(
                                                        div()
                                                            .text_sm()
                                                            .font_semibold()
                                                            .child(snapshot.server.clone()),
                                                    )
                                                    .child(
                                                        div()
                                                            .text_xs()
                                                            .text_color(
                                                                if snapshot.collection.failed == 0 {
                                                                    tokens.success
                                                                } else {
                                                                    tokens.warning
                                                                },
                                                            )
                                                            .child(format!(
                                                                "失败 {}",
                                                                snapshot.collection.failed
                                                            )),
                                                    ),
                                            )
                                            .child(
                                                div()
                                                    .mt_1()
                                                    .text_xs()
                                                    .text_color(tokens.muted)
                                                    .child(
                                                        snapshot
                                                            .timestamp
                                                            .format("%Y-%m-%d %H:%M:%S UTC")
                                                            .to_string(),
                                                    ),
                                            )
                                            .child(
                                                div()
                                                    .mt_1()
                                                    .font_family("Cascadia Mono")
                                                    .text_xs()
                                                    .text_color(tokens.muted)
                                                    .child(format!(
                                                        "SHA-256 {}…",
                                                        &snapshot.sha256[..16]
                                                    )),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .mt_2()
                                            .flex()
                                            .gap_2()
                                            .child(
                                                crate::buttons::button(SharedString::from(
                                                    format!("forensic-baseline-{}", snapshot.id),
                                                ))
                                                .label("设为基线")
                                                .small()
                                                .selected(
                                                    self.model.diff_older_id.as_ref()
                                                        == Some(&snapshot.id),
                                                )
                                                .on_click(cx.listener(move |page, _, _, cx| {
                                                    page.model.diff_older_id =
                                                        Some(baseline_id.clone());
                                                    page.model.diff = None;
                                                    cx.notify();
                                                })),
                                            )
                                            .child(
                                                crate::buttons::button(SharedString::from(
                                                    format!("forensic-compare-{}", snapshot.id),
                                                ))
                                                .label("设为对比")
                                                .small()
                                                .selected(
                                                    self.model.diff_newer_id.as_ref()
                                                        == Some(&snapshot.id),
                                                )
                                                .on_click(cx.listener(move |page, _, _, cx| {
                                                    page.model.diff_newer_id =
                                                        Some(compare_id.clone());
                                                    page.model.diff = None;
                                                    cx.notify();
                                                })),
                                            ),
                                    )
                            })),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .min_h_0()
                            .flex()
                            .flex_col()
                            .rounded_lg()
                            .border_1()
                            .border_color(tokens.border)
                            .bg(tokens.surface)
                            .when_some(selected, |view, snapshot| {
                                view.child(
                                    div()
                                        .flex()
                                        .items_center()
                                        .gap_2()
                                        .flex_wrap()
                                        .px_3()
                                        .py_2()
                                        .border_b_1()
                                        .border_color(tokens.border)
                                        .children(ForensicCollector::ALL.into_iter().map(
                                            |collector| {
                                                crate::buttons::button(SharedString::from(format!(
                                                    "forensic-field-{}",
                                                    collector.id()
                                                )))
                                                .label(collector.label())
                                                .small()
                                                .selected(selected_collector == collector)
                                                .on_click(cx.listener(move |page, _, _, cx| {
                                                    page.model.selected_collector = collector;
                                                    cx.notify();
                                                }))
                                            },
                                        )),
                                )
                                .child(
                                    div()
                                        .flex_1()
                                        .min_h_0()
                                        .overflow_scrollbar()
                                        .p_4()
                                        .font_family("Cascadia Mono")
                                        .text_sm()
                                        .whitespace_normal()
                                        .child(snapshot.data.get(selected_collector).to_owned()),
                                )
                            })
                            .when_some(diff, |view, diff| {
                                let field = diff
                                    .fields
                                    .iter()
                                    .find(|field| field.collector == selected_collector)
                                    .cloned();
                                view.child(
                                    div()
                                        .border_t_1()
                                        .border_color(tokens.border)
                                        .p_3()
                                        .when_some(field, |view, field| {
                                            view.child(
                                                div().text_xs().text_color(tokens.muted).child(
                                                    format!(
                                                        "差异 · 新增 {} · 删除 {}",
                                                        field.added.len(),
                                                        field.removed.len()
                                                    ),
                                                ),
                                            )
                                            .child(
                                                div()
                                                    .mt_2()
                                                    .max_h(px(180.0))
                                                    .overflow_y_scrollbar()
                                                    .font_family("Cascadia Mono")
                                                    .text_xs()
                                                    .children(field.added.into_iter().map(|line| {
                                                        div()
                                                            .text_color(tokens.success)
                                                            .child(format!("+ {line}"))
                                                    }))
                                                    .children(field.removed.into_iter().map(
                                                        |line| {
                                                            div()
                                                                .text_color(tokens.danger)
                                                                .child(format!("- {line}"))
                                                        },
                                                    )),
                                            )
                                        }),
                                )
                            })
                            .when(self.model.selected_forensic().is_none(), |view| {
                                view.child(empty_state("选择左侧快照查看 12 项取证内容", tokens))
                            }),
                    ),
            )
            .into_any_element()
    }

    fn render_journal(&self, tokens: ThemeTokens) -> AnyElement {
        let entries = self.model.journal.clone();
        div()
            .size_full()
            .min_h_0()
            .overflow_y_scrollbar()
            .rounded_lg()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .when(entries.is_empty(), |view| {
                view.child(empty_state("当前目标尚无快照操作记录", tokens))
            })
            .children(entries.into_iter().map(|entry| {
                div()
                    .px_4()
                    .py_3()
                    .border_b_1()
                    .border_color(tokens.border)
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(div().text_sm().font_semibold().child(entry.summary))
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(tokens.muted)
                                    .child(format!("{:?}", entry.phase)),
                            ),
                    )
                    .child(
                        div()
                            .mt_1()
                            .text_xs()
                            .text_color(tokens.muted)
                            .child(format!(
                                "{} · {}",
                                entry.occurred_at.format("%Y-%m-%d %H:%M:%S UTC"),
                                entry.detail
                            )),
                    )
            }))
            .into_any_element()
    }
}

impl Render for SnapshotPage {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens = self.shared.read(cx).theme.tokens();
        let tab = self.model.tab;
        let content = match tab {
            SnapshotTab::Directory => self.render_directory(tokens, cx),
            SnapshotTab::Forensic => self.render_forensic(tokens, cx),
            SnapshotTab::Journal => self.render_journal(tokens),
        };
        let pending_summary = self
            .pending
            .as_ref()
            .map(|pending| pending.definition().summary.clone());

        div()
            .size_full()
            .min_h_0()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .children(SnapshotTab::ALL.into_iter().map(|item| {
                        crate::buttons::button(SharedString::from(format!(
                            "snapshot-tab-{}",
                            item.label()
                        )))
                            .label(item.label())
                            .selected(tab == item)
                            .on_click(cx.listener(move |page, _, _, cx| {
                                page.model.tab = item;
                                cx.notify();
                            }))
                    }))
                    .child(div().flex_1())
                    .child(
                        crate::buttons::button("snapshot-refresh")
                            .label("刷新")
                            .small()
                            .disabled(self.busy)
                            .on_click(cx.listener(|page, _, _, cx| page.refresh(cx))),
                    ),
            )
            .when_some(self.error.clone(), |view, error| {
                view.child(message_banner(error, tokens.danger, tokens))
            })
            .when_some(self.notice.clone(), |view, notice| {
                view.child(message_banner(notice, tokens.success, tokens))
            })
            .when_some(pending_summary, |view, summary| {
                view.child(
                    div()
                        .rounded_lg()
                        .border_1()
                        .border_color(tokens.danger)
                        .bg(tokens.surface)
                        .p_3()
                        .flex()
                        .items_center()
                        .gap_3()
                        .child(
                            div()
                                .flex_1()
                                .child(div().font_semibold().text_color(tokens.danger).child("危险操作确认"))
                                .child(div().mt_1().text_sm().child(summary))
                                .child(
                                    div()
                                        .mt_1()
                                        .text_xs()
                                        .text_color(tokens.muted)
                                        .child("确认只对这一个计划有效；恢复前会保存当前状态并在失败时自动回滚。"),
                                ),
                        )
                        .child(
                            crate::buttons::button("snapshot-cancel-mutation")
                                .label("取消")
                                .on_click(cx.listener(|page, _, _, cx| {
                                    page.pending = None;
                                    page.notice = Some("操作计划已取消，未产生远端变更".into());
                                    cx.notify();
                                })),
                        )
                        .child(
                            crate::buttons::button("snapshot-approve-mutation")
                                .label("确认执行")
                                .danger()
                                .on_click(cx.listener(|page, _, _, cx| page.approve_mutation(cx))),
                        ),
                )
            })
            .child(div().flex_1().min_h_0().child(content))
    }
}

fn empty_state(message: &'static str, tokens: ThemeTokens) -> impl IntoElement {
    div()
        .h_full()
        .min_h(px(120.0))
        .flex()
        .items_center()
        .justify_center()
        .text_sm()
        .text_color(tokens.muted)
        .child(message)
}

fn message_banner(
    message: SharedString,
    color: gpui::Rgba,
    tokens: ThemeTokens,
) -> impl IntoElement {
    div()
        .rounded_md()
        .border_1()
        .border_color(color)
        .bg(tokens.surface)
        .px_3()
        .py_2()
        .text_sm()
        .text_color(color)
        .child(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lovelyres_core::target::TargetIdentity;

    fn binding(id: &str, generation: u64) -> SnapshotBinding {
        SnapshotBinding {
            session_id: format!("session-{generation}"),
            connection_id: id.to_owned(),
            target: TargetGuard {
                identity: TargetIdentity::new(id).unwrap(),
                generation,
            },
        }
    }

    #[test]
    fn default_selection_matches_the_eight_legacy_presets() {
        let model = SnapshotModel::default();
        assert_eq!(SnapshotPreset::ALL.len(), 8);
        assert_eq!(model.selected_presets.len(), 6);
        assert!(!model.selected_presets.contains(&SnapshotPreset::CronSpool));
        assert!(!model.selected_presets.contains(&SnapshotPreset::RootHome));
    }

    #[test]
    fn stale_request_is_rejected_after_reconnect_or_deactivate() {
        let mut model = SnapshotModel::default();
        let first = binding("target-a", 1);
        model.activate(Some(first.clone()));
        let lease = model.begin_request(first.clone()).unwrap();
        assert!(model.accepts(&lease, Some(&first)));
        let reconnect = binding("target-a", 2);
        model.rebind(Some(reconnect.clone()));
        assert!(!model.accepts(&lease, Some(&reconnect)));
        model.deactivate();
        assert!(!model.accepts(&lease, Some(&first)));
    }

    #[test]
    fn a_newer_request_invalidates_an_older_result() {
        let mut model = SnapshotModel::default();
        let target = binding("target-a", 1);
        model.activate(Some(target.clone()));
        let old = model.begin_request(target.clone()).unwrap();
        let new = model.begin_request(target.clone()).unwrap();
        assert!(!model.accepts(&old, Some(&target)));
        assert!(model.accepts(&new, Some(&target)));
    }
}
