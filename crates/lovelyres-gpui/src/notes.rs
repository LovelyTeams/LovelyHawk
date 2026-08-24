use std::sync::Arc;

use gpui::{
    AnyElement, ClipboardItem, Context, Entity, IntoElement, Render, SharedString, Subscription,
    Window, div, prelude::*, px,
};
use gpui_component::{
    Sizable,
    button::ButtonVariants,
    input::{Input, InputEvent, InputState},
    scroll::ScrollableElement,
};
use lovelyres_core::{
    BackendServices, CoreError, CoreResult,
    investigation::{CreateNote, Note, NoteDeletePlan, NoteRepository, NotesExport, UpdateNote},
    operations::{DangerousConfirmation, OperationPlan},
    target::{TargetContext, TargetGuard},
};

use crate::{
    app::SharedAppState,
    interaction::{DialogError, DialogId, DialogOutcome},
    runtime::TokioBridge,
    theme::ThemeTokens,
};

const MAX_PREVIEW_CHARS: usize = 80;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotesTargetBinding(Option<TargetGuard>);

impl NotesTargetBinding {
    pub fn capture(target: &TargetContext) -> Self {
        Self(target.current_guard().ok())
    }

    pub fn is_current(&self, target: &TargetContext) -> bool {
        self.0 == target.current_guard().ok()
    }

    pub fn label(&self) -> String {
        self.0.as_ref().map_or_else(
            || "便携 Notes 工作区（未连接目标）".to_owned(),
            |guard| {
                format!(
                    "目标 {} · generation {}",
                    guard.identity.as_str(),
                    guard.generation
                )
            },
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotesRequestLease {
    activation_generation: u64,
    request_id: u64,
    target: NotesTargetBinding,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NoteDraft {
    id: String,
    title: String,
    content: String,
    dirty: bool,
}

impl From<&Note> for NoteDraft {
    fn from(note: &Note) -> Self {
        Self {
            id: note.id.clone(),
            title: note.title.clone(),
            content: note.content.clone(),
            dirty: false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DeleteProposal {
    lease: NotesRequestLease,
    deletion: NoteDeletePlan,
}

impl DeleteProposal {
    pub fn plan(&self) -> &OperationPlan {
        self.deletion.definition()
    }
}

#[derive(Clone, Debug)]
struct PendingDelete {
    proposal: DeleteProposal,
    dialog_id: DialogId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeleteResolution {
    Ignored,
    Cancelled,
    Stale,
    Authorized {
        deletion: Box<NoteDeletePlan>,
        confirmation: DangerousConfirmation,
        presentation: NotesRequestLease,
    },
}

#[derive(Debug)]
pub struct NotesModel {
    notes: Vec<Note>,
    selected_id: Option<String>,
    query: String,
    draft: Option<NoteDraft>,
    active: bool,
    activation_generation: u64,
    next_request_id: u64,
    latest_list_request_id: Option<u64>,
    binding: NotesTargetBinding,
    pending_delete: Option<PendingDelete>,
}

impl Default for NotesModel {
    fn default() -> Self {
        Self {
            notes: Vec::new(),
            selected_id: None,
            query: String::new(),
            draft: None,
            active: false,
            activation_generation: 0,
            next_request_id: 0,
            latest_list_request_id: None,
            binding: NotesTargetBinding(None),
            pending_delete: None,
        }
    }
}

impl NotesModel {
    pub fn activate(&mut self, target: &TargetContext) -> u64 {
        if !self.active {
            self.active = true;
            self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
        }
        self.binding = NotesTargetBinding::capture(target);
        self.activation_generation
    }

    pub fn deactivate(&mut self) {
        self.active = false;
        self.latest_list_request_id = None;
        self.pending_delete = None;
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub const fn activation_generation(&self) -> u64 {
        self.activation_generation
    }

    pub fn binding(&self) -> &NotesTargetBinding {
        &self.binding
    }

    pub fn query(&self) -> &str {
        &self.query
    }

    pub fn set_query(&mut self, query: impl Into<String>) {
        self.query = query.into();
    }

    pub fn notes(&self) -> &[Note] {
        &self.notes
    }

    pub fn selected(&self) -> Option<&Note> {
        let selected = self.selected_id.as_deref()?;
        self.notes.iter().find(|note| note.id == selected)
    }

    pub fn selected_id(&self) -> Option<&str> {
        self.selected_id.as_deref()
    }

    fn draft(&self) -> Option<&NoteDraft> {
        self.draft.as_ref()
    }

    fn draft_is_dirty(&self) -> bool {
        self.draft.as_ref().is_some_and(|draft| draft.dirty)
    }

    fn edit_title(&mut self, title: String) {
        if let Some(draft) = self.draft.as_mut()
            && draft.title != title
        {
            draft.title = title;
            draft.dirty = true;
        }
    }

    fn edit_content(&mut self, content: String) {
        if let Some(draft) = self.draft.as_mut()
            && draft.content != content
        {
            draft.content = content;
            draft.dirty = true;
        }
    }

    pub fn select(&mut self, id: &str) -> bool {
        let Some(note) = self.notes.iter().find(|note| note.id == id) else {
            return false;
        };
        self.selected_id = Some(note.id.clone());
        self.draft = Some(NoteDraft::from(note));
        true
    }

    fn begin_list_request(&mut self, target: &TargetContext) -> Option<NotesRequestLease> {
        if !self.active {
            return None;
        }
        self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
        let lease = NotesRequestLease {
            activation_generation: self.activation_generation,
            request_id: self.next_request_id,
            target: NotesTargetBinding::capture(target),
        };
        self.latest_list_request_id = Some(lease.request_id);
        Some(lease)
    }

    pub fn accepts(&self, lease: &NotesRequestLease, target: &TargetContext) -> bool {
        self.active
            && self.activation_generation == lease.activation_generation
            && lease.target.is_current(target)
    }

    fn apply_list(
        &mut self,
        lease: &NotesRequestLease,
        target: &TargetContext,
        notes: Vec<Note>,
    ) -> bool {
        if self.latest_list_request_id != Some(lease.request_id) || !self.accepts(lease, target) {
            return false;
        }
        self.latest_list_request_id = None;
        let prior_selected = self.selected_id.clone();
        self.notes = notes;
        let selected = prior_selected
            .filter(|id| self.notes.iter().any(|note| note.id == *id))
            .or_else(|| self.notes.first().map(|note| note.id.clone()));
        self.selected_id = selected.clone();
        self.draft = selected
            .as_deref()
            .and_then(|id| self.notes.iter().find(|note| note.id == id))
            .map(NoteDraft::from);
        true
    }

    fn replace_note(&mut self, updated: Note) {
        if let Some(note) = self.notes.iter_mut().find(|note| note.id == updated.id) {
            *note = updated.clone();
        } else {
            self.notes.push(updated.clone());
        }
        self.notes.sort_by(|left, right| {
            right
                .pinned
                .cmp(&left.pinned)
                .then_with(|| right.updated_at.cmp(&left.updated_at))
                .then_with(|| left.id.cmp(&right.id))
        });
        if self.selected_id.as_deref() == Some(&updated.id) {
            self.draft = Some(NoteDraft::from(&updated));
        }
    }

    fn insert_and_select(&mut self, note: Note) {
        let id = note.id.clone();
        self.replace_note(note);
        let _ = self.select(&id);
    }

    fn remove(&mut self, id: &str) {
        self.notes.retain(|note| note.id != id);
        if self.selected_id.as_deref() == Some(id) {
            self.selected_id = None;
            self.draft = None;
        }
    }

    fn apply_delete_success(
        &mut self,
        lease: &NotesRequestLease,
        target: &TargetContext,
        note_id: &str,
    ) -> bool {
        if !self.accepts(lease, target) {
            return false;
        }
        self.remove(note_id);
        true
    }

    pub fn propose_delete(
        &mut self,
        id: &str,
        target: &TargetContext,
        repository: &NoteRepository,
    ) -> CoreResult<DeleteProposal> {
        if !self.active {
            return Err(CoreError::Validation {
                subject: "notes page",
                message: "page is not active".to_owned(),
            });
        }
        let _note = self
            .notes
            .iter()
            .find(|note| note.id == id)
            .ok_or_else(|| CoreError::Validation {
                subject: "note",
                message: "selected note no longer exists".to_owned(),
            })?;
        self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
        let lease = NotesRequestLease {
            activation_generation: self.activation_generation,
            request_id: self.next_request_id,
            target: NotesTargetBinding::capture(target),
        };
        let deletion = repository.plan_delete(id)?;
        Ok(DeleteProposal { lease, deletion })
    }

    pub fn arm_delete(&mut self, proposal: DeleteProposal, dialog_id: DialogId) {
        self.pending_delete = Some(PendingDelete {
            proposal,
            dialog_id,
        });
    }

    pub fn pending_delete_dialog_id(&self) -> Option<DialogId> {
        self.pending_delete
            .as_ref()
            .map(|pending| pending.dialog_id)
    }

    pub fn resolve_delete(
        &mut self,
        outcome: &DialogOutcome,
        target: &TargetContext,
    ) -> DeleteResolution {
        let Some(pending) = self.pending_delete.as_ref() else {
            return DeleteResolution::Ignored;
        };
        let matches_dialog = match outcome {
            DialogOutcome::Cancelled { dialog_id }
            | DialogOutcome::DangerousApproved { dialog_id, .. } => *dialog_id == pending.dialog_id,
            DialogOutcome::AlertDismissed { .. } | DialogOutcome::PromptSubmitted { .. } => false,
        };
        if !matches_dialog {
            return DeleteResolution::Ignored;
        }
        let pending = self
            .pending_delete
            .take()
            .expect("matched pending delete exists");
        match outcome {
            DialogOutcome::Cancelled { .. } => DeleteResolution::Cancelled,
            DialogOutcome::DangerousApproved { operation_id, .. }
                if operation_id == &pending.proposal.plan().id =>
            {
                if self.accepts(&pending.proposal.lease, target) {
                    DeleteResolution::Authorized {
                        confirmation: DangerousConfirmation::approve(pending.proposal.plan()),
                        presentation: pending.proposal.lease,
                        deletion: Box::new(pending.proposal.deletion),
                    }
                } else {
                    DeleteResolution::Stale
                }
            }
            DialogOutcome::DangerousApproved { .. } => DeleteResolution::Ignored,
            DialogOutcome::AlertDismissed { .. } | DialogOutcome::PromptSubmitted { .. } => {
                DeleteResolution::Ignored
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotesTextExport {
    pub note_count: usize,
    pub text: String,
}

impl NotesTextExport {
    pub fn from_export(export: NotesExport) -> Self {
        let note_count = export.notes.len();
        let mut lines = vec![
            "LovelyRes Notes Export".to_owned(),
            format!("Schema: {}", export.schema),
            format!("Exported-At-Unix-Ms: {}", export.exported_at_millis),
            format!("Count: {note_count}"),
        ];
        for note in export.notes {
            lines.extend([
                String::new(),
                "----------------------------------------".to_owned(),
                format!("Title: {}", note.title),
                format!("Pinned: {}", note.pinned),
                format!("Created-At-Unix-Ms: {}", note.created_at),
                format!("Updated-At-Unix-Ms: {}", note.updated_at),
                format!(
                    "Tags: {}",
                    if note.tags.is_empty() {
                        "(none)".to_owned()
                    } else {
                        note.tags.join(", ")
                    }
                ),
                "Content:".to_owned(),
                note.content,
            ]);
        }
        lines.push(String::new());
        Self {
            note_count,
            text: lines.join("\n"),
        }
    }
}

pub struct NotesPage {
    services: Arc<BackendServices>,
    tokio: Arc<TokioBridge>,
    shared: Entity<SharedAppState>,
    model: NotesModel,
    search_input: Entity<InputState>,
    title_input: Entity<InputState>,
    content_input: Entity<InputState>,
    tag_input: Entity<InputState>,
    loading_inputs: bool,
    list_abort: Option<tokio::task::AbortHandle>,
    notice: Option<(SharedString, bool)>,
    _subscriptions: Vec<Subscription>,
}

impl NotesPage {
    pub fn new(
        services: Arc<BackendServices>,
        tokio: Arc<TokioBridge>,
        shared: Entity<SharedAppState>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let search_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("搜索标题、正文或 #标签…"));
        let title_input = cx.new(|cx| InputState::new(window, cx).placeholder("笔记标题"));
        let content_input = cx.new(|cx| {
            InputState::new(window, cx)
                .multi_line(true)
                .rows(18)
                .placeholder("开始记录…")
        });
        let tag_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("添加标签，按 Enter 确认"));
        let subscriptions = vec![
            cx.subscribe_in(
                &search_input,
                window,
                |page, input, event: &InputEvent, _, cx| {
                    if matches!(event, InputEvent::Change) {
                        page.model.set_query(input.read(cx).value().to_string());
                        page.refresh_list(cx);
                    }
                },
            ),
            cx.subscribe_in(
                &title_input,
                window,
                |page, input, event: &InputEvent, _, cx| match event {
                    InputEvent::Change if !page.loading_inputs => {
                        page.model.edit_title(input.read(cx).value().to_string());
                        cx.notify();
                    }
                    InputEvent::Blur => page.save_editor(cx),
                    InputEvent::Change | InputEvent::PressEnter { .. } | InputEvent::Focus => {}
                },
            ),
            cx.subscribe_in(
                &content_input,
                window,
                |page, input, event: &InputEvent, _, cx| match event {
                    InputEvent::Change if !page.loading_inputs => {
                        page.model.edit_content(input.read(cx).value().to_string());
                        cx.notify();
                    }
                    InputEvent::Blur => page.save_editor(cx),
                    InputEvent::Change | InputEvent::PressEnter { .. } | InputEvent::Focus => {}
                },
            ),
            cx.subscribe_in(
                &tag_input,
                window,
                |page, input, event: &InputEvent, window, cx| {
                    if matches!(event, InputEvent::PressEnter { .. }) {
                        page.add_tag(input.read(cx).value().to_string(), window, cx);
                    }
                },
            ),
        ];
        Self {
            services,
            tokio,
            shared,
            model: NotesModel::default(),
            search_input,
            title_input,
            content_input,
            tag_input,
            loading_inputs: false,
            list_abort: None,
            notice: None,
            _subscriptions: subscriptions,
        }
    }

    pub fn activate(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.model.activate(self.services.target());
        self.search_input.update(cx, |input, cx| {
            input.focus(window, cx);
        });
        self.refresh_list(cx);
        cx.notify();
    }

    pub fn deactivate(&mut self, cx: &mut Context<Self>) {
        self.save_editor(cx);
        if let Some(abort) = self.list_abort.take() {
            abort.abort();
        }
        if let Some(dialog_id) = self.model.pending_delete_dialog_id() {
            self.shared.update(cx, |state, cx| {
                if state
                    .interactions
                    .dialogs
                    .active()
                    .map(|dialog| dialog.id())
                    == Some(dialog_id)
                {
                    let _ = state
                        .interactions
                        .dialogs
                        .dispatch(crate::interaction::DialogAction::Cancel { dialog_id });
                    state.interactions.mark_overlay_closed();
                    cx.notify();
                }
            });
        }
        self.model.deactivate();
        cx.notify();
    }

    pub fn handle_dialog_outcome(
        &mut self,
        outcome: &DialogOutcome,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        match self.model.resolve_delete(outcome, self.services.target()) {
            DeleteResolution::Ignored => false,
            DeleteResolution::Cancelled => {
                self.notice = Some(("删除已取消".into(), false));
                cx.notify();
                true
            }
            DeleteResolution::Stale => {
                self.notice = Some(("目标或页面已变化，迟到的删除确认未执行".into(), true));
                cx.notify();
                true
            }
            DeleteResolution::Authorized {
                deletion,
                confirmation,
                presentation,
            } => {
                let note_id = deletion.note_id().to_owned();
                let repository = self.services.investigation().notes().clone();
                let journal = self.services.operation_journal().clone();
                let task = self.tokio.spawn(async move {
                    repository
                        .execute_delete(*deletion, confirmation, &journal)
                        .await
                });
                cx.spawn(async move |page, cx| {
                    let result = task.await;
                    let _ = cx.update(|cx| {
                        if let Some(page) = page.upgrade() {
                            page.update(cx, |page, cx| {
                                page.finish_delete(presentation, note_id, result, cx)
                            });
                        }
                    });
                })
                .detach();
                true
            }
        }
    }

    fn finish_delete(
        &mut self,
        presentation: NotesRequestLease,
        note_id: String,
        result: Result<
            CoreResult<lovelyres_core::investigation::InvestigationOperationOutcome>,
            tokio::task::JoinError,
        >,
        cx: &mut Context<Self>,
    ) {
        if !self.model.accepts(&presentation, self.services.target()) {
            return;
        }
        match result {
            Err(error) => {
                self.notice = Some((format!("删除任务失败：{error}").into(), true));
            }
            Ok(Err(error)) => {
                self.notice = Some((format!("删除失败：{error}").into(), true));
            }
            Ok(Ok(_)) => {
                let _ = self.model.apply_delete_success(
                    &presentation,
                    self.services.target(),
                    &note_id,
                );
                self.notice = Some(("笔记已永久删除并完成日志验证".into(), false));
            }
        }
        cx.notify();
    }

    fn refresh_list(&mut self, cx: &mut Context<Self>) {
        let Some(lease) = self.model.begin_list_request(self.services.target()) else {
            return;
        };
        if let Some(abort) = self.list_abort.take() {
            abort.abort();
        }
        let query = self.model.query().to_owned();
        let repository = self.services.investigation().notes().clone();
        let task = self.tokio.spawn(async move {
            if query.trim().is_empty() {
                repository.list()
            } else {
                repository.search(&query)
            }
        });
        self.list_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_list(lease, result, cx));
                }
            });
        })
        .detach();
    }

    fn finish_list(
        &mut self,
        lease: NotesRequestLease,
        result: Result<CoreResult<Vec<Note>>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let result = match result {
            Ok(result) => result,
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.notice = Some((format!("笔记加载任务失败：{error}").into(), true));
                cx.notify();
                return;
            }
        };
        if !self.model.accepts(&lease, self.services.target()) {
            return;
        }
        match result {
            Ok(notes) => {
                if self.model.apply_list(&lease, self.services.target(), notes) {
                    self.list_abort = None;
                }
            }
            Err(error) => {
                self.notice = Some((format!("笔记读取失败：{error}").into(), true));
            }
        }
        cx.notify();
    }

    fn save_editor(&mut self, cx: &mut Context<Self>) {
        if !self.model.draft_is_dirty() {
            return;
        }
        let Some(draft) = self.model.draft().cloned() else {
            return;
        };
        match self.services.investigation().notes().update(
            &draft.id,
            UpdateNote {
                title: Some(draft.title),
                content: Some(draft.content),
                tags: None,
            },
        ) {
            Ok(note) => {
                self.model.replace_note(note);
                self.notice = Some(("笔记已保存".into(), false));
            }
            Err(error) => {
                self.notice = Some((format!("笔记保存失败：{error}").into(), true));
            }
        }
        cx.notify();
    }

    fn create_note(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.save_editor(cx);
        match self
            .services
            .investigation()
            .notes()
            .create(CreateNote::default())
        {
            Ok(note) => {
                self.model.set_query("");
                self.search_input
                    .update(cx, |input, cx| input.set_value("", window, cx));
                self.model.insert_and_select(note);
                self.sync_editor_inputs(window, cx);
                self.title_input.update(cx, |input, cx| {
                    input.focus(window, cx);
                });
                self.notice = Some(("已新建笔记".into(), false));
            }
            Err(error) => {
                self.notice = Some((format!("新建笔记失败：{error}").into(), true));
            }
        }
        cx.notify();
    }

    fn select_note(&mut self, id: &str, window: &mut Window, cx: &mut Context<Self>) {
        self.save_editor(cx);
        if self.model.select(id) {
            self.sync_editor_inputs(window, cx);
            cx.notify();
        }
    }

    fn toggle_pin(&mut self, id: &str, cx: &mut Context<Self>) {
        let Some(note) = self.model.notes().iter().find(|note| note.id == id) else {
            return;
        };
        match self
            .services
            .investigation()
            .notes()
            .set_pinned(id, !note.pinned)
        {
            Ok(note) => {
                self.model.replace_note(note);
                self.notice = Some(("置顶状态已保存".into(), false));
            }
            Err(error) => {
                self.notice = Some((format!("置顶更新失败：{error}").into(), true));
            }
        }
        cx.notify();
    }

    fn add_tag(&mut self, tag: String, window: &mut Window, cx: &mut Context<Self>) {
        let Some(id) = self.model.selected_id().map(ToOwned::to_owned) else {
            return;
        };
        if tag.trim().is_empty() {
            return;
        }
        match self.services.investigation().notes().add_tag(&id, tag) {
            Ok(note) => {
                self.model.replace_note(note);
                self.tag_input
                    .update(cx, |input, cx| input.set_value("", window, cx));
                self.notice = Some(("标签已添加".into(), false));
            }
            Err(error) => {
                self.notice = Some((format!("添加标签失败：{error}").into(), true));
            }
        }
        cx.notify();
    }

    fn remove_tag(&mut self, tag: &str, cx: &mut Context<Self>) {
        let Some(id) = self.model.selected_id().map(ToOwned::to_owned) else {
            return;
        };
        match self.services.investigation().notes().remove_tag(&id, tag) {
            Ok(note) => {
                self.model.replace_note(note);
                self.notice = Some(("标签已移除".into(), false));
            }
            Err(error) => {
                self.notice = Some((format!("移除标签失败：{error}").into(), true));
            }
        }
        cx.notify();
    }

    fn filter_tag(&mut self, tag: &str, window: &mut Window, cx: &mut Context<Self>) {
        let query = format!("#{tag}");
        self.model.set_query(query.clone());
        self.search_input
            .update(cx, |input, cx| input.set_value(query, window, cx));
        self.refresh_list(cx);
    }

    fn request_delete(&mut self, id: &str, cx: &mut Context<Self>) {
        self.save_editor(cx);
        let proposal = match self.model.propose_delete(
            id,
            self.services.target(),
            self.services.investigation().notes(),
        ) {
            Ok(proposal) => proposal,
            Err(error) => {
                self.notice = Some((format!("无法创建删除计划：{error}").into(), true));
                cx.notify();
                return;
            }
        };
        let plan = proposal.plan().clone();
        let dialog = self.shared.update(cx, |state, cx| {
            if state.interactions.dialogs.active().is_some() {
                return Err(DialogError::ActionTypeMismatch);
            }
            let dialog_id = state.interactions.dialogs.show_dangerous(&plan)?;
            state.interactions.focus_dialog();
            cx.notify();
            Ok(dialog_id)
        });
        match dialog {
            Ok(dialog_id) => self.model.arm_delete(proposal, dialog_id),
            Err(error) => {
                self.notice = Some((format!("删除确认框无法打开：{error:?}").into(), true));
            }
        }
        cx.notify();
    }

    fn export_all(&mut self, cx: &mut Context<Self>) {
        match self.services.investigation().notes().export_all() {
            Ok(export) => self.copy_export(NotesTextExport::from_export(export), cx),
            Err(error) => {
                self.notice = Some((format!("导出失败：{error}").into(), true));
                cx.notify();
            }
        }
    }

    fn export_selected(&mut self, cx: &mut Context<Self>) {
        self.save_editor(cx);
        let Some(id) = self.model.selected_id().map(ToOwned::to_owned) else {
            return;
        };
        match self.services.investigation().notes().export_one(&id) {
            Ok(export) => self.copy_export(NotesTextExport::from_export(export), cx),
            Err(error) => {
                self.notice = Some((format!("导出失败：{error}").into(), true));
                cx.notify();
            }
        }
    }

    fn copy_export(&mut self, export: NotesTextExport, cx: &mut Context<Self>) {
        cx.write_to_clipboard(ClipboardItem::new_string(export.text));
        self.notice = Some((
            format!("已复制 {} 条笔记的纯文本导出", export.note_count).into(),
            false,
        ));
        cx.notify();
    }

    fn sync_editor_inputs(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let (title, content) = self.model.draft().map_or_else(
            || (String::new(), String::new()),
            |draft| (draft.title.clone(), draft.content.clone()),
        );
        self.loading_inputs = true;
        self.title_input
            .update(cx, |input, cx| input.set_value(title, window, cx));
        self.content_input
            .update(cx, |input, cx| input.set_value(content, window, cx));
        self.tag_input
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.loading_inputs = false;
    }
}

impl Render for NotesPage {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens = self.shared.read(cx).theme.tokens();
        let notes = self.model.notes().to_vec();
        let selected_id = self.model.selected_id().map(ToOwned::to_owned);
        let selected = self.model.selected().cloned();
        let notice = self.notice.clone();
        let binding = self.model.binding().label();

        div()
            .id("notes-page")
            .size_full()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(
                        div()
                            .child(div().text_2xl().child("调查笔记"))
                            .child(div().text_xs().text_color(tokens.muted).child(binding)),
                    )
                    .child(
                        div()
                            .ml_auto()
                            .flex()
                            .gap_2()
                            .child(
                                crate::buttons::button("notes-refresh")
                                    .label("刷新")
                                    .small()
                                    .on_click(cx.listener(|this, _, _, cx| this.refresh_list(cx))),
                            )
                            .child(
                                crate::buttons::button("notes-export-all")
                                    .label("导出全部")
                                    .small()
                                    .on_click(cx.listener(|this, _, _, cx| this.export_all(cx))),
                            )
                            .child(
                                crate::buttons::button("notes-create")
                                    .label("+ 新建笔记")
                                    .small()
                                    .primary()
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.create_note(window, cx)
                                    })),
                            ),
                    ),
            )
            .when_some(notice, |page, (message, is_error)| {
                page.child(
                    div()
                        .rounded_md()
                        .border_1()
                        .border_color(if is_error {
                            tokens.danger
                        } else {
                            tokens.success
                        })
                        .p_2()
                        .text_sm()
                        .text_color(if is_error {
                            tokens.danger
                        } else {
                            tokens.success
                        })
                        .child(message),
                )
            })
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .flex()
                    .gap_3()
                    .child(
                        div()
                            .w(px(330.0))
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
                            .child(Input::new(&self.search_input).small())
                            .child(
                                div()
                                    .flex_1()
                                    .min_h_0()
                                    .overflow_y_scrollbar()
                                    .when(notes.is_empty(), |list| {
                                        list.child(
                                            div()
                                                .p_5()
                                                .text_center()
                                                .text_sm()
                                                .text_color(tokens.muted)
                                                .child(if self.model.query().trim().is_empty() {
                                                    "暂无笔记，点击“新建笔记”开始记录"
                                                } else {
                                                    "没有匹配的笔记"
                                                }),
                                        )
                                    })
                                    .children(notes.into_iter().map(|note| {
                                        note_list_item(note, selected_id.as_deref(), tokens, cx)
                                    })),
                            )
                            .child(
                                div()
                                    .pt_2()
                                    .border_t_1()
                                    .border_color(tokens.border)
                                    .text_xs()
                                    .text_color(tokens.muted)
                                    .child(format!("当前筛选 {} 条", self.model.notes().len())),
                            ),
                    )
                    .child(match selected {
                        Some(note) => self.render_editor(note, tokens, cx),
                        None => empty_editor(tokens, cx),
                    }),
            )
    }
}

impl NotesPage {
    fn render_editor(
        &mut self,
        note: Note,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let pin_id = note.id.clone();
        let delete_id = note.id.clone();
        div()
            .id("notes-editor")
            .flex_1()
            .min_w_0()
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
                    .gap_2()
                    .child(div().flex_1().child(Input::new(&self.title_input)))
                    .child(
                        crate::buttons::button("notes-save")
                            .label(if self.model.draft_is_dirty() {
                                "保存 *"
                            } else {
                                "已保存"
                            })
                            .small()
                            .on_click(cx.listener(|this, _, _, cx| this.save_editor(cx))),
                    )
                    .child(
                        crate::buttons::button("notes-export-selected")
                            .label("复制导出")
                            .small()
                            .on_click(cx.listener(|this, _, _, cx| this.export_selected(cx))),
                    )
                    .child(
                        crate::buttons::button("notes-pin-selected")
                            .label(if note.pinned {
                                "取消置顶"
                            } else {
                                "置顶"
                            })
                            .small()
                            .on_click(
                                cx.listener(move |this, _, _, cx| this.toggle_pin(&pin_id, cx)),
                            ),
                    )
                    .child(
                        crate::buttons::button("notes-delete-selected")
                            .label("永久删除")
                            .small()
                            .danger()
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.request_delete(&delete_id, cx)
                            })),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .items_center()
                    .gap_2()
                    .children(note.tags.into_iter().map(|tag| {
                        let filter_tag = tag.clone();
                        let remove_tag = tag.clone();
                        div()
                            .flex()
                            .items_center()
                            .rounded_md()
                            .bg(tokens.surface_alt)
                            .child(
                                crate::buttons::button(SharedString::from(format!(
                                    "notes-filter-tag-{filter_tag}"
                                )))
                                .label(format!("#{filter_tag}"))
                                .xsmall()
                                .on_click(cx.listener(
                                    move |this, _, window, cx| {
                                        this.filter_tag(&filter_tag, window, cx)
                                    },
                                )),
                            )
                            .child(
                                crate::buttons::button(SharedString::from(format!(
                                    "notes-remove-tag-{remove_tag}"
                                )))
                                .label("×")
                                .xsmall()
                                .on_click(cx.listener(
                                    move |this, _, _, cx| this.remove_tag(&remove_tag, cx),
                                )),
                            )
                    }))
                    .child(
                        div()
                            .w(px(240.0))
                            .child(Input::new(&self.tag_input).small()),
                    ),
            )
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .child(Input::new(&self.content_input)),
            )
            .child(
                div()
                    .flex()
                    .justify_between()
                    .text_xs()
                    .text_color(tokens.muted)
                    .child(format!("创建：{}", note.created_at))
                    .child(format!("更新：{}", note.updated_at)),
            )
            .into_any_element()
    }
}

fn note_list_item(
    note: Note,
    selected_id: Option<&str>,
    tokens: ThemeTokens,
    cx: &mut Context<NotesPage>,
) -> AnyElement {
    let select_id = note.id.clone();
    let pin_id = note.id.clone();
    let delete_id = note.id.clone();
    let selected = selected_id == Some(note.id.as_str());
    let preview = note_preview(&note.content);
    div()
        .id(SharedString::from(format!("notes-list-item-{}", note.id)))
        .mb_2()
        .rounded_md()
        .border_1()
        .border_color(if selected {
            tokens.accent
        } else {
            tokens.border
        })
        .bg(if selected {
            tokens.surface_alt
        } else {
            tokens.surface
        })
        .p_2()
        .child(
            crate::buttons::button(SharedString::from(format!("notes-select-{}", note.id)))
                .label(if note.pinned {
                    format!("★ {}", note.title)
                } else {
                    note.title.clone()
                })
                .small()
                .on_click(
                    cx.listener(move |this, _, window, cx| {
                        this.select_note(&select_id, window, cx)
                    }),
                ),
        )
        .child(
            div()
                .mt_1()
                .text_xs()
                .text_color(tokens.muted)
                .child(preview),
        )
        .child(
            div()
                .mt_2()
                .flex()
                .items_center()
                .gap_1()
                .child(
                    crate::buttons::button(SharedString::from(format!("notes-pin-{}", note.id)))
                        .label(if note.pinned {
                            "取消置顶"
                        } else {
                            "置顶"
                        })
                        .xsmall()
                        .on_click(cx.listener(move |this, _, _, cx| this.toggle_pin(&pin_id, cx))),
                )
                .child(
                    crate::buttons::button(SharedString::from(format!("notes-delete-{}", note.id)))
                        .label("删除")
                        .xsmall()
                        .danger()
                        .on_click(
                            cx.listener(move |this, _, _, cx| this.request_delete(&delete_id, cx)),
                        ),
                )
                .child(
                    div()
                        .ml_auto()
                        .text_xs()
                        .text_color(tokens.muted)
                        .child(format!("{}", note.updated_at)),
                ),
        )
        .into_any_element()
}

fn empty_editor(tokens: ThemeTokens, cx: &mut Context<NotesPage>) -> AnyElement {
    div()
        .id("notes-empty-editor")
        .flex_1()
        .min_w_0()
        .rounded_lg()
        .border_1()
        .border_color(tokens.border)
        .bg(tokens.surface)
        .items_center()
        .justify_center()
        .flex()
        .flex_col()
        .gap_3()
        .text_color(tokens.muted)
        .child("选择或创建笔记开始记录")
        .child(
            crate::buttons::button("notes-empty-create")
                .label("+ 新建笔记")
                .primary()
                .on_click(cx.listener(|this, _, window, cx| this.create_note(window, cx))),
        )
        .into_any_element()
}

fn note_preview(content: &str) -> String {
    let preview = content
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(MAX_PREVIEW_CHARS)
        .collect::<String>();
    if preview.is_empty() {
        "空笔记".to_owned()
    } else {
        preview
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use lovelyres_core::{PortableStore, investigation::NOTES_SCHEMA_ID, target::TargetIdentity};
    use uuid::Uuid;

    use super::*;
    use crate::interaction::{DialogAction, DialogHost};

    fn services() -> (PathBuf, Arc<BackendServices>) {
        let root = std::env::temp_dir().join(format!("lovelyres-notes-page-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let store = PortableStore::prepare(root.clone()).unwrap();
        (root, Arc::new(BackendServices::new(store).unwrap()))
    }

    #[test]
    fn repository_crud_search_selection_and_export_are_typed() {
        let (root, services) = services();
        let repository = services.investigation().notes();
        let first = repository
            .create(CreateNote {
                title: Some("Rootkit 调查".to_owned()),
                content: "检查 /proc".to_owned(),
                tags: vec!["linux".to_owned()],
            })
            .unwrap();
        repository
            .create(CreateNote {
                title: Some("网络".to_owned()),
                content: "pcap evidence".to_owned(),
                tags: vec!["network".to_owned()],
            })
            .unwrap();
        let results = repository.search("#linux").unwrap();
        assert_eq!(results, vec![first.clone()]);

        let mut model = NotesModel::default();
        model.activate(services.target());
        let lease = model.begin_list_request(services.target()).unwrap();
        assert!(model.apply_list(&lease, services.target(), results));
        assert_eq!(model.selected_id(), Some(first.id.as_str()));
        assert!(model.select(&first.id));

        let export = NotesTextExport::from_export(repository.export_one(&first.id).unwrap());
        assert_eq!(export.note_count, 1);
        assert!(export.text.contains(NOTES_SCHEMA_ID));
        assert!(export.text.contains("Rootkit 调查"));
        assert!(export.text.contains("检查 /proc"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn malicious_html_remains_ordinary_text_in_preview_and_export() {
        let (root, services) = services();
        let attack = "<img src=x onerror=alert(1)><script>steal()</script>";
        let note = services
            .investigation()
            .notes()
            .create(CreateNote {
                title: Some("<b>not bold</b>".to_owned()),
                content: attack.to_owned(),
                tags: vec!["<svg/onload=bad>".to_owned()],
            })
            .unwrap();
        assert_eq!(note_preview(&note.content), attack);
        let export = NotesTextExport::from_export(
            services
                .investigation()
                .notes()
                .export_one(&note.id)
                .unwrap(),
        );
        assert!(export.text.contains("<b>not bold</b>"));
        assert!(export.text.contains(attack));
        let source = include_str!("notes.rs").to_lowercase();
        assert!(!source.contains(&["inner", "_html"].concat()));
        assert!(!source.contains(&["render", "_markdown"].concat()));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn deactivation_and_target_generation_reject_late_results() {
        let (root, services) = services();
        let target = TargetIdentity::new("connection-a").unwrap();
        services.activate_target(target.clone()).unwrap();
        let mut model = NotesModel::default();
        model.activate(services.target());
        let deactivated = model.begin_list_request(services.target()).unwrap();
        model.deactivate();
        assert!(!model.apply_list(&deactivated, services.target(), Vec::new()));

        model.activate(services.target());
        let old_target = model.begin_list_request(services.target()).unwrap();
        services.activate_target(target).unwrap();
        assert!(!model.apply_list(&old_target, services.target(), Vec::new()));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn delete_without_exact_confirmation_never_calls_repository_delete() {
        let (root, services) = services();
        let repository = services.investigation().notes();
        let note = repository
            .create(CreateNote {
                title: Some("do not delete".to_owned()),
                content: String::new(),
                tags: Vec::new(),
            })
            .unwrap();
        let mut model = NotesModel::default();
        model.activate(services.target());
        let lease = model.begin_list_request(services.target()).unwrap();
        assert!(model.apply_list(&lease, services.target(), repository.list().unwrap()));
        let proposal = model
            .propose_delete(&note.id, services.target(), repository)
            .unwrap();
        let mut dialogs = DialogHost::default();
        let dialog_id = dialogs.show_dangerous(proposal.plan()).unwrap();
        model.arm_delete(proposal, dialog_id);

        let cancelled = dialogs
            .dispatch(DialogAction::Cancel { dialog_id })
            .unwrap();
        assert_eq!(
            model.resolve_delete(&cancelled, services.target()),
            DeleteResolution::Cancelled
        );
        assert_eq!(repository.list().unwrap().len(), 1);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn a_confirmation_for_another_plan_cannot_authorize_note_deletion() {
        let (root, services) = services();
        let repository = services.investigation().notes();
        let first = repository
            .create(CreateNote {
                title: Some("first".to_owned()),
                ..CreateNote::default()
            })
            .unwrap();
        let second = repository
            .create(CreateNote {
                title: Some("second".to_owned()),
                ..CreateNote::default()
            })
            .unwrap();
        let mut model = NotesModel::default();
        model.activate(services.target());
        let lease = model.begin_list_request(services.target()).unwrap();
        assert!(model.apply_list(&lease, services.target(), repository.list().unwrap()));
        let proposal = model
            .propose_delete(&first.id, services.target(), repository)
            .unwrap();
        let other = repository.plan_delete(&second.id).unwrap();
        let mut dialogs = DialogHost::default();
        let dialog_id = dialogs.show_dangerous(proposal.plan()).unwrap();
        model.arm_delete(proposal, dialog_id);

        let wrong = DialogOutcome::DangerousApproved {
            dialog_id,
            operation_id: other.definition().id.clone(),
        };
        assert_eq!(
            model.resolve_delete(&wrong, services.target()),
            DeleteResolution::Ignored
        );
        assert_eq!(repository.list().unwrap().len(), 2);
        assert!(services.operation_journal().entries().unwrap().is_empty());
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn exact_operation_id_authorizes_only_the_bound_note() {
        let (root, services) = services();
        let repository = services.investigation().notes();
        let note = repository
            .create(CreateNote {
                title: Some("confirmed delete".to_owned()),
                content: String::new(),
                tags: Vec::new(),
            })
            .unwrap();
        let mut model = NotesModel::default();
        model.activate(services.target());
        let lease = model.begin_list_request(services.target()).unwrap();
        assert!(model.apply_list(&lease, services.target(), repository.list().unwrap()));
        let proposal = model
            .propose_delete(&note.id, services.target(), repository)
            .unwrap();
        let operation_id = proposal.plan().id.clone();
        let mut dialogs = DialogHost::default();
        let dialog_id = dialogs.show_dangerous(proposal.plan()).unwrap();
        model.arm_delete(proposal, dialog_id);

        let approved = dialogs
            .dispatch(DialogAction::ConfirmDangerous {
                dialog_id,
                operation_id,
            })
            .unwrap();
        let DeleteResolution::Authorized {
            deletion,
            confirmation,
            presentation,
        } = model.resolve_delete(&approved, services.target())
        else {
            panic!("exact confirmation must authorize the bound note");
        };
        assert_eq!(deletion.note_id(), note.id);
        repository
            .execute_delete(*deletion, confirmation, services.operation_journal())
            .await
            .unwrap();
        assert!(repository.list().unwrap().is_empty());
        assert!(model.apply_delete_success(&presentation, services.target(), &note.id));
        assert!(model.notes().is_empty());
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn late_delete_result_is_journaled_but_not_applied_after_page_or_target_change() {
        let (root, services) = services();
        let original_target = TargetIdentity::new("connection-a").unwrap();
        services.activate_target(original_target.clone()).unwrap();
        let repository = services.investigation().notes();
        let note = repository
            .create(CreateNote {
                title: Some("late result".to_owned()),
                ..CreateNote::default()
            })
            .unwrap();
        let mut model = NotesModel::default();
        model.activate(services.target());
        let list = model.begin_list_request(services.target()).unwrap();
        assert!(model.apply_list(&list, services.target(), repository.list().unwrap()));
        let proposal = model
            .propose_delete(&note.id, services.target(), repository)
            .unwrap();
        let mut dialogs = DialogHost::default();
        let dialog_id = dialogs.show_dangerous(proposal.plan()).unwrap();
        let operation_id = proposal.plan().id.clone();
        model.arm_delete(proposal, dialog_id);
        let approved = dialogs
            .dispatch(DialogAction::ConfirmDangerous {
                dialog_id,
                operation_id,
            })
            .unwrap();
        let DeleteResolution::Authorized {
            deletion,
            confirmation,
            presentation,
        } = model.resolve_delete(&approved, services.target())
        else {
            panic!("exact confirmation must authorize deletion");
        };

        repository
            .execute_delete(*deletion, confirmation, services.operation_journal())
            .await
            .unwrap();
        services.activate_target(original_target).unwrap();
        model.deactivate();
        assert!(!model.apply_delete_success(&presentation, services.target(), &note.id));
        assert!(model.notes().iter().any(|item| item.id == note.id));
        assert!(repository.get(&note.id).unwrap().is_none());
        assert_eq!(services.operation_journal().entries().unwrap().len(), 2);
        let _ = fs::remove_dir_all(root);
    }
}
