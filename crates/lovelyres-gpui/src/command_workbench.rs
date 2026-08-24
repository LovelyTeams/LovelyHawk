use std::{collections::BTreeMap, sync::Arc};

use gpui::{
    AnyElement, ClipboardItem, Context, Entity, Render, ScrollHandle, SharedString, Subscription,
    Window, div, prelude::*, px,
};
use gpui_component::{
    Disableable, Selectable, Sizable, StyledExt,
    button::ButtonVariants,
    input::{Input, InputEvent, InputState},
    scroll::ScrollableElement,
};
use lovelyres_core::{
    BackendServices, CoreResult,
    command_workbench::{
        CommandCatalogEntry, CommandCategory, CommandExecutionReceipt, CommandResultKind,
        SystemFamily,
    },
    ssh::BoundSshSession,
    target::TargetGuard,
};
use tokio::task::AbortHandle;

use crate::{app::SharedAppState, runtime::TokioBridge, theme::ThemeTokens};

#[derive(Clone, Debug, Eq, PartialEq)]
struct WorkbenchBinding {
    connection_id: String,
    session_id: String,
    target: TargetGuard,
}

impl WorkbenchBinding {
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

    fn label(&self) -> String {
        format!(
            "{} · generation {}",
            self.target.identity.as_str(),
            self.target.generation
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum RequestLane {
    System,
    Execute,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RequestLease {
    activation_generation: u64,
    request_id: u64,
    lane: RequestLane,
    binding: WorkbenchBinding,
    command_id: Option<String>,
}

#[derive(Debug)]
struct WorkbenchModel {
    active: bool,
    activation_generation: u64,
    next_request_id: u64,
    latest: BTreeMap<RequestLane, u64>,
    binding: Option<WorkbenchBinding>,
    family: Option<SystemFamily>,
    catalog: Vec<CommandCatalogEntry>,
    category: Option<CommandCategory>,
    query: String,
    selected_command_id: Option<String>,
    receipt: Option<CommandExecutionReceipt>,
    busy: bool,
}

impl WorkbenchModel {
    fn new(catalog: Vec<CommandCatalogEntry>) -> Self {
        let selected_command_id = catalog.first().map(|entry| entry.id.to_owned());
        Self {
            active: false,
            activation_generation: 0,
            next_request_id: 0,
            latest: BTreeMap::new(),
            binding: None,
            family: None,
            catalog,
            category: None,
            query: String::new(),
            selected_command_id,
            receipt: None,
            busy: false,
        }
    }

    fn activate(&mut self, binding: Option<WorkbenchBinding>) {
        self.active = true;
        self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
        self.rebind(binding);
    }

    fn deactivate(&mut self) {
        self.active = false;
        self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
        self.latest.clear();
        self.busy = false;
    }

    fn rebind(&mut self, binding: Option<WorkbenchBinding>) {
        if self.binding == binding {
            return;
        }
        self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
        self.binding = binding;
        self.family = None;
        self.receipt = None;
        self.latest.clear();
        self.busy = false;
    }

    fn begin(&mut self, lane: RequestLane, command_id: Option<String>) -> CoreResult<RequestLease> {
        let binding =
            self.binding
                .clone()
                .ok_or_else(|| lovelyres_core::CoreError::Validation {
                    subject: "command workbench target",
                    message: "an active SSH target is required".to_owned(),
                })?;
        if !self.active {
            return Err(lovelyres_core::CoreError::Validation {
                subject: "command workbench lifecycle",
                message: "page is not active".to_owned(),
            });
        }
        self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
        self.latest.insert(lane, self.next_request_id);
        Ok(RequestLease {
            activation_generation: self.activation_generation,
            request_id: self.next_request_id,
            lane,
            binding,
            command_id,
        })
    }

    fn accepts(&self, lease: &RequestLease, binding: Option<&WorkbenchBinding>) -> bool {
        self.active
            && self.activation_generation == lease.activation_generation
            && self.latest.get(&lease.lane) == Some(&lease.request_id)
            && self.binding.as_ref() == Some(&lease.binding)
            && binding == Some(&lease.binding)
            && lease
                .command_id
                .as_deref()
                .is_none_or(|command_id| self.selected_command_id.as_deref() == Some(command_id))
    }

    fn set_query(&mut self, query: String) {
        self.query = query;
        self.ensure_visible_selection();
    }

    fn set_category(&mut self, category: Option<CommandCategory>) {
        self.category = category;
        self.ensure_visible_selection();
    }

    fn matches(&self, entry: &CommandCatalogEntry) -> bool {
        if self
            .category
            .is_some_and(|category| category != entry.category)
        {
            return false;
        }
        let query = self.query.trim().to_lowercase();
        query.is_empty()
            || entry.id.contains(&query)
            || entry.title.to_lowercase().contains(&query)
            || entry.description.to_lowercase().contains(&query)
            || entry.command_preview.to_lowercase().contains(&query)
    }

    fn filtered(&self) -> Vec<CommandCatalogEntry> {
        self.catalog
            .iter()
            .copied()
            .filter(|entry| self.matches(entry))
            .collect()
    }

    fn ensure_visible_selection(&mut self) {
        if self
            .selected_command()
            .is_some_and(|entry| self.matches(&entry))
        {
            return;
        }
        self.selected_command_id = self
            .catalog
            .iter()
            .find(|entry| self.matches(entry))
            .map(|entry| entry.id.to_owned());
        self.receipt = None;
    }

    fn selected_command(&self) -> Option<CommandCatalogEntry> {
        let selected = self.selected_command_id.as_deref()?;
        self.catalog
            .iter()
            .copied()
            .find(|entry| entry.id == selected)
    }
}

type SystemTaskResult = Result<CoreResult<SystemFamily>, tokio::task::JoinError>;
type ExecuteTaskResult = Result<CoreResult<CommandExecutionReceipt>, tokio::task::JoinError>;

pub struct CommandWorkbenchPage {
    services: Arc<BackendServices>,
    tokio: Arc<TokioBridge>,
    shared: Entity<SharedAppState>,
    model: WorkbenchModel,
    search: Entity<InputState>,
    page_scroll: ScrollHandle,
    command_scroll: ScrollHandle,
    output_scroll: ScrollHandle,
    task_abort: Option<AbortHandle>,
    error: Option<SharedString>,
    notice: Option<SharedString>,
    _subscriptions: Vec<Subscription>,
}

impl CommandWorkbenchPage {
    pub fn new(
        services: Arc<BackendServices>,
        tokio: Arc<TokioBridge>,
        shared: Entity<SharedAppState>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let search =
            cx.new(|cx| InputState::new(window, cx).placeholder("搜索命令、用途或静态命令预览…"));
        let subscriptions = vec![
            cx.subscribe_in(&search, window, |page, input, event: &InputEvent, _, cx| {
                if matches!(event, InputEvent::Change) {
                    page.model.set_query(input.read(cx).value().to_string());
                    cx.notify();
                }
            }),
            cx.observe(&shared, |page, _, cx| page.handle_shared_change(cx)),
        ];
        let catalog = services.commands().catalog();
        Self {
            services,
            tokio,
            shared,
            model: WorkbenchModel::new(catalog),
            search,
            page_scroll: ScrollHandle::new(),
            command_scroll: ScrollHandle::new(),
            output_scroll: ScrollHandle::new(),
            task_abort: None,
            error: None,
            notice: None,
            _subscriptions: subscriptions,
        }
    }

    pub fn activate(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.model.activate(self.current_binding(cx));
        self.search.update(cx, |input, cx| input.focus(window, cx));
        if self.model.binding.is_some() {
            self.detect_system(cx);
        } else {
            self.error = Some("未连接目标，无法运行只读排障命令。".into());
        }
        cx.notify();
    }

    pub fn deactivate(&mut self, cx: &mut Context<Self>) {
        self.abort_task();
        self.model.deactivate();
        cx.notify();
    }

    pub const fn is_active(&self) -> bool {
        self.model.active
    }

    pub fn select_catalog_command(
        &mut self,
        command_id: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        if !self
            .model
            .catalog
            .iter()
            .any(|entry| entry.id == command_id)
        {
            return false;
        }
        self.model.set_category(None);
        self.model.set_query(String::new());
        self.search
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.select_command(command_id.to_owned(), cx);
        true
    }

    fn current_binding(&self, cx: &Context<Self>) -> Option<WorkbenchBinding> {
        WorkbenchBinding::capture(self.shared.read(cx))
    }

    fn current_session(&self, cx: &Context<Self>) -> Option<BoundSshSession> {
        self.shared
            .read(cx)
            .active_ssh
            .as_ref()
            .map(|active| active.session.clone())
    }

    fn handle_shared_change(&mut self, cx: &mut Context<Self>) {
        if !self.model.active {
            return;
        }
        let binding = self.current_binding(cx);
        if self.model.binding == binding {
            return;
        }
        self.abort_task();
        self.model.rebind(binding);
        if self.model.binding.is_some() {
            self.notice = Some("活动目标已变化；旧请求和结果已失效，正在重新识别系统。".into());
            self.error = None;
            self.detect_system(cx);
        } else {
            self.error = Some("活动 SSH 目标已断开。".into());
            self.notice = None;
        }
        cx.notify();
    }

    fn detect_system(&mut self, cx: &mut Context<Self>) {
        let Some(session) = self.current_session(cx) else {
            self.error = Some("未连接目标，无法识别系统。".into());
            return;
        };
        let lease = match self.model.begin(RequestLane::System, None) {
            Ok(lease) => lease,
            Err(error) => {
                self.error = Some(error.to_string().into());
                return;
            }
        };
        self.abort_task();
        self.model.busy = true;
        self.notice = Some("正在识别远端 Linux 系统族…".into());
        self.error = None;
        let service = self.services.commands().clone();
        let task = self
            .tokio
            .spawn(async move { service.detect_system(&session).await });
        self.task_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_detect(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_detect(
        &mut self,
        lease: RequestLease,
        result: SystemTaskResult,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            return;
        }
        self.model.busy = false;
        self.task_abort = None;
        match result {
            Ok(Ok(family)) => {
                self.model.family = Some(family);
                self.notice = Some(format!("已识别为 {}。", family.label()).into());
                self.error = None;
            }
            Ok(Err(error)) => {
                self.model.family = Some(SystemFamily::Other);
                self.notice = Some("系统识别失败，已使用通用 Linux 静态命令回退。".into());
                self.error = Some(error.to_string().into());
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.model.family = Some(SystemFamily::Other);
                self.error = Some(format!("系统识别任务异常终止：{error}").into());
            }
        }
        cx.notify();
    }

    fn select_category(&mut self, category: Option<CommandCategory>, cx: &mut Context<Self>) {
        self.model.set_category(category);
        cx.notify();
    }

    fn select_command(&mut self, command_id: String, cx: &mut Context<Self>) {
        self.model.selected_command_id = Some(command_id);
        self.model.receipt = None;
        self.error = None;
        cx.notify();
    }

    fn execute_selected(&mut self, cx: &mut Context<Self>) {
        let Some(entry) = self.model.selected_command() else {
            self.error = Some("请先选择一项只读命令。".into());
            cx.notify();
            return;
        };
        let Some(session) = self.current_session(cx) else {
            self.error = Some("活动 SSH 目标已断开。".into());
            cx.notify();
            return;
        };
        let family = self.model.family.unwrap_or(SystemFamily::Other);
        let lease = match self
            .model
            .begin(RequestLane::Execute, Some(entry.id.to_owned()))
        {
            Ok(lease) => lease,
            Err(error) => {
                self.error = Some(error.to_string().into());
                cx.notify();
                return;
            }
        };
        self.abort_task();
        self.model.busy = true;
        self.model.receipt = None;
        self.notice = Some(format!("正在执行只读命令：{}", entry.title).into());
        self.error = None;
        let command_id = entry.id.to_owned();
        let service = self.services.commands().clone();
        let task = self
            .tokio
            .spawn(async move { service.execute(&session, &command_id, family).await });
        self.task_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_execute(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_execute(
        &mut self,
        lease: RequestLease,
        result: ExecuteTaskResult,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            return;
        }
        self.model.busy = false;
        self.task_abort = None;
        match result {
            Ok(Ok(receipt)) => {
                let warning = receipt.history_warning.clone();
                self.notice = Some(
                    format!(
                        "{} · {} ms{}",
                        receipt.message,
                        receipt.duration_ms,
                        if receipt.truncated {
                            " · 输出已截断"
                        } else {
                            ""
                        }
                    )
                    .into(),
                );
                self.error = warning.map(Into::into);
                self.model.receipt = Some(receipt);
            }
            Ok(Err(error)) => self.error = Some(format!("命令执行失败：{error}").into()),
            Err(error) if error.is_cancelled() => {
                self.notice = Some("命令任务已取消；晚到结果不会应用到页面。".into());
            }
            Err(error) => self.error = Some(format!("命令任务异常终止：{error}").into()),
        }
        cx.notify();
    }

    fn cancel(&mut self, cx: &mut Context<Self>) {
        if !self.model.busy {
            return;
        }
        self.abort_task();
        self.model.next_request_id = self.model.next_request_id.wrapping_add(1).max(1);
        self.model
            .latest
            .insert(RequestLane::Execute, self.model.next_request_id);
        self.model.busy = false;
        self.notice = Some("已取消等待；SSH actor 会丢弃已取消调用的响应。".into());
        cx.notify();
    }

    fn abort_task(&mut self) {
        if let Some(abort) = self.task_abort.take() {
            abort.abort();
        }
    }

    fn copy_preview(&self, cx: &mut Context<Self>) {
        if let Some(entry) = self.model.selected_command() {
            cx.write_to_clipboard(ClipboardItem::new_string(entry.command_preview.to_owned()));
        }
    }

    fn copy_output(&self, cx: &mut Context<Self>) {
        if let Some(receipt) = &self.model.receipt {
            cx.write_to_clipboard(ClipboardItem::new_string(receipt.output.clone()));
        }
    }

    fn render_category_filters(&self, _tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        div()
            .flex()
            .flex_wrap()
            .gap_2()
            .child(
                crate::buttons::button("command-category-all")
                    .label("全部")
                    .small()
                    .ghost()
                    .selected(self.model.category.is_none())
                    .on_click(cx.listener(|page, _, _, cx| page.select_category(None, cx))),
            )
            .children(CommandCategory::ALL.into_iter().map(|category| {
                crate::buttons::button(SharedString::from(format!(
                    "command-category-{}",
                    category.label()
                )))
                .label(category.label())
                .small()
                .ghost()
                .selected(self.model.category == Some(category))
                .on_click(
                    cx.listener(move |page, _, _, cx| page.select_category(Some(category), cx)),
                )
            }))
            .into_any_element()
    }

    fn render_command_list(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let commands = self.model.filtered();
        div()
            .relative()
            .min_h_0()
            .flex_1()
            .child(
                div()
                    .id("command-list-scroll")
                    .size_full()
                    .overflow_y_scroll()
                    .track_scroll(&self.command_scroll)
                    .flex()
                    .flex_col()
                    .gap_1()
                    .when(commands.is_empty(), |view| {
                        view.child(
                            div()
                                .p_3()
                                .text_sm()
                                .text_color(tokens.muted)
                                .child("没有匹配的内置命令。"),
                        )
                    })
                    .children(commands.into_iter().map(|entry| {
                        let selected = self.model.selected_command_id.as_deref() == Some(entry.id);
                        let command_id = entry.id.to_owned();
                        div()
                            .id(SharedString::from(format!("command-row-{}", entry.id)))
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
                            .p_3()
                            .cursor_pointer()
                            .hover(|style| style.bg(tokens.surface_alt))
                            .on_click(cx.listener(move |page, _, _, cx| {
                                page.select_command(command_id.clone(), cx)
                            }))
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .gap_2()
                                    .child(div().font_semibold().child(entry.title))
                                    .child(
                                        div()
                                            .text_xs()
                                            .text_color(tokens.muted)
                                            .child(entry.category.label()),
                                    ),
                            )
                            .child(
                                div()
                                    .mt_1()
                                    .text_xs()
                                    .text_color(tokens.muted)
                                    .child(entry.description),
                            )
                    })),
            )
            .vertical_scrollbar(&self.command_scroll)
            .into_any_element()
    }

    fn render_detail(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let Some(entry) = self.model.selected_command() else {
            return div()
                .size_full()
                .flex()
                .items_center()
                .justify_center()
                .text_color(tokens.muted)
                .child("从左侧选择一项只读命令。")
                .into_any_element();
        };
        let execute_disabled = self.model.busy || self.model.binding.is_none();
        div()
            .size_full()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .rounded_lg()
                    .border_1()
                    .border_color(tokens.border)
                    .bg(tokens.surface)
                    .p_4()
                    .child(
                        div()
                            .flex()
                            .items_start()
                            .justify_between()
                            .gap_4()
                            .child(
                                div()
                                    .min_w_0()
                                    .child(div().text_lg().font_semibold().child(entry.title))
                                    .child(
                                        div()
                                            .mt_1()
                                            .text_sm()
                                            .text_color(tokens.muted)
                                            .child(entry.description),
                                    ),
                            )
                            .child(
                                div()
                                    .flex()
                                    .gap_2()
                                    .child(
                                        crate::buttons::button("command-copy-preview")
                                            .label("复制命令")
                                            .ghost()
                                            .on_click(
                                                cx.listener(|page, _, _, cx| page.copy_preview(cx)),
                                            ),
                                    )
                                    .child(
                                        crate::buttons::button("command-run")
                                            .label(if self.model.busy {
                                                "执行中…"
                                            } else {
                                                "运行只读命令"
                                            })
                                            .primary()
                                            .disabled(execute_disabled)
                                            .on_click(cx.listener(|page, _, _, cx| {
                                                page.execute_selected(cx)
                                            })),
                                    )
                                    .when(self.model.busy, |view| {
                                        view.child(
                                            crate::buttons::button("command-cancel")
                                                .label("取消")
                                                .danger()
                                                .on_click(
                                                    cx.listener(|page, _, _, cx| page.cancel(cx)),
                                                ),
                                        )
                                    }),
                            ),
                    )
                    .child(
                        div()
                            .mt_3()
                            .rounded_md()
                            .bg(tokens.surface_alt)
                            .p_3()
                            .font_family("Cascadia Mono")
                            .text_sm()
                            .child(entry.command_preview),
                    ),
            )
            .child(self.render_output(tokens, cx))
            .into_any_element()
    }

    fn render_output(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let Some(receipt) = &self.model.receipt else {
            return div()
                .min_h_0()
                .flex_1()
                .rounded_lg()
                .border_1()
                .border_color(tokens.border)
                .bg(tokens.surface)
                .flex()
                .items_center()
                .justify_center()
                .text_color(tokens.muted)
                .child("执行结果将在这里以纯文本显示。")
                .into_any_element();
        };
        let status_color = if receipt.success {
            tokens.success
        } else {
            tokens.danger
        };
        div()
            .min_h_0()
            .flex_1()
            .rounded_lg()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .flex()
            .flex_col()
            .child(
                div()
                    .h(px(44.0))
                    .flex_none()
                    .flex()
                    .items_center()
                    .justify_between()
                    .px_3()
                    .border_b_1()
                    .border_color(tokens.border)
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_3()
                            .child(
                                div()
                                    .font_semibold()
                                    .text_color(status_color)
                                    .child(result_kind_label(receipt.kind)),
                            )
                            .child(div().text_xs().text_color(tokens.muted).child(format!(
                                    "exit={} · {} ms{}",
                                    receipt
                                        .exit_code
                                        .map_or_else(|| "?".to_owned(), |code| code.to_string()),
                                    receipt.duration_ms,
                                    if receipt.truncated {
                                        " · 已截断"
                                    } else {
                                        ""
                                    }
                                ))),
                    )
                    .child(
                        crate::buttons::button("command-copy-output")
                            .label("复制结果")
                            .small()
                            .ghost()
                            .on_click(cx.listener(|page, _, _, cx| page.copy_output(cx))),
                    ),
            )
            .child(
                div()
                    .relative()
                    .min_h_0()
                    .flex_1()
                    .child(
                        div()
                            .id("command-output-scroll")
                            .size_full()
                            .overflow_y_scroll()
                            .track_scroll(&self.output_scroll)
                            .p_4()
                            .bg(tokens.surface_alt)
                            .font_family("Cascadia Mono")
                            .text_sm()
                            .child(if receipt.output.is_empty() {
                                "(无输出)".to_owned()
                            } else {
                                receipt.output.clone()
                            }),
                    )
                    .vertical_scrollbar(&self.output_scroll),
            )
            .into_any_element()
    }
}

impl Render for CommandWorkbenchPage {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens = self.shared.read(cx).theme.tokens();
        let target = self
            .model
            .binding
            .as_ref()
            .map(WorkbenchBinding::label)
            .unwrap_or_else(|| "未连接目标".to_owned());
        let family = self
            .model
            .family
            .map(SystemFamily::label)
            .unwrap_or("识别中");
        let filtered_count = self.model.filtered().len();
        div()
            .relative()
            .size_full()
            .min_h_0()
            .bg(tokens.background)
            .text_color(tokens.text)
            .child(
                div()
                    .id("command-workbench-page-scroll")
                    .size_full()
                    .overflow_y_scroll()
                    .track_scroll(&self.page_scroll)
                    .flex()
                    .flex_col()
                    .gap_3()
                    .p_4()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .gap_3()
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child(div().text_color(tokens.success).child("●"))
                                    .child(div().text_sm().child(target))
                                    .child(
                                        div()
                                            .text_xs()
                                            .text_color(tokens.muted)
                                            .child(format!(
                                                "{family} · {filtered_count}/{} 项",
                                                self.model.catalog.len()
                                            )),
                                    ),
                            )
                            .child(
                                crate::buttons::button("command-detect-system")
                                    .label("重新识别系统")
                                    .small()
                                    .ghost()
                                    .disabled(self.model.busy || self.model.binding.is_none())
                                    .on_click(
                                        cx.listener(|page, _, _, cx| page.detect_system(cx)),
                                    ),
                            ),
                    )
                    .child(
                        div()
                            .rounded_md()
                            .border_1()
                            .border_color(tokens.border)
                            .bg(tokens.surface_alt)
                            .px_3()
                            .py_2()
                            .text_xs()
                            .child("安全边界：这里只能按固定 ID 执行内置只读命令；自定义 Shell 与可写命令没有执行入口。"),
                    )
                    .when_some(self.error.clone(), |view, error| {
                        view.child(
                            div()
                                .rounded_md()
                                .bg(tokens.surface_alt)
                                .px_3()
                                .py_2()
                                .text_sm()
                                .text_color(tokens.danger)
                                .child(error),
                        )
                    })
                    .when_some(self.notice.clone(), |view, notice| {
                        view.child(div().text_xs().text_color(tokens.muted).child(notice))
                    })
                    .child(
                        div()
                            .min_h(px(360.0))
                            .flex_1()
                            .flex()
                            .gap_3()
                            .child(
                                div()
                                    .w(px(380.0))
                                    .min_w(px(320.0))
                                    .min_h_0()
                                    .rounded_lg()
                                    .border_1()
                                    .border_color(tokens.border)
                                    .bg(tokens.surface)
                                    .p_3()
                                    .flex()
                                    .flex_col()
                                    .gap_3()
                                    .child(Input::new(&self.search))
                                    .child(self.render_category_filters(tokens, cx))
                                    .child(self.render_command_list(tokens, cx)),
                            )
                            .child(
                                div()
                                    .min_w_0()
                                    .min_h_0()
                                    .flex_1()
                                    .child(self.render_detail(tokens, cx)),
                            ),
                    ),
            )
            .vertical_scrollbar(&self.page_scroll)
    }
}

fn result_kind_label(kind: CommandResultKind) -> &'static str {
    match kind {
        CommandResultKind::Success => "执行成功",
        CommandResultKind::Empty => "成功 · 无输出",
        CommandResultKind::NonZero => "非零退出",
        CommandResultKind::Timeout => "执行超时",
        CommandResultKind::MissingCommand => "命令缺失",
        CommandResultKind::PermissionDenied => "权限不足",
        CommandResultKind::UnknownExit => "退出状态未知",
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, sync::Arc};

    use gpui::{AppContext as _, ScrollDelta, ScrollWheelEvent, TestAppContext, point, size};
    use lovelyres_core::{BackendServices, PortableStore};
    use uuid::Uuid;

    use super::*;
    use lovelyres_core::target::{TargetContext, TargetIdentity};

    fn app_shell_scroll_mount(page: Entity<CommandWorkbenchPage>) -> AnyElement {
        div()
            .size_full()
            .min_h_0()
            .flex()
            .flex_col()
            .child(crate::app::scroll_managed_workspace(
                crate::app::constrained_workspace_page(page),
            ))
            .into_any_element()
    }

    fn binding(identity: &str, generation_seed: usize) -> WorkbenchBinding {
        let target = TargetContext::new();
        let mut guard = target
            .activate(TargetIdentity::new(identity).unwrap())
            .unwrap();
        for _ in 0..generation_seed {
            guard = target
                .activate(TargetIdentity::new(identity).unwrap())
                .unwrap();
        }
        WorkbenchBinding {
            connection_id: identity.to_owned(),
            session_id: format!("session-{identity}"),
            target: guard,
        }
    }

    fn catalog() -> Vec<CommandCatalogEntry> {
        vec![
            CommandCatalogEntry {
                id: "network-listen",
                category: CommandCategory::Network,
                title: "监听端口",
                description: "网络端口",
                command_preview: "ss -tulpen",
                timeout_seconds: 30,
            },
            CommandCatalogEntry {
                id: "system-kernel",
                category: CommandCategory::System,
                title: "系统与内核",
                description: "系统版本",
                command_preview: "uname -a",
                timeout_seconds: 30,
            },
        ]
    }

    #[test]
    fn target_and_lifecycle_reject_late_results() {
        let mut model = WorkbenchModel::new(catalog());
        let first = binding("connection-a", 0);
        model.activate(Some(first.clone()));
        let lease = model
            .begin(RequestLane::Execute, Some("network-listen".to_owned()))
            .unwrap();
        assert!(model.accepts(&lease, Some(&first)));
        model.rebind(Some(binding("connection-b", 0)));
        assert!(!model.accepts(&lease, Some(&first)));
        model.deactivate();
        assert!(!model.accepts(&lease, None));
    }

    #[test]
    fn system_detection_is_scoped_to_the_exact_trusted_target_epoch() {
        let mut model = WorkbenchModel::new(catalog());
        let first = binding("connection-a", 0);
        model.activate(Some(first.clone()));
        model.family = Some(SystemFamily::Alpine);

        model.rebind(Some(binding("connection-b", 0)));
        assert_eq!(model.family, None, "another host cannot reuse Alpine");

        model.family = Some(SystemFamily::RedHat);
        model.rebind(Some(binding("connection-a", 1)));
        assert_eq!(
            model.family, None,
            "a reconnect gets a fresh target generation and a fresh probe"
        );

        let current = binding("connection-a", 2);
        model.rebind(Some(current.clone()));
        let lease = model.begin(RequestLane::System, None).unwrap();
        model.rebind(Some(binding("connection-b", 1)));
        assert!(
            !model.accepts(&lease, Some(&current)),
            "an in-flight result from the previous target must be rejected"
        );
    }

    #[test]
    fn filtering_keeps_stable_command_identity() {
        let mut model = WorkbenchModel::new(catalog());
        model.set_category(Some(CommandCategory::System));
        assert_eq!(model.filtered()[0].id, "system-kernel");
        assert_eq!(model.selected_command_id.as_deref(), Some("system-kernel"));
        model.set_query("端口".to_owned());
        assert!(model.filtered().is_empty());
        assert!(model.selected_command_id.is_none());
        model.set_category(None);
        assert_eq!(model.selected_command_id.as_deref(), Some("network-listen"));
    }

    #[gpui::test]
    fn short_viewport_can_reach_page_commands_and_long_output(cx: &mut TestAppContext) {
        let root =
            std::env::temp_dir().join(format!("lovelyres-command-scroll-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let services =
            Arc::new(BackendServices::new(PortableStore::prepare(root.clone()).unwrap()).unwrap());
        let tokio = TokioBridge::new().unwrap();

        cx.update(gpui_component::init);
        let cx = cx.add_empty_window();
        let page = cx.update(|window, cx| {
            let shared = cx.new(|_| SharedAppState::default());
            cx.new(|cx| CommandWorkbenchPage::new(services, tokio, shared, window, cx))
        });
        let viewport = size(px(1_000.0), px(420.0));
        cx.draw(point(px(0.0), px(0.0)), viewport, |_, _| {
            app_shell_scroll_mount(page.clone())
        });

        let page_scroll = page.update(cx, |page, _| page.page_scroll.clone());
        assert!(
            page_scroll.max_offset().height > px(0.0),
            "the complete workbench page must overflow a short viewport"
        );
        cx.simulate_event(ScrollWheelEvent {
            position: point(px(900.0), px(24.0)),
            delta: ScrollDelta::Pixels(point(px(0.0), px(-5_000.0))),
            ..Default::default()
        });
        cx.draw(point(px(0.0), px(0.0)), viewport, |_, _| {
            app_shell_scroll_mount(page.clone())
        });
        assert_eq!(page_scroll.offset().y, -page_scroll.max_offset().height);

        page_scroll.set_offset(point(px(0.0), px(0.0)));
        cx.draw(point(px(0.0), px(0.0)), viewport, |_, _| {
            app_shell_scroll_mount(page.clone())
        });
        let scroll = page.update(cx, |page, _| page.command_scroll.clone());
        assert!(
            scroll.max_offset().height > px(0.0),
            "the full command catalog must overflow a short workbench viewport"
        );
        cx.simulate_event(ScrollWheelEvent {
            position: scroll.bounds().center(),
            delta: ScrollDelta::Pixels(point(px(0.0), px(-5_000.0))),
            ..Default::default()
        });
        cx.draw(point(px(0.0), px(0.0)), viewport, |_, _| {
            app_shell_scroll_mount(page.clone())
        });
        assert_eq!(scroll.offset().y, -scroll.max_offset().height);
        let last_command = page.update(cx, |page, _| page.model.filtered().len() - 1);
        assert_eq!(
            scroll.bottom_item(),
            last_command,
            "the last built-in command must be reachable by wheel scrolling"
        );

        page.update(cx, |page, cx| {
            page.model.receipt = Some(CommandExecutionReceipt {
                command_id: "network-listen".to_owned(),
                title: "监听端口".to_owned(),
                output: (0..200)
                    .map(|index| format!("evidence line {index}"))
                    .collect::<Vec<_>>()
                    .join("\n"),
                exit_code: Some(0),
                duration_ms: 5,
                timed_out: false,
                kind: CommandResultKind::Success,
                success: true,
                message: "执行完成".to_owned(),
                truncated: false,
                history_id: None,
                history_warning: None,
            });
            cx.notify();
        });
        cx.draw(point(px(0.0), px(0.0)), viewport, |_, _| {
            app_shell_scroll_mount(page.clone())
        });

        let output_scroll = page.update(cx, |page, _| page.output_scroll.clone());
        assert!(output_scroll.max_offset().height > px(0.0));
        cx.simulate_event(ScrollWheelEvent {
            position: output_scroll.bounds().center(),
            delta: ScrollDelta::Pixels(point(px(0.0), px(-20_000.0))),
            ..Default::default()
        });
        cx.draw(point(px(0.0), px(0.0)), viewport, |_, _| {
            app_shell_scroll_mount(page.clone())
        });
        assert_eq!(output_scroll.offset().y, -output_scroll.max_offset().height);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn page_source_has_no_raw_command_execution_surface() {
        let source = include_str!("command_workbench.rs");
        let forbidden = concat!("execute_", "raw");
        let arbitrary = concat!("custom_", "command");
        assert!(!source.contains(forbidden));
        assert!(!source.contains(arbitrary));
        assert!(source.contains("service.execute(&session, &command_id, family)"));
    }
}
