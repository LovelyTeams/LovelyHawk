use std::collections::BTreeSet;
use std::sync::Arc;

use gpui::{
    AnyElement, ClipboardItem, Context, Entity, Render, SharedString, Subscription, Window, div,
    prelude::*, px, relative,
};
use gpui_component::{
    Disableable, Selectable, Sizable, StyledExt,
    button::ButtonVariants,
    input::{Input, InputState},
    scroll::ScrollableElement,
};
use lovelyres_core::{
    BackendServices, CoreError, CoreResult,
    batch::{
        BatchCancellation, BatchEvent, BatchExecutionOutcome, BatchExecutionPlan, BatchRequest,
        BatchStrategy, BatchTargetReceipt, BatchTargetStatus, BatchTaskRecord, batch_event_channel,
    },
    connections::ConnectionView,
    operations::DangerousConfirmation,
};

use crate::{app::SharedAppState, runtime::TokioBridge, theme::ThemeTokens};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BatchView {
    Execute,
    History,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BatchLease {
    activation_generation: u64,
    request_id: u64,
}

#[derive(Debug)]
struct BatchModel {
    active: bool,
    activation_generation: u64,
    next_request_id: u64,
    view: BatchView,
    targets: Vec<ConnectionView>,
    selected: BTreeSet<String>,
    history: Vec<BatchTaskRecord>,
    current: Option<BatchTaskRecord>,
    selected_result: Option<String>,
    strategy: BatchStrategy,
    progress_completed: usize,
    progress_total: usize,
    progress_label: String,
}

impl Default for BatchModel {
    fn default() -> Self {
        Self {
            active: false,
            activation_generation: 0,
            next_request_id: 0,
            view: BatchView::Execute,
            targets: Vec::new(),
            selected: BTreeSet::new(),
            history: Vec::new(),
            current: None,
            selected_result: None,
            strategy: BatchStrategy::Rolling {
                stop_on_failure: false,
            },
            progress_completed: 0,
            progress_total: 0,
            progress_label: String::new(),
        }
    }
}

impl BatchModel {
    fn activate(&mut self) {
        self.active = true;
        self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
    }

    fn deactivate(&mut self) {
        self.active = false;
        self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
    }

    fn begin(&mut self) -> CoreResult<BatchLease> {
        if !self.active {
            return Err(CoreError::Validation {
                subject: "batch page lifecycle",
                message: "page is not active".to_owned(),
            });
        }
        self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
        Ok(BatchLease {
            activation_generation: self.activation_generation,
            request_id: self.next_request_id,
        })
    }

    fn accepts(&self, lease: &BatchLease) -> bool {
        self.active
            && self.activation_generation == lease.activation_generation
            && self.next_request_id == lease.request_id
    }

    fn set_targets(&mut self, targets: Vec<ConnectionView>) {
        let available = targets
            .iter()
            .map(|target| target.config.id.as_str())
            .collect::<BTreeSet<_>>();
        self.selected
            .retain(|connection_id| available.contains(connection_id.as_str()));
        self.targets = targets;
    }
}

pub struct BatchServersPage {
    services: Arc<BackendServices>,
    tokio: Arc<TokioBridge>,
    shared: Entity<SharedAppState>,
    model: BatchModel,
    name_input: Entity<InputState>,
    command_input: Entity<InputState>,
    verify_input: Entity<InputState>,
    canary_input: Entity<InputState>,
    pending: Option<BatchExecutionPlan>,
    running: bool,
    cancellation: Option<BatchCancellation>,
    error: Option<SharedString>,
    notice: Option<SharedString>,
    _subscriptions: Vec<Subscription>,
}

impl BatchServersPage {
    pub fn new(
        services: Arc<BackendServices>,
        tokio: Arc<TokioBridge>,
        shared: Entity<SharedAppState>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let name_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("任务名称，例如 SSH 加固复核"));
        let command_input = cx.new(|cx| {
            InputState::new(window, cx)
                .multi_line(true)
                .placeholder("要在每台目标上执行的命令")
        });
        let verify_input = cx.new(|cx| {
            InputState::new(window, cx)
                .multi_line(true)
                .placeholder("独立验证命令（强烈建议填写）")
        });
        let canary_input = cx.new(|cx| InputState::new(window, cx).placeholder("1"));
        Self {
            services,
            tokio,
            shared,
            model: BatchModel::default(),
            name_input,
            command_input,
            verify_input,
            canary_input,
            pending: None,
            running: false,
            cancellation: None,
            error: None,
            notice: None,
            _subscriptions: Vec::new(),
        }
    }

    pub fn activate(&mut self, _window: &mut Window, cx: &mut Context<Self>) {
        self.model.activate();
        self.reload_local();
        cx.notify();
    }

    pub fn deactivate(&mut self, cx: &mut Context<Self>) {
        self.pending = None;
        self.model.deactivate();
        cx.notify();
    }

    pub const fn is_active(&self) -> bool {
        self.model.active
    }

    fn reload_local(&mut self) {
        match self.services.batch().available_targets() {
            Ok(targets) => self.model.set_targets(targets),
            Err(error) => self.error = Some(format!("无法读取连接列表：{error}").into()),
        }
        match self.services.batch().list_history() {
            Ok(mut history) => {
                history.reverse();
                self.model.history = history;
            }
            Err(error) => self.error = Some(format!("无法读取批量历史：{error}").into()),
        }
    }

    fn toggle_target(&mut self, connection_id: String, cx: &mut Context<Self>) {
        if self.running || self.pending.is_some() {
            return;
        }
        if !self.model.selected.remove(&connection_id) {
            self.model.selected.insert(connection_id);
        }
        cx.notify();
    }

    fn select_all(&mut self, cx: &mut Context<Self>) {
        if self.running || self.pending.is_some() {
            return;
        }
        self.model.selected = self
            .model
            .targets
            .iter()
            .map(|target| target.config.id.clone())
            .collect();
        cx.notify();
    }

    fn clear_selection(&mut self, cx: &mut Context<Self>) {
        if self.running || self.pending.is_some() {
            return;
        }
        self.model.selected.clear();
        cx.notify();
    }

    fn set_strategy(&mut self, strategy: BatchStrategy, cx: &mut Context<Self>) {
        if self.running || self.pending.is_some() {
            return;
        }
        self.model.strategy = strategy;
        cx.notify();
    }

    fn toggle_stop_on_failure(&mut self, cx: &mut Context<Self>) {
        if let BatchStrategy::Rolling { stop_on_failure } = self.model.strategy {
            self.model.strategy = BatchStrategy::Rolling {
                stop_on_failure: !stop_on_failure,
            };
            cx.notify();
        }
    }

    fn prepare_plan(&mut self, cx: &mut Context<Self>) {
        if self.running || self.pending.is_some() {
            return;
        }
        let command = self.command_input.read(cx).value().trim().to_owned();
        let name = self.name_input.read(cx).value().trim().to_owned();
        let verify = self.verify_input.read(cx).value().trim().to_owned();
        let strategy = match self.model.strategy {
            BatchStrategy::Canary { .. } => {
                let count = match self.canary_input.read(cx).value().trim().parse::<usize>() {
                    Ok(count) => count,
                    Err(_) => {
                        self.error = Some("Canary 台数必须是正整数".into());
                        cx.notify();
                        return;
                    }
                };
                BatchStrategy::Canary { count }
            }
            rolling => rolling,
        };
        let request = BatchRequest {
            name: if name.is_empty() {
                command.chars().take(40).collect()
            } else {
                name
            },
            command,
            verify_command: (!verify.is_empty()).then_some(verify),
            connection_ids: self.model.selected.iter().cloned().collect(),
            strategy,
            timeout_seconds: 120,
        };
        match self.services.batch().plan(request) {
            Ok(plan) => {
                self.pending = Some(plan);
                self.error = None;
                self.notice = None;
            }
            Err(error) => self.error = Some(format!("无法生成批量计划：{error}").into()),
        }
        cx.notify();
    }

    fn approve_pending(&mut self, cx: &mut Context<Self>) {
        if self.running {
            return;
        }
        let Some(plan) = self.pending.take() else {
            return;
        };
        let lease = match self.model.begin() {
            Ok(lease) => lease,
            Err(error) => {
                self.error = Some(error.to_string().into());
                return;
            }
        };
        let confirmation = DangerousConfirmation::approve(plan.definition());
        let cancellation = BatchCancellation::default();
        let (events, receiver) = match batch_event_channel(128) {
            Ok(channel) => channel,
            Err(error) => {
                self.error = Some(error.to_string().into());
                return;
            }
        };
        self.running = true;
        self.cancellation = Some(cancellation.clone());
        self.model.progress_completed = 0;
        self.model.progress_total = plan.targets().len();
        self.model.progress_label = "准备独立 SSH 会话…".to_owned();
        self.error = None;
        self.notice = Some("批量任务已确认；离开页面不会中断审计、验证与历史写入。".into());

        cx.spawn({
            let lease = lease.clone();
            async move |page, cx| {
                while let Ok(event) = receiver.recv().await {
                    let _ = cx.update(|cx| {
                        if let Some(page) = page.upgrade() {
                            page.update(cx, |page, cx| page.apply_event(&lease, event, cx));
                        }
                    });
                }
            }
        })
        .detach();

        let service = self.services.batch().clone();
        let task = self.tokio.spawn(async move {
            service
                .execute(plan, confirmation, cancellation, Some(events))
                .await
        });
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn apply_event(&mut self, lease: &BatchLease, event: BatchEvent, cx: &mut Context<Self>) {
        if !self.model.accepts(lease) {
            return;
        }
        match event {
            BatchEvent::Started { total, .. } => {
                self.model.progress_total = total;
                self.model.progress_label = format!("0/{total} · 开始");
            }
            BatchEvent::TargetStarted {
                index,
                total,
                server_name,
                ..
            } => {
                self.model.progress_completed = index;
                self.model.progress_total = total;
                self.model.progress_label = format!("{index}/{total} · {server_name}");
            }
            BatchEvent::TargetFinished { index, total, .. } => {
                self.model.progress_completed = index + 1;
                self.model.progress_total = total;
            }
            BatchEvent::Finished { .. } => {
                self.model.progress_label = "正在写入审计并验证回执…".to_owned();
            }
        }
        cx.notify();
    }

    fn finish(
        &mut self,
        lease: BatchLease,
        result: Result<CoreResult<BatchExecutionOutcome>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if self.model.next_request_id != lease.request_id {
            return;
        }
        self.running = false;
        self.cancellation = None;
        self.reload_local();
        if !self.model.accepts(&lease) {
            cx.notify();
            return;
        }
        match result {
            Ok(Ok(outcome)) => {
                self.model.selected_result = outcome
                    .task
                    .results
                    .first()
                    .map(|result| result.connection_id.clone());
                self.model.current = Some(outcome.task.clone());
                self.notice = Some(
                    format!(
                        "批量任务完成：成功 {}，失败 {}，整体回执验证{}。",
                        outcome.task.success_count(),
                        outcome.task.failure_count(),
                        if outcome.verification.passed {
                            "通过"
                        } else {
                            "未通过"
                        }
                    )
                    .into(),
                );
                self.error = None;
            }
            Ok(Err(error)) => self.error = Some(format!("批量任务失败：{error}").into()),
            Err(error) if error.is_cancelled() => self.notice = Some("批量任务执行器已取消".into()),
            Err(error) => self.error = Some(format!("批量任务异常终止：{error}").into()),
        }
        cx.notify();
    }

    fn cancel(&mut self, cx: &mut Context<Self>) {
        if let Some(cancellation) = &self.cancellation {
            cancellation.cancel();
            self.notice = Some("已请求取消；当前远端命令完成后不会再派发新目标。".into());
            cx.notify();
        }
    }

    fn select_result(&mut self, connection_id: String, cx: &mut Context<Self>) {
        self.model.selected_result = Some(connection_id);
        cx.notify();
    }

    fn load_history(&mut self, task_id: String, cx: &mut Context<Self>) {
        if let Some(task) = self.model.history.iter().find(|task| task.id == task_id) {
            self.model.current = Some(task.clone());
            self.model.selected_result = task
                .results
                .first()
                .map(|result| result.connection_id.clone());
            self.model.view = BatchView::Execute;
            cx.notify();
        }
    }

    fn copy_csv(&mut self, cx: &mut Context<Self>) {
        let Some(task) = self.model.current.as_ref() else {
            return;
        };
        cx.write_to_clipboard(ClipboardItem::new_string(task_csv(task)));
        self.notice = Some("当前批量回执已复制为 CSV（UTF-8）".into());
        cx.notify();
    }

    fn render_targets(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let disabled = self.running || self.pending.is_some();
        div()
            .w(px(330.0))
            .min_w(px(280.0))
            .h_full()
            .min_h_0()
            .rounded_lg()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .flex()
            .flex_col()
            .child(
                div()
                    .p_3()
                    .border_b_1()
                    .border_color(tokens.border)
                    .child(div().font_semibold().child("目标服务器"))
                    .child(
                        div()
                            .mt_1()
                            .text_xs()
                            .text_color(tokens.muted)
                            .child(format!(
                                "已选 {} / {}；只显示便携连接仓库中的目标",
                                self.model.selected.len(),
                                self.model.targets.len()
                            )),
                    )
                    .child(
                        div()
                            .mt_2()
                            .flex()
                            .gap_2()
                            .child(
                                crate::buttons::button("batch-select-all")
                                    .label("全选")
                                    .small()
                                    .disabled(disabled)
                                    .on_click(cx.listener(|page, _, _, cx| page.select_all(cx))),
                            )
                            .child(
                                crate::buttons::button("batch-select-none")
                                    .label("清空")
                                    .small()
                                    .disabled(disabled)
                                    .on_click(
                                        cx.listener(|page, _, _, cx| page.clear_selection(cx)),
                                    ),
                            ),
                    ),
            )
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scrollbar()
                    .when(self.model.targets.is_empty(), |view| {
                        view.child(empty_state(
                            "暂无已保存连接；请先在 SSH 连接页保存并确认主机指纹。",
                            tokens,
                        ))
                    })
                    .children(self.model.targets.iter().map(|target| {
                        let connection_id = target.config.id.clone();
                        let selected = self.model.selected.contains(&connection_id);
                        let pinned = target.config.host_key_fingerprint.is_some()
                            && target
                                .config
                                .jump_host
                                .as_ref()
                                .is_none_or(|jump| jump.host_key_fingerprint.is_some());
                        div()
                            .id(SharedString::from(format!("batch-target-{connection_id}")))
                            .mx_2()
                            .mt_2()
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
                            .when(!disabled, |row| {
                                row.cursor_pointer()
                                    .on_click(cx.listener(move |page, _, _, cx| {
                                        page.toggle_target(connection_id.clone(), cx)
                                    }))
                            })
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child(div().size(px(9.0)).rounded_full().bg(if pinned {
                                        tokens.success
                                    } else {
                                        tokens.danger
                                    }))
                                    .child(div().font_semibold().child(target.config.name.clone()))
                                    .child(div().flex_1())
                                    .child(if selected { "已选" } else { "" }),
                            )
                            .child(
                                div()
                                    .mt_1()
                                    .font_family("Cascadia Mono")
                                    .text_xs()
                                    .text_color(tokens.muted)
                                    .child(format!(
                                        "{}@{}:{}",
                                        target.config.username,
                                        target.config.host,
                                        target.config.port
                                    )),
                            )
                            .child(
                                div()
                                    .mt_1()
                                    .text_xs()
                                    .text_color(if pinned { tokens.muted } else { tokens.danger })
                                    .child(if pinned {
                                        target
                                            .config
                                            .environment
                                            .clone()
                                            .unwrap_or_else(|| "主机指纹已固定".to_owned())
                                    } else {
                                        "缺少已确认主机指纹，计划会拒绝".to_owned()
                                    }),
                            )
                    })),
            )
            .into_any_element()
    }

    fn render_execute(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let can_run = !self.running && self.pending.is_none() && !self.model.selected.is_empty();
        let canary = matches!(self.model.strategy, BatchStrategy::Canary { .. });
        let stop_on_failure = matches!(
            self.model.strategy,
            BatchStrategy::Rolling {
                stop_on_failure: true
            }
        );
        div()
            .size_full()
            .min_h_0()
            .flex()
            .gap_3()
            .child(self.render_targets(tokens, cx))
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .h_full()
                    .min_h_0()
                    .overflow_y_scrollbar()
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
                            .child(div().font_semibold().child("批量执行计划"))
                            .child(
                                div()
                                    .mt_1()
                                    .text_sm()
                                    .text_color(tokens.muted)
                                    .child("连接、凭据与主机指纹只在 Core 内解析；确认绑定命令摘要和每台连接快照。"),
                            )
                            .child(
                                div()
                                    .mt_3()
                                    .grid()
                                    .grid_cols(2)
                                    .gap_3()
                                    .child(
                                        div()
                                            .child(field_label("任务名称"))
                                            .child(Input::new(&self.name_input)),
                                    )
                                    .child(
                                        div()
                                            .child(field_label("策略"))
                                            .child(
                                                div()
                                                    .flex()
                                                    .gap_2()
                                                    .child(
                                                        crate::buttons::button("batch-strategy-rolling")
                                                            .label("滚动")
                                                            .selected(!canary)
                                                            .disabled(self.running || self.pending.is_some())
                                                            .on_click(cx.listener(|page, _, _, cx| {
                                                                page.set_strategy(
                                                                    BatchStrategy::Rolling {
                                                                        stop_on_failure: false,
                                                                    },
                                                                    cx,
                                                                )
                                                            })),
                                                    )
                                                    .child(
                                                        crate::buttons::button("batch-strategy-canary")
                                                            .label("Canary")
                                                            .selected(canary)
                                                            .disabled(self.running || self.pending.is_some())
                                                            .on_click(cx.listener(|page, _, _, cx| {
                                                                page.set_strategy(
                                                                    BatchStrategy::Canary { count: 1 },
                                                                    cx,
                                                                )
                                                            })),
                                                    )
                                                    .when(canary, |row| {
                                                        row.child(
                                                            div()
                                                                .w(px(90.0))
                                                                .child(Input::new(&self.canary_input)),
                                                        )
                                                    })
                                                    .when(!canary, |row| {
                                                        row.child(
                                                            crate::buttons::button("batch-stop-on-failure")
                                                                .label("遇错即停")
                                                                .selected(stop_on_failure)
                                                                .disabled(
                                                                    self.running
                                                                        || self.pending.is_some(),
                                                                )
                                                                .on_click(cx.listener(
                                                                    |page, _, _, cx| {
                                                                        page.toggle_stop_on_failure(cx)
                                                                    },
                                                                )),
                                                        )
                                                    }),
                                            ),
                                    ),
                            )
                            .child(
                                div()
                                    .mt_3()
                                    .child(field_label("执行命令（任意 Shell，危险）"))
                                    .h(px(110.0))
                                    .child(Input::new(&self.command_input)),
                            )
                            .child(
                                div()
                                    .mt_3()
                                    .child(field_label("独立验证命令"))
                                    .h(px(86.0))
                                    .child(Input::new(&self.verify_input)),
                            )
                            .child(
                                div()
                                    .mt_3()
                                    .flex()
                                    .items_center()
                                    .gap_3()
                                    .child(
                                        div()
                                            .flex_1()
                                            .text_xs()
                                            .text_color(tokens.warning)
                                            .child("未填写验证命令时，只能以 SSH 退出码判定成功；本纵切不提供任意命令自动回滚。"),
                                    )
                                    .when(self.running, |row| {
                                        row.child(
                                            crate::buttons::button("batch-cancel")
                                                .label("停止后续派发")
                                                .danger()
                                                .on_click(
                                                    cx.listener(|page, _, _, cx| page.cancel(cx)),
                                                ),
                                        )
                                    })
                                    .child(
                                        crate::buttons::button("batch-plan")
                                            .label(if self.running { "执行中…" } else { "生成计划" })
                                            .primary()
                                            .disabled(!can_run)
                                            .on_click(
                                                cx.listener(|page, _, _, cx| page.prepare_plan(cx)),
                                            ),
                                    ),
                            ),
                    )
                    .when(self.running, |view| {
                        let total = self.model.progress_total.max(1);
                        let percent = (self.model.progress_completed * 100 / total).min(100);
                        view.child(
                            div()
                                .rounded_lg()
                                .border_1()
                                .border_color(tokens.accent)
                                .bg(tokens.surface)
                                .p_3()
                                .child(
                                    div()
                                        .flex()
                                        .child(self.model.progress_label.clone())
                                        .child(div().flex_1())
                                        .child(format!("{percent}%")),
                                )
                                .child(
                                    div()
                                        .mt_2()
                                        .h(px(5.0))
                                        .rounded_full()
                                        .bg(tokens.surface_alt)
                                        .child(
                                            div()
                                                .h_full()
                                                .w(relative(percent as f32 / 100.0))
                                                .rounded_full()
                                                .bg(tokens.accent),
                                        ),
                                ),
                        )
                    })
                    .when_some(self.model.current.as_ref(), |view, task| {
                        view.child(self.render_result(task, tokens, cx))
                    }),
            )
            .into_any_element()
    }

    fn render_result(
        &self,
        task: &BatchTaskRecord,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let selected = self
            .model
            .selected_result
            .as_deref()
            .and_then(|id| {
                task.results
                    .iter()
                    .find(|result| result.connection_id == id)
            })
            .or_else(|| task.results.first());
        div()
            .rounded_lg()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .p_3()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(div().font_semibold().child(task.name.clone()))
                    .child(
                        div()
                            .text_xs()
                            .text_color(tokens.success)
                            .child(format!("成功 {}", task.success_count())),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(if task.failure_count() == 0 {
                                tokens.muted
                            } else {
                                tokens.danger
                            })
                            .child(format!("失败 {}", task.failure_count())),
                    )
                    .child(div().flex_1())
                    .child(
                        crate::buttons::button("batch-copy-csv")
                            .label("复制 CSV")
                            .small()
                            .on_click(cx.listener(|page, _, _, cx| page.copy_csv(cx))),
                    ),
            )
            .child(
                div()
                    .mt_3()
                    .grid()
                    .grid_cols(2)
                    .gap_3()
                    .child(div().max_h(px(280.0)).overflow_y_scrollbar().children(
                        task.results.iter().map(|result| {
                            let connection_id = result.connection_id.clone();
                            let active = selected.is_some_and(|selected| {
                                selected.connection_id == result.connection_id
                            });
                            result_row(result, active, tokens).on_click(cx.listener(
                                move |page, _, _, cx| page.select_result(connection_id.clone(), cx),
                            ))
                        }),
                    ))
                    .child(
                        div()
                            .min_h(px(180.0))
                            .rounded_md()
                            .bg(tokens.terminal_background)
                            .p_3()
                            .font_family("Cascadia Mono")
                            .text_xs()
                            .text_color(gpui::rgb(0xd7e0ee))
                            .when_some(selected, |panel, result| {
                                panel
                                    .child(format!(
                                        "{} · {} · {:?}\n\n",
                                        result.server_name, result.address, result.status
                                    ))
                                    .child(if result.status == BatchTargetStatus::Success {
                                        result.output.clone()
                                    } else {
                                        format!(
                                            "{}\n\n{}",
                                            result.error.clone().unwrap_or_default(),
                                            result.output
                                        )
                                    })
                                    .when_some(result.verify_output.clone(), |panel, verify| {
                                        panel.child(format!("\n\n[verification]\n{verify}"))
                                    })
                            }),
                    ),
            )
    }

    fn render_history(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        div()
            .size_full()
            .min_h_0()
            .overflow_y_scrollbar()
            .rounded_lg()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .when(self.model.history.is_empty(), |view| {
                view.child(empty_state("暂无批量任务历史", tokens))
            })
            .children(self.model.history.iter().map(|task| {
                let task_id = task.id.clone();
                div()
                    .id(SharedString::from(format!("batch-history-{task_id}")))
                    .mx_3()
                    .mt_3()
                    .rounded_md()
                    .border_1()
                    .border_color(tokens.border)
                    .p_3()
                    .cursor_pointer()
                    .on_click(
                        cx.listener(move |page, _, _, cx| page.load_history(task_id.clone(), cx)),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .child(div().font_semibold().child(task.name.clone()))
                            .child(div().flex_1())
                            .child(format!(
                                "{} / {} 成功",
                                task.success_count(),
                                task.results.len()
                            )),
                    )
                    .child(
                        div()
                            .mt_1()
                            .font_family("Cascadia Mono")
                            .text_xs()
                            .text_color(tokens.muted)
                            .child(format!(
                                "{} · {}… · {}",
                                task.command_preview,
                                &task.command_sha256[..12],
                                task.completed_at.format("%Y-%m-%d %H:%M:%S UTC")
                            )),
                    )
            }))
            .into_any_element()
    }
}

impl Render for BatchServersPage {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens = self.shared.read(cx).theme.tokens();
        let view = self.model.view;
        let pending = self.pending.as_ref().map(|plan| {
            (
                plan.definition().summary.clone(),
                plan.command_preview(),
                plan.has_independent_verification(),
            )
        });
        let content = match view {
            BatchView::Execute => self.render_execute(tokens, cx),
            BatchView::History => self.render_history(tokens, cx),
        };
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
                        crate::buttons::button("batch-view-execute")
                            .label("执行任务")
                            .selected(view == BatchView::Execute)
                            .on_click(cx.listener(|page, _, _, cx| {
                                page.model.view = BatchView::Execute;
                                cx.notify();
                            })),
                    )
                    .child(
                        crate::buttons::button("batch-view-history")
                            .label("任务历史")
                            .selected(view == BatchView::History)
                            .on_click(cx.listener(|page, _, _, cx| {
                                page.reload_local();
                                page.model.view = BatchView::History;
                                cx.notify();
                            })),
                    )
                    .child(div().flex_1())
                    .child(
                        crate::buttons::button("batch-refresh")
                            .label("刷新连接")
                            .small()
                            .disabled(self.running)
                            .on_click(cx.listener(|page, _, _, cx| {
                                page.reload_local();
                                cx.notify();
                            })),
                    ),
            )
            .when_some(self.error.clone(), |root, error| {
                root.child(message_banner(error, tokens.danger, tokens))
            })
            .when_some(self.notice.clone(), |root, notice| {
                root.child(message_banner(notice, tokens.success, tokens))
            })
            .when_some(pending, |root, (summary, command, verified)| {
                root.child(
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
                                .child(
                                    div()
                                        .font_semibold()
                                        .text_color(tokens.danger)
                                        .child("确认多机危险操作"),
                                )
                                .child(div().mt_1().text_sm().child(summary))
                                .child(
                                    div()
                                        .mt_2()
                                        .rounded_md()
                                        .bg(tokens.terminal_background)
                                        .p_2()
                                        .font_family("Cascadia Mono")
                                        .text_xs()
                                        .text_color(gpui::rgb(0xd7e0ee))
                                        .child(command),
                                )
                                .child(
                                    div()
                                        .mt_1()
                                        .text_xs()
                                        .text_color(if verified {
                                            tokens.success
                                        } else {
                                            tokens.warning
                                        })
                                        .child(if verified {
                                            "每台成功执行后还必须通过独立验证命令。"
                                        } else {
                                            "未配置独立验证；只能检查远端退出码。"
                                        }),
                                ),
                        )
                        .child(
                            crate::buttons::button("batch-cancel-plan")
                                .label("取消")
                                .on_click(cx.listener(|page, _, _, cx| {
                                    page.pending = None;
                                    page.notice = Some("计划已取消，未连接任何目标".into());
                                    cx.notify();
                                })),
                        )
                        .child(
                            crate::buttons::button("batch-approve-plan")
                                .label("确认执行")
                                .danger()
                                .on_click(cx.listener(|page, _, _, cx| page.approve_pending(cx))),
                        ),
                )
            })
            .child(div().flex_1().min_h_0().child(content))
    }
}

fn result_row(
    result: &BatchTargetReceipt,
    active: bool,
    tokens: ThemeTokens,
) -> gpui::Stateful<gpui::Div> {
    div()
        .id(SharedString::from(format!(
            "batch-result-{}",
            result.connection_id
        )))
        .mb_2()
        .rounded_md()
        .border_1()
        .border_color(if active { tokens.accent } else { tokens.border })
        .bg(if active {
            tokens.surface_alt
        } else {
            tokens.surface
        })
        .p_2()
        .cursor_pointer()
        .child(
            div()
                .flex()
                .items_center()
                .gap_2()
                .child(
                    div()
                        .size(px(8.0))
                        .rounded_full()
                        .bg(status_color(result.status, tokens)),
                )
                .child(result.server_name.clone())
                .child(div().flex_1())
                .child(format!("{} ms", result.duration_ms)),
        )
        .child(
            div()
                .mt_1()
                .font_family("Cascadia Mono")
                .text_xs()
                .text_color(tokens.muted)
                .child(result.address.clone()),
        )
}

fn status_color(status: BatchTargetStatus, tokens: ThemeTokens) -> gpui::Rgba {
    match status {
        BatchTargetStatus::Success => tokens.success,
        BatchTargetStatus::Failed => tokens.danger,
        BatchTargetStatus::Skipped => tokens.warning,
    }
}

fn field_label(label: &'static str) -> impl IntoElement {
    div().mb_1().text_xs().child(label)
}

fn empty_state(message: &'static str, tokens: ThemeTokens) -> impl IntoElement {
    div()
        .min_h(px(150.0))
        .p_4()
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

fn task_csv(task: &BatchTaskRecord) -> String {
    let mut rows =
        vec!["server,address,status,duration_ms,exit_code,verified,output,error".to_owned()];
    rows.extend(task.results.iter().map(|result| {
        [
            result.server_name.as_str(),
            result.address.as_str(),
            match result.status {
                BatchTargetStatus::Success => "success",
                BatchTargetStatus::Failed => "failed",
                BatchTargetStatus::Skipped => "skipped",
            },
            &result.duration_ms.to_string(),
            &result
                .exit_code
                .map(|code| code.to_string())
                .unwrap_or_default(),
            &result
                .verified
                .map(|value| value.to_string())
                .unwrap_or_default(),
            result.output.as_str(),
            result.error.as_deref().unwrap_or_default(),
        ]
        .into_iter()
        .map(csv_field)
        .collect::<Vec<_>>()
        .join(",")
    }));
    rows.join("\n")
}

fn csv_field(value: &str) -> String {
    let trimmed = value.trim_start();
    let guarded = if trimmed.starts_with(['=', '+', '-', '@']) {
        format!("'{value}")
    } else {
        value.to_owned()
    };
    format!("\"{}\"", guarded.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lovelyres_core::batch::BatchTaskStatus;
    use uuid::Uuid;

    #[test]
    fn lifecycle_invalidates_late_progress_without_cancelling_confirmed_work() {
        let mut model = BatchModel::default();
        model.activate();
        let lease = model.begin().unwrap();
        assert!(model.accepts(&lease));
        model.deactivate();
        assert!(!model.accepts(&lease));
    }

    #[test]
    fn selection_survives_refresh_but_removed_connections_are_dropped() {
        let mut model = BatchModel::default();
        model.selected.insert("one".to_owned());
        model.selected.insert("gone".to_owned());
        model.set_targets(vec![connection("one")]);
        assert_eq!(model.selected, BTreeSet::from(["one".to_owned()]));
    }

    #[test]
    fn csv_quotes_remote_text_as_inert_data() {
        let mut task = task();
        task.results[0].output = "=cmd|' /C calc'!A0\n\"quoted\"".to_owned();
        let csv = task_csv(&task);
        assert!(csv.contains("\"\"quoted\"\""));
        assert!(csv.contains("'=cmd|' /C calc'!A0"));
        assert_eq!(csv.lines().count(), 3);
    }

    fn connection(id: &str) -> ConnectionView {
        use lovelyres_core::connections::{ConnectionConfig, SshAuthMethod};
        ConnectionView {
            config: ConnectionConfig {
                id: id.to_owned(),
                name: id.to_owned(),
                host: "192.0.2.1".to_owned(),
                port: 22,
                username: "root".to_owned(),
                auth_method: SshAuthMethod::Agent,
                private_key_path: None,
                certificate_path: None,
                agent_identity_fingerprint: None,
                jump_host: None,
                tags: BTreeSet::new(),
                notes: None,
                environment: None,
                role: None,
                group: None,
                host_key_fingerprint: Some("SHA256:test".to_owned()),
            },
            has_password: false,
            has_key_passphrase: false,
            jump_host_has_password: false,
            jump_host_has_key_passphrase: false,
            last_connected_at: None,
        }
    }

    fn task() -> BatchTaskRecord {
        BatchTaskRecord {
            id: Uuid::nil().to_string(),
            operation_id: Uuid::nil().to_string(),
            name: "test".to_owned(),
            command_preview: "true".to_owned(),
            command_sha256: "00".repeat(32),
            verify_command_sha256: None,
            strategy: BatchStrategy::Rolling {
                stop_on_failure: false,
            },
            status: BatchTaskStatus::Completed,
            results: vec![BatchTargetReceipt {
                connection_id: "one".to_owned(),
                server_name: "one".to_owned(),
                address: "root@192.0.2.1:22".to_owned(),
                target: None,
                connection_snapshot_sha256: "00".repeat(32),
                status: BatchTargetStatus::Success,
                output: "ok".to_owned(),
                error: None,
                exit_code: Some(0),
                timed_out: false,
                command_dispatched: true,
                verify_output: None,
                verified: None,
                duration_ms: 1,
            }],
            created_at: chrono::Utc::now(),
            completed_at: chrono::Utc::now(),
            digest: String::new(),
        }
    }
}
