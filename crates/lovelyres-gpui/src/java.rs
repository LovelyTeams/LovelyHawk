use std::sync::Arc;

use gpui::{
    AnyElement, Context, Entity, IntoElement, PathPromptOptions, Render, SharedString,
    Subscription, Window, div, prelude::*, px,
};
use gpui_component::{
    Disableable, Selectable, Sizable, StyledExt,
    button::ButtonVariants,
    input::{Input, InputState},
    scroll::ScrollableElement,
};
use lovelyres_core::{
    BackendServices, CoreError, CoreResult,
    java::{
        JarEntryPath, JavaEnvironment, JavaJarInspection, JavaJarUpdatePlan, JavaOperationOutcome,
        JavaRestorePlan, JavaTool, JavaUpdateRecord, JavaUpdateState, StagedClassArtifact,
    },
    operations::{DangerousConfirmation, OperationPlan},
    sftp::RemotePath,
    ssh::BoundSshSession,
    target::TargetGuard,
};
use tokio::task::AbortHandle;

use crate::{app::SharedAppState, runtime::TokioBridge, theme::ThemeTokens};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JavaTab {
    Environment,
    JarUpdate,
    History,
}

impl JavaTab {
    const ALL: [Self; 3] = [Self::Environment, Self::JarUpdate, Self::History];

    const fn label(self) -> &'static str {
        match self {
            Self::Environment => "JVM 与工具",
            Self::JarUpdate => "JAR Class 更新",
            Self::History => "恢复历史",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct JavaBinding {
    session_id: String,
    connection_id: String,
    target: TargetGuard,
}

impl JavaBinding {
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
struct JavaLease {
    activation_generation: u64,
    request_id: u64,
    binding: JavaBinding,
}

#[derive(Debug)]
struct JavaModel {
    active: bool,
    activation_generation: u64,
    next_request_id: u64,
    latest_request_id: Option<u64>,
    binding: Option<JavaBinding>,
    tab: JavaTab,
    environment: Option<JavaEnvironment>,
    inspection: Option<JavaJarInspection>,
    history: Vec<JavaUpdateRecord>,
}

impl Default for JavaModel {
    fn default() -> Self {
        Self {
            active: false,
            activation_generation: 0,
            next_request_id: 0,
            latest_request_id: None,
            binding: None,
            tab: JavaTab::Environment,
            environment: None,
            inspection: None,
            history: Vec::new(),
        }
    }
}

impl JavaModel {
    fn activate(&mut self, binding: Option<JavaBinding>) {
        self.active = true;
        self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
        self.rebind(binding);
    }

    fn deactivate(&mut self) {
        self.active = false;
        self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
        self.latest_request_id = None;
    }

    fn rebind(&mut self, binding: Option<JavaBinding>) {
        if self.binding == binding {
            return;
        }
        self.binding = binding;
        self.latest_request_id = None;
        self.environment = None;
        self.inspection = None;
        self.history.clear();
    }

    fn begin_request(&mut self, binding: JavaBinding) -> CoreResult<JavaLease> {
        if !self.active {
            return Err(CoreError::Validation {
                subject: "Java page",
                message: "page is not active".to_owned(),
            });
        }
        self.rebind(Some(binding.clone()));
        self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
        self.latest_request_id = Some(self.next_request_id);
        Ok(JavaLease {
            activation_generation: self.activation_generation,
            request_id: self.next_request_id,
            binding,
        })
    }

    fn accepts(&self, lease: &JavaLease, binding: Option<&JavaBinding>) -> bool {
        self.active
            && self.activation_generation == lease.activation_generation
            && self.latest_request_id == Some(lease.request_id)
            && binding == Some(&lease.binding)
    }
}

#[derive(Debug)]
struct SelectedClass {
    display_name: SharedString,
    artifact: StagedClassArtifact,
}

#[derive(Debug)]
enum PendingJavaPlan {
    Update(JavaJarUpdatePlan),
    Restore(JavaRestorePlan),
}

impl PendingJavaPlan {
    fn definition(&self) -> &OperationPlan {
        match self {
            Self::Update(plan) => plan.definition(),
            Self::Restore(plan) => plan.definition(),
        }
    }
}

pub struct JavaHotUpdatePage {
    services: Arc<BackendServices>,
    tokio: Arc<TokioBridge>,
    shared: Entity<SharedAppState>,
    model: JavaModel,
    jar_input: Entity<InputState>,
    entry_input: Entity<InputState>,
    selected_class: Option<SelectedClass>,
    pending: Option<PendingJavaPlan>,
    read_task_abort: Option<AbortHandle>,
    busy: bool,
    error: Option<SharedString>,
    notice: Option<SharedString>,
    _subscriptions: Vec<Subscription>,
}

impl JavaHotUpdatePage {
    pub fn new(
        services: Arc<BackendServices>,
        tokio: Arc<TokioBridge>,
        shared: Entity<SharedAppState>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let jar_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder("远端 JAR 绝对路径，例如 /opt/app/app.jar")
        });
        let entry_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("JAR 内 class 路径，例如 BOOT-INF/classes/com/example/App.class")
        });
        let subscriptions = vec![cx.observe(&shared, |page, _, cx| page.handle_shared_change(cx))];
        Self {
            services,
            tokio,
            shared,
            model: JavaModel::default(),
            jar_input,
            entry_input,
            selected_class: None,
            pending: None,
            read_task_abort: None,
            busy: false,
            error: None,
            notice: None,
            _subscriptions: subscriptions,
        }
    }

    pub fn activate(&mut self, _window: &mut Window, cx: &mut Context<Self>) {
        self.busy = false;
        self.model.activate(self.current_binding(cx));
        self.refresh(cx);
        cx.notify();
    }

    pub fn deactivate(&mut self, cx: &mut Context<Self>) {
        self.cancel_read_task();
        self.pending = None;
        self.selected_class = None;
        self.model.deactivate();
        cx.notify();
    }

    pub const fn is_active(&self) -> bool {
        self.model.active
    }

    fn current_binding(&self, cx: &Context<Self>) -> Option<JavaBinding> {
        JavaBinding::capture(self.shared.read(cx))
    }

    fn current_session(&self, cx: &Context<Self>) -> Option<BoundSshSession> {
        self.shared
            .read(cx)
            .active_ssh
            .as_ref()
            .map(|active| active.session.clone())
    }

    fn cancel_read_task(&mut self) {
        if let Some(task) = self.read_task_abort.take() {
            task.abort();
        }
        self.model.latest_request_id = None;
    }

    fn begin(&mut self, session: &BoundSshSession) -> CoreResult<JavaLease> {
        self.cancel_read_task();
        self.model.begin_request(JavaBinding::from_session(session))
    }

    fn handle_shared_change(&mut self, cx: &mut Context<Self>) {
        if !self.model.active {
            return;
        }
        let binding = self.current_binding(cx);
        if binding == self.model.binding {
            return;
        }
        self.cancel_read_task();
        self.pending = None;
        self.selected_class = None;
        self.busy = false;
        self.model.rebind(binding);
        self.error = None;
        self.notice = None;
        if self.model.binding.is_some() {
            self.refresh(cx);
        } else {
            self.error = Some("未连接可信目标，无法执行 Java 检查或更新".into());
            cx.notify();
        }
    }

    fn refresh(&mut self, cx: &mut Context<Self>) {
        if self.busy {
            return;
        }
        let Some(session) = self.current_session(cx) else {
            self.error = Some("未连接可信目标".into());
            return;
        };
        let lease = match self.begin(&session) {
            Ok(lease) => lease,
            Err(error) => {
                self.error = Some(error.to_string().into());
                return;
            }
        };
        self.busy = true;
        self.error = None;
        self.notice = Some("正在读取 Java 进程、JDK 工具与恢复历史…".into());
        let service = self.services.java().clone();
        let task = self.tokio.spawn(async move {
            let environment = service.scan_environment(&session).await?;
            let history = service.list_history(session.target())?;
            Ok::<_, CoreError>((environment, history))
        });
        self.read_task_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_refresh(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_refresh(
        &mut self,
        lease: JavaLease,
        result: Result<
            CoreResult<(JavaEnvironment, Vec<JavaUpdateRecord>)>,
            tokio::task::JoinError,
        >,
        cx: &mut Context<Self>,
    ) {
        if !self
            .model
            .accepts(&lease, self.current_binding(cx).as_ref())
        {
            return;
        }
        self.busy = false;
        self.read_task_abort = None;
        match result {
            Ok(Ok((environment, history))) => {
                self.model.environment = Some(environment);
                self.model.history = history;
                self.error = None;
                self.notice = None;
            }
            Ok(Err(error)) => self.error = Some(format!("读取 Java 环境失败：{error}").into()),
            Err(error) if error.is_cancelled() => return,
            Err(error) => self.error = Some(format!("Java 环境任务异常终止：{error}").into()),
        }
        cx.notify();
    }

    fn inspect_jar(&mut self, cx: &mut Context<Self>) {
        if self.busy {
            return;
        }
        let Some(session) = self.current_session(cx) else {
            self.error = Some("未连接可信目标".into());
            return;
        };
        let jar_path = match RemotePath::new(self.jar_input.read(cx).value().to_string()) {
            Ok(path) => path,
            Err(error) => {
                self.error = Some(format!("JAR 路径无效：{error}").into());
                return;
            }
        };
        let lease = match self.begin(&session) {
            Ok(lease) => lease,
            Err(error) => {
                self.error = Some(error.to_string().into());
                return;
            }
        };
        self.busy = true;
        self.error = None;
        self.notice = Some("正在校验 JAR 并读取 class 目录…".into());
        let service = self.services.java().clone();
        let task = self
            .tokio
            .spawn(async move { service.inspect_jar(&session, jar_path).await });
        self.read_task_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_inspection(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_inspection(
        &mut self,
        lease: JavaLease,
        result: Result<CoreResult<JavaJarInspection>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if !self
            .model
            .accepts(&lease, self.current_binding(cx).as_ref())
        {
            return;
        }
        self.busy = false;
        self.read_task_abort = None;
        match result {
            Ok(Ok(inspection)) => {
                self.notice = Some(
                    format!(
                        "JAR 已校验：{} 个 class，SHA-256 {}…",
                        inspection.class_count,
                        &inspection.sha256[..12]
                    )
                    .into(),
                );
                self.model.inspection = Some(inspection);
                self.error = None;
            }
            Ok(Err(error)) => self.error = Some(format!("JAR 检查失败：{error}").into()),
            Err(error) if error.is_cancelled() => return,
            Err(error) => self.error = Some(format!("JAR 检查任务异常终止：{error}").into()),
        }
        cx.notify();
    }

    fn select_entry(&mut self, entry: JarEntryPath, window: &mut Window, cx: &mut Context<Self>) {
        let value = entry.as_str().to_owned();
        self.entry_input
            .update(cx, |input, cx| input.set_value(value, window, cx));
        cx.notify();
    }

    fn choose_class_file(&mut self, cx: &mut Context<Self>) {
        if self.busy {
            return;
        }
        let Some(session) = self.current_session(cx) else {
            self.error = Some("未连接可信目标".into());
            return;
        };
        let lease = match self.begin(&session) {
            Ok(lease) => lease,
            Err(error) => {
                self.error = Some(error.to_string().into());
                return;
            }
        };
        let receiver = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some("选择已编译的 .class 文件".into()),
        });
        let paths = match self.services.path_guard([]) {
            Ok(paths) => paths,
            Err(error) => {
                self.error = Some(format!("无法准备受管暂存目录：{error}").into());
                return;
            }
        };
        let service = self.services.java().clone();
        let tokio = self.tokio.clone();
        self.busy = true;
        self.notice = Some("等待选择本地 class 文件…".into());
        cx.spawn(async move |page, cx| {
            let selection = receiver.await;
            let selected = match selection {
                Ok(Ok(Some(mut paths))) if paths.len() == 1 => paths.remove(0),
                Ok(Ok(None)) => {
                    let _ = cx.update(|cx| {
                        if let Some(page) = page.upgrade() {
                            page.update(cx, |page, cx| {
                                page.finish_picker_cancel(lease, cx);
                            });
                        }
                    });
                    return;
                }
                Ok(Ok(Some(_))) => {
                    let _ = cx.update(|cx| {
                        if let Some(page) = page.upgrade() {
                            page.update(cx, |page, cx| {
                                page.finish_picker_error(
                                    lease,
                                    "一次只能选择一个 class 文件".into(),
                                    cx,
                                );
                            });
                        }
                    });
                    return;
                }
                Ok(Err(error)) => {
                    let message = error.to_string();
                    let _ = cx.update(|cx| {
                        if let Some(page) = page.upgrade() {
                            page.update(cx, |page, cx| {
                                page.finish_picker_error(lease, message.into(), cx);
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
                                page.finish_picker_error(lease, message.into(), cx);
                            });
                        }
                    });
                    return;
                }
            };
            let display_name = selected
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("selected.class")
                .to_owned();
            let task = tokio.spawn(async move {
                tokio::task::spawn_blocking(move || service.stage_class_file(&paths, &selected))
                    .await
                    .map_err(|error| CoreError::Validation {
                        subject: "Java class staging task",
                        message: error.to_string(),
                    })?
            });
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.finish_class_staging(lease, display_name.into(), result, cx);
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_picker_cancel(&mut self, lease: JavaLease, cx: &mut Context<Self>) {
        if !self
            .model
            .accepts(&lease, self.current_binding(cx).as_ref())
        {
            return;
        }
        self.busy = false;
        self.notice = Some("未选择 class 文件".into());
        cx.notify();
    }

    fn finish_picker_error(
        &mut self,
        lease: JavaLease,
        error: SharedString,
        cx: &mut Context<Self>,
    ) {
        if !self
            .model
            .accepts(&lease, self.current_binding(cx).as_ref())
        {
            return;
        }
        self.busy = false;
        self.error = Some(error);
        cx.notify();
    }

    fn finish_class_staging(
        &mut self,
        lease: JavaLease,
        display_name: SharedString,
        result: Result<CoreResult<StagedClassArtifact>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if !self
            .model
            .accepts(&lease, self.current_binding(cx).as_ref())
        {
            return;
        }
        self.busy = false;
        match result {
            Ok(Ok(artifact)) => {
                self.notice = Some(
                    format!(
                        "已暂存 {}（{} 字节，SHA-256 {}…）",
                        display_name,
                        artifact.bytes(),
                        &artifact.sha256()[..12]
                    )
                    .into(),
                );
                self.selected_class = Some(SelectedClass {
                    display_name,
                    artifact,
                });
                self.error = None;
            }
            Ok(Err(error)) => self.error = Some(format!("class 文件不符合要求：{error}").into()),
            Err(error) if error.is_cancelled() => return,
            Err(error) => self.error = Some(format!("class 暂存任务异常终止：{error}").into()),
        }
        cx.notify();
    }

    fn prepare_update(&mut self, cx: &mut Context<Self>) {
        if self.busy || self.pending.is_some() {
            return;
        }
        let Some(session) = self.current_session(cx) else {
            self.error = Some("未连接可信目标".into());
            return;
        };
        let jar_path = match RemotePath::new(self.jar_input.read(cx).value().to_string()) {
            Ok(path) => path,
            Err(error) => {
                self.error = Some(format!("JAR 路径无效：{error}").into());
                return;
            }
        };
        let entry_path = match JarEntryPath::new(self.entry_input.read(cx).value().to_string()) {
            Ok(path) => path,
            Err(error) => {
                self.error = Some(format!("class 条目无效：{error}").into());
                return;
            }
        };
        let Some(selection) = self.selected_class.take() else {
            self.error = Some("请先选择并校验本地 .class 文件".into());
            return;
        };
        let paths = match self.services.path_guard([]) {
            Ok(paths) => paths,
            Err(error) => {
                self.selected_class = Some(selection);
                self.error = Some(format!("无法校验暂存目录：{error}").into());
                return;
            }
        };
        let lease = match self.begin(&session) {
            Ok(lease) => lease,
            Err(error) => {
                self.selected_class = Some(selection);
                self.error = Some(error.to_string().into());
                return;
            }
        };
        self.busy = true;
        self.error = None;
        self.notice = Some("正在重读 JAR 与原 class 哈希并生成不可变计划…".into());
        let service = self.services.java().clone();
        let task = self.tokio.spawn(async move {
            service
                .plan_jar_update(&session, &paths, jar_path, entry_path, selection.artifact)
                .await
        });
        self.read_task_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_update_plan(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_update_plan(
        &mut self,
        lease: JavaLease,
        result: Result<CoreResult<JavaJarUpdatePlan>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if !self
            .model
            .accepts(&lease, self.current_binding(cx).as_ref())
        {
            return;
        }
        self.busy = false;
        self.read_task_abort = None;
        match result {
            Ok(Ok(plan)) => {
                self.pending = Some(PendingJavaPlan::Update(plan));
                self.notice = None;
                self.error = None;
            }
            Ok(Err(error)) => {
                self.error =
                    Some(format!("无法创建 JAR 更新计划：{error}；请重新选择 class").into())
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => self.error = Some(format!("JAR 计划任务异常终止：{error}").into()),
        }
        cx.notify();
    }

    fn prepare_restore(&mut self, record_id: String, cx: &mut Context<Self>) {
        if self.busy || self.pending.is_some() {
            return;
        }
        let Some(session) = self.current_session(cx) else {
            self.error = Some("未连接可信目标".into());
            return;
        };
        match self.services.java().plan_restore(&session, &record_id) {
            Ok(plan) => {
                self.pending = Some(PendingJavaPlan::Restore(plan));
                self.error = None;
                self.notice = None;
            }
            Err(error) => self.error = Some(format!("无法创建 JAR 恢复计划：{error}").into()),
        }
        cx.notify();
    }

    fn approve_pending(&mut self, cx: &mut Context<Self>) {
        if self.busy {
            return;
        }
        let Some(pending) = self.pending.take() else {
            return;
        };
        let Some(session) = self.current_session(cx) else {
            self.error = Some("目标已断开，计划未执行".into());
            return;
        };
        let lease = match self.begin(&session) {
            Ok(lease) => lease,
            Err(error) => {
                self.error = Some(error.to_string().into());
                return;
            }
        };
        self.busy = true;
        self.error = None;
        self.notice = Some("正在执行、写入审计日志并回读 SHA-256…".into());
        let service = self.services.java().clone();
        let task = self.tokio.spawn(async move {
            match pending {
                PendingJavaPlan::Update(plan) => {
                    let confirmation = DangerousConfirmation::approve(plan.definition());
                    service
                        .execute_jar_update(&session, plan, confirmation)
                        .await
                }
                PendingJavaPlan::Restore(plan) => {
                    let confirmation = DangerousConfirmation::approve(plan.definition());
                    service.execute_restore(&session, plan, confirmation).await
                }
            }
        });
        // Once confirmed, destructive work is detached so core can always
        // journal, verify, or run its compensation path even if the page closes.
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_operation(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_operation(
        &mut self,
        lease: JavaLease,
        result: Result<CoreResult<JavaOperationOutcome>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if !self
            .model
            .accepts(&lease, self.current_binding(cx).as_ref())
        {
            return;
        }
        self.busy = false;
        match result {
            Ok(Ok(outcome)) => {
                self.notice = Some(
                    format!(
                        "{}：{} / {}，SHA-256 已回读验证",
                        outcome.record.state.label(),
                        outcome.record.jar_path.as_str(),
                        outcome.record.entry_path.as_str()
                    )
                    .into(),
                );
                self.error = None;
                self.model.tab = JavaTab::History;
                self.refresh(cx);
            }
            Ok(Err(error)) => {
                self.error = Some(format!("Java JAR 操作失败：{error}").into());
                self.refresh(cx);
            }
            Err(error) => self.error = Some(format!("Java JAR 任务异常终止：{error}").into()),
        }
        cx.notify();
    }

    fn render_environment(&self, tokens: ThemeTokens) -> AnyElement {
        let Some(environment) = self.model.environment.as_ref() else {
            return empty_state("尚未读取 Java 环境", tokens).into_any_element();
        };
        div()
            .size_full()
            .min_h_0()
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
                            .text_xs()
                            .text_color(tokens.muted)
                            .child("Java 运行时"),
                    )
                    .child(
                        div().mt_1().font_semibold().child(
                            environment
                                .version
                                .clone()
                                .unwrap_or_else(|| "未发现 java".to_owned()),
                        ),
                    ),
            )
            .child(
                div()
                    .grid()
                    .grid_cols(4)
                    .gap_2()
                    .children(JavaTool::ALL.into_iter().map(|tool| {
                        let available = environment.tools.get(&tool).copied().unwrap_or(false);
                        tool_card(tool.command(), available, tokens)
                    })),
            )
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scrollbar()
                    .rounded_lg()
                    .border_1()
                    .border_color(tokens.border)
                    .bg(tokens.surface)
                    .child(
                        div()
                            .h(px(36.0))
                            .px_3()
                            .grid()
                            .grid_cols(6)
                            .items_center()
                            .bg(tokens.surface_alt)
                            .text_xs()
                            .font_semibold()
                            .text_color(tokens.muted)
                            .child("PID")
                            .child("用户")
                            .child("CPU")
                            .child("内存")
                            .child("运行时间")
                            .child("命令"),
                    )
                    .when(environment.processes.is_empty(), |view| {
                        view.child(empty_state("未发现 Java 进程", tokens))
                    })
                    .children(environment.processes.iter().map(|process| {
                        div()
                            .min_h(px(40.0))
                            .px_3()
                            .py_2()
                            .grid()
                            .grid_cols(6)
                            .items_center()
                            .border_t_1()
                            .border_color(tokens.border)
                            .text_sm()
                            .child(process.pid.to_string())
                            .child(process.user.clone())
                            .child(format!("{:.1}%", process.cpu_percent))
                            .child(format!("{:.1}%", process.memory_percent))
                            .child(format_elapsed(process.elapsed_seconds))
                            .child(
                                div()
                                    .min_w_0()
                                    .font_family("Cascadia Mono")
                                    .text_xs()
                                    .text_color(tokens.muted)
                                    .child(process.command.clone()),
                            )
                    })),
            )
            .into_any_element()
    }

    fn render_update(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let inspected = self.model.inspection.as_ref();
        let selected = self.selected_class.as_ref();
        div()
            .size_full()
            .min_h_0()
            .overflow_y_scrollbar()
            .flex()
            .flex_col()
            .gap_3()
            .child(message_banner(
                "本页只原子更新磁盘上的 JAR，不会声称已替换运行中 JVM 的类。应用是否重载由目标自身部署策略决定。".into(),
                tokens.warning,
                tokens,
            ))
            .child(
                div()
                    .rounded_lg()
                    .border_1()
                    .border_color(tokens.border)
                    .bg(tokens.surface)
                    .p_4()
                    .child(div().font_semibold().child("1. 校验远端 JAR"))
                    .child(
                        div()
                            .mt_1()
                            .text_sm()
                            .text_color(tokens.muted)
                            .child("仅接受绝对 .jar 路径；core 拒绝符号链接并读取归档 SHA-256 与 class 目录。"),
                    )
                    .child(
                        div()
                            .mt_3()
                            .flex()
                            .gap_3()
                            .child(div().flex_1().child(Input::new(&self.jar_input)))
                            .child(
                                crate::buttons::button("java-inspect-jar")
                                    .label("检查 JAR")
                                    .disabled(self.busy)
                                    .on_click(cx.listener(|page, _, _, cx| page.inspect_jar(cx))),
                            ),
                    )
                    .when_some(inspected, |view, inspection| {
                        view.child(
                            div()
                                .mt_3()
                                .text_xs()
                                .text_color(tokens.muted)
                                .child(format!(
                                    "{} 字节 · {} 个 class · SHA-256 {}{}",
                                    inspection.size,
                                    inspection.class_count,
                                    &inspection.sha256[..12],
                                    if inspection.truncated { " · 列表仅显示前 100 项" } else { "" }
                                )),
                        )
                    }),
            )
            .child(
                div()
                    .rounded_lg()
                    .border_1()
                    .border_color(tokens.border)
                    .bg(tokens.surface)
                    .p_4()
                    .child(div().font_semibold().child("2. 选择归档条目与新 class"))
                    .child(
                        div()
                            .mt_3()
                            .flex()
                            .gap_3()
                            .child(div().flex_1().child(Input::new(&self.entry_input)))
                            .child(
                                crate::buttons::button("java-select-class")
                                    .label("选择本地 .class")
                                    .disabled(self.busy)
                                    .on_click(cx.listener(|page, _, _, cx| {
                                        page.choose_class_file(cx)
                                    })),
                            ),
                    )
                    .when_some(selected, |view, selected| {
                        view.child(
                            div()
                                .mt_2()
                                .text_xs()
                                .text_color(tokens.success)
                                .child(format!(
                                    "{} · {} 字节 · {}… · CAFEBABE 已验证",
                                    selected.display_name,
                                    selected.artifact.bytes(),
                                    &selected.artifact.sha256()[..12]
                                )),
                        )
                    })
                    .when_some(inspected, |view, inspection| {
                        let entries = inspection
                            .class_entries
                            .iter()
                            .take(100)
                            .cloned()
                            .collect::<Vec<_>>();
                        view.child(
                            div()
                                .mt_3()
                                .max_h(px(260.0))
                                .overflow_y_scrollbar()
                                .rounded_md()
                                .border_1()
                                .border_color(tokens.border)
                                .children(entries.into_iter().map(|entry| {
                                    let selected_entry = entry.clone();
                                    crate::buttons::button(SharedString::from(format!(
                                        "java-entry-{}",
                                        entry.as_str()
                                    )))
                                    .ghost()
                                    .label(entry.as_str().to_owned())
                                    .w_full()
                                    .justify_start()
                                    .on_click(cx.listener(move |page, _, window, cx| {
                                        page.select_entry(selected_entry.clone(), window, cx)
                                    }))
                                })),
                        )
                    }),
            )
            .child(
                div()
                    .rounded_lg()
                    .border_1()
                    .border_color(tokens.border)
                    .bg(tokens.surface)
                    .p_4()
                    .flex()
                    .items_center()
                    .gap_4()
                    .child(
                        div()
                            .flex_1()
                            .child(div().font_semibold().child("3. 创建不可变更新计划"))
                            .child(
                                div()
                                    .mt_1()
                                    .text_sm()
                                    .text_color(tokens.muted)
                                    .child("执行前再次读取原 JAR 与 class 哈希；候选 JAR 在原目录生成、验证后原子替换。原始包和已应用包都保存在受管恢复目录。"),
                            ),
                    )
                    .child(
                        crate::buttons::button("java-plan-update")
                            .label("创建更新计划")
                            .danger()
                            .disabled(self.busy || self.selected_class.is_none())
                            .on_click(cx.listener(|page, _, _, cx| page.prepare_update(cx))),
                    ),
            )
            .into_any_element()
    }

    fn render_history(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let history = self.model.history.clone();
        div()
            .size_full()
            .min_h_0()
            .overflow_y_scrollbar()
            .rounded_lg()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .when(history.is_empty(), |view| {
                view.child(empty_state("当前目标尚无 Java JAR 更新记录", tokens))
            })
            .children(history.into_iter().map(|record| {
                let record_id = record.id.clone();
                div()
                    .px_4()
                    .py_3()
                    .border_b_1()
                    .border_color(tokens.border)
                    .flex()
                    .items_center()
                    .gap_4()
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child(
                                        div()
                                            .font_semibold()
                                            .child(record.entry_path.as_str().to_owned()),
                                    )
                                    .child(
                                        div()
                                            .text_xs()
                                            .text_color(update_state_color(record.state, tokens))
                                            .child(record.state.label()),
                                    ),
                            )
                            .child(
                                div()
                                    .mt_1()
                                    .text_sm()
                                    .text_color(tokens.muted)
                                    .child(record.jar_path.as_str().to_owned()),
                            )
                            .child(
                                div()
                                    .mt_1()
                                    .font_family("Cascadia Mono")
                                    .text_xs()
                                    .text_color(tokens.muted)
                                    .child(format!(
                                        "{} · {}… → {}… · {}",
                                        record.id,
                                        &record.before_jar_sha256[..12],
                                        &record.applied_jar_sha256[..12],
                                        record.created_at.format("%Y-%m-%d %H:%M:%S UTC")
                                    )),
                            ),
                    )
                    .when(record.state == JavaUpdateState::Applied, |view| {
                        view.child(
                            crate::buttons::button(SharedString::from(format!(
                                "java-restore-{record_id}"
                            )))
                            .label("恢复原 JAR")
                            .danger()
                            .small()
                            .disabled(self.busy)
                            .on_click(cx.listener(
                                move |page, _, _, cx| page.prepare_restore(record_id.clone(), cx),
                            )),
                        )
                    })
            }))
            .into_any_element()
    }
}

impl Render for JavaHotUpdatePage {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens = self.shared.read(cx).theme.tokens();
        let tab = self.model.tab;
        let pending_summary = self
            .pending
            .as_ref()
            .map(|pending| pending.definition().summary.clone());
        let content = match tab {
            JavaTab::Environment => self.render_environment(tokens),
            JavaTab::JarUpdate => self.render_update(tokens, cx),
            JavaTab::History => self.render_history(tokens, cx),
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
                    .children(JavaTab::ALL.into_iter().map(|item| {
                        crate::buttons::button(SharedString::from(format!("java-tab-{}", item.label())))
                            .label(item.label())
                            .selected(tab == item)
                            .on_click(cx.listener(move |page, _, _, cx| {
                                page.model.tab = item;
                                cx.notify();
                            }))
                    }))
                    .child(div().flex_1())
                    .child(
                        crate::buttons::button("java-refresh")
                            .label(if self.busy { "处理中…" } else { "刷新" })
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
                                .child(
                                    div()
                                        .font_semibold()
                                        .text_color(tokens.danger)
                                        .child("危险操作确认"),
                                )
                                .child(div().mt_1().text_sm().child(summary))
                                .child(
                                    div()
                                        .mt_1()
                                        .text_xs()
                                        .text_color(tokens.muted)
                                        .child("确认只绑定这一份计划及当前目标 generation；执行后必须完成 journal、回读验证或安全补偿。"),
                                ),
                        )
                        .child(
                            crate::buttons::button("java-cancel-plan")
                                .label("取消")
                                .on_click(cx.listener(|page, _, _, cx| {
                                    page.pending = None;
                                    page.notice = Some("计划已取消，未产生远端修改".into());
                                    cx.notify();
                                })),
                        )
                        .child(
                            crate::buttons::button("java-approve-plan")
                                .label("确认执行")
                                .danger()
                                .on_click(cx.listener(|page, _, _, cx| {
                                    page.approve_pending(cx)
                                })),
                        ),
                )
            })
            .child(div().flex_1().min_h_0().child(content))
    }
}

fn tool_card(label: &'static str, available: bool, tokens: ThemeTokens) -> impl IntoElement {
    div()
        .rounded_md()
        .border_1()
        .border_color(tokens.border)
        .bg(tokens.surface)
        .px_3()
        .py_2()
        .flex()
        .items_center()
        .gap_2()
        .child(div().size(px(8.0)).rounded_full().bg(if available {
            tokens.success
        } else {
            tokens.muted
        }))
        .child(div().font_family("Cascadia Mono").text_sm().child(label))
        .child(div().flex_1())
        .child(
            div()
                .text_xs()
                .text_color(if available {
                    tokens.success
                } else {
                    tokens.muted
                })
                .child(if available { "可用" } else { "缺失" }),
        )
}

fn empty_state(message: &'static str, tokens: ThemeTokens) -> impl IntoElement {
    div()
        .h_full()
        .min_h(px(140.0))
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

fn update_state_color(state: JavaUpdateState, tokens: ThemeTokens) -> gpui::Rgba {
    match state {
        JavaUpdateState::Applied => tokens.warning,
        JavaUpdateState::Restored => tokens.success,
    }
}

fn format_elapsed(seconds: u64) -> String {
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lovelyres_core::target::TargetIdentity;

    fn binding(id: &str, generation: u64) -> JavaBinding {
        JavaBinding {
            session_id: format!("session-{generation}"),
            connection_id: id.to_owned(),
            target: TargetGuard {
                identity: TargetIdentity::new(id).unwrap(),
                generation,
            },
        }
    }

    #[test]
    fn target_rebind_clears_remote_java_state() {
        let mut model = JavaModel::default();
        model.activate(Some(binding("a", 1)));
        let lease = model.begin_request(binding("a", 1)).unwrap();
        model.history.push(JavaUpdateRecord {
            id: "placeholder".to_owned(),
            operation_id: "operation".to_owned(),
            last_operation_id: "operation".to_owned(),
            target: TargetIdentity::new("a").unwrap(),
            jar_path: RemotePath::new("/opt/app.jar").unwrap(),
            entry_path: JarEntryPath::new("app/Main.class").unwrap(),
            remote_root: RemotePath::new("/var/lib/test").unwrap(),
            before_jar_sha256: "00".repeat(32),
            before_entry_sha256: "00".repeat(32),
            source_sha256: "00".repeat(32),
            applied_jar_sha256: "00".repeat(32),
            backup_sha256: "00".repeat(32),
            digest: "00".repeat(32),
            state: JavaUpdateState::Restored,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        });
        model.rebind(Some(binding("b", 2)));
        assert!(model.history.is_empty());
        assert!(model.environment.is_none());
        assert!(model.inspection.is_none());
        assert!(!model.accepts(&lease, Some(&binding("b", 2))));
    }

    #[test]
    fn deactivation_rejects_late_java_results() {
        let mut model = JavaModel::default();
        let current = binding("a", 1);
        model.activate(Some(current.clone()));
        let lease = model.begin_request(current.clone()).unwrap();
        model.deactivate();
        assert!(!model.accepts(&lease, Some(&current)));
    }

    #[test]
    fn java_tabs_are_stable_and_unique() {
        assert_eq!(JavaTab::ALL.len(), 3);
        assert_ne!(JavaTab::Environment.label(), JavaTab::JarUpdate.label());
        assert_ne!(JavaTab::JarUpdate.label(), JavaTab::History.label());
    }

    #[test]
    fn elapsed_time_is_compact_and_deterministic() {
        assert_eq!(format_elapsed(59), "0m");
        assert_eq!(format_elapsed(3_661), "1h 1m");
        assert_eq!(format_elapsed(90_000), "1d 1h");
    }

    #[test]
    fn class_entry_contract_is_used_directly_by_the_native_page() {
        assert!(JarEntryPath::new("../bad.class").is_err());
        assert!(JarEntryPath::new("app/Main.class").is_ok());
    }
}
