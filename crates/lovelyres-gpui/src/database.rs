use std::{collections::BTreeMap, ops::Range, sync::Arc};

use gpui::{
    AnyElement, Context, Entity, Render, SharedString, Subscription, UniformListScrollHandle,
    Window, div, prelude::*, px, uniform_list,
};
use gpui_component::{
    Disableable, Selectable, Sizable, StyledExt,
    button::ButtonVariants,
    input::{Input, InputEvent, InputState},
    scroll::ScrollableElement,
};
use lovelyres_core::{
    BackendServices, CoreError, CoreResult,
    crypto::SecretValue,
    database::{
        DatabaseActionOutcome, DatabaseActionPlan, DatabaseColumn, DatabaseConfigInventorySnapshot,
        DatabaseEngine, DatabaseMutationRequest, DatabaseProfileChanges, DatabaseProfileConfig,
        DatabaseProfileDeletePlan, DatabaseProfileView, DatabaseRuntimeParametersSnapshot,
        DatabaseRuntimeStatus, DatabaseSecretChange, DatabaseServiceAction, DatabaseStatementKind,
        DatabaseStats, DatabaseTable, DatabaseUser, DetectedDatabase, SqlResult,
    },
    database_config::DatabaseConfigProduct,
    database_config_inventory::{
        DatabaseConfigComponentRegistration, DatabaseConfigInventoryDocument,
        DatabaseConfigInventorySurface, DatabaseConfigInventoryText,
        DatabaseConfigPluginInventoryRow, DatabaseConfigPluginLoadOption,
        DatabaseConfigPluginMaturity, DatabaseConfigPluginStatus,
    },
    database_config_runtime::{
        DatabaseConfigRuntimeApply, DatabaseConfigRuntimeScope, DatabaseConfigRuntimeValue,
        DatabaseConfigRuntimeValuePresence, PostgreSqlRuntimeContext,
    },
    operations::DangerousConfirmation,
    ssh::BoundSshSession,
    target::TargetGuard,
};
use tokio::task::AbortHandle;

use crate::{app::SharedAppState, runtime::TokioBridge, theme::ThemeTokens};

type ConnectTaskResult = Result<
    CoreResult<(String, CoreResult<Vec<String>>, CoreResult<DatabaseStats>)>,
    tokio::task::JoinError,
>;

type RuntimeParametersTaskResult =
    Result<CoreResult<DatabaseRuntimeParametersSnapshot>, tokio::task::JoinError>;

type InventoryTaskResult =
    Result<CoreResult<DatabaseConfigInventorySnapshot>, tokio::task::JoinError>;

const MAX_RUNTIME_PARAMETER_RENDER_ROWS: usize = 500;
const MAX_RUNTIME_PARAMETER_CELL_CHARS: usize = 512;
const MAX_RUNTIME_PARAMETER_ENUM_VALUES: usize = 16;
const MAX_RUNTIME_PARAMETER_FILTER_CHARS: usize = 128;
const MAX_RUNTIME_PROFILE_BUTTONS: usize = 128;
const MAX_INVENTORY_RENDER_ROWS: usize = 500;
const MAX_INVENTORY_CELL_CHARS: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MysqlRuntimeProduct {
    MySql,
    MariaDb,
}

impl MysqlRuntimeProduct {
    const ALL: [Self; 2] = [Self::MySql, Self::MariaDb];

    const fn label(self) -> &'static str {
        match self {
            Self::MySql => "MySQL",
            Self::MariaDb => "MariaDB",
        }
    }

    const fn product(self) -> DatabaseConfigProduct {
        match self {
            Self::MySql => DatabaseConfigProduct::MySql,
            Self::MariaDb => DatabaseConfigProduct::MariaDb,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeProductAvailability {
    MissingProfile,
    NeedsMysqlChoice,
    Ready(DatabaseConfigProduct),
    Unsupported(DatabaseEngine),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum RuntimeParametersStatus {
    #[default]
    NotRun,
    Loading,
    Ready,
    Failed,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum InventoryStatus {
    #[default]
    NotRun,
    Loading,
    Ready,
    Failed,
}

impl InventoryStatus {
    const fn label(self) -> &'static str {
        match self {
            Self::NotRun => "NOT_RUN",
            Self::Loading => "RUNNING",
            Self::Ready => "READY",
            Self::Failed => "FAILED",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InventoryAvailability {
    MissingProfile,
    NeedsMysqlChoice,
    Ready {
        product: DatabaseConfigProduct,
        surface: DatabaseConfigInventorySurface,
    },
    UnsupportedEngine(DatabaseEngine),
    UnsupportedSurface {
        product: DatabaseConfigProduct,
        surface: DatabaseConfigInventorySurface,
    },
}

impl RuntimeParametersStatus {
    const fn label(self) -> &'static str {
        match self {
            Self::NotRun => "NOT_RUN",
            Self::Loading => "RUNNING",
            Self::Ready => "READY",
            Self::Failed => "FAILED",
        }
    }
}

fn runtime_product_for_engine(
    engine: DatabaseEngine,
    mysql_choice: Option<MysqlRuntimeProduct>,
) -> RuntimeProductAvailability {
    match engine {
        DatabaseEngine::Mysql => mysql_choice
            .map_or(RuntimeProductAvailability::NeedsMysqlChoice, |choice| {
                RuntimeProductAvailability::Ready(choice.product())
            }),
        DatabaseEngine::Postgresql => {
            RuntimeProductAvailability::Ready(DatabaseConfigProduct::PostgreSql)
        }
        engine => RuntimeProductAvailability::Unsupported(engine),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DatabaseTab {
    Connections,
    Console,
    Browser,
    RuntimeParameters,
    Inventory,
    Users,
    Operations,
}

impl DatabaseTab {
    const ALL: [Self; 7] = [
        Self::Connections,
        Self::Console,
        Self::Browser,
        Self::RuntimeParameters,
        Self::Inventory,
        Self::Users,
        Self::Operations,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Connections => "连接",
            Self::Console => "SQL 控制台",
            Self::Browser => "对象浏览",
            Self::RuntimeParameters => "运行时参数（只读）",
            Self::Inventory => "插件 / 组件清单（只读）",
            Self::Users => "用户权限",
            Self::Operations => "运维",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DatabaseBinding {
    connection_id: String,
    session_id: String,
    target: TargetGuard,
}

impl DatabaseBinding {
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum RequestLane {
    Detect,
    Connect,
    Catalog,
    Table,
    Users,
    Stats,
    RuntimeParameters,
    Inventory,
    Query,
    Plan,
    Mutation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RequestLease {
    activation_generation: u64,
    request_id: u64,
    lane: RequestLane,
    binding: DatabaseBinding,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RuntimeParametersRequest {
    lease: RequestLease,
    profile_id: String,
    product: DatabaseConfigProduct,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InventoryRequest {
    lease: RequestLease,
    profile_id: String,
    product: DatabaseConfigProduct,
    surface: DatabaseConfigInventorySurface,
}

#[derive(Debug)]
enum PendingAction {
    Remote {
        plan: DatabaseActionPlan,
        lease: RequestLease,
    },
    DeleteProfile {
        plan: DatabaseProfileDeletePlan,
        profile_name: String,
    },
}

impl PendingAction {
    fn definition(&self) -> &lovelyres_core::operations::OperationPlan {
        match self {
            Self::Remote { plan, .. } => plan.definition(),
            Self::DeleteProfile { plan, .. } => plan.definition(),
        }
    }
}

#[derive(Debug)]
struct DatabaseModel {
    active: bool,
    activation_generation: u64,
    next_request_id: u64,
    latest: BTreeMap<RequestLane, u64>,
    binding: Option<DatabaseBinding>,
    tab: DatabaseTab,
    profiles: Vec<DatabaseProfileView>,
    selected_profile_id: Option<String>,
    editing_profile_id: Option<String>,
    selected_engine: DatabaseEngine,
    connected_profile_id: Option<String>,
    detected: Vec<DetectedDatabase>,
    databases: Vec<String>,
    selected_database: Option<String>,
    tables: Vec<DatabaseTable>,
    selected_table: Option<String>,
    columns: Vec<DatabaseColumn>,
    users: Vec<DatabaseUser>,
    stats: Option<DatabaseStats>,
    result: Option<SqlResult>,
    runtime_mysql_product: Option<(String, MysqlRuntimeProduct)>,
    runtime_parameters_status: RuntimeParametersStatus,
    runtime_parameters_snapshot: Option<DatabaseRuntimeParametersSnapshot>,
    inventory_surface: DatabaseConfigInventorySurface,
    inventory_status: InventoryStatus,
    inventory_snapshot: Option<DatabaseConfigInventorySnapshot>,
}

impl Default for DatabaseModel {
    fn default() -> Self {
        Self {
            active: false,
            activation_generation: 0,
            next_request_id: 0,
            latest: BTreeMap::new(),
            binding: None,
            tab: DatabaseTab::Connections,
            profiles: Vec::new(),
            selected_profile_id: None,
            editing_profile_id: None,
            selected_engine: DatabaseEngine::Mysql,
            connected_profile_id: None,
            detected: Vec::new(),
            databases: Vec::new(),
            selected_database: None,
            tables: Vec::new(),
            selected_table: None,
            columns: Vec::new(),
            users: Vec::new(),
            stats: None,
            result: None,
            runtime_mysql_product: None,
            runtime_parameters_status: RuntimeParametersStatus::NotRun,
            runtime_parameters_snapshot: None,
            inventory_surface: DatabaseConfigInventorySurface::PluginRegistry,
            inventory_status: InventoryStatus::NotRun,
            inventory_snapshot: None,
        }
    }
}

impl DatabaseModel {
    fn activate(&mut self, binding: Option<DatabaseBinding>) {
        self.active = true;
        self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
        self.rebind(binding);
    }

    fn deactivate(&mut self) {
        self.active = false;
        self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
        self.latest.clear();
        self.runtime_mysql_product = None;
        self.runtime_parameters_status = RuntimeParametersStatus::NotRun;
        self.runtime_parameters_snapshot = None;
        self.inventory_status = InventoryStatus::NotRun;
        self.inventory_snapshot = None;
    }

    fn rebind(&mut self, binding: Option<DatabaseBinding>) {
        if self.binding == binding {
            return;
        }
        self.binding = binding;
        self.latest.clear();
        self.connected_profile_id = None;
        self.detected.clear();
        self.databases.clear();
        self.selected_database = None;
        self.tables.clear();
        self.selected_table = None;
        self.columns.clear();
        self.users.clear();
        self.stats = None;
        self.result = None;
        self.runtime_mysql_product = None;
        self.runtime_parameters_status = RuntimeParametersStatus::NotRun;
        self.runtime_parameters_snapshot = None;
        self.inventory_status = InventoryStatus::NotRun;
        self.inventory_snapshot = None;
    }

    fn begin(&mut self, lane: RequestLane, binding: DatabaseBinding) -> CoreResult<RequestLease> {
        if !self.active {
            return Err(CoreError::Validation {
                subject: "database page",
                message: "page is not active".to_owned(),
            });
        }
        self.rebind(Some(binding.clone()));
        self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
        self.latest.insert(lane, self.next_request_id);
        Ok(RequestLease {
            activation_generation: self.activation_generation,
            request_id: self.next_request_id,
            lane,
            binding,
        })
    }

    fn accepts(&self, lease: &RequestLease, binding: Option<&DatabaseBinding>) -> bool {
        self.active
            && self.activation_generation == lease.activation_generation
            && self.latest.get(&lease.lane) == Some(&lease.request_id)
            && binding == Some(&lease.binding)
    }

    fn is_connected(&self) -> bool {
        self.connected_profile_id.is_some()
    }

    fn selected_profile(&self) -> Option<&DatabaseProfileView> {
        let profile_id = self.selected_profile_id.as_deref()?;
        self.profiles
            .iter()
            .find(|profile| profile.config.id == profile_id)
    }

    fn runtime_product_availability(&self) -> RuntimeProductAvailability {
        let Some(profile) = self.selected_profile() else {
            return RuntimeProductAvailability::MissingProfile;
        };
        let mysql_choice = self
            .runtime_mysql_product
            .as_ref()
            .filter(|(profile_id, _)| profile_id == &profile.config.id)
            .map(|(_, choice)| *choice);
        runtime_product_for_engine(profile.config.connection.engine, mysql_choice)
    }

    fn runtime_request_input(&self) -> Option<(String, DatabaseConfigProduct)> {
        let profile = self.selected_profile()?;
        let RuntimeProductAvailability::Ready(product) = self.runtime_product_availability() else {
            return None;
        };
        Some((profile.config.id.clone(), product))
    }

    fn accepts_runtime_parameters(
        &self,
        request: &RuntimeParametersRequest,
        binding: Option<&DatabaseBinding>,
    ) -> bool {
        self.accepts(&request.lease, binding)
            && self.runtime_request_input().as_ref()
                == Some(&(request.profile_id.clone(), request.product))
    }

    fn displayed_runtime_parameters(&self) -> Option<&DatabaseRuntimeParametersSnapshot> {
        if self.runtime_parameters_status != RuntimeParametersStatus::Ready {
            return None;
        }
        let (profile_id, product) = self.runtime_request_input()?;
        self.runtime_parameters_snapshot
            .as_ref()
            .filter(|snapshot| snapshot.profile_id() == profile_id && snapshot.product() == product)
    }

    fn runtime_password_blocked(&self) -> bool {
        self.selected_profile()
            .is_some_and(|profile| profile.has_password)
    }

    fn inventory_availability(&self) -> InventoryAvailability {
        let Some(profile) = self.selected_profile() else {
            return InventoryAvailability::MissingProfile;
        };
        if profile.config.connection.engine != DatabaseEngine::Mysql {
            return InventoryAvailability::UnsupportedEngine(profile.config.connection.engine);
        }
        let Some(product) = self
            .runtime_mysql_product
            .as_ref()
            .filter(|(profile_id, _)| profile_id == &profile.config.id)
            .map(|(_, choice)| choice.product())
        else {
            return InventoryAvailability::NeedsMysqlChoice;
        };
        if product == DatabaseConfigProduct::MariaDb
            && self.inventory_surface == DatabaseConfigInventorySurface::ComponentRegistry
        {
            return InventoryAvailability::UnsupportedSurface {
                product,
                surface: self.inventory_surface,
            };
        }
        InventoryAvailability::Ready {
            product,
            surface: self.inventory_surface,
        }
    }

    fn inventory_request_input(
        &self,
    ) -> Option<(
        String,
        DatabaseConfigProduct,
        DatabaseConfigInventorySurface,
    )> {
        let profile = self.selected_profile()?;
        let InventoryAvailability::Ready { product, surface } = self.inventory_availability()
        else {
            return None;
        };
        Some((profile.config.id.clone(), product, surface))
    }

    fn accepts_inventory(
        &self,
        request: &InventoryRequest,
        binding: Option<&DatabaseBinding>,
    ) -> bool {
        self.accepts(&request.lease, binding)
            && self.inventory_request_input().as_ref()
                == Some(&(request.profile_id.clone(), request.product, request.surface))
    }

    fn displayed_inventory(&self) -> Option<&DatabaseConfigInventorySnapshot> {
        if self.inventory_status != InventoryStatus::Ready {
            return None;
        }
        let (profile_id, product, surface) = self.inventory_request_input()?;
        self.inventory_snapshot.as_ref().filter(|snapshot| {
            snapshot.profile_id() == profile_id
                && snapshot.product() == product
                && inventory_document_matches_surface(snapshot.document(), surface)
        })
    }

    fn reset_runtime_parameters(&mut self, clear_product_choice: bool) {
        self.latest.remove(&RequestLane::RuntimeParameters);
        self.runtime_parameters_status = RuntimeParametersStatus::NotRun;
        self.runtime_parameters_snapshot = None;
        if clear_product_choice {
            self.runtime_mysql_product = None;
        }
    }

    fn reset_inventory(&mut self) {
        self.latest.remove(&RequestLane::Inventory);
        self.inventory_status = InventoryStatus::NotRun;
        self.inventory_snapshot = None;
    }
}

pub struct DatabasePage {
    services: Arc<BackendServices>,
    tokio: Arc<TokioBridge>,
    shared: Entity<SharedAppState>,
    model: DatabaseModel,
    name_input: Entity<InputState>,
    host_input: Entity<InputState>,
    port_input: Entity<InputState>,
    username_input: Entity<InputState>,
    database_input: Entity<InputState>,
    password_input: Entity<InputState>,
    sql_input: Entity<InputState>,
    verification_input: Entity<InputState>,
    restore_input: Entity<InputState>,
    runtime_filter_input: Entity<InputState>,
    result_scroll: UniformListScrollHandle,
    task_abort: Option<AbortHandle>,
    runtime_task_abort: Option<AbortHandle>,
    inventory_task_abort: Option<AbortHandle>,
    busy: bool,
    runtime_busy: bool,
    inventory_busy: bool,
    mutation_running: bool,
    pending: Option<PendingAction>,
    error: Option<SharedString>,
    notice: Option<SharedString>,
    _subscriptions: Vec<Subscription>,
}

impl DatabasePage {
    pub fn new(
        services: Arc<BackendServices>,
        tokio: Arc<TokioBridge>,
        shared: Entity<SharedAppState>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let name_input = cx.new(|cx| InputState::new(window, cx).placeholder("连接名称"));
        let host_input = cx.new(|cx| InputState::new(window, cx).placeholder("127.0.0.1"));
        let port_input = cx.new(|cx| InputState::new(window, cx).placeholder("3306"));
        let username_input = cx.new(|cx| InputState::new(window, cx).placeholder("root"));
        let database_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("默认数据库（可选）"));
        let password_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("留空则保留已保存密码")
                .masked(true)
        });
        let sql_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("输入单条只读查询，或需要危险确认的变更语句")
                .multi_line(true)
        });
        let verification_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("可选：变更后的只读验证语句")
                .multi_line(true)
        });
        let restore_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("可选：验证失败时执行的恢复语句")
                .multi_line(true)
        });
        let runtime_filter_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("按参数名筛选（最多 128 字符）")
                .validate(|value, _| value.chars().count() <= MAX_RUNTIME_PARAMETER_FILTER_CHARS)
        });
        let mut subscriptions =
            vec![cx.observe(&shared, |page, _, cx| page.handle_shared_change(cx))];
        for input in [
            &name_input,
            &host_input,
            &port_input,
            &username_input,
            &database_input,
            &password_input,
            &sql_input,
            &verification_input,
            &restore_input,
            &runtime_filter_input,
        ] {
            subscriptions.push(cx.subscribe_in(
                input,
                window,
                |page, _, event: &InputEvent, _, cx| {
                    if matches!(event, InputEvent::Change) {
                        page.error = None;
                        cx.notify();
                    }
                },
            ));
        }
        Self {
            services,
            tokio,
            shared,
            model: DatabaseModel::default(),
            name_input,
            host_input,
            port_input,
            username_input,
            database_input,
            password_input,
            sql_input,
            verification_input,
            restore_input,
            runtime_filter_input,
            result_scroll: UniformListScrollHandle::new(),
            task_abort: None,
            runtime_task_abort: None,
            inventory_task_abort: None,
            busy: false,
            runtime_busy: false,
            inventory_busy: false,
            mutation_running: false,
            pending: None,
            error: None,
            notice: None,
            _subscriptions: subscriptions,
        }
    }

    pub fn activate(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.model
            .activate(DatabaseBinding::capture(self.shared.read(cx)));
        self.reload_profiles(window, cx);
        if self.model.detected.is_empty() {
            self.detect(cx);
        }
        cx.notify();
    }

    pub fn deactivate(&mut self, cx: &mut Context<Self>) {
        self.model.deactivate();
        abort_task(&mut self.task_abort);
        abort_task(&mut self.runtime_task_abort);
        abort_task(&mut self.inventory_task_abort);
        self.busy = false;
        self.runtime_busy = false;
        self.inventory_busy = false;
        self.pending = None;
        cx.notify();
    }

    pub const fn is_active(&self) -> bool {
        self.model.active
    }

    fn current_session(&self, cx: &Context<Self>) -> Option<BoundSshSession> {
        self.shared
            .read(cx)
            .active_ssh
            .as_ref()
            .map(|active| active.session.clone())
    }

    fn current_binding(&self, cx: &Context<Self>) -> Option<DatabaseBinding> {
        DatabaseBinding::capture(self.shared.read(cx))
    }

    fn handle_shared_change(&mut self, cx: &mut Context<Self>) {
        let binding = self.current_binding(cx);
        if self.model.binding != binding {
            self.model.rebind(binding);
            abort_task(&mut self.task_abort);
            abort_task(&mut self.runtime_task_abort);
            abort_task(&mut self.inventory_task_abort);
            self.busy = false;
            self.runtime_busy = false;
            self.inventory_busy = false;
            self.pending = None;
            self.error = Some("SSH 目标已变化；数据库会话与未执行计划已清空。".into());
        }
        cx.notify();
    }

    fn reload_profiles(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let previous_profile_id = self.model.selected_profile_id.clone();
        match self.services.database().profiles() {
            Ok(profiles) => {
                self.model.profiles = profiles;
                if self.model.selected_profile_id.as_ref().is_none_or(|id| {
                    !self
                        .model
                        .profiles
                        .iter()
                        .any(|profile| &profile.config.id == id)
                }) {
                    self.model.selected_profile_id = self
                        .model
                        .profiles
                        .first()
                        .map(|profile| profile.config.id.clone());
                }
                if self.model.selected_profile_id != previous_profile_id {
                    self.reset_runtime_parameters(true);
                    self.reset_inventory();
                }
                if let Some(id) = self.model.selected_profile_id.clone() {
                    self.load_profile_editor(&id, window, cx);
                } else {
                    self.new_profile(window, cx);
                }
            }
            Err(error) => self.error = Some(format!("读取数据库连接失败：{error}").into()),
        }
    }

    fn new_profile(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.model.editing_profile_id = None;
        self.model.selected_engine = DatabaseEngine::Mysql;
        set_input(&self.name_input, "", window, cx);
        set_input(&self.host_input, "127.0.0.1", window, cx);
        set_input(&self.port_input, "3306", window, cx);
        set_input(&self.username_input, "root", window, cx);
        set_input(&self.database_input, "", window, cx);
        set_input(&self.password_input, "", window, cx);
        cx.notify();
    }

    fn load_profile_editor(
        &mut self,
        profile_id: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(profile) = self
            .model
            .profiles
            .iter()
            .find(|profile| profile.config.id == profile_id)
            .cloned()
        else {
            return;
        };
        if self.model.selected_profile_id.as_deref() != Some(profile_id) {
            self.reset_runtime_parameters(true);
            self.reset_inventory();
        }
        self.model.selected_profile_id = Some(profile_id.to_owned());
        self.model.editing_profile_id = Some(profile_id.to_owned());
        self.model.selected_engine = profile.config.connection.engine;
        set_input(&self.name_input, &profile.config.name, window, cx);
        set_input(
            &self.host_input,
            &profile.config.connection.host,
            window,
            cx,
        );
        set_input(
            &self.port_input,
            &profile.config.connection.port.to_string(),
            window,
            cx,
        );
        set_input(
            &self.username_input,
            profile
                .config
                .connection
                .username
                .as_deref()
                .unwrap_or_default(),
            window,
            cx,
        );
        set_input(
            &self.database_input,
            profile
                .config
                .connection
                .database
                .as_deref()
                .unwrap_or_default(),
            window,
            cx,
        );
        set_input(&self.password_input, "", window, cx);
        cx.notify();
    }

    fn set_engine(&mut self, engine: DatabaseEngine, window: &mut Window, cx: &mut Context<Self>) {
        self.model.selected_engine = engine;
        set_input(
            &self.port_input,
            &engine.default_port().to_string(),
            window,
            cx,
        );
        if engine == DatabaseEngine::Redis {
            set_input(&self.username_input, "", window, cx);
        }
        cx.notify();
    }

    fn save_profile(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let name = input_value(&self.name_input, cx);
        let host = input_value(&self.host_input, cx);
        let username = input_value(&self.username_input, cx);
        let database = input_value(&self.database_input, cx);
        let password = input_value(&self.password_input, cx);
        let port = match input_value(&self.port_input, cx).parse::<u16>() {
            Ok(port) => port,
            Err(_) => {
                self.error = Some("数据库端口必须是 1–65535 的整数".into());
                cx.notify();
                return;
            }
        };
        let id =
            self.model.editing_profile_id.clone().unwrap_or_else(|| {
                DatabaseProfileConfig::new(&name, self.model.selected_engine).id
            });
        let config = DatabaseProfileConfig {
            id,
            name,
            connection: lovelyres_core::database::DatabaseConnection {
                engine: self.model.selected_engine,
                host,
                port,
                username: (!username.is_empty()).then_some(username),
                database: (!database.is_empty()).then_some(database),
            },
        };
        let changes = DatabaseProfileChanges {
            password: if password.is_empty() {
                DatabaseSecretChange::Keep
            } else {
                DatabaseSecretChange::Replace(SecretValue::new(password))
            },
        };
        match self.services.database().upsert_profile(config, changes) {
            Ok(view) => {
                self.reset_runtime_parameters(true);
                self.reset_inventory();
                self.model.selected_profile_id = Some(view.config.id.clone());
                self.notice = Some("数据库连接已写入便携加密存储。".into());
                self.error = None;
                set_input(&self.password_input, "", window, cx);
                self.reload_profiles(window, cx);
            }
            Err(error) => self.error = Some(format!("保存连接失败：{error}").into()),
        }
        cx.notify();
    }

    fn set_tab(&mut self, tab: DatabaseTab, cx: &mut Context<Self>) {
        self.model.tab = tab;
        if tab == DatabaseTab::Users
            && self.model.users.is_empty()
            && self.model.is_connected()
            && !self.runtime_busy
        {
            self.refresh_users(cx);
        }
        if tab == DatabaseTab::Operations
            && self.model.stats.is_none()
            && self.model.is_connected()
            && !self.runtime_busy
        {
            self.refresh_stats(cx);
        }
        cx.notify();
    }

    fn set_runtime_mysql_product(&mut self, choice: MysqlRuntimeProduct, cx: &mut Context<Self>) {
        let Some(profile) = self.model.selected_profile() else {
            self.error = Some("请先选择一个已保存的数据库连接".into());
            cx.notify();
            return;
        };
        if profile.config.connection.engine != DatabaseEngine::Mysql {
            self.error = Some("仅 MySQL / MariaDB 连接需要显式选择产品".into());
            cx.notify();
            return;
        }
        let profile_id = profile.config.id.clone();
        if self.model.runtime_mysql_product.as_ref() == Some(&(profile_id.clone(), choice)) {
            return;
        }
        self.reset_runtime_parameters(false);
        self.reset_inventory();
        self.model.runtime_mysql_product = Some((profile_id, choice));
        self.error = None;
        self.notice = Some(format!("数据库配置只读读取已限定为 {}。", choice.label()).into());
        cx.notify();
    }

    fn read_runtime_parameters(&mut self, cx: &mut Context<Self>) {
        if self.model.runtime_password_blocked() {
            self.error = Some(
                "密码连接暂不执行运行时读取：在改用 SSH 隧道内的原生数据库协议前，不能把密码交给可能被替换的远端 mysql/psql。"
                    .into(),
            );
            cx.notify();
            return;
        }
        let Some(session) = self.current_session(cx) else {
            self.error = Some("请先连接可信 SSH 目标".into());
            cx.notify();
            return;
        };
        let binding = DatabaseBinding::from_session(&session);
        if self.model.binding.as_ref() != Some(&binding) {
            self.reset_runtime_parameters(true);
            self.reset_inventory();
            self.model.rebind(Some(binding));
            self.error = Some("SSH 目标刚刚变化；请重新确认数据库产品后再读取。".into());
            cx.notify();
            return;
        }
        let (profile_id, product) = match self.model.runtime_request_input() {
            Some(input) => input,
            None => {
                self.error = Some(
                    match self.model.runtime_product_availability() {
                        RuntimeProductAvailability::MissingProfile => {
                            "请先选择一个已保存的数据库连接".to_owned()
                        }
                        RuntimeProductAvailability::NeedsMysqlChoice => {
                            "请显式选择 MySQL 或 MariaDB".to_owned()
                        }
                        RuntimeProductAvailability::Unsupported(engine) => {
                            format!("{} 不支持已审核的运行时参数读取", engine.label())
                        }
                        RuntimeProductAvailability::Ready(_) => {
                            "运行时参数选择已失效，请重新选择".to_owned()
                        }
                    }
                    .into(),
                );
                cx.notify();
                return;
            }
        };
        let lease = match self.model.begin(RequestLane::RuntimeParameters, binding) {
            Ok(lease) => lease,
            Err(error) => {
                self.error = Some(error.to_string().into());
                cx.notify();
                return;
            }
        };
        let request = RuntimeParametersRequest {
            lease,
            profile_id: profile_id.clone(),
            product,
        };
        abort_task(&mut self.runtime_task_abort);
        self.runtime_busy = true;
        self.model.runtime_parameters_status = RuntimeParametersStatus::Loading;
        self.model.runtime_parameters_snapshot = None;
        self.error = None;
        self.notice = Some("正在通过当前绑定 SSH 会话读取已审核的只读运行时参数…".into());

        let service = self.services.database().clone();
        let task = self.tokio.spawn(async move {
            service
                .read_runtime_parameters(&session, &profile_id, product)
                .await
        });
        self.runtime_task_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.finish_runtime_parameters(request, result, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_runtime_parameters(
        &mut self,
        request: RuntimeParametersRequest,
        result: RuntimeParametersTaskResult,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self
            .model
            .accepts_runtime_parameters(&request, binding.as_ref())
        {
            return;
        }
        self.runtime_busy = false;
        self.runtime_task_abort = None;
        match result {
            Ok(Ok(snapshot)) => {
                if snapshot.profile_id() != request.profile_id
                    || snapshot.product() != request.product
                {
                    self.model.runtime_parameters_status = RuntimeParametersStatus::Failed;
                    self.model.runtime_parameters_snapshot = None;
                    self.error = Some("运行时参数快照与请求不匹配，结果已拒绝。".into());
                } else if let Err(error) = self
                    .services
                    .database()
                    .validate_runtime_parameters_snapshot(&snapshot)
                {
                    self.model.runtime_parameters_status = RuntimeParametersStatus::Failed;
                    self.model.runtime_parameters_snapshot = None;
                    self.error = Some(format!("运行时参数快照复验失败：{error}").into());
                } else {
                    let row_count = snapshot.document().rows().len();
                    self.model.runtime_parameters_status = RuntimeParametersStatus::Ready;
                    self.model.runtime_parameters_snapshot = Some(snapshot);
                    self.error = None;
                    self.notice = Some(
                        format!(
                            "已读取并复验 {row_count} 条只读运行时参数。任何未公开值均保持脱敏。"
                        )
                        .into(),
                    );
                }
            }
            Ok(Err(error)) => {
                self.model.runtime_parameters_status = RuntimeParametersStatus::Failed;
                self.model.runtime_parameters_snapshot = None;
                self.error = Some(format!("读取运行时参数失败：{error}").into());
            }
            Err(error) if error.is_cancelled() => {
                self.model.runtime_parameters_status = RuntimeParametersStatus::NotRun;
                self.model.runtime_parameters_snapshot = None;
            }
            Err(error) => {
                self.model.runtime_parameters_status = RuntimeParametersStatus::Failed;
                self.model.runtime_parameters_snapshot = None;
                self.error = Some(format!("运行时参数任务异常终止：{error}").into());
            }
        }
        cx.notify();
    }

    fn reset_runtime_parameters(&mut self, clear_product_choice: bool) {
        abort_task(&mut self.runtime_task_abort);
        self.runtime_busy = false;
        self.model.reset_runtime_parameters(clear_product_choice);
    }

    fn cancel_runtime_parameters(&mut self, cx: &mut Context<Self>) {
        if !self.runtime_busy {
            return;
        }
        self.reset_runtime_parameters(false);
        self.notice = Some("运行时参数读取已取消；未应用任何迟到结果。".into());
        self.error = None;
        cx.notify();
    }

    fn set_inventory_surface(
        &mut self,
        surface: DatabaseConfigInventorySurface,
        cx: &mut Context<Self>,
    ) {
        if self.model.inventory_surface == surface {
            return;
        }
        self.reset_inventory();
        self.model.inventory_surface = surface;
        self.error = None;
        self.notice = Some(
            format!(
                "只读清单范围已切换为 {}。",
                inventory_surface_label(surface)
            )
            .into(),
        );
        cx.notify();
    }

    fn read_database_config_inventory(&mut self, cx: &mut Context<Self>) {
        if self.model.runtime_password_blocked() {
            self.error = Some(
                "PASSWORD_BLOCKED：此入口同时禁用密码连接；core 也会在首个 SSH 命令前拒绝该请求。"
                    .into(),
            );
            cx.notify();
            return;
        }
        let Some(session) = self.current_session(cx) else {
            self.error = Some("请先连接可信 SSH 目标".into());
            cx.notify();
            return;
        };
        let binding = DatabaseBinding::from_session(&session);
        if self.model.binding.as_ref() != Some(&binding) {
            self.reset_runtime_parameters(true);
            self.reset_inventory();
            self.model.rebind(Some(binding));
            self.error = Some("SSH 目标刚刚变化；请重新确认数据库产品与清单范围。".into());
            cx.notify();
            return;
        }
        let (profile_id, product, surface) = match self.model.inventory_request_input() {
            Some(input) => input,
            None => {
                self.error = Some(
                    match self.model.inventory_availability() {
                        InventoryAvailability::MissingProfile => {
                            "请先选择一个已保存的数据库连接".to_owned()
                        }
                        InventoryAvailability::NeedsMysqlChoice => {
                            "请显式选择 MySQL 或 MariaDB".to_owned()
                        }
                        InventoryAvailability::UnsupportedEngine(engine) => {
                            format!("{} 不支持插件 / 组件清单读取", engine.label())
                        }
                        InventoryAvailability::UnsupportedSurface { product, surface } => {
                            format!(
                                "{} 不支持 {}；请求已在 UI 发起前关闭。",
                                database_config_product_label(product),
                                inventory_surface_label(surface)
                            )
                        }
                        InventoryAvailability::Ready { .. } => {
                            "清单选择已失效，请重新选择".to_owned()
                        }
                    }
                    .into(),
                );
                cx.notify();
                return;
            }
        };
        let lease = match self.model.begin(RequestLane::Inventory, binding) {
            Ok(lease) => lease,
            Err(error) => {
                self.error = Some(error.to_string().into());
                cx.notify();
                return;
            }
        };
        let request = InventoryRequest {
            lease,
            profile_id: profile_id.clone(),
            product,
            surface,
        };
        abort_task(&mut self.inventory_task_abort);
        self.inventory_busy = true;
        self.model.inventory_status = InventoryStatus::Loading;
        self.model.inventory_snapshot = None;
        self.error = None;
        self.notice = Some(
            format!(
                "正在读取已审核的 {} {}…",
                database_config_product_label(product),
                inventory_surface_label(surface)
            )
            .into(),
        );

        let service = self.services.database().clone();
        let task = self.tokio.spawn(async move {
            service
                .read_database_config_inventory(&session, &profile_id, product, surface)
                .await
        });
        self.inventory_task_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.finish_database_config_inventory(request, result, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_database_config_inventory(
        &mut self,
        request: InventoryRequest,
        result: InventoryTaskResult,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts_inventory(&request, binding.as_ref()) {
            return;
        }
        self.inventory_busy = false;
        self.inventory_task_abort = None;
        match result {
            Ok(Ok(snapshot)) => {
                if snapshot.target() != &request.lease.binding.target
                    || snapshot.profile_id() != request.profile_id
                    || snapshot.product() != request.product
                    || !inventory_document_matches_surface(snapshot.document(), request.surface)
                {
                    self.model.inventory_status = InventoryStatus::Failed;
                    self.model.inventory_snapshot = None;
                    self.error = Some("插件 / 组件清单快照与请求不匹配，结果已拒绝。".into());
                } else if let Err(error) = self
                    .services
                    .database()
                    .validate_database_config_inventory_snapshot(&snapshot)
                {
                    self.model.inventory_status = InventoryStatus::Failed;
                    self.model.inventory_snapshot = None;
                    self.error = Some(format!("插件 / 组件清单快照复验失败：{error}").into());
                } else {
                    let row_count = snapshot.document().len();
                    self.model.inventory_status = InventoryStatus::Ready;
                    self.model.inventory_snapshot = Some(snapshot);
                    self.error = None;
                    self.notice = Some(
                        format!("已读取并复验 {row_count} 条只读清单记录；非公开文本保持脱敏。")
                            .into(),
                    );
                }
            }
            Ok(Err(error)) => {
                self.model.inventory_status = InventoryStatus::Failed;
                self.model.inventory_snapshot = None;
                self.error = Some(format!("读取插件 / 组件清单失败：{error}").into());
            }
            Err(error) if error.is_cancelled() => {
                self.model.inventory_status = InventoryStatus::NotRun;
                self.model.inventory_snapshot = None;
            }
            Err(error) => {
                self.model.inventory_status = InventoryStatus::Failed;
                self.model.inventory_snapshot = None;
                self.error = Some(format!("插件 / 组件清单任务异常终止：{error}").into());
            }
        }
        cx.notify();
    }

    fn reset_inventory(&mut self) {
        abort_task(&mut self.inventory_task_abort);
        self.inventory_busy = false;
        self.model.reset_inventory();
    }

    fn cancel_inventory(&mut self, cx: &mut Context<Self>) {
        if !self.inventory_busy {
            return;
        }
        self.reset_inventory();
        self.notice = Some("插件 / 组件清单读取已取消；未应用任何迟到结果。".into());
        self.error = None;
        cx.notify();
    }

    fn detect(&mut self, cx: &mut Context<Self>) {
        let Some(session) = self.current_session(cx) else {
            self.error = Some("请先连接可信 SSH 目标".into());
            cx.notify();
            return;
        };
        let lease = match self
            .model
            .begin(RequestLane::Detect, DatabaseBinding::from_session(&session))
        {
            Ok(lease) => lease,
            Err(error) => {
                self.error = Some(error.to_string().into());
                cx.notify();
                return;
            }
        };
        self.start_task();
        self.notice = Some("正在目标主机上探测数据库客户端与服务状态…".into());
        let service = self.services.database().clone();
        let task = self
            .tokio
            .spawn(async move { service.detect(&session).await });
        self.task_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        let binding = page.current_binding(cx);
                        if !page.model.accepts(&lease, binding.as_ref()) {
                            return;
                        }
                        page.finish_task();
                        match result {
                            Ok(Ok(detected)) => {
                                page.notice = Some(
                                    format!("已发现 {} 个数据库运行时。", detected.len()).into(),
                                );
                                page.model.detected = detected;
                                page.error = None;
                            }
                            Ok(Err(error)) => {
                                page.error = Some(format!("数据库探测失败：{error}").into())
                            }
                            Err(error) if error.is_cancelled() => return,
                            Err(error) => {
                                page.error = Some(format!("探测任务异常终止：{error}").into())
                            }
                        }
                        cx.notify();
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn connect_selected(&mut self, cx: &mut Context<Self>) {
        let Some(profile_id) = self.model.selected_profile_id.clone() else {
            self.error = Some("请先保存并选择一个数据库连接".into());
            cx.notify();
            return;
        };
        let Some(session) = self.current_session(cx) else {
            self.error = Some("请先连接可信 SSH 目标".into());
            cx.notify();
            return;
        };
        let lease = match self.model.begin(
            RequestLane::Connect,
            DatabaseBinding::from_session(&session),
        ) {
            Ok(lease) => lease,
            Err(error) => {
                self.error = Some(error.to_string().into());
                cx.notify();
                return;
            }
        };
        self.start_task();
        self.notice = Some("正在通过已绑定 SSH 会话验证数据库连接…".into());
        let service = self.services.database().clone();
        let task = self.tokio.spawn(async move {
            service.test_profile(&session, &profile_id).await?;
            let databases = service.list_databases(&session, &profile_id).await;
            let stats = service.stats(&session, &profile_id).await;
            CoreResult::Ok((profile_id, databases, stats))
        });
        self.task_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_connect(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_connect(
        &mut self,
        lease: RequestLease,
        result: ConnectTaskResult,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            return;
        }
        self.finish_task();
        match result {
            Ok(Ok((profile_id, databases, stats))) => {
                self.model.connected_profile_id = Some(profile_id);
                self.model.databases = databases.unwrap_or_default();
                self.model.selected_database = self
                    .model
                    .databases
                    .first()
                    .cloned()
                    .or_else(|| self.selected_profile_database());
                self.model.stats = stats.ok();
                self.notice =
                    Some("数据库连接已验证；目录或统计缺少权限时仍可使用获授权功能。".into());
                self.error = None;
                self.model.tab = DatabaseTab::Console;
            }
            Ok(Err(error)) => self.error = Some(format!("数据库连接失败：{error}").into()),
            Err(error) if error.is_cancelled() => return,
            Err(error) => self.error = Some(format!("连接任务异常终止：{error}").into()),
        }
        cx.notify();
    }

    fn selected_profile_database(&self) -> Option<String> {
        let selected = self.model.selected_profile_id.as_ref()?;
        self.model
            .profiles
            .iter()
            .find(|profile| &profile.config.id == selected)
            .and_then(|profile| profile.config.connection.database.clone())
    }

    fn disconnect(&mut self, cx: &mut Context<Self>) {
        self.model.connected_profile_id = None;
        self.model.databases.clear();
        self.model.selected_database = None;
        self.model.tables.clear();
        self.model.selected_table = None;
        self.model.columns.clear();
        self.model.users.clear();
        self.model.stats = None;
        self.model.result = None;
        self.pending = None;
        self.notice = Some("数据库逻辑会话已断开；SSH 目标保持连接。".into());
        cx.notify();
    }

    fn select_database(&mut self, database: String, cx: &mut Context<Self>) {
        self.model.selected_database = Some(database);
        self.model.selected_table = None;
        self.model.columns.clear();
        self.model.result = None;
        self.refresh_tables(cx);
    }

    fn refresh_tables(&mut self, cx: &mut Context<Self>) {
        let Some(profile_id) = self.model.connected_profile_id.clone() else {
            self.error = Some("请先连接数据库".into());
            cx.notify();
            return;
        };
        let Some(database) = self.model.selected_database.clone() else {
            self.error = Some("请先选择数据库".into());
            cx.notify();
            return;
        };
        let Some(session) = self.current_session(cx) else {
            return;
        };
        let lease = match self.model.begin(
            RequestLane::Catalog,
            DatabaseBinding::from_session(&session),
        ) {
            Ok(lease) => lease,
            Err(error) => {
                self.error = Some(error.to_string().into());
                cx.notify();
                return;
            }
        };
        self.start_task();
        let service = self.services.database().clone();
        let task = self
            .tokio
            .spawn(async move { service.list_tables(&session, &profile_id, &database).await });
        self.task_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        let binding = page.current_binding(cx);
                        if !page.model.accepts(&lease, binding.as_ref()) {
                            return;
                        }
                        page.finish_task();
                        match result {
                            Ok(Ok(tables)) => {
                                page.model.tables = tables;
                                page.error = None;
                            }
                            Ok(Err(error)) => {
                                page.error = Some(format!("加载数据库对象失败：{error}").into())
                            }
                            Err(error) if error.is_cancelled() => return,
                            Err(error) => {
                                page.error = Some(format!("目录任务异常终止：{error}").into())
                            }
                        }
                        cx.notify();
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn select_table(&mut self, table: String, cx: &mut Context<Self>) {
        let Some(profile_id) = self.model.connected_profile_id.clone() else {
            return;
        };
        let Some(database) = self.model.selected_database.clone() else {
            return;
        };
        let Some(session) = self.current_session(cx) else {
            return;
        };
        self.model.selected_table = Some(table.clone());
        let lease = match self
            .model
            .begin(RequestLane::Table, DatabaseBinding::from_session(&session))
        {
            Ok(lease) => lease,
            Err(error) => {
                self.error = Some(error.to_string().into());
                cx.notify();
                return;
            }
        };
        self.start_task();
        let service = self.services.database().clone();
        let task = self.tokio.spawn(async move {
            let columns = service
                .list_columns(&session, &profile_id, &database, &table)
                .await;
            let sample = service
                .sample_table(&session, &profile_id, &database, &table, 100)
                .await;
            (columns, sample)
        });
        self.task_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        let binding = page.current_binding(cx);
                        if !page.model.accepts(&lease, binding.as_ref()) {
                            return;
                        }
                        page.finish_task();
                        match result {
                            Ok((columns, sample)) => {
                                page.model.columns = columns.unwrap_or_default();
                                page.model.result = sample.ok();
                                page.error = None;
                            }
                            Err(error) if error.is_cancelled() => return,
                            Err(error) => {
                                page.error = Some(format!("表详情任务异常终止：{error}").into())
                            }
                        }
                        cx.notify();
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn refresh_users(&mut self, cx: &mut Context<Self>) {
        let Some(profile_id) = self.model.connected_profile_id.clone() else {
            self.error = Some("请先连接数据库".into());
            cx.notify();
            return;
        };
        let Some(session) = self.current_session(cx) else {
            return;
        };
        let lease = match self
            .model
            .begin(RequestLane::Users, DatabaseBinding::from_session(&session))
        {
            Ok(lease) => lease,
            Err(error) => {
                self.error = Some(error.to_string().into());
                cx.notify();
                return;
            }
        };
        self.start_task();
        let service = self.services.database().clone();
        let task = self
            .tokio
            .spawn(async move { service.list_users(&session, &profile_id).await });
        self.task_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        let binding = page.current_binding(cx);
                        if !page.model.accepts(&lease, binding.as_ref()) {
                            return;
                        }
                        page.finish_task();
                        match result {
                            Ok(Ok(users)) => {
                                page.model.users = users;
                                page.error = None;
                            }
                            Ok(Err(error)) => {
                                page.error = Some(format!("加载数据库用户失败：{error}").into())
                            }
                            Err(error) if error.is_cancelled() => return,
                            Err(error) => {
                                page.error = Some(format!("用户任务异常终止：{error}").into())
                            }
                        }
                        cx.notify();
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn refresh_stats(&mut self, cx: &mut Context<Self>) {
        let Some(profile_id) = self.model.connected_profile_id.clone() else {
            self.error = Some("请先连接数据库".into());
            cx.notify();
            return;
        };
        let Some(session) = self.current_session(cx) else {
            return;
        };
        let lease = match self
            .model
            .begin(RequestLane::Stats, DatabaseBinding::from_session(&session))
        {
            Ok(lease) => lease,
            Err(error) => {
                self.error = Some(error.to_string().into());
                cx.notify();
                return;
            }
        };
        self.start_task();
        let service = self.services.database().clone();
        let task = self
            .tokio
            .spawn(async move { service.stats(&session, &profile_id).await });
        self.task_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        let binding = page.current_binding(cx);
                        if !page.model.accepts(&lease, binding.as_ref()) {
                            return;
                        }
                        page.finish_task();
                        match result {
                            Ok(Ok(stats)) => {
                                page.model.stats = Some(stats);
                                page.error = None;
                            }
                            Ok(Err(error)) => {
                                page.error = Some(format!("加载数据库统计失败：{error}").into())
                            }
                            Err(error) if error.is_cancelled() => return,
                            Err(error) => {
                                page.error = Some(format!("统计任务异常终止：{error}").into())
                            }
                        }
                        cx.notify();
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn execute_sql(&mut self, cx: &mut Context<Self>) {
        let Some(profile_id) = self.model.connected_profile_id.clone() else {
            self.error = Some("请先连接数据库".into());
            cx.notify();
            return;
        };
        let Some(profile) = self
            .model
            .profiles
            .iter()
            .find(|profile| profile.config.id == profile_id)
        else {
            self.error = Some("连接配置已不存在，请重新选择".into());
            cx.notify();
            return;
        };
        let statement = input_value(&self.sql_input, cx);
        let kind = match lovelyres_core::database::DatabaseService::classify_statement(
            profile.config.connection.engine,
            &statement,
        ) {
            Ok(kind) => kind,
            Err(error) => {
                self.error = Some(error.to_string().into());
                cx.notify();
                return;
            }
        };
        match kind {
            DatabaseStatementKind::ReadOnly => self.run_read_query(profile_id, statement, cx),
            DatabaseStatementKind::Mutation => self.plan_sql_mutation(profile_id, statement, cx),
        }
    }

    fn run_read_query(&mut self, profile_id: String, statement: String, cx: &mut Context<Self>) {
        let Some(session) = self.current_session(cx) else {
            return;
        };
        let database = self.model.selected_database.clone();
        let lease = match self
            .model
            .begin(RequestLane::Query, DatabaseBinding::from_session(&session))
        {
            Ok(lease) => lease,
            Err(error) => {
                self.error = Some(error.to_string().into());
                cx.notify();
                return;
            }
        };
        self.start_task();
        self.notice = Some("正在执行只读查询…".into());
        let service = self.services.database().clone();
        let task = self.tokio.spawn(async move {
            service
                .query_profile(&session, &profile_id, database.as_deref(), &statement)
                .await
        });
        self.task_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        let binding = page.current_binding(cx);
                        if !page.model.accepts(&lease, binding.as_ref()) {
                            return;
                        }
                        page.finish_task();
                        match result {
                            Ok(Ok(result)) => {
                                page.notice = Some(
                                    format!(
                                        "查询完成：{} 行 · {} ms{}",
                                        result.rows.len(),
                                        result.execution_time_ms,
                                        if result.truncated {
                                            " · 结果已截断"
                                        } else {
                                            ""
                                        }
                                    )
                                    .into(),
                                );
                                page.model.result = Some(result);
                                page.error = None;
                            }
                            Ok(Err(error)) => {
                                page.error = Some(format!("查询失败：{error}").into())
                            }
                            Err(error) if error.is_cancelled() => return,
                            Err(error) => {
                                page.error = Some(format!("查询任务异常终止：{error}").into())
                            }
                        }
                        cx.notify();
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn plan_sql_mutation(&mut self, profile_id: String, statement: String, cx: &mut Context<Self>) {
        let Some(session) = self.current_session(cx) else {
            return;
        };
        let database = self.model.selected_database.clone();
        let verification = input_value(&self.verification_input, cx);
        let restore = input_value(&self.restore_input, cx);
        let summary_fragment: String = statement.chars().take(180).collect();
        let request = DatabaseMutationRequest {
            statement,
            verification_statement: (!verification.is_empty()).then_some(verification),
            verification_contains: None,
            restore_statement: (!restore.is_empty()).then_some(restore),
            summary: format!("执行数据库变更语句：{summary_fragment}"),
        };
        let lease = match self
            .model
            .begin(RequestLane::Plan, DatabaseBinding::from_session(&session))
        {
            Ok(lease) => lease,
            Err(error) => {
                self.error = Some(error.to_string().into());
                cx.notify();
                return;
            }
        };
        self.start_task();
        self.notice = Some("正在生成绑定目标与密文凭据的不可变 SQL 计划…".into());
        let service = self.services.database().clone();
        let task = self.tokio.spawn(async move {
            service
                .plan_mutation(&session, &profile_id, database.as_deref(), &request)
                .await
        });
        self.task_abort = Some(task.abort_handle());
        self.finish_plan_task(lease, task, cx);
    }

    fn plan_service(
        &mut self,
        engine: DatabaseEngine,
        action: DatabaseServiceAction,
        cx: &mut Context<Self>,
    ) {
        let Some(session) = self.current_session(cx) else {
            return;
        };
        let lease = match self
            .model
            .begin(RequestLane::Plan, DatabaseBinding::from_session(&session))
        {
            Ok(lease) => lease,
            Err(error) => {
                self.error = Some(error.to_string().into());
                cx.notify();
                return;
            }
        };
        self.start_task();
        let service = self.services.database().clone();
        let task = self
            .tokio
            .spawn(async move { service.plan_service_action(&session, engine, action).await });
        self.task_abort = Some(task.abort_handle());
        self.finish_plan_task(lease, task, cx);
    }

    fn plan_backup(&mut self, cx: &mut Context<Self>) {
        let Some(profile_id) = self.model.connected_profile_id.clone() else {
            self.error = Some("请先连接数据库".into());
            cx.notify();
            return;
        };
        let Some(database) = self.model.selected_database.clone() else {
            self.error = Some("请先选择要备份的数据库".into());
            cx.notify();
            return;
        };
        let Some(session) = self.current_session(cx) else {
            return;
        };
        let lease = match self
            .model
            .begin(RequestLane::Plan, DatabaseBinding::from_session(&session))
        {
            Ok(lease) => lease,
            Err(error) => {
                self.error = Some(error.to_string().into());
                cx.notify();
                return;
            }
        };
        self.start_task();
        self.notice = Some("正在分配唯一远端备份路径并生成验证计划…".into());
        let service = self.services.database().clone();
        let task = self
            .tokio
            .spawn(async move { service.plan_backup(&session, &profile_id, &database).await });
        self.task_abort = Some(task.abort_handle());
        self.finish_plan_task(lease, task, cx);
    }

    fn finish_plan_task(
        &mut self,
        lease: RequestLease,
        task: tokio::task::JoinHandle<CoreResult<DatabaseActionPlan>>,
        cx: &mut Context<Self>,
    ) {
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        let binding = page.current_binding(cx);
                        if !page.model.accepts(&lease, binding.as_ref()) {
                            return;
                        }
                        page.finish_task();
                        match result {
                            Ok(Ok(plan)) => {
                                page.notice =
                                    Some("计划已生成；请核对目标、摘要与恢复能力后确认。".into());
                                page.pending = Some(PendingAction::Remote { plan, lease });
                                page.error = None;
                            }
                            Ok(Err(error)) => {
                                page.error = Some(format!("生成操作计划失败：{error}").into())
                            }
                            Err(error) if error.is_cancelled() => return,
                            Err(error) => {
                                page.error = Some(format!("计划任务异常终止：{error}").into())
                            }
                        }
                        cx.notify();
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn plan_delete_profile(&mut self, profile_id: String, cx: &mut Context<Self>) {
        let profile_name = self
            .model
            .profiles
            .iter()
            .find(|profile| profile.config.id == profile_id)
            .map(|profile| profile.config.name.clone())
            .unwrap_or_else(|| profile_id.clone());
        match self.services.database().plan_delete_profile(&profile_id) {
            Ok(plan) => {
                self.pending = Some(PendingAction::DeleteProfile { plan, profile_name });
                self.notice = Some("删除计划已绑定当前配置快照；编辑后原确认会失效。".into());
                self.error = None;
            }
            Err(error) => self.error = Some(format!("无法生成删除计划：{error}").into()),
        }
        cx.notify();
    }

    fn approve_pending(&mut self, cx: &mut Context<Self>) {
        if self.mutation_running {
            return;
        }
        let Some(pending) = self.pending.take() else {
            return;
        };
        match pending {
            PendingAction::Remote { plan, lease } => {
                let binding = self.current_binding(cx);
                if !self.model.accepts(&lease, binding.as_ref()) {
                    self.error = Some("目标或页面生命周期已变化，原数据库计划已失效".into());
                    cx.notify();
                    return;
                }
                let Some(session) = self.current_session(cx) else {
                    self.error = Some("未连接可信 SSH 目标".into());
                    cx.notify();
                    return;
                };
                let mutation_lease = match self.model.begin(
                    RequestLane::Mutation,
                    DatabaseBinding::from_session(&session),
                ) {
                    Ok(lease) => lease,
                    Err(error) => {
                        self.error = Some(error.to_string().into());
                        cx.notify();
                        return;
                    }
                };
                let confirmation = DangerousConfirmation::approve(plan.definition());
                let service = self.services.database().clone();
                let journal = self.services.operation_journal().clone();
                self.mutation_running = true;
                self.notice = Some("操作正在执行；切换页面不会中断日志与读回验证。".into());
                let task = self.tokio.spawn(async move {
                    service
                        .execute_action(&session, plan, confirmation, &journal)
                        .await
                });
                cx.spawn(async move |page, cx| {
                    let result = task.await;
                    let _ = cx.update(|cx| {
                        if let Some(page) = page.upgrade() {
                            page.update(cx, |page, cx| {
                                page.finish_remote_action(mutation_lease, result, cx)
                            });
                        }
                    });
                })
                .detach();
            }
            PendingAction::DeleteProfile { plan, .. } => {
                let confirmation = DangerousConfirmation::approve(plan.definition());
                let service = self.services.database().clone();
                let journal = self.services.operation_journal().clone();
                self.mutation_running = true;
                let task = self.tokio.spawn(async move {
                    service
                        .execute_delete_profile(plan, confirmation, &journal)
                        .await
                });
                cx.spawn(async move |page, cx| {
                    let result = task.await;
                    let _ = cx.update(|cx| {
                        if let Some(page) = page.upgrade() {
                            page.update(cx, |page, cx| {
                                page.mutation_running = false;
                                match result {
                                    Ok(Ok(outcome)) if outcome.verification.passed => {
                                        page.notice = Some("数据库连接及其密文凭据已删除。".into());
                                        page.reset_runtime_parameters(true);
                                        page.reset_inventory();
                                        page.model.selected_profile_id = None;
                                        page.model.editing_profile_id = None;
                                        page.model.connected_profile_id = None;
                                        match page.services.database().profiles() {
                                            Ok(profiles) => page.model.profiles = profiles,
                                            Err(error) => {
                                                page.error = Some(
                                                    format!("重新加载连接失败：{error}").into(),
                                                )
                                            }
                                        }
                                    }
                                    Ok(Ok(outcome)) => {
                                        page.error = Some(outcome.verification.detail.into())
                                    }
                                    Ok(Err(error)) => {
                                        page.error = Some(format!("删除连接失败：{error}").into())
                                    }
                                    Err(error) => {
                                        page.error =
                                            Some(format!("删除任务异常终止：{error}").into())
                                    }
                                }
                                cx.notify();
                            });
                        }
                    });
                })
                .detach();
            }
        }
        cx.notify();
    }

    fn finish_remote_action(
        &mut self,
        lease: RequestLease,
        result: Result<CoreResult<DatabaseActionOutcome>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        self.mutation_running = false;
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            return;
        }
        match result {
            Ok(Ok(outcome)) if outcome.verified => {
                self.notice = Some(format!("操作已执行并验证：{}", outcome.detail).into());
                self.error = None;
                if self.model.tab == DatabaseTab::Operations {
                    self.refresh_stats(cx);
                }
            }
            Ok(Ok(outcome)) => {
                self.error = Some(
                    format!(
                        "验证未通过{}：{}",
                        if outcome.restored_after_failed_verification {
                            "，已执行恢复"
                        } else {
                            ""
                        },
                        outcome.detail
                    )
                    .into(),
                )
            }
            Ok(Err(error)) => self.error = Some(format!("数据库操作失败：{error}").into()),
            Err(error) => self.error = Some(format!("数据库操作任务异常终止：{error}").into()),
        }
        cx.notify();
    }

    fn cancel_pending(&mut self, cx: &mut Context<Self>) {
        self.pending = None;
        self.notice = Some("操作计划已取消，远端和便携存储均未发生变化。".into());
        cx.notify();
    }

    fn start_task(&mut self) {
        abort_task(&mut self.task_abort);
        self.busy = true;
        self.error = None;
    }

    fn finish_task(&mut self) {
        self.busy = false;
        self.task_abort = None;
    }

    fn render_connections(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let profile_rows = self.model.profiles.iter().map(|profile| {
            let profile_id = profile.config.id.clone();
            let edit_id = profile_id.clone();
            let delete_id = profile_id.clone();
            let selected = self.model.selected_profile_id.as_deref() == Some(&profile.config.id);
            div()
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
                .flex()
                .items_center()
                .justify_between()
                .gap_3()
                .child(
                    div()
                        .min_w_0()
                        .flex_1()
                        .child(div().font_semibold().child(profile.config.name.clone()))
                        .child(div().text_xs().text_color(tokens.muted).child(format!(
                                    "{} · {}:{} · {}{}",
                                    profile.config.connection.engine.label(),
                                    profile.config.connection.host,
                                    profile.config.connection.port,
                                    profile
                                        .config
                                        .connection
                                        .username
                                        .as_deref()
                                        .unwrap_or("匿名"),
                                    if profile.has_password { " · 已保存密码" } else { "" }
                                ))),
                )
                .child(
                    div()
                        .flex()
                        .gap_1()
                        .child(
                            crate::buttons::button(SharedString::from(format!(
                                "db-profile-use-{profile_id}"
                            )))
                            .label("选择")
                            .small()
                            .primary()
                            .on_click(cx.listener(
                                move |page, _, window, cx| {
                                    page.load_profile_editor(&profile_id, window, cx)
                                },
                            )),
                        )
                        .child(
                            crate::buttons::button(SharedString::from(format!(
                                "db-profile-edit-{edit_id}"
                            )))
                            .label("编辑")
                            .small()
                            .ghost()
                            .on_click(cx.listener(
                                move |page, _, window, cx| {
                                    page.load_profile_editor(&edit_id, window, cx)
                                },
                            )),
                        )
                        .child(
                            crate::buttons::button(SharedString::from(format!(
                                "db-profile-delete-{delete_id}"
                            )))
                            .label("删除")
                            .small()
                            .danger()
                            .disabled(self.mutation_running || self.pending.is_some())
                            .on_click(cx.listener(
                                move |page, _, _, cx| {
                                    page.plan_delete_profile(delete_id.clone(), cx)
                                },
                            )),
                        ),
                )
        });

        let detected = self.model.detected.iter().cloned().map(|database| {
            let start_engine = database.engine;
            let stop_engine = database.engine;
            let restart_engine = database.engine;
            let status_color = match database.status {
                DatabaseRuntimeStatus::Running => tokens.success,
                DatabaseRuntimeStatus::Stopped => tokens.warning,
                DatabaseRuntimeStatus::Unknown => tokens.muted,
            };
            div()
                .rounded_md()
                .border_1()
                .border_color(tokens.border)
                .bg(tokens.surface)
                .p_3()
                .flex()
                .items_center()
                .justify_between()
                .gap_3()
                .child(
                    div()
                        .min_w_0()
                        .flex_1()
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap_2()
                                .child(div().size(px(7.0)).rounded_full().bg(status_color))
                                .child(div().font_semibold().child(database.name)),
                        )
                        .child(div().text_xs().text_color(tokens.muted).child(format!(
                            "{} · 端口 {} · {} · {}",
                            database.version,
                            database.port,
                            database.data_directory,
                            match database.status {
                                DatabaseRuntimeStatus::Running => "运行中",
                                DatabaseRuntimeStatus::Stopped => "已停止",
                                DatabaseRuntimeStatus::Unknown => "状态未知",
                            }
                        ))),
                )
                .child(
                    div()
                        .flex()
                        .gap_1()
                        .child(
                            crate::buttons::button(SharedString::from(format!(
                                "db-service-start-{:?}",
                                database.engine
                            )))
                            .label("启动")
                            .small()
                            .disabled(self.busy || self.pending.is_some())
                            .on_click(cx.listener(
                                move |page, _, _, cx| {
                                    page.plan_service(
                                        start_engine,
                                        DatabaseServiceAction::Start,
                                        cx,
                                    )
                                },
                            )),
                        )
                        .child(
                            crate::buttons::button(SharedString::from(format!(
                                "db-service-stop-{:?}",
                                database.engine
                            )))
                            .label("停止")
                            .small()
                            .danger()
                            .disabled(self.busy || self.pending.is_some())
                            .on_click(cx.listener(
                                move |page, _, _, cx| {
                                    page.plan_service(stop_engine, DatabaseServiceAction::Stop, cx)
                                },
                            )),
                        )
                        .child(
                            crate::buttons::button(SharedString::from(format!(
                                "db-service-restart-{:?}",
                                database.engine
                            )))
                            .label("重启")
                            .small()
                            .disabled(self.busy || self.pending.is_some())
                            .on_click(cx.listener(
                                move |page, _, _, cx| {
                                    page.plan_service(
                                        restart_engine,
                                        DatabaseServiceAction::Restart,
                                        cx,
                                    )
                                },
                            )),
                        ),
                )
        });

        div()
            .size_full()
            .min_h_0()
            .flex()
            .gap_3()
            .child(
                div()
                    .w(px(460.0))
                    .min_h_0()
                    .rounded_lg()
                    .border_1()
                    .border_color(tokens.border)
                    .bg(tokens.surface)
                    .flex()
                    .flex_col()
                    .child(
                        div()
                            .px_4()
                            .py_3()
                            .border_b_1()
                            .border_color(tokens.border)
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(div().font_semibold().child("便携连接配置"))
                            .child(
                                crate::buttons::button("db-new-profile")
                                    .label("新建")
                                    .small()
                                    .on_click(cx.listener(|page, _, window, cx| {
                                        page.new_profile(window, cx)
                                    })),
                            ),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_h_0()
                            .overflow_y_scrollbar()
                            .p_3()
                            .flex()
                            .flex_col()
                            .gap_2()
                            .children(profile_rows),
                    ),
            )
            .child(
                div()
                    .flex_1()
                    .min_w_0()
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
                            .flex()
                            .flex_col()
                            .gap_3()
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .child(div().font_semibold().child("连接编辑器"))
                                    .child(
                                        div()
                                            .text_xs()
                                            .text_color(tokens.muted)
                                            .child("密码只写入 enc:v1 密文，不会回显"),
                                    ),
                            )
                            .child(div().flex().gap_2().children(
                                DatabaseEngine::ALL.into_iter().map(|engine| {
                                    crate::buttons::button(SharedString::from(format!(
                                        "db-engine-{engine:?}"
                                    )))
                                    .label(engine.label())
                                    .small()
                                    .ghost()
                                    .selected(self.model.selected_engine == engine)
                                    .on_click(cx.listener(move |page, _, window, cx| {
                                        page.set_engine(engine, window, cx)
                                    }))
                                }),
                            ))
                            .child(
                                div()
                                    .grid()
                                    .grid_cols(2)
                                    .gap_3()
                                    .child(input_field("名称", self.name_input.clone(), tokens))
                                    .child(input_field("主机", self.host_input.clone(), tokens))
                                    .child(input_field("端口", self.port_input.clone(), tokens))
                                    .child(input_field(
                                        "用户名",
                                        self.username_input.clone(),
                                        tokens,
                                    ))
                                    .child(input_field(
                                        "默认数据库",
                                        self.database_input.clone(),
                                        tokens,
                                    ))
                                    .child(input_field(
                                        "密码",
                                        self.password_input.clone(),
                                        tokens,
                                    )),
                            )
                            .child(
                                div()
                                    .flex()
                                    .justify_end()
                                    .gap_2()
                                    .child(
                                        crate::buttons::button("db-save-profile")
                                            .label("保存配置")
                                            .primary()
                                            .disabled(self.busy || self.mutation_running)
                                            .on_click(cx.listener(|page, _, window, cx| {
                                                page.save_profile(window, cx)
                                            })),
                                    )
                                    .child(
                                        crate::buttons::button("db-connect-profile")
                                            .label("验证并连接")
                                            .primary()
                                            .disabled(
                                                self.busy
                                                    || self.model.selected_profile_id.is_none(),
                                            )
                                            .on_click(cx.listener(|page, _, _, cx| {
                                                page.connect_selected(cx)
                                            })),
                                    ),
                            ),
                    )
                    .child(
                        div()
                            .rounded_lg()
                            .border_1()
                            .border_color(tokens.border)
                            .bg(tokens.surface)
                            .p_4()
                            .flex()
                            .flex_col()
                            .gap_2()
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .child(div().font_semibold().child("目标数据库运行时"))
                                    .child(
                                        crate::buttons::button("db-detect")
                                            .label("重新探测")
                                            .small()
                                            .disabled(self.busy)
                                            .on_click(
                                                cx.listener(|page, _, _, cx| page.detect(cx)),
                                            ),
                                    ),
                            )
                            .children(detected),
                    ),
            )
            .into_any_element()
    }

    fn render_database_selector(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        div()
            .flex()
            .items_center()
            .gap_2()
            .overflow_x_scrollbar()
            .child(
                div()
                    .flex_none()
                    .text_xs()
                    .text_color(tokens.muted)
                    .child("数据库"),
            )
            .children(self.model.databases.iter().map(|database| {
                let selected = self.model.selected_database.as_deref() == Some(database.as_str());
                let label = database.clone();
                let database_id = database.clone();
                crate::buttons::button(SharedString::from(format!("db-select-{database}")))
                    .label(label)
                    .small()
                    .ghost()
                    .selected(selected)
                    .on_click(cx.listener(move |page, _, _, cx| {
                        page.select_database(database_id.clone(), cx)
                    }))
            }))
            .into_any_element()
    }

    fn render_console(&mut self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        if !self.model.is_connected() {
            return disconnected_placeholder(tokens).into_any_element();
        }
        div()
            .size_full()
            .min_h_0()
            .flex()
            .flex_col()
            .gap_3()
            .child(self.render_database_selector(tokens, cx))
            .child(
                div()
                    .h(px(150.0))
                    .flex_none()
                    .rounded_lg()
                    .border_1()
                    .border_color(tokens.border)
                    .bg(tokens.surface)
                    .p_3()
                    .child(Input::new(&self.sql_input).h_full()),
            )
            .child(
                div()
                    .grid()
                    .grid_cols(2)
                    .gap_3()
                    .child(
                        div()
                            .h(px(82.0))
                            .rounded_md()
                            .border_1()
                            .border_color(tokens.border)
                            .bg(tokens.surface)
                            .p_2()
                            .child(Input::new(&self.verification_input).h_full()),
                    )
                    .child(
                        div()
                            .h(px(82.0))
                            .rounded_md()
                            .border_1()
                            .border_color(tokens.border)
                            .bg(tokens.surface)
                            .p_2()
                            .child(Input::new(&self.restore_input).h_full()),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .text_xs()
                            .text_color(tokens.muted)
                            .child("只读语句直接执行；其他语句必须生成计划并确认。验证与恢复语句均不会自动推断。"),
                    )
                    .child(
                        crate::buttons::button("db-execute-sql")
                            .label("执行")
                            .primary()
                            .disabled(self.busy || self.mutation_running || self.pending.is_some())
                            .on_click(cx.listener(|page, _, _, cx| page.execute_sql(cx))),
                    ),
            )
            .child(div().flex_1().min_h_0().child(self.render_result(tokens, cx)))
            .into_any_element()
    }

    fn render_result(&mut self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let Some(result) = &self.model.result else {
            return div()
                .size_full()
                .rounded_lg()
                .border_1()
                .border_color(tokens.border)
                .bg(tokens.surface)
                .flex()
                .items_center()
                .justify_center()
                .text_sm()
                .text_color(tokens.muted)
                .child("执行查询或选择表后，结果会显示在这里")
                .into_any_element();
        };
        let columns = result.columns.clone();
        let count = result.rows.len();
        let width = (columns.len().max(1) as f32 * 180.0).max(640.0);
        div()
            .size_full()
            .min_h_0()
            .rounded_lg()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .overflow_x_scrollbar()
            .child(
                div()
                    .w(px(width))
                    .h_full()
                    .min_h_0()
                    .flex()
                    .flex_col()
                    .child(
                        div()
                            .h(px(34.0))
                            .flex_none()
                            .flex()
                            .items_center()
                            .bg(tokens.surface_alt)
                            .border_b_1()
                            .border_color(tokens.border)
                            .children(columns.into_iter().map(|column| {
                                div()
                                    .w(px(180.0))
                                    .px_3()
                                    .text_xs()
                                    .font_semibold()
                                    .text_color(tokens.muted)
                                    .overflow_hidden()
                                    .child(column)
                            })),
                    )
                    .child(
                        uniform_list(
                            "database-query-results",
                            count,
                            cx.processor(move |page, range, _, cx| {
                                page.render_result_rows(range, tokens, cx)
                            }),
                        )
                        .flex_1()
                        .min_h_0()
                        .track_scroll(self.result_scroll.clone()),
                    ),
            )
            .into_any_element()
    }

    fn render_result_rows(
        &mut self,
        range: Range<usize>,
        tokens: ThemeTokens,
        _: &mut Context<Self>,
    ) -> Vec<AnyElement> {
        let Some(result) = &self.model.result else {
            return Vec::new();
        };
        let column_count = result.columns.len().max(1);
        range
            .filter_map(|index| {
                let row = result.rows.get(index)?;
                Some(
                    div()
                        .h(px(34.0))
                        .flex()
                        .items_center()
                        .border_b_1()
                        .border_color(tokens.border)
                        .children((0..column_count).map(|column| {
                            div()
                                .w(px(180.0))
                                .px_3()
                                .text_sm()
                                .overflow_hidden()
                                .child(row.get(column).cloned().unwrap_or_default())
                        }))
                        .into_any_element(),
                )
            })
            .collect()
    }

    fn render_browser(&mut self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        if !self.model.is_connected() {
            return disconnected_placeholder(tokens).into_any_element();
        }
        let table_rows = self
            .model
            .tables
            .iter()
            .map(|table| {
                let name = table.name.clone();
                let selected = self.model.selected_table.as_deref() == Some(&table.name);
                crate::buttons::button(SharedString::from(format!("db-table-{}", table.name)))
                    .label(format!(
                        "{}{}",
                        table.name,
                        table
                            .row_count
                            .map(|count| format!("  ·  {count}"))
                            .unwrap_or_default()
                    ))
                    .ghost()
                    .selected(selected)
                    .on_click(
                        cx.listener(move |page, _, _, cx| page.select_table(name.clone(), cx)),
                    )
            })
            .collect::<Vec<_>>();
        let columns = self.model.columns.iter().cloned().map(|column| {
            div()
                .h(px(34.0))
                .flex()
                .items_center()
                .gap_3()
                .px_3()
                .border_b_1()
                .border_color(tokens.border)
                .child(div().w(px(180.0)).font_semibold().child(column.name))
                .child(div().w(px(180.0)).child(column.data_type))
                .child(
                    div()
                        .w(px(90.0))
                        .text_color(if column.primary_key {
                            tokens.accent
                        } else {
                            tokens.muted
                        })
                        .child(if column.primary_key { "主键" } else { "—" }),
                )
                .child(
                    div()
                        .w(px(90.0))
                        .child(if column.nullable { "可空" } else { "非空" }),
                )
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .overflow_hidden()
                        .child(column.default_value.unwrap_or_else(|| "—".to_owned())),
                )
        });
        div()
            .size_full()
            .min_h_0()
            .flex()
            .flex_col()
            .gap_3()
            .child(self.render_database_selector(tokens, cx))
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .flex()
                    .gap_3()
                    .child(
                        div()
                            .w(px(260.0))
                            .min_h_0()
                            .rounded_lg()
                            .border_1()
                            .border_color(tokens.border)
                            .bg(tokens.surface)
                            .flex()
                            .flex_col()
                            .child(
                                div()
                                    .h(px(40.0))
                                    .px_3()
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .border_b_1()
                                    .border_color(tokens.border)
                                    .child(div().font_semibold().child("表 / 集合"))
                                    .child(
                                        crate::buttons::button("db-refresh-tables")
                                            .label("刷新")
                                            .small()
                                            .disabled(self.busy)
                                            .on_click(cx.listener(|page, _, _, cx| {
                                                page.refresh_tables(cx)
                                            })),
                                    ),
                            )
                            .child(
                                div()
                                    .flex_1()
                                    .min_h_0()
                                    .overflow_y_scrollbar()
                                    .p_2()
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .children(table_rows),
                            ),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .min_h_0()
                            .flex()
                            .flex_col()
                            .gap_3()
                            .child(
                                div()
                                    .max_h(px(230.0))
                                    .rounded_lg()
                                    .border_1()
                                    .border_color(tokens.border)
                                    .bg(tokens.surface)
                                    .overflow_y_scrollbar()
                                    .child(
                                        div()
                                            .h(px(34.0))
                                            .flex()
                                            .items_center()
                                            .gap_3()
                                            .px_3()
                                            .bg(tokens.surface_alt)
                                            .border_b_1()
                                            .border_color(tokens.border)
                                            .text_xs()
                                            .font_semibold()
                                            .text_color(tokens.muted)
                                            .child(div().w(px(180.0)).child("列"))
                                            .child(div().w(px(180.0)).child("类型"))
                                            .child(div().w(px(90.0)).child("键"))
                                            .child(div().w(px(90.0)).child("空值"))
                                            .child(div().flex_1().child("默认值")),
                                    )
                                    .children(columns),
                            )
                            .child(
                                div()
                                    .flex_1()
                                    .min_h_0()
                                    .child(self.render_result(tokens, cx)),
                            ),
                    ),
            )
            .into_any_element()
    }

    fn render_users(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        if !self.model.is_connected() {
            return disconnected_placeholder(tokens).into_any_element();
        }
        div()
            .size_full()
            .min_h_0()
            .rounded_lg()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .flex()
            .flex_col()
            .child(
                div()
                    .h(px(46.0))
                    .px_4()
                    .flex()
                    .items_center()
                    .justify_between()
                    .border_b_1()
                    .border_color(tokens.border)
                    .child(
                        div()
                            .child(div().font_semibold().child("数据库用户与权限摘要"))
                            .child(div().text_xs().text_color(tokens.muted).child(format!(
                                "{} 个用户；远端返回值按纯文本显示",
                                self.model.users.len()
                            ))),
                    )
                    .child(
                        crate::buttons::button("db-refresh-users")
                            .label("刷新")
                            .small()
                            .disabled(self.busy)
                            .on_click(cx.listener(|page, _, _, cx| page.refresh_users(cx))),
                    ),
            )
            .child(
                div()
                    .h(px(34.0))
                    .flex_none()
                    .flex()
                    .items_center()
                    .gap_3()
                    .px_4()
                    .bg(tokens.surface_alt)
                    .border_b_1()
                    .border_color(tokens.border)
                    .text_xs()
                    .font_semibold()
                    .text_color(tokens.muted)
                    .child(div().w(px(220.0)).child("用户"))
                    .child(div().w(px(180.0)).child("来源主机"))
                    .child(div().flex_1().child("权限 / 角色")),
            )
            .child(div().flex_1().min_h_0().overflow_y_scrollbar().children(
                self.model.users.iter().cloned().map(|user| {
                    div()
                        .min_h(px(38.0))
                        .flex()
                        .items_center()
                        .gap_3()
                        .px_4()
                        .border_b_1()
                        .border_color(tokens.border)
                        .child(div().w(px(220.0)).font_semibold().child(user.username))
                        .child(div().w(px(180.0)).child(user.host))
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .text_sm()
                                .text_color(tokens.muted)
                                .child(if user.privileges.is_empty() {
                                    "未返回权限详情".to_owned()
                                } else {
                                    user.privileges.join(", ")
                                }),
                        )
                }),
            ))
            .into_any_element()
    }

    fn render_runtime_parameters(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let selected_profile_id = self.model.selected_profile_id.as_deref();
        let selected_profile_engine = self
            .model
            .selected_profile()
            .map(|profile| profile.config.connection.engine);
        let password_blocked = self.model.runtime_password_blocked();
        let selected_mysql_choice = self
            .model
            .runtime_mysql_product
            .as_ref()
            .filter(|(profile_id, _)| Some(profile_id.as_str()) == selected_profile_id)
            .map(|(_, choice)| *choice);
        let profile_buttons = self
            .model
            .profiles
            .iter()
            .take(MAX_RUNTIME_PROFILE_BUTTONS)
            .enumerate()
            .map(|(index, profile)| {
                let profile_id = profile.config.id.clone();
                crate::buttons::button(SharedString::from(format!("db-runtime-profile-{index}")))
                    .label(profile.config.name.clone())
                    .small()
                    .ghost()
                    .selected(selected_profile_id == Some(profile.config.id.as_str()))
                    .on_click(cx.listener(move |page, _, window, cx| {
                        page.load_profile_editor(&profile_id, window, cx)
                    }))
            });
        let product_control =
            match selected_profile_engine {
                Some(DatabaseEngine::Mysql) => div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(div().text_xs().text_color(tokens.muted).child("显式产品"))
                    .children(MysqlRuntimeProduct::ALL.into_iter().map(|choice| {
                        crate::buttons::button(SharedString::from(format!(
                            "db-runtime-product-{choice:?}"
                        )))
                        .label(choice.label())
                        .small()
                        .ghost()
                        .selected(selected_mysql_choice == Some(choice))
                        .disabled(self.runtime_busy || self.inventory_busy)
                        .on_click(cx.listener(move |page, _, _, cx| {
                            page.set_runtime_mysql_product(choice, cx)
                        }))
                    }))
                    .into_any_element(),
                Some(DatabaseEngine::Postgresql) => div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(div().text_xs().text_color(tokens.muted).child("固定产品"))
                    .child(
                        crate::buttons::button("db-runtime-product-postgresql")
                            .label("PostgreSQL")
                            .small()
                            .selected(true)
                            .disabled(true),
                    )
                    .into_any_element(),
                Some(engine) => div()
                    .text_sm()
                    .text_color(tokens.muted)
                    .child(format!(
                        "{} 没有已审核的只读运行时参数方案，此入口已禁用。",
                        engine.label()
                    ))
                    .into_any_element(),
                None => div()
                    .text_sm()
                    .text_color(tokens.muted)
                    .child("请先选择一个已保存的数据库连接。")
                    .into_any_element(),
            };
        let availability = self.model.runtime_product_availability();
        let read_disabled = self.busy
            || self.runtime_busy
            || password_blocked
            || !matches!(availability, RuntimeProductAvailability::Ready(_))
            || self.shared.read(cx).active_ssh.is_none();
        let snapshot = self.model.displayed_runtime_parameters();
        let effective_status = if self.model.runtime_parameters_status
            == RuntimeParametersStatus::Ready
            && snapshot.is_none()
        {
            RuntimeParametersStatus::NotRun
        } else {
            self.model.runtime_parameters_status
        };
        let status_color = match effective_status {
            RuntimeParametersStatus::NotRun => tokens.muted,
            RuntimeParametersStatus::Loading => tokens.accent,
            RuntimeParametersStatus::Ready => tokens.success,
            RuntimeParametersStatus::Failed => tokens.danger,
        };
        let filter = bounded_filter_query(&input_value(&self.runtime_filter_input, cx));
        let normalized_filter = filter.to_lowercase();
        let runtime_rows = snapshot
            .map(|snapshot| snapshot.document().rows())
            .unwrap_or_default();
        let matches_filter = |name: &str| {
            normalized_filter.is_empty() || name.to_lowercase().contains(&normalized_filter)
        };
        let matching_rows = runtime_rows
            .iter()
            .filter(|row| matches_filter(row.name()))
            .count();
        let table_rows = runtime_rows
            .iter()
            .filter(|row| matches_filter(row.name()))
            .take(MAX_RUNTIME_PARAMETER_RENDER_ROWS)
            .enumerate()
            .map(|(index, row)| {
                let name = bounded_plain_text(row.name(), MAX_RUNTIME_PARAMETER_CELL_CHARS);
                let value = runtime_value_label(row.value());
                let scope = runtime_scope_label(row.scope()).to_owned();
                let apply = runtime_apply_label(row.apply());
                let source = optional_runtime_cell(row.source());
                let pending = runtime_pending_label(row.pending_restart()).to_owned();
                let minimum = optional_runtime_cell(row.minimum());
                let maximum = optional_runtime_cell(row.maximum());
                let enum_values = runtime_enum_label(row.enum_values());
                div()
                    .id(SharedString::from(format!("db-runtime-row-{index}")))
                    .min_w(px(1680.0))
                    .min_h(px(38.0))
                    .grid()
                    .grid_cols(9)
                    .items_center()
                    .border_b_1()
                    .border_color(tokens.border)
                    .children([
                        runtime_table_cell(name, tokens),
                        runtime_table_cell(value, tokens),
                        runtime_table_cell(scope, tokens),
                        runtime_table_cell(apply, tokens),
                        runtime_table_cell(source, tokens),
                        runtime_table_cell(pending, tokens),
                        runtime_table_cell(minimum, tokens),
                        runtime_table_cell(maximum, tokens),
                        runtime_table_cell(enum_values, tokens),
                    ])
            })
            .collect::<Vec<_>>();
        let row_summary = if snapshot.is_some() {
            format!(
                "共 {} 条，筛选命中 {} 条，当前最多渲染 {} 条",
                runtime_rows.len(),
                matching_rows,
                MAX_RUNTIME_PARAMETER_RENDER_ROWS
            )
        } else {
            "尚未应用实机读取结果。".to_owned()
        };

        div()
            .size_full()
            .min_h_0()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex_none()
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
                            .justify_between()
                            .gap_3()
                            .child(
                                div()
                                    .child(div().font_semibold().child("运行时参数（只读）"))
                                    .child(
                                        div()
                                            .text_sm()
                                            .text_color(tokens.muted)
                                            .child("仅调用 core 内已审核的固定读取方案；不会接受任意 SQL，也不提供修改或部署入口。"),
                                    ),
                            )
                            .child(
                                div()
                                    .rounded_md()
                                    .border_1()
                                    .border_color(status_color)
                                    .px_3()
                                    .py_1()
                                    .text_sm()
                                    .font_semibold()
                                    .text_color(status_color)
                                    .child(effective_status.label()),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .overflow_x_scrollbar()
                            .child(
                                div()
                                    .flex_none()
                                    .text_xs()
                                    .text_color(tokens.muted)
                                    .child("已有连接"),
                            )
                            .children(profile_buttons),
                    )
                    .when(
                        self.model.profiles.len() > MAX_RUNTIME_PROFILE_BUTTONS,
                        |view| {
                            view.child(
                                div()
                                    .text_xs()
                                    .text_color(tokens.warning)
                                    .child(format!(
                                        "连接列表仅显示前 {MAX_RUNTIME_PROFILE_BUTTONS} 项。"
                                    )),
                            )
                        },
                    )
                    .child(product_control)
                    .when(password_blocked, |view| {
                        view.child(
                            div()
                                .rounded_md()
                                .border_1()
                                .border_color(tokens.warning)
                                .px_3()
                                .py_2()
                                .text_sm()
                                .text_color(tokens.warning)
                                .child("PASSWORD_BLOCKED：密码连接不会把凭据交给远端 mysql/psql；需等待 SSH 隧道内原生数据库协议后启用。"),
                        )
                    })
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_end()
                            .gap_2()
                            .when(self.runtime_busy, |view| {
                                view.child(
                                    crate::buttons::button("db-runtime-cancel")
                                        .label("取消读取")
                                        .small()
                                        .on_click(cx.listener(|page, _, _, cx| {
                                            page.cancel_runtime_parameters(cx)
                                        })),
                                )
                            })
                            .child(
                                crate::buttons::button("db-runtime-read")
                                    .label("读取只读参数")
                                    .primary()
                                    .disabled(read_disabled)
                                    .on_click(cx.listener(|page, _, _, cx| {
                                        page.read_runtime_parameters(cx)
                                    })),
                            ),
                    ),
            )
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .rounded_lg()
                    .border_1()
                    .border_color(tokens.border)
                    .bg(tokens.surface)
                    .flex()
                    .flex_col()
                    .child(
                        div()
                            .flex_none()
                            .p_3()
                            .border_b_1()
                            .border_color(tokens.border)
                            .flex()
                            .items_center()
                            .justify_between()
                            .gap_3()
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(tokens.muted)
                                    .child(row_summary),
                            )
                            .child(
                                div()
                                    .w(px(320.0))
                                    .child(Input::new(&self.runtime_filter_input)),
                            ),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_h_0()
                            .overflow_scrollbar()
                            .child(
                                div()
                                    .min_w(px(1680.0))
                                    .flex()
                                    .flex_col()
                                    .child(
                                        div()
                                            .min_h(px(36.0))
                                            .grid()
                                            .grid_cols(9)
                                            .items_center()
                                            .bg(tokens.surface_alt)
                                            .border_b_1()
                                            .border_color(tokens.border)
                                            .children(
                                                [
                                                    "name", "value", "scope", "apply", "source",
                                                    "pending", "min", "max", "enum",
                                                ]
                                                .into_iter()
                                                .map(|label| {
                                                    runtime_table_header_cell(label, tokens)
                                                }),
                                            ),
                                    )
                                    .children(table_rows)
                                    .when(runtime_rows.is_empty(), |view| {
                                        view.child(
                                            div()
                                                .min_h(px(120.0))
                                                .flex()
                                                .items_center()
                                                .justify_center()
                                                .text_sm()
                                                .text_color(tokens.muted)
                                                .child(if effective_status
                                                    == RuntimeParametersStatus::NotRun
                                                {
                                                    "NOT_RUN：选择现有连接与产品后手动读取。"
                                                } else {
                                                    "当前结果没有可显示的运行时参数。"
                                                }),
                                        )
                                    }),
                            ),
                    ),
            )
            .into_any_element()
    }

    fn render_database_config_inventory(
        &self,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let selected_profile_id = self.model.selected_profile_id.as_deref();
        let selected_profile_engine = self
            .model
            .selected_profile()
            .map(|profile| profile.config.connection.engine);
        let password_blocked = self.model.runtime_password_blocked();
        let selected_mysql_choice = self
            .model
            .runtime_mysql_product
            .as_ref()
            .filter(|(profile_id, _)| Some(profile_id.as_str()) == selected_profile_id)
            .map(|(_, choice)| *choice);
        let profile_buttons = self
            .model
            .profiles
            .iter()
            .take(MAX_RUNTIME_PROFILE_BUTTONS)
            .enumerate()
            .map(|(index, profile)| {
                let profile_id = profile.config.id.clone();
                crate::buttons::button(SharedString::from(format!("db-inventory-profile-{index}")))
                    .label(profile.config.name.clone())
                    .small()
                    .ghost()
                    .selected(selected_profile_id == Some(profile.config.id.as_str()))
                    .on_click(cx.listener(move |page, _, window, cx| {
                        page.load_profile_editor(&profile_id, window, cx)
                    }))
            });
        let product_control =
            match selected_profile_engine {
                Some(DatabaseEngine::Mysql) => div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(div().text_xs().text_color(tokens.muted).child("显式产品"))
                    .children(MysqlRuntimeProduct::ALL.into_iter().map(|choice| {
                        crate::buttons::button(SharedString::from(format!(
                            "db-inventory-product-{choice:?}"
                        )))
                        .label(choice.label())
                        .small()
                        .ghost()
                        .selected(selected_mysql_choice == Some(choice))
                        .disabled(self.runtime_busy || self.inventory_busy)
                        .on_click(cx.listener(move |page, _, _, cx| {
                            page.set_runtime_mysql_product(choice, cx)
                        }))
                    }))
                    .into_any_element(),
                Some(engine) => div()
                    .text_sm()
                    .text_color(tokens.muted)
                    .child(format!(
                        "{} 没有已审核的插件 / 组件清单方案，此入口已禁用。",
                        engine.label()
                    ))
                    .into_any_element(),
                None => div()
                    .text_sm()
                    .text_color(tokens.muted)
                    .child("请先选择一个已保存的数据库连接。")
                    .into_any_element(),
            };
        let maria_component_unsupported =
            selected_mysql_choice == Some(MysqlRuntimeProduct::MariaDb);
        let surface_control = div()
            .flex()
            .items_center()
            .gap_2()
            .child(div().text_xs().text_color(tokens.muted).child("固定范围"))
            .children(
                [
                    DatabaseConfigInventorySurface::PluginRegistry,
                    DatabaseConfigInventorySurface::ComponentRegistry,
                ]
                .into_iter()
                .map(|surface| {
                    let unsupported = maria_component_unsupported
                        && surface == DatabaseConfigInventorySurface::ComponentRegistry;
                    crate::buttons::button(SharedString::from(format!(
                        "db-inventory-surface-{surface:?}"
                    )))
                    .label(inventory_surface_label(surface))
                    .small()
                    .ghost()
                    .selected(self.model.inventory_surface == surface)
                    .disabled(self.inventory_busy || self.runtime_busy || unsupported)
                    .on_click(
                        cx.listener(move |page, _, _, cx| page.set_inventory_surface(surface, cx)),
                    )
                }),
            );
        let availability = self.model.inventory_availability();
        let read_disabled = self.busy
            || self.runtime_busy
            || self.inventory_busy
            || password_blocked
            || !matches!(availability, InventoryAvailability::Ready { .. })
            || self.shared.read(cx).active_ssh.is_none();
        let snapshot = self.model.displayed_inventory();
        let effective_status =
            if self.model.inventory_status == InventoryStatus::Ready && snapshot.is_none() {
                InventoryStatus::NotRun
            } else {
                self.model.inventory_status
            };
        let status_color = match effective_status {
            InventoryStatus::NotRun => tokens.muted,
            InventoryStatus::Loading => tokens.accent,
            InventoryStatus::Ready => tokens.success,
            InventoryStatus::Failed => tokens.danger,
        };
        let rows = snapshot
            .map(|snapshot| inventory_document_rows(snapshot.document()))
            .unwrap_or_default();
        let total_rows = snapshot.map_or(0, |snapshot| snapshot.document().len());
        let table_rows = rows
            .into_iter()
            .take(MAX_INVENTORY_RENDER_ROWS)
            .enumerate()
            .map(|(index, cells)| inventory_table_row(index, cells, tokens))
            .collect::<Vec<_>>();
        let row_summary = snapshot.map_or_else(
            || "尚未应用实机读取结果。".to_owned(),
            |snapshot| {
                format!(
                    "{} · {} · 共 {total_rows} 条，当前最多渲染 {MAX_INVENTORY_RENDER_ROWS} 条",
                    database_config_product_label(snapshot.product()),
                    inventory_surface_label(self.model.inventory_surface)
                )
            },
        );
        let unsupported_message = match availability {
            InventoryAvailability::UnsupportedSurface { product, surface } => Some(format!(
                "UNSUPPORTED：{} 没有 {} 读取方案；不会启动 SSH / SQL 清单任务。",
                database_config_product_label(product),
                inventory_surface_label(surface)
            )),
            _ => None,
        };

        div()
            .size_full()
            .min_h_0()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex_none()
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
                            .justify_between()
                            .gap_3()
                            .child(
                                div()
                                    .child(div().font_semibold().child("插件 / 组件清单（只读）"))
                                    .child(
                                        div()
                                            .text_sm()
                                            .text_color(tokens.muted)
                                            .child("只调用 core 的固定产品、固定范围读取；本页没有 SQL 输入、复制、导出或修改入口。"),
                                    ),
                            )
                            .child(
                                div()
                                    .rounded_md()
                                    .border_1()
                                    .border_color(status_color)
                                    .px_3()
                                    .py_1()
                                    .text_sm()
                                    .font_semibold()
                                    .text_color(status_color)
                                    .child(effective_status.label()),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .overflow_x_scrollbar()
                            .child(
                                div()
                                    .flex_none()
                                    .text_xs()
                                    .text_color(tokens.muted)
                                    .child("已有连接"),
                            )
                            .children(profile_buttons),
                    )
                    .when(
                        self.model.profiles.len() > MAX_RUNTIME_PROFILE_BUTTONS,
                        |view| {
                            view.child(
                                div()
                                    .text_xs()
                                    .text_color(tokens.warning)
                                    .child(format!(
                                        "连接列表仅显示前 {MAX_RUNTIME_PROFILE_BUTTONS} 项。"
                                    )),
                            )
                        },
                    )
                    .child(product_control)
                    .child(surface_control)
                    .when_some(unsupported_message, |view, message| {
                        view.child(
                            div()
                                .rounded_md()
                                .border_1()
                                .border_color(tokens.warning)
                                .px_3()
                                .py_2()
                                .text_sm()
                                .text_color(tokens.warning)
                                .child(message),
                        )
                    })
                    .when(password_blocked, |view| {
                        view.child(
                            div()
                                .rounded_md()
                                .border_1()
                                .border_color(tokens.warning)
                                .px_3()
                                .py_2()
                                .text_sm()
                                .text_color(tokens.warning)
                                .child("PASSWORD_BLOCKED：控件已禁用；core 合同保证在首个 SSH 命令之前拒绝密码 profile。"),
                        )
                    })
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_end()
                            .gap_2()
                            .when(self.inventory_busy, |view| {
                                view.child(
                                    crate::buttons::button("db-inventory-cancel")
                                        .label("取消读取")
                                        .small()
                                        .on_click(cx.listener(|page, _, _, cx| {
                                            page.cancel_inventory(cx)
                                        })),
                                )
                            })
                            .child(
                                crate::buttons::button("db-inventory-read")
                                    .label("读取只读清单")
                                    .primary()
                                    .disabled(read_disabled)
                                    .on_click(cx.listener(|page, _, _, cx| {
                                        page.read_database_config_inventory(cx)
                                    })),
                            ),
                    ),
            )
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .rounded_lg()
                    .border_1()
                    .border_color(tokens.border)
                    .bg(tokens.surface)
                    .flex()
                    .flex_col()
                    .child(
                        div()
                            .flex_none()
                            .p_3()
                            .border_b_1()
                            .border_color(tokens.border)
                            .text_xs()
                            .text_color(tokens.muted)
                            .child(row_summary),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_h_0()
                            .overflow_scrollbar()
                            .child(
                                div()
                                    .min_w(px(1120.0))
                                    .flex()
                                    .flex_col()
                                    .child(
                                        div()
                                            .min_h(px(36.0))
                                            .grid()
                                            .grid_cols(7)
                                            .items_center()
                                            .bg(tokens.surface_alt)
                                            .border_b_1()
                                            .border_color(tokens.border)
                                            .children(
                                                [
                                                    "row_kind",
                                                    "name / component_urn",
                                                    "status",
                                                    "plugin_type",
                                                    "library",
                                                    "load_option",
                                                    "maturity",
                                                ]
                                                .into_iter()
                                                .map(|label| {
                                                    runtime_table_header_cell(label, tokens)
                                                }),
                                            ),
                                    )
                                    .children(table_rows)
                                    .when(total_rows == 0, |view| {
                                        view.child(
                                            div()
                                                .min_h(px(120.0))
                                                .flex()
                                                .items_center()
                                                .justify_center()
                                                .text_sm()
                                                .text_color(tokens.muted)
                                                .child(if effective_status == InventoryStatus::NotRun {
                                                    "NOT_RUN：选择连接、产品与固定范围后手动读取。"
                                                } else {
                                                    "当前已复验清单为空。"
                                                }),
                                        )
                                    }),
                            ),
                    ),
            )
            .into_any_element()
    }

    fn render_operations(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        if !self.model.is_connected() {
            return disconnected_placeholder(tokens).into_any_element();
        }
        let stats = self.model.stats.clone().unwrap_or_default();
        let cards = [
            ("运行时间", stats.uptime),
            ("累计连接", stats.total_connections.to_string()),
            ("活动连接", stats.active_connections.to_string()),
            ("数据规模", stats.total_size),
            ("慢查询", stats.slow_queries.to_string()),
        ];
        div()
            .size_full()
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
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(div().font_semibold().child("运行统计"))
                            .child(
                                crate::buttons::button("db-refresh-stats")
                                    .label("刷新")
                                    .small()
                                    .disabled(self.busy)
                                    .on_click(cx.listener(|page, _, _, cx| page.refresh_stats(cx))),
                            ),
                    )
                    .child(
                        div()
                            .grid()
                            .grid_cols(5)
                            .gap_3()
                            .children(cards.into_iter().map(|(label, value)| {
                                div()
                                    .rounded_md()
                                    .bg(tokens.surface_alt)
                                    .p_3()
                                    .child(
                                        div()
                                            .text_xs()
                                            .text_color(tokens.muted)
                                            .child(label),
                                    )
                                    .child(div().mt_1().font_semibold().child(value))
                            })),
                    )
                    .when(!stats.extra.is_empty(), |view| {
                        view.child(
                            div()
                                .text_xs()
                                .text_color(tokens.muted)
                                .child(
                                    stats
                                        .extra
                                        .iter()
                                        .map(|(key, value)| format!("{key}: {value}"))
                                        .collect::<Vec<_>>()
                                        .join(" · "),
                                ),
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
                    .justify_between()
                    .gap_4()
                    .child(
                        div()
                            .child(div().font_semibold().child("远端备份"))
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(tokens.muted)
                                    .child("为当前数据库分配唯一 /tmp 路径，完成后读回文件大小与 SHA-256（Redis 验证 LASTSAVE）。"),
                            ),
                    )
                    .child(
                        crate::buttons::button("db-plan-backup")
                            .label("计划备份")
                            .primary()
                            .disabled(
                                self.busy
                                    || self.pending.is_some()
                                    || self.model.selected_database.is_none(),
                            )
                            .on_click(cx.listener(|page, _, _, cx| page.plan_backup(cx))),
                    ),
            )
            .child(
                div()
                    .rounded_lg()
                    .border_1()
                    .border_color(tokens.warning)
                    .bg(tokens.surface)
                    .p_4()
                    .child(div().font_semibold().child("服务控制安全边界"))
                    .child(
                        div()
                            .mt_1()
                            .text_sm()
                            .text_color(tokens.muted)
                            .child("启动、停止与重启必须重新读取确认前状态；执行后用 systemd 状态读回验证，必要时恢复原状态。入口位于“连接”页的探测结果。"),
                    ),
            )
            .into_any_element()
    }
}

impl Render for DatabasePage {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens = self.shared.read(cx).theme.tokens();
        let connected_label = self
            .model
            .connected_profile_id
            .as_ref()
            .and_then(|id| {
                self.model
                    .profiles
                    .iter()
                    .find(|profile| &profile.config.id == id)
            })
            .map(|profile| profile.config.name.clone());
        let pending_summary = self.pending.as_ref().map(|pending| {
            let definition = pending.definition();
            let suffix = match pending {
                PendingAction::Remote { .. } => format!(
                    "目标 {} · epoch {}",
                    definition.target.identity.as_str(),
                    definition.target.generation
                ),
                PendingAction::DeleteProfile { profile_name, .. } => {
                    format!("本地连接：{profile_name}")
                }
            };
            format!("{} · {suffix}", definition.summary)
        });
        let content = match self.model.tab {
            DatabaseTab::Connections => self.render_connections(tokens, cx),
            DatabaseTab::Console => self.render_console(tokens, cx),
            DatabaseTab::Browser => self.render_browser(tokens, cx),
            DatabaseTab::RuntimeParameters => self.render_runtime_parameters(tokens, cx),
            DatabaseTab::Inventory => self.render_database_config_inventory(tokens, cx),
            DatabaseTab::Users => self.render_users(tokens, cx),
            DatabaseTab::Operations => self.render_operations(tokens, cx),
        };
        div()
            .size_full()
            .min_h_0()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex_none()
                    .rounded_lg()
                    .border_1()
                    .border_color(tokens.border)
                    .bg(tokens.surface)
                    .px_4()
                    .py_3()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .child(div().text_lg().font_semibold().child("数据库运维"))
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(tokens.muted)
                                    .child("连接凭据密文保存；只读查询与危险操作使用不同的强类型执行路径。"),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .when_some(connected_label, |view, label| {
                                view.child(
                                    div()
                                        .rounded_md()
                                        .bg(tokens.surface_alt)
                                        .px_3()
                                        .py_1()
                                        .text_sm()
                                        .text_color(tokens.success)
                                        .child(format!("已连接 · {label}")),
                                )
                            })
                            .when(self.model.is_connected(), |view| {
                                view.child(
                                    crate::buttons::button("db-disconnect")
                                        .label("断开")
                                        .small()
                                        .on_click(cx.listener(|page, _, _, cx| page.disconnect(cx))),
                                )
                            }),
                    ),
            )
            .child(
                div()
                    .h(px(38.0))
                    .flex_none()
                    .flex()
                    .items_center()
                    .gap_2()
                    .children(DatabaseTab::ALL.into_iter().map(|tab| {
                        crate::buttons::button(SharedString::from(format!("database-tab-{tab:?}")))
                            .label(tab.label())
                            .small()
                            .ghost()
                            .selected(self.model.tab == tab)
                            .on_click(cx.listener(move |page, _, _, cx| page.set_tab(tab, cx)))
                    })),
            )
            .when_some(self.error.clone(), |view, error| {
                view.child(message_banner(error, tokens.danger, tokens))
            })
            .when_some(self.notice.clone(), |view, notice| {
                view.child(message_banner(notice, tokens.accent, tokens))
            })
            .child(div().flex_1().min_h_0().child(content))
            .when_some(pending_summary, |view, summary| {
                view.child(
                    div()
                        .flex_none()
                        .rounded_lg()
                        .border_1()
                        .border_color(tokens.danger)
                        .bg(tokens.surface)
                        .p_3()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap_4()
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .child(
                                    div()
                                        .font_semibold()
                                        .text_color(tokens.danger)
                                        .child("危险操作确认"),
                                )
                                .child(div().text_sm().child(summary))
                                .child(
                                    div()
                                        .text_xs()
                                        .text_color(tokens.muted)
                                        .child("确认只对该计划 ID、配置快照与目标 epoch 有效；状态变化会拒绝执行。"),
                                ),
                        )
                        .child(
                            div()
                                .flex()
                                .gap_2()
                                .child(
                                    crate::buttons::button("database-plan-cancel")
                                        .label("取消")
                                        .small()
                                        .on_click(cx.listener(|page, _, _, cx| {
                                            page.cancel_pending(cx)
                                        })),
                                )
                                .child(
                                    crate::buttons::button("database-plan-approve")
                                        .label("确认执行")
                                        .danger()
                                        .small()
                                        .disabled(self.mutation_running)
                                        .on_click(cx.listener(|page, _, _, cx| {
                                            page.approve_pending(cx)
                                        })),
                                ),
                        ),
                )
            })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InventoryValuePresence {
    Null,
    Present,
}

const fn database_config_product_label(product: DatabaseConfigProduct) -> &'static str {
    match product {
        DatabaseConfigProduct::MySql => "MySQL",
        DatabaseConfigProduct::MariaDb => "MariaDB",
        _ => "UNSUPPORTED",
    }
}

const fn inventory_surface_label(surface: DatabaseConfigInventorySurface) -> &'static str {
    match surface {
        DatabaseConfigInventorySurface::PluginRegistry => "plugin registry",
        DatabaseConfigInventorySurface::ComponentRegistry => "component registry",
    }
}

fn inventory_document_matches_surface(
    document: &DatabaseConfigInventoryDocument,
    surface: DatabaseConfigInventorySurface,
) -> bool {
    matches!(
        (document, surface),
        (
            DatabaseConfigInventoryDocument::Plugins(_),
            DatabaseConfigInventorySurface::PluginRegistry
        ) | (
            DatabaseConfigInventoryDocument::Components(_),
            DatabaseConfigInventorySurface::ComponentRegistry
        )
    )
}

fn inventory_value_display(public_value: Option<&str>, presence: InventoryValuePresence) -> String {
    match public_value {
        Some("") => "[EMPTY]".to_owned(),
        Some(value) => bounded_plain_text(value, MAX_INVENTORY_CELL_CHARS),
        None => format!(
            "[REDACTED] · {}",
            match presence {
                InventoryValuePresence::Null => "NULL",
                InventoryValuePresence::Present => "PRESENT",
            }
        ),
    }
}

fn inventory_text_display(value: &DatabaseConfigInventoryText) -> String {
    // No raw or Debug fallback is permitted: public_value is the only text channel.
    inventory_value_display(value.public_value(), InventoryValuePresence::Present)
}

fn optional_inventory_text_display(value: Option<&DatabaseConfigInventoryText>) -> String {
    value.map_or_else(
        || inventory_value_display(None, InventoryValuePresence::Null),
        inventory_text_display,
    )
}

fn inventory_plugin_status_label(status: DatabaseConfigPluginStatus) -> String {
    match status {
        DatabaseConfigPluginStatus::Active => "ACTIVE".to_owned(),
        DatabaseConfigPluginStatus::Inactive => "INACTIVE".to_owned(),
        DatabaseConfigPluginStatus::Disabled => "DISABLED".to_owned(),
        DatabaseConfigPluginStatus::Deleting => "DELETING".to_owned(),
        DatabaseConfigPluginStatus::Deleted => "DELETED".to_owned(),
        DatabaseConfigPluginStatus::Unrecognized => {
            inventory_value_display(None, InventoryValuePresence::Present)
        }
    }
}

fn inventory_plugin_load_option_label(option: DatabaseConfigPluginLoadOption) -> String {
    match option {
        DatabaseConfigPluginLoadOption::Off => "OFF".to_owned(),
        DatabaseConfigPluginLoadOption::On => "ON".to_owned(),
        DatabaseConfigPluginLoadOption::Force => "FORCE".to_owned(),
        DatabaseConfigPluginLoadOption::ForcePlusPermanent => "FORCE_PLUS_PERMANENT".to_owned(),
        DatabaseConfigPluginLoadOption::Unrecognized => {
            inventory_value_display(None, InventoryValuePresence::Present)
        }
    }
}

fn inventory_plugin_maturity_label(maturity: Option<DatabaseConfigPluginMaturity>) -> String {
    match maturity {
        None => inventory_value_display(None, InventoryValuePresence::Null),
        Some(DatabaseConfigPluginMaturity::VendorUnknown) => "VENDOR_UNKNOWN".to_owned(),
        Some(DatabaseConfigPluginMaturity::Experimental) => "EXPERIMENTAL".to_owned(),
        Some(DatabaseConfigPluginMaturity::Alpha) => "ALPHA".to_owned(),
        Some(DatabaseConfigPluginMaturity::Beta) => "BETA".to_owned(),
        Some(DatabaseConfigPluginMaturity::Gamma) => "GAMMA".to_owned(),
        Some(DatabaseConfigPluginMaturity::Stable) => "STABLE".to_owned(),
        Some(DatabaseConfigPluginMaturity::Unrecognized) => {
            inventory_value_display(None, InventoryValuePresence::Present)
        }
    }
}

fn inventory_plugin_row_cells(row: &DatabaseConfigPluginInventoryRow) -> [String; 7] {
    match row {
        DatabaseConfigPluginInventoryRow::Loaded(plugin) => [
            "LOADED".to_owned(),
            inventory_text_display(plugin.name()),
            inventory_plugin_status_label(plugin.status()),
            inventory_text_display(plugin.plugin_type()),
            optional_inventory_text_display(plugin.library()),
            inventory_plugin_load_option_label(plugin.load_option()),
            inventory_plugin_maturity_label(plugin.maturity()),
        ],
        DatabaseConfigPluginInventoryRow::Registered(plugin) => [
            "REGISTERED".to_owned(),
            inventory_text_display(plugin.name()),
            "N/A".to_owned(),
            "N/A".to_owned(),
            inventory_text_display(plugin.library()),
            "N/A".to_owned(),
            "N/A".to_owned(),
        ],
    }
}

fn inventory_component_row_cells(component: &DatabaseConfigComponentRegistration) -> [String; 7] {
    [
        "COMPONENT".to_owned(),
        inventory_text_display(component.urn()),
        "N/A".to_owned(),
        "N/A".to_owned(),
        "N/A".to_owned(),
        "N/A".to_owned(),
        "N/A".to_owned(),
    ]
}

fn inventory_document_rows(document: &DatabaseConfigInventoryDocument) -> Vec<[String; 7]> {
    match document {
        DatabaseConfigInventoryDocument::Plugins(inventory) => inventory
            .rows()
            .iter()
            .take(MAX_INVENTORY_RENDER_ROWS)
            .map(inventory_plugin_row_cells)
            .collect(),
        DatabaseConfigInventoryDocument::Components(inventory) => inventory
            .rows()
            .iter()
            .take(MAX_INVENTORY_RENDER_ROWS)
            .map(inventory_component_row_cells)
            .collect(),
    }
}

fn inventory_table_row(index: usize, cells: [String; 7], tokens: ThemeTokens) -> AnyElement {
    div()
        .id(SharedString::from(format!("db-inventory-row-{index}")))
        .min_w(px(1120.0))
        .min_h(px(38.0))
        .grid()
        .grid_cols(7)
        .items_center()
        .border_b_1()
        .border_color(tokens.border)
        .children(
            cells
                .into_iter()
                .map(|cell| runtime_table_cell(cell, tokens)),
        )
        .into_any_element()
}

fn bounded_filter_query(value: &str) -> String {
    value
        .chars()
        .take(MAX_RUNTIME_PARAMETER_FILTER_CHARS)
        .collect()
}

fn bounded_plain_text(value: &str, max_chars: usize) -> String {
    let mut characters = value.chars();
    let mut bounded = characters.by_ref().take(max_chars).collect::<String>();
    if characters.next().is_some() {
        bounded.push('…');
    }
    bounded
}

fn runtime_value_presence_label(presence: DatabaseConfigRuntimeValuePresence) -> &'static str {
    match presence {
        DatabaseConfigRuntimeValuePresence::Null => "NULL",
        DatabaseConfigRuntimeValuePresence::Empty => "EMPTY",
        DatabaseConfigRuntimeValuePresence::Present => "PRESENT",
    }
}

fn runtime_value_display(
    public_value: Option<&str>,
    presence: DatabaseConfigRuntimeValuePresence,
) -> String {
    match public_value {
        Some("") => "[EMPTY]".to_owned(),
        Some(value) => bounded_plain_text(value, MAX_RUNTIME_PARAMETER_CELL_CHARS),
        None => format!("[REDACTED] · {}", runtime_value_presence_label(presence)),
    }
}

fn runtime_value_label(value: &DatabaseConfigRuntimeValue) -> String {
    // The core's public_value gate is the only source of displayable plaintext.
    runtime_value_display(value.public_value(), value.presence())
}

fn runtime_scope_label(scope: DatabaseConfigRuntimeScope) -> &'static str {
    match scope {
        DatabaseConfigRuntimeScope::Global => "GLOBAL",
        DatabaseConfigRuntimeScope::GlobalAndSession => "GLOBAL + SESSION",
        DatabaseConfigRuntimeScope::SessionOnly => "SESSION",
        DatabaseConfigRuntimeScope::ServerOrSession => "SERVER / SESSION",
    }
}

fn runtime_apply_label(apply: DatabaseConfigRuntimeApply) -> String {
    match apply {
        DatabaseConfigRuntimeApply::VendorDefined => "VENDOR_DEFINED".to_owned(),
        DatabaseConfigRuntimeApply::Dynamic => "DYNAMIC".to_owned(),
        DatabaseConfigRuntimeApply::ReadOnly => "READ_ONLY".to_owned(),
        DatabaseConfigRuntimeApply::PostgreSql(context) => format!(
            "POSTGRESQL · {}",
            match context {
                PostgreSqlRuntimeContext::Internal => "INTERNAL",
                PostgreSqlRuntimeContext::Postmaster => "POSTMASTER",
                PostgreSqlRuntimeContext::Sighup => "SIGHUP",
                PostgreSqlRuntimeContext::SuperuserBackend => "SUPERUSER_BACKEND",
                PostgreSqlRuntimeContext::Backend => "BACKEND",
                PostgreSqlRuntimeContext::Superuser => "SUPERUSER",
                PostgreSqlRuntimeContext::User => "USER",
            }
        ),
    }
}

fn runtime_pending_label(pending: Option<bool>) -> &'static str {
    match pending {
        Some(true) => "YES",
        Some(false) => "NO",
        None => "—",
    }
}

fn optional_runtime_cell(value: Option<&str>) -> String {
    value.map_or_else(
        || "—".to_owned(),
        |value| bounded_plain_text(value, MAX_RUNTIME_PARAMETER_CELL_CHARS),
    )
}

fn runtime_enum_label(values: &[String]) -> String {
    if values.is_empty() {
        return "—".to_owned();
    }
    let joined = values
        .iter()
        .take(MAX_RUNTIME_PARAMETER_ENUM_VALUES)
        .map(|value| bounded_plain_text(value, 64))
        .collect::<Vec<_>>()
        .join(", ");
    let mut label = bounded_plain_text(&joined, MAX_RUNTIME_PARAMETER_CELL_CHARS);
    if values.len() > MAX_RUNTIME_PARAMETER_ENUM_VALUES {
        label.push_str(" …");
    }
    label
}

fn runtime_table_header_cell(label: &'static str, tokens: ThemeTokens) -> AnyElement {
    div()
        .min_w_0()
        .px_3()
        .text_xs()
        .font_semibold()
        .text_color(tokens.muted)
        .truncate()
        .child(label)
        .into_any_element()
}

fn runtime_table_cell(value: String, tokens: ThemeTokens) -> AnyElement {
    div()
        .min_w_0()
        .px_3()
        .text_xs()
        .text_color(tokens.text)
        .truncate()
        .child(value)
        .into_any_element()
}

fn input_value(input: &Entity<InputState>, cx: &Context<DatabasePage>) -> String {
    input.read(cx).value().trim().to_owned()
}

fn set_input(
    input: &Entity<InputState>,
    value: &str,
    window: &mut Window,
    cx: &mut Context<DatabasePage>,
) {
    let value = value.to_owned();
    input.update(cx, |input, cx| input.set_value(value, window, cx));
}

fn input_field(
    label: &'static str,
    input: Entity<InputState>,
    tokens: ThemeTokens,
) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .gap_1()
        .child(div().text_xs().text_color(tokens.muted).child(label))
        .child(Input::new(&input))
}

fn disconnected_placeholder(tokens: ThemeTokens) -> impl IntoElement {
    div()
        .size_full()
        .rounded_lg()
        .border_1()
        .border_color(tokens.border)
        .bg(tokens.surface)
        .flex()
        .items_center()
        .justify_center()
        .child(
            div()
                .text_center()
                .child(div().font_semibold().child("尚未连接数据库"))
                .child(
                    div()
                        .mt_1()
                        .text_sm()
                        .text_color(tokens.muted)
                        .child("请在“连接”页保存配置并完成验证。"),
                ),
        )
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

fn abort_task(task: &mut Option<AbortHandle>) {
    if let Some(task) = task.take() {
        task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lovelyres_core::target::TargetIdentity;

    fn binding(identity: &str, generation: u64) -> DatabaseBinding {
        DatabaseBinding {
            connection_id: identity.to_owned(),
            session_id: format!("session-{identity}"),
            target: TargetGuard {
                identity: TargetIdentity::new(identity).unwrap(),
                generation,
            },
        }
    }

    fn profile(id: &str, engine: DatabaseEngine) -> DatabaseProfileView {
        DatabaseProfileView {
            config: DatabaseProfileConfig {
                id: id.to_owned(),
                name: format!("profile-{id}"),
                connection: lovelyres_core::database::DatabaseConnection {
                    engine,
                    host: "127.0.0.1".to_owned(),
                    port: engine.default_port(),
                    username: Some("operator".to_owned()),
                    database: None,
                },
            },
            has_password: false,
        }
    }

    #[test]
    fn lifecycle_and_target_epoch_reject_late_database_results() {
        let mut model = DatabaseModel::default();
        let first = binding("host-a", 1);
        model.activate(Some(first.clone()));
        let lease = model.begin(RequestLane::Query, first.clone()).unwrap();
        assert!(model.accepts(&lease, Some(&first)));

        let replacement = binding("host-b", 2);
        model.rebind(Some(replacement.clone()));
        assert!(!model.accepts(&lease, Some(&replacement)));
        assert!(model.connected_profile_id.is_none());
        assert!(model.result.is_none());

        model.deactivate();
        assert!(!model.accepts(&lease, Some(&first)));
    }

    #[test]
    fn database_tabs_cover_legacy_work_areas_without_duplicate_titles() {
        assert_eq!(DatabaseTab::ALL.len(), 7);
        let labels = DatabaseTab::ALL.map(DatabaseTab::label);
        assert_eq!(
            labels,
            [
                "连接",
                "SQL 控制台",
                "对象浏览",
                "运行时参数（只读）",
                "插件 / 组件清单（只读）",
                "用户权限",
                "运维",
            ]
        );
    }

    #[test]
    fn runtime_parameter_status_starts_and_resets_to_not_run() {
        let mut model = DatabaseModel::default();
        assert_eq!(
            model.runtime_parameters_status,
            RuntimeParametersStatus::NotRun
        );
        assert_eq!(model.runtime_parameters_status.label(), "NOT_RUN");

        model.runtime_parameters_status = RuntimeParametersStatus::Loading;
        model.reset_runtime_parameters(false);
        assert_eq!(
            model.runtime_parameters_status,
            RuntimeParametersStatus::NotRun
        );
        assert!(model.runtime_parameters_snapshot.is_none());
    }

    #[test]
    fn runtime_password_profiles_are_blocked_until_native_protocol_transport() {
        let mut model = DatabaseModel::default();
        let mut selected = profile("mysql-main", DatabaseEngine::Mysql);
        model.selected_profile_id = Some(selected.config.id.clone());
        model.profiles.push(selected.clone());
        assert!(!model.runtime_password_blocked());

        selected.has_password = true;
        model.profiles[0] = selected;
        assert!(model.runtime_password_blocked());
    }

    #[test]
    fn runtime_product_mapping_requires_explicit_mysql_family_choice() {
        assert_eq!(
            runtime_product_for_engine(DatabaseEngine::Mysql, None),
            RuntimeProductAvailability::NeedsMysqlChoice
        );
        assert_eq!(
            runtime_product_for_engine(DatabaseEngine::Mysql, Some(MysqlRuntimeProduct::MySql)),
            RuntimeProductAvailability::Ready(DatabaseConfigProduct::MySql)
        );
        assert_eq!(
            runtime_product_for_engine(DatabaseEngine::Mysql, Some(MysqlRuntimeProduct::MariaDb)),
            RuntimeProductAvailability::Ready(DatabaseConfigProduct::MariaDb)
        );
        assert_eq!(
            runtime_product_for_engine(DatabaseEngine::Postgresql, None),
            RuntimeProductAvailability::Ready(DatabaseConfigProduct::PostgreSql)
        );
        for engine in [
            DatabaseEngine::Redis,
            DatabaseEngine::Mongo,
            DatabaseEngine::Dm,
            DatabaseEngine::Kingbase,
        ] {
            assert_eq!(
                runtime_product_for_engine(engine, None),
                RuntimeProductAvailability::Unsupported(engine)
            );
        }
    }

    #[test]
    fn runtime_parameter_request_rejects_profile_product_and_target_changes() {
        let mut model = DatabaseModel::default();
        let first = binding("host-a", 1);
        model.profiles = vec![
            profile("mysql-main", DatabaseEngine::Mysql),
            profile("postgres-main", DatabaseEngine::Postgresql),
        ];
        model.selected_profile_id = Some("mysql-main".to_owned());
        model.activate(Some(first.clone()));
        model.runtime_mysql_product = Some(("mysql-main".to_owned(), MysqlRuntimeProduct::MySql));
        let request = RuntimeParametersRequest {
            lease: model
                .begin(RequestLane::RuntimeParameters, first.clone())
                .unwrap(),
            profile_id: "mysql-main".to_owned(),
            product: DatabaseConfigProduct::MySql,
        };
        assert!(model.accepts_runtime_parameters(&request, Some(&first)));

        model.runtime_mysql_product = Some(("mysql-main".to_owned(), MysqlRuntimeProduct::MariaDb));
        assert!(!model.accepts_runtime_parameters(&request, Some(&first)));

        model.runtime_mysql_product = Some(("mysql-main".to_owned(), MysqlRuntimeProduct::MySql));
        model.selected_profile_id = Some("postgres-main".to_owned());
        assert!(!model.accepts_runtime_parameters(&request, Some(&first)));

        let replacement = binding("host-b", 2);
        model.rebind(Some(replacement.clone()));
        assert!(!model.accepts_runtime_parameters(&request, Some(&replacement)));

        model.deactivate();
        assert!(!model.accepts_runtime_parameters(&request, Some(&first)));
    }

    #[test]
    fn runtime_values_use_only_public_value_and_redact_every_absent_value() {
        let public = "<script>still plain text</script>";
        assert_eq!(
            runtime_value_display(Some(public), DatabaseConfigRuntimeValuePresence::Present),
            public
        );
        for (presence, label) in [
            (DatabaseConfigRuntimeValuePresence::Null, "NULL"),
            (DatabaseConfigRuntimeValuePresence::Empty, "EMPTY"),
            (DatabaseConfigRuntimeValuePresence::Present, "PRESENT"),
        ] {
            let display = runtime_value_display(None, presence);
            assert_eq!(display, format!("[REDACTED] · {label}"));
            assert!(!display.contains("MAX_CONNECTIONS"));
        }
        assert_eq!(
            runtime_value_display(Some(""), DatabaseConfigRuntimeValuePresence::Empty),
            "[EMPTY]"
        );
    }

    #[test]
    fn runtime_filter_and_cells_are_bounded_without_interpreting_text() {
        let hostile = concat!("<b on", "click='run()'>remote</b>");
        assert_eq!(bounded_plain_text(hostile, 128), hostile);
        assert_eq!(bounded_plain_text("abcdef", 3), "abc…");
        assert_eq!(
            bounded_filter_query(&"x".repeat(MAX_RUNTIME_PARAMETER_FILTER_CHARS + 10)).len(),
            MAX_RUNTIME_PARAMETER_FILTER_CHARS
        );
    }

    #[test]
    fn inventory_accepts_only_reviewed_mysql_and_mariadb_surfaces() {
        let mut model = DatabaseModel::default();
        let current = binding("host-a", 1);
        model.profiles = vec![profile("mysql-main", DatabaseEngine::Mysql)];
        model.selected_profile_id = Some("mysql-main".to_owned());
        model.activate(Some(current.clone()));

        model.runtime_mysql_product = Some(("mysql-main".to_owned(), MysqlRuntimeProduct::MySql));
        for surface in [
            DatabaseConfigInventorySurface::PluginRegistry,
            DatabaseConfigInventorySurface::ComponentRegistry,
        ] {
            model.inventory_surface = surface;
            assert_eq!(
                model.inventory_request_input(),
                Some((
                    "mysql-main".to_owned(),
                    DatabaseConfigProduct::MySql,
                    surface,
                ))
            );
            let request = InventoryRequest {
                lease: model
                    .begin(RequestLane::Inventory, current.clone())
                    .unwrap(),
                profile_id: "mysql-main".to_owned(),
                product: DatabaseConfigProduct::MySql,
                surface,
            };
            assert!(model.accepts_inventory(&request, Some(&current)));
        }

        model.runtime_mysql_product = Some(("mysql-main".to_owned(), MysqlRuntimeProduct::MariaDb));
        model.inventory_surface = DatabaseConfigInventorySurface::PluginRegistry;
        assert_eq!(
            model.inventory_request_input(),
            Some((
                "mysql-main".to_owned(),
                DatabaseConfigProduct::MariaDb,
                DatabaseConfigInventorySurface::PluginRegistry,
            ))
        );

        model.inventory_surface = DatabaseConfigInventorySurface::ComponentRegistry;
        assert_eq!(
            model.inventory_availability(),
            InventoryAvailability::UnsupportedSurface {
                product: DatabaseConfigProduct::MariaDb,
                surface: DatabaseConfigInventorySurface::ComponentRegistry,
            }
        );
        assert!(model.inventory_request_input().is_none());

        model.profiles[0] = profile("mysql-main", DatabaseEngine::Postgresql);
        assert_eq!(
            model.inventory_availability(),
            InventoryAvailability::UnsupportedEngine(DatabaseEngine::Postgresql)
        );
    }

    #[test]
    fn inventory_request_rejects_repeat_surface_product_profile_target_and_activation_changes() {
        let mut model = DatabaseModel::default();
        let first = binding("host-a", 1);
        model.profiles = vec![
            profile("mysql-main", DatabaseEngine::Mysql),
            profile("mysql-alt", DatabaseEngine::Mysql),
        ];
        model.selected_profile_id = Some("mysql-main".to_owned());
        model.activate(Some(first.clone()));
        model.runtime_mysql_product = Some(("mysql-main".to_owned(), MysqlRuntimeProduct::MySql));
        model.inventory_surface = DatabaseConfigInventorySurface::PluginRegistry;

        let original = InventoryRequest {
            lease: model.begin(RequestLane::Inventory, first.clone()).unwrap(),
            profile_id: "mysql-main".to_owned(),
            product: DatabaseConfigProduct::MySql,
            surface: DatabaseConfigInventorySurface::PluginRegistry,
        };
        let repeated = InventoryRequest {
            lease: model.begin(RequestLane::Inventory, first.clone()).unwrap(),
            profile_id: "mysql-main".to_owned(),
            product: DatabaseConfigProduct::MySql,
            surface: DatabaseConfigInventorySurface::PluginRegistry,
        };
        assert!(!model.accepts_inventory(&original, Some(&first)));
        assert!(model.accepts_inventory(&repeated, Some(&first)));

        model.inventory_surface = DatabaseConfigInventorySurface::ComponentRegistry;
        assert!(!model.accepts_inventory(&repeated, Some(&first)));
        model.inventory_surface = DatabaseConfigInventorySurface::PluginRegistry;
        model.runtime_mysql_product = Some(("mysql-main".to_owned(), MysqlRuntimeProduct::MariaDb));
        assert!(!model.accepts_inventory(&repeated, Some(&first)));
        model.runtime_mysql_product = Some(("mysql-main".to_owned(), MysqlRuntimeProduct::MySql));
        model.selected_profile_id = Some("mysql-alt".to_owned());
        assert!(!model.accepts_inventory(&repeated, Some(&first)));

        model.selected_profile_id = Some("mysql-main".to_owned());
        let replacement = binding("host-b", 2);
        model.rebind(Some(replacement.clone()));
        assert!(!model.accepts_inventory(&repeated, Some(&replacement)));

        model.deactivate();
        assert!(!model.accepts_inventory(&repeated, Some(&first)));
    }

    #[test]
    fn inventory_values_use_only_public_plain_text_or_redacted_presence() {
        let hostile_looking_public = concat!("<img src=x on", "error='run()'>");
        assert_eq!(
            inventory_value_display(
                Some(hostile_looking_public),
                InventoryValuePresence::Present
            ),
            hostile_looking_public
        );
        let discarded_hostile = "remote\nsecret";
        let redacted = inventory_value_display(None, InventoryValuePresence::Present);
        assert_eq!(redacted, "[REDACTED] · PRESENT");
        assert!(!redacted.contains(discarded_hostile));
        assert_eq!(
            inventory_value_display(None, InventoryValuePresence::Null),
            "[REDACTED] · NULL"
        );
        assert_eq!(
            inventory_plugin_status_label(DatabaseConfigPluginStatus::Unrecognized),
            "[REDACTED] · PRESENT"
        );
        assert_eq!(
            inventory_plugin_load_option_label(DatabaseConfigPluginLoadOption::Unrecognized),
            "[REDACTED] · PRESENT"
        );
        assert_eq!(
            inventory_plugin_maturity_label(Some(DatabaseConfigPluginMaturity::Unrecognized)),
            "[REDACTED] · PRESENT"
        );
    }

    #[test]
    fn source_keeps_mutations_behind_plan_confirmation_and_journal() {
        let source = include_str!("database.rs");
        for required in [
            "plan_mutation(",
            "plan_service_action(",
            "plan_backup(",
            "DangerousConfirmation::approve",
            "operation_journal()",
            "execute_action(",
            "read_runtime_parameters(",
            "validate_runtime_parameters_snapshot(&snapshot)",
            "runtime_value_display(value.public_value(), value.presence())",
            "read_database_config_inventory(&session, &profile_id, product, surface)",
            "validate_database_config_inventory_snapshot(&snapshot)",
            "snapshot.target() != &request.lease.binding.target",
            "inventory_value_display(value.public_value(), InventoryValuePresence::Present)",
            "core 也会在首个 SSH 命令前拒绝该请求",
        ] {
            assert!(source.contains(required), "missing {required}");
        }
        assert!(!source.contains(concat!("db-runtime-", "copy")));
        for forbidden in [
            concat!("db-inventory-", "copy"),
            concat!("db-inventory-", "export"),
            concat!("db-inventory-", "edit"),
            concat!("db-inventory-", "apply"),
            concat!("db-inventory-", "delete"),
            concat!("db-inventory-", "install"),
            concat!("db-inventory-", "uninstall"),
            concat!("db-inventory-", "sql"),
        ] {
            assert!(!source.contains(forbidden), "forbidden {forbidden}");
        }
        assert!(!source.contains(concat!("execute_", "command(")));
        assert!(!source.contains(concat!("tau", "ri")));
        assert!(!source.contains(concat!("inner", "HTML")));
    }
}
